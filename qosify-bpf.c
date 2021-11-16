// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2021 Felix Fietkau <nbd@nbd.name>
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/filter.h>
#include <uapi/linux/pkt_cls.h>
#include <linux/ip.h>
#include <net/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "qosify-bpf.h"

#define INET_ECN_MASK 3

#define FLOW_CHECK_INTERVAL	((u32)((1000000000ULL) >> 24))
#define FLOW_TIMEOUT		((u32)((30ULL * 1000000000ULL) >> 24))
#define FLOW_BULK_TIMEOUT	5

#define EWMA_SHIFT		12

const volatile static uint32_t module_flags = 0;

struct flow_bucket {
	__u32 last_update;
	__u32 pkt_len_avg;
	__u16 pkt_count;
	struct qosify_dscp_val val;
	__u8 bulk_timeout;
} __packed;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(pinning, 1);
	__type(key, __u32);
	__type(value, struct qosify_config);
	__uint(max_entries, 1);
} config SEC(".maps");

typedef struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(pinning, 1);
	__type(key, __u32);
	__type(value, struct qosify_dscp_val);
	__uint(max_entries, 1 << 16);
} port_array_t;

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(pinning, 1);
	__type(key, __u32);
	__uint(value_size, sizeof(struct flow_bucket));
	__uint(max_entries, QOSIFY_FLOW_BUCKETS);
} flow_map SEC(".maps");

port_array_t tcp_ports SEC(".maps");
port_array_t udp_ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(pinning, 1);
	__uint(key_size, sizeof(struct in_addr));
	__type(value, struct qosify_ip_map_val);
	__uint(max_entries, 100000);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} ipv4_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(pinning, 1);
	__uint(key_size, sizeof(struct in6_addr));
	__type(value, struct qosify_ip_map_val);
	__uint(max_entries, 100000);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} ipv6_map SEC(".maps");

static struct qosify_config *get_config(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&config, &key);
}

static __always_inline int proto_is_vlan(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
		  h_proto == bpf_htons(ETH_P_8021AD));
}

static __always_inline int proto_is_ip(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_IP) ||
		  h_proto == bpf_htons(ETH_P_IPV6));
}

static __always_inline void *skb_ptr(struct __sk_buff *skb, __u32 offset)
{
	void *start = (void *)(unsigned long long)skb->data;

	return start + offset;
}

static __always_inline void *skb_end_ptr(struct __sk_buff *skb)
{
	return (void *)(unsigned long long)skb->data_end;
}

static __always_inline int skb_check(struct __sk_buff *skb, void *ptr)
{
	if (ptr > skb_end_ptr(skb))
		return -1;

	return 0;
}

static __always_inline __u32 cur_time(void)
{
	__u32 val = bpf_ktime_get_ns() >> 24;

	if (!val)
		val = 1;

	return val;
}

static __always_inline __u32 ewma(__u32 *avg, __u32 val)
{
	if (*avg)
		*avg = (*avg * 3) / 4 + (val << EWMA_SHIFT) / 4;
	else
		*avg = val << EWMA_SHIFT;

	return *avg >> EWMA_SHIFT;
}

static __always_inline __u8 dscp_val(struct qosify_dscp_val *val, bool ingress)
{
	__u8 ival = val->ingress;
	__u8 eval = val->egress;

	return ingress ? ival : eval;
}

static __always_inline void
ipv4_change_dsfield(struct iphdr *iph, __u8 mask, __u8 value, bool force)
{
	__u32 check = bpf_ntohs(iph->check);
	__u8 dsfield;

	if ((iph->tos & mask) && !force)
		return;

	dsfield = (iph->tos & mask) | value;
	if (iph->tos == dsfield)
		return;

	check += iph->tos;
	if ((check + 1) >> 16)
		check = (check + 1) & 0xffff;
	check -= dsfield;
	check += check >> 16;
	iph->check = bpf_htons(check);
	iph->tos = dsfield;
}

static __always_inline void
ipv6_change_dsfield(struct ipv6hdr *ipv6h, __u8 mask, __u8 value, bool force)
{
	__u16 *p = (__u16 *)ipv6h;
	__u16 val;

	if (((*p >> 4) & mask) && !force)
		return;

	val = (*p & bpf_htons((((__u16)mask << 4) | 0xf00f))) | bpf_htons((__u16)value << 4);
	if (val == *p)
		return;

	*p = val;
}

static __always_inline int
parse_ethernet(struct __sk_buff *skb, __u32 *offset)
{
	struct ethhdr *eth;
	__u16 h_proto;
	int i;

	eth = skb_ptr(skb, *offset);
	if (skb_check(skb, eth + 1))
		return -1;

	h_proto = eth->h_proto;
	*offset += sizeof(*eth);

#pragma unroll
	for (i = 0; i < 2; i++) {
		struct vlan_hdr *vlh = skb_ptr(skb, *offset);

		if (!proto_is_vlan(h_proto))
			break;

		if (skb_check(skb, vlh + 1))
			return -1;

		h_proto = vlh->h_vlan_encapsulated_proto;
		*offset += sizeof(*vlh);
	}

	return h_proto;
}

static void
parse_l4proto(struct qosify_config *config, struct __sk_buff *skb,
	      __u32 offset, __u8 proto, bool ingress,
	      struct qosify_dscp_val *out_val)
{
	struct qosify_dscp_val *value;
	struct udphdr *udp;
	__u32 src, dest, key;

	udp = skb_ptr(skb, offset);
	if (skb_check(skb, &udp->len))
		return;

	if (config && (proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6)) {
		*out_val = config->dscp_icmp;
		return;
	}

	if (ingress)
		key = udp->source;
	else
		key = udp->dest;

	if (proto == IPPROTO_TCP) {
		value = bpf_map_lookup_elem(&tcp_ports, &key);
	} else {
		if (proto != IPPROTO_UDP)
			key = 0;

		value = bpf_map_lookup_elem(&udp_ports, &key);
	}

	if (value)
		*out_val = *value;
}

static __always_inline void
check_flow_bulk(struct qosify_flow_config *config, struct __sk_buff *skb,
		struct flow_bucket *flow, struct qosify_dscp_val *out_val)
{
	bool trigger = false;
	__s32 delta;
	__u32 time;

	if (!config->bulk_trigger_pps)
		return;

	if (!flow->last_update)
		goto reset;

	time = cur_time();
	delta = time - flow->last_update;
	if ((u32)delta > FLOW_TIMEOUT)
		goto reset;

	if (flow->pkt_count < 0xffff)
		flow->pkt_count++;

	if (flow->pkt_count > config->bulk_trigger_pps) {
		flow->val = config->dscp_bulk;
		flow->val.flags = QOSIFY_VAL_FLAG_BULK_CHECK;
		flow->bulk_timeout = config->bulk_trigger_timeout + 1;
		trigger = true;
	}

	if (delta >= FLOW_CHECK_INTERVAL) {
		if (flow->bulk_timeout && !trigger) {
			flow->bulk_timeout--;
			if (!flow->bulk_timeout)
				flow->val.flags = 0;
		}

		goto clear;
	}

	return;

reset:
	flow->val.flags = 0;
	flow->pkt_len_avg = 0;
clear:
	flow->pkt_count = 1;
	flow->last_update = time;
}

static __always_inline void
check_flow_prio(struct qosify_flow_config *config, struct __sk_buff *skb,
		struct flow_bucket *flow, struct qosify_dscp_val *out_val)
{
	if ((flow->val.flags & QOSIFY_VAL_FLAG_BULK_CHECK) ||
	    !config->prio_max_avg_pkt_len)
		return;

	if (ewma(&flow->pkt_len_avg, skb->len) > config->prio_max_avg_pkt_len) {
		flow->val.flags = 0;
		return;
	}

	flow->val = config->dscp_prio;
	flow->val.flags = QOSIFY_VAL_FLAG_PRIO_CHECK;
}

static __always_inline void
check_flow(struct qosify_flow_config *config, struct __sk_buff *skb,
	   struct qosify_dscp_val *out_val)
{
	struct flow_bucket flow_data;
	struct flow_bucket *flow;
	__u32 hash;

	if (!(out_val->flags & (QOSIFY_VAL_FLAG_PRIO_CHECK |
			        QOSIFY_VAL_FLAG_BULK_CHECK)))
		return;

	if (!config)
		return;

	hash = bpf_get_hash_recalc(skb);
	flow = bpf_map_lookup_elem(&flow_map, &hash);
	if (!flow) {
		memset(&flow_data, 0, sizeof(flow_data));
		bpf_map_update_elem(&flow_map, &hash, &flow_data, BPF_ANY);
		flow = bpf_map_lookup_elem(&flow_map, &hash);
		if (!flow)
			return;
	}


	if (out_val->flags & QOSIFY_VAL_FLAG_BULK_CHECK)
		check_flow_bulk(config, skb, flow, out_val);
	if (out_val->flags & QOSIFY_VAL_FLAG_PRIO_CHECK)
		check_flow_prio(config, skb, flow, out_val);

	if (flow->val.flags & out_val->flags)
		*out_val = flow->val;
}

static __always_inline struct qosify_ip_map_val *
parse_ipv4(struct qosify_config *config, struct __sk_buff *skb, __u32 *offset,
	   bool ingress, struct qosify_dscp_val *out_val)
{
	struct qosify_dscp_val *value;
	struct iphdr *iph;
	__u8 ipproto;
	int hdr_len;
	void *key;

	iph = skb_ptr(skb, *offset);
	if (skb_check(skb, iph + 1))
		return NULL;

	hdr_len = iph->ihl * 4;
	if (bpf_skb_pull_data(skb, *offset + hdr_len + sizeof(struct udphdr)))
		return NULL;

	iph = skb_ptr(skb, *offset);
	*offset += hdr_len;

	if (skb_check(skb, (void *)(iph + 1)))
		return NULL;

	ipproto = iph->protocol;
	parse_l4proto(config, skb, *offset, ipproto, ingress, out_val);

	if (ingress)
		key = &iph->saddr;
	else
		key = &iph->daddr;

	return bpf_map_lookup_elem(&ipv4_map, key);
}

static __always_inline struct qosify_ip_map_val *
parse_ipv6(struct qosify_config *config, struct __sk_buff *skb, __u32 *offset,
	   bool ingress, struct qosify_dscp_val *out_val)
{
	struct qosify_dscp_val *value;
	struct ipv6hdr *iph;
	__u8 ipproto;
	void *key;

	if (bpf_skb_pull_data(skb, *offset + sizeof(*iph) + sizeof(struct udphdr)))
		return NULL;

	iph = skb_ptr(skb, *offset);
	*offset += sizeof(*iph);

	if (skb_check(skb, (void *)(iph + 1)))
		return NULL;

	ipproto = iph->nexthdr;
	if (ingress)
		key = &iph->saddr;
	else
		key = &iph->daddr;

	parse_l4proto(config, skb, *offset, ipproto, ingress, out_val);

	return bpf_map_lookup_elem(&ipv6_map, key);
}

SEC("classifier")
int classify(struct __sk_buff *skb)
{
	bool ingress = module_flags & QOSIFY_INGRESS;
	struct qosify_config *config;
	struct qosify_ip_map_val *ip_val;
	struct qosify_dscp_val val = {
		.ingress = 0xff,
		.egress = 0xff,
		.flags = 0,
	};
	__u32 offset = 0;
	__u32 iph_offset;
	void *iph;
	__u8 dscp;
	bool force;
	int type;

	config = get_config();
	if (!config)
		return TC_ACT_OK;

	if (module_flags & QOSIFY_IP_ONLY)
		type = skb->protocol;
	else
		type = parse_ethernet(skb, &offset);

	iph_offset = offset;
	if (type == bpf_htons(ETH_P_IP))
		ip_val = parse_ipv4(config, skb, &offset, ingress, &val);
	else if (type == bpf_htons(ETH_P_IPV6))
		ip_val = parse_ipv6(config, skb, &offset, ingress, &val);
	else
		return TC_ACT_OK;

	if (ip_val) {
		if (!ip_val->seen)
			ip_val->seen = 1;
		val = ip_val->dscp;
	}

	check_flow(&config->flow, skb, &val);

	dscp = dscp_val(&val, ingress);
	if (dscp == 0xff)
		return TC_ACT_OK;

	dscp &= GENMASK(5, 0);
	dscp <<= 2;
	force = !(dscp & QOSIFY_DSCP_FALLBACK_FLAG);

	iph = skb_ptr(skb, iph_offset);
	if (skb_check(skb, (void *)iph + sizeof(struct ipv6hdr)))
		return TC_ACT_OK;

	if (type == bpf_htons(ETH_P_IP))
		ipv4_change_dsfield(iph, INET_ECN_MASK, dscp, force);
	else if (type == bpf_htons(ETH_P_IPV6))
		ipv6_change_dsfield(iph, INET_ECN_MASK, dscp, force);

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
