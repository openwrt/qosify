#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <resolv.h>

#include <libubox/uloop.h>
#include <libubox/avl-cmp.h>

#define FLAG_RESPONSE		0x8000
#define FLAG_OPCODE		0x7800
#define FLAG_AUTHORATIVE	0x0400
#define FLAG_RCODE		0x000f

#define TYPE_A			0x0001
#define TYPE_CNAME		0x0005
#define TYPE_PTR		0x000c
#define TYPE_TXT		0x0010
#define TYPE_AAAA		0x001c
#define TYPE_SRV		0x0021
#define TYPE_ANY		0x00ff

#define IS_COMPRESSED(x)	((x & 0xc0) == 0xc0)

#define CLASS_FLUSH		0x8000
#define CLASS_UNICAST		0x8000
#define CLASS_IN		0x0001

#define MAX_NAME_LEN            256
#define MAX_DATA_LEN            8096

#include "qosify.h"

static struct uloop_fd ufd;
static struct uloop_timeout cname_gc_timer;
static AVL_TREE(cname_cache, avl_strcmp, false, NULL);

struct vlan_hdr {
	uint16_t tci;
	uint16_t proto;
};

struct packet {
	void *buffer;
	unsigned int len;
};

struct dns_header {
	uint16_t id;
	uint16_t flags;
	uint16_t questions;
	uint16_t answers;
	uint16_t authority;
	uint16_t additional;
} __packed;

struct dns_question {
	uint16_t type;
	uint16_t class;
} __packed;

struct dns_answer {
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t rdlength;
} __packed;

struct cname_entry {
	struct avl_node node;
	uint32_t seq;
	uint8_t dscp;
	uint8_t age;
};

static void *pkt_peek(struct packet *pkt, unsigned int len)
{
	if (len > pkt->len)
		return NULL;

	return pkt->buffer;
}


static void *pkt_pull(struct packet *pkt, unsigned int len)
{
	void *ret = pkt_peek(pkt, len);

	if (!ret)
		return NULL;

	pkt->buffer += len;
	pkt->len -= len;

	return ret;
}

static int pkt_pull_name(struct packet *pkt, const void *hdr, char *dest)
{
	int len;

	if (dest)
		len = dn_expand(hdr, pkt->buffer + pkt->len, pkt->buffer,
				(void *)dest, MAX_NAME_LEN);
	else
		len = dn_skipname(pkt->buffer, pkt->buffer + pkt->len - 1);

	if (len < 0 || !pkt_pull(pkt, len))
		return -1;

	return 0;
}

static bool
proto_is_vlan(uint16_t proto)
{
	return proto == ETH_P_8021Q || proto == ETH_P_8021AD;
}

static void
cname_cache_set(const char *name, uint8_t dscp, uint32_t seq)
{
	struct cname_entry *e;

	e = avl_find_element(&cname_cache, name, e, node);
	if (!e) {
		char *name_buf;

		e = calloc_a(sizeof(*e), &name_buf, strlen(name) + 1);
		e->node.key = strcpy(name_buf, name);
		avl_insert(&cname_cache, &e->node);
	}

	e->age = 0;
	e->dscp = dscp;
	e->seq = seq;
}

static int
cname_cache_get(const char *name, uint8_t *dscp, uint32_t *seq)
{
	struct cname_entry *e;

	e = avl_find_element(&cname_cache, name, e, node);
	if (!e)
		return -1;

	if (*dscp == 0xff || e->seq < *seq) {
		*dscp = e->dscp;
		*seq = e->seq;
	}

	return 0;
}

static int
dns_parse_question(struct packet *pkt, const void *hdr, uint8_t *dscp, uint32_t *seq)
{
	char qname[MAX_NAME_LEN];

	if (pkt_pull_name(pkt, hdr, qname) ||
	    !pkt_pull(pkt, sizeof(struct dns_question)))
		return -1;

	cname_cache_get(qname, dscp, seq);
	qosify_map_lookup_dns_entry(qname, false, dscp, seq);

	return 0;
}

static int
dns_parse_answer(struct packet *pkt, void *hdr, uint8_t *dscp, uint32_t *seq)
{
	struct qosify_map_data data = {};
	char cname[MAX_NAME_LEN];
	struct dns_answer *a;
	int prev_timeout;
	void *rdata;
	int len;

	if (pkt_pull_name(pkt, hdr, NULL))
		return -1;

	a = pkt_pull(pkt, sizeof(*a));
	if (!a)
		return -1;

	len = be16_to_cpu(a->rdlength);
	rdata = pkt_pull(pkt, len);
	if (!rdata)
		return -1;

	switch (be16_to_cpu(a->type)) {
	case TYPE_CNAME:
		if (dn_expand(hdr, pkt->buffer + pkt->len, rdata,
			      cname, sizeof(cname)) < 0)
			return -1;

		qosify_map_lookup_dns_entry(cname, true, dscp, seq);
		cname_cache_set(cname, *dscp, *seq);

		return 0;
	case TYPE_A:
		data.id = CL_MAP_IPV4_ADDR;
		memcpy(&data.addr, rdata, 4);
		break;
	case TYPE_AAAA:
		data.id = CL_MAP_IPV6_ADDR;
		memcpy(&data.addr, rdata, 16);
		break;
	default:
		return 0;
	}

	data.user = true;
	data.dscp = *dscp;

	prev_timeout = qosify_map_timeout;
	qosify_map_timeout = be32_to_cpu(a->ttl);
	__qosify_map_set_entry(&data);
	qosify_map_timeout = prev_timeout;

	return 0;
}

static void
qosify_dns_data_cb(struct packet *pkt)
{
	struct dns_header *h;
	uint32_t lookup_seq = 0;
	uint8_t dscp = 0xff;
	int i;

	h = pkt_pull(pkt, sizeof(*h));
	if (!h)
		return;

	if ((h->flags & cpu_to_be16(FLAG_RESPONSE | FLAG_OPCODE | FLAG_RCODE)) !=
	    cpu_to_be16(FLAG_RESPONSE))
		return;

	if (h->questions != cpu_to_be16(1))
		return;

	if (dns_parse_question(pkt, h, &dscp, &lookup_seq))
		return;

	for (i = 0; i < be16_to_cpu(h->answers); i++)
		if (dns_parse_answer(pkt, h, &dscp, &lookup_seq))
			return;
}

static void
qosify_dns_packet_cb(struct packet *pkt)
{
	struct ethhdr *eth;
	struct ip6_hdr *ip6;
	struct ip *ip;
	uint16_t proto;

	eth = pkt_pull(pkt, sizeof(*eth));
	if (!eth)
		return;

	proto = be16_to_cpu(eth->h_proto);
	if (proto_is_vlan(proto)) {
		struct vlan_hdr *vlan;

		vlan = pkt_pull(pkt, sizeof(*vlan));
		if (!vlan)
			return;

		proto = vlan->proto;
	}

	switch (proto) {
	case ETH_P_IP:
		ip = pkt_peek(pkt, sizeof(struct ip));
		if (!ip)
			return;

		if (!pkt_pull(pkt, ip->ip_hl * 4))
			return;

		proto = ip->ip_p;
		break;
	case ETH_P_IPV6:
		ip6 = pkt_pull(pkt, sizeof(*ip6));
		if (!ip6)
			return;

		proto = ip6->ip6_nxt;
		break;
	default:
		return;
	}

	if (proto != IPPROTO_UDP)
		return;

	if (!pkt_pull(pkt, sizeof(struct udphdr)))
		return;

	qosify_dns_data_cb(pkt);
}

static void
qosify_dns_socket_cb(struct uloop_fd *fd, unsigned int events)
{
	static uint8_t buf[8192];
	struct packet pkt = {
		.buffer = buf,
	};
	int len;

retry:
	len = recvfrom(fd->fd, buf, sizeof(buf), MSG_DONTWAIT, NULL, NULL);
	if (len < 0) {
		if (errno == EINTR)
			goto retry;
		return;
	}

	if (!len)
		return;

	pkt.len = len;
	qosify_dns_packet_cb(&pkt);
}

static void
qosify_cname_cache_gc(struct uloop_timeout *timeout)
{
	struct cname_entry *e, *tmp;

	avl_for_each_element_safe(&cname_cache, e, node, tmp) {
		if (e->age++ < 5)
			continue;

		avl_delete(&cname_cache, &e->node);
		free(e);
	}

	uloop_timeout_set(timeout, 1000);
}

static int
qosify_open_dns_socket(void)
{
	struct sockaddr_ll sll = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_ALL),
	};
	int sock;

	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock == -1) {
		ULOG_ERR("failed to create raw socket: %s\n", strerror(errno));
		return -1;
	}

	sll.sll_ifindex = if_nametoindex(QOSIFY_DNS_IFNAME);
	if (bind(sock, (struct sockaddr *)&sll, sizeof(sll))) {
		ULOG_ERR("failed to bind socket to "QOSIFY_DNS_IFNAME": %s\n",
			 strerror(errno));
		goto error;
	}

	ufd.fd = sock;
	ufd.cb = qosify_dns_socket_cb;
	uloop_fd_add(&ufd, ULOOP_READ);

	return 0;

error:
	close(sock);
	return -1;
}

static void
qosify_dns_del_ifb(void)
{
	qosify_run_cmd("ip link del ifb-dns type ifb", true);
}

int qosify_dns_init(void)
{
	cname_gc_timer.cb = qosify_cname_cache_gc;
	qosify_cname_cache_gc(&cname_gc_timer);

	qosify_dns_del_ifb();

	if (qosify_run_cmd("ip link add ifb-dns type ifb", false) ||
	    qosify_run_cmd("ip link set dev ifb-dns up", false) ||
	    qosify_open_dns_socket())
		return -1;

	return 0;
}

void qosify_dns_stop(void)
{
	struct cname_entry *e, *tmp;

	if (ufd.registered) {
		uloop_fd_delete(&ufd);
		close(ufd.fd);
	}

	qosify_dns_del_ifb();

	avl_remove_all_elements(&cname_cache, e, node, tmp)
		free(e);
}

