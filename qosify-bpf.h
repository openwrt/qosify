// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2021 Felix Fietkau <nbd@nbd.name>
 */
#ifndef __BPF_QOSIFY_H
#define __BPF_QOSIFY_H

#ifndef QOSIFY_FLOW_BUCKET_SHIFT
#define QOSIFY_FLOW_BUCKET_SHIFT	13
#endif

#define QOSIFY_FLOW_BUCKETS		(1 << QOSIFY_FLOW_BUCKET_SHIFT)

/* rodata per-instance flags */
#define QOSIFY_INGRESS			(1 << 0)
#define QOSIFY_IP_ONLY			(1 << 1)

#define QOSIFY_DSCP_FALLBACK_FLAG	(1 << 6)

#define QOSIFY_VAL_FLAG_PRIO_CHECK	(1 << 0)
#define QOSIFY_VAL_FLAG_BULK_CHECK	(1 << 1)

struct qosify_dscp_val {
	uint8_t ingress;
	uint8_t egress;
	uint8_t flags;
} __attribute__((packed));

/* global config data */

struct qosify_flow_config {
	struct qosify_dscp_val dscp_prio;
	struct qosify_dscp_val dscp_bulk;

	uint8_t bulk_trigger_timeout;
	uint16_t bulk_trigger_pps;

	uint16_t prio_max_avg_pkt_len;
};

struct qosify_config {
	struct qosify_dscp_val dscp_icmp;

	struct qosify_flow_config flow;
};

struct qosify_ip_map_val {
	struct qosify_dscp_val dscp; /* must be first */
	uint8_t seen;
};

#endif
