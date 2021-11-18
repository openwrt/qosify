// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2021 Felix Fietkau <nbd@nbd.name>
 */
#ifndef __BPF_QOSIFY_H
#define __BPF_QOSIFY_H

#define QOSIFY_MAX_CLASS_ENTRIES	16
#define QOSIFY_DEFAULT_CLASS_ENTRIES	2

#ifndef QOSIFY_FLOW_BUCKET_SHIFT
#define QOSIFY_FLOW_BUCKET_SHIFT	13
#endif

#define QOSIFY_FLOW_BUCKETS		(1 << QOSIFY_FLOW_BUCKET_SHIFT)

/* rodata per-instance flags */
#define QOSIFY_INGRESS			(1 << 0)
#define QOSIFY_IP_ONLY			(1 << 1)

#define QOSIFY_DSCP_VALUE_MASK		((1 << 6) - 1)
#define QOSIFY_DSCP_FALLBACK_FLAG	(1 << 6)
#define QOSIFY_DSCP_CLASS_FLAG		(1 << 7)

#define QOSIFY_CLASS_FLAG_PRESENT	(1 << 0)

struct qosify_dscp_val {
	uint8_t ingress;
	uint8_t egress;
};

/* global config data */

struct qosify_flow_config {
	uint8_t dscp_prio;
	uint8_t dscp_bulk;

	uint8_t bulk_trigger_timeout;
	uint16_t bulk_trigger_pps;

	uint16_t prio_max_avg_pkt_len;
};

struct qosify_config {
	uint8_t dscp_icmp;
};

struct qosify_ip_map_val {
	uint8_t dscp; /* must be first */
	uint8_t seen;
};

struct qosify_class {
	struct qosify_flow_config config;

	struct qosify_dscp_val val;

	uint8_t flags;
};

#endif
