/* Copyright (c) 2014, Nokia
 * Copyright (c) 2014, ENEA Software AB
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFP_STAT_H__
#define __OFP_STAT_H__

#include <odp.h>

struct ofp_packet_stat {
	struct {
		int rx_fp;
		int tx_fp;
		int rx_sp;
		int tx_sp;
		int tx_eth_frag;
		int rx_ip_frag;
		int rx_ip_reass;
		uint64_t input_latency[64];
		uint64_t last_input_cycles;
	} per_core[ODP_CONFIG_MAX_THREADS];
};

/* Stats: Get stats */
struct ofp_packet_stat *ofp_get_packet_statistics(void);

/* Stats: configure*/
#define OFP_STAT_COMPUTE_LATENCY 1

void ofp_set_stat_flags(unsigned long int flags);
unsigned long int ofp_get_stat_flags(void);

#endif /* __OFP_STAT_H__ */
