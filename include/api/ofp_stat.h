/* Copyright (c) 2014, Nokia
 * Copyright (c) 2014, ENEA Software AB
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFP_STAT_H__
#define __OFP_STAT_H__

#include <odp.h>

#if __GNUC__ >= 4
#pragma GCC visibility push(default)
#endif

struct ofp_packet_stat {
	struct {
		unsigned int rx_fp;
		unsigned int tx_fp;
		unsigned int rx_sp;
		unsigned int tx_sp;
		unsigned int tx_eth_frag;
		unsigned int rx_ip_frag;
		unsigned int rx_ip_reass;
		uint64_t input_latency[64];
		odp_time_t last_input_cycles;
	} per_core[ODP_CPUMASK_STR_SIZE];
};

struct ofp_perf_stat {
	uint64_t rx_fp_pps;
	uint64_t rx_prev_sum;
};

/* Stats: Get stats */
struct ofp_packet_stat *ofp_get_packet_statistics(void);
struct ofp_perf_stat *ofp_get_perf_statistics(void);

/* Stats: configure*/
#define OFP_STAT_COMPUTE_LATENCY 1
#define OFP_STAT_COMPUTE_PERF 2

void ofp_set_stat_flags(unsigned long int flags);
unsigned long int ofp_get_stat_flags(void);

#if __GNUC__ >= 4
#pragma GCC visibility pop
#endif

#endif /* __OFP_STAT_H__ */
