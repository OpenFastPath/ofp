/*
 * Copyright (c) 2018, Nokia.
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef OFP_IPSEC_INIT_H
#define OFP_IPSEC_INIT_H

#include <odp_api.h>

#if __GNUC__ >= 4
#pragma GCC visibility push(default)
#endif

/**
 * Default values for the corresponding initialization parameters
 */
#define OFP_IPSEC_MAX_NUM_SA 8
#define OFP_IPSEC_MAX_NUM_SP 8
#define OFP_IPSEC_MAX_INBOUND_SPI 100

/**
 * IPsec initialization parameters
 */
struct ofp_ipsec_param {
	/**
	 * Inbound operation mode. Default is ODP_IPSEC_OP_MODE_SYNC.
	 */
	odp_ipsec_op_mode_t inbound_op_mode;

	/**
	 * Outbound operation mode. Default is ODP_IPSEC_OP_MODE_SYNC.
	 */
	odp_ipsec_op_mode_t outbound_op_mode;

	/**
	 * Maximum number of security policies that can exist at a time.
	 */
	uint32_t max_num_sp;

	/**
	 * Maximum number of SAs that can exist at a time.
	 */
	uint32_t max_num_sa;

	/**
	 * Maximum inbound SPI value that may be used.
	 */
	uint32_t max_inbound_spi;

	/**
	 * Event queue for signaling the completion of asynchronous
	 * inbound IPsec operations in async and inline operation mode.
	 *
	 * If the value is ODP_QUEUE_INVALID, OFP will create a schedulable
	 * event queue itself if needed.
	 *
	 * If the queue is schedulable and ordered, OFP will make use of its
	 * ordered lock with index 0 (see sched.lock_count queue parameter).
	 *
	 * Ownership of the queue transfers to OFP at ofp_init_global().
	 *
	 * Default value is ODP_QUEUE_INVALID.
	 */
	odp_queue_t inbound_queue;

	/**
	 * Event queue for signaling the completion of asynchronous
	 * outbound IPsec operations in async and inline operation mode.
	 *
	 * Similar to inbound_queue in other respects.
	 *
	 * outbound_queue and inbound_queue can be the same queue.
	 */
	odp_queue_t outbound_queue;
};

#if __GNUC__ >= 4
#pragma GCC visibility pop
#endif

#endif /* OFP_IPSEC_INIT_H */
