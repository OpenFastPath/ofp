/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

/**
 * @file
 *
 * @brief OFP initialization.
 *
 * OFP requires a global level init for the API library and a local init per
 * thread before the other OFP APIs may be called.
 * - ofp_init_global()
 * - ofp_init_local()
 *
 * For a graceful termination the matching termination APIs exit
 * - ofp_term_global()
 * - ofp_term_local()
 */

#ifndef __OFP_INIT_H__
#define __OFP_INIT_H__

#include "ofp_hook.h"

#if __GNUC__ >= 4
#pragma GCC visibility push(default)
#endif

/**
 * OFP API initialization data
 *
 * @see ofp_init_global_param()
 */
typedef struct ofp_init_global_t {
	/** Count of interfaces to be initialized. The default value is 0. */
	uint16_t if_count;

	/** CPU core to which internal OFP control threads are pinned.
	 *  The default value is 0. */
	uint16_t linux_core_id;

	/** Names of the interfaces to be initialized. The naming convention
	 *  depends on the operating system and the ODP implementation.
	 *  Must point to an array of at least if_count zero terminated
	 *  strings. */
	char **if_names;

	/** ODP event scheduling group for all scheduled event queues
	 *  (pktio queues, timer queues and other queues) created in OFP
	 *  initialization. The default value is ODP_SCHED_GROUP_ALL. */
	odp_schedule_group_t sched_group;

	/** Packet processing hooks. @see ofp_hook.h
	 *  The default value is NULL for every hook. */
	ofp_pkt_hook pkt_hook[OFP_HOOK_MAX];

	/** Use direct input mode for all interfaces if set. Otherwise use
	 *  scheduled input mode. Default value is 0 (i.e. scheduled mode). */
	uint8_t burst_recv_mode;

	/** Create netlink listener thread. If slow path is enabled,
	 *  then default is TRUE, otherwise default is FALSE. */
	odp_bool_t enable_nl_thread;
} ofp_init_global_t;

/**
 * Initialize ofp_init_global_t to its default values.
 *
 * This function should be called to initialize the supplied parameter
 * structure to default values before setting application specific values
 * and before passing the parameter structure to ofp_init_global().
 *
 * Using this function makes the application to some extent forward
 * compatible with future versions of OFP that may add new fields in
 * the parameter structure.
 *
 * @params parameter structure to initialize
 *
 * @see ofp_init_global()
 */
void ofp_init_global_param(ofp_init_global_t *params);

/**
 * OFP global initialization
 *
 * This function must be called once in an ODP control thread before calling any
 * other OFP API functions.
 *
 * @param params Structure with parameters for global init of OFP API
 *
 * @retval 0 on success
 * @retval -1 on failure
 *
 * @see ofp_init_local() which is required per thread before use.
 */
int ofp_init_global(odp_instance_t instance, ofp_init_global_t *params);

/**
 * Thread local OFP initialization
 *
 * All threads must call this function before calling any other OFP API
 * functions.
 *
 * @retval 0 on success
 * @retval -1 on failure
 *
 * @see ofp_init_global() which must have been called prior to this.
 */
int ofp_init_local(void);

/**
 * OFP global termination
 *
 * This function must be called only once in an ODP control
 * thread before exiting application.
 *
 * Should be called from a thread within the same schedule group specified in
 * the parameters of ofp_init_global().
 *
 * @retval 0 on success
 * @retval -1 on failure
 *
 * @see ofp_term_local() which is required per thread before
 *      use.
 */
int ofp_term_global(void);

/**
 * Thread local OFP termination
 *
 * All threads must call this function before thread
 * termination.
 *
 * @retval 0 on success
 * @retval -1 on failure
 *
 * @see ofp_term_global() which may be called after this.
 */
int ofp_term_local(void);


/**
 * Stop packet processing
 *
 * Stop processing threads
 *
 *
 * @retval ofp_get_processing_state() which may be called get
 *         the processing state
 *
 *
 * @see
 */
void ofp_stop_processing(void);

/**
 * Get address of processing state variable
 *
 * All processing loops should stop when
 * processing state turns 0
 *
 * @retval non NULL on success
 * @retval NULL on failure
 *
 * @see ofp_stop_processing() which may be called to stop the
 *      processing.
 */

odp_bool_t *ofp_get_processing_state(void);

#if __GNUC__ >= 4
#pragma GCC visibility pop
#endif

#endif /* __OFP_INIT_H__ */
