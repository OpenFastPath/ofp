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
 */
typedef struct ofp_init_global_t {
	uint16_t if_count;	/**< Interface count that needs init */
	uint16_t linux_core_id;	/**< Core index that is reserved for Linux */
	char **if_names;	/**< Interface names in relation to #if_count */
	ofp_pkt_hook pkt_hook[OFP_HOOK_MAX];	/**< @see ofp_hook.h */
	uint8_t burst_recv_mode;		/**< Interfaces use polling
						when value set is 1.
						Interfaces use scheduling
						when value set is 0. */
} ofp_init_global_t;

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
