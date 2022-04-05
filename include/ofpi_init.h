/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */
#ifndef __OFPI_INIT_H__
#define __OFPI_INIT_H__

#include "api/ofp_init.h"
#include <odp/helper/odph_api.h>

#define SHM_NAME_GLOBAL_CONFIG "OfpGlobalConfigShMem"

extern odp_pool_t ofp_packet_pool;
extern odp_cpumask_t cpumask;

int ofp_term_post_global(const char *pool_name);

struct ofp_global_config_mem {
	odp_bool_t is_running ODP_ALIGNED_CACHE;

#ifdef SP
	odph_thread_t nl_thread;
	odp_bool_t nl_thread_is_running;
#endif /* SP */

	odph_thread_t cli_thread;
	odp_bool_t cli_thread_is_running;

	ofp_global_param_t global_param;
};

extern __thread ofp_global_param_t *global_param;

struct ofp_global_config_mem *ofp_get_global_config(void);

#endif /* __OFPI_INIT_H__ */
