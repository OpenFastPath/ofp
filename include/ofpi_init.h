/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */
#ifndef __OFPI_INIT_H__
#define __OFPI_INIT_H__

#include <odp.h>

#include "ofpi_hook.h"

odp_pool_t ofp_init_pre_global(const char *pool_name,
			       odp_pool_param_t *pool_params,
			       ofp_pkt_hook hooks[]);

#endif /* __OFPI_INIT_H__ */
