/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef __OFP_INIT_H__
#define __OFP_INIT_H__

#include "ofp_hook.h"

typedef struct ofp_init_global_t {
	uint16_t if_count;
	uint16_t linux_core_id;
	char **if_names;
	ofp_pkt_hook pkt_hook[OFP_HOOK_MAX];
	uint8_t burst_recv_mode;
} ofp_init_global_t;

int ofp_init_global(ofp_init_global_t *params);
int ofp_init_local(void);

#endif /* __OFP_INIT_H__ */
