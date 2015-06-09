/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef __OFP_HOOK_H__
#define __OFP_HOOK_H__

#include <odp.h>

typedef enum ofp_return_code (*ofp_pkt_hook)(odp_packet_t pkt, void *arg);

enum ofp_hook_id {
	OFP_HOOK_LOCAL = 0,
	OFP_HOOK_FWD_IPv4,
	OFP_HOOK_FWD_IPv6,
	OFP_HOOK_GRE,
	OFP_HOOK_MAX
};

enum ofp_hook_local_par {
	IS_IPV4 = 0,
	IS_IPV6,
	IS_IPV4_UDP,
	IS_IPV6_UDP
};

#endif /* __OFP_HOOK_H__ */
