/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef __OFP_HOOK_H__
#define __OFP_HOOK_H__

#include <odp.h>

/**
 * @file
 *
 * @brief Register callback functions for hook handles supported by OFP
 *
 */


/**
 * @brief Function callback format
 *
 * @param pkt The packet received by the hook callback
 * @param arg Argument structure now specifies protocol type of packet received
 * with an integer that is an ofp_hook_local_par value
 *
 * @retval ofp_return_code Control how OFP will behave after hook processing
 */
typedef enum ofp_return_code (*ofp_pkt_hook)(odp_packet_t pkt, void *arg);

/**
 * @brief Hook handles
 *
 * A function callback is called by OFP when a specific processing phase(handle)
 * is found. One can register any ofp_pkt_hook() function callback for any
 * handle.
 * The registration is done with ofp_global_init() by assigning function
 * callbacks on #pkt_hook[#ofp_hook_id]
 */
enum ofp_hook_id {
	OFP_HOOK_LOCAL = 0,	/**< Registers a function to handle all packets
					with processing at IP level */
	OFP_HOOK_LOCAL_IPv4,	/**< Registers a function to handle all packets
					with processing at IPv4 level */
	OFP_HOOK_LOCAL_IPv6,	/**< Registers a function to handle all packets
					with processing at IPv6 level */
	OFP_HOOK_LOCAL_UDPv4,	/**< Registers a function to handle all packets
					with processing at UDP IPv4 level */
	OFP_HOOK_LOCAL_UDPv6,	/**< Registers a function to handle all packets
					with processing at UDP IPv6 level */
	OFP_HOOK_FWD_IPv4,	/**< Registers a function to handle all IPv4
					packets	that require forwarding */
	OFP_HOOK_FWD_IPv6,	/**< Registers a function to handle all IPv6
					packets	that require forwarding */
	OFP_HOOK_GRE,		/**< Registers a function to handle GRE tunnels
					not registered to OFP */
	OFP_HOOK_OUT_IPv4,	/**< Registers a function to handle all IPv4
					packets to be sent by OFP*/
	OFP_HOOK_OUT_IPv6,	/**< Registers a function to handle all IPv6
					packets to be sent by OFP*/
	OFP_HOOK_MAX
};

/**
 * @brief Parameter value received as argument in hook callback
 */
enum ofp_hook_local_par {
	IS_IPV4 = 0,	/**< IPv4 packet received in hook*/
	IS_IPV6,	/**< IPv6 packet received in hook*/
	IS_IPV4_UDP,	/**< UDP over IPv4 packet received in hook*/
	IS_IPV6_UDP	/**< UDP over IPv6 packet received in hook*/
};

#endif /* __OFP_HOOK_H__ */
