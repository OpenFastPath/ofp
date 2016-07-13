/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef __OFP_ROUTE_ARP_H__
#define __OFP_ROUTE_ARP_H__

#include <stdint.h>
#include <string.h>

#include "ofp_log.h"

#if __GNUC__ >= 4
#pragma GCC visibility push(default)
#endif

/* ROUTE: ADD/DEL*/

struct ofp_route_msg {
	uint32_t type;
#define OFP_ROUTE_ADD		1
#define OFP_ROUTE_DEL		2
#define OFP_MOBILE_ROUTE_ADD	3
#define OFP_MOBILE_ROUTE_DEL	4
#define OFP_LOCAL_INTERFACE_ADD	5
#define OFP_LOCAL_INTERFACE_DEL	6
#define OFP_ROUTE6_ADD		7
#define OFP_ROUTE6_DEL		8
	uint32_t flags;
#define	OFP_RTF_NET		0x1	/* route usable */
#define	OFP_RTF_GATEWAY		0x2	/* destination is a gateway */
#define	OFP_RTF_HOST		0x4	/* host entry (lb, p2p)(net otherwise)*/
#define	OFP_RTF_REJECT		0x8	/* host or net unreachable */
#define	OFP_RTF_BLACKHOLE	0x1000	/* just discard pkts (during updates) */
#define	OFP_RTF_LOCAL		0x200000/* route represents a local address */
#define	OFP_RTF_BROADCAST	0x400000/* route represents a bcast address */
#define	OFP_RTF_MULTICAST	0x800000/* route represents a mcast address */
	uint32_t dst;
	uint32_t masklen;
	uint32_t gw;
	uint32_t port;
	uint16_t vlan;
	uint16_t vrf;
	uint8_t  dst6[16];
	uint8_t  gw6[16];
};

int32_t ofp_set_route_msg(struct ofp_route_msg *msg);

static inline int32_t ofp_set_route_params(uint32_t type, uint16_t vrf,
					   uint16_t vlan, uint32_t port,
					   uint32_t dst, uint32_t masklen,
					   uint32_t gw, uint32_t flags)
{
	struct ofp_route_msg msg;

#if defined(OFP_DEBUG)
	if (type == OFP_ROUTE6_ADD || type == OFP_ROUTE6_DEL) {
		OFP_ERR("Incompatible type=%d\n", type);
		return -1;
	}
#endif
	msg.type    = type;
	msg.flags   = flags;
	msg.vrf     = vrf;
	msg.vlan    = vlan;
	msg.port    = port;

	msg.dst     = dst;
	msg.masklen = masklen;
	msg.gw      = gw;

	return ofp_set_route_msg(&msg);
}

static inline int32_t ofp_set_route6_params(uint32_t type, uint16_t vrf,
					    uint16_t vlan, uint32_t port,
					    const uint8_t dst6[],
					    uint32_t masklen,
					    const uint8_t gw6[],
					    uint32_t flags)
{
	struct ofp_route_msg msg;

#if defined(OFP_DEBUG)
	if (type != OFP_ROUTE6_ADD && type != OFP_ROUTE6_DEL) {
		OFP_ERR("Incompatible type=%d\n", type);
		return -1;
	}
#endif
	msg.type    = type;
	msg.flags   = flags;
	msg.vrf     = vrf;
	msg.vlan    = vlan;
	msg.port    = port;

	if (dst6) {
		memcpy(msg.dst6, dst6,
		       (masklen > 0) ? (1 + ((masklen - 1) >> 3)) : 0);
	}
	msg.masklen = masklen;
	if (gw6) {
		memcpy(msg.gw6, gw6, 16);
	}

	return ofp_set_route_msg(&msg);
}

/* ROUTE: SHOW */

#define OFP_SHOW_ARP        0
#define OFP_SHOW_ROUTES     1
void ofp_show_routes(int fd, int what);

/* ROUTE operations */
struct ofp_nh_entry *ofp_get_next_hop(uint16_t vrf,
		uint32_t addr, uint32_t *flags);
struct ofp_nh6_entry *ofp_get_next_hop6(uint16_t vrf,
		uint8_t *addr, uint32_t *flags);

uint16_t ofp_get_probable_vlan(int port, uint32_t addr);

/* ARP */
struct ofp_ifnet;
int ofp_add_mac(struct ofp_ifnet *dev, uint32_t addr, uint8_t *mac);
int ofp_get_mac(struct ofp_ifnet *dev, uint32_t addr, uint8_t *mac_out);
int ofp_del_mac(struct ofp_ifnet *dev, uint32_t addr, uint8_t *mac);
void ofp_add_mac6(struct ofp_ifnet *dev, uint8_t *addr, uint8_t *mac);

#if __GNUC__ >= 4
#pragma GCC visibility pop
#endif

#endif /* __OFP_ROUTE_ARP_H__ */
