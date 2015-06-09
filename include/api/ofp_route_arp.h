/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef __OFP_ROUTE_ARP_H__
#define __OFP_ROUTE_ARP_H__

/* ROUTE: ADD/DEL*/

struct ofp_route_msg {
	uint32_t type;
#define OFP_ROUTE_ADD 1
#define OFP_ROUTE_DEL 2
#define OFP_MOBILE_ROUTE_ADD 3
#define OFP_MOBILE_ROUTE_DEL 4
#define OFP_LOCAL_INTERFACE_ADD 5
#define OFP_LOCAL_INTERFACE_DEL 6
#define OFP_ROUTE6_ADD 7
#define OFP_ROUTE6_DEL 8
	uint16_t vrf;
	uint32_t dst;
	uint32_t masklen;
	uint32_t gw;
	uint32_t port;
	uint16_t vlan;
	uint8_t  dst6[16];
	uint8_t  gw6[16];
};

#define SET_ROUTE(_type, _vrf, _dst, _mlen, _gw, _port, _vlan) do {     \
		struct ofp_route_msg msg;                                    \
		msg.type = _type;                                              \
		msg.vrf = _vrf;                                                \
		msg.dst = _dst;                                                \
		msg.masklen = _mlen;                                           \
		msg.gw = _gw;                                                  \
		msg.port = _port;                                              \
		msg.vlan = _vlan;                                              \
		ofp_set_route(&msg);                                         \
	} while (0)

#define SET_ROUTE6(_type, _dst6, _prefix, _gw6, _port, _vlan) do {	\
		struct ofp_route_msg msg;				\
		memset(&msg, 0, sizeof(msg));				\
		msg.type = _type;					\
		msg.vrf = 0;						\
		memcpy(msg.dst6, _dst6, 16);				\
		msg.masklen = _prefix;					\
		memcpy(msg.gw6, _gw6, 16);				\
		msg.port = _port;					\
		msg.vlan = _vlan;					\
		ofp_set_route(&msg);					\
	} while (0)

int32_t ofp_set_route(struct ofp_route_msg *msg);

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

#endif /* __OFP_ROUTE_ARP_H__ */
