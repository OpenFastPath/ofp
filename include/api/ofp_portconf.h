/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef __OFP_PORTCONF_H__
#define __OFP_PORTCONF_H__

#include <odp_api.h>

#if __GNUC__ >= 4
#pragma GCC visibility push(default)
#endif

#define OFP_IFNAMSIZ  32

struct ofp_ifnet;

/* Interfaces: UP/DOWN */

const char *ofp_config_interface_up_v4(int port, uint16_t vlan, uint16_t vrf,
			uint32_t addr, int masklen);
const char *ofp_config_interface_up_v6(int port, uint16_t vlan,
			uint8_t *addr, int masklen);
const char *ofp_config_interface_up_tun(int port, uint16_t greid,
					  uint16_t vrf, uint32_t tun_loc,
					  uint32_t tun_rem, uint32_t p2p,
					  uint32_t addr, int mlen);
const char *ofp_config_interface_up_vxlan(uint16_t vrf, uint32_t addr, int mlen,
					  int vni, uint32_t group,
					  int port, int vlan);
const char *ofp_config_interface_up_local(uint16_t id, uint16_t vrf,
					  uint32_t addr, int masklen);
const char *ofp_config_interface_up_local_v6(uint16_t id,
					uint8_t *addr, int masklen);
const char *ofp_config_interface_down(int port, uint16_t vlan);

const char *ofp_config_interface_add_ip_v4(int port, uint16_t vlan,
								uint16_t vrf, uint32_t addr, int masklen);
const char *ofp_config_interface_del_ip_v4(int port, uint16_t vlan,
								int vrf, uint32_t addr, int masklen);

/* Interfaces: SHOW */
void ofp_show_interfaces(int fd);

/* Show ifnet ips */
void ofp_show_ifnet_ip_addrs(int fd);

/* Interfaces: operations*/
int ofp_get_num_ports(void);

struct ofp_ifnet *ofp_get_ifnet(int port, uint16_t vlan);
struct ofp_ifnet *ofp_get_create_ifnet(int port, uint16_t vlan);
int ofp_delete_ifnet(int port, uint16_t vlan);
struct ofp_ifnet *ofp_vlan_alloc(void);

odp_pktio_t ofp_port_pktio_get(int port);

/* LINUX interface lookup table*/
struct ofp_ifnet *ofp_get_ifnet_by_linux_ifindex(int ix);
/* Finds the node interface by the local ip assigned */
struct ofp_ifnet *ofp_get_ifnet_match(uint32_t ip,
					uint16_t vrf, uint16_t vlan);

/* Interface ODP queues */
struct ofp_ifnet *ofp_get_ifnet_pktio(odp_pktio_t pktio);
odp_queue_t ofp_pktio_spq_get(odp_pktio_t pktio);
odp_queue_t ofp_pktio_loopq_get(odp_pktio_t pktio);

enum ofp_portconf_ip_type {
	OFP_PORTCONF_IP_TYPE_IP_ADDR = 0,
	OFP_PORTCONF_IP_TYPE_P2P,
	OFP_PORTCONF_IP_TYPE_TUN_LOCAL,
	OFP_PORTCONF_IP_TYPE_TUN_REM
};

uint32_t ofp_port_get_ipv4_addr(int port, uint16_t vlan,
				  enum ofp_portconf_ip_type type);

#if __GNUC__ >= 4
#pragma GCC visibility pop
#endif

#endif /* __OFP_PORTCONF_H__ */
