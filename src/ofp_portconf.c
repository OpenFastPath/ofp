/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#include "ofpi.h"
#include "ofpi_portconf.h"
#include "ofpi_route.h"
#include "ofpi_util.h"
#include "ofpi_avl.h"

#include "ofpi_queue.h"
#include "ofpi_ioctl.h"
#include "ofpi_if_vxlan.h"
#include "ofpi_ifnet.h"
#include "ofpi_tree.h"
#include "ofpi_sysctl.h"
#include "ofpi_in_var.h"
#include "ofpi_log.h"
#include "ofpi_netlink.h"
#include "ofpi_igmp_var.h"

#define SHM_NAME_PORTS "OfpPortconfShMem"
#define SHM_NAME_PORT_LOCKS "OfpPortconfLocksShMem"
#define SHM_NAME_VLAN "OfpVlanconfShMem"


#ifdef SP
#define NUM_LINUX_INTERFACES 512
#endif /*SP*/

#define PORT_UNDEF 0xFFFF
void ofp_ifnet_print_ip_addrs(struct ofp_ifnet *dev);
/*
 * Shared data
 */
struct ofp_portconf_mem {
	struct ofp_ifnet ofp_ifnet_data[NUM_PORTS];
	odp_atomic_u32_t free_port;
	int ofp_num_ports;

	struct ofp_in_ifaddrhead in_ifaddrhead;
#ifdef INET6
	struct ofp_in_ifaddrhead in_ifaddr6head;
#endif /* INET6 */

#ifdef SP
	struct {
		uint16_t port;
		uint16_t vlan;
	} linux_interface_table[NUM_LINUX_INTERFACES];
#endif /* SP */
};

struct ofp_vlan_mem {
	struct ofp_ifnet *free_ifnet_list;
	odp_rwlock_t vlan_mtx;
	struct ofp_ifnet vlan_ifnet[0];
};

/*
 * Data per core
 */
static __thread struct ofp_portconf_mem *shm;
struct ofp_ifnet_locks_str  *ofp_ifnet_locks_shm;

static __thread struct ofp_vlan_mem *vlan_shm;

/*Wrapper functions over AVL tree*/
static void *new_vlan(
		int (*compare_fun)(void *compare_arg, void *a, void *b),
		void *compare_arg)
{
	return avl_tree_new(compare_fun, compare_arg);
}

static void free_vlan(void *root, int (*free_key_fun)(void *arg))
{
	avl_tree_free((avl_tree *)root, free_key_fun);
}

static int vlan_iterate_inorder(void *root,
			int (*iterate_fun)(void *key, void *iter_arg),
			void *iter_arg)
{
	return avl_iterate_inorder(root, iterate_fun, iter_arg);
}

int vlan_ifnet_insert(void *root, void *elem)
{
	return avl_insert((avl_tree *)root, elem);
}

int vlan_ifnet_delete(void *root, void *elem,
					int (*free_key_fun)(void *arg))
{
	return avl_delete(root, elem, free_key_fun);
}

int ofp_vlan_get_by_key(
	void *root,
	void *key,
	void **value_address
	)
{
	return avl_get_by_key(root, key, value_address);
}

int ofp_get_num_ports(void)
{
	return shm->ofp_num_ports;
}

static int vlan_ifnet_compare(void *compare_arg, void *a, void *b)
{
	struct ofp_ifnet *a1 = a;
	struct ofp_ifnet *b1 = b;

	(void)compare_arg;

	return (a1->vlan - b1->vlan);
}

static int vlan_match_ip(void *key, void *iter_arg)
{
	struct ofp_ifnet *iface = key;
	uint32_t ip = *((uint32_t *)iter_arg);

	if (-1 != ofp_ifnet_ip_find(iface, ip))
		return iface->vlan;
	else
		return 0;
}

int ofp_free_port_alloc(void)
{
	int port = (int)odp_atomic_fetch_inc_u32(&shm->free_port);
	if (port >= OFP_FP_INTERFACE_MAX) {
		OFP_ERR("Interfaces are depleted");
		return -1;
	}
	return port;
}

struct ofp_ifnet *ofp_vlan_alloc(void)
{
	odp_rwlock_write_lock(&vlan_shm->vlan_mtx);
	struct ofp_ifnet *vlan = vlan_shm->free_ifnet_list;
	if (vlan_shm->free_ifnet_list) {
		vlan_shm->free_ifnet_list = vlan_shm->free_ifnet_list->next;
	}
	odp_rwlock_write_unlock(&vlan_shm->vlan_mtx);

	if (vlan == NULL) {
		OFP_ERR("Cannot allocate vlan!");
		return (NULL);
	}

	return vlan;
}

static void ofp_vlan_free(struct ofp_ifnet *vlan)
{
	odp_rwlock_write_lock(&vlan_shm->vlan_mtx);
	vlan->next = vlan_shm->free_ifnet_list;
	vlan_shm->free_ifnet_list = vlan;
	odp_rwlock_write_unlock(&vlan_shm->vlan_mtx);
}

static void print_eth_stats (odp_pktio_stats_t stats, int fd)
{
	ofp_sendf(fd,
		"\tRX: bytes:%lu packets:%lu dropped:%lu errors:%lu unknown:%lu\r\n",
		stats.in_octets,
		stats.in_ucast_pkts,
		stats.in_discards,
		stats.in_errors,
		stats.in_unknown_protos);

	ofp_sendf(fd,
		"\tTX: bytes:%lu packets:%lu dropped:%lu error:%lu\r\n\r\n",
		stats.out_octets,
		stats.out_ucast_pkts,
		stats.out_discards,
		stats.out_errors);
}

static int iter_vlan(void *key, void *iter_arg)
{
	struct ofp_ifnet *iface = key;
	char buf[16];
	int fd = *((int *)iter_arg);
	odp_pktio_stats_t stats;
	int res;
	uint32_t mask = ~0;


	res = odp_pktio_stats(iface->pktio, &stats);

	mask = odp_cpu_to_be_32(mask << (32 - iface->ip_addr_info[0].masklen));

	if (ofp_if_type(iface) == OFP_IFT_GRE && iface->vlan) {
#ifdef SP
		ofp_sendf(fd, "gre%d	(%d) slowpath: %s\r\n", iface->vlan,
			    iface->linux_index,
			    iface->sp_status ? "on" : "off");
#else
		ofp_sendf(fd, "gre%d\r\n", iface->vlan);
#endif /* SP */

		if (iface->vrf)
			ofp_sendf(fd, "	VRF: %d\r\n", iface->vrf);

		ofp_sendf(fd,
			"	Link encap:Ethernet	HWaddr: %s\r\n"
			"	inet addr:%s	P-t-P:%s	Mask:%s\r\n"
#ifdef INET6
			"	inet6 addr: %s\r\n"
#endif /* INET6 */
			"	MTU: %d\r\n",
			ofp_print_mac(iface->mac),
			ofp_print_ip_addr(iface->ip_addr_info[0].ip_addr),
			ofp_print_ip_addr(iface->ip_p2p),
			ofp_print_ip_addr(mask),
#ifdef INET6
			ofp_print_ip6_addr(iface->link_local),
#endif /* INET6 */
			iface->if_mtu);

		ofp_sendf(fd,
			"	Local: %s	Remote: %s\r\n",
			ofp_print_ip_addr(iface->ip_local),
			ofp_print_ip_addr(iface->ip_remote));
		if (res == 0)
			print_eth_stats(stats, fd);
		else
			ofp_sendf(fd, "\r\n");
		return 0;
	} else if (ofp_if_type(iface) == OFP_IFT_GRE && !iface->vlan) {
		ofp_sendf(fd, "gre%d\r\n"
				"	Link not configured\r\n\r\n",
				iface->vlan);
		return 0;
	}

	if (ofp_if_type(iface) == OFP_IFT_VXLAN) {
#ifdef SP
		ofp_sendf(fd, "vxlan%d	(%d) slowpath: %s\r\n", iface->vlan,
			    iface->linux_index,
			    iface->sp_status ? "on" : "off");
#else
		ofp_sendf(fd, "vxlan%d\r\n", iface->vlan);
#endif /* SP */

		if (iface->vrf)
			ofp_sendf(fd, "	VRF: %d\r\n", iface->vrf);

		ofp_sendf(fd,
			"	Link encap:Ethernet	HWaddr: %s\r\n"
			"	inet addr:%s	Bcast:%s	Mask:%s\r\n"
#ifdef INET6
			"	inet6 addr: %s\r\n"
#endif /* INET6 */
			"	Group:%s	Iface:%s\r\n"
			"	MTU: %d\r\n",
			  ofp_print_mac(iface->mac),
			  ofp_print_ip_addr(iface->ip_addr_info[0].ip_addr),
			  ofp_print_ip_addr(iface->ip_addr_info[0].bcast_addr),
			  ofp_print_ip_addr(mask),
#ifdef INET6
			  ofp_print_ip6_addr(iface->link_local),
#endif /* INET6 */
			  ofp_print_ip_addr(iface->ip_p2p),
			  ofp_port_vlan_to_ifnet_name(iface->physport,
						      iface->physvlan),
			  iface->if_mtu);
		if (res == 0)
			print_eth_stats(stats, fd);
		else
			ofp_sendf(fd, "\r\n");
		return 0;
	}

	if (ofp_if_type(iface) == OFP_IFT_LOOP) {
#ifdef SP
		ofp_sendf(fd, "lo%d  (%d) slowpath: %s\r\n", iface->vlan,
			    iface->linux_index,
			    iface->sp_status ? "on" : "off");
#else
		ofp_sendf(fd, "lo%d\r\n", iface->vlan);
#endif /* SP */

		if (iface->vrf)
			ofp_sendf(fd, "	VRF: %d\r\n", iface->vrf);

		ofp_sendf(fd,
			"	Link encap:loopback\r\n"
			"	inet addr:%s	Bcast:%s	Mask:%s\r\n"
#ifdef INET6
			"	inet6 addr: %s/%d\r\n"
#endif /* INET6 */
			"	MTU: %d\r\n",
			  ofp_print_ip_addr(iface->ip_addr_info[0].ip_addr),
			  ofp_print_ip_addr(iface->ip_addr_info[0].bcast_addr),
			  ofp_print_ip_addr(mask),
#ifdef INET6
			  ofp_print_ip6_addr(iface->ip6_addr),
			  iface->ip6_prefix,
#endif /* INET6 */
			  iface->if_mtu);
		if (res == 0)
			print_eth_stats(stats, fd);
		else
			ofp_sendf(fd, "\r\n");
		return 0;
	}

	snprintf(buf, sizeof(buf), ".%d", iface->vlan);

	if (ofp_has_mac(iface->mac)) {
#ifdef SP
		ofp_sendf(fd,
			"%s%d%s	(%d) (%s) slowpath: %s\r\n",
			OFP_IFNAME_PREFIX,
			iface->port,
			iface->vlan ? buf : "",
			iface->linux_index,
		        iface->if_name,
			iface->sp_status ? "on" : "off");
#else
		ofp_sendf(fd,
			"%s%d%s	(%s)\r\n",
			OFP_IFNAME_PREFIX,
			iface->port,
			iface->vlan ? buf : "",
			iface->if_name);
#endif /* SP */

		if (iface->vrf)
			ofp_sendf(fd, "	VRF: %d\r\n", iface->vrf);

		ofp_sendf(fd,
			"	Link encap:Ethernet	HWaddr: %s\r\n",
			ofp_print_mac(iface->mac));

		if (iface->ip_addr_info[0].ip_addr)
			ofp_sendf(fd,
				"	inet addr:%s	Bcast:%s	Mask:%s\r\n",
				ofp_print_ip_addr(iface->ip_addr_info[0].ip_addr),
				ofp_print_ip_addr(iface->ip_addr_info[0].bcast_addr),
				ofp_print_ip_addr(mask));

#ifdef INET6
		ofp_sendf(fd,
			"	inet6 addr: %s Scope:Link\r\n",
			ofp_print_ip6_addr(iface->link_local));

		if (ofp_ip6_is_set(iface->ip6_addr))
			ofp_sendf(fd,
				"	inet6 addr: %s/%d\r\n",
				ofp_print_ip6_addr(iface->ip6_addr),
				iface->ip6_prefix);
#endif /* INET6 */

		ofp_sendf(fd,
			"	MTU: %d\r\n",
			iface->if_mtu);
		if (res == 0)
			print_eth_stats(stats, fd);
		else
			ofp_sendf(fd, "\r\n");
	} else {
		ofp_sendf(fd, "%s%d%s\r\n"
			"	Link not configured\r\n\r\n",
			OFP_IFNAME_PREFIX,
			iface->port, iface->vlan ? buf : "");
	}

	return 0;
}

void ofp_show_interfaces(int fd)
{
	int i;

	/* fp interfaces */
	for (i = 0; i < OFP_FP_INTERFACE_MAX; i++) {
		iter_vlan(&shm->ofp_ifnet_data[i], &fd);
		vlan_iterate_inorder(shm->ofp_ifnet_data[i].vlan_structs,
					iter_vlan, &fd);
	}

	/* gre interfaces */
	if (avl_get_first(shm->ofp_ifnet_data[GRE_PORTS].vlan_structs))
		vlan_iterate_inorder(
			shm->ofp_ifnet_data[GRE_PORTS].vlan_structs,
			iter_vlan, &fd);
	else
		ofp_sendf(fd, "gre\r\n"
				"	Link not configured\r\n\r\n");

	/* vxlan interfaces */
	if (avl_get_first(shm->ofp_ifnet_data[VXLAN_PORTS].vlan_structs))
		vlan_iterate_inorder(
			shm->ofp_ifnet_data[VXLAN_PORTS].vlan_structs,
			iter_vlan, &fd);
	else
		ofp_sendf(fd, "vxlan\r\n"
				"	Link not configured\r\n\r\n");
	/* local interfaces */
	if (avl_get_first(shm->ofp_ifnet_data[LOCAL_PORTS].vlan_structs))
		vlan_iterate_inorder(
			shm->ofp_ifnet_data[LOCAL_PORTS].vlan_structs,
			iter_vlan, &fd);
	else
		ofp_sendf(fd, "lo\r\n"
				"	Link not configured\r\n\r\n");
}

static int iter_vlan_2(void *key, void *iter_arg)
{
	struct ofp_ifnet *iface = key;
	int fd = *((int *)iter_arg);

	ofp_ifnet_print_ip_info(fd, iface);

	return 0;
}

void ofp_show_ifnet_ip_addrs(int fd)
{
	int i;
	for (i = 0; i < OFP_FP_INTERFACE_MAX; i++) {
		iter_vlan_2(&shm->ofp_ifnet_data[i], &fd);
		vlan_iterate_inorder(shm->ofp_ifnet_data[i].vlan_structs,
				iter_vlan_2, &fd);
	}
}

int free_key(void *key)
{
	ofp_vlan_free(key);
	return 1;
}

#ifdef SP
static int exec_sys_call_depending_on_vrf(const char *cmd, uint16_t vrf)
{
	char buf[PATH_MAX];
	int netns, ret;

	OFP_DBG("system(%s) vrf=%d", cmd, vrf);
	if (vrf == 0) {
		return system(cmd);
	}

	/* Does vrf exist? */
	snprintf(buf, sizeof(buf), "/var/run/netns/vrf%d", vrf);
	netns = open(buf, O_RDONLY | O_CLOEXEC);
	if (netns < 0) {
		/* Create a vrf */
		OFP_INFO("Creating network namespace 'vrf%d'...", vrf);
		snprintf(buf, sizeof(buf), "ip netns add vrf%d", vrf);
		ret = system(buf);
		if (ret < 0)
			OFP_WARN("System call failed: '%s'", buf);
		ofp_create_ns_socket(vrf);
	}
	close(netns);

	/* Dummy cmd to create a new namespace? */
	if (cmd == NULL || cmd[0] == 0)
		return 0;

	snprintf(buf, sizeof(buf), "ip netns exec vrf%d %s", vrf, cmd);
	ret = system(buf);
	if (ret < 0)
		OFP_WARN("System call failed: '%s'", buf);
	return ret;
}
#endif /* SP */

const char *ofp_config_interface_up_v4(int port, uint16_t vlan, uint16_t vrf,
			uint32_t addr, int masklen)
{
#ifdef SP
	char cmd[200];
	int ret = 0;
	uint32_t mask_t;
#endif /* SP */
	struct ofp_ifnet *data;
	uint32_t mask;

#ifdef SP
	(void)ret;
#endif /*SP*/
	if (port < 0 || port >= OFP_FP_INTERFACE_MAX)
		return "Wrong port number";

	mask = ~0;
	mask = odp_cpu_to_be_32(mask << (32 - masklen));

	data = ofp_get_ifnet(port, vlan);

	if (data && data->vrf != vrf) {
#ifdef SP
		if (vlan == 0 && data->vrf == 0) {
			/* Create vrf in not exist using dummy call */
			exec_sys_call_depending_on_vrf("", vrf);
			/* Move to vrf (can be done only once!) */
			snprintf(cmd, sizeof(cmd),
				 "ip link set %s netns vrf%d",
				 ofp_port_vlan_to_ifnet_name(port, 0), vrf);
			ret = exec_sys_call_depending_on_vrf(cmd, 0);
		}
#endif /* SP */

		ofp_config_interface_down(data->port, data->vlan);
		data = ofp_get_create_ifnet(port, vlan);
	}

	if (vlan) {
		if (data == NULL) {
			data = ofp_get_create_ifnet(port, vlan);
			data->if_type = OFP_IFT_ETHER;
#ifdef SP
			char *iname = ofp_port_vlan_to_ifnet_name(port, 0);
			snprintf(cmd, sizeof(cmd),
				 "ip link add name %s.%d link %s type vlan id %d",
				 iname, vlan, iname, vlan);
			ret = exec_sys_call_depending_on_vrf(cmd, 0);

			if (vrf) {
				/* Create vrf if not exist using dummy call */
				exec_sys_call_depending_on_vrf("", vrf);
				/* Move to vrf */
				snprintf(cmd, sizeof(cmd),
					 "ip link set %s.%d netns vrf%d",
					 iname, vlan, vrf);
				ret = exec_sys_call_depending_on_vrf(cmd, 0);
			}
#endif /* SP */
		} else {
			ofp_set_route_params(OFP_ROUTE_DEL, data->vrf, vlan, port,
					data->ip_addr_info[0].ip_addr, data->ip_addr_info[0].masklen, 0, 0);
			ofp_set_route_params(OFP_ROUTE_DEL, data->vrf, vlan, port,
					data->ip_addr_info[0].ip_addr, 32, 0, 0);
		}
		data->vrf = vrf;
		ofp_set_route_params(OFP_ROUTE_ADD, data->vrf, vlan, port,
				addr, 32, 0,
				OFP_RTF_LOCAL);
		ofp_set_route_params(OFP_ROUTE_ADD, data->vrf, vlan, port,
				addr & mask, masklen, 0, OFP_RTF_NET);
		ofp_set_first_ifnet_addr(data, addr, addr | ~mask, masklen);
#ifdef SP
		if (vrf == 0)
			data->sp_status = OFP_SP_UP;
		else
			data->sp_status = OFP_SP_DOWN;

		mask_t = odp_be_to_cpu_32(mask);
		snprintf(cmd, sizeof(cmd), "ifconfig %s %s netmask %d.%d.%d.%d up",
			 ofp_port_vlan_to_ifnet_name(port, vlan),
			 ofp_print_ip_addr(addr),
			(uint8_t)(mask_t >> 24),
			(uint8_t)(mask_t >> 16),
			(uint8_t)(mask_t >> 8),
			(uint8_t)mask_t);

		ret = exec_sys_call_depending_on_vrf(cmd, vrf);
#endif /* SP */
	} else {
		if (data->ip_addr_info[0].ip_addr) {
			ofp_set_route_params(OFP_ROUTE_DEL, data->vrf, 0 /*vlan*/,
					port, data->ip_addr_info[0].ip_addr, data->ip_addr_info[0].masklen,
					0, 0);
			ofp_set_route_params(OFP_ROUTE_DEL, data->vrf, 0 /*vlan*/,
					port, data->ip_addr_info[0].ip_addr, 32,
					0, 0);
		}

		data->vrf = vrf;

		/* Add interface to the if_addr v4 queue */
		ofp_ifaddr_elem_add(data);
#ifdef INET6
		ofp_mac_to_link_local(data->mac, data->link_local);
#endif /* INET6 */

		ofp_set_route_params(OFP_ROUTE_ADD, data->vrf, 0 /*vlan*/, port,
				addr, 32, 0, OFP_RTF_LOCAL);
		ofp_set_route_params(OFP_ROUTE_ADD, data->vrf, 0 /*vlan*/, port,
				addr & mask, masklen, 0, OFP_RTF_NET);
		ofp_set_first_ifnet_addr(data, addr, addr | ~mask, masklen);

#ifdef SP
		if (vrf == 0)
			data->sp_status = OFP_SP_UP;
		else
			data->sp_status = OFP_SP_DOWN;

		mask_t = odp_be_to_cpu_32(mask);
		snprintf(cmd, sizeof(cmd), "ifconfig %s %s netmask %d.%d.%d.%d up",
			ofp_port_vlan_to_ifnet_name(port, 0),
			ofp_print_ip_addr(addr),
			(uint8_t)(mask_t >> 24),
			(uint8_t)(mask_t >> 16),
			(uint8_t)(mask_t >> 8),
			(uint8_t)mask_t);
		ret = exec_sys_call_depending_on_vrf(cmd, vrf);
#endif /* SP */
	}

	return NULL;
}

const char *ofp_config_interface_add_ip_v4(int port, uint16_t vlan, uint16_t vrf,
						uint32_t addr, int masklen)
{
#ifdef SP
	char cmd[200];
	int ret = 0;
#endif /* SP */
	uint32_t mask;
	struct ofp_ifnet *data;
	int idx;
	if (port < 0 || port >= OFP_FP_INTERFACE_MAX)
		return "Wrong port number";

	data = ofp_get_ifnet(port, vlan);
	if (NULL == data)
		return "Invalid interface";
	idx = ofp_ifnet_ip_find(data, addr);
	if (-1 == idx) {
		mask = ~0;
		mask = odp_cpu_to_be_32(mask << (32 - masklen));
		ofp_set_route_params(OFP_ROUTE_ADD, vrf, vlan, port,
			addr, 32, 0,
			OFP_RTF_LOCAL);
		ofp_set_route_params(OFP_ROUTE_ADD, vrf, vlan, port,
			addr & mask, masklen, 0, OFP_RTF_NET);

		idx = ofp_ifnet_ip_find_update_fields(data, addr, masklen, addr | ~mask);
		if (-1 == idx) {
			ofp_set_route_params(OFP_ROUTE_DEL, vrf, vlan, port,
				addr & mask, masklen, 0, 0);
			ofp_set_route_params(OFP_ROUTE_DEL, vrf, vlan, port,
				addr, 32, 0, 0);

			return "Failed to add IP address";
		}
#ifdef SP
		snprintf(cmd, sizeof(cmd), "ip address add %s/%d broadcast %s dev %s",
			ofp_print_ip_addr(addr), masklen, ofp_print_ip_addr(addr | ~mask),
			ofp_port_vlan_to_ifnet_name(port, vlan));
		ret = exec_sys_call_depending_on_vrf(cmd, vrf);
		if (0 != ret)
			OFP_INFO("Command %s failed\n", cmd);
#endif
	} else
		return "Address already added";

	return NULL;
}

const char *ofp_config_interface_del_ip_v4(int port, uint16_t vlan, int vrf,
		uint32_t addr, int masklen)
{
#ifdef SP
	char cmd[200];
	int ret = 0;
#endif /* SP */
	struct ofp_ifnet *data;
	int idx;
	static char msg[64];

	(void)vrf; /* Suppress unused parameter warning when SP is not enabled. */

	if (port < 0 || port >= OFP_FP_INTERFACE_MAX)
		return "Wrong port number";

	data = ofp_get_ifnet(port, vlan);
	if (NULL == data)
		return "Invalid interface";

	idx = ofp_ifnet_ip_find(data, addr);
	if (-1 != idx) {
		uint32_t mask = ~0;
		mask = odp_cpu_to_be_32(mask << (32 - data->ip_addr_info[idx].masklen));

		if (masklen != data->ip_addr_info[idx].masklen) {
			memset(msg, 0, sizeof(msg));
			snprintf(msg, sizeof(msg) , "Provided %d differs from the %d saved\n", masklen, data->ip_addr_info[idx].masklen);
			return msg;
		}
		ofp_set_route_params(OFP_ROUTE_DEL, data->vrf, data->vlan, port,
			addr & mask , masklen, 0, 0);
		ofp_set_route_params(OFP_ROUTE_DEL, data->vrf, data->vlan, port,
			addr, 32, 0, 0);

		idx = ofp_ifnet_ip_find(data, addr);
		if (-1 != idx) {
			memset(msg, 0, sizeof(msg));
			snprintf(msg, sizeof(msg) , "Failed to remove %s address\n", ofp_print_ip_addr(addr));
			return msg;
		}
#ifdef SP
		snprintf(cmd, sizeof(cmd),
			"ip addr del %s/%d dev %s",
			ofp_print_ip_addr(addr),
			masklen, ofp_port_vlan_to_ifnet_name(port, vlan));
		ret = exec_sys_call_depending_on_vrf(cmd, vrf);
		if (0 != ret)
			OFP_INFO("Command %s failed\n", cmd);
#endif
		if (0 == data->ip_addr_info[0].ip_addr) {
			/* Remove interface from the if_addr v4 queue */
			ofp_ifaddr_elem_del(data);
		}
	} else {
		return "Address not found!";
	}

	return NULL;
}

const char *ofp_config_interface_up_tun(int port, uint16_t greid,
					  uint16_t vrf, uint32_t tun_loc,
					  uint32_t tun_rem, uint32_t p2p,
					  uint32_t addr, int mlen)
{
#ifdef SP
	char cmd[200];
	int ret = 0, new = 0;
#endif /* SP */
	struct ofp_ifnet *data, *dev_root;

#ifdef SP
	(void)ret;
	(void)new;
#endif /*SP*/

	if (port != GRE_PORTS || greid == 0)
		return "Wrong port number or tunnel ID.";

	dev_root = ofp_get_ifnet_by_ip(tun_loc, vrf);
	if (dev_root == NULL)
		return "Tunnel local ip not configured.";

	data = ofp_get_ifnet(port, greid);

	if (data && data->vrf != vrf) {
		ofp_config_interface_down(data->port, data->vlan);
		data = NULL;
	}

	if (data == NULL) {
#ifdef SP
		new = 1;
#endif /* SP */
		data = ofp_get_create_ifnet(port, greid);
		data->if_type = OFP_IFT_GRE;
	} else {
		ofp_set_route_params(OFP_ROUTE_DEL, data->vrf, greid, port,
				     data->ip_p2p, data->ip_addr_info[0].masklen, 0, 0);
#ifdef SP
		snprintf(cmd, sizeof(cmd),
			 "ip addr del dev %s %s peer %s",
			 ofp_port_vlan_to_ifnet_name(port, greid),
			 ofp_print_ip_addr(data->ip_addr_info[0].ip_addr),
			 ofp_print_ip_addr(data->ip_p2p));
		ret = exec_sys_call_depending_on_vrf(cmd, data->vrf);
#endif /* SP */
	}

	data->vrf = vrf;
	data->ip_local = tun_loc;
	data->ip_remote = tun_rem;
	data->ip_p2p = p2p;
	data->ip_addr_info[0].ip_addr = addr;
	data->ip_addr_info[0].masklen = mlen;
	data->if_mtu = dev_root->if_mtu - sizeof(struct ofp_greip);

	ofp_set_route_params(OFP_ROUTE_ADD, data->vrf, greid, port,
			     data->ip_p2p, data->ip_addr_info[0].masklen, 0,
			     OFP_RTF_HOST);

#ifdef SP
	if (vrf == 0)
		data->sp_status = OFP_SP_UP;
	else
		data->sp_status = OFP_SP_DOWN;

	snprintf(cmd, sizeof(cmd),
		 "ip tunnel %s %s mode gre local %s remote %s ttl 255",
		 (new ? "add" : "change"),
		 ofp_port_vlan_to_ifnet_name(port, greid),
		 ofp_print_ip_addr(tun_loc), ofp_print_ip_addr(tun_rem));
	ret = exec_sys_call_depending_on_vrf(cmd, vrf);

	snprintf(cmd, sizeof(cmd),
		 "ip link set dev %s up",
		 ofp_port_vlan_to_ifnet_name(port, greid));
	ret = exec_sys_call_depending_on_vrf(cmd, vrf);

	snprintf(cmd, sizeof(cmd),
		 "ip addr add dev %s %s peer %s",
		 ofp_port_vlan_to_ifnet_name(port, greid),
		 ofp_print_ip_addr(addr), ofp_print_ip_addr(p2p));
	ret = exec_sys_call_depending_on_vrf(cmd, vrf);
#endif /* SP */
	return NULL;
}

void ofp_join_device_to_multicast_group(struct ofp_ifnet *dev_root,
				       struct ofp_ifnet *dev_vxlan,
				       uint32_t group)
{
	/* Join root device to multicast group. */
	struct ofp_in_addr gina;
	gina.s_addr = group;

	OFP_DBG("Device joining multicast group: "
		"interface=%d/%d vni=%d group=%x",
		dev_root->port, dev_root->vlan,
		dev_vxlan->vlan, group);
	/* Use data->ii_inet.ii_allhosts for Vxlan purposes. */
	ofp_in_joingroup(dev_root, &gina, NULL, &(dev_vxlan->ii_inet.ii_allhosts));
	fflush(NULL);
}

void ofp_leave_multicast_group(struct ofp_ifnet *dev_vxlan)
{
	if (dev_vxlan->ii_inet.ii_allhosts) {
		/* Use data->ii_inet.ii_allhosts for Vxlan. */
		ofp_in_leavegroup(dev_vxlan->ii_inet.ii_allhosts, NULL);
	}
	dev_vxlan->ii_inet.ii_allhosts = NULL;
}

const char *ofp_config_interface_up_vxlan(uint16_t vrf, uint32_t addr, int mlen,
					  int vni, uint32_t group,
					  int physport, int physvlan)
{
#ifdef SP
	char cmd[200];
	int ret = 0, new = 0;
#endif /* SP */
	struct ofp_ifnet *data, *dev_root;
	uint32_t mask;

#ifdef SP
	(void)ret;
	(void)new;
#endif /*SP*/
	(void)vrf; /* vrf is copied from the root device */

	mask = ~0;
	mask = odp_cpu_to_be_32(mask << (32 - mlen));
	dev_root = ofp_get_ifnet(physport, physvlan);
	if (dev_root == NULL)
		return "No physical device configured.";

	data = ofp_get_ifnet(VXLAN_PORTS, vni);

	/* To be on the safe side it is better to put down the interface and
	   reconfigure.*/
	if (data) {
		ofp_config_interface_down(data->port, data->vlan);
		data = NULL;
	}

	data = ofp_get_create_ifnet(VXLAN_PORTS, vni);
	data->if_type = OFP_IFT_VXLAN;

	data->vrf = dev_root->vrf;
	data->ip_p2p = group;
	data->if_mtu = dev_root->if_mtu - sizeof(struct ofp_vxlan_udp_ip);
	data->physport = physport;
	data->physvlan = physvlan;
	data->pkt_pool = ofp_packet_pool;

	shm->ofp_ifnet_data[VXLAN_PORTS].pkt_pool = ofp_packet_pool;
	ofp_set_route_params(OFP_ROUTE_ADD, data->vrf, vni, VXLAN_PORTS,
			addr, 32, 0, OFP_RTF_LOCAL);
	ofp_set_route_params(OFP_ROUTE_ADD, data->vrf, vni, VXLAN_PORTS,
			addr & mask, mlen, 0, OFP_RTF_NET);
	ofp_ifnet_ip_find_update_fields(data, addr, mlen, addr | ~mask);

	/* Join root device to multicast group. */
	ofp_join_device_to_multicast_group(dev_root, data, group);

#ifdef SP
	if (data->vrf == 0)
		data->sp_status = OFP_SP_UP;
	else
		data->sp_status = OFP_SP_DOWN;

	snprintf(cmd, sizeof(cmd),
		 "ip link add vxlan%d type vxlan id %d group %s dev %s",
		 vni, vni, ofp_print_ip_addr(group),
		 ofp_port_vlan_to_ifnet_name(physport, physvlan));
	ret = exec_sys_call_depending_on_vrf(cmd, vrf);

	snprintf(cmd, sizeof(cmd),
		 "ip link set dev vxlan%d up", vni);
	ret = exec_sys_call_depending_on_vrf(cmd, vrf);

	snprintf(cmd, sizeof(cmd),
		 "ip addr add dev vxlan%d %s", vni,
		 ofp_print_ip_addr(addr));
	ret = exec_sys_call_depending_on_vrf(cmd, vrf);
#endif /* SP */

	return NULL;
}

const char *ofp_config_interface_up_local(uint16_t id, uint16_t vrf,
					  uint32_t addr, int masklen)
{
#ifdef SP
	char cmd[200];
	int ret = 0;
#endif /* SP */
	struct ofp_ifnet *data;
	uint32_t mask;

#ifdef SP
	(void)ret;
#endif /*SP*/
	mask = ~0;
	mask = odp_cpu_to_be_32(mask << (32 - masklen));

	data = ofp_get_ifnet(LOCAL_PORTS, id);
	if (data)
		ofp_config_interface_down(data->port, data->vlan);
	data = ofp_get_create_ifnet(LOCAL_PORTS, id);
	ofp_loopq_create(data);

#ifdef SP
	if (vrf) {
		/* Create vrf if not exist using dummy call */
		exec_sys_call_depending_on_vrf("", vrf);
	}
#endif /* SP */
	data->vrf = vrf;
	data->if_type = OFP_IFT_LOOP;
	data->if_flags = OFP_IFF_LOOPBACK;

	ofp_set_route_params(OFP_ROUTE_ADD, data->vrf, id, LOCAL_PORTS,
				addr, masklen, 0,
				OFP_RTF_LOCAL | OFP_RTF_HOST);
	ofp_ifnet_ip_find_update_fields(data, addr, masklen, addr | ~mask);
#ifdef SP
	if (vrf == 0)
		data->sp_status = OFP_SP_UP;
	else
		data->sp_status = OFP_SP_DOWN;

	ret = exec_sys_call_depending_on_vrf("ip link set lo up", vrf);
	snprintf(cmd, sizeof(cmd), "ip addr add %s/%d dev lo",
		 ofp_print_ip_addr(addr), masklen);
	ret = exec_sys_call_depending_on_vrf(cmd, vrf);
#endif /* SP */

	return NULL;
}


#ifdef INET6
const char *ofp_config_interface_up_v6(int port, uint16_t vlan,
			uint8_t *addr, int masklen)
{
#ifdef SP
	char cmd[200];
	int ret = 0;
#endif /* SP */
	uint8_t gw6[16];
	struct ofp_ifnet *data;

#ifdef SP
	(void)ret;
#endif /*SP*/
	memset(gw6, 0, 16);

	if (port < 0 || port >= OFP_FP_INTERFACE_MAX)
		return "Wrong port number";

	data = ofp_get_ifnet(port, vlan);

	if (vlan) {
		if (data == NULL) {
			data = ofp_get_create_ifnet(port, vlan);
			data->vrf = 0;
#ifdef SP
			char *iname = ofp_port_vlan_to_ifnet_name(port, 0);
			snprintf(cmd, sizeof(cmd),
				 "ip link add name %s.%d link %s type vlan id %d",
				 iname, vlan, iname, vlan);
			ret = exec_sys_call_depending_on_vrf(cmd, data->vrf);
#endif /* SP */
		} else {
			if (ofp_ip6_is_set(data->ip6_addr)) {
				ofp_set_route6_params(OFP_ROUTE6_DEL, 0 /*vrf*/, vlan,
						      port, data->ip6_addr,
						      data->ip6_prefix, gw6, 0);
				ofp_set_route6_params(OFP_ROUTE6_DEL, 0 /*vrf*/, vlan,
						      port, data->ip6_addr,
						      128, gw6, 0);
			}
		}

		memcpy(data->ip6_addr, addr, 16);
		data->ip6_prefix = masklen;
		ofp_set_route6_params(OFP_ROUTE6_ADD, 0 /*vrf*/, vlan, port,
				      data->ip6_addr, data->ip6_prefix, gw6,
				      OFP_RTF_NET);
		ofp_set_route6_params(OFP_ROUTE6_ADD, 0 /*vrf*/, vlan, port,
				      data->ip6_addr, 128, gw6,
				      OFP_RTF_LOCAL);
#ifdef SP
		if (data->vrf == 0)
			data->sp_status = OFP_SP_UP;
		else
			data->sp_status = OFP_SP_DOWN;

		snprintf(cmd, sizeof(cmd),
			 "ifconfig %s inet6 add %s/%d up",
			 ofp_port_vlan_to_ifnet_name(port, vlan),
			 ofp_print_ip6_addr(addr), masklen);
		ret = exec_sys_call_depending_on_vrf(cmd, data->vrf);
#endif /*SP*/
	} else {
		if (ofp_ip6_is_set(data->ip6_addr)) {
			ofp_set_route6_params(OFP_ROUTE6_DEL, 0 /*vrf*/, 0 /*vlan*/,
					      port, data->ip6_addr, data->ip6_prefix,
					      gw6, 0);
			ofp_set_route6_params(OFP_ROUTE6_DEL, 0 /*vrf*/, 0 /*vlan*/,
					      port, data->ip6_addr, 128,
					      gw6, 0);
		}
		memcpy(data->ip6_addr, addr, 16);
		data->ip6_prefix = masklen;

		ofp_mac_to_link_local(data->mac, data->link_local);

		/* Add interface to the if_addr v6 queue */
		ofp_ifaddr6_elem_add(data);

		ofp_set_route6_params(OFP_ROUTE6_ADD, 0 /*vrf*/, 0 /*vlan*/, port,
				      data->ip6_addr, 128, gw6,
				      OFP_RTF_LOCAL);
		ofp_set_route6_params(OFP_ROUTE6_ADD, 0 /*vrf*/, 0 /*vlan*/, port,
				      data->ip6_addr, data->ip6_prefix, gw6,
				      OFP_RTF_NET);
#ifdef SP
		if (data->vrf == 0)
			data->sp_status = OFP_SP_UP;
		else
			data->sp_status = OFP_SP_DOWN;

		snprintf(cmd, sizeof(cmd),
			 "ifconfig %s inet6 add %s/%d up",
			 ofp_port_vlan_to_ifnet_name(port, 0),
			 ofp_print_ip6_addr(addr), masklen);

		ret = exec_sys_call_depending_on_vrf(cmd, data->vrf);
#endif /* SP */
	}

	return NULL;
}
#endif /* INET6 */

#ifdef INET6
const char *ofp_config_interface_up_local_v6(uint16_t id,
					     uint8_t *addr, int masklen)
{
#ifdef SP
	char cmd[200];
	int ret = 0;
#endif /* SP */
	uint8_t gw6[16];
	struct ofp_ifnet *data;

#ifdef SP
	(void)ret;
#endif /*SP*/
	memset(gw6, 0, 16);

	data = ofp_get_ifnet(LOCAL_PORTS, id);
	if (data == NULL)
		return "Create IPv4 loopback interface first";

	if (ofp_ip6_is_set(data->ip6_addr)) {
#ifdef SP
		snprintf(cmd, sizeof(cmd),
			 "ip -f inet6 addr del %s/%d dev lo",
			 ofp_print_ip6_addr(data->ip6_addr), data->ip6_prefix);
		ret = exec_sys_call_depending_on_vrf(cmd, data->vrf);
#endif
		ofp_set_route6_params(OFP_ROUTE6_DEL, data->vrf, id,
				      LOCAL_PORTS, data->ip6_addr,
				      data->ip6_prefix, gw6, 0);
		ofp_set_route6_params(OFP_ROUTE6_DEL, data->vrf, id,
				      LOCAL_PORTS, data->ip6_addr,
				      128, gw6, 0);
	}

	memcpy(data->ip6_addr, addr, 16);
	data->ip6_prefix = masklen;
	ofp_set_route6_params(OFP_ROUTE6_ADD, data->vrf, id, LOCAL_PORTS,
			      data->ip6_addr, data->ip6_prefix, gw6, 0);
	ofp_set_route6_params(OFP_ROUTE6_ADD, data->vrf, id, LOCAL_PORTS,
			      data->ip6_addr, 128, gw6,
			      OFP_RTF_LOCAL);
#ifdef SP
		if (data->vrf == 0)
			data->sp_status = OFP_SP_UP;
		else
			data->sp_status = OFP_SP_DOWN;

		snprintf(cmd, sizeof(cmd),
			 "ip -f inet6 addr add %s/%d dev lo",
			 ofp_print_ip6_addr(addr), masklen);
		ret = exec_sys_call_depending_on_vrf(cmd, data->vrf);
#endif /*SP*/

	return NULL;
}
#endif /* INET6 */

static int iter_local_iface_destroy(void *key, void *iter_arg)
{
	struct ofp_ifnet *iface = key;
	(void)iter_arg;

	ofp_config_interface_down(iface->port, iface->vlan);

	return 0;
}

int ofp_local_interfaces_destroy(void)
{
	if (!shm)
		shm = ofp_shared_memory_lookup(SHM_NAME_PORTS);
	if (!shm) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}

	if (!shm->ofp_ifnet_data[LOCAL_PORTS].vlan_structs)
		return 0;

	vlan_iterate_inorder(shm->ofp_ifnet_data[LOCAL_PORTS].vlan_structs,
			     iter_local_iface_destroy, NULL);

	return 0;
}

const char *ofp_config_interface_down(int port, uint16_t vlan)
{
#ifdef SP
	char cmd[200];
	int ret = 0;
	uint16_t vrf;
#endif /* SP */
	uint8_t gw6[16];
	struct ofp_ifnet *data;

#ifdef SP
	(void)ret;
#endif /*SP*/
	memset(gw6, 0, 16);

	if (port < 0 || port >= shm->ofp_num_ports)
		return "Wrong port number";

	if (vlan || port == LOCAL_PORTS) {
		struct ofp_ifnet key;

		key.vlan = vlan;
		if (ofp_vlan_get_by_key(
			shm->ofp_ifnet_data[port].vlan_structs,
			&key,
			(void *)&data))
			return "Unknown interface";

		/* Remove interface from the if_addr v4 queue */
		ofp_ifaddr_elem_del(data);
#ifdef INET6
		/* Remove interface from the if_addr v6 queue */
		ofp_ifaddr6_elem_del(data);
#endif
#ifdef SP
		vrf = data->vrf;
#endif /*SP*/
		if (data->ip_addr_info[0].ip_addr) {
			uint32_t a = (ofp_if_type(data) == OFP_IFT_GRE) ?
				data->ip_p2p : data->ip_addr_info[0].ip_addr;
			int m = data->ip_addr_info[0].masklen;
			a = odp_cpu_to_be_32(odp_be_to_cpu_32(a) & (0xFFFFFFFFULL << (32-data->ip_addr_info[0].masklen)));
			if (ofp_if_type(data) == OFP_IFT_LOOP)
				ofp_set_route_params(OFP_ROUTE_DEL, data->vrf, vlan, port,
					data->ip_addr_info[0].ip_addr, data->ip_addr_info[0].masklen, 0, 0);
			else if (ofp_if_type(data) != OFP_IFT_GRE)
				ofp_set_route_params(OFP_ROUTE_DEL, data->vrf, vlan, port,
					data->ip_addr_info[0].ip_addr, 32, 0, 0);
			ofp_set_route_params(OFP_ROUTE_DEL, data->vrf, vlan, port,
					a, m, 0, 0);
			ofp_free_ifnet_ip_list(data);
#ifdef SP
			if (port == LOCAL_PORTS)
				snprintf(cmd, sizeof(cmd),
					 "ip addr del %s/%d dev lo",
					 ofp_print_ip_addr(a),
					 m);
			else
				snprintf(cmd, sizeof(cmd),
					 "ifconfig %s 0.0.0.0",
					 ofp_port_vlan_to_ifnet_name(port, vlan));
			ret = exec_sys_call_depending_on_vrf(cmd, vrf);
#endif /*SP*/
		}
#ifdef INET6
		if (ofp_ip6_is_set(data->ip6_addr)) {
			ofp_set_route6_params(OFP_ROUTE6_DEL, 0 /*vrf*/, vlan, port,
					      data->ip6_addr, data->ip6_prefix,
					      gw6, 0);
			ofp_set_route6_params(OFP_ROUTE6_DEL, 0 /*vrf*/, vlan, port,
					      data->ip6_addr, 128,
					      gw6, 0);
#ifdef SP
			snprintf(cmd, sizeof(cmd),
				 "ifconfig %s inet6 del %s/%d",
				 port == LOCAL_PORTS ? "lo" :
				 ofp_port_vlan_to_ifnet_name(port, vlan),
				 ofp_print_ip6_addr(data->ip6_addr),
				 data->ip6_prefix);

			ret = exec_sys_call_depending_on_vrf(cmd, vrf);
#endif /* SP */
		}
#endif /* INET6 */
		if (data->loopq_def != ODP_QUEUE_INVALID) {
			if (odp_queue_destroy(data->loopq_def) < 0) {
				OFP_ERR("Failed to destroy loop queue for %s",
					data->if_name);
			}
			data->loopq_def = ODP_QUEUE_INVALID;
		}

		if (ofp_if_type(data) == OFP_IFT_VXLAN &&
		    data->ii_inet.ii_allhosts) {
			/* Use data->ii_inet.ii_allhosts for Vxlan. */
			ofp_in_leavegroup(data->ii_inet.ii_allhosts, NULL);
		}

		free(data->ii_inet.ii_igmp);
		vlan_ifnet_delete(
			shm->ofp_ifnet_data[port].vlan_structs,
			&key,
			free_key);
#ifdef SP
		if (ofp_if_type(data) == OFP_IFT_GRE)
			snprintf(cmd, sizeof(cmd), "ip tunnel del %s",
				 ofp_port_vlan_to_ifnet_name(port, vlan));
		else if (ofp_if_type(data) != OFP_IFT_LOOP)
			snprintf(cmd, sizeof(cmd), "ip link del %s",
				 ofp_port_vlan_to_ifnet_name(port, vlan));
		ret = exec_sys_call_depending_on_vrf(cmd, vrf);
#endif /*SP*/
	} else {
		data = ofp_get_ifnet(port, vlan);

		/* Remove interface from the if_addr v4 queue */
		ofp_ifaddr_elem_del(data);
#ifdef INET6
		/* Remove interface from the if_addr v6 queue */
		ofp_ifaddr6_elem_del(data);
#endif
#ifdef SP
		vrf = data->vrf;
#endif /*SP*/
		if (data->ip_addr_info[0].ip_addr) {
			uint32_t a = odp_cpu_to_be_32(
				odp_be_to_cpu_32(data->ip_addr_info[0].ip_addr) &
				(0xFFFFFFFFULL << (32 - data->ip_addr_info[0].masklen)));
			ofp_set_route_params(OFP_ROUTE_DEL, data->vrf, 0 /*vlan*/, port,
					a, data->ip_addr_info[0].masklen, 0, 0);
			ofp_set_route_params(OFP_ROUTE_DEL, data->vrf, 0 /*vlan*/, port,
					data->ip_addr_info[0].ip_addr, 32, 0, 0);

			ofp_free_ifnet_ip_list(data);
#ifdef SP
			snprintf(cmd, sizeof(cmd),
				 "ifconfig %s 0.0.0.0",
				 ofp_port_vlan_to_ifnet_name(port, 0));

			ret = exec_sys_call_depending_on_vrf(cmd, vrf);
#endif /* SP */
		}
#ifdef INET6
		if (ofp_ip6_is_set(data->ip6_addr)) {
			ofp_set_route6_params(OFP_ROUTE6_DEL, 0 /*vrf*/, 0 /*vlan*/,
					      port, data->ip6_addr, data->ip6_prefix,
					      gw6, 0);
			ofp_set_route6_params(OFP_ROUTE6_DEL, 0 /*vrf*/, 0 /*vlan*/,
					      port, data->ip6_addr, 128,
					      gw6, 0);
#ifdef SP
			snprintf(cmd, sizeof(cmd),
				 "ifconfig %s inet6 del %s/%d",
				 ofp_port_vlan_to_ifnet_name(port, vlan),
				 ofp_print_ip6_addr(data->ip6_addr),
				 data->ip6_prefix);

			ret = exec_sys_call_depending_on_vrf(cmd, vrf);
#endif /*SP*/
			memset(data->ip6_addr, 0, 16);
		}
#endif /* INET6 */
	}

	return NULL;
}

struct ofp_ifnet *ofp_get_ifnet(int port, uint16_t vlan)
{
	if (port < 0 || port >= shm->ofp_num_ports) {
		OFP_DBG("port:%d is outside the valid interval", port);
		return NULL;
	}

	if (vlan || port == LOCAL_PORTS) {
		struct ofp_ifnet key, *data;

		key.vlan = vlan;
		if (ofp_vlan_get_by_key(
				shm->ofp_ifnet_data[port].vlan_structs,
				&key,
				(void *)&data))
			return NULL;

		return data;
	}

	if (port != PORT_UNDEF)
		return &(shm->ofp_ifnet_data[port]);
	else
		return NULL;
}

struct ofp_ifnet *ofp_get_create_ifnet(int port, uint16_t vlan)
{
	if (vlan || port == LOCAL_PORTS) {
		struct ofp_ifnet key, *data;

		key.vlan = vlan;
		if (ofp_vlan_get_by_key(
				shm->ofp_ifnet_data[port].vlan_structs,
				&key,
				(void *)&data)) {
			data = ofp_vlan_alloc();
			memset(data, 0, sizeof(*data));
			data->port = port;
			data->vlan = vlan;
			memcpy(data->mac, shm->ofp_ifnet_data[port].mac, 6);
			data->chksum_offload_flags =
				shm->ofp_ifnet_data[port].chksum_offload_flags;
			data->if_mtu = shm->ofp_ifnet_data[port].if_mtu;
#ifdef INET6
			memcpy(data->link_local,
				shm->ofp_ifnet_data[port].link_local, 16);
#endif /* INET6 */
			/* Add interface to the if_addr v4 queue */
			ofp_ifaddr_elem_add(data);
#ifdef INET6
			/* Add interface to the if_addr v6 queue */
			ofp_ifaddr6_elem_add(data);
#endif
			/* Multicast related */
			OFP_TAILQ_INIT(&data->if_multiaddrs);
			data->if_flags |= OFP_IFF_MULTICAST;
			data->if_afdata[OFP_AF_INET] = &data->ii_inet;
			struct ofp_in_ifinfo *ii = &data->ii_inet;
			ii->ii_igmp = ofp_igmp_domifattach(data);
			vlan_ifnet_insert(
				shm->ofp_ifnet_data[port].vlan_structs, data);
			IP_ADDR_LIST_INIT(data);
			memset(data->ip_addr_info, 0, sizeof(data->ip_addr_info));
		}
		return data;
	}

	return &(shm->ofp_ifnet_data[port]);
}

int ofp_delete_ifnet(int port, uint16_t vlan)
{
	if (vlan || port == LOCAL_PORTS) {
		struct ofp_ifnet key, *data;

		key.vlan = vlan;
		if (ofp_vlan_get_by_key(
			shm->ofp_ifnet_data[port].vlan_structs,
			&key,
			(void *)&data))
			return 0; /* vlan not found (deleted already)*/

		vlan_ifnet_delete(
			shm->ofp_ifnet_data[port].vlan_structs,
			&key,
			free_key);
		return 0;
	}
	return -1;
}

#ifdef SP
struct iter_str {
	int ix;
	struct ofp_ifnet *dev;
};

static int iter_vlan_1(void *key, void *iter_arg)
{
	struct ofp_ifnet *iface = key;
	struct iter_str *data = iter_arg;

	if (iface->linux_index == data->ix) {
		data->dev = key;
		return 1;
	}

	return 0;
}

struct ofp_ifnet *ofp_get_ifnet_by_linux_ifindex(int ix)
{
	int i;
	struct iter_str data;

	if (odp_likely(ix < NUM_LINUX_INTERFACES))
		return ofp_get_ifnet(
			shm->linux_interface_table[ix].port,
			shm->linux_interface_table[ix].vlan);

	/* Iterate through other index values */
	data.ix = ix;
	data.dev = NULL;

	for (i = 0; i < shm->ofp_num_ports && data.dev == NULL; i++) {
		if (shm->ofp_ifnet_data[i].linux_index == ix)
			return &(shm->ofp_ifnet_data[i]);

		vlan_iterate_inorder(shm->ofp_ifnet_data[i].vlan_structs,
				iter_vlan_1, &data);
	}

	return data.dev;
}

void ofp_update_ifindex_lookup_tab(struct ofp_ifnet *ifnet)
{
	/* quick access table */
	if (ifnet->linux_index < NUM_LINUX_INTERFACES) {
		shm->linux_interface_table[ifnet->linux_index].port =
			ifnet->port;
		shm->linux_interface_table[ifnet->linux_index].vlan =
			ifnet->vlan;
	}
}
#else
struct ofp_ifnet *ofp_get_ifnet_by_linux_ifindex(int ix)
{
	(void)ix;

	return NULL;
}
#endif /* SP */

struct ofp_ifnet *ofp_get_ifnet_match(uint32_t ip,
		uint16_t vrf,
		uint16_t vlan)
{
	uint16_t port;

	if (vlan == 0) {
		for (port = 0; port < OFP_FP_INTERFACE_MAX; port++) {
			struct ofp_ifnet *ifnet =
				&shm->ofp_ifnet_data[port];

			if (ifnet->vrf == vrf)
				if (-1 != ofp_ifnet_ip_find(ifnet, ip))
					return ifnet;
		}
	} else {
		for (port = 0; port < OFP_FP_INTERFACE_MAX; port++) {
			uint16_t vlan_id = vlan_iterate_inorder(
				shm->ofp_ifnet_data[port].vlan_structs,
				vlan_match_ip, &ip);

			if (vlan_id)
				return ofp_get_ifnet(port, vlan);
		}
	}
	return NULL;
}

static int iter_interface(void *key, void *iter_arg)
{
	struct ofp_ifnet *iface = key;
	struct ofp_ifconf *ifc = iter_arg;
	int len = ifc->ifc_current_len;
	struct ofp_ifreq *ifr = (struct ofp_ifreq *)(((uint8_t *)ifc->ifc_buf) + len);

	if (len + (int)sizeof(struct ofp_ifreq) > ifc->ifc_len)
		return 1;

	ifc->ifc_current_len += sizeof(struct ofp_ifreq);

	((struct ofp_sockaddr_in *)&ifr->ifr_addr)->sin_addr.s_addr =
		iface->ip_addr_info[0].ip_addr;
	ifr->ifr_addr.sa_family = OFP_AF_INET;

	if (ofp_if_type(iface) == OFP_IFT_GRE)
		snprintf(ifr->ifr_name, OFP_IFNAMSIZ,
			 "gre%d", iface->vlan);
	else if (ofp_if_type(iface) == OFP_IFT_VXLAN)
		snprintf(ifr->ifr_name, OFP_IFNAMSIZ,
			 "vxlan%d", iface->vlan);
	else if (iface->vlan)
		snprintf(ifr->ifr_name, OFP_IFNAMSIZ,
			 "fp%d.%d", iface->port, iface->vlan);
	else
		snprintf(ifr->ifr_name, OFP_IFNAMSIZ,
			 "fp%d", iface->port);

	return 0;
}

void ofp_get_interfaces(struct ofp_ifconf *ifc)
{
	int i;

	ifc->ifc_current_len = 0;

	/* fp interfaces */
	for (i = 0; i < OFP_FP_INTERFACE_MAX; i++) {
		iter_interface(&shm->ofp_ifnet_data[i], ifc);
		vlan_iterate_inorder(shm->ofp_ifnet_data[i].vlan_structs,
					iter_interface, ifc);
	}

	/* gre interfaces */
	if (avl_get_first(shm->ofp_ifnet_data[GRE_PORTS].vlan_structs))
		vlan_iterate_inorder(
			shm->ofp_ifnet_data[GRE_PORTS].vlan_structs,
			iter_interface, ifc);

	/* vxlan interfaces */
	if (avl_get_first(shm->ofp_ifnet_data[VXLAN_PORTS].vlan_structs))
		vlan_iterate_inorder(
			shm->ofp_ifnet_data[VXLAN_PORTS].vlan_structs,
			iter_interface, ifc);

	ifc->ifc_len = ifc->ifc_current_len;
}

struct iter_ip {
	uint32_t addr;
	uint16_t vrf;
};

static int vlan_match_ip_vrf(void *key, void *iter_arg)
{
	struct ofp_ifnet *iface = key;
	struct iter_ip *iterdata = (struct iter_ip *)iter_arg;

	if (iface->ip_addr_info[0].ip_addr == iterdata->addr &&
	    iface->vrf == iterdata->vrf)
		return iface->vlan;
	else
		return 0;
}

struct ofp_ifnet *ofp_get_ifnet_by_ip(uint32_t ip, uint16_t vrf)
{
	uint16_t port;
	struct ofp_ifnet *ifnet;
	uint16_t vlan;
	struct iter_ip iterdata;

	for (port = 0; port < OFP_FP_INTERFACE_MAX; ++port) {
		ifnet = &shm->ofp_ifnet_data[port];
		if (ifnet->ip_addr_info[0].ip_addr == ip && ifnet->vrf == vrf)
			return ifnet;
	}

	iterdata.addr = ip;
	iterdata.vrf = vrf;

	for (port = 0; port < OFP_FP_INTERFACE_MAX; ++port) {
		vlan = vlan_iterate_inorder(
			shm->ofp_ifnet_data[port].vlan_structs,
			vlan_match_ip_vrf, &iterdata);
		if (vlan)
			return ofp_get_ifnet(port, vlan);
	}

	return NULL;
}

struct iter_tun {
	uint32_t tun_loc;
	uint32_t tun_rem;
	uint16_t vrf;
};

static int vlan_match_tun(void *key, void *iter_arg)
{
	struct ofp_ifnet *iface = key;
	struct iter_tun *tundata = iter_arg;

	if (iface->ip_local == tundata->tun_loc &&
	    iface->ip_remote == tundata->tun_rem &&
	    iface->vrf == tundata->vrf)
		return iface->vlan;
	else
		return 0;
}

struct ofp_ifnet *ofp_get_ifnet_by_tunnel(uint32_t tun_loc,
					  uint32_t tun_rem, uint16_t vrf)
{
	uint16_t port = GRE_PORTS;
	uint16_t greid;
	struct iter_tun tundata;

	tundata.tun_loc = tun_loc;
	tundata.tun_rem = tun_rem;
	tundata.vrf = vrf;

	greid = vlan_iterate_inorder(
		shm->ofp_ifnet_data[port].vlan_structs,
		vlan_match_tun, &tundata);

	if (greid)
		return ofp_get_ifnet(port, greid);

	return NULL;
}

struct ofp_ifnet *ofp_get_ifnet_pktio(odp_pktio_t pktio)
{
	int i;

	for (i = 0; i < NUM_PORTS; i++) {
		if (shm->ofp_ifnet_data[i].if_state == OFP_IFT_STATE_USED &&
			shm->ofp_ifnet_data[i].pktio == pktio)
				return &shm->ofp_ifnet_data[i];
	}

	return NULL;
}

odp_queue_t ofp_pktio_spq_get(odp_pktio_t pktio)
{
#ifdef SP
	struct ofp_ifnet *ifnet = ofp_get_ifnet_pktio(pktio);

	return ifnet->spq_def;
#else
	(void)pktio;

	return ODP_QUEUE_INVALID;
#endif /*SP*/
}

odp_queue_t ofp_pktio_loopq_get(odp_pktio_t pktio)
{
	struct ofp_ifnet *ifnet = ofp_get_ifnet_pktio(pktio);

	return ifnet->loopq_def;
}

odp_pktio_t ofp_port_pktio_get(int port)
{
	struct ofp_ifnet *ifnet = ofp_get_ifnet(port, 0);

	return ifnet->pktio;
}

void ofp_portconf_init_prepare(void)
{
	ofp_shared_memory_prealloc(SHM_NAME_PORTS, sizeof(*shm));
	ofp_shared_memory_prealloc(SHM_NAME_PORT_LOCKS,
				   sizeof(*ofp_ifnet_locks_shm));
}

static int ofp_portconf_alloc_shared_memory(void)
{
	shm = ofp_shared_memory_alloc(SHM_NAME_PORTS, sizeof(*shm));
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}

	ofp_ifnet_locks_shm = ofp_shared_memory_alloc(SHM_NAME_PORT_LOCKS,
		sizeof(*ofp_ifnet_locks_shm));
	if (ofp_ifnet_locks_shm == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}

	return 0;
}

#define SHM_SIZE_VLAN (sizeof(struct ofp_vlan_mem) + \
		       sizeof(struct ofp_ifnet) * global_param->num_vlan)

static int ofp_vlan_alloc_shared_memory(void)
{
	vlan_shm = ofp_shared_memory_alloc(SHM_NAME_VLAN, SHM_SIZE_VLAN);
	if (vlan_shm == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}
	return 0;
}

void ofp_vlan_init_prepare(void)
{
	ofp_shared_memory_prealloc(SHM_NAME_VLAN, SHM_SIZE_VLAN);
}

static int ofp_portconf_free_shared_memory(void)
{
	int rc = 0;

	if (ofp_shared_memory_free(SHM_NAME_PORTS) == -1) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}
	shm = NULL;

	if (ofp_shared_memory_free(SHM_NAME_PORT_LOCKS) == -1) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}
	ofp_ifnet_locks_shm = NULL;
	return rc;
}


static int ofp_vlan_free_shared_memory(void)
{
	int rc = 0;

	if (ofp_shared_memory_free(SHM_NAME_VLAN) == -1) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}
	vlan_shm = NULL;
	return rc;
}


int ofp_portconf_lookup_shared_memory(void)
{
	shm = ofp_shared_memory_lookup(SHM_NAME_PORTS);
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}

	ofp_ifnet_locks_shm = ofp_shared_memory_lookup(SHM_NAME_PORT_LOCKS);
	if (ofp_ifnet_locks_shm == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}

	return 0;
}


int ofp_vlan_lookup_shared_memory(void)
{
	vlan_shm = ofp_shared_memory_lookup(SHM_NAME_VLAN);
	if (vlan_shm == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}
	return 0;
}

int ofp_portconf_init_global(void)
{
	int i, j;

	HANDLE_ERROR(ofp_portconf_alloc_shared_memory());

	memset(shm, 0, sizeof(*shm));
	for (i = 0; i < NUM_PORTS; i++) {
		shm->ofp_ifnet_data[i].if_state = OFP_IFT_STATE_FREE;
		shm->ofp_ifnet_data[i].pktio = ODP_PKTIO_INVALID;

		for (j = 0; j < OFP_PKTOUT_QUEUE_MAX; j++)
			shm->ofp_ifnet_data[i].out_queue_queue[j] =
				ODP_QUEUE_INVALID;

		shm->ofp_ifnet_data[i].loopq_def = ODP_QUEUE_INVALID;
#ifdef SP
		shm->ofp_ifnet_data[i].spq_def = ODP_QUEUE_INVALID;
#endif /*SP*/
		shm->ofp_ifnet_data[i].pkt_pool = ODP_POOL_INVALID;
	}

	memset(ofp_ifnet_locks_shm, 0, sizeof(*ofp_ifnet_locks_shm));

	odp_atomic_init_u32(&shm->free_port, 0);

	shm->ofp_num_ports = NUM_PORTS;

	for (i = 0; i < shm->ofp_num_ports; i++) {
		shm->ofp_ifnet_data[i].vlan_structs =
					new_vlan(vlan_ifnet_compare, NULL);
		if (shm->ofp_ifnet_data[i].vlan_structs == NULL) {
			OFP_ERR("Failed to initialize vlan structures.");
			return -1;
		}
		shm->ofp_ifnet_data[i].port = i;
		shm->ofp_ifnet_data[i].if_type = OFP_IFT_ETHER;
		/*TODO get if_mtu from Linux/SDK*/
		shm->ofp_ifnet_data[i].if_mtu = 1500;
		shm->ofp_ifnet_data[i].if_state = OFP_IFT_STATE_FREE;
		/* Multicast related */
		OFP_TAILQ_INIT(&shm->ofp_ifnet_data[i].if_multiaddrs);
		shm->ofp_ifnet_data[i].if_flags |= OFP_IFF_MULTICAST;
		shm->ofp_ifnet_data[i].if_afdata[OFP_AF_INET] =
			&shm->ofp_ifnet_data[i].ii_inet;
		/* TO DO:
		   shm->ofp_ifnet_data[i].if_afdata[OFP_AF_INET6] =
		   &shm->ofp_ifnet_data[i].ii_inet6;
		*/
		/* Set locally administered default mac address.
		   This is needed by vxlan and other
		   virtual interfaces.
		*/
		if (odp_random_data((uint8_t *)shm->ofp_ifnet_data[i].mac,
				sizeof(shm->ofp_ifnet_data[i].mac), 0) < 0) {
			OFP_ERR("Failed to initialize default MAC address.");
			return -1;
		}
		/* Universally administered and locally administered addresses
		   are distinguished by setting the second least significant bit
		   of the most significant byte of the address.
		*/
		shm->ofp_ifnet_data[i].mac[0] = 0x02;
		/* Port number. */
		shm->ofp_ifnet_data[i].mac[1] = i;
		memset(shm->ofp_ifnet_data[i].ip_addr_info, 0, sizeof(shm->ofp_ifnet_data[i].ip_addr_info));
	}

#ifdef SP
	for (i = 0; i < NUM_LINUX_INTERFACES; ++i)
		shm->linux_interface_table[i].port = PORT_UNDEF;
#endif /* SP */

	OFP_TAILQ_INIT(&shm->in_ifaddrhead);
	odp_rwlock_init(&ofp_ifnet_locks_shm->lock_ifaddr_list_rw);
#ifdef INET6
	OFP_TAILQ_INIT(&shm->in_ifaddr6head);
	odp_rwlock_init(&ofp_ifnet_locks_shm->lock_ifaddr6_list_rw);
#endif /* INET6 */

	return 0;
}

int ofp_vlan_init_global(void)
{
	int i;

	/* init vlan shared memory */
	HANDLE_ERROR(ofp_vlan_alloc_shared_memory());
	memset(vlan_shm, 0, sizeof(*vlan_shm));
	for (i = 0; i < global_param->num_vlan; i++) {
		vlan_shm->vlan_ifnet[i].next = (i == global_param->num_vlan - 1) ?
			NULL : &(vlan_shm->vlan_ifnet[i+1]);
	}
	vlan_shm->free_ifnet_list = &(vlan_shm->vlan_ifnet[0]);
	odp_rwlock_init(&vlan_shm->vlan_mtx);

	return 0;
}

int ofp_portconf_term_global(void)
{
	int i;
	int rc = 0;

	shm = ofp_shared_memory_lookup(SHM_NAME_PORTS);
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		rc = -1;
	} else
		for (i = 0; i < shm->ofp_num_ports; ++i)
			if (shm->ofp_ifnet_data[i].vlan_structs)
				free_vlan(shm->ofp_ifnet_data[i].vlan_structs,
					free_key);

	CHECK_ERROR(ofp_portconf_free_shared_memory(), rc);

	return rc;
}


int ofp_vlan_term_global(void)
{
	int rc = 0;

	vlan_shm = ofp_shared_memory_lookup(SHM_NAME_VLAN);
	if (vlan_shm == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		rc = -1;
	}
	CHECK_ERROR(ofp_vlan_free_shared_memory(), rc);

	return rc;
}


struct ofp_in_ifaddrhead *ofp_get_ifaddrhead(void)
{
	return &shm->in_ifaddrhead;
}

void ofp_ifaddr_elem_add(struct ofp_ifnet *ifnet)
{
	struct ofp_ifnet *ia;

	OFP_IFNET_LOCK_WRITE(ifaddr_list);

	OFP_TAILQ_FOREACH(ia, ofp_get_ifaddrhead(), ia_link) {
		if (ia == ifnet)
			break;
	}

	if (!ia)
		OFP_TAILQ_INSERT_TAIL(ofp_get_ifaddrhead(), ifnet, ia_link);

	OFP_IFNET_UNLOCK_WRITE(ifaddr_list);
}

void ofp_ifaddr_elem_del(struct ofp_ifnet *ifnet)
{
	struct ofp_ifnet *ia;

	OFP_IFNET_LOCK_WRITE(ifaddr_list);

	OFP_TAILQ_FOREACH(ia, ofp_get_ifaddrhead(), ia_link) {
		if (ia == ifnet)
			break;
	}

	if (ia)
		OFP_TAILQ_REMOVE(ofp_get_ifaddrhead(), ifnet, ia_link);

	OFP_IFNET_UNLOCK_WRITE(ifaddr_list);
}

struct ofp_ifnet *ofp_ifaddr_elem_get(int vrf, uint8_t *addr)
{
	struct ofp_ifnet *ifa;

	OFP_IFNET_LOCK_WRITE(ifaddr_list);

	OFP_TAILQ_FOREACH(ifa, ofp_get_ifaddrhead(), ia_link) {
		if (ifa->ip_addr_info[0].ip_addr == *(uint32_t *)addr &&
		    ifa->vrf == vrf)
			break;
	}

	OFP_IFNET_UNLOCK_WRITE(ifaddr_list);
	return ifa;
}

uint32_t ofp_port_get_ipv4_addr(int port, uint16_t vlan,
				  enum ofp_portconf_ip_type type)
{
	struct ofp_ifnet *dev = ofp_get_ifnet(port, vlan);
	uint32_t addr = 0;

	switch (type) {
	case OFP_PORTCONF_IP_TYPE_IP_ADDR:
		addr = dev->ip_addr_info[0].ip_addr;
		break;
	case OFP_PORTCONF_IP_TYPE_P2P:
		addr = dev->ip_p2p;
		break;
	case OFP_PORTCONF_IP_TYPE_TUN_LOCAL:
		addr = dev->ip_local;
		break;
	case OFP_PORTCONF_IP_TYPE_TUN_REM:
		addr = dev->ip_remote;
		break;
	default:
		addr = 0;
		break;
	}

	return addr;
}
/* The dev->ip_addr_info array holds IP entries.
	When an element is inserted it is inserted in the first entry != 0
	When an element is deleted the last element != 0 replaces the removed element.
 */
static inline int get_first_free_ifnet_pos(struct ofp_ifnet *dev)
{
	int free_idx = 0;
	while(free_idx < OFP_NUM_IFNET_IP_ADDRS && dev->ip_addr_info[free_idx].ip_addr)
	{
		free_idx++;
	}
	return free_idx;
}

inline int ofp_ifnet_ip_add(struct ofp_ifnet *dev, uint32_t addr)
{
	IP_ADDR_LIST_WLOCK(dev);
	int free_idx = get_first_free_ifnet_pos(dev);
	if (odp_likely(free_idx < OFP_NUM_IFNET_IP_ADDRS))
		dev->ip_addr_info[free_idx].ip_addr = addr;
	else {
		IP_ADDR_LIST_WUNLOCK(dev);
		return -1;
	}
	IP_ADDR_LIST_WUNLOCK(dev);
	return 0;
}

inline void ofp_ifnet_ip_remove(struct ofp_ifnet *dev, uint32_t addr)
{
	int i;
	int free_idx;

	IP_ADDR_LIST_WLOCK(dev);
	i = ofp_ifnet_ip_find(dev, addr);
	if (-1 != i) {
		free_idx = get_first_free_ifnet_pos(dev);
		if (OFP_NUM_IFNET_IP_ADDRS != free_idx) {
			free_idx--;
			if (free_idx != i) {
				dev->ip_addr_info[i].ip_addr = dev->ip_addr_info[free_idx].ip_addr;
				dev->ip_addr_info[i].masklen = dev->ip_addr_info[free_idx].masklen;
				dev->ip_addr_info[i].bcast_addr = dev->ip_addr_info[free_idx].bcast_addr;
			}
			dev->ip_addr_info[free_idx].ip_addr = 0;
			dev->ip_addr_info[free_idx].masklen = 0;
			dev->ip_addr_info[free_idx].bcast_addr = 0;
		}
	}
	IP_ADDR_LIST_WUNLOCK(dev);
}

inline int ofp_ifnet_ip_find(struct ofp_ifnet *dev, uint32_t addr)
{
	for (int i=0; i < OFP_NUM_IFNET_IP_ADDRS && dev->ip_addr_info[i].ip_addr; i++)
	{
		if (addr == dev->ip_addr_info[i].ip_addr)
			return i;
	}
	return -1;
}
/*
 * The address is already added in the list. Move it in the first element of the list
 * and update its fields.
 */
inline int ofp_set_first_ifnet_addr(struct ofp_ifnet *dev, uint32_t addr, uint32_t bcast_addr, int masklen)
{
	int idx;

	IP_ADDR_LIST_WLOCK(dev);
	idx = ofp_ifnet_ip_find(dev, addr);
	if (-1 == idx) {
		IP_ADDR_LIST_WUNLOCK(dev);
		return idx;
	}
	else if (0 == idx) {
		dev->ip_addr_info[0].bcast_addr = bcast_addr;
		dev->ip_addr_info[0].masklen = masklen;
	}
	else {
		dev->ip_addr_info[idx].ip_addr = dev->ip_addr_info[0].ip_addr;
		dev->ip_addr_info[idx].bcast_addr = dev->ip_addr_info[0].bcast_addr;
		dev->ip_addr_info[idx].masklen = dev->ip_addr_info[0].masklen;

		dev->ip_addr_info[0].ip_addr = addr;
		dev->ip_addr_info[0].bcast_addr = bcast_addr;
		dev->ip_addr_info[0].masklen = masklen;
	}
	IP_ADDR_LIST_WUNLOCK(dev);
	return 0;
}

inline void ofp_ifnet_print_ip_addrs(struct ofp_ifnet *dev)
{
	int i;

	IP_ADDR_LIST_RLOCK(dev);
	for(i=0; i < OFP_NUM_IFNET_IP_ADDRS && dev->ip_addr_info[i].ip_addr; i++)
	{
		uint32_t mask = ~0;
		mask = odp_cpu_to_be_32(mask << (32 - dev->ip_addr_info[i].masklen));
		OFP_INFO("       inet addr:%s    Bcast:%s        Mask:%s\r\n",
				ofp_print_ip_addr(dev->ip_addr_info[i].ip_addr),
				ofp_print_ip_addr(dev->ip_addr_info[i].bcast_addr),
				ofp_print_ip_addr(mask));
	}
	IP_ADDR_LIST_RUNLOCK(dev);
}

inline int ofp_ifnet_ip_find_update_fields(struct ofp_ifnet *dev, uint32_t addr, int masklen, uint32_t bcast_addr)
{
	int i;
	IP_ADDR_LIST_WLOCK(dev);
	i = ofp_ifnet_ip_find(dev, addr);
	if (-1 != i) {
		dev->ip_addr_info[i].masklen = masklen;
		dev->ip_addr_info[i].bcast_addr = bcast_addr;
		IP_ADDR_LIST_WUNLOCK(dev);
		return 0;
	}
	IP_ADDR_LIST_WUNLOCK(dev);
	return -1;
}

inline void ofp_free_ifnet_ip_list(struct ofp_ifnet *dev)
{
	int i;
	uint32_t mask;
	struct ofp_ifnet_ipaddr *ip_addr_info;
	int size;

	IP_ADDR_LIST_RLOCK(dev);
	size = get_first_free_ifnet_pos(dev);

	ip_addr_info = malloc(size*sizeof(struct ofp_ifnet_ipaddr));
	if (NULL == ip_addr_info) {
		OFP_INFO("ofp_free_ifnet_ip_list failed");
		return;
	}
	memset(ip_addr_info, 0, size*sizeof(struct ofp_ifnet_ipaddr));

	for(i=0; i < OFP_NUM_IFNET_IP_ADDRS && dev->ip_addr_info[i].ip_addr; i++)
	{
		ip_addr_info[i].ip_addr = dev->ip_addr_info[i].ip_addr;
		ip_addr_info[i].masklen = dev->ip_addr_info[i].masklen;
	}
	IP_ADDR_LIST_RUNLOCK(dev);

	for(i=0; i < size && ip_addr_info[i].ip_addr; i++)
	{
		mask = ~0;
		mask = odp_cpu_to_be_32(mask << (32 - dev->ip_addr_info[i].masklen));
		ofp_set_route_params(OFP_ROUTE_DEL, dev->vrf, dev->vlan, dev->port,
				ip_addr_info[i].ip_addr & mask, ip_addr_info[i].masklen, 0, 0);
		ofp_set_route_params(OFP_ROUTE_DEL, dev->vrf, dev->vlan, dev->port,
				ip_addr_info[i].ip_addr, 32, 0, 0);

	}
	free(ip_addr_info);

	IP_ADDR_LIST_RLOCK(dev);
	size = get_first_free_ifnet_pos(dev);
	IP_ADDR_LIST_RUNLOCK(dev);

	if (0 != size)
		OFP_INFO("IP address %s not removed", ofp_print_ip_addr(dev->ip_addr_info[0].ip_addr));

}

inline void ofp_ifnet_print_ip_info(int fd, struct ofp_ifnet *dev)
{
	char buf[16];
	int i;

	if (dev->vlan)
		snprintf(buf, sizeof(buf), ".%d", dev->vlan);

	ofp_sendf(fd, "%s%d%s (%s):\r\n",
			OFP_IFNAME_PREFIX,
			dev->port,
			(dev->vlan) ? buf:"",
			dev->if_name);
	IP_ADDR_LIST_RLOCK(dev);
	for(i=0; i < OFP_NUM_IFNET_IP_ADDRS && dev->ip_addr_info[i].ip_addr; i++)
	{
		uint32_t mask = ~0;
		mask = odp_cpu_to_be_32(mask << (32 - dev->ip_addr_info[i].masklen));
		ofp_sendf(fd,
				"       inet addr:%s    Bcast:%s        Mask:%s\r\n",
				ofp_print_ip_addr(dev->ip_addr_info[i].ip_addr),
				ofp_print_ip_addr(dev->ip_addr_info[i].bcast_addr),
				ofp_print_ip_addr(mask));
	}
	IP_ADDR_LIST_RUNLOCK(dev);
	ofp_sendf(fd,"\r\n");
}

#ifdef INET6
struct ofp_in_ifaddrhead *ofp_get_ifaddr6head(void)
{
	return &shm->in_ifaddr6head;
}

void ofp_ifaddr6_elem_add(struct ofp_ifnet *ifnet)
{
	struct ofp_ifnet *ia6;

	OFP_IFNET_LOCK_WRITE(ifaddr6_list);

	OFP_TAILQ_FOREACH(ia6, ofp_get_ifaddr6head(), ia6_link) {
		if (ia6 == ifnet)
			break;
	}

	if (!ia6)
		OFP_TAILQ_INSERT_TAIL(ofp_get_ifaddr6head(), ifnet, ia6_link);

	OFP_IFNET_UNLOCK_WRITE(ifaddr6_list);
}

void ofp_ifaddr6_elem_del(struct ofp_ifnet *ifnet)
{
	struct ofp_ifnet *ia6;

	OFP_IFNET_LOCK_WRITE(ifaddr6_list);

	OFP_TAILQ_FOREACH(ia6, ofp_get_ifaddr6head(), ia6_link) {
		if (ia6 == ifnet)
			break;
	}

	if (ia6)
		OFP_TAILQ_REMOVE(ofp_get_ifaddr6head(), ifnet, ia6_link);

	OFP_IFNET_UNLOCK_WRITE(ifaddr6_list);
}

struct ofp_ifnet *ofp_ifaddr6_elem_get(uint8_t *addr6)
{
	struct ofp_ifnet *ifa6 = NULL;

	OFP_IFNET_LOCK_WRITE(ifaddr6_list);

	OFP_TAILQ_FOREACH(ifa6, ofp_get_ifaddr6head(), ia6_link) {
		if (!memcmp(ifa6->ip6_addr, addr6, 16))
			break;
	}

	OFP_IFNET_UNLOCK_WRITE(ifaddr6_list);
	return ifa6;
}
#endif /* INET6 */
