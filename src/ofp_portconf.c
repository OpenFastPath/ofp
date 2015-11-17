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

#include "ofpi.h"
#include "ofpi_portconf.h"
#include "ofpi_route.h"
#include "ofpi_util.h"
#include "ofpi_avl.h"

#include "ofpi_queue.h"
#include "ofpi_ioctl.h"
#include "ofpi_if_vxlan.h"
#include "ofpi_tree.h"
#include "ofpi_sysctl.h"
#include "ofpi_in_var.h"
#include "ofpi_log.h"
#include "ofpi_netlink.h"

#define SHM_NAME_PORTS "OfpPortconfShMem"
#define SHM_NAME_PORT_LOCKS "OfpPortconfLocksShMem"

#ifdef SP
#define NUM_LINUX_INTERFACES 512
#endif /*SP*/

#define PORT_UNDEF 0xFFFF

/*
 * Shared data
 */
struct ofp_portconf_mem {
	struct ofp_ifnet ofp_ifnet_data[NUM_PORTS];
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


/*
 * Data per core
 */
static __thread struct ofp_portconf_mem *shm;
struct ofp_ifnet_locks_str  *ofp_ifnet_locks_shm;

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

	compare_arg = compare_arg;

	return (a1->vlan - b1->vlan);
}

int ofp_portconf_init_global(void)
{
	int i;

	memset(&shm->ofp_ifnet_data, 0, sizeof(shm->ofp_ifnet_data));

	shm->ofp_num_ports = NUM_PORTS;

	for (i = 0; i < shm->ofp_num_ports; i++) {
		shm->ofp_ifnet_data[i].vlan_structs =
					new_vlan(vlan_ifnet_compare, NULL);
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
		odp_random_data((uint8_t *)shm->ofp_ifnet_data[i].mac,
				sizeof(shm->ofp_ifnet_data[i].mac), 0);
		/* Universally administered and locally administered addresses
		   are distinguished by setting the second least significant bit
		   of the most significant byte of the address.
		*/
		shm->ofp_ifnet_data[i].mac[0] = 0x02;
		/* Port number. */
		shm->ofp_ifnet_data[i].mac[1] = i;
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

static int vlan_match_ip(void *key, void *iter_arg)
{
	struct ofp_ifnet *iface = key;
	uint32_t ip = *((uint32_t *)iter_arg);

	if (iface->ip_addr == ip)
		return iface->vlan;
	else
		return 0;
}



static int iter_vlan(void *key, void *iter_arg)
{
	struct ofp_ifnet *iface = key;
	char buf[16];
	int fd = *((int *)iter_arg);

	uint32_t mask = ~0;

	mask = odp_cpu_to_be_32(mask << (32 - iface->masklen));

	if (iface->port == GRE_PORTS && iface->vlan) {
#ifdef SP
		ofp_sendf(fd, "gre%d	(%d) slowpath: %s\r\n", iface->vlan,
			    iface->linux_index,
			    iface->sp_status ? "on" : "off");
#else
		ofp_sendf(fd, "gre%d\r\n", iface->vlan);
#endif

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
			ofp_print_ip_addr(iface->ip_addr),
			ofp_print_ip_addr(iface->ip_p2p),
			ofp_print_ip_addr(mask),
#ifdef INET6
			ofp_print_ip6_addr(iface->link_local),
#endif /* INET6 */
			iface->if_mtu);

		ofp_sendf(fd,
			"	Local: %s	Remote: %s\r\n\r\n",
			ofp_print_ip_addr(iface->ip_local),
			ofp_print_ip_addr(iface->ip_remote));
		return 0;
	} else if (iface->port == GRE_PORTS && !iface->vlan) {
		ofp_sendf(fd, "gre%d\r\n"
				"	Link not configured\r\n\r\n",
				iface->vlan);
		return 0;
	}

	if (iface->port == VXLAN_PORTS) {
#ifdef SP
		ofp_sendf(fd, "vxlan%d	(%d) slowpath: %s\r\n", iface->vlan,
			    iface->linux_index,
			    iface->sp_status ? "on" : "off");
#else
		ofp_sendf(fd, "vxlan%d\r\n", iface->vlan);
#endif

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
			  ofp_print_ip_addr(iface->ip_addr),
			  ofp_print_ip_addr(iface->bcast_addr),
			  ofp_print_ip_addr(mask),
#ifdef INET6
			  ofp_print_ip6_addr(iface->link_local),
#endif /* INET6 */
			  ofp_print_ip_addr(iface->ip_p2p),
			  ofp_port_vlan_to_ifnet_name(iface->physport,
						      iface->physvlan),
			  iface->if_mtu);
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
#endif

		if (iface->vrf)
			ofp_sendf(fd, "	VRF: %d\r\n", iface->vrf);

		ofp_sendf(fd,
			"	Link encap:Ethernet	HWaddr: %s\r\n",
			ofp_print_mac(iface->mac));

		if (iface->ip_addr)
			ofp_sendf(fd,
				"	inet addr:%s	Bcast:%s	Mask:%s\r\n",
				ofp_print_ip_addr(iface->ip_addr),
				ofp_print_ip_addr(iface->bcast_addr),
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
			"	MTU: %d\r\n\r\n",
			iface->if_mtu);
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
}

int free_key(void *key)
{
	free(key);
	return 1;
}

static int exec_sys_call_depending_on_vrf(const char *cmd, uint16_t vrf)
{
	char buf[PATH_MAX];
	int netns;

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
		int ret = system(buf);
		if (ret < 0)
			OFP_WARN("System call failed: '%s'", buf);
		ofp_create_ns_socket(vrf);
	}
	close(netns);

	/* Dummy cmd to create a new namespace? */
	if (cmd == NULL || cmd[0] == 0)
		return 0;

	snprintf(buf, sizeof(buf), "ip netns exec vrf%d %s", vrf, cmd);
	return system(buf);
}

const char *ofp_config_interface_up_v4(int port, uint16_t vlan, uint16_t vrf,
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
#endif
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
		data = ofp_get_ifnet(port, vlan);
	}

	if (vlan) {
		if (data == NULL) {
			data = ofp_get_create_ifnet(port, vlan);
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
					     data->ip_addr, data->masklen, 0 /*gw*/);
		}
		data->vrf = vrf;
		data->ip_addr = addr;
		data->masklen = masklen;
		data->bcast_addr = addr | ~mask;
		ofp_set_route_params(OFP_ROUTE_ADD, data->vrf, vlan, port,
				     data->ip_addr, data->masklen, 0 /*gw*/);
#ifdef SP
		if (vrf == 0)
			data->sp_status = OFP_SP_UP;
		else
			data->sp_status = OFP_SP_DOWN;

		snprintf(cmd, sizeof(cmd), "ifconfig %s %s/%d up",
			 ofp_port_vlan_to_ifnet_name(port, vlan),
			 ofp_print_ip_addr(addr), masklen);
		ret = exec_sys_call_depending_on_vrf(cmd, vrf);
#endif /* SP */
	} else {
		if (data->ip_addr) {
			ofp_set_route_params(OFP_ROUTE_DEL, data->vrf, 0 /*vlan*/,
					     port, data->ip_addr, data->masklen,
					     0 /*gw*/);
		}

		data->vrf = vrf;
		data->ip_addr = addr;
		data->masklen = masklen;
		data->bcast_addr = addr | ~mask;

		/* Add interface to the if_addr v4 queue */
		ofp_ifaddr_elem_add(data);
#ifdef INET6
		ofp_mac_to_link_local(data->mac, data->link_local);
#endif /* INET6 */

		ofp_set_route_params(OFP_ROUTE_ADD, data->vrf, 0 /*vlan*/, port,
				     data->ip_addr, data->masklen, 0 /*gw*/);
#ifdef SP
		if (vrf == 0)
			data->sp_status = OFP_SP_UP;
		else
			data->sp_status = OFP_SP_DOWN;

		snprintf(cmd, sizeof(cmd), "ifconfig %s %s/%d up",
			 ofp_port_vlan_to_ifnet_name(port, 0),
			 ofp_print_ip_addr(addr), masklen);
		ret = exec_sys_call_depending_on_vrf(cmd, vrf);
#endif /* SP */
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
#endif

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
				     data->ip_p2p, data->masklen, 0 /*gw*/);
#ifdef SP
		snprintf(cmd, sizeof(cmd),
			 "ip addr del dev %s %s peer %s",
			 ofp_port_vlan_to_ifnet_name(port, greid),
			 ofp_print_ip_addr(data->ip_addr),
			 ofp_print_ip_addr(data->ip_p2p));
		ret = exec_sys_call_depending_on_vrf(cmd, data->vrf);
#endif /* SP */
	}

	data->vrf = vrf;
	data->ip_local = tun_loc;
	data->ip_remote = tun_rem;
	data->ip_p2p = p2p;
	data->ip_addr = addr;
	data->masklen = mlen;
	data->if_mtu = dev_root->if_mtu - sizeof(struct ofp_greip);

	ofp_set_route_params(OFP_ROUTE_ADD, data->vrf, greid, port,
			     data->ip_p2p, data->masklen, 0 /*gw*/);

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

void ofp_join_device_to_multicat_group(struct ofp_ifnet *dev_root,
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

#ifdef SP
	(void)ret;
	(void)new;
#endif
	(void)vrf; /* vrf is copied from the root device */

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
	data->ip_addr = addr;
	data->masklen = mlen;
	data->bcast_addr = addr | ~odp_cpu_to_be_32(~0 << (32 - mlen));
	data->if_mtu = dev_root->if_mtu - sizeof(struct ofp_vxlan_udp_ip);
	data->physport = physport;
	data->physvlan = physvlan;
	data->pkt_pool = ofp_packet_pool;

	/* Add interface to the if_addr v4 queue */
	ofp_ifaddr_elem_add(data);

	shm->ofp_ifnet_data[VXLAN_PORTS].pkt_pool = ofp_packet_pool;
	ofp_set_route_params(OFP_ROUTE_ADD, data->vrf, vni, VXLAN_PORTS,
			     data->ip_addr, data->masklen, 0 /*gw*/);

	/* Join root device to multicast group. */
	ofp_join_device_to_multicat_group(dev_root, data, group);

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
#endif
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
						      data->ip6_prefix, gw6);
			}
		}

		memcpy(data->ip6_addr, addr, 16);
		data->ip6_prefix = masklen;
		ofp_set_route6_params(OFP_ROUTE6_ADD, 0 /*vrf*/, vlan, port,
				      data->ip6_addr, data->ip6_prefix, gw6);
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
					      gw6);
		}
		memcpy(data->ip6_addr, addr, 16);
		data->ip6_prefix = masklen;

		ofp_mac_to_link_local(data->mac, data->link_local);

		/* Add interface to the if_addr v6 queue */
		ofp_ifaddr6_elem_add(data);

		ofp_set_route6_params(OFP_ROUTE6_ADD, 0 /*vrf*/, 0 /*vlan*/, port,
				      data->ip6_addr, data->ip6_prefix, gw6);
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
#endif
	memset(gw6, 0, 16);

	if (port < 0 || port >= shm->ofp_num_ports)
		return "Wrong port number";

	if (vlan) {
		struct ofp_ifnet key;

		key.vlan = vlan;
		if (ofp_vlan_get_by_key(
			shm->ofp_ifnet_data[port].vlan_structs,
			&key,
			(void *)&data))
			return "Unknown interface";

#ifdef SP
		vrf = data->vrf;
#endif
		if (data->ip_addr) {
			ofp_set_route_params(OFP_ROUTE_DEL, data->vrf, vlan, port,
					     (data->port == GRE_PORTS) ? data->ip_p2p : data->ip_addr,
					     data->masklen, 0 /*gw*/);
#ifdef SP
			snprintf(cmd, sizeof(cmd),
				 "ifconfig %s 0.0.0.0",
				 ofp_port_vlan_to_ifnet_name(port, vlan));
			ret = exec_sys_call_depending_on_vrf(cmd, vrf);
#endif /*SP*/
		}
#ifdef INET6
		if (ofp_ip6_is_set(data->ip6_addr)) {
			ofp_set_route6_params(OFP_ROUTE6_DEL, 0 /*vrf*/, vlan, port,
					      data->ip6_addr, data->ip6_prefix, gw6);
#ifdef SP
			snprintf(cmd, sizeof(cmd),
				 "ifconfig %s inet6 del %s/%d",
				 ofp_port_vlan_to_ifnet_name(port, vlan),
				 ofp_print_ip6_addr(data->ip6_addr),
				 data->ip6_prefix);

			ret = exec_sys_call_depending_on_vrf(cmd, vrf);
#endif /* SP */
		}
#endif /* INET6 */

		if (data->port == VXLAN_PORTS &&
		    data->ii_inet.ii_allhosts) {
			/* Use data->ii_inet.ii_allhosts for Vxlan. */
			ofp_in_leavegroup(data->ii_inet.ii_allhosts, NULL);
		}

		vlan_ifnet_delete(
			shm->ofp_ifnet_data[port].vlan_structs,
			&key,
			free_key);
#ifdef SP
		if (data->port == GRE_PORTS)
			snprintf(cmd, sizeof(cmd), "ip tunnel del %s",
				 ofp_port_vlan_to_ifnet_name(port, vlan));
		else
			snprintf(cmd, sizeof(cmd), "ip link del %s",
				 ofp_port_vlan_to_ifnet_name(port, vlan));
		ret = exec_sys_call_depending_on_vrf(cmd, vrf);
#endif /*SP*/
	} else {
		data = ofp_get_ifnet(port, vlan);

#ifdef SP
		vrf = data->vrf;
#endif
		if (data->ip_addr) {
			ofp_set_route_params(OFP_ROUTE_DEL, data->vrf, 0 /*vlan*/, port,
					     data->ip_addr, data->masklen, 0 /*gw*/);
#ifdef SP
			snprintf(cmd, sizeof(cmd),
				 "ifconfig %s 0.0.0.0",
				 ofp_port_vlan_to_ifnet_name(port, 0));

			ret = exec_sys_call_depending_on_vrf(cmd, vrf);
#endif /* SP */
			data->ip_addr = 0;
			/* Remove interface from the if_addr v4 queue */
			ofp_ifaddr_elem_del(data);
		}
#ifdef INET6
		if (ofp_ip6_is_set(data->ip6_addr)) {
			ofp_set_route6_params(OFP_ROUTE6_DEL, 0 /*vrf*/, 0 /*vlan*/,
					      port, data->ip6_addr, data->ip6_prefix,
					      gw6);
#ifdef SP
			snprintf(cmd, sizeof(cmd),
				 "ifconfig %s inet6 del %s/%d",
				 ofp_port_vlan_to_ifnet_name(port, vlan),
				 ofp_print_ip6_addr(data->ip6_addr),
				 data->ip6_prefix);

			ret = exec_sys_call_depending_on_vrf(cmd, vrf);
#endif
			memset(data->ip6_addr, 0, 16);

			/* Remove interface from the if_addr v4 queue */
			ofp_ifaddr6_elem_del(data);
		}
#endif /* INET6 */
	}

	return NULL;
}

struct ofp_ifnet *ofp_get_ifnet(int port, uint16_t vlan)
{
	if (port >= shm->ofp_num_ports) {
		OFP_ERR("ifnet port larger than structure allocated!");
		return NULL;
	}

	if (vlan) {
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
	if (vlan) {
		struct ofp_ifnet key, *data;

		key.vlan = vlan;
		if (ofp_vlan_get_by_key(
				shm->ofp_ifnet_data[port].vlan_structs,
				&key,
				(void *)&data)) {
			data = malloc(sizeof(*data));
			memset(data, 0, sizeof(*data));
			data->port = port;
			data->vlan = vlan;
			memcpy(data->mac, shm->ofp_ifnet_data[port].mac, 6);
			data->if_mtu = shm->ofp_ifnet_data[port].if_mtu;
#ifdef INET6
			memcpy(data->link_local,
				shm->ofp_ifnet_data[port].link_local, 16);
#endif /* INET6 */
			vlan_ifnet_insert(
				shm->ofp_ifnet_data[port].vlan_structs, data);
		}
		return data;
	}

	return &(shm->ofp_ifnet_data[port]);
}

int ofp_delete_ifnet(int port, uint16_t vlan)
{
	if (vlan) {
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

			if (ifnet->ip_addr == ip && ifnet->vrf == vrf && !vlan)
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
		iface->ip_addr;
	ifr->ifr_addr.sa_family = OFP_AF_INET;

	if (iface->port == GRE_PORTS)
		snprintf(ifr->ifr_name, OFP_IFNAMSIZ,
			 "gre%d", iface->vlan);
	else if (iface->port == VXLAN_PORTS)
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

	if (iface->ip_addr == iterdata->addr &&
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
		if (ifnet->ip_addr == ip && ifnet->vrf == vrf)
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
	return (struct ofp_ifnet *)odp_queue_context(
			odp_pktio_outq_getdef(pktio));
}
odp_queue_t ofp_pktio_spq_get(odp_pktio_t pktio)
{
#ifdef SP
	struct ofp_ifnet *ifnet = ofp_get_ifnet_pktio(pktio);

	return ifnet->spq_def;
#else
	(void)pktio;

	return ODP_QUEUE_INVALID;
#endif
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

int ofp_portconf_alloc_shared_memory(void)
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
		ofp_shared_memory_free(SHM_NAME_PORTS);
		return -1;
	}

	memset(shm, 0, sizeof(*shm));
	memset(ofp_ifnet_locks_shm, 0, sizeof(*ofp_ifnet_locks_shm));

	return 0;
}

void ofp_portconf_free_shared_memory(void)
{
	ofp_shared_memory_free(SHM_NAME_PORTS);
	shm = NULL;

	ofp_shared_memory_free(SHM_NAME_PORT_LOCKS);
	ofp_ifnet_locks_shm = NULL;
}

int ofp_portconf_lookup_shared_memory(void)
{
	shm = ofp_shared_memory_lookup(SHM_NAME_PORTS);
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		ofp_shared_memory_free(SHM_NAME_PORT_LOCKS);
		return -1;
	}

	ofp_ifnet_locks_shm = ofp_shared_memory_lookup(SHM_NAME_PORT_LOCKS);
	if (ofp_ifnet_locks_shm == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		ofp_shared_memory_free(SHM_NAME_PORTS);
		return -1;
	}

	return 0;
}

void ofp_portconf_term_global(void)
{
	int i;
	struct ofp_ifnet *ifnet;

	for (i = 0; i < shm->ofp_num_ports; ++i) {
		ifnet = &shm->ofp_ifnet_data[i];

		if (ifnet->if_state == OFP_IFT_STATE_FREE)
			continue;
		free_vlan(shm->ofp_ifnet_data[i].vlan_structs, free_key);

		ifnet->if_state = OFP_IFT_STATE_FREE;
	}
	memset(shm, 0, sizeof(*shm));
	memset(ofp_ifnet_locks_shm, 0, sizeof(*ofp_ifnet_locks_shm));
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

struct ofp_ifnet *ofp_ifaddr_elem_get(uint8_t *addr)
{
	struct ofp_ifnet *ifa;

	OFP_IFNET_LOCK_WRITE(ifaddr_list);

	OFP_TAILQ_FOREACH(ifa, ofp_get_ifaddrhead(), ia_link) {
		if (ifa->ip_addr == *(uint32_t *)addr)
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
		addr = dev->ip_addr;
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
