/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <stdio.h>
#include <string.h>

#include "ofpi.h"
#include "odp/rwlock.h"
#include "ofpi_rt_lookup.h"
#include "ofpi_route.h"

#include "ofpi_util.h"
#include "ofpi_pkt_processing.h"
#include "ofpi_arp.h"
#include "ofpi_avl.h"
#include "ofpi_portconf.h"
#include "ofpi_log.h"

#define SHM_NAME_ROUTE "OfpRouteShMem"
#define SHM_NAME_ROUTE_LK "OfpLocksShMem"

#define USE_RW_LOCK 1

/* number of saved packets waiting for Neighbor Advertisement */
#define NUM_PKTS 2048

/*
 * Structure definitions
 */
struct routes_by_vrf {
	uint16_t vrf;
	struct ofp_rtl_tree routes;
};

struct pkt6_entry {
	odp_packet_t pkt;

	OFP_SLIST_ENTRY(pkt6_entry) next;
};

struct _pkt6 {
	struct pkt6_entry entries[NUM_PKTS] ODP_ALIGNED_CACHE;
	struct pkt6_list free_entries;
	odp_rwlock_t fr_ent_rwlock;
};


/*
 * Shared data
 */
struct ofp_route_mem {
	avl_tree *vrf_routes;
	struct ofp_rtl_tree default_routes;
	struct ofp_rtl6_tree default_routes_6;
	struct _pkt6 pkt6;
};

/*
 * Data per core
 */

static __thread struct ofp_route_mem *shm;
struct ofp_locks_str *ofp_locks_shm;

static int free_data(void *data);
#ifdef INET6
static void route6_cleanup(int fd, uint8_t *key, int level,
		struct ofp_nh6_entry *data);
#endif /* INET6 */

static int routes_avl_compare(void *compare_arg, void *a, void *b)
{
	(void) compare_arg;
	struct routes_by_vrf *a1 = a;
	struct routes_by_vrf *b1 = b;

	return (a1->vrf - b1->vrf);
}

void ofp_route_init_global(void)
{
	int i;

	odp_rwlock_init(&ofp_locks_shm->lock_config_rw);
	odp_rwlock_init(&ofp_locks_shm->lock_route_rw);

	ofp_rt_lookup_init_global();

	/*avl_tree_new(routes_avl_compare, NULL);*/
	ofp_rtl_init(&shm->default_routes);
	ofp_rtl6_init(&shm->default_routes_6);
	shm->vrf_routes = avl_tree_new(routes_avl_compare, NULL);

	odp_rwlock_init(&shm->pkt6.fr_ent_rwlock);
	memset(shm->pkt6.entries, 0, sizeof(shm->pkt6.entries));
	OFP_SLIST_INIT(&shm->pkt6.free_entries);
	for (i = NUM_PKTS - 1; i >= 0; --i)
		OFP_SLIST_INSERT_HEAD(&shm->pkt6.free_entries,
			&shm->pkt6.entries[i], next);
}

static inline void *pkt6_entry_alloc(void)
{
	struct pkt6_entry *pktentry;

	odp_rwlock_write_lock(&shm->pkt6.fr_ent_rwlock);

	pktentry = OFP_SLIST_FIRST(&shm->pkt6.free_entries);

	if (pktentry)
		OFP_SLIST_REMOVE_HEAD(&shm->pkt6.free_entries, next);

	odp_sync_stores();
	odp_rwlock_write_unlock(&shm->pkt6.fr_ent_rwlock);

	return pktentry;
}

static inline void pkt6_entry_free(struct pkt6_entry *pktentry)
{
	memset(pktentry, 0, sizeof(*pktentry));

	odp_rwlock_write_lock(&shm->pkt6.fr_ent_rwlock);
	OFP_SLIST_INSERT_HEAD(&shm->pkt6.free_entries, pktentry, next);
	odp_sync_stores();
	odp_rwlock_write_unlock(&shm->pkt6.fr_ent_rwlock);
}


/* ARP related functions */
int ofp_add_mac(struct ofp_ifnet *dev, uint32_t addr, uint8_t *mac)
{
	int ret;

	OFP_DBG("Port %d vlan %d vrf %d add_mac ip %s - MAC %s",
		dev->port, dev->vlan, dev->vrf,
		ofp_print_ip_addr(addr), ofp_print_mac(mac));

	ret = ofp_arp_ipv4_insert(addr, mac, dev);

	return ret;
}

int ofp_get_mac(struct ofp_ifnet *dev, uint32_t addr, uint8_t *mac_out)
{
	int ifindex;

	ifindex = ofp_ipv4_lookup_mac(addr, mac_out, dev);
	return ifindex;
}

int ofp_del_mac(struct ofp_ifnet *dev, uint32_t addr, uint8_t *mac)
{
	int ret;

	OFP_DBG("Port %d vlan %d vrf %d add_mac  ip %s - MAC %s" ,
		dev->port, dev->vlan , dev->vrf ,
		ofp_print_ip_addr(addr) , ofp_print_mac(mac));
	ret = ofp_arp_ipv4_remove(addr, dev);
	return ret;
}

struct ofp_nh6_entry *ofp_get_next_hop6(uint16_t vrf,
	uint8_t *addr, uint32_t *flags)
{
	struct ofp_nh6_entry *nh6;

	(void) vrf;
	(void) flags;

	OFP_LOCK_READ(route);
	nh6 = ofp_rtl_search6(&shm->default_routes_6, addr);
	OFP_UNLOCK_READ(route);

	return nh6;
}

void ofp_add_mac6(struct ofp_ifnet *dev, uint8_t *addr, uint8_t *mac)
{
	struct ofp_nh6_entry *nh;
	struct pkt6_entry *pktentry;
	struct pkt6_list pkt6_send;

	OFP_LOCK_READ(route);
	nh = ofp_rtl_search6(&shm->default_routes_6, addr);
	if (!nh) {
		OFP_DBG("Cannot add MAC for %s", ofp_print_ip6_addr(addr));
		OFP_UNLOCK_READ(route);
		return;
	}

	OFP_DBG("Added MAC for %s (%s)",
		ofp_print_ip6_addr(addr),
		ofp_port_vlan_to_ifnet_name(dev->port, dev->vlan));

	memcpy(nh->mac, mac, 6);

	/* We need to
		- copy pkt list to release lock while sending packets
		- reverse pkt list to send data in proper order*/
	OFP_SLIST_INIT(&pkt6_send);
	while ((pktentry = OFP_SLIST_FIRST(&nh->pkt6_hold))) {
		OFP_SLIST_REMOVE_HEAD(&nh->pkt6_hold, next);
		OFP_SLIST_INSERT_HEAD(&pkt6_send, pktentry, next);
	}
	OFP_SLIST_INIT(&nh->pkt6_hold);
	OFP_UNLOCK_READ(route);

	while ((pktentry = OFP_SLIST_FIRST(&pkt6_send))) {
		OFP_SLIST_REMOVE_HEAD(&pkt6_send, next);
		if (ofp_ip6_output(pktentry->pkt, nh) == OFP_PKT_DROP)
			odp_packet_free(pktentry->pkt);
		pkt6_entry_free(pktentry);
	}
}

static int add_route(struct ofp_route_msg *msg)
{
	struct ofp_nh_entry tmp;

	OFP_LOCK_WRITE(route);

	tmp.gw = msg->gw;
	tmp.port = msg->port;
	tmp.vlan = msg->vlan;

	OFP_DBG("Adding route vrf=%d addr=%s/%d", msg->vrf,
		   ofp_print_ip_addr(msg->dst), msg->masklen);
	if (msg->vrf) {
		struct routes_by_vrf key, *data;

		key.vrf = msg->vrf;
		if (avl_get_by_key(shm->vrf_routes, &key, (void *)&data)) {
			OFP_DBG("VRF does not yet exist");
			data = malloc(sizeof(*data));
			memset(data, 0, sizeof(*data));
			data->vrf = msg->vrf;
			ofp_rtl_root_init(&(data->routes), msg->vrf);
			avl_insert(shm->vrf_routes, data);
		}
		if (ofp_rtl_insert(&(data->routes), msg->dst,
				msg->masklen, &tmp))
			OFP_ERR("ofp_rtl_insert failed");
	} else {
		if (ofp_rtl_insert(&shm->default_routes, msg->dst,
				msg->masklen, &tmp))
			OFP_ERR("ofp_rtl_insert failed");
	}
#ifdef MTRIE
	ofp_rt_rule_add(msg->vrf, msg->dst, msg->masklen, &tmp);
#endif

	OFP_UNLOCK_WRITE(route);

	return 0;
}

static int del_route(struct ofp_route_msg *msg)
{
	OFP_DBG("Deleting route vrf=%d addr=%s/%d", msg->vrf,
		   ofp_print_ip_addr(msg->dst), msg->masklen);

	OFP_LOCK_WRITE(route);

	if (msg->vrf) {
		struct routes_by_vrf key, *data;

		key.vrf = msg->vrf;
		if (avl_get_by_key(shm->vrf_routes, &key, (void *)&data)) {
			OFP_DBG("VRF does not exist");
			OFP_UNLOCK_WRITE(route);
			return -1;
		}
		if (!ofp_rtl_remove(&(data->routes), msg->dst, msg->masklen))
			OFP_DBG("ofp_rtl_remove failed");
	} else {
		if (!ofp_rtl_remove(&shm->default_routes, msg->dst, msg->masklen))
			OFP_DBG("ofp_rtl_remove failed");
	}
#ifdef MTRIE
	ofp_rt_rule_remove(msg->vrf, msg->dst, msg->masklen);
#endif

	OFP_UNLOCK_WRITE(route);

	return 0;
}
#ifdef INET6
static int add_route6(struct ofp_route_msg *msg)
{
	struct ofp_nh6_entry tmp;

	memset(&tmp, 0, sizeof(tmp));

	OFP_LOCK_WRITE(route);

	memcpy(tmp.gw, msg->gw6, 16);
	tmp.port = msg->port;
	tmp.vlan = msg->vlan;
	OFP_SLIST_INIT(&tmp.pkt6_hold);

	OFP_DBG("Adding ipv6 route vrf=%d addr=%s/%d gw=%s", msg->vrf,
		   ofp_print_ip6_addr(msg->dst6), msg->masklen,
		   ofp_print_ip6_addr(msg->gw6));

	if (ofp_rtl_insert6(&shm->default_routes_6, msg->dst6,
			msg->masklen, &tmp))
		OFP_DBG("ofp_rtl_insert6 failed");

	OFP_UNLOCK_WRITE(route);

	return 0;
}

static int del_route6(struct ofp_route_msg *msg)
{
	struct ofp_nh6_entry *nh6;
	struct pkt6_entry *pktentry;

	OFP_DBG("Deleting route vrf=%d addr=%s/%d", msg->vrf,
		   ofp_print_ip6_addr(msg->dst6), msg->masklen);

	OFP_LOCK_WRITE(route);

	nh6 = ofp_rtl_remove6(&shm->default_routes_6, msg->dst6, msg->masklen);

	if (nh6) {
		while ((pktentry = OFP_SLIST_FIRST(&nh6->pkt6_hold))) {
			OFP_SLIST_REMOVE_HEAD(&nh6->pkt6_hold, next);
			odp_packet_free(pktentry->pkt);
			pkt6_entry_free(pktentry);
		}
	} else
		OFP_DBG("ofp_rtl_remove6 failed");

	OFP_UNLOCK_WRITE(route);

	return 0;
}

int ofp_route_save_ipv6_pkt(odp_packet_t pkt,
	uint8_t *addr, struct ofp_ifnet *dev)
{
	struct ofp_nh6_entry *nh6 = NULL;
	struct pkt6_entry *pktentry;

	(void)dev;

	OFP_LOCK_READ(route);
	nh6 = ofp_rtl_search6(&shm->default_routes_6, addr);
	if (!nh6) {
		OFP_UNLOCK_READ(route);
		return OFP_PKT_DROP;
	}

	pktentry = pkt6_entry_alloc();
	if (!pktentry) {
		OFP_UNLOCK_READ(route);
		return OFP_PKT_DROP;
	}
	pktentry->pkt = pkt;

	OFP_SLIST_INSERT_HEAD(&nh6->pkt6_hold, pktentry, next);

	OFP_UNLOCK_READ(route);
	return OFP_PKT_PROCESSED;
}
#endif /* INET6 */

static void show_routes(int fd, uint32_t key, int level, struct ofp_nh_entry *data)
{
	char buf[24];
	snprintf(buf, sizeof(buf), "%s/%d", ofp_print_ip_addr(odp_cpu_to_be_32(key)), level);
	ofp_sendf(fd, "%-18s %-15s %s\r\n",
		  buf,
		  ofp_print_ip_addr(data->gw),
		  ofp_port_vlan_to_ifnet_name(data->port, data->vlan));
}

#ifdef INET6
static void show_routes6(int fd, uint8_t *key, int level, struct ofp_nh6_entry *data)
{
	char buf[128];
	snprintf(buf, sizeof(buf), "%s/%d", ofp_print_ip6_addr(key), level);
	ofp_sendf(fd, "%-30s %-28s  %s\r\n",
		  buf,
		  ofp_print_ip6_addr(data->gw),
		  ofp_port_vlan_to_ifnet_name(data->port, data->vlan));
}
#endif /* INET6 */

static int iter_routes(void * key, void * iter_arg)
{
	struct routes_by_vrf *rbv = key;
	int fd = *((int *)iter_arg);
	ofp_sendf(fd, "VRF: %d\r\n", rbv->vrf);
#ifdef MTRIE
	ofp_rt_rule_print(fd, rbv->vrf, show_routes);
#else
	ofp_rtl_traverse(fd, &(rbv->routes), show_routes);
#endif
	return 0;
}

void ofp_show_routes(int fd, int what)
{
	switch (what) {
	case OFP_SHOW_ARP:
		ofp_sendf(fd,
			    "VRF  ADDRESS          MAC                AGE\r\n");
		ofp_arp_show_table(fd); /* ofp_rtl_traverse(fd, &shm->default_routes, show_arp); */
		break;
	case OFP_SHOW_ROUTES:
		ofp_sendf(fd, "Destination        Gateway         Iface\r\n");
#ifdef MTRIE
		ofp_rt_rule_print(fd, 0, show_routes);
#else
		ofp_rtl_traverse(fd, &shm->default_routes, show_routes);
#endif
		avl_iterate_inorder(shm->vrf_routes, iter_routes, &fd);
#ifdef INET6
		ofp_sendf(fd, "\r\nIPv6 routes\r\n");
		ofp_rtl_traverse6(fd, &shm->default_routes_6, show_routes6);
#endif /* INET6 */
		break;
	}
}

struct ofp_nh_entry *ofp_get_next_hop(uint16_t vrf, uint32_t addr, uint32_t *flags)
{
	(void) flags;
	struct ofp_nh_entry *node;

	if (vrf) {
		struct routes_by_vrf key, *data;

		key.vrf = vrf;
		if (avl_get_by_key(shm->vrf_routes, &key, (void *)&data)) {
			OFP_DBG("avl_get_by_key failed");
			return NULL;
		}
		OFP_LOCK_READ(route);
		node = ofp_rtl_search(&(data->routes), addr);
		OFP_UNLOCK_READ(route);
	} else {
		OFP_LOCK_READ(route);
		node = ofp_rtl_search(&shm->default_routes, addr);
		OFP_UNLOCK_READ(route);
	}

	return node;
}

static int add_local_interface(struct ofp_route_msg *msg)
{
	msg->masklen = 32;
	return add_route(msg);
}

static int del_local_interface(struct ofp_route_msg *msg)
{
		OFP_LOCK_WRITE(route);
		if (!ofp_rtl_remove(&shm->default_routes, msg->dst, 32))
			OFP_DBG("ofp_rtl_remove failed");
		OFP_UNLOCK_WRITE(route);

		return 0;
}

int32_t ofp_set_route_msg(struct ofp_route_msg *msg)
{
		/*printf("routing msg: type = %d, dst=%x/%d, gw=%x\n",
		  msg->type, msg->dst, msg->masklen, msg->gw);*/
		if (msg->type == OFP_ROUTE_ADD)
				return add_route(msg);

		if (msg->type == OFP_ROUTE_DEL)
				return del_route(msg);
#ifdef INET6
		if (msg->type == OFP_ROUTE6_ADD)
				return add_route6(msg);

		if (msg->type == OFP_ROUTE6_DEL)
				return del_route6(msg);
#endif /* INET6 */
/*
TODO hash implementation for OFP_MOBILE_ROUTE_ADD,OFP_MOBILE_ROUTE_DEL
*/
		if (msg->type == OFP_LOCAL_INTERFACE_ADD)
				return add_local_interface(msg);

		if (msg->type == OFP_LOCAL_INTERFACE_DEL)
				return del_local_interface(msg);

		return -1;
}

int32_t ofp_is_mobile(uint32_t addr)
{
	(void) addr;
		/* TODO find other hash implementation
		*/
		return 0;
}

struct find_vlan_data {
	uint32_t addr;
	uint16_t vlan;
};

static int iter_vrfs(void *key, void *iter_arg)
{
	struct routes_by_vrf *rbv = key;
	struct find_vlan_data *data = iter_arg;
	struct ofp_nh_entry *node = ofp_rtl_search(&(rbv->routes), data->addr);

	if (node) {
		data->vlan = node->vlan;
		return 1;
	}
	return 0;
}

uint16_t ofp_get_probable_vlan(int port, uint32_t addr)
{
	(void) port;
	struct ofp_nh_entry *node;
	struct find_vlan_data data;

	node = ofp_rtl_search(&shm->default_routes, addr);
	if (node)
		return node->vlan;

	data.addr = addr;
	data.vlan = 0;

	avl_iterate_inorder(shm->vrf_routes, iter_vrfs, &data);
	return data.vlan;
}

void ofp_route_alloc_shared_memory(void)
{
	ofp_rt_lookup_alloc_shared_memory();

	shm = ofp_shared_memory_alloc(SHM_NAME_ROUTE, sizeof(*shm));
	if (shm == NULL) {
		OFP_ABORT("%s shared mem alloc failed", SHM_NAME_ROUTE);
	}

	ofp_locks_shm = ofp_shared_memory_alloc(SHM_NAME_ROUTE_LK,
		sizeof(*ofp_locks_shm));
	if (ofp_locks_shm == NULL) {
		OFP_ABORT("%s shared mem alloc failed", SHM_NAME_ROUTE_LK);
	}

	memset(shm, 0, sizeof(*shm));
	memset(ofp_locks_shm, 0, sizeof(*ofp_locks_shm));
}

void ofp_route_free_shared_memory(void)
{
	ofp_shared_memory_free(SHM_NAME_ROUTE);
	shm = NULL;

	ofp_shared_memory_free(SHM_NAME_ROUTE_LK);
	ofp_locks_shm = NULL;

	ofp_rt_lookup_free_shared_memory();
}

void ofp_route_lookup_shared_memory(void)
{
	ofp_rt_lookup_lookup_shared_memory();

	shm = ofp_shared_memory_lookup(SHM_NAME_ROUTE);
	if (shm == NULL) {
		OFP_ABORT("%s shared mem lookup failed", SHM_NAME_ROUTE);
	}

	ofp_locks_shm = ofp_shared_memory_lookup(SHM_NAME_ROUTE_LK);
	if (ofp_locks_shm == NULL) {
		OFP_ABORT("%s shared mem lookup failed", SHM_NAME_ROUTE_LK);
	}
}

void ofp_route_term_global(void)
{
	if (shm->vrf_routes) {
		avl_tree_free(shm->vrf_routes, free_data);
		shm->vrf_routes = NULL;
	}

#ifdef INET6
	ofp_rtl_traverse6(0, &shm->default_routes_6, route6_cleanup);
#endif /*INET6*/

	memset(shm, 0, sizeof(*shm));

	ofp_rt_lookup_term_global();
}

static int free_data(void *data)
{
	free(data);
	return 1;
}

#ifdef INET6
static void route6_cleanup(int fd, uint8_t *key, int level,
		struct ofp_nh6_entry *data)
{
	struct pkt6_entry *pktentry;

	(void)fd;
	(void)key;
	(void)level;

	while ((pktentry = OFP_SLIST_FIRST(&data->pkt6_hold))) {
		OFP_SLIST_REMOVE_HEAD(&data->pkt6_hold, next);
		odp_packet_free(pktentry->pkt);
		pkt6_entry_free(pktentry);
	}
}
#endif /* INET6 */
