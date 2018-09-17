/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <stdio.h>
#include <string.h>

#include "ofpi.h"
#include <odp_api.h>
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
#define SHM_NAME_VRF_ROUTE "OfpVrfRouteShMem"

/* number of saved packets waiting for Neighbor Advertisement */
#define NUM_PKTS 2048

/*
 * Structure definitions
 */
struct routes_by_vrf {
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
	struct ofp_rtl6_tree default_routes_6;
	struct _pkt6 pkt6;
};

struct vrf_route_mem {
	struct routes_by_vrf fib[0];
};

/*
 * Data per core
 */

static __thread struct ofp_route_mem *shm;
static __thread struct vrf_route_mem *vrf_shm;

struct ofp_locks_str *ofp_locks_shm;

#ifdef INET6
static void route6_cleanup(int fd, uint8_t *key, int level,
		struct ofp_nh6_entry *data);
#endif /* INET6 */

static inline void *pkt6_entry_alloc(void)
{
	struct pkt6_entry *pktentry;

	odp_rwlock_write_lock(&shm->pkt6.fr_ent_rwlock);

	pktentry = OFP_SLIST_FIRST(&shm->pkt6.free_entries);

	if (pktentry)
		OFP_SLIST_REMOVE_HEAD(&shm->pkt6.free_entries, next);

	odp_rwlock_write_unlock(&shm->pkt6.fr_ent_rwlock);

	return pktentry;
}

static inline void pkt6_entry_free(struct pkt6_entry *pktentry)
{
	memset(pktentry, 0, sizeof(*pktentry));

	odp_rwlock_write_lock(&shm->pkt6.fr_ent_rwlock);
	OFP_SLIST_INSERT_HEAD(&shm->pkt6.free_entries, pktentry, next);
	odp_rwlock_write_unlock(&shm->pkt6.fr_ent_rwlock);
}

/* ARP related functions */
int ofp_add_mac(struct ofp_ifnet *dev, uint32_t addr, uint8_t *mac)
{
	OFP_DBG("Adding MAC=%s IP=%s on device port=%d vlan=%d vrf=%d",
		ofp_print_mac(mac), ofp_print_ip_addr(addr),
		dev->port, dev->vlan, dev->vrf);

	return ofp_arp_ipv4_insert(addr, mac, dev);
}

int ofp_get_mac(struct ofp_ifnet *dev, struct ofp_nh_entry *nh_data,
		uint32_t addr, uint32_t is_link_local, uint8_t *mac_out)
{
#ifndef OFP_USE_LIBCK
	if (!is_link_local)
		return ofp_ipv4_get_mac_by_idx(mac_out, nh_data->arp_ent_idx);
#else
	(void)nh_data;
	(void)is_link_local;
#endif
	return ofp_ipv4_lookup_mac(addr, mac_out, dev);
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

#ifdef INET6
void ofp_add_mac6(struct ofp_ifnet *dev, uint8_t *addr, uint8_t *mac)
{
	struct ofp_nh6_entry *nh;
	struct pkt6_entry *pktentry;
	struct pkt6_list pkt6_send;

	OFP_LOCK_READ(route);
	nh = ofp_rtl_search6(&shm->default_routes_6, addr);
	if (!nh) {
		OFP_DBG("Cannot add mac for %s", ofp_print_ip6_addr(addr));
		OFP_UNLOCK_READ(route);
		return;
	}

	(void) dev;
	OFP_DBG("MAC added for %s (%s)", ofp_print_ip6_addr(addr),
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
#endif

static int add_route(struct ofp_route_msg *msg)
{
	struct ofp_nh_entry tmp;
	uint8_t  eth_addr[OFP_ETHER_ADDR_LEN];
	odp_bool_t route_add_success = TRUE;
	struct routes_by_vrf *fib;
	int ret = 0;

	memset(&eth_addr, 0, sizeof(eth_addr));
#ifndef OFP_USE_LIBCK
	if (ofp_ipv4_lookup_arp_entry_idx(msg->gw, msg->vrf,
					  &tmp.arp_ent_idx) < 0) {
		if (ofp_arp_ipv4_insert_entry(msg->gw, eth_addr,
					      msg->vrf, FALSE,
					      &tmp.arp_ent_idx, NULL) < 0) {
			OFP_DBG("ARP insert failure in add route.");
			return -1;
		}
	}
#endif

	OFP_LOCK_WRITE(route);

#ifndef OFP_USE_LIBCK
	ofp_arp_inc_ref_count(tmp.arp_ent_idx);
#endif
	tmp.gw = msg->gw;
	tmp.port = msg->port;
	tmp.vlan = msg->vlan;
	tmp.flags = msg->flags;

	OFP_DBG("Adding route vrf=%d dst=%s/%d gw=%s arp idx=%u", msg->vrf,
		ofp_print_ip_addr(msg->dst), msg->masklen,
		ofp_print_ip_addr(msg->gw), tmp.arp_ent_idx);

	fib = &vrf_shm->fib[msg->vrf];
	if (ofp_rtl_insert(&fib->routes, msg->dst, msg->masklen, &tmp)) {
		OFP_DBG("ofp_rtl_insert failed");
		route_add_success = FALSE;
	}
#ifndef OFP_USE_LIBCK
	if (!route_add_success) {
		ofp_arp_dec_ref_count(tmp.arp_ent_idx);
		ofp_arp_ipv4_remove_entry_idx(tmp.arp_ent_idx);
	}
#endif

#ifdef MTRIE
	ret = ofp_rt_rule_add(msg->vrf, msg->dst, msg->masklen, &tmp);
#endif
	OFP_UNLOCK_WRITE(route);
	OFP_DBG("route_add_success = %d ret = %d tmp.port=%d tmp.vlan = %d \n",route_add_success,ret, tmp.port,tmp.vlan);
	if (route_add_success && !ret) {
		if ((tmp.flags & OFP_RTF_LOCAL) && (msg->masklen == 32)) {
			OFP_DBG("Adding static route for %s\n", ofp_print_ip_addr(msg->dst));
			struct ofp_ifnet *ifnet = ofp_get_create_ifnet(tmp.port, tmp.vlan);
			if (NULL != ifnet) {
				ofp_ifnet_ip_add(ifnet, msg->dst);
			}
		}
	}
	return 0;
}

static int del_route(struct ofp_route_msg *msg)
{
	struct ofp_nh_entry *nh_data;
	struct routes_by_vrf *fib;

	OFP_DBG("Deleting route vrf=%d addr=%s/%d", msg->vrf,
		   ofp_print_ip_addr(msg->dst), msg->masklen);

	OFP_LOCK_WRITE(route);

	fib = &vrf_shm->fib[msg->vrf];
	nh_data = ofp_rtl_remove(&fib->routes, msg->dst, msg->masklen);

	if (!nh_data)
		OFP_DBG("ofp_rtl_remove failed");
#ifndef OFP_USE_LIBCK
	else
		ofp_arp_dec_ref_count(nh_data->arp_ent_idx);
#endif

#ifdef MTRIE
	ofp_rt_rule_remove(msg->vrf, msg->dst, msg->masklen);
#endif

	OFP_UNLOCK_WRITE(route);

	if (NULL != nh_data) {
		if (nh_data->flags & OFP_RTF_LOCAL) {
			struct ofp_ifnet *ifnet;
			ifnet = ofp_get_ifnet(nh_data->port, nh_data->vlan);
			if (!ifnet)
				OFP_INFO("ofp_rt_rule_remove Interface doesn't exist\n");
			else {
				ofp_ifnet_ip_remove(ifnet, msg->dst);
			}
		}
	}

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
	tmp.flags = msg->flags;
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

enum ofp_return_code ofp_route_save_ipv6_pkt(odp_packet_t pkt,
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

static void send_flags(int fd, uint32_t flags)
{
	if (flags & OFP_RTF_NET)
		ofp_sendf(fd, " net");
	if (flags & OFP_RTF_GATEWAY)
		ofp_sendf(fd, " gateway");
	if (flags & OFP_RTF_HOST)
		ofp_sendf(fd, " host");
	if (flags & OFP_RTF_REJECT)
		ofp_sendf(fd, " reject");
	if (flags & OFP_RTF_BLACKHOLE)
		ofp_sendf(fd, " blackhole");
	if (flags & OFP_RTF_LOCAL)
		ofp_sendf(fd, " local");
	if (flags & OFP_RTF_BROADCAST)
		ofp_sendf(fd, " bcast");
	if (flags & OFP_RTF_MULTICAST)
		ofp_sendf(fd, " mcast");
}

static void show_routes(int fd, uint32_t key, int level, struct ofp_nh_entry *data)
{
	char buf[24];
	snprintf(buf, sizeof(buf), "%s/%d", ofp_print_ip_addr(odp_cpu_to_be_32(key)), level);
	ofp_sendf(fd, "%-18s %-15s %s   ",
		  buf,
		  ofp_print_ip_addr(data->gw),
		  ofp_port_vlan_to_ifnet_name(data->port, data->vlan));
	send_flags(fd, data->flags);
	ofp_sendf(fd, "\r\n");
}

#ifdef INET6
static void show_routes6(int fd, uint8_t *key, int level, struct ofp_nh6_entry *data)
{
	char buf[128];
	snprintf(buf, sizeof(buf), "%s/%d", ofp_print_ip6_addr(key), level);
	ofp_sendf(fd, "%-30s %-28s  %s ",
		  buf,
		  ofp_print_ip6_addr(data->gw),
		  ofp_port_vlan_to_ifnet_name(data->port, data->vlan));
	send_flags(fd, data->flags);
	ofp_sendf(fd, "\r\n");
}
#endif /* INET6 */

static void iter_routes(int fd, int vrf, struct ofp_rtl_tree *tree)
{
	ofp_sendf(fd, "VRF: %d\r\n", vrf);
#ifdef MTRIE
	(void) tree;
	ofp_rt_rule_print(fd, vrf, show_routes);
#else
	ofp_rtl_traverse(fd, tree, show_routes);
#endif
}

void ofp_show_routes(int fd, int what)
{
	int i;

	switch (what) {
	case OFP_SHOW_ARP:
		ofp_sendf(fd,
			    "VRF  ADDRESS          MAC                AGE\r\n");
		ofp_arp_show_table(fd);
		break;
	case OFP_SHOW_ROUTES:
		ofp_sendf(fd, "Destination        Gateway         Iface  Flags\r\n");
		for (i = 0; i < global_param->num_vrf; i++)
			iter_routes(fd, i, &vrf_shm->fib[i].routes);
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
	struct routes_by_vrf *fib;

	fib = &vrf_shm->fib[vrf];
#ifndef MTRIE
	OFP_LOCK_READ(route);
#endif
	node = ofp_rtl_search(&fib->routes, addr);
#ifndef MTRIE
	OFP_UNLOCK_READ(route);
#endif

	return node;
}

static int add_local_interface(struct ofp_route_msg *msg)
{
	msg->masklen = 32;
	msg->flags = OFP_RTF_LOCAL;
	return add_route(msg);
}

static int del_local_interface(struct ofp_route_msg *msg)
{
	OFP_LOCK_WRITE(route);
	if (!ofp_rtl_remove(&vrf_shm->fib[msg->vrf].routes, msg->dst, 32))
		OFP_DBG("ofp_rtl_remove failed");
	OFP_UNLOCK_WRITE(route);

	return 0;
}

int32_t ofp_set_route_msg(struct ofp_route_msg *msg)
{
		if (msg->vrf >= global_param->num_vrf) {
			OFP_ERR("VRF ID too big\n");
			return -1;
		}

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

static int ofp_route_alloc_shared_memory(void)
{
	shm = ofp_shared_memory_alloc(SHM_NAME_ROUTE, sizeof(*shm));
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}

	ofp_locks_shm = ofp_shared_memory_alloc(SHM_NAME_ROUTE_LK,
		sizeof(*ofp_locks_shm));
	if (ofp_locks_shm == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}

	return 0;
}

static int ofp_route_free_shared_memory(void)
{
	int rc = 0;

	if (ofp_shared_memory_free(SHM_NAME_ROUTE) == -1) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}
	shm = NULL;

	if (ofp_shared_memory_free(SHM_NAME_ROUTE_LK) == -1) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}
	ofp_locks_shm = NULL;

	return rc;
}

int ofp_route_lookup_shared_memory(void)
{
	HANDLE_ERROR(ofp_rt_lookup_lookup_shared_memory());

	shm = ofp_shared_memory_lookup(SHM_NAME_ROUTE);
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}

	ofp_locks_shm = ofp_shared_memory_lookup(SHM_NAME_ROUTE_LK);
	if (ofp_locks_shm == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}

	return 0;
}

#define SHM_SIZE_VRF_ROUTE  (sizeof(struct vrf_route_mem) + \
			     sizeof(struct routes_by_vrf) * global_param->num_vrf)

static int ofp_vrf_route_alloc_shared_memory(void)
{
	vrf_shm = ofp_shared_memory_alloc(SHM_NAME_VRF_ROUTE,
					  SHM_SIZE_VRF_ROUTE);
	if (vrf_shm == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}
	return 0;
}

static int ofp_vrf_route_free_shared_memory(void)
{
	int rc = 0;

	if (ofp_shared_memory_free(SHM_NAME_VRF_ROUTE) == -1) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}
	shm = NULL;

	return rc;
}

int ofp_vrf_route_lookup_shared_memory(void)
{
	HANDLE_ERROR(ofp_rt_lookup_lookup_shared_memory());

	vrf_shm = ofp_shared_memory_lookup(SHM_NAME_VRF_ROUTE);
	if (vrf_shm == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}

	return 0;
}

void ofp_route_init_prepare(void)
{
	ofp_rt_lookup_init_prepare();
	ofp_shared_memory_prealloc(SHM_NAME_ROUTE, sizeof(*shm));
	ofp_shared_memory_prealloc(SHM_NAME_ROUTE_LK, sizeof(*ofp_locks_shm));
	ofp_shared_memory_prealloc(SHM_NAME_VRF_ROUTE, SHM_SIZE_VRF_ROUTE);
}

int ofp_route_init_global(void)
{
	int i;

	HANDLE_ERROR(ofp_rt_lookup_init_global());

	HANDLE_ERROR(ofp_route_alloc_shared_memory());

	HANDLE_ERROR(ofp_vrf_route_alloc_shared_memory());

	memset(shm, 0, sizeof(*shm));
	for (i = 0; i < NUM_PKTS; i++)
		shm->pkt6.entries[i].pkt = ODP_PACKET_INVALID;

	memset(ofp_locks_shm, 0, sizeof(*ofp_locks_shm));
	odp_rwlock_init(&ofp_locks_shm->lock_config_rw);
	odp_rwlock_init(&ofp_locks_shm->lock_route_rw);

	HANDLE_ERROR(ofp_rtl6_init(&shm->default_routes_6));

	odp_rwlock_init(&shm->pkt6.fr_ent_rwlock);
	memset(shm->pkt6.entries, 0, sizeof(shm->pkt6.entries));
	OFP_SLIST_INIT(&shm->pkt6.free_entries);
	for (i = NUM_PKTS - 1; i >= 0; --i)
		OFP_SLIST_INSERT_HEAD(&shm->pkt6.free_entries,
			&shm->pkt6.entries[i], next);

	memset(vrf_shm, 0, sizeof(*vrf_shm));
	for (i = 0; i < global_param->num_vrf; i++)
		(void) ofp_rtl_root_init(&vrf_shm->fib[i].routes, i);

	return 0;
}

int ofp_route_term_global(void)
{
	int rc = 0;

	shm = ofp_shared_memory_lookup(SHM_NAME_ROUTE);
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		rc = -1;
	} else {
#ifdef INET6
		ofp_rtl_traverse6(0, &shm->default_routes_6, route6_cleanup);
#endif /*INET6*/
	}

	CHECK_ERROR(ofp_route_free_shared_memory(), rc);

	CHECK_ERROR(ofp_rt_lookup_term_global(), rc);

	vrf_shm = ofp_shared_memory_lookup(SHM_NAME_VRF_ROUTE);
	if (vrf_shm == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		rc = -1;
	}
	CHECK_ERROR(ofp_vrf_route_free_shared_memory(), rc);

	return rc;
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
