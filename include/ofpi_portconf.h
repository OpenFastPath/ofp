/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef _OFPI_PORTCONF_H_
#define _OFPI_PORTCONF_H_

#include <stdint.h>

#include "odp.h"
#include "linux.h"
#include "api/ofp_portconf.h"
#include "ofpi_ethernet.h"
#include "ofpi_queue.h"

#define NUM_PORTS 16
/* GRE ports are the last port assigned in the port vector.
 * Ports start from 0, and the last value is NUM_PORTS - 1.
 */
#define GRE_PORTS (NUM_PORTS - 1)
#define OFP_IFNAME_PREFIX "fp"
#define OFP_GRE_IFNAME_PREFIX "gre"

#define OFP_IFNET_LOCK_READ(name) odp_rwlock_read_lock(\
		&ofp_ifnet_locks_shm->lock_##name##_rw)
#define OFP_IFNET_UNLOCK_READ(name) odp_rwlock_read_unlock(\
		&ofp_ifnet_locks_shm->lock_##name##_rw)
#define OFP_IFNET_LOCK_WRITE(name) odp_rwlock_write_lock(\
		&ofp_ifnet_locks_shm->lock_##name##_rw)
#define OFP_IFNET_UNLOCK_WRITE(name) odp_rwlock_write_unlock(\
		&ofp_ifnet_locks_shm->lock_##name##_rw)

struct ofp_ifnet_locks_str {
	odp_rwlock_t lock_ifaddr_list_rw;
#ifdef INET6
	odp_rwlock_t lock_ifaddr6_list_rw;
#endif /* INET6 */
};

extern struct ofp_ifnet_locks_str *ofp_ifnet_locks_shm;

OFP_TAILQ_HEAD(in_ifaddrhead, ofp_ifnet);

struct ofp_ifnet {
	uint16_t	port;
	uint16_t	vlan;
	uint16_t	vrf;
#define OFP_IFT_STATE_FREE 0
#define OFP_IFT_STATE_USED 1
	uint8_t		if_state;
	uint16_t	if_mtu;
	uint32_t	ip_addr; /* network byte order */
	uint32_t	ip_p2p; /* network byte order */
	uint32_t	ip_local; /* network byte order */
	uint32_t	ip_remote; /* network byte order */
	uint32_t	bcast_addr; /* network byte order */
	int		masklen;
#ifdef INET6
	uint8_t		link_local[16];
	uint8_t		ip6_addr[16];
	uint8_t		ip6_prefix;
#endif /* INET6 */
	uint8_t		mac[OFP_ETHER_ADDR_LEN];
	void		*vlan_structs;
#define OFP_IFT_ETHER  1
#define OFP_IFT_LOCAL  2
#define OFP_IFT_LOOP   3
#define OFP_IFT_GRE    4
	uint8_t		if_type;
	uint8_t		if_flags;

	char		if_name[OFP_IFNAMSIZ];
	odp_pktio_t	pktio;
	odp_queue_t	outq_def;
	odp_queue_t	inq_def;
	odp_queue_t	loopq_def;
	odp_pool_t	pkt_pool;
#ifdef SP
	int		linux_index;
	int		fd;
	odp_queue_t	spq_def;
#define OFP_SP_DOWN 0
#define OFP_SP_UP 1
	int		sp_status;
	odph_linux_pthread_t	rx_tbl[1];
	odph_linux_pthread_t	tx_tbl[1];
#endif /*SP */

	OFP_LIST_ENTRY(ofp_ifnet) ia_hash; /* entry in bucket of inet addresses */
	OFP_TAILQ_ENTRY(ofp_ifnet) ia_link; /* list of internet addresses */
#ifdef INET6
	OFP_TAILQ_ENTRY(ofp_ifnet) ia6_link; /* list of internet addresses */
#endif /* INET6 */
};

struct in_ifaddrhead *ofp_get_ifaddrhead(void);
void ofp_ifaddr_elem_add(struct ofp_ifnet *ifnet);
void ofp_ifaddr_elem_del(struct ofp_ifnet *ifnet);
struct ofp_ifnet *ofp_ifaddr_elem_get(uint8_t *addr);

#ifdef INET6
struct in_ifaddrhead *ofp_get_ifaddr6head(void);
void ofp_ifaddr6_elem_add(struct ofp_ifnet *ifnet);
void ofp_ifaddr6_elem_del(struct ofp_ifnet *ifnet);
struct ofp_ifnet *ofp_ifaddr6_elem_get(uint8_t *addr6);
#endif /* INET6 */

void *sp_tx_thread(void *ifnet_void);
void *sp_rx_thread(void *ifnet_void);
int sp_setup_device(struct ofp_ifnet *ifnet);

void ofp_portconf_alloc_shared_memory(void);
void ofp_portconf_free_shared_memory(void);
void ofp_portconf_lookup_shared_memory(void);
void ofp_portconf_init_global(void);
void ofp_portconf_term_global(void);

#ifdef SP
void ofp_update_ifindex_lookup_tab(struct ofp_ifnet *ifnet);
#endif /* SP */

int ofp_vlan_get_by_key(void *root, void *key, void **value_address);
int vlan_ifnet_insert(void *root, void *elem);
int vlan_ifnet_delete(void *root, void *elem, int (*free_key_fun)(void *arg));
int free_key(void *key);

struct ofp_ifconf;
void ofp_get_interfaces(struct ofp_ifconf *ifc);

/* Finds the node interface by the local ip assigned regardless of vlan */
struct ofp_ifnet *ofp_get_ifnet_by_ip(uint32_t ip, uint16_t vrf);
/* Finds the tunnel interface by tunnel addresses  */
struct ofp_ifnet *ofp_get_ifnet_by_tunnel(uint32_t tun_loc,
					      uint32_t tun_rem, uint16_t vrf);

#endif
