/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef _OFPI_PORTCONF_H_
#define _OFPI_PORTCONF_H_

#include <stdint.h>

#include <odp_api.h>
#include "odp/helper/odph_api.h"

#include "api/ofp_portconf.h"
#include "api/ofp_socket.h"

#include "ofpi_config.h"
#include "ofpi_ethernet.h"
#include "ofpi_queue.h"

#define NUM_PORTS (OFP_FP_INTERFACE_MAX + 3)

/* GRE ports are the last port assigned in the port vector.
 * Ports start from 0, and the last value is NUM_PORTS - 1.
 */
#define GRE_PORTS (NUM_PORTS - 1)

/* VXLANs ports are the before last port assigned in the port vector.
 * Ports start from 0, and the last value is NUM_PORTS - 1.
 */
#define VXLAN_PORTS (NUM_PORTS - 2)
#define LOCAL_PORTS (NUM_PORTS - 3)
#define PHYS_PORT(_port) (_port < OFP_FP_INTERFACE_MAX)
#define OFP_IFNAME_PREFIX "fp"
#define OFP_GRE_IFNAME_PREFIX "gre"
#define OFP_VXLAN_IFNAME_PREFIX "vxlan"
#define OFP_LOCAL_IFNAME_PREFIX "lo"

OFP_TAILQ_HEAD(ofp_ifmultihead, ofp_ifmultiaddr);

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

OFP_TAILQ_HEAD(ofp_in_ifaddrhead, ofp_ifnet);

/*
 * Structure defining a queue for a network interface.
 */
struct ifq_entry {
	struct		ifq_entry *next;
	odp_packet_t	pkt;
	int		flags;
	int		flowid;
	uint16_t	vt_nrecs;
};

struct	ofp_ifqueue {
	struct	ifq_entry *ifq_head;
	struct	ifq_entry *ifq_tail;
	int	ifq_len;
	int	ifq_maxlen;
	int	ifq_drops;
	odp_rwlock_t ifq_mtx;
};

/*
 * IPv4 per-interface state.
 */
struct ofp_igmp_ifinfo;
struct ofp_in_multi;
struct lltable;

struct ofp_in_ifinfo {
	struct lltable		*ii_llt;	/* ARP state */
	struct ofp_igmp_ifinfo	*ii_igmp;	/* IGMP state */
	struct ofp_in_multi	*ii_allhosts;	/* 224.0.0.1 membership */
};

/*
 * Multicast address structure.  This is analogous to the ifaddr
 * structure except that it keeps track of multicast addresses.
 */
struct ofp_ifmultiaddr {
	OFP_TAILQ_ENTRY(ofp_ifmultiaddr) ifma_link;	 /* queue macro glue */
	struct	ofp_sockaddr *ifma_addr; 	/* address this membership is for */
	struct	ofp_sockaddr *ifma_lladdr;	/* link-layer translation, if any */
	struct	ofp_ifnet *ifma_ifp;		/* back-pointer to interface */
	uint32_t	ifma_refcount;		/* reference count */
	void	*ifma_protospec;		/* protocol-specific state, if any */
	struct ofp_ifmultiaddr *ifma_llifma; 	/* pointer to ifma for ifma_lladdr */
};

struct ofp_ifnet_ipaddr {
	uint32_t ip_addr; /* network byte order */
	uint32_t bcast_addr; /* network byte order */
	uint8_t  masklen;
};

#define IP_ADDR_LIST_INIT(if) odp_rwlock_init(&(if)->ip_addr_mtx)
#define IP_ADDR_LIST_RLOCK(if)   odp_rwlock_read_lock(&(if)->ip_addr_mtx)
#define IP_ADDR_LIST_RUNLOCK(if) odp_rwlock_read_unlock(&(if)->ip_addr_mtx)
#define IP_ADDR_LIST_WLOCK(if)   odp_rwlock_write_lock(&(if)->ip_addr_mtx)
#define IP_ADDR_LIST_WUNLOCK(if) odp_rwlock_write_unlock(&(if)->ip_addr_mtx)

struct ODP_ALIGNED_CACHE ofp_ifnet {
	struct ofp_ifnet_ipaddr	ip_addr_info[OFP_NUM_IFNET_IP_ADDRS];
	odp_rwlock_t ip_addr_mtx;
	uint16_t	port;
	uint16_t	vlan;
	uint16_t	vrf;
#define OFP_IFT_STATE_FREE 0
#define OFP_IFT_STATE_USED 1
	uint8_t		if_state;
#define OFP_IFT_ETHER  1
#define OFP_IFT_LOCAL  2
#define OFP_IFT_LOOP   3
#define OFP_IFT_GRE    4
#define OFP_IFT_VXLAN  5
	uint8_t		if_type;
#define	OFP_IFF_UP		0x1		/* (n) interface is up */
#define	OFP_IFF_BROADCAST	0x2		/* (i) broadcast address valid */
#define	OFP_IFF_DEBUG		0x4		/* (n) turn on debugging */
#define	OFP_IFF_LOOPBACK	0x8		/* (i) is a loopback net */
#define	OFP_IFF_POINTOPOINT	0x10		/* (i) is a point-to-point link */
#define	OFP_IFF_SMART		0x20		/* (i) interface manages own routes */
#define	OFP_IFF_DRV_RUNNING	0x40		/* (d) resources allocated */
#define	OFP_IFF_NOARP		0x80		/* (n) no address resolution protocol */
#define	OFP_IFF_PROMISC		0x100		/* (n) receive all packets */
#define	OFP_IFF_ALLMULTI	0x200		/* (n) receive all multicast packets */
#define	OFP_IFF_DRV_OACTIVE	0x400		/* (d) tx hardware queue is full */
#define	OFP_IFF_SIMPLEX		0x800		/* (i) can't hear own transmissions */
#define	OFP_IFF_LINK0		0x1000		/* per link layer defined bit */
#define	OFP_IFF_LINK1		0x2000		/* per link layer defined bit */
#define	OFP_IFF_LINK2		0x4000		/* per link layer defined bit */
#define	OFP_IFF_ALTPHYS		OFP_IFF_LINK2	/* use alternate physical connection */
#define	OFP_IFF_MULTICAST	0x8000		/* (i) supports multicast */
#define	OFP_IFF_CANTCONFIG	0x10000		/* (i) unconfigurable using ioctl(2) */
#define	OFP_IFF_PPROMISC	0x20000		/* (n) user-requested promisc mode */
#define	OFP_IFF_MONITOR		0x40000		/* (n) user-requested monitor mode */
#define	OFP_IFF_STATICARP	0x80000		/* (n) static ARP */
#define	OFP_IFF_DYING		0x200000	/* (n) interface is winding down */
#define	OFP_IFF_RENAMING	0x400000	/* (n) interface is being renamed */
#define OFP_IFF_PROMISCINET 	0x800000	/* (n) interface is in PROMISCUOUS_INET mode */
	uint32_t	if_flags;

	uint8_t		mac[OFP_ETHER_ADDR_LEN];
	uint16_t	if_mtu;

	uint32_t	ip_p2p; /* network byte order */
	uint32_t	ip_local; /* network byte order */
	uint16_t	physport;
	uint16_t	physvlan;
	uint32_t	ip_remote; /* network byte order */
#ifdef INET6
	uint8_t		link_local[16];
	uint8_t		ip6_addr[16];
	uint8_t		ip6_prefix;
#endif /* INET6 */
	void		*vlan_structs;

	char		if_name[OFP_IFNAMSIZ];
	odp_pktio_t	pktio;
#define OFP_IF_IPV4_RX_CHKSUM 0x1
#define OFP_IF_IPV4_TX_CHKSUM 0x2
#define OFP_IF_UDP_RX_CHKSUM  0x4
#define OFP_IF_UDP_TX_CHKSUM  0x8
#define OFP_IF_TCP_RX_CHKSUM  0x10
#define OFP_IF_TCP_TX_CHKSUM  0x20
	uint32_t        chksum_offload_flags;
	unsigned	out_queue_num;
#define OFP_OUT_QUEUE_TYPE_PKTOUT 0
#define OFP_OUT_QUEUE_TYPE_QUEUE 1
	uint8_t		out_queue_type;

	odp_pktout_queue_t out_queue_pktout[OFP_PKTOUT_QUEUE_MAX];
	odp_queue_t out_queue_queue[OFP_PKTOUT_QUEUE_MAX];

	odp_queue_t	loopq_def;
	odp_pool_t	pkt_pool;
#ifdef SP
	int		linux_index;
	int		fd;
	odp_queue_t	spq_def;
#define OFP_SP_DOWN 0
#define OFP_SP_UP 1
	int		sp_status;
	odph_thread_t	rx_tbl[1];
	odph_thread_t	tx_tbl[1];
#endif /*SP */

	OFP_LIST_ENTRY(ofp_ifnet) ia_hash; /* entry in bucket of inet addresses */
	OFP_TAILQ_ENTRY(ofp_ifnet) ia_link; /* list of internet addresses */
#ifdef INET6
	OFP_TAILQ_ENTRY(ofp_ifnet) ia6_link; /* list of internet addresses */
#endif /* INET6 */
	odp_rwlock_t	if_addr_mtx;	/* mutex to protect address lists */
	struct ofp_in_ifinfo ii_inet;
	void	*if_afdata[OFP_AF_MAX];
	struct	ofp_ifmultihead if_multiaddrs; /* multicast addresses configured */
	struct ofp_ifnet *next;	/* next in the free list */
};

#define outq_def out_queue_queue[0]

static inline uint8_t ofp_if_type(struct ofp_ifnet *ifnet)
{
	return ifnet->if_type;
}

/*
 * Output queues (ifp->if_snd) and slow device input queues (*ifp->if_slowq)
 * are queues of messages stored on ifqueue structures
 * (defined above).  Entries are added to and deleted from these structures
 * by these macros, which should be called with ipl raised to splimp().
 */
#define IF_LOCK(ifq)		mtx_lock(&(ifq)->ifq_mtx)
#define IF_UNLOCK(ifq)		mtx_unlock(&(ifq)->ifq_mtx)
#define	IF_LOCK_ASSERT(ifq)	mtx_assert(&(ifq)->ifq_mtx, MA_OWNED)
#define	_IF_QFULL(ifq)		((ifq)->ifq_len >= (ifq)->ifq_maxlen)
#define	_IF_DROP(ifq)		((ifq)->ifq_drops++)
#define	_IF_QLEN(ifq)		((ifq)->ifq_len)

static inline void _IF_ENQUEUE(struct ofp_ifqueue *ifq, odp_packet_t m)
{
	struct ifq_entry *e = odp_packet_head(m);
	e->pkt = m;
	e->next = NULL;
	if (ifq->ifq_tail == NULL)
		ifq->ifq_head = e;
	else
		ifq->ifq_tail->next = e;
	ifq->ifq_tail = e;
	ifq->ifq_len++;
}

#define IF_ENQUEUE(ifq, m) do {					\
	IF_LOCK(ifq); 						\
	_IF_ENQUEUE(ifq, m); 					\
	IF_UNLOCK(ifq); 					\
} while (0)

#define	_IF_PREPEND(ifq, m) do {				\
	struct ifq_entry *e = odp_packet_head(m);		\
	e->pkt = m;						\
	e->next = (ifq)->ifq_head; 			\
	if ((ifq)->ifq_tail == NULL) 				\
		(ifq)->ifq_tail = e; 				\
	(ifq)->ifq_head = e; 					\
	(ifq)->ifq_len++; 					\
} while (0)

#define IF_PREPEND(ifq, m) do {		 			\
	IF_LOCK(ifq); 						\
	_IF_PREPEND(ifq, m); 					\
	IF_UNLOCK(ifq); 					\
} while (0)

#define _IF_DEQUEUE(ifq, m) do { 				\
	struct ifq_entry *e = (ifq)->ifq_head;			\
	m = ODP_PACKET_INVALID;					\
	if (e) {						\
		m = e->pkt;					\
		if (((ifq)->ifq_head = e->next) == NULL)	\
			(ifq)->ifq_tail = NULL;			\
		e->next = NULL;					\
		(ifq)->ifq_len--;				\
	}							\
} while (0)

#define IF_DEQUEUE(ifq, m) do { 				\
	IF_LOCK(ifq); 						\
	_IF_DEQUEUE(ifq, m); 					\
	IF_UNLOCK(ifq); 					\
} while (0)

#define	_IF_DEQUEUE_ALL(ifq, m) do {				\
	(m) = ODP_PACKET_INVALID;				\
	if ((ifq)->ifq_head)					\
		(m) = (ifq)->ifq_head->pkt;			\
	(ifq)->ifq_head = (ifq)->ifq_tail = NULL;		\
	(ifq)->ifq_len = 0;					\
} while (0)

#define	IF_DEQUEUE_ALL(ifq, m) do {				\
	IF_LOCK(ifq); 						\
	_IF_DEQUEUE_ALL(ifq, m);				\
	IF_UNLOCK(ifq); 					\
} while (0)

#define	_IF_POLL(ifq, m)	((m) = (ifq)->ifq_head->pkt)
#define	IF_POLL(ifq, m)		_IF_POLL(ifq, m)

#define _IF_DRAIN(ifq) do { 					\
	odp_packet_t m; 					\
	for (;;) { 						\
		_IF_DEQUEUE(ifq, m); 				\
		if (m == ODP_PACKET_INVALID)			\
			break; 					\
		odp_packet_free(m);				\
	} 							\
} while (0)

#define IF_DRAIN(ifq) do {					\
	IF_LOCK(ifq);						\
	_IF_DRAIN(ifq);						\
	IF_UNLOCK(ifq);						\
} while(0)

#define	IFQ_LOCK(ifq)			IF_LOCK(ifq)
#define	IFQ_UNLOCK(ifq)			IF_UNLOCK(ifq)
#define	IFQ_LOCK_ASSERT(ifq)		IF_LOCK_ASSERT(ifq)
#define	IFQ_IS_EMPTY(ifq)		((ifq)->ifq_len == 0)
#define	IFQ_INC_LEN(ifq)		((ifq)->ifq_len++)
#define	IFQ_DEC_LEN(ifq)		(--(ifq)->ifq_len)
#define	IFQ_INC_DROPS(ifq)		((ifq)->ifq_drops++)
#define	IFQ_SET_MAXLEN(ifq, len)	((ifq)->ifq_maxlen = (len))

/*
 * Locks for address lists on the network interface.
 */
#define	IF_ADDR_LOCK_INIT(if)	odp_rwlock_init(&(if)->if_addr_mtx);
#define	IF_ADDR_LOCK_DESTROY(if)	do {} while (0) /*mtx_destroy(&(if)->if_addr_mtx)*/
#define	IF_ADDR_WLOCK(if)	odp_rwlock_write_lock(&(if)->if_addr_mtx)
#define	IF_ADDR_WUNLOCK(if)	odp_rwlock_write_unlock(&(if)->if_addr_mtx)
#define	IF_ADDR_RLOCK(if)	odp_rwlock_read_lock(&(if)->if_addr_mtx)
#define	IF_ADDR_RUNLOCK(if)	odp_rwlock_read_unlock(&(if)->if_addr_mtx)
#define	IF_ADDR_LOCK_ASSERT(if)	do {} while (0) /*mtx_assert(&(if)->if_addr_mtx, MA_OWNED)*/
#define	IF_ADDR_WLOCK_ASSERT(if)	do {} while (0) /*mtx_assert(&(if)->if_addr_mtx, MA_OWNED)*/
/* XXX: Compat. */
#define	IF_ADDR_LOCK(if)	IF_ADDR_WLOCK(if)
#define	IF_ADDR_UNLOCK(if)	IF_ADDR_WUNLOCK(if)


struct ofp_in_ifaddrhead *ofp_get_ifaddrhead(void);
void ofp_ifaddr_elem_add(struct ofp_ifnet *ifnet);
void ofp_ifaddr_elem_del(struct ofp_ifnet *ifnet);
struct ofp_ifnet *ofp_ifaddr_elem_get(int vrf, uint8_t *addr);

#ifdef INET6
struct ofp_in_ifaddrhead *ofp_get_ifaddr6head(void);
void ofp_ifaddr6_elem_add(struct ofp_ifnet *ifnet);
void ofp_ifaddr6_elem_del(struct ofp_ifnet *ifnet);
struct ofp_ifnet *ofp_ifaddr6_elem_get(uint8_t *addr6);
#endif /* INET6 */

int sp_tx_thread(void *ifnet_void);
int sp_rx_thread(void *ifnet_void);
int sp_setup_device(struct ofp_ifnet *ifnet);

int ofp_free_port_alloc(void);

int ofp_portconf_lookup_shared_memory(void);
void ofp_portconf_init_prepare(void);
int ofp_portconf_init_global(void);
int ofp_portconf_term_global(void);
int ofp_vlan_lookup_shared_memory(void);
void ofp_vlan_init_prepare(void);
int ofp_vlan_init_global(void);
int ofp_vlan_term_global(void);

#ifdef SP
void ofp_update_ifindex_lookup_tab(struct ofp_ifnet *ifnet);
#endif /* SP */

int ofp_vlan_get_by_key(void *root, void *key, void **value_address);
int vlan_ifnet_insert(void *root, void *elem);
int vlan_ifnet_delete(void *root, void *elem, int (*free_key_fun)(void *arg));
int free_key(void *key);

struct ofp_ifconf;
void ofp_get_interfaces(struct ofp_ifconf *ifc);

int ofp_ifnet_ip_find(struct ofp_ifnet *dev, uint32_t addr);
int ofp_set_first_ifnet_addr(struct ofp_ifnet *dev, uint32_t addr, uint32_t bcast_addr, int masklen);
void ofp_free_ifnet_ip_list(struct ofp_ifnet *dev);
void ofp_ifnet_print_ip_info(int fd, struct ofp_ifnet *dev);
int ofp_ifnet_ip_find_update_fields(struct ofp_ifnet *dev, uint32_t addr, int masklen, uint32_t bcast_addr);
void ofp_ifnet_print_ip_info(int fd, struct ofp_ifnet *dev);
int ofp_ifnet_ip_add(struct ofp_ifnet *dev, uint32_t addr);
void ofp_ifnet_ip_remove(struct ofp_ifnet *dev, uint32_t addr);

/* Finds the node interface by the local ip assigned regardless of vlan */
struct ofp_ifnet *ofp_get_ifnet_by_ip(uint32_t ip, uint16_t vrf);
/* Finds the tunnel interface by tunnel addresses  */
struct ofp_ifnet *ofp_get_ifnet_by_tunnel(uint32_t tun_loc,
					      uint32_t tun_rem, uint16_t vrf);
void ofp_join_device_to_multicast_group(struct ofp_ifnet *dev_root,
				       struct ofp_ifnet *dev_vxlan,
				       uint32_t group);
void ofp_leave_multicast_group(struct ofp_ifnet *dev_vxlan);
int ofp_local_interfaces_destroy(void);

#endif
