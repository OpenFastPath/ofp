/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */
#ifndef __OFPI_ARP_H__
#define __OFPI_ARP_H__

#include <odp_api.h>

#include "ofpi_pkt_processing.h" /* return codes, i.e.: OFP_DROP */
#include "ofpi.h"

/*
 * The size of this must be a multiple of 4. That way the hash
 * function doesn't need to deal with partial doublewords.
 */
struct arp_key {
	uint32_t vrf;
	uint32_t ipv4_addr;
};

#ifdef OFP_USE_LIBCK
#include <ck_queue.h>

struct arp_entry {
	struct arp_key key;
	/* Keep ifx/timestamp/state together in the same word! */
	uint16_t ifx;
	uint8_t state;
	uint8_t slowpath_keepalive_timer_armed;
	uint64_t macaddr;
	uint16_t timer_armed; /* Slowpath neigh update timer */
	CK_SLIST_ENTRY(arp_entry) next;
};

#else /* ! OFP_USE_LIBCK */
#include "ofpi_queue.h"

struct pkt_entry {
	odp_packet_t pkt;
	struct ofp_nh_entry *nh;
	OFP_SLIST_ENTRY(pkt_entry) next;
};

struct pkt_list {
	struct pkt_entry *slh_first;
}; /* OFP_SLIST_HEAD */

struct arp_entry {
	struct arp_key key;

	odp_time_t usetime;
	odp_timer_t usetime_upd_tmo;
	odp_rwlock_t usetime_rwlock;

	odp_bool_t is_valid;
	uint64_t macaddr;
	struct pkt_list pkt_list_head;
	odp_timer_t pkt_tmo;
	uint32_t ref_count;

	OFP_STAILQ_ENTRY(arp_entry) next;
} ODP_ALIGNED_CACHE;
#endif /* OFP_USE_LIBCK */

struct arp_cache {
	odp_atomic_u32_t entry_idx;
};

#define ARP_IS_CACHE_HIT(_entry, _key) \
	(((_key)->vrf == (_entry)->key.vrf) && \
	 ((_key)->ipv4_addr == (_entry)->key.ipv4_addr))

#define ARP_GET_CACHE(_cache) \
	(&(shm->arp.entries[odp_atomic_load_u32(&(_cache)->entry_idx)]))

#define ARP_SET_CACHE(_cache, _entry) \
	odp_atomic_store_u32(&(_cache)->entry_idx, \
			     (_entry) - &(shm->arp.entries[0]))

#define ARP_DEL_CACHE(_cache) \
	odp_atomic_store_u32(&(_cache)->entry_idx, 0)

#define ARP_GET_IDX(_entry) \
	((_entry) - &shm->arp.entries[0])

#define ARP_GET_ENTRY(_entry_idx) \
	&shm->arp.entries[(_entry_idx)]

int ofp_arp_lookup_shared_memory(void);
void ofp_arp_init_prepare(void);
int ofp_arp_init_global(void);
int ofp_arp_term_global(void);
int ofp_arp_init_local(void);
void ofp_arp_term_local(void);
int ofp_arp_ipv4_insert_entry(uint32_t ipv4_addr, unsigned char *ll_addr,
			      uint16_t vrf, odp_bool_t is_valid,
			      uint32_t *entry_idx_out,
			      struct pkt_list *send_list);
int ofp_arp_ipv4_insert(uint32_t ipv4_addr, unsigned char *ll_addr,
			struct ofp_ifnet *dev);
void ofp_arp_ipv4_remove_entry(uint32_t set, struct arp_entry *entry);
void ofp_arp_ipv4_remove_entry_idx(uint32_t entry_idx);
int ofp_arp_inc_ref_count(uint32_t entry_idx);
int ofp_arp_dec_ref_count(uint32_t entry_idx);
odp_bool_t ofp_arp_entry_validity(uint32_t entry_idx);
int ofp_ipv4_lookup_arp_entry_idx(uint32_t ipv4_addr, uint16_t vrf,
				       uint32_t *entry_idx);
int ofp_ipv4_lookup_mac(uint32_t ipv4_addr, unsigned char *ll_addr,
			struct ofp_ifnet *dev);
int ofp_ipv4_get_mac_by_idx(unsigned char *ll_addr, uint32_t entry_idx);
enum ofp_return_code ofp_arp_save_ipv4_pkt(odp_packet_t pkt, struct ofp_nh_entry *nh_param,
				uint32_t ipv4_addr, struct ofp_ifnet *dev);

void ofp_arp_show_table(int fd);
void ofp_arp_show_saved_packets(int fd);
void ofp_arp_age_cb(void *arg);
int ofp_arp_init_tables(void);
void ofp_arp_init_tables_pkt_list(void);

#endif /* __OFPI_ARP_H__ */
