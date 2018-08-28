/* Copyright (c) 2015, ENEA Software AB
 * Copyright (c) 2015, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include <odp_api.h>

#include "ofpi_config.h"
#include "ofpi_portconf.h"
#include "ofpi_timer.h"
#include "ofpi_arp.h"
#include "ofpi_hash.h"
#include "ofpi_log.h"
#include "ofpi_util.h"

#define SHM_NAME_ARP "OfpArpShMem"
#define SIZEOF_ENTRIES (sizeof(struct arp_entry) * NUM_ARPS)
#define SIZEOF_SETS (sizeof(struct set_s) * NUM_SETS)
#define SHM_SIZE_ARP (sizeof(struct ofp_arp_mem) + \
		      SIZEOF_ENTRIES + SIZEOF_SETS)

/* Default ARP age interval (in seconds). If set to 0, then age interval is half of OFP_ARP_ENTRY_TIMEOUT. */
#define ARP_AGE_INTERVAL 0
/* Timer interval for entry use time update. */
#define ARP_ENTRY_UPD_TIMEOUT 2
/* Maximum number of saved packets waiting for an ARP reply. */
#define ARP_WAITING_PKTS_SIZE 2048

#define NUM_SETS (1<<global_param->arp.hash_bits)
/* Plus one because zeroth entry is used as the invalid entry. */
#define NUM_ARPS (global_param->arp.entries + 1)
#define ENTRY_UPD_TIMEOUT (ARP_ENTRY_UPD_TIMEOUT * US_PER_SEC)
#define SAVED_PKT_TIMEOUT (global_param->arp.saved_pkt_timeout * US_PER_SEC)
#define AGE_DIVISOR 2

/*
 * Data
 */

struct arp_entry_tailq {
	struct arp_entry *stqh_first;
	struct arp_entry **stqh_last;
}; /* OFP_STAILQ_HEAD */

struct set_s {
	struct arp_entry_tailq table;
	struct arp_cache cache;
	odp_rwlock_t table_rwlock;
} ODP_ALIGNED_CACHE;

struct _arp {
	struct arp_entry *entries;
	struct arp_entry_tailq free_entries;
	odp_rwlock_t fr_ent_rwlock;
	struct set_s *set;
};

struct _pkt {
	struct pkt_entry entries[ARP_WAITING_PKTS_SIZE] ODP_ALIGNED_CACHE;
	struct pkt_list free_entries;
	odp_rwlock_t fr_ent_rwlock;
};

struct ofp_arp_mem {
	struct _arp arp;
	struct _pkt pkt;

	odp_time_t entry_timeout;        /* ARP entry timeout */
	unsigned int age_interval;       /* ageing interval (in seconds) */
	odp_timer_t age_timer;
};

static __thread struct ofp_arp_mem *shm;

/*
 * Private functions
 */

static inline uint32_t ipv4_hash(struct arp_key *key)
{
	return ofp_hashword((const uint32_t *)key, sizeof(*key)/sizeof(uint32_t), 0) & (NUM_SETS - 1);
}

static inline uint32_t set_key_and_hash(uint32_t vrf, uint32_t ipv4_addr,
					struct arp_key *key)
{
	uint32_t set;

	key->vrf = vrf;
	key->ipv4_addr = ipv4_addr;
	set = ipv4_hash(key);

	return set;
}

static int ofp_arp_entry_reset(struct arp_entry *entry)
{
	int rc;

	rc = 0;

	if (entry->pkt_tmo != ODP_TIMER_INVALID)
		CHECK_ERROR(ofp_timer_cancel(entry->pkt_tmo), rc);

	odp_rwlock_write_lock(&entry->usetime_rwlock);
	if (entry->usetime_upd_tmo != ODP_TIMER_INVALID) {
		CHECK_ERROR(ofp_timer_cancel(entry->usetime_upd_tmo), rc);
		entry->usetime_upd_tmo = ODP_TIMER_INVALID;
	}
	odp_rwlock_write_unlock(&entry->usetime_rwlock);

	entry->pkt_tmo = ODP_TIMER_INVALID;

	memset(&entry->key, 0, sizeof(entry->key));
	entry->macaddr = 0;
	entry->ref_count = 0;
	entry->is_valid = FALSE;

	return rc;
}
static inline void *entry_alloc(void)
{
	struct arp_entry *entry = NULL;

	odp_rwlock_write_lock(&shm->arp.fr_ent_rwlock);

	entry = OFP_STAILQ_FIRST(&shm->arp.free_entries);

	if (entry) {
		OFP_STAILQ_REMOVE_HEAD(&shm->arp.free_entries, next);
		if (ofp_arp_entry_reset(entry) != 0) {
			OFP_STAILQ_INSERT_TAIL(&shm->arp.free_entries, entry, next);
			odp_rwlock_write_unlock(&shm->arp.fr_ent_rwlock);
			return NULL;
		}
		memset(&entry->pkt_list_head, 0, sizeof(entry->pkt_list_head));
	}

	odp_rwlock_write_unlock(&shm->arp.fr_ent_rwlock);

	return entry;
}

/*Assumption: entry to be reset in entry_alloc()*/
static inline void entry_free(struct arp_entry *entry)
{
	entry->pkt_tmo = ODP_TIMER_INVALID;

	odp_rwlock_write_lock(&shm->arp.fr_ent_rwlock);
	/* Inserting freed entry to tail of the list so a freed entry */
	/* is not reused soon, as other worker threads may have reference */
	OFP_STAILQ_INSERT_TAIL(&shm->arp.free_entries, entry, next);
	odp_rwlock_write_unlock(&shm->arp.fr_ent_rwlock);
}

static inline struct arp_entry *arp_lookup(int set, struct arp_key *key)
{
	struct arp_entry *new;

	OFP_STAILQ_FOREACH(new, &shm->arp.set[set].table, next) {
		if (odp_likely((new->key.ipv4_addr == key->ipv4_addr) &&
			       (new->key.vrf == key->vrf)))
			return new;
	}

	return NULL;
}

static inline void *insert_new_entry(int set, struct arp_key *key)
{
	struct arp_entry *new;

	new = arp_lookup(set, key);

	if (odp_likely(new == NULL)) {
		new = entry_alloc();

		if (odp_unlikely(new == NULL))
			return NULL;

		new->key.ipv4_addr = key->ipv4_addr;
		new->key.vrf = key->vrf;
		new->usetime_upd_tmo = ODP_TIMER_INVALID;
		OFP_STAILQ_INSERT_HEAD(&shm->arp.set[set].table, new, next);
	}

	return new;
}

static inline int remove_entry(int set, struct arp_entry *entry)
{
	struct arp_cache *cache;
	struct arp_entry *cache_entry;
	int rc = 0;

	/* remove from set's cache */
	cache = &shm->arp.set[set].cache;

	cache_entry = ARP_GET_CACHE(cache);

	if (ARP_IS_CACHE_HIT(cache_entry, &entry->key))
		ARP_DEL_CACHE(cache);

	/* remove from set */
	OFP_STAILQ_REMOVE(&shm->arp.set[set].table, entry, arp_entry, next);

	/* kill update timer*/
	odp_rwlock_write_lock(&entry->usetime_rwlock);

	if (entry->usetime_upd_tmo != ODP_TIMER_INVALID) {
		CHECK_ERROR(ofp_timer_cancel(entry->usetime_upd_tmo), rc);
		entry->usetime_upd_tmo = ODP_TIMER_INVALID;
	}

	odp_rwlock_write_unlock(&entry->usetime_rwlock);

	/* free */
	entry_free(entry);
	return rc;
}

static inline void show_arp_entry(int fd, struct arp_entry *entry)
{
	odp_time_t t, time_diff;

	t = odp_time_global();
	time_diff = odp_time_diff(t, entry->usetime);
	ofp_sendf(fd, "%3d  %-15s %-17s %4u\r\n",
		    entry->key.vrf,
		    ofp_print_ip_addr(entry->key.ipv4_addr),
		    ofp_print_mac((uint8_t *)&entry->macaddr),
		    odp_time_to_ns(time_diff) / ODP_TIME_SEC_IN_NS);
}

static inline void *pkt_entry_alloc(void)
{
	struct pkt_entry *pktentry;

	odp_rwlock_write_lock(&shm->pkt.fr_ent_rwlock);

	pktentry = OFP_SLIST_FIRST(&shm->pkt.free_entries);

	if (pktentry)
		OFP_SLIST_REMOVE_HEAD(&shm->pkt.free_entries, next);

	odp_rwlock_write_unlock(&shm->pkt.fr_ent_rwlock);

	return pktentry;
}

static inline void pkt_entry_free(struct pkt_entry *pktentry)
{
	memset(pktentry, 0, sizeof(*pktentry));

	odp_rwlock_write_lock(&shm->pkt.fr_ent_rwlock);
	OFP_SLIST_INSERT_HEAD(&shm->pkt.free_entries, pktentry, next);
	odp_rwlock_write_unlock(&shm->pkt.fr_ent_rwlock);
}

int ofp_arp_ipv4_insert_entry(uint32_t ipv4_addr, unsigned char *ll_addr,
			      uint16_t vrf, odp_bool_t is_valid,
			      uint32_t *entry_idx_out, struct pkt_list *send_list)
{
	struct arp_entry *new;
	struct arp_key key;
	uint32_t set;
	odp_time_t tnow;

	set = set_key_and_hash(vrf, ipv4_addr, &key);

	odp_rwlock_write_lock(&shm->arp.set[set].table_rwlock);

	new = insert_new_entry(set, &key);

	if (odp_unlikely(new == NULL)) {
		odp_rwlock_write_unlock(&shm->arp.set[set].table_rwlock);
		return -1;
	}

	memcpy(&new->macaddr, ll_addr, OFP_ETHER_ADDR_LEN);

	new->is_valid = is_valid;

	if (new->is_valid == TRUE && send_list != NULL) {

		tnow = odp_time_global();
		new->usetime = tnow;

		OFP_SLIST_INIT(send_list);

		OFP_SLIST_SWAP(send_list, &new->pkt_list_head, pkt_entry);

		if (OFP_SLIST_FIRST(send_list)) {
			ofp_timer_cancel(new->pkt_tmo);
			new->pkt_tmo = ODP_TIMER_INVALID;
		}
	}

	*entry_idx_out = ARP_GET_IDX(new);

	OFP_DBG("ARP Insert Set: %u IP: %s VRF: %u Inserted Idx: %u",
		set, ofp_print_ip_addr(key.ipv4_addr), key.vrf, *entry_idx_out);

	odp_rwlock_write_unlock(&shm->arp.set[set].table_rwlock);

	return 0;
}


/*
 * Public functions
 */
int ofp_arp_ipv4_insert(uint32_t ipv4_addr, unsigned char *ll_addr,
			struct ofp_ifnet *dev)
{
	struct pkt_entry *pktentry;
	struct pkt_list send_list;
	uint32_t entry_idx;
	int ret_val;

	ret_val = ofp_arp_ipv4_insert_entry(ipv4_addr, ll_addr, dev->vrf,
					    TRUE, &entry_idx, &send_list);
	if (ret_val < 0)
		return ret_val;

	/* Send queued packets */
	pktentry = OFP_SLIST_FIRST(&send_list);
	while (pktentry) {
		OFP_DBG("Sending saved packet %" PRIX64 " to %s",
			odp_packet_to_u64(pktentry->pkt),
			ofp_print_ip_addr(ipv4_addr));

		if (ofp_ip_output_common(pktentry->pkt, pktentry->nh, 0) == OFP_PKT_DROP)
			odp_packet_free(pktentry->pkt);

		OFP_SLIST_REMOVE_HEAD(&send_list, next);
		pkt_entry_free(pktentry);

		pktentry = OFP_SLIST_FIRST(&send_list);
	}

	return 0;
}

void ofp_arp_ipv4_remove_entry(uint32_t set, struct arp_entry *entry)
{
	struct pkt_entry *pktentry;

	if (entry->ref_count == 0 && !entry->is_valid) {
		while ((pktentry = OFP_SLIST_FIRST(&entry->pkt_list_head))) {
			OFP_SLIST_REMOVE_HEAD(&entry->pkt_list_head, next);
			pkt_entry_free(pktentry);
		}
		remove_entry(set, entry);
	} else {
	        OFP_DBG("Remove ARP entry bypassed as ref_count= %u > 0 validity = %s",
			entry->ref_count, entry->is_valid ? "True":"False");
	}
}

void ofp_arp_ipv4_remove_entry_idx(uint32_t entry_idx)
{
	uint32_t set;
	struct arp_key key;
	struct arp_entry *entry;

	entry = ARP_GET_ENTRY(entry_idx);

	set = set_key_and_hash(entry->key.vrf, entry->key.ipv4_addr, &key);

	odp_rwlock_write_lock(&shm->arp.set[set].table_rwlock);

	ofp_arp_ipv4_remove_entry(set, entry);

	odp_rwlock_write_unlock(&shm->arp.set[set].table_rwlock);
}

int ofp_arp_inc_ref_count(uint32_t entry_idx)
{
	struct arp_entry *entry = ARP_GET_ENTRY(entry_idx);
	struct arp_key key;
	uint32_t set;

	set = set_key_and_hash(entry->key.vrf, entry->key.ipv4_addr, &key);

	odp_rwlock_write_lock(&shm->arp.set[set].table_rwlock);

	++entry->ref_count;

	odp_rwlock_write_unlock(&shm->arp.set[set].table_rwlock);

	return 0;
}

int ofp_arp_dec_ref_count(uint32_t entry_idx)
{
	struct arp_entry *entry = ARP_GET_ENTRY(entry_idx);
	struct arp_key key;
	uint32_t set;

	set = set_key_and_hash(entry->key.vrf, entry->key.ipv4_addr, &key);

	odp_rwlock_write_lock(&shm->arp.set[set].table_rwlock);

	--entry->ref_count;

	ofp_arp_ipv4_remove_entry(set, entry);

	odp_rwlock_write_unlock(&shm->arp.set[set].table_rwlock);

	return 0;
}

odp_bool_t ofp_arp_entry_validity(uint32_t entry_idx)
{
	struct arp_entry *entry;

	entry = ARP_GET_ENTRY(entry_idx);

	return entry->is_valid;
}

static void ofp_arp_entry_usetime_tmo(void *arg)
{
	struct arp_entry *entry;
	uint32_t entry_idx;

	entry_idx = *(uint32_t *)arg;

	entry = ARP_GET_ENTRY(entry_idx);

	odp_rwlock_write_lock(&entry->usetime_rwlock);

	entry->usetime_upd_tmo = ODP_TIMER_INVALID;

	odp_rwlock_write_unlock(&entry->usetime_rwlock);
}

int ofp_ipv4_lookup_arp_entry_idx(uint32_t ipv4_addr, uint16_t vrf,
				  uint32_t *entry_idx_out)
{
	struct arp_entry *entry = NULL;
	struct arp_key key;
	uint32_t set;
	odp_time_t tnew;
	uint32_t entry_idx;
	struct arp_cache *cache;

	set = set_key_and_hash(vrf, ipv4_addr, &key);

	cache = &shm->arp.set[set].cache;

	entry = ARP_GET_CACHE(cache);

	if (!ARP_IS_CACHE_HIT(entry, &key)) {
		odp_rwlock_write_lock(&shm->arp.set[set].table_rwlock);

		entry = arp_lookup(set, &key);

		if (odp_unlikely(entry == NULL) ||
		    OFP_SLIST_FIRST(&entry->pkt_list_head)) {
			odp_rwlock_write_unlock(&shm->arp.set[set].table_rwlock);
			return -1;
		}

		ARP_SET_CACHE(cache, entry);

		odp_rwlock_write_unlock(&shm->arp.set[set].table_rwlock);
	}


	if (odp_unlikely(entry->usetime_upd_tmo == ODP_TIMER_INVALID)) {
		odp_rwlock_write_lock(&entry->usetime_rwlock);
		if (entry->usetime_upd_tmo == ODP_TIMER_INVALID) {
			tnew = odp_time_global();
			entry->usetime = tnew;

			entry_idx = ARP_GET_IDX(entry);
			entry->usetime_upd_tmo = ofp_timer_start(
				ENTRY_UPD_TIMEOUT,
				ofp_arp_entry_usetime_tmo,
				&entry_idx, sizeof(entry_idx));
		}
		odp_rwlock_write_unlock(&entry->usetime_rwlock);
	}

	*entry_idx_out = ARP_GET_IDX(entry);

	return 0;
}

int ofp_ipv4_lookup_mac(uint32_t ipv4_addr, unsigned char *ll_addr,
			struct ofp_ifnet *dev)
{
	uint32_t entry_idx = 0;
	struct arp_entry *entry;

	OFP_DBG("ARP Lookup IP: %s VRF: %u",
		ofp_print_ip_addr(ipv4_addr), dev->vrf);

	if (ofp_ipv4_lookup_arp_entry_idx(ipv4_addr, dev->vrf,
					  &entry_idx) < 0)
		return -1;

	if (!ofp_arp_entry_validity(entry_idx))
		return -1;

	entry = ARP_GET_ENTRY(entry_idx);

	ofp_copy_mac(ll_addr, &entry->macaddr);

	return 0;
}

int ofp_ipv4_get_mac_by_idx(unsigned char *ll_addr, uint32_t entry_idx)
{
	struct arp_entry *entry;

	if (!ofp_arp_entry_validity(entry_idx))
		return -1;

	OFP_DBG("ARP Lookup Index Idx: %u", entry_idx);
	entry = ARP_GET_ENTRY(entry_idx);
	ofp_copy_mac(ll_addr, &entry->macaddr);
	return 0;
}

struct cleanup_arg {
	uint32_t entry_idx;
};

static void ofp_arp_cleanup_pkt_list(void *arg)
{
	struct cleanup_arg *args;
	struct arp_entry *entry;

	args = (struct cleanup_arg *)arg;
#ifdef OFP_DEBUG
	entry = ARP_GET_ENTRY(args->entry_idx);
	OFP_DBG("Arp reply did not arrive on time, %s",
		ofp_print_ip_addr(entry->key.ipv4_addr));
#else
	(void)entry;
#endif

	ofp_arp_ipv4_remove_entry_idx(args->entry_idx);
}

enum ofp_return_code ofp_arp_save_ipv4_pkt(odp_packet_t pkt, struct ofp_nh_entry *nh_param,
			    uint32_t ipv4_addr, struct ofp_ifnet *dev)
{
	struct arp_entry *newarp;
	struct arp_key key;
	struct pkt_entry *newpkt;
	uint32_t set;
	struct cleanup_arg cl_arg;

	OFP_DBG("Saving packet %" PRIX64 " to %s", odp_packet_to_u64(pkt),
		  ofp_print_ip_addr(ipv4_addr));

	set = set_key_and_hash(dev->vrf, ipv4_addr, &key);

	odp_rwlock_write_lock(&shm->arp.set[set].table_rwlock);

#if (ARP_SANITY_CHECK)
	newarp = arp_lookup(set, &key);
       if (newarp && newarp->is_valid)
		OFP_ERR("ARP Entry failed the sanity check!");
#endif

	newarp = ARP_GET_ENTRY(nh_param->arp_ent_idx);
	newarp->usetime = ODP_TIME_NULL;

	newpkt = pkt_entry_alloc();
	if (newpkt == NULL) {
		OFP_ERR("PKT entry alloc failed, %" PRIX64 " to %s",
			  odp_packet_to_u64(pkt),
			  ofp_print_ip_addr(ipv4_addr));
		if (OFP_SLIST_FIRST(&newarp->pkt_list_head) == NULL)
			ofp_arp_ipv4_remove_entry(set, newarp);
		odp_rwlock_write_unlock(&shm->arp.set[set].table_rwlock);
		return OFP_PKT_DROP;
	}
	newpkt->pkt = pkt;
	newpkt->nh = nh_param;

	/* Start timer only when the first pkt is saved */
	if (OFP_SLIST_FIRST(&newarp->pkt_list_head) == NULL) {
		cl_arg.entry_idx = ARP_GET_IDX(newarp);
		newarp->pkt_tmo = ofp_timer_start(SAVED_PKT_TIMEOUT,
						    ofp_arp_cleanup_pkt_list,
						    &cl_arg, sizeof(cl_arg));
	}

	OFP_SLIST_INSERT_HEAD(&newarp->pkt_list_head, newpkt, next);

	odp_rwlock_write_unlock(&shm->arp.set[set].table_rwlock);

	return OFP_PKT_PROCESSED;
}

static void ofp_arp_entry_cleanup_on_tmo(int set, struct arp_entry *entry)
{
	OFP_INFO("ARP entry removed on timeout: vrf: %3d IP: %-15s MAC: %-17s",
		entry->key.vrf, ofp_print_ip_addr(entry->key.ipv4_addr),
		ofp_print_mac((uint8_t *)&entry->macaddr));

	ofp_arp_ipv4_remove_entry(set, entry);
}

static odp_bool_t ofp_arp_entry_is_timeout(struct arp_entry *entry,
						odp_time_t now)
{
	odp_time_t end = odp_time_sum(entry->usetime, shm->entry_timeout);
	odp_bool_t res = odp_time_cmp(now, end) > 0;
	if (res)
		entry->is_valid = FALSE;
	return res;
}

void ofp_arp_age_cb(void *arg)
{
	struct arp_entry *entry, *next_entry;
	int i, cli;
	odp_time_t now;

	cli =  *(int *)arg;
	now = odp_time_global();

	for (i = 0; i < NUM_SETS; ++i) {
		odp_rwlock_write_lock(&shm->arp.set[i].table_rwlock);

		entry = OFP_STAILQ_FIRST(&shm->arp.set[i].table);
		while (entry) {
			next_entry = OFP_STAILQ_NEXT(entry, next);
			if (OFP_SLIST_FIRST(&entry->pkt_list_head) == NULL &&
					ofp_arp_entry_is_timeout(entry, now))
				ofp_arp_entry_cleanup_on_tmo(i, entry);
			entry = next_entry;
		}

		odp_rwlock_write_unlock(&shm->arp.set[i].table_rwlock);
	}

	if (!cli) {
		shm->age_timer = ofp_timer_start(
			shm->age_interval * US_PER_SEC, ofp_arp_age_cb,
			&cli, sizeof(cli));
	}
}

void ofp_arp_show_table(int fd)
{
	int i;

	for (i = 0; i < NUM_ARPS; ++i)
		if (shm->arp.entries[i].key.ipv4_addr &&
		    OFP_SLIST_FIRST(&shm->arp.entries[i].pkt_list_head) == NULL)
			show_arp_entry(fd, &shm->arp.entries[i]);
}

void ofp_arp_show_saved_packets(int fd)
{
	int i;
	struct pkt_entry *pktentry;
	struct arp_entry *entry;

	ofp_sendf(fd, "Saved packets:\r\n");
	for (i = 0; i < NUM_ARPS; ++i) {
		entry = &shm->arp.entries[i];
		if (entry->key.ipv4_addr &&
		    OFP_SLIST_FIRST(&entry->pkt_list_head) != NULL) {
			ofp_sendf(fd, "IP: %-15s: ",
				    ofp_print_ip_addr(entry->key.ipv4_addr));

			OFP_SLIST_FOREACH(pktentry, &entry->pkt_list_head, next)
				ofp_sendf(fd, "%" PRIX64 "\t",
					    odp_packet_to_u64(pktentry->pkt));

			ofp_sendf(fd, "\r\n");
		}
	}
}
void ofp_arp_init_tables_pkt_list(void)
{
	int i;

	odp_rwlock_write_lock(&shm->pkt.fr_ent_rwlock);

	for (i = 0; i < NUM_ARPS; ++i)
		memset(&shm->arp.entries[i].pkt_list_head, 0,
		       sizeof(shm->arp.entries[i].pkt_list_head));

	memset(shm->pkt.entries, 0, sizeof(shm->pkt.entries));

	OFP_SLIST_INIT(&shm->pkt.free_entries);

	for (i = ARP_WAITING_PKTS_SIZE - 1; i >= 0; --i)
		OFP_SLIST_INSERT_HEAD(&shm->pkt.free_entries, &shm->pkt.entries[i],
				      next);

	odp_rwlock_write_unlock(&shm->pkt.fr_ent_rwlock);

}
int ofp_arp_init_tables(void)
{
	int i;
	int rc = 0;

	for (i = 0; i < NUM_SETS; ++i)
		odp_rwlock_write_lock(&shm->arp.set[i].table_rwlock);
	odp_rwlock_write_lock(&shm->arp.fr_ent_rwlock);

	for (i = 0; i < NUM_ARPS; ++i)
		CHECK_ERROR(ofp_arp_entry_reset(&shm->arp.entries[i]), rc);

	for (i = 0; i < NUM_SETS; ++i) {
		memset(&shm->arp.set[i].table, 0, sizeof(shm->arp.set[i].table));
		memset(&shm->arp.set[i].cache, 0, sizeof(shm->arp.set[i].cache));
	}

	OFP_STAILQ_INIT(&shm->arp.free_entries);

	for (i = NUM_ARPS - 1; i >= 1; --i)
		OFP_STAILQ_INSERT_HEAD(&shm->arp.free_entries, &shm->arp.entries[i],
				  next);
	memset(&shm->arp.entries[0], 1, sizeof(shm->arp.entries[0]));

	for (i = 0; i < NUM_SETS; ++i)
		odp_rwlock_write_unlock(&shm->arp.set[i].table_rwlock);

	odp_rwlock_write_unlock(&shm->arp.fr_ent_rwlock);

	ofp_arp_init_tables_pkt_list();

	return rc;
}

static int ofp_arp_alloc_shared_memory(void)
{
	shm = ofp_shared_memory_alloc(SHM_NAME_ARP, SHM_SIZE_ARP);
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}
	return 0;
}

static int ofp_arp_free_shared_memory(void)
{
	int rc = 0;

	if (ofp_shared_memory_free(SHM_NAME_ARP) == -1) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}
	shm = NULL;
	return rc;
}

void ofp_arp_init_prepare(void)
{
	ofp_shared_memory_prealloc(SHM_NAME_ARP, SHM_SIZE_ARP);
}

int ofp_arp_init_global(void)
{
	int i;
	int cli = 0;
	int age_interval = ARP_AGE_INTERVAL;
	int entry_timeout = global_param->arp.entry_timeout;

	HANDLE_ERROR(ofp_arp_alloc_shared_memory());

	memset(shm, 0, SHM_SIZE_ARP);
	shm->age_timer = ODP_TIMER_INVALID;
	shm->arp.entries = (struct arp_entry *)((char *)shm + sizeof(*shm));
	shm->arp.set = (struct set_s *)((char *)shm->arp.entries + SIZEOF_ENTRIES);

	for (i = 0; i < NUM_SETS; ++i)
		odp_rwlock_init(&shm->arp.set[i].table_rwlock);
	odp_rwlock_init(&shm->arp.fr_ent_rwlock);
	odp_rwlock_init(&shm->pkt.fr_ent_rwlock);

	for (i = 0; i < NUM_ARPS; ++i) {
		shm->arp.entries[i].pkt_tmo = ODP_TIMER_INVALID;
		shm->arp.entries[i].usetime_upd_tmo = ODP_TIMER_INVALID;
		odp_rwlock_init(&shm->arp.entries[i].usetime_rwlock);

	}

	HANDLE_ERROR(ofp_arp_init_tables());

	if (!age_interval) {
		age_interval = entry_timeout/AGE_DIVISOR;
		if (age_interval < 1) age_interval = 1;
	}
	if (entry_timeout < age_interval) {
		OFP_WARN("ARP age interval should be less than entry timeout, "
			 "setting to %ds", entry_timeout);
		age_interval = entry_timeout;
	}
	shm->entry_timeout =
		odp_time_global_from_ns(entry_timeout * NS_PER_SEC);
	shm->age_interval = age_interval;
	shm->age_timer = ofp_timer_start(
		shm->age_interval * US_PER_SEC, ofp_arp_age_cb, &cli, sizeof(cli));
	if (shm->age_timer == ODP_TIMER_INVALID) {
		OFP_ERR("Failed to create ARP age timer");
		return -1;
	}

	return 0;
}

int ofp_arp_term_global(void)
{
	int i;
	struct arp_entry *entry, *next_entry;
	struct pkt_entry *pktentry;
	int rc = 0;

	if (ofp_arp_lookup_shared_memory())
		return -1;

	if (shm->age_timer != ODP_TIMER_INVALID)
		CHECK_ERROR(ofp_timer_cancel(shm->age_timer), rc);

	for (i = 0; i < NUM_SETS; i++) {
		entry = OFP_STAILQ_FIRST(&shm->arp.set[i].table);

		while (entry) {
			next_entry = OFP_STAILQ_NEXT(entry, next);

			if (entry->pkt_tmo != ODP_TIMER_INVALID)
				CHECK_ERROR(ofp_timer_cancel(entry->pkt_tmo),
					rc);

			pktentry = OFP_SLIST_FIRST(&entry->pkt_list_head);
			while (pktentry) {
				OFP_SLIST_REMOVE_HEAD(&entry->pkt_list_head,
						next);

				pkt_entry_free(pktentry);

				pktentry =
					OFP_SLIST_FIRST(&entry->pkt_list_head);
			}

			CHECK_ERROR(remove_entry(i, entry), rc);
			entry = next_entry;
		}
	}

	CHECK_ERROR(ofp_arp_free_shared_memory(), rc);

	return rc;
}

int ofp_arp_init_local(void)
{
	return 0;
}

void ofp_arp_term_local(void)
{
}

int ofp_arp_lookup_shared_memory(void)
{
	shm = ofp_shared_memory_lookup(SHM_NAME_ARP);
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}
	return 0;
}
