/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 *
 * SPMC ARP table in shmem
 * Needs a writelock on writes to become MPMC for controlplane
 * to scale properly.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <netinet/if_ether.h>
#include <ck_epoch.h>
#include <ck_queue.h>
#include <ck_pr.h>
#include <odp_api.h>

#include "api/ofp_types.h"
#include "ofpi_portconf.h"
#include "ofpi_arp.h"
#include "ofpi_hash.h"
#include "ofpi_log.h"
#include "ofpi_util.h"

#include <config.h>

#define SHM_NAME_ARP_CK "OfpArpCkShMem"

#define ENTRIES_PER_CACHE_LINE (ODP_CACHE_LINE_SIZE / sizeof(struct arp_entry))
#define ENTRIES_PER_SET (ENTRIES_PER_CACHE_LINE * 4)
#define NUM_SETS 2048 /* Must be power of two */

struct arp_tbl {
	struct arp_entry *slh_first;
};

struct ofp_arp_mem {
	struct arp_tbl arp_table[NUM_SETS] ODP_ALIGNED_CACHE;
	struct arp_entry arp_entries[NUM_SETS][ENTRIES_PER_SET] ODP_ALIGNED_CACHE;
};

static __thread struct ofp_arp_mem *shm;

static ck_epoch_t arp_epoch;
static ck_epoch_section_t section ODP_ALIGNED_CACHE;
static __thread ck_epoch_record_t record ODP_ALIGNED_CACHE;

static inline uint32_t ipv4_hash(struct arp_key *key)
{
	return ofp_hashword((const uint32_t *)key, sizeof(*key)/sizeof(uint32_t), 0) & (NUM_SETS - 1);
}

static inline void *arp_malloc(int index, struct arp_key *key)
{
	uint32_t i;

	for (i = 0; i < ENTRIES_PER_SET; i++) {
		if (ck_pr_cas_32(&(shm->arp_entries[index][i].key.ipv4_addr), 0,
				 key->ipv4_addr)) {
			ck_pr_store_32(&(shm->arp_entries[index][i].key.vrf),
				       key->vrf);

			/* Success */
			return (void *)&(shm->arp_entries[index][i]);
		}
	}

	OFP_ERR("Arp table bucket size error.");
	return NULL;
}

static inline void arp_free(void *p)
{
	struct arp_entry *entry = (struct arp_entry *)p;

	memset(&entry->key, 0, sizeof(entry->key));
	odp_mb_release();
}

static inline struct arp_entry *arp_lookup(struct arp_key *key)
{
	struct arp_entry *new;
	int set;

	set = ipv4_hash(key);

	CK_SLIST_FOREACH(new, &(shm->arp_table[set]), next) {
		if (odp_likely((new->key.ipv4_addr == key->ipv4_addr) &&
			       (new->key.vrf == key->vrf))) {
			return new;
		}
	}

	return NULL;
}

inline int ofp_arp_ipv4_insert(uint32_t ipv4_addr, unsigned char *ll_addr,
			        struct ofp_ifnet *dev)
{
	struct arp_entry *new;
	struct arp_key key;
	int set;

	key.vrf = dev->vrf;
	key.ipv4_addr = ipv4_addr;
	set = ipv4_hash(&key);

	ck_epoch_begin(&record, &section);
	new = arp_lookup(&key);
	/*
	  TODO: when mac is changing for an existing node and read while
	  changing. We should always alloc, and if we find an existing entry
	  we should swap the addresses atomically.
	*/
	if (odp_unlikely(new != NULL)) {
		new->ifx = dev->port;
		memcpy(&new->macaddr, ll_addr, ETH_ALEN);
		odp_mb_release();
		ck_epoch_end(&record, &section);
		return 0;
	}

	new = arp_malloc(set, &key);
	if (odp_unlikely(new == NULL)) {
		ck_epoch_end(&record, &section);
		return -1;
	}

	new->ifx = dev->port;
	memcpy(&new->macaddr, ll_addr, ETH_ALEN);
	CK_SLIST_INSERT_HEAD(&(shm->arp_table[set]), new, next);
	ck_epoch_end(&record, &section);

	return 0;
}

inline int ofp_arp_ipv4_remove(uint32_t ipv4_addr, struct ofp_ifnet *dev)
{
	struct arp_entry *new;
	struct arp_key key;
	int ret = -1;
	int set;

	key.vrf = dev->vrf;
	key.ipv4_addr = ipv4_addr;
	set = ipv4_hash(&key);

	ck_epoch_begin(&record, &section);
	new = arp_lookup(&key);

	if (odp_likely(new != NULL)) {
		CK_SLIST_REMOVE(&(shm->arp_table[set]), new, arp_entry, next);
		ret = 0;
	}

	ck_epoch_end(&record, &section);
	if (odp_likely(ret == 0)) {
		/* Blocking RCU cleanup from controlplane side */
		ck_epoch_barrier(&record);
		/* epoch has passed, we can now safely free object */
		arp_free(new);
	}

	return ret;
}

inline int ofp_ipv4_lookup_mac(uint32_t ipv4_addr, unsigned char *ll_addr,
				 struct ofp_ifnet *dev)
{
	struct arp_entry *new;
	struct arp_key key;
	int ret;

	key.vrf = dev->vrf;
	key.ipv4_addr = ipv4_addr;

	ck_epoch_begin(&record, &section);
	new = arp_lookup(&key);

	if (odp_likely(new != NULL)) {
		memcpy(ll_addr, &new->macaddr, ETH_ALEN);
		ret = new->ifx;
	} else {
		ret = -1;
	}
	ck_epoch_end(&record, &section);

	return ret;
}

static inline void show_arp_entry(int fd, int s, int e)
{
	if (shm->arp_entries[s][e].key.ipv4_addr)
		ofp_sendf(fd, "%3d  %-15s %s\r\n",
			    shm->arp_entries[s][e].key.vrf,
			    ofp_print_ip_addr(shm->arp_entries[s][e].key.ipv4_addr),
			    ofp_print_mac((uint8_t *)&shm->arp_entries[s][e].macaddr));
}

void ofp_arp_show_table(int fd)
{
	uint32_t i, j;

	ck_epoch_begin(&record, &section);
	for (i = 0; i < NUM_SETS; ++i)
		for (j = 0; j < ENTRIES_PER_SET; ++j)
			show_arp_entry(fd, i, j);
	ck_epoch_end(&record, &section);
}

/*
 * TODO, stubs
 */

enum ofp_return_code ofp_arp_save_ipv4_pkt(odp_packet_t pkt, struct ofp_nh_entry *nh_param,
					   uint32_t ipv4_addr, struct ofp_ifnet *dev)
{
	(void) pkt;
	(void) nh_param;
	(void) ipv4_addr;
	(void) dev;

	return OFP_PKT_DROP;
}

void ofp_arp_show_saved_packets(int fd)
{
	(void) fd;
}

int ofp_arp_init_tables(void)
{
	return 0;
}

/******************************************************************************/

static int ofp_arp_alloc_shared_memory(void)
{
	shm = ofp_shared_memory_alloc(SHM_NAME_ARP_CK, sizeof(*shm));
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}
	return 0;
}

static int ofp_arp_free_shared_memory(void)
{
	int rc = 0;

	if (ofp_shared_memory_free(SHM_NAME_ARP_CK) == -1) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}
	shm = NULL;
	return rc;
}

int ofp_arp_lookup_shared_memory(void)
{
	shm = ofp_shared_memory_lookup(SHM_NAME_ARP_CK);
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}
	return 0;
}

void ofp_arp_init_prepare(void)
{
	ofp_shared_memory_prealloc(SHM_NAME_ARP_CK, sizeof(*shm));
}

int ofp_arp_init_global(void)
{
	HANDLE_ERROR(ofp_arp_alloc_shared_memory());

	memset(shm, 0, sizeof(*shm));

	memset((void *)&(shm->arp_table[0]), 0x0, sizeof(shm->arp_table));
	memset((void *)&(shm->arp_entries[0][0]), 0x0,
	       sizeof(shm->arp_entries));
	ck_epoch_init(&arp_epoch);
	odp_mb_release();

	return 0;
}

int ofp_arp_term_global(void)
{
	int rc = 0;

	if (ofp_arp_lookup_shared_memory())
		return -1;

	CHECK_ERROR(ofp_arp_free_shared_memory(), rc);

	return rc;
}

int ofp_arp_init_local(void)
{
	ck_epoch_register(&arp_epoch, &record);
	odp_mb_release();
	return 0;
}

void ofp_arp_term_local(void)
{
}
