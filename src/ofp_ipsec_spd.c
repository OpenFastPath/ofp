/*
 * Copyright (c) 2018, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_api.h>
#include "api/ofp_types.h"
#include "api/ofp_pkt_processing.h"
#include "api/ofp_log.h"
#include "api/ofp_ipsec.h"
#include "ofpi_in.h"
#include "ofpi_ip.h"
#include "ofpi_shared_mem.h"
#include "ofpi_ipsec_spd.h"
#include "ofpi_ipsec_sad.h"

struct ofp_ipsec_sp {
	ofp_ipsec_sp_param_t param;
	struct ofp_ipsec_sp *next_in_lookup;
	ofp_ipsec_sa_handle sa;			/* user managed */
	uint32_t refcount;
	int destroyed;
	struct ofp_ipsec_sp *next;
};

struct ofp_ipsec_spd {
	odp_rwlock_t lock;
	struct ofp_ipsec_sp *sp_list;
	struct ofp_ipsec_sp *outbound_lookup_list;
	struct ofp_ipsec_sp *inbound_lookup_list;
	struct ofp_ipsec_sp *free_sp_list;
};

struct ofp_ipsec_selector_values {
	uint32_t src_addr;
	uint32_t dst_addr;
	uint8_t ip_proto;
};

#define SHM_NAME_IPSEC_SPD "ofp_ipsec_spd"
static __thread struct ofp_ipsec_spd *shm;

#define SHM_NAME_IPSEC_SP_TABLE "ofp_ipsec_sp_table"
static __thread struct ofp_ipsec_sp *shm_sp_table;

static struct ofp_ipsec_sp *sp_alloc(void)
{
	struct ofp_ipsec_sp *sp;

	sp = shm->free_sp_list;
	if (sp) {
		shm->free_sp_list = sp->next;
		sp->refcount = 1;
	}
	return sp;
}

static void sp_free(struct ofp_ipsec_sp *sp)
{
	sp->next = shm->free_sp_list;
	shm->free_sp_list = sp;
}

static void sp_ref(struct ofp_ipsec_sp *sp)
{
	if (sp)
		sp->refcount++;
}

static void sp_unref(struct ofp_ipsec_sp *sp)
{
	if (sp && --sp->refcount == 0)
		sp_free(sp);
}

void ofp_ipsec_sp_ref(struct ofp_ipsec_sp *sp)
{
	odp_rwlock_write_lock(&shm->lock);
	sp_ref(sp);
	odp_rwlock_write_unlock(&shm->lock);
}

void ofp_ipsec_sp_unref(struct ofp_ipsec_sp *sp)
{
	odp_rwlock_write_lock(&shm->lock);
	sp_unref(sp);
	odp_rwlock_write_unlock(&shm->lock);
}

static void ipsec_ntohl(uint32_t *val)
{
	*val = odp_be_to_cpu_32(*val);
}

static void ipsec_htonl(uint32_t *val)
{
	*val = odp_cpu_to_be_32(*val);
}

static uint64_t sp_table_size(uint32_t max_num_sp)
{
	return max_num_sp * sizeof(struct ofp_ipsec_sp);
}

void ofp_ipsec_spd_init_prepare(uint32_t max_num_sp)
{
	ofp_shared_memory_prealloc(SHM_NAME_IPSEC_SPD, sizeof(*shm));
	ofp_shared_memory_prealloc(SHM_NAME_IPSEC_SP_TABLE,
				   sp_table_size(max_num_sp));
}

int ofp_ipsec_spd_init_global(uint32_t max_num_sp)
{
	uint32_t n;

	shm = ofp_shared_memory_alloc(SHM_NAME_IPSEC_SPD, sizeof(*shm));
	if (!shm) {
		OFP_ERR("Failed to allocate IPsec SPD shared memory");
		return -1;
	}
	odp_rwlock_init(&shm->lock);
	shm->sp_list = NULL;
	shm->outbound_lookup_list = NULL;
	shm->inbound_lookup_list = NULL;
	shm->free_sp_list = NULL;

	shm_sp_table = ofp_shared_memory_alloc(SHM_NAME_IPSEC_SP_TABLE,
					       sp_table_size(max_num_sp));
	if (!shm_sp_table) {
		OFP_ERR("Failed to allocate IPsec SP table");
		ofp_shared_memory_free(SHM_NAME_IPSEC_SPD);
		return -1;
	}
	for (n = 0; n < max_num_sp; n++)
		sp_free(&shm_sp_table[n]);
	return 0;
}

int ofp_ipsec_spd_init_local(void)
{
	shm = ofp_shared_memory_lookup(SHM_NAME_IPSEC_SPD);
	if (!shm) {
		OFP_ERR("Failed to lookup IPsec SPD shared memory");
		return -1;
	}

	shm_sp_table = ofp_shared_memory_lookup(SHM_NAME_IPSEC_SP_TABLE);
	if (!shm) {
		OFP_ERR("Failed to lookup IPsec SP table shared memory");
		return -1;
	}
	return 0;
}

int ofp_ipsec_spd_term_global(void)
{
	ofp_shared_memory_free(SHM_NAME_IPSEC_SPD);
	ofp_shared_memory_free(SHM_NAME_IPSEC_SP_TABLE);
	return 0;
}


static struct ofp_ipsec_sp *sp_find_by_id(uint32_t id)
{
	struct ofp_ipsec_sp *sp = shm->sp_list;

	while (sp) {
		if (sp->param.id == id) {
			break;
		}
		sp = sp->next;
	}
	return sp;
}

struct ofp_ipsec_sp *ofp_ipsec_sp_find_by_id(uint32_t id)
{
	struct ofp_ipsec_sp *sp;

	odp_rwlock_write_lock(&shm->lock);
	sp = sp_find_by_id(id);
	sp_ref(sp);
	odp_rwlock_write_unlock(&shm->lock);
	return sp;
}

ofp_ipsec_sp_handle ofp_ipsec_sp_first(void)
{
	ofp_ipsec_sp_handle sp;

	odp_rwlock_write_lock(&shm->lock);
	sp = shm->sp_list;
	sp_ref(sp);
	odp_rwlock_write_unlock(&shm->lock);
	return sp;
}

ofp_ipsec_sp_handle ofp_ipsec_sp_next(ofp_ipsec_sp_handle sp)
{
	ofp_ipsec_sp_handle next;

	odp_rwlock_write_lock(&shm->lock);
	next = sp->next;
	sp_ref(next);
	sp_unref(sp);
	odp_rwlock_write_unlock(&shm->lock);
	return next;
}

void ofp_ipsec_sp_get_info(ofp_ipsec_sp_handle sp, ofp_ipsec_sp_info_t *info)
{
	odp_rwlock_read_lock(&shm->lock);
	if (sp->destroyed)
		info->status = OFP_IPSEC_SP_DESTROYED;
	else
		info->status = OFP_IPSEC_SP_ACTIVE;
	info->param = sp->param;
	/*
	 * Convert addresses back to network byte order as expected by the API
	 */
	ipsec_htonl(&info->param.selectors.src_ipv4_range.first_addr.s_addr);
	ipsec_htonl(&info->param.selectors.src_ipv4_range.last_addr.s_addr);
	ipsec_htonl(&info->param.selectors.dst_ipv4_range.first_addr.s_addr);
	ipsec_htonl(&info->param.selectors.dst_ipv4_range.last_addr.s_addr);

	odp_rwlock_read_unlock(&shm->lock);
}

/*
 * Insert SP to the right place in the given lookup list based on priority.
 */
static void sp_insert(struct ofp_ipsec_sp **link,
		      struct ofp_ipsec_sp *sp)
{
	while (*link) {
		if ((*link)->param.priority >= sp->param.priority)
			break;
		link = &(*link)->next_in_lookup;
	}
	sp->next_in_lookup = *link;
	*link = sp;
}

void ofp_ipsec_sp_param_init(ofp_ipsec_sp_param_t *param)
{
	memset(param, 0, sizeof(*param));
}

struct ofp_ipsec_sp *ofp_ipsec_sp_add(const ofp_ipsec_sp_param_t *param)
{
	struct ofp_ipsec_sp *sp = NULL;

	odp_rwlock_write_lock(&shm->lock);

	if (param->selectors.src_port_range.first_port != 0 ||
	    param->selectors.src_port_range.last_port != 0 ||
	    param->selectors.dst_port_range.first_port != 0 ||
	    param->selectors.dst_port_range.last_port != 0) {
		OFP_ERR("Port based IPsec selectors are not supported");
		goto out;
	}

	if (param->selectors.type != OFP_IPSEC_SELECTOR_IPV4) {
		OFP_ERR("IPsec is not supported with IPv6");
		goto out;
	}

	if (sp_find_by_id(param->id)) {
		OFP_ERR("IPsec SP with the same ID already exists");
		goto out;
	}

	if (param->sa != OFP_IPSEC_SA_INVALID) {
		OFP_ERR("Binding IPsec SA to an SP is not supported as part"
			"of IPsec SP creation.");
		goto out;
	}

	sp = sp_alloc();
	if (!sp) {
		OFP_ERR("Out of free IPsec SPs");
		goto out;
	}

	sp->param = *param;
	sp->destroyed = 0;
	sp->sa = OFP_IPSEC_SA_INVALID;

	/*
	 * Convert IPv4 addresses to host byte order here to avoid
	 * the conversion in SP matching.
	 */
	ipsec_ntohl(&sp->param.selectors.src_ipv4_range.first_addr.s_addr);
	ipsec_ntohl(&sp->param.selectors.src_ipv4_range.last_addr.s_addr);
	ipsec_ntohl(&sp->param.selectors.dst_ipv4_range.first_addr.s_addr);
	ipsec_ntohl(&sp->param.selectors.dst_ipv4_range.last_addr.s_addr);

	sp->next = shm->sp_list;
	shm->sp_list = sp;
	/*
	 * We already hold one reference ourselves since the SP is now part
	 * of SPD. Increment refcount for the returned handle too.
	 */
	sp_ref(sp);
out:
	odp_rwlock_write_unlock(&shm->lock);
	return sp;
}

int ofp_ipsec_sp_del(struct ofp_ipsec_sp *sp)
{
	struct ofp_ipsec_sp **link;
	int found = 0;

	odp_rwlock_write_lock(&shm->lock);

	link = &shm->sp_list;
	while (*link) {
		if (*link == sp) {
			found = 1;
			*link = sp->next;
			break;
		}
		link = &(*link)->next;
	}

	if (found) {
		sp->destroyed = 1;
		sp_unref(sp);
	}

	odp_rwlock_write_unlock(&shm->lock);
	return !found;
}

const ofp_ipsec_sp_param_t *ofp_ipsec_sp_get_param(struct ofp_ipsec_sp *sp)
{
	return &sp->param;
}

ofp_ipsec_sa_handle *ofp_ipsec_sp_get_sa_area(struct ofp_ipsec_sp *sp)
{
	return &sp->sa;
}

static void get_selector_values(odp_packet_t pkt,
				struct ofp_ipsec_selector_values *s)
{
	struct ofp_ip *ip;
	uint32_t len;

	ip = odp_packet_l3_ptr(pkt, &len);
	if (odp_unlikely(!ip || len < sizeof(*ip))) {
		memset(s, 0, sizeof(*s));
		return;
	}
	/*
	 * We assume, like other OFP code, that unaligned access is ok
	 */
	s->src_addr = odp_be_to_cpu_32(ip->ip_src.s_addr);
	s->dst_addr = odp_be_to_cpu_32(ip->ip_dst.s_addr);
	s->ip_proto = ip->ip_p;
}

static int sp_match(const struct ofp_ipsec_sp *sp,
		    const struct ofp_ipsec_selector_values *sel)
{
	const ofp_ipsec_selectors_t *pol_sel = &sp->param.selectors;

	if (pol_sel->type != OFP_IPSEC_SELECTOR_IPV4)
		return 0;
	if (sel->src_addr < pol_sel->src_ipv4_range.first_addr.s_addr ||
	    sel->src_addr > pol_sel->src_ipv4_range.last_addr.s_addr)
		return 0;
	if (sel->dst_addr < pol_sel->dst_ipv4_range.first_addr.s_addr ||
	    sel->dst_addr > pol_sel->dst_ipv4_range.last_addr.s_addr)
		return 0;
	if (pol_sel->ip_proto != 0 && sel->ip_proto != pol_sel->ip_proto)
		return 0;
	return 1;
}

void ofp_ipsec_sp_lookup_add_sp(struct ofp_ipsec_sp *sp)
{
	if (sp->param.dir == OFP_IPSEC_DIR_INBOUND)
		sp_insert(&shm->inbound_lookup_list, sp);
	else
		sp_insert(&shm->outbound_lookup_list, sp);
}

int ofp_ipsec_sp_lookup_del_sp(struct ofp_ipsec_sp *sp, int *empty)
{
	struct ofp_ipsec_sp **link;

	if (sp->param.dir == OFP_IPSEC_DIR_INBOUND)
		link = &shm->inbound_lookup_list;
	else
		link = &shm->outbound_lookup_list;

	while (*link && (*link) != sp)
		link = &(*link)->next_in_lookup;
	if (link == NULL)
		return -1;

	*link = sp->next_in_lookup;
	*empty = (shm->inbound_lookup_list == NULL &&
		  shm->outbound_lookup_list == NULL);
	return 0;
}

static inline ofp_ipsec_action_t sp_lookup(struct ofp_ipsec_sp *sp,
					   uint16_t vrf,
					   odp_packet_t pkt,
					   ofp_ipsec_sa_handle *sa)
{
	ofp_ipsec_action_t action;
	struct ofp_ipsec_selector_values sel;

	get_selector_values(pkt, &sel);

	while (sp) {
		if (sp->param.vrf == vrf && sp_match(sp, &sel))
			break;
		sp = sp->next_in_lookup;
	}
	if (sp)  {
		if (sa) {
			if (!ofp_ipsec_sa_disabled(sp->sa)) {
				*sa = sp->sa;
			} else {
				*sa = OFP_IPSEC_SA_INVALID;
			}
		}
		action = sp->param.action;
	} else {
		action = OFP_IPSEC_ACTION_BYPASS;
	}
	return action;
}

ofp_ipsec_action_t ofp_ipsec_sp_out_lookup(uint16_t vrf, odp_packet_t pkt,
					   ofp_ipsec_sa_handle *sa)
{
	return sp_lookup(shm->outbound_lookup_list, vrf, pkt, sa);
}

ofp_ipsec_action_t ofp_ipsec_sp_in_lookup(uint16_t vrf, odp_packet_t pkt)
{
	return sp_lookup(shm->inbound_lookup_list, vrf, pkt, NULL);
}
