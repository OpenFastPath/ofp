/*
 * Copyright (c) 2018, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_api.h>
#include <inttypes.h>
#include "api/ofp_types.h"
#include "api/ofp_log.h"
#include "api/ofp_ipsec.h"
#include "ofpi_in.h"
#include "ofpi_ip.h"
#include "ofpi_shared_mem.h"
#include "ofpi_ipsec_sad.h"

struct ofp_ipsec_sad {
	odp_rwlock_t lock;
	odp_queue_t inbound_queue;
	odp_queue_t outbound_queue;
	struct ofp_ipsec_sa *sa_list;
	struct ofp_ipsec_sa *free_sa_list;
};

struct ofp_ipsec_sa {
	odp_ipsec_sa_t odp_sa;
	odp_atomic_u32_t disabled;   /* Do not start new operations */
	ofp_ipsec_sa_param_t param;
	odp_atomic_u32_t selectors_set;  /* Selectors field has been set */
	ofp_ipsec_selectors_t selectors; /* For inbound SAs */
	uint32_t refcount;
	int destroyed;		     /* SA has been destroyed */
	struct ofp_ipsec_sa *next;   /* next SA in a linked list */
};

#define SHM_NAME_IPSEC_SAD "ofp_ipsec_sad"
static __thread struct ofp_ipsec_sad *shm;

#define SHM_NAME_IPSEC_SA_TABLE "ofp_ipsec_sa_table"
static __thread struct ofp_ipsec_sa *shm_sa_table;

static struct ofp_ipsec_sa *sa_find_by_id(uint32_t id);
static int sa_init(struct ofp_ipsec_sa *sa, const ofp_ipsec_sa_param_t *param);
static struct ofp_ipsec_sa *sa_in_lookup(uint32_t spi);

/*
 * Tell if ODP SA lookup is offloaded to ODP so that the ODP SA is not
 * explicitly passed to ODP IPsec packet input/output functions.
 */
static inline int lookup_offloaded(struct ofp_ipsec_sa *sa)
{
	return sa->param.dir == OFP_IPSEC_DIR_INBOUND;
}

static struct ofp_ipsec_sa *sa_alloc(void)
{
	struct ofp_ipsec_sa *sa;

	sa = shm->free_sa_list;
	if (sa) {
		shm->free_sa_list = sa->next;
		sa->refcount = 1;
	}
	return sa;
}

static void sa_free(struct ofp_ipsec_sa *sa)
{
	sa->next = shm->free_sa_list;
	shm->free_sa_list = sa;
}

static void sa_ref(struct ofp_ipsec_sa *sa)
{
	if (sa)
		sa->refcount++;
}

static void sa_unref(struct ofp_ipsec_sa *sa)
{
	if (sa && --sa->refcount == 0)
		sa_free(sa);
}

void ofp_ipsec_sa_ref(struct ofp_ipsec_sa *sa)
{
	odp_rwlock_write_lock(&shm->lock);
	sa_ref(sa);
	odp_rwlock_write_unlock(&shm->lock);
}

void ofp_ipsec_sa_unref(struct ofp_ipsec_sa *sa)
{
	odp_rwlock_write_lock(&shm->lock);
	sa_unref(sa);
	odp_rwlock_write_unlock(&shm->lock);
}

static uint64_t sa_table_size(uint32_t max_num_sa)
{
	return sizeof(*shm_sa_table) * max_num_sa;
}

void ofp_ipsec_sad_init_prepare(uint32_t max_num_sa)
{
	ofp_shared_memory_prealloc(SHM_NAME_IPSEC_SAD, sizeof(*shm));
	ofp_shared_memory_prealloc(SHM_NAME_IPSEC_SA_TABLE,
				   sa_table_size(max_num_sa));
}

int ofp_ipsec_sad_init_global(uint32_t max_num_sa,
			      odp_queue_t inbound_queue,
			      odp_queue_t outbound_queue)
{
	uint32_t n;

	shm = ofp_shared_memory_alloc(SHM_NAME_IPSEC_SAD, sizeof(*shm));
	if (!shm) {
		OFP_ERR("Failed to allocate IPsec SAD shared memory");
		return -1;
	}
	odp_rwlock_init(&shm->lock);
	shm->sa_list = NULL;
	shm->free_sa_list = NULL;
	shm->inbound_queue = inbound_queue;
	shm->outbound_queue = outbound_queue;

	shm_sa_table = ofp_shared_memory_alloc(SHM_NAME_IPSEC_SA_TABLE,
					       sa_table_size(max_num_sa));
	if (!shm_sa_table) {
		OFP_ERR("shared memory allocation for SAD failed");
		ofp_shared_memory_free(SHM_NAME_IPSEC_SAD);
		return -1;
	}
	for (n = 0; n < max_num_sa; n++)
		sa_free(&shm_sa_table[n]);
	return 0;
}

int ofp_ipsec_sad_init_local(void)
{
	shm = ofp_shared_memory_lookup(SHM_NAME_IPSEC_SAD);
	if (!shm) {
		OFP_ERR("Failed to lookup IPsec SAD shared memory");
		return -1;
	}
	shm_sa_table = ofp_shared_memory_lookup(SHM_NAME_IPSEC_SA_TABLE);
	if (!shm_sa_table) {
		OFP_ERR("Failed to lookup IPsec SA table shared memory");
		return -1;
	}
	return 0;
}

int ofp_ipsec_sad_term_global(void)
{
	ofp_shared_memory_free(SHM_NAME_IPSEC_SAD);
	ofp_shared_memory_free(SHM_NAME_IPSEC_SA_TABLE);
	return 0;
}

#define SALT_LEN 4

/*
 * Move salt from end of the key data to cipher_key_extra parameter for ODP.
 */
static void extract_salt(odp_ipsec_crypto_param_t *crypto,
			 odp_crypto_key_t *key)
{
	if (key->length < SALT_LEN)
		return;
	key->length -= SALT_LEN;
	crypto->cipher_key_extra.data = &key->data[key->length];
	crypto->cipher_key_extra.length = SALT_LEN;
}

static odp_ipsec_sa_t create_odp_sa(struct ofp_ipsec_sa *sa)
{
	ofp_ipsec_sa_param_t *param = &sa->param;
	odp_ipsec_sa_param_t odp_param;
	odp_ipsec_crypto_param_t *crypto = &odp_param.crypto;
	odp_ipsec_sa_opt_t *opt = &odp_param.opt;
	odp_ipsec_tunnel_param_t *tunnel = &odp_param.outbound.tunnel;

	odp_ipsec_sa_param_init(&odp_param);

	crypto->cipher_alg = (odp_cipher_alg_t)param->crypto.cipher_alg;
	crypto->cipher_key.data = param->crypto.cipher_key.key_data;
	crypto->cipher_key.length = param->crypto.cipher_key.key_len;
	crypto->cipher_key_extra.data = NULL;
	crypto->cipher_key_extra.length = 0;
	if (crypto->cipher_alg == ODP_CIPHER_ALG_AES_GCM)
		extract_salt(crypto, &crypto->cipher_key);
	crypto->auth_alg = (odp_auth_alg_t)param->crypto.auth_alg;
	crypto->auth_key.data = param->crypto.auth_key.key_data;
	crypto->auth_key.length = param->crypto.auth_key.key_len;
	if (crypto->auth_alg == ODP_AUTH_ALG_AES_GCM ||
	    crypto->auth_alg == ODP_AUTH_ALG_AES_GMAC)
		extract_salt(crypto, &crypto->auth_key);

	opt->esn = param->opt.esn;
	opt->udp_encap = param->opt.udp_encap;
	opt->copy_dscp = param->opt.copy_dscp;
	opt->copy_flabel = param->opt.copy_flabel;
	opt->copy_df = 0;
	opt->dec_ttl = 0;

	odp_param.dir = (odp_ipsec_dir_t)param->dir;
	odp_param.proto = (odp_ipsec_protocol_t)param->proto;
	odp_param.mode = (odp_ipsec_mode_t)param->mode;
	odp_param.lifetime = param->lifetime;
	odp_param.spi = param->spi;
	odp_param.context = sa;
	odp_param.context_len = 0;

	if (odp_param.dir == ODP_IPSEC_DIR_INBOUND) {
		odp_param.inbound.lookup_mode = ODP_IPSEC_LOOKUP_SPI;
		odp_param.inbound.antireplay_ws = param->antireplay_ws;
		odp_param.inbound.pipeline = ODP_IPSEC_PIPELINE_NONE;
		odp_param.dest_queue = shm->inbound_queue;
	} else {
		tunnel->type = (odp_ipsec_tunnel_type_t)param->tunnel.type;
		tunnel->ipv4.src_addr = &param->tunnel.ipv4.src_addr;
		tunnel->ipv4.dst_addr = &param->tunnel.ipv4.dst_addr;
		tunnel->ipv4.dscp = param->tunnel.ipv4.dscp;
		tunnel->ipv4.df = 0;
		tunnel->ipv4.ttl = param->tunnel.ipv4.ttl;

		odp_param.outbound.frag_mode = ODP_IPSEC_FRAG_DISABLED;
		odp_param.outbound.mtu = UINT32_MAX;
		odp_param.dest_queue = shm->outbound_queue;
	}

	return odp_ipsec_sa_create(&odp_param);
}

static int sa_init(struct ofp_ipsec_sa *sa,
		   const ofp_ipsec_sa_param_t *param)
{
	/*
	 * Disallow unsupported settings
	 */
	if (param->opt.udp_encap ||
	    param->opt.copy_flabel ||
	    ((param->mode == OFP_IPSEC_MODE_TUNNEL &&
	      param->tunnel.type != OFP_IPSEC_TUNNEL_IPV4))) {
		OFP_ERR("Unsupported IPsec SA parameter");
		return -1;
	}

	if (sa_find_by_id(param->id)) {
		OFP_ERR("IPsec SA with the same ID already exists");
		return -1;
	}

	if (param->dir == OFP_IPSEC_DIR_INBOUND && sa_in_lookup(param->spi)) {
		OFP_ERR("Inbound IPsec SA with the same SPI already exists");
		return -1;
	}

	sa->param = *param;
	odp_atomic_store_u32(&sa->disabled, 0);
	odp_atomic_store_u32(&sa->selectors_set, 0);
	sa->destroyed = 0;

	odp_mb_full();

	sa->odp_sa = create_odp_sa(sa);
	if (sa->odp_sa == ODP_IPSEC_SA_INVALID) {
		OFP_ERR("Couldn't create ODP SA with the requested parameters");
		return -1;
	}

	sa->next = shm->sa_list;
	shm->sa_list = sa;
	return 0;
}

void ofp_ipsec_sa_param_init(ofp_ipsec_sa_param_t *param)
{
	memset(param, 0, sizeof(*param));
}

ofp_ipsec_sa_handle ofp_ipsec_sa_create(const ofp_ipsec_sa_param_t *param)
{
	struct ofp_ipsec_sa *sa;

	odp_rwlock_write_lock(&shm->lock);
	sa = sa_alloc();
	if (!sa) {
		OFP_ERR("Out of free IPsec SAs");
		odp_rwlock_write_unlock(&shm->lock);
		return NULL;
	}

	if (sa_init(sa, param)) {
		sa_unref(sa);
		sa = OFP_IPSEC_SA_INVALID;
	}
	/*
	 * We already hold one reference ourselves since the SA is now part
	 * of SAD. Increment refcount for the returned handle too.
	 */
	sa_ref(sa);
	odp_rwlock_write_unlock(&shm->lock);
	return sa;
}

int ofp_ipsec_sa_disable(struct ofp_ipsec_sa *sa)
{
	odp_rwlock_write_lock(&shm->lock);

	if (odp_atomic_load_u32(&sa->disabled)) {
		OFP_ERR("Disabling SA that has already been disabled");
		odp_rwlock_write_unlock(&shm->lock);
		return -1;
	}

	/*
	 * Mark SA disabled for non-offloaded lookup.
	 */
	odp_atomic_store_u32(&sa->disabled, 1);

	odp_rwlock_write_unlock(&shm->lock);

	/*
	 * Disable offloaded SA lookup.
	 */
	if (lookup_offloaded(sa)) {
		if (odp_ipsec_sa_disable(sa->odp_sa)) {
			OFP_ERR("odp_ipsec_sa_disable() failed");
			return -1;
		}
	}

	return 0;
}

int ofp_ipsec_sa_disable_finish(struct ofp_ipsec_sa *sa)
{
	if (!lookup_offloaded(sa)) {
		/*
		 * The caller guarantees that the SA is no longer explicitly
		 * used in OFP IPsec in/out operations so it is now safe to
		 * disable the ODP SA also when the lookup is not offloaded.
		 */
		if (odp_ipsec_sa_disable(sa->odp_sa)) {
			OFP_ERR("odp_ipsec_sa_disable() failed");
			return -1;
		}
	}
	return 0;
}

int ofp_ipsec_sa_destroy_finish(struct ofp_ipsec_sa *sa)
{
	struct ofp_ipsec_sa **link;
	int found = 0;

	odp_rwlock_write_lock(&shm->lock);

	link = &shm->sa_list;
	while (*link) {
		if (*link == sa) {
			found = 1;
			*link = sa->next;
			break;
		}
		link = &(*link)->next;
	}

	if (!found) {
		odp_rwlock_write_unlock(&shm->lock);
		OFP_ERR("IPsec SA destroy failed. Could not find the SA.");
		return -1;
	}

	if (odp_ipsec_sa_destroy(sa->odp_sa)) {
		OFP_ERR("odp_ipsec_sa_destroy() failed");
		odp_rwlock_write_unlock(&shm->lock);
		return -1;
	}
	/*
	 * Mark destroyed in case someone has a handle and queries SA info.
	 */
	sa->destroyed = 1;

	/* The SA was removed from SAD, so decrement its reference count. */
	sa_unref(sa);

	odp_rwlock_write_unlock(&shm->lock);
	return 0;
}

ofp_ipsec_sa_handle ofp_ipsec_sa_first(void)
{
	ofp_ipsec_sa_handle sa;

	odp_rwlock_write_lock(&shm->lock);
	sa = shm->sa_list;
	sa_ref(sa);
	odp_rwlock_write_unlock(&shm->lock);
	return sa;
}

ofp_ipsec_sa_handle ofp_ipsec_sa_next(ofp_ipsec_sa_handle sa)
{
	ofp_ipsec_sa_handle next;

	odp_rwlock_write_lock(&shm->lock);
	next = sa->next;
	sa_ref(next);
	sa_unref(sa);
	odp_rwlock_write_unlock(&shm->lock);
	return next;
}

void ofp_ipsec_sa_get_info(ofp_ipsec_sa_handle sa, ofp_ipsec_sa_info_t *info)
{
	odp_rwlock_read_lock(&shm->lock);
	if (sa->destroyed)
		info->status = OFP_IPSEC_SA_DESTROYED;
	else if (odp_atomic_load_u32(&sa->disabled))
		info->status = OFP_IPSEC_SA_DISABLED;
	else
		info->status = OFP_IPSEC_SA_ACTIVE;
	odp_rwlock_read_unlock(&shm->lock);
	info->param = sa->param;
}

static struct ofp_ipsec_sa *sa_in_lookup(uint32_t spi)
{
	struct ofp_ipsec_sa *sa = shm->sa_list;

	while (sa) {
		if (sa->param.dir == OFP_IPSEC_DIR_INBOUND &&
		    sa->param.spi == spi) {
			break;
		}
		sa = sa->next;
	}
	return sa;
}

static struct ofp_ipsec_sa *sa_find_by_id(uint32_t id)
{
	struct ofp_ipsec_sa *sa = shm->sa_list;

	while (sa) {
		if (sa->param.id == id) {
			break;
		}
		sa = sa->next;
	}
	return sa;
}

struct ofp_ipsec_sa *ofp_ipsec_sa_find_by_id(uint32_t id)
{
	struct ofp_ipsec_sa *sa = NULL;

	odp_rwlock_write_lock(&shm->lock);
	sa = sa_find_by_id(id);
	sa_ref(sa);
	odp_rwlock_write_unlock(&shm->lock);
	return sa;
}

odp_ipsec_sa_t ofp_ipsec_sa_get_odp_sa(struct ofp_ipsec_sa *sa)
{
	return sa->odp_sa;
}

const ofp_ipsec_sa_param_t *ofp_ipsec_sa_get_param(struct ofp_ipsec_sa *sa)
{
	return &sa->param;
}

int ofp_ipsec_sa_disabled(struct ofp_ipsec_sa *sa)
{
	return !sa || odp_atomic_load_u32(&sa->disabled);
}

int ofp_ipsec_sa_set_selectors(struct ofp_ipsec_sa *sa,
			       const ofp_ipsec_selectors_t *sel)
{
	odp_rwlock_write_lock(&shm->lock);
	if (odp_atomic_load_acq_u32(&sa->selectors_set)) {
		odp_rwlock_write_unlock(&shm->lock);
		OFP_ERR("Selectors already set in an SA");
		return -1;
	}
	sa->selectors = *sel;
	odp_atomic_store_rel_u32(&sa->selectors_set, 1);
	odp_rwlock_write_unlock(&shm->lock);
	return 0;
}

ofp_ipsec_selectors_t *ofp_ipsec_sa_get_selectors(struct ofp_ipsec_sa *sa)
{
	if (odp_likely(odp_atomic_load_acq_u32(&sa->selectors_set)))
		return &sa->selectors;
	return NULL;
}
