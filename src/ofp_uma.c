/*-
 * Copyright (c) 2014 Nokia
 * Copyright (c) 2014 ENEA Software AB
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#include <odp_api.h>
#include "ofpi_uma.h"
#include "ofpi_log.h"
#include "ofpi_util.h"

#define SHM_NAME_UMA "OfpUmaShMem"

struct ofp_uma_mem {
	odp_pool_t pools[OFP_NUM_UMA_POOLS];
	int num_pools;
};

static __thread struct ofp_uma_mem *shm;

struct uma_pool_metadata {
	union {
		odp_buffer_t buffer_handle;
		uint64_t u64;
	};
	uint8_t data[0];
};

BUILD_ASSERT(sizeof(struct uma_pool_metadata) == 8);

uma_zone_t ofp_uma_pool_create(const char *name, int nitems, int size)
{
	odp_pool_param_t pool_params;
	odp_pool_t pool;
	uma_zone_t zone;

	odp_pool_param_init(&pool_params);
	pool_params.buf.size  = size + sizeof(struct uma_pool_metadata);
	pool_params.buf.align = 0;
	pool_params.buf.num   = nitems;
	pool_params.type      = ODP_POOL_BUFFER;

	OFP_INFO("Creating pool '%s', nitems=%d size=%d total=%d",
		 name, pool_params.buf.num, pool_params.buf.size,
		 pool_params.buf.num * pool_params.buf.size);

	if (shm->num_pools >= OFP_NUM_UMA_POOLS) {
		OFP_ERR("Exceeded max number (%d) of pools",
			OFP_NUM_UMA_POOLS);
		return OFP_UMA_ZONE_INVALID;
	}
	pool = ofp_pool_create(name, &pool_params);
	if (pool == ODP_POOL_INVALID) {
		OFP_ERR("odp_pool_create failed");
		return OFP_UMA_ZONE_INVALID;
	}

	zone = shm->num_pools++;
	shm->pools[zone] = pool;

	return zone;
}

int ofp_uma_pool_destroy(uma_zone_t zone)
{
	int ret = 0;

	if (zone > OFP_NUM_UMA_POOLS || zone < 0)
		return -1;
	if (shm->pools[zone] == ODP_POOL_INVALID)
		return -1;

	ret = odp_pool_destroy(shm->pools[zone]);

	shm->pools[zone] = ODP_POOL_INVALID;

	return ret;
}

void *ofp_uma_pool_alloc(uma_zone_t zone, int flags)
{
	odp_buffer_t buffer;
	struct uma_pool_metadata *meta;

	if (zone < 0 || zone >= shm->num_pools) {
		OFP_ERR("Wrong zone %d!", zone);
		return NULL;
	}

	buffer = odp_buffer_alloc(shm->pools[zone]);
	if (buffer == ODP_BUFFER_INVALID) {
		OFP_ERR("odp_buffer_alloc failed");
		return NULL;
	}

	meta = (struct uma_pool_metadata *) odp_buffer_addr(buffer);
	meta->buffer_handle = buffer;

	if (flags & OFP_M_ZERO)
		odp_memset((void *)&meta->data, 0, odp_buffer_size(buffer) -
			sizeof(struct uma_pool_metadata));
	return (void *) &meta->data;
}

void ofp_uma_pool_free(void *data)
{
	struct uma_pool_metadata *meta = (struct uma_pool_metadata *)
		((uint8_t *) data - sizeof(struct uma_pool_metadata));

	odp_buffer_free(meta->buffer_handle);
}

static int ofp_uma_alloc_shared_memory(void)
{
	shm = ofp_shared_memory_alloc(SHM_NAME_UMA, sizeof(*shm));
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}
	return 0;
}

static int ofp_uma_free_shared_memory(void)
{
	int rc = 0;

	if (ofp_shared_memory_free(SHM_NAME_UMA) == -1) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}
	shm = NULL;
	return rc;
}


int ofp_uma_lookup_shared_memory(void)
{
	shm = ofp_shared_memory_lookup(SHM_NAME_UMA);
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}
	return 0;
}

void ofp_uma_init_prepare(void)
{
	ofp_shared_memory_prealloc(SHM_NAME_UMA, sizeof(*shm));
}

int ofp_uma_init_global(void)
{
	uint32_t i;

	HANDLE_ERROR(ofp_uma_alloc_shared_memory());

	memset(shm, 0, sizeof(*shm));

	for (i = 0; i < OFP_NUM_UMA_POOLS; i++)
		shm->pools[i] = ODP_POOL_INVALID;

	shm->num_pools = 0;

	return 0;
}

int ofp_uma_term_global(void)
{
	uint32_t i;
	int rc = 0;

	for (i = 0; i < OFP_NUM_UMA_POOLS; i++)
		if (shm->pools[i] != ODP_POOL_INVALID)
			CHECK_ERROR(odp_pool_destroy(shm->pools[i]), rc);

	CHECK_ERROR(ofp_uma_free_shared_memory(), rc);

	return rc;
}
