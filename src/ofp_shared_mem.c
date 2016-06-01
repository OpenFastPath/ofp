/* Copyright (c) 2015, ENEA Software AB
 * Copyright (c) 2015, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "ofpi_shared_mem.h"

static void *allocate_shared_memory(const char *name, uint64_t size)
{
	odp_shm_t shm_h;
	void *shm;

	shm_h = odp_shm_reserve(name, size, ODP_CACHE_LINE_SIZE, 0);
	if (shm_h == ODP_SHM_INVALID)
		return NULL;

	shm = odp_shm_addr(shm_h);

	if (shm == NULL) {
		odp_shm_free(shm_h);
		return NULL;
	}

	return shm;
}

static void *(*shared_memory_allocator)(const char *name, uint64_t size) =
	allocate_shared_memory;

void *ofp_shared_memory_alloc(const char *name, uint64_t size)
{
	return shared_memory_allocator(name, size);
}

int ofp_shared_memory_free(const char *name)
{
	odp_shm_t shm_h;

	shm_h = odp_shm_lookup(name);
	if (shm_h == ODP_SHM_INVALID)
		return -1;

	odp_shm_free(shm_h);
	return 0;
}

void *ofp_shared_memory_lookup(const char *name)
{
	odp_shm_t shm_h;
	void *shm;

	shm_h = odp_shm_lookup(name);
	if (shm_h == ODP_SHM_INVALID)
		return NULL;

	shm = odp_shm_addr(shm_h);
	if (shm == NULL) {
		odp_shm_free(shm_h);
		return NULL;
	}

	return shm;
}

void ofp_set_custom_allocator(void *(*allocator)(const char *name, uint64_t size))
{
	shared_memory_allocator = allocator ? allocator : allocate_shared_memory;
}
