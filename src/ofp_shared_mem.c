/* Copyright (c) 2015, ENEA Software AB
 * Copyright (c) 2015, 2017 Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <string.h>
#include <inttypes.h>
#include "ofpi_shared_mem.h"
#include "ofpi_odp_compat.h"
#include "ofp_log.h"

#define SHM_NAME_COMMON "OfpCommon"
#define SHM_NAME_INTERNAL "OfpShmInternal"
#define OFP_SHM_BLOCKS_MAX 100  /* Maximum number of preallocations stored */
#define OFP_SHM_NAME_LEN 60     /* Maximum shared memory name lenght */

/*
 * Tests are broken, we cannot yet emit debug logs here.
 */
#if 0
#define OFP_DBG_SHM OFP_DBG
#else
#define OFP_DBG_SHM(ftm, ...) do {} while (0)
#endif

/*
 * Information about a (pre)allocated shared memory block
 */
struct ofp_shm_block {
	int valid : 1;      /* This entry represents a valid (pre)allocation */
	int allocated : 1;  /* The block has been allocated */
	uint64_t size;      /* Actual size of the block */
	uint64_t offset;    /* Offset of the block from the start of the SHM */
	char name[OFP_SHM_NAME_LEN];
};

static __thread struct ofp_shm_blocks {
	int next_free;            /* next free entry in the block array */
	struct ofp_shm_block block[OFP_SHM_BLOCKS_MAX];
	uint8_t *shared_memory;	  /* Common SHM area for all blocks */
	uint64_t total_size;      /* Total size of the common area */
} *shm;

static void *allocate_shared_memory(const char *name, uint64_t size)
{
	odp_shm_t shm_h;
	void *shm;

	shm_h = odp_shm_reserve(name, size, ODP_CACHE_LINE_SIZE,
				OFP_SHM_SINGLE_VA);
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

void *ofp_shared_memory_alloc_raw(const char *name, uint64_t size)
{
	return shared_memory_allocator(name, size);
}

int ofp_shared_memory_free_raw(const char *name)
{
	odp_shm_t shm_h;

	shm_h = odp_shm_lookup(name);
	if (shm_h == ODP_SHM_INVALID)
		return -1;

	odp_shm_free(shm_h);
	return 0;
}

void *ofp_shared_memory_lookup_raw(const char *name)
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

int ofp_shared_memory_init_global(void)
{
	shm = ofp_shared_memory_alloc_raw(SHM_NAME_INTERNAL, sizeof(*shm));
	if (!shm) {
		OFP_ERR("Shared memory allocation failed (name: %s)",
			SHM_NAME_INTERNAL);
		return 1;
	}
	memset(shm, 0, sizeof(*shm));
	return 0;
}

int ofp_shared_memory_init_local(void)
{
	shm = ofp_shared_memory_lookup_raw(SHM_NAME_INTERNAL);
	if (!shm) {
		OFP_ERR("Shared memory lookup failed (name: %s)",
			SHM_NAME_INTERNAL);
		return -1;
	}
	return 0;
}

int ofp_shared_memory_term_global(void)
{
	int n;
	int ret = 0;

	for (n = 0; n < OFP_SHM_BLOCKS_MAX; n++) {
		if (shm && shm->block[n].valid && shm->block[n].allocated) {
			OFP_ERR("Shared memory block \"%s\" not freed,"
				"cannot free common shared memory",
				shm->block[n].name);
			return -1;
		}
	}

	if (ofp_shared_memory_free_raw(SHM_NAME_COMMON)) {
		OFP_ERR("Freeing shared memory failed (name: %s)",
			SHM_NAME_COMMON);
		ret = -1;
	}

	if (ofp_shared_memory_free_raw(SHM_NAME_INTERNAL)) {
		OFP_ERR("Freeing shared memory failed (name: %s)",
			SHM_NAME_INTERNAL);
		ret = -1;
	}
	shm = NULL;
	return ret;
}

static struct ofp_shm_block *ofp_shm_block_find(const char *name)
{
	int n;

	for (n = 0; n < OFP_SHM_BLOCKS_MAX; n++)
		if (shm->block[n].valid && !strcmp(shm->block[n].name, name))
			return &shm->block[n];
	return NULL;
}

void ofp_shared_memory_prealloc(const char *name, uint64_t size)
{
	struct ofp_shm_block *block;

	OFP_DBG_SHM("Shared memory preallocation: name: %s, size: %" PRIu64,
		    name, size);

	if (!shm) {
		OFP_ERR("Shared memory preallocated before initialization");
		return;
	}
	if (shm->shared_memory) {
		OFP_WARN("Shared memory preallocated too late");
		return;
	}
	if (ofp_shm_block_find(name) != NULL) {
		OFP_ERR("Duplicate shared memory preallocation (name: %s)",
			name);
		return;
	}
	if (shm->next_free >= OFP_SHM_BLOCKS_MAX) {
		OFP_WARN("Shared memory preallocation table full.");
		return;
	}
	block = &shm->block[shm->next_free++];
	block->valid = 1;
	block->allocated = 0;
	strncpy(block->name, name, sizeof(block->name));
	block->name[sizeof(block->name) - 1] = 0;

	/* Round up to a multiple of cache line size */
	block->size = (size + ODP_CACHE_LINE_SIZE - 1) / ODP_CACHE_LINE_SIZE;
	block->size = block->size * ODP_CACHE_LINE_SIZE;

	block->offset = shm->total_size;
	shm->total_size += block->size;

	OFP_DBG_SHM("Shared memory blocks preallocated so far: %d",
		    shm->next_free);
	OFP_DBG_SHM("Shared memory bytes preallocated so far: %" PRIu64,
		    shm->total_size);
}

int ofp_shared_memory_prealloc_finish(void)
{
	shm->shared_memory = allocate_shared_memory(SHM_NAME_COMMON,
						    shm->total_size);
	if (!shm->shared_memory) {
		OFP_ERR("Allocation of shared memory failed:"
			"name: %s, size: %" PRIu64,
			SHM_NAME_COMMON, shm->total_size);
		return -1;
	}
	return 0;
}

static void *preallocated_alloc(const char *name, uint64_t size)
{
	struct ofp_shm_block *block;

	if (!shm) {
		OFP_DBG_SHM("Not initialized");
		return NULL;
	}

	block = ofp_shm_block_find(name);
	if (!block) {
		OFP_DBG_SHM("Not found in the preallocated memory");
		return NULL;
	}
	if (!shm->shared_memory) {
		OFP_ERR("Allocation of preallocated shared memory before "
			"preallocation phase has finished. Name: %s", name);
		return NULL;
	}
	if (block->allocated) {
		OFP_ERR("Shared memory (name: %s) already allocated", name);
		return NULL;
	}
	if (block->size < size) {
		OFP_WARN("Shared memory allocation (name: %s) larger than "
			 "the corresponding preallocation: "
			 "(%" PRIu64 " > %" PRIu64 ")",
			name, size, block->size);
		return NULL;
	}
	block->allocated = 1;

	return &shm->shared_memory[block->offset];
}

static void *preallocated_lookup(const char *name)
{
	struct ofp_shm_block *block;

	if (!shm) {
		OFP_DBG_SHM("Not initialized");
		return NULL;
	}

	block = ofp_shm_block_find(name);
	if (!block || !block->allocated) {
		return NULL;
	}
	return &shm->shared_memory[block->offset];
}

static int preallocated_free(const char *name)
{
	struct ofp_shm_block *block;

	if (!shm) {
		OFP_DBG_SHM("Not initialized");
		return -1;
	}

	block = ofp_shm_block_find(name);

	if (!block) {
		OFP_DBG_SHM("Not found in the preallocated memory");
		return -1;
	}
	if (!block->allocated) {
		OFP_DBG_SHM("Not allocated in the preallocated memory");
		return -1;
	}
	block->allocated = 0;
	return 0;
}

void *ofp_shared_memory_alloc(const char *name, uint64_t size)
{
	void *ret;

	OFP_DBG_SHM("Shared memory allocation: name: %s, size: %" PRIu64,
		name, size);

	ret = preallocated_alloc(name, size);
	if (!ret) {
		OFP_DBG_SHM("Falling back to raw allocator");
		ret = ofp_shared_memory_alloc_raw(name, size);
	}

	if (!ret)
		OFP_ERR("Shared memory allocation failed: "
			"name: %s, size: %" PRIu64,
			name, size);
	return ret;
}

void *ofp_shared_memory_lookup(const char *name)
{
	void *ret;

	OFP_DBG_SHM("Shared memory lookup: name: %s", name);

	ret = preallocated_lookup(name);
	if (!ret) {
		OFP_DBG_SHM("Falling back to raw allocator");
		ret = ofp_shared_memory_lookup_raw(name);
	}

	if (!ret)
		OFP_ERR("Shared memory lookup failed: name: %s", name);
	return ret;
}

int ofp_shared_memory_free(const char *name)
{
	int ret;

	OFP_DBG_SHM("Shared memory free: name: %s", name);

	ret = preallocated_free(name);
	if (ret) {
		OFP_DBG_SHM("Falling back to raw allocator");
		ret = ofp_shared_memory_free_raw(name);
	}

	if (ret)
		OFP_ERR("Freeing shared memory failed: name: %s", name);
	return ret;
}
