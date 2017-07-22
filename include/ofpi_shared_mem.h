/*-
 * Copyright (c) 2014 ENEA Software AB
 * Copyright (c) 2014, 2017 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#ifndef __OFP_SHARED_MEM_H__
#define __OFP_SHARED_MEM_H__

#include <odp.h>

/*
 * Raw allocator that maps to ODP shared memory allocator or to a
 * custom allocator
 */

void *ofp_shared_memory_alloc_raw(const char *name, uint64_t size);
int ofp_shared_memory_free_raw(const char *name);
void *ofp_shared_memory_lookup_raw(const char *name);

void ofp_set_custom_allocator(void *(*allocator)(const char *name, uint64_t size));

/*
 * This is a shared memory allocator that either maps directly to the
 * shared memory allocator in ODP or tries to combine the allocation
 * with other allocations into one common shared memory block. The latter
 * is done only for those shared memory blocks that have been preallocated
 * during early initialization.
 *
 * In the preallocation phase clients can tell what kind of shared
 * memory blocks they are going to need later. Single common memory
 * block is allocated once the preallocation phase has finished and
 * the total amount of required memory is known. After that clients
 * can do the actual allocations.
 *
 * Preallocation is not mandatory. The allocator will fall back to
 * the normal allocator if preallocation is not done or does not
 * succeed.
 *
 * Allocations done before finishing the preallocation phase should
 * not use preallocation.
 */

int ofp_shared_memory_init_global(void);
int ofp_shared_memory_init_local(void);
int ofp_shared_memory_term_global(void);

/*
 * Inform the allocator about future memory need. The indicated amount
 * of memory will be preallocated.
 */
void ofp_shared_memory_prealloc(const char *name, uint64_t size);

/*
 * Inform the allocator that preallocations have been done.
 */
int ofp_shared_memory_prealloc_finish(void);

/*
 * Allocate a shared memory block. The returned memory is aligned to
 * a cache line boundary.
 *
 * If 'name' matches an earlier preallocation and 'size' does not
 * exceed the preallocation, memory is allocated from the common
 * shared memory block. Otherwise a separate block is allocated.
 */
void *ofp_shared_memory_alloc(const char *name, uint64_t size);

/*
 * Get a pointer to a previously allocated shared memory block
 */
void *ofp_shared_memory_lookup(const char *name);

/*
 * Free a memory block before OFP shutdown.
 */
int ofp_shared_memory_free(const char *name);

#endif /*__OFP_SHARED_MEM_H__*/
