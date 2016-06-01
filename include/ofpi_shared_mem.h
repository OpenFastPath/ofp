/*-
 * Copyright (c) 2014 ENEA Software AB
 * Copyright (c) 2014 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#ifndef __OFP_SHARED_MEM_H__
#define __OFP_SHARED_MEM_H__

#include <odp.h>

void *ofp_shared_memory_alloc(const char *name, uint64_t size);
int ofp_shared_memory_free(const char *name);
void *ofp_shared_memory_lookup(const char *name);

void ofp_set_custom_allocator(void *(*allocator)(const char *name, uint64_t size));

#endif /*__OFP_SHARED_MEM_H__*/
