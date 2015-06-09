/* Copyright (c) 2014, Nokia
 * Copyright (c) 2014, ENEA Software AB
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <string.h>

#include <odp.h>

#include "ofpi_log.h"
#include "ofpi_hook.h"

typedef struct {
	ofp_pkt_hook pkt_hook[OFP_HOOK_MAX];
} hook_shm_t;

static __thread hook_shm_t *shm_hook = NULL;

inline ofp_pkt_hook *ofp_get_packet_hooks(void)
{
	if (!shm_hook)
		return NULL;

	return &(shm_hook->pkt_hook[0]);
}

void ofp_hook_alloc_shared_memory(ofp_pkt_hook* pkt_hook_init)
{
	odp_shm_t shm_h;

	shm_h = odp_shm_reserve("OfpHookShMem", sizeof(*shm_hook),
				ODP_CACHE_LINE_SIZE, 0);
	shm_hook = odp_shm_addr(shm_h);

	if (shm_hook == NULL)
		OFP_ABORT("Error: Hook shared mem alloc failed on core: %u.\n",
			  odp_cpu_id());

	memcpy(&shm_hook->pkt_hook[0], pkt_hook_init,
		OFP_HOOK_MAX * sizeof(ofp_pkt_hook));
}

void ofp_hook_lookup_shared_memory(void)
{
	odp_shm_t shm_h;

	shm_h = odp_shm_lookup("OfpHookShMem");
	shm_hook = odp_shm_addr(shm_h);

	if (shm_hook == NULL)
		OFP_ABORT("Error: Hook shared mem lookup failed on core: %u.\n",
			  odp_cpu_id());
}
