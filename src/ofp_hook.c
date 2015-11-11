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
#include "ofpi_util.h"

#define SHM_NAME_HOOK "OfpHookShMem"

typedef struct {
	ofp_pkt_hook pkt_hook[OFP_HOOK_MAX];
} hook_shm_t;

static __thread hook_shm_t *shm_hook;

ofp_pkt_hook *ofp_get_packet_hooks(void)
{
	if (!shm_hook)
		return NULL;

	return &(shm_hook->pkt_hook[0]);
}

static int ofp_hook_alloc_shared_memory(void)
{
	shm_hook = ofp_shared_memory_alloc(SHM_NAME_HOOK, sizeof(*shm_hook));
	if (shm_hook == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}
	return 0;
}

static int ofp_hook_free_shared_memory(void)
{
	int rc = 0;

	if (ofp_shared_memory_free(SHM_NAME_HOOK) == -1) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}
	shm_hook = NULL;
	return rc;
}

int ofp_hook_lookup_shared_memory(void)
{
	shm_hook = ofp_shared_memory_lookup(SHM_NAME_HOOK);
	if (shm_hook == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}
	return 0;
}


int ofp_hook_init_global(ofp_pkt_hook *pkt_hook_init)
{
	HANDLE_ERROR(ofp_hook_alloc_shared_memory());

	memcpy(&shm_hook->pkt_hook[0], pkt_hook_init,
		OFP_HOOK_MAX * sizeof(ofp_pkt_hook));
	return 0;
}

int ofp_hook_term_global(void)
{
	int rc = 0;

	if (ofp_hook_lookup_shared_memory())
		return -1;

	CHECK_ERROR(ofp_hook_free_shared_memory(), rc);

	return rc;
}
