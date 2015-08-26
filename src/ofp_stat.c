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
#include "ofpi_stat.h"
#include "ofpi_util.h"

#define SHM_NAME_STAT "OfpStatShMem"

typedef struct {
	struct ofp_packet_stat ofp_packet_statistics;
} stat_shm_t;

static __thread stat_shm_t *shm_stat;

unsigned long int ofp_stat_flags = 0;

struct ofp_packet_stat *ofp_get_packet_statistics(void)
{
	if (!shm_stat)
		return NULL;

	return &(shm_stat->ofp_packet_statistics);
}

void ofp_stat_alloc_shared_memory(void)
{
	shm_stat = ofp_shared_memory_alloc(SHM_NAME_STAT, sizeof(*shm_stat));
	if (shm_stat == NULL) {
		OFP_ABORT("Error: %s shared mem alloc failed on core: %u.\n",
			SHM_NAME_STAT, odp_cpu_id());
		exit(EXIT_FAILURE);
	}

	memset(shm_stat, 0, sizeof(*shm_stat));
}

void ofp_stat_free_shared_memory(void)
{
	ofp_shared_memory_free(SHM_NAME_STAT);
	shm_stat = NULL;
}

void ofp_stat_lookup_shared_memory(void)
{
	shm_stat = ofp_shared_memory_lookup(SHM_NAME_STAT);
	if (shm_stat == NULL) {
		OFP_ABORT("Error: %s shared mem lookup failed on core: %u.\n",
			SHM_NAME_STAT, odp_cpu_id());
		exit(EXIT_FAILURE);
	}
}

void ofp_stat_init_global(void)
{
	memset(shm_stat, 0, sizeof(*shm_stat));
}

void ofp_stat_term_global(void)
{
	memset(shm_stat, 0, sizeof(*shm_stat));
}

void ofp_set_stat_flags(unsigned long int flags)
{
	ofp_stat_flags = flags;
}
unsigned long int ofp_get_stat_flags(void)
{
	return ofp_stat_flags;
}
