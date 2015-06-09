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

typedef struct {
	struct ofp_packet_stat ofp_packet_statistics;
} stat_shm_t;

static __thread stat_shm_t *shm_stat = NULL;

unsigned long int ofp_stat_flags = 0;

struct ofp_packet_stat *ofp_get_packet_statistics(void)
{
	if (!shm_stat)
		return NULL;

	return &(shm_stat->ofp_packet_statistics);
}

void ofp_stat_alloc_shared_memory(void)
{
	odp_shm_t shm_h;

	shm_h = odp_shm_reserve("OfpStatShMem", sizeof(*shm_stat),
				ODP_CACHE_LINE_SIZE, 0);
	shm_stat = odp_shm_addr(shm_h);

	if (shm_stat == NULL)
		OFP_ABORT("Error: Stat shared mem alloc failed on core: %u.\n",
			  odp_cpu_id());

	memset(shm_stat, 0, sizeof(*shm_stat));
}

void ofp_stat_lookup_shared_memory(void)
{
	odp_shm_t shm_h;

	shm_h = odp_shm_lookup("OfpStatShMem");
	shm_stat = odp_shm_addr(shm_h);

	if (shm_stat == NULL)
		OFP_ABORT("Error: Stat shared mem lookup failed on core: %u.\n",
			  odp_cpu_id());
}

void ofp_set_stat_flags(unsigned long int flags)
{
	ofp_stat_flags = flags;
}
unsigned long int ofp_get_stat_flags(void)
{
	return ofp_stat_flags;
}
