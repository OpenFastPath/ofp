/* Copyright (c) 2014, Nokia
 * Copyright (c) 2014, ENEA Software AB
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <string.h>

#include <odp.h>

#include "ofpi_config.h"
#include "ofpi_log.h"
#include "ofpi_stat.h"
#include "ofpi_util.h"

#define SHM_NAME_STAT "OfpStatShMem"


typedef struct {
	struct ofp_packet_stat ofp_packet_statistics;
	struct ofp_perf_stat ofp_perf_stat;
} stat_shm_t;

static __thread stat_shm_t *shm_stat;

unsigned long int ofp_stat_flags = 0;

struct ofp_packet_stat *ofp_get_packet_statistics(void)
{
	if (!shm_stat)
		return NULL;

	return &shm_stat->ofp_packet_statistics;
}

struct ofp_perf_stat *ofp_get_perf_statistics(void)
{
	if (!shm_stat)
		return NULL;

	return &shm_stat->ofp_perf_stat;
}

#define PROBES 3UL
static void ofp_perf_tmo(void *arg)
{
	uint64_t pps, value = 0;
	int core;
	(void)arg;

	if (ofp_stat_flags & OFP_STAT_COMPUTE_PERF)
		ofp_timer_start(US_PER_SEC/PROBES, ofp_perf_tmo, NULL, 0);

	odp_mb_release();

	for (core = 0; core < odp_cpu_count(); core++)
		value += shm_stat->ofp_packet_statistics.per_core[core].rx_fp;

	if (value >= shm_stat->ofp_perf_stat.rx_prev_sum)
		pps = value - shm_stat->ofp_perf_stat.rx_prev_sum;
	else
		pps = (uint64_t)(-1) - shm_stat->ofp_perf_stat.rx_prev_sum +
			value;

	shm_stat->ofp_perf_stat.rx_fp_pps =
		(shm_stat->ofp_perf_stat.rx_fp_pps + pps * PROBES) / 2;

	shm_stat->ofp_perf_stat.rx_prev_sum = value;
}

static void ofp_start_perf_stat(void)
{
	ofp_timer_start(US_PER_SEC/PROBES, ofp_perf_tmo, NULL, 0);
}

static int ofp_stat_alloc_shared_memory(void)
{
	shm_stat = ofp_shared_memory_alloc(SHM_NAME_STAT, sizeof(*shm_stat));
	if (shm_stat == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}
	return 0;
}

static int ofp_stat_free_shared_memory(void)
{
	int rc = 0;

	if (ofp_shared_memory_free(SHM_NAME_STAT)) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}
	shm_stat = NULL;

	return rc;
}

int ofp_stat_lookup_shared_memory(void)
{
	shm_stat = ofp_shared_memory_lookup(SHM_NAME_STAT);
	if (shm_stat == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}
	return 0;
}

int ofp_stat_init_global(void)
{
	HANDLE_ERROR(ofp_stat_alloc_shared_memory());

	memset(shm_stat, 0, sizeof(*shm_stat));

	return 0;
}

int ofp_stat_term_global(void)
{
	int rc = 0;

	if (ofp_stat_lookup_shared_memory())
		return -1;

	CHECK_ERROR(ofp_stat_free_shared_memory(), rc);

	return rc;
}

void ofp_set_stat_flags(unsigned long int flags)
{
	unsigned long int old_flags = ofp_stat_flags;

	ofp_stat_flags = flags;

	if ((!(old_flags & OFP_STAT_COMPUTE_PERF)) &&
		ofp_stat_flags & OFP_STAT_COMPUTE_PERF)
		ofp_start_perf_stat();
}
unsigned long int ofp_get_stat_flags(void)
{
	return ofp_stat_flags;
}
