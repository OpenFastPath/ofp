/* Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _OFPI_IP_H_
#define _OFPI_IP_H_

#include <odp_api.h>
#include "api/ofp_ip.h"
#include "api/ofp_log.h"
#include "ofpi_shared_mem.h"

#define SHM_NAME_IP "OfpIpShMem"

struct ofp_global_ip_state {
	union {
		odp_atomic_u32_t ip_id;
		uint8_t padding[ODP_CACHE_LINE_SIZE];
	} ODP_ALIGNED_CACHE;
};

extern __thread struct ofp_global_ip_state *ofp_ip_shm;

static inline void ofp_ip_id_assign(struct ofp_ip *ip)
{
	uint16_t id = odp_atomic_fetch_inc_u32(&ofp_ip_shm->ip_id) & 0xffff;
	/*
	 * The byte swap is not necessary but it produces nicer packet dumps.
	 */
	ip->ip_id = odp_cpu_to_be_16(id);
}

static inline int ofp_ip_init_global(void)
{
	ofp_ip_shm = ofp_shared_memory_alloc(SHM_NAME_IP, sizeof(*ofp_ip_shm));
	if (ofp_ip_shm == NULL) {
		OFP_ERR("ofp_shared_memory_alloc(\"" SHM_NAME_IP "\") failed");
		return -1;
	}
	odp_atomic_init_u32(&ofp_ip_shm->ip_id, 0);
	return 0;
}

static inline int ofp_ip_init_local(void)
{
	ofp_ip_shm = ofp_shared_memory_lookup(SHM_NAME_IP);
	if (ofp_ip_shm == NULL) {
		OFP_ERR("ofp_shared_memory_lookup(\"" SHM_NAME_IP "\") failed");
		return -1;
	}
	return 0;
}

static inline int ofp_ip_term_local(void)
{
	ofp_ip_shm = NULL;
	return 0;
}

static inline int ofp_ip_term_global(void)
{
	if (ofp_shared_memory_free(SHM_NAME_IP)) {
		OFP_ERR("ofp_shared_memory_free(\"" SHM_NAME_IP "\") failed");
		return -1;
	}
	return 0;
}

/*
 * Definitions for IP precedence (also in ip_tos) (hopefully unused).
 */
#define	IPTOS_PREC_NETCONTROL		0xe0
#define	IPTOS_PREC_INTERNETCONTROL	0xc0
#define	IPTOS_PREC_CRITIC_ECP		0xa0
#define	IPTOS_PREC_FLASHOVERRIDE	0x80
#define	IPTOS_PREC_FLASH		0x60
#define	IPTOS_PREC_IMMEDIATE		0x40
#define	IPTOS_PREC_PRIORITY		0x20
#define	IPTOS_PREC_ROUTINE		0x00

#endif
