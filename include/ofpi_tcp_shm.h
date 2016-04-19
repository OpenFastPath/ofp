/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#pragma once

#include "ofpi_in_pcb.h"
#include "ofpi_callout.h"
#include "ofpi_tcp_var.h"
#include "ofpi_tcp_syncache.h"

/*
 * Shared data format
 */
struct ofp_tcp_var_mem {
	VNET_DEFINE(struct inpcbhead, ofp_tcb);/* queue of active tcpcb's */
	VNET_DEFINE(struct inpcbinfo, ofp_tcbinfo);
	VNET_DEFINE(OFP_TAILQ_HEAD(, tcptw), twq_2msl);

/* Target size of TCP PCB hash tables. Must be a power of two.*/
#define TCBHASHSIZE			512
	struct inpcbhead	ofp_hashtbl[TCBHASHSIZE];
	struct inpcbporthead	ofp_porthashtbl[TCBHASHSIZE];

#define TCP_SYNCACHE_HASHSIZE		512
	struct syncache_head	syncache[TCP_SYNCACHE_HASHSIZE];

	VNET_DEFINE(uma_zone_t, tcp_reass_zone);
	VNET_DEFINE(uma_zone_t, tcp_syncache_zone);
	VNET_DEFINE(uma_zone_t, tcpcb_zone);
	VNET_DEFINE(uma_zone_t, tcptw_zone);
	VNET_DEFINE(uma_zone_t, ofp_sack_hole_zone);
};
extern __thread struct ofp_tcp_var_mem *shm_tcp;

#define	V_tcb			VNET(shm_tcp->ofp_tcb)
#define	V_tcbinfo		VNET(shm_tcp->ofp_tcbinfo)
#define	V_tcp_reass_zone	VNET(shm_tcp->tcp_reass_zone)
#define	V_tcpcb_zone		VNET(shm_tcp->tcpcb_zone)
#define	V_tcptw_zone		VNET(shm_tcp->tcptw_zone)
#define	V_twq_2msl		VNET(shm_tcp->twq_2msl)
#define	V_tcp_syncache_zone	VNET(shm_tcp->tcp_syncache_zone)
#define	V_sack_hole_zone	VNET(shm_tcp->ofp_sack_hole_zone)
