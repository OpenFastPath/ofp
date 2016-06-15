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

#include "api/ofp_timer.h"

/*
 * Shared data format
 */
struct ofp_tcp_var_mem {
#ifdef OFP_RSS
	VNET_DEFINE(struct inpcbhead, ofp_tcb[OFP_MAX_NUM_CPU]);
	VNET_DEFINE(struct inpcbinfo, ofp_tcbinfo[OFP_MAX_NUM_CPU]);
	VNET_DEFINE(OFP_TAILQ_HEAD(, tcptw), twq_2msl[OFP_MAX_NUM_CPU]);
	odp_timer_t ofp_tcp_slow_timer[OFP_MAX_NUM_CPU];
#else
	VNET_DEFINE(struct inpcbhead, ofp_tcb);/* queue of active tcpcb's */
	VNET_DEFINE(struct inpcbinfo, ofp_tcbinfo);
	VNET_DEFINE(OFP_TAILQ_HEAD(, tcptw), twq_2msl);
	odp_timer_t ofp_tcp_slow_timer;
#endif

/* Target size of TCP PCB hash tables. Must be a power of two.*/
#define TCBHASHSIZE			1024
	struct inpcbhead	ofp_hashtbl[TCBHASHSIZE];
	struct inpcbporthead	ofp_porthashtbl[TCBHASHSIZE];

#define TCP_SYNCACHE_HASHSIZE		1024
	struct syncache_head	syncache[TCP_SYNCACHE_HASHSIZE];

	VNET_DEFINE(uma_zone_t, tcp_reass_zone);
	VNET_DEFINE(uma_zone_t, tcp_syncache_zone);
	VNET_DEFINE(uma_zone_t, tcpcb_zone);
	VNET_DEFINE(uma_zone_t, tcptw_zone);
	VNET_DEFINE(uma_zone_t, ofp_sack_hole_zone);
};
extern __thread struct ofp_tcp_var_mem *shm_tcp;

#ifdef OFP_RSS
#define	V_tcb			VNET(shm_tcp->ofp_tcb[odp_cpu_id()])
#define	V_tcbinfo		VNET(shm_tcp->ofp_tcbinfo[odp_cpu_id()])
#define	V_twq_2msl		VNET(shm_tcp->twq_2msl[odp_cpu_id()])
#else
#define	V_tcb			VNET(shm_tcp->ofp_tcb)
#define	V_tcbinfo		VNET(shm_tcp->ofp_tcbinfo)
#define	V_twq_2msl		VNET(shm_tcp->twq_2msl)
#endif

#define	V_tcp_reass_zone	VNET(shm_tcp->tcp_reass_zone)
#define	V_tcpcb_zone		VNET(shm_tcp->tcpcb_zone)
#define	V_tcptw_zone		VNET(shm_tcp->tcptw_zone)
#define	V_tcp_syncache_zone	VNET(shm_tcp->tcp_syncache_zone)
#define	V_sack_hole_zone	VNET(shm_tcp->ofp_sack_hole_zone)
