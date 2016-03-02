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
};
extern __thread struct ofp_tcp_var_mem *shm_tcp;

#define	V_tcb			VNET(shm_tcp->ofp_tcb)
#define	V_tcbinfo		VNET(shm_tcp->ofp_tcbinfo)
