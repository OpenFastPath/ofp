/* Copyright (c) 2015, ENEA Software AB
 * Copyright (c) 2015, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */
#ifndef __OFPI_IFNET_H__
#define __OFPI_IFNET_H__

#include "api/ofp_ifnet.h"
#include "ofpi_portconf.h"

/* Open a packet IO instance for this ifnet device for the pktin_mode. */
int ofp_pktio_open(struct ofp_ifnet *ifnet, int pktin_mode);
int ofp_pktio_outq_def_set(struct ofp_ifnet *ifnet);
/* Create loop queue */
int ofp_loopq_create(struct ofp_ifnet *ifnet);
/* Set ifnet interface MAC address */
int ofp_mac_set(struct ofp_ifnet *ifnet);
/* Set interface MTU*/
int ofp_mtu_set(struct ofp_ifnet *ifnet);
/* IGMP protocol used for multicasting. */
void ofp_igmp_attach(struct ofp_ifnet *ifnet);
/* Create VIF local input queue */
int ofp_sp_inq_create(struct ofp_ifnet *ifnet);
#endif
