/* Copyright (c) 2015, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _OFPI_IF_VXLAN_H
#define _OFPI_IF_VXLAN_H

#define VXLAN_PORT 4789
#define LINUX_VXLAN_PORT 8472

struct ofp_vxlan_h {
	uint32_t flags;
	uint32_t vni;
} __attribute__((packed));


struct ofp_vxlan_udp_ip {
	struct ofp_ip		ip;
	struct ofp_udphdr	udp;
	struct ofp_vxlan_h	vxlan;
} __attribute__((packed));

#endif
