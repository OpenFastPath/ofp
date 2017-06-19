/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 *
 */
#ifndef __OFPI_GRE_H__
#define __OFPI_GRE_H__

enum ofp_return_code ofp_gre_input(odp_packet_t, int);

enum ofp_return_code ofp_output_ipv4_to_gre(odp_packet_t pkt,
					    struct ofp_ifnet *dev_gre,
					    uint16_t vrfid,
					    struct ofp_nh_entry **nh_new);

enum ofp_return_code ofp_output_ipv6_to_gre(odp_packet_t pkt,
					    struct ofp_ifnet *dev_gre,
					    uint16_t vrfid,
					    struct ofp_nh_entry **nh_new);

#endif /*__OFPI_GRE_H__*/
