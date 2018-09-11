/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 *
 */

#include <odp_api.h>
#include "api/ofp_types.h"
#include "api/ofp_route_arp.h"
#include "api/ofp_ip6.h"
#include "ofpi_pkt_processing.h"
#include "ofpi_in.h"
#include "ofpi_ip.h"
#include "ofpi_gre.h"
#include "ofpi_if_gre.h"
#include "ofpi_if_vlan.h"
#include "ofpi_ethernet.h"
#include "ofpi_portconf.h"
#include "ofpi_log.h"
#include "ofpi_hook.h"
#include "ofpi_util.h"
#include "ofpi_ipsec.h"

enum ofp_return_code ofp_gre_input(odp_packet_t *pkt, int off0)
{
	int res;
	struct ofp_ifnet *dev, *dev_in;
	struct ofp_ether_header *eth_hdr;
	struct ofp_ether_vlan_header *eth_hdr_vlan;
	struct ofp_greip *greip;
	uint32_t grelen;
	uint8_t eth_d_addr[OFP_ETHER_ADDR_LEN];
	uint8_t eth_s_addr[OFP_ETHER_ADDR_LEN];
	uint16_t ptype, offset, eth_hdr_len = OFP_ETHER_HDR_LEN;

	(void)off0;

	dev = odp_packet_user_ptr(*pkt);
	greip = odp_packet_l3_ptr(*pkt, NULL);

	/* Validate tunnel */
	dev_in = ofp_get_ifnet_by_tunnel(greip->gi_dst.s_addr,
					   greip->gi_src.s_addr, dev->vrf);
	if (dev_in == NULL) {
		OFP_HOOK(OFP_HOOK_GRE, *pkt, NULL, &res);
		return res;
	}

	/* save eth hdr data */
	if (dev->vlan) {
		eth_hdr_vlan = odp_packet_l2_ptr(*pkt, NULL);
		memcpy(eth_d_addr, eth_hdr_vlan->evl_dhost,
		       OFP_ETHER_ADDR_LEN);
		memcpy(eth_s_addr, eth_hdr_vlan->evl_shost,
		       OFP_ETHER_ADDR_LEN);
		eth_hdr_len += OFP_ETHER_VLAN_ENCAP_LEN;
	} else {
		eth_hdr = odp_packet_l2_ptr(*pkt, NULL);
		memcpy(eth_d_addr, eth_hdr->ether_dhost, OFP_ETHER_ADDR_LEN);
		memcpy(eth_s_addr, eth_hdr->ether_shost, OFP_ETHER_ADDR_LEN);
	}

	/* Process gre header */
	ptype = greip->gi_ptype;

	grelen = 4;
	if ((greip->gi_g.flags & OFP_GRE_CP) ||
		(greip->gi_g.flags & OFP_GRE_RP))
		grelen += 4;
	if (greip->gi_g.flags & OFP_GRE_KP)
		grelen += 4;
	if (greip->gi_g.flags & OFP_GRE_SP)
		grelen += 4;

	/* remove outerIP and GRE header */
	offset = odp_packet_l3_offset(*pkt) + (greip->gi_i.ip_hl << 2) + grelen -
		eth_hdr_len;
	if (odp_packet_pull_head(*pkt, offset) == NULL) {
		OFP_ERR("odp_packet_pull_head failed");
		return OFP_PKT_DROP;
	}
	odp_packet_l2_offset_set(*pkt, 0);
	odp_packet_l3_offset_set(*pkt, eth_hdr_len);

	/* Add eth header */
	if (dev->vlan) {
		eth_hdr_vlan = odp_packet_l2_ptr(*pkt, NULL);
		memcpy(eth_hdr_vlan->evl_dhost, eth_d_addr,
		       OFP_ETHER_ADDR_LEN);
		memcpy(eth_hdr_vlan->evl_dhost, eth_s_addr,
		       OFP_ETHER_ADDR_LEN);
		eth_hdr_vlan->evl_encap_proto = odp_cpu_to_be_16(0x8100);
		eth_hdr_vlan->evl_tag = odp_cpu_to_be_16(dev->vlan);
		eth_hdr_vlan->evl_proto = ptype;
	} else {
		eth_hdr = odp_packet_l2_ptr(*pkt, NULL);
		memcpy(eth_hdr->ether_dhost, eth_d_addr, OFP_ETHER_ADDR_LEN);
		memcpy(eth_hdr->ether_shost, eth_s_addr, OFP_ETHER_ADDR_LEN);
		eth_hdr->ether_type = ptype;
	}

	odp_packet_user_ptr_set(*pkt, dev_in);
	ofp_ipsec_flags_set(*pkt, 0);

	switch (odp_be_to_cpu_16(ptype)) {
	case OFP_ETHERTYPE_IP:
		return ofp_ipv4_processing(pkt);
#ifdef INET6
	case OFP_ETHERTYPE_IPV6:
		return ofp_ipv6_processing(pkt);
#endif /* INET6 */
	default:
		return OFP_PKT_CONTINUE;
	}

	return OFP_PKT_CONTINUE;
}

enum ofp_return_code ofp_output_ipv4_to_gre(odp_packet_t pkt,
					    struct ofp_ifnet *dev_gre)
{
	struct ofp_ip	*ip;
	struct ofp_greip *greip;
	uint8_t	l2_size = 0;
	int32_t	offset;

	ip = odp_packet_l3_ptr(pkt, NULL);

	/* Remove eth header, prepend gre + ip */
	if (odp_packet_has_l2(pkt))
		l2_size = odp_packet_l3_offset(pkt) - odp_packet_l2_offset(pkt);

	offset = sizeof(*greip) - l2_size;
	if (offset >= 0)
		greip = odp_packet_push_head(pkt, offset);
	else
		greip = odp_packet_pull_head(pkt, -offset);

	odp_packet_has_l2_set(pkt, 0);
	odp_packet_l3_offset_set(pkt, 0);

	if (!greip)
		return OFP_PKT_DROP;

	greip->gi_flags = 0;
	greip->gi_ptype = odp_cpu_to_be_16(OFP_GREPROTO_IP);

	greip->gi_i.ip_hl = 5;
	greip->gi_i.ip_v = OFP_IPVERSION;
	greip->gi_i.ip_tos = ip->ip_tos;
	greip->gi_i.ip_len =
		odp_cpu_to_be_16(odp_be_to_cpu_16(ip->ip_len) +
				 sizeof(*greip));
	greip->gi_i.ip_off = 0;
	greip->gi_i.ip_ttl = ip->ip_ttl;
	greip->gi_i.ip_p = OFP_IPPROTO_GRE;
	greip->gi_i.ip_sum = 0;
	greip->gi_i.ip_src.s_addr = dev_gre->ip_local;
	greip->gi_i.ip_dst.s_addr = dev_gre->ip_remote;

	return ofp_ip_output_recurse(pkt, NULL);
}

#ifdef INET6
enum ofp_return_code ofp_output_ipv6_to_gre(odp_packet_t pkt,
					    struct ofp_ifnet *dev_gre)
{
	struct ofp_ip6_hdr *ip6;
	struct ofp_greip *greip;
	uint8_t	l2_size = 0;
	int32_t	offset;

	ip6 = odp_packet_l3_ptr(pkt, NULL);

	/* Remove eth header, prepend gre + ip */
	if (odp_packet_has_l2(pkt))
		l2_size = odp_packet_l3_offset(pkt) - odp_packet_l2_offset(pkt);

	offset = sizeof(*greip) - l2_size;
	if (offset >= 0)
		greip = odp_packet_push_head(pkt, offset);
	else
		greip = odp_packet_pull_head(pkt, -offset);

	odp_packet_has_l2_set(pkt, 0);
	odp_packet_l3_offset_set(pkt, 0);

	if (!greip)
		return OFP_PKT_DROP;

	greip->gi_flags = 0;
	greip->gi_ptype = odp_cpu_to_be_16(OFP_ETHERTYPE_IPV6);

	greip->gi_i.ip_hl = 5;
	greip->gi_i.ip_v = OFP_IPVERSION;
	greip->gi_i.ip_tos = 0;
	greip->gi_i.ip_len = odp_cpu_to_be_16(
		odp_be_to_cpu_16(ip6->ofp_ip6_plen) +
		sizeof(*ip6) + sizeof(*greip));
	greip->gi_i.ip_off = 0;
	greip->gi_i.ip_ttl = ip6->ofp_ip6_hlim;
	greip->gi_i.ip_p = OFP_IPPROTO_GRE;
	greip->gi_i.ip_sum = 0;
	greip->gi_i.ip_src.s_addr = dev_gre->ip_local;
	greip->gi_i.ip_dst.s_addr = dev_gre->ip_remote;

	odp_packet_has_ipv6_set(pkt, 0);
	odp_packet_has_ipv4_set(pkt, 1);

	return ofp_ip_output_recurse(pkt, NULL);
}
#endif
