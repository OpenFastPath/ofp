/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 *
 */

#include "ofpi.h"
#include "ofpi_ip6.h"
#include "ofpi_icmp6.h"
#include "ofpi_log.h"
#include "ofpi_util.h"
#include "ofpi_protosw.h"
#include "ofpi_route.h"
#include "ofpi_pkt_processing.h" /* send_pkt_out */


void ofp_nd6_ns_input(odp_packet_t m, int off, int icmp6len)
{
	struct ofp_ether_header *eth;
	struct ofp_ip6_hdr *ip6;
	struct ofp_icmp6_hdr *icmp6;
	struct ofp_ifnet *ifp;

	(void)icmp6len;

	ifp = odp_packet_user_ptr(m);
	eth = (struct ofp_ether_header *) odp_packet_l2_ptr(m, NULL);
	ip6 = (struct ofp_ip6_hdr *)odp_packet_l3_ptr(m, NULL);
	icmp6 = (struct ofp_icmp6_hdr *)((uint8_t *)ip6 + off);

	if (icmp6->ofp_icmp6_data8[20] == OFP_ND_OPT_SOURCE_LINKADDR &&
		!OFP_IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src) &&
		!OFP_IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_src)) {
		ofp_set_route6_params(OFP_ROUTE6_ADD, 0 /*vrf*/, ifp->vlan,
				      ifp->port, ip6->ip6_src.ofp_s6_addr,
				      128 /*masklen*/,
				      ofp_in6addr_any.ofp_s6_addr,
				      OFP_RTF_HOST);

		ofp_add_mac6(ifp,
			&ip6->ip6_src.ofp_s6_addr[0],
			(uint8_t *)&eth->ether_shost);
	}
}

enum ofp_return_code ofp_nd6_ns_output(struct ofp_ifnet *dev,
	uint8_t *daddr6, uint8_t *taddr6)
{
	size_t size = 0;
	size_t iter = 0;
	struct ofp_ether_header *e1;
	struct ofp_ether_vlan_header *e2;
	struct ofp_ip6_hdr *ip6hdr;
	struct ofp_icmp6_hdr *icmp;
	odp_packet_t pkt;

	if (dev->vlan)
		size = sizeof(struct ofp_ether_vlan_header);
	else
		size = sizeof(struct ofp_ether_header);

	size += sizeof(struct ofp_ip6_hdr) + sizeof(struct ofp_icmp6_hdr) +
		16 /*target addr*/ + 8; /* option*/

	pkt = odp_packet_alloc(ofp_packet_pool, size);
	if (pkt == ODP_PACKET_INVALID)
		return OFP_PKT_DROP;

	odp_packet_has_eth_set(pkt, 1);
	odp_packet_l2_offset_set(pkt, iter);

	if (dev->vlan) {
		e2 = (struct ofp_ether_vlan_header *)odp_packet_l2_ptr(pkt,
			NULL);
		iter += sizeof(*e2);

		memset(e2->evl_dhost, 0xff, OFP_ETHER_ADDR_LEN);
		memcpy(e2->evl_shost, dev->mac, OFP_ETHER_ADDR_LEN);

		e2->evl_encap_proto = odp_cpu_to_be_16(OFP_ETHERTYPE_VLAN);
		e2->evl_tag = odp_cpu_to_be_16(dev->vlan);
		e2->evl_proto = odp_cpu_to_be_16(OFP_ETHERTYPE_IPV6);
	} else {
		e1 = (struct ofp_ether_header *)odp_packet_l2_ptr(pkt, NULL);
		iter += sizeof(*e1);

		memset(e1->ether_dhost, 0xff, OFP_ETHER_ADDR_LEN);
		memcpy(e1->ether_shost, dev->mac, OFP_ETHER_ADDR_LEN);
		e1->ether_type = odp_cpu_to_be_16(OFP_ETHERTYPE_IPV6);
	}
	odp_packet_l3_offset_set(pkt, iter);
	ip6hdr = (struct ofp_ip6_hdr *)odp_packet_l3_ptr(pkt, NULL);
	iter += sizeof(*ip6hdr);

	ip6hdr->ofp_ip6_flow = 0;
	ip6hdr->ofp_ip6_vfc = OFP_IPV6_VERSION;
	ip6hdr->ofp_ip6_plen = odp_cpu_to_be_16(32);
		/*sizeof(*icmp) + sizeof taddr + 8*/

	/* for checksum calculation */
	ip6hdr->ofp_ip6_nxt = 0;
	ip6hdr->ofp_ip6_hlim = OFP_IPPROTO_ICMPV6;
	/* XXX should be multicast address*/
	memcpy(ip6hdr->ip6_src.ofp_s6_addr, dev->ip6_addr, 16);
	if (ofp_ip6_is_set(daddr6))
		memcpy(ip6hdr->ip6_dst.ofp_s6_addr, daddr6, 16);
	else {
		/* Solicited-node multicast address */
		ip6hdr->ip6_dst.ofp_s6_addr16[0] = OFP_IPV6_ADDR_INT16_MLL;
		ip6hdr->ip6_dst.ofp_s6_addr16[1] = 0;
		ip6hdr->ip6_dst.ofp_s6_addr32[1] = 0;
		ip6hdr->ip6_dst.ofp_s6_addr32[2] = OFP_IPV6_ADDR_INT32_ONE;
		ip6hdr->ip6_dst.ofp_s6_addr32[3] = *((uint32_t *)taddr6 + 3);
		ip6hdr->ip6_dst.ofp_s6_addr[12] = 0xff;
	}

	odp_packet_l4_offset_set(pkt, iter);
	icmp = (struct ofp_icmp6_hdr *)odp_packet_l4_ptr(pkt, NULL);
	iter += sizeof(*icmp) + 8 /* option */;

	icmp->icmp6_type = OFP_ND_NEIGHBOR_SOLICIT;
	icmp->icmp6_code = 0;
	icmp->icmp6_cksum = 0;
	icmp->ofp_icmp6_data32[0] = 0; /* Reserved */

	memcpy(&icmp->ofp_icmp6_data8[4], taddr6, 16);

	/* Option: Source link-layer address */
	icmp->ofp_icmp6_data8[20] = OFP_ND_OPT_SOURCE_LINKADDR;
	icmp->ofp_icmp6_data8[21] = 1; /* 8 octets */
	memcpy(&icmp->ofp_icmp6_data8[22], dev->mac, 6);

	icmp->icmp6_cksum =
		ofp_cksum_buffer((uint16_t *)&ip6hdr->ofp_ip6_plen, 68);

	ip6hdr->ofp_ip6_nxt = OFP_IPPROTO_ICMPV6;
	ip6hdr->ofp_ip6_hlim = 255;

	if (send_pkt_out(dev, pkt) == OFP_PKT_DROP) {
		OFP_ERR("Drop packet");
		odp_packet_free(pkt);
		return OFP_PKT_DROP;
	}

	return OFP_PKT_PROCESSED;
}

void ofp_nd6_na_input(odp_packet_t m, int off, int icmp6len)
{
	struct ofp_ether_header *eth;
	struct ofp_ip6_hdr *ip6;
	struct ofp_icmp6_hdr *icmp6;
	struct ofp_ifnet *ifp;

	(void)icmp6len;

	ifp = odp_packet_user_ptr(m);
	eth = (struct ofp_ether_header *) odp_packet_l2_ptr(m, NULL);
	ip6 = (struct ofp_ip6_hdr *)odp_packet_l3_ptr(m, NULL);
	icmp6 = (struct ofp_icmp6_hdr *)((uint8_t *)ip6 + off);

	if (icmp6->ofp_icmp6_data8[20] == OFP_ND_OPT_TARGET_LINKADDR) {
		ofp_set_route6_params(OFP_ROUTE6_ADD, 0 /*vrf*/, ifp->vlan,
				      ifp->port, &icmp6->ofp_icmp6_data8[4],
				      128 /*masklen*/,
				      ofp_in6addr_any.ofp_s6_addr,
				      OFP_RTF_HOST);

		ofp_add_mac6(ifp,
			&icmp6->ofp_icmp6_data8[4],
			(uint8_t *)&eth->ether_shost);
	}
}

enum ofp_return_code ofp_nd6_na_output(struct ofp_ifnet *dev,
	uint8_t *daddr6, uint8_t *taddr6, uint8_t *tlladdr)
{
	size_t size = 0;
	size_t iter = 0;
	struct ofp_ether_header *e1;
	struct ofp_ether_vlan_header *e2;
	struct ofp_ip6_hdr *ip6hdr;
	struct ofp_icmp6_hdr *icmp;
	odp_packet_t pkt;

	if (dev->vlan)
		size = sizeof(struct ofp_ether_vlan_header);
	else
		size = sizeof(struct ofp_ether_header);

	size += sizeof(struct ofp_ip6_hdr) +
		sizeof(struct ofp_nd_neighbor_advert) +
		8; /* option - Target link-layer address*/

	pkt = odp_packet_alloc(ofp_packet_pool, size);
	if (pkt == ODP_PACKET_INVALID)
		return OFP_PKT_DROP;

	odp_packet_has_eth_set(pkt, 1);
	odp_packet_l2_offset_set(pkt, iter);

	if (dev->vlan) {
		e2 = (struct ofp_ether_vlan_header *)odp_packet_l2_ptr(pkt,
			NULL);
		iter += sizeof(*e2);

		memcpy(e2->evl_dhost, tlladdr, OFP_ETHER_ADDR_LEN);
		memcpy(e2->evl_shost, dev->mac, OFP_ETHER_ADDR_LEN);

		e2->evl_encap_proto = odp_cpu_to_be_16(OFP_ETHERTYPE_VLAN);
		e2->evl_tag = odp_cpu_to_be_16(dev->vlan);
		e2->evl_proto = odp_cpu_to_be_16(OFP_ETHERTYPE_IPV6);
	} else {
		e1 = (struct ofp_ether_header *)odp_packet_l2_ptr(pkt, NULL);
		iter += sizeof(*e1);

		memcpy(e1->ether_dhost, tlladdr, OFP_ETHER_ADDR_LEN);
		memcpy(e1->ether_shost, dev->mac, OFP_ETHER_ADDR_LEN);
		e1->ether_type = odp_cpu_to_be_16(OFP_ETHERTYPE_IPV6);
	}
	odp_packet_l3_offset_set(pkt, iter);
	ip6hdr = (struct ofp_ip6_hdr *)odp_packet_l3_ptr(pkt, NULL);
	iter += sizeof(*ip6hdr);

	ip6hdr->ofp_ip6_flow = 0;
	ip6hdr->ofp_ip6_vfc = OFP_IPV6_VERSION;
	ip6hdr->ofp_ip6_plen = odp_cpu_to_be_16(32);
		/*sizeof(*icmp) + sizeof taddr + 8*/

	/* for checksum calculation */
	ip6hdr->ofp_ip6_nxt = 0;
	ip6hdr->ofp_ip6_hlim = OFP_IPPROTO_ICMPV6;

	if (!ofp_ip6_is_set(daddr6)) {
		/* reply to DAD */
		ip6hdr->ip6_dst.ofp_s6_addr16[0] = OFP_IPV6_ADDR_INT16_MLL;
		ip6hdr->ip6_dst.ofp_s6_addr16[1] = 0;
		ip6hdr->ip6_dst.ofp_s6_addr32[1] = 0;
		ip6hdr->ip6_dst.ofp_s6_addr32[2] = 0;
		ip6hdr->ip6_dst.ofp_s6_addr32[3] = OFP_IPV6_ADDR_INT32_ONE;
	} else
		memcpy(ip6hdr->ip6_dst.ofp_s6_addr, daddr6, 16);

	memcpy(ip6hdr->ip6_src.ofp_s6_addr, dev->ip6_addr, 16);

	odp_packet_l4_offset_set(pkt, iter);
	icmp = (struct ofp_icmp6_hdr *)odp_packet_l4_ptr(pkt, NULL);
	iter += sizeof(*icmp) + 8 /* option */;

	icmp->icmp6_type = OFP_ND_NEIGHBOR_ADVERT;
	icmp->icmp6_code = 0;
	icmp->icmp6_cksum = 0;
	icmp->ofp_icmp6_data32[0] = 0; /* Reserved */

	memcpy(&icmp->ofp_icmp6_data8[4], taddr6, 16);

	/* Option: Source link-layer address */
	icmp->ofp_icmp6_data8[20] = OFP_ND_OPT_TARGET_LINKADDR;
	icmp->ofp_icmp6_data8[21] = 1; /* 8 octets */
	memcpy(&icmp->ofp_icmp6_data8[22], dev->mac, 6);

	icmp->icmp6_cksum =
		ofp_cksum_buffer((uint16_t *)&ip6hdr->ofp_ip6_plen, 68);

	ip6hdr->ofp_ip6_nxt = OFP_IPPROTO_ICMPV6;
	ip6hdr->ofp_ip6_hlim = 255;

	if (send_pkt_out(dev, pkt) == OFP_PKT_DROP) {
		OFP_ERR("Drop packet");
		odp_packet_free(pkt);
		return OFP_PKT_DROP;
	}

	return OFP_PKT_PROCESSED;
}

