/*-
 * Copyright (c) 2014 ENEA Software AB
 * Copyright (c) 2014 Nokia
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ofpi.h"
#include "ofpi_pkt_processing.h"
#include "ofpi_portconf.h"
#include "ofpi_rt_lookup.h"
#include "ofpi_route.h"
#include "ofpi_util.h"
#include "ofpi_stat.h"
#include "ofpi_timer.h"
#include "ofpi_debug.h"
#include "ofpi_avl.h"
#include "ofpi_protosw.h"
#include "ofpi_ip6protosw.h"
#include "ofpi_arp.h"
#include "ofpi_hook.h"
#include "ofpi_log.h"
#include "ofpi_reass.h"
#include "ofpi_if_vxlan.h"
#include "ofpi_vxlan.h"
#include "ofpi_gre.h"
#include "ofpi_ip.h"
#include "api/ofp_init.h"

static inline enum ofp_return_code ofp_ip_output_continue(odp_packet_t pkt,
							  struct ip_out *odata);

extern odp_pool_t ofp_packet_pool;

__thread struct ofp_global_ip_state *ofp_ip_shm;

int default_event_dispatcher(void *arg)
{
	odp_event_t ev;
	odp_packet_t pkt;
	odp_queue_t in_queue;
	int event_idx = 0;
	int event_cnt = 0;
	ofp_pkt_processing_func pkt_func = (ofp_pkt_processing_func)arg;
	odp_bool_t *is_running = NULL;

	if (ofp_init_local()) {
		OFP_ERR("ofp_init_local failed");
		return -1;
	}

	int rx_burst = global_param->evt_rx_burst_size;
	odp_event_t events[rx_burst];

	is_running = ofp_get_processing_state();
	if (is_running == NULL) {
		OFP_ERR("ofp_get_processing_state failed");
		ofp_term_local();
		return -1;
	}

	/* PER CORE DISPATCHER */
	while (*is_running) {
		event_cnt = odp_schedule_multi(&in_queue, ODP_SCHED_WAIT,
					 events, rx_burst);
		for (event_idx = 0; event_idx < event_cnt; event_idx++) {
			odp_event_type_t ev_type;

			ev = events[event_idx];

			if (ev == ODP_EVENT_INVALID)
				continue;
			ev_type = odp_event_type(ev);

			if (odp_likely(ev_type == ODP_EVENT_PACKET)) {
				pkt = odp_packet_from_event(ev);
#if 0
				if (odp_unlikely(odp_packet_has_error(pkt))) {
					OFP_DBG("Dropping packet with error");
					odp_packet_free(pkt);
					continue;
				}
#endif
				ofp_packet_input(pkt, in_queue, pkt_func);
				continue;
			}
			if (ev_type == ODP_EVENT_TIMEOUT) {
				ofp_timer_handle(ev);
				continue;
			}

			OFP_ERR("Unexpected event type: %u", ev_type);
			odp_event_free(ev);
		}
		ofp_send_pending_pkt();
	}

	if (ofp_term_local())
		OFP_ERR("ofp_term_local failed");

	return 0;
}

uint32_t ofp_packet_min_user_area(void)
{
	return sizeof(struct ofp_packet_user_area);
}

enum ofp_return_code ofp_eth_vlan_processing(odp_packet_t *pkt)
{
	uint16_t vlan = 0, ethtype;
	struct ofp_ether_header *eth;
	struct ofp_ifnet *ifnet = odp_packet_user_ptr(*pkt);

	eth = (struct ofp_ether_header *)odp_packet_l2_ptr(*pkt, NULL);

	if (odp_unlikely(eth == NULL)) {
		OFP_DBG("eth is NULL");
		return OFP_PKT_DROP;
	}

	ethtype = odp_be_to_cpu_16(eth->ether_type);

	if (ethtype == OFP_ETHERTYPE_VLAN) {
		struct ofp_ether_vlan_header *vlan_hdr;

		vlan_hdr = (struct ofp_ether_vlan_header *)eth;
		vlan = OFP_EVL_VLANOFTAG(odp_be_to_cpu_16(vlan_hdr->evl_tag));
		ethtype = odp_be_to_cpu_16(vlan_hdr->evl_proto);
		ifnet = ofp_get_ifnet(ifnet->port, vlan);
		if (!ifnet)
			return OFP_PKT_DROP;
		if (odp_likely(ofp_if_type(ifnet) != OFP_IFT_VXLAN))
			odp_packet_user_ptr_set(*pkt, ifnet);
	}

	OFP_DBG("ETH TYPE = %04x", ethtype);

	/* network layer classifier */
	switch (ethtype) {
	/* STUB: except for ARP, just terminate all traffic to slowpath.
	 * FIXME: test/implement other cases */
#ifdef INET
	case OFP_ETHERTYPE_IP:
		return ofp_ipv4_processing(pkt);
#endif /* INET */
#ifdef INET6
	case OFP_ETHERTYPE_IPV6:
		return ofp_ipv6_processing(pkt);
#endif /* INET6 */
#if 0
	case OFP_ETHERTYPE_MPLS:
		return OFP_PKT_DROP;
#endif
	case OFP_ETHERTYPE_ARP:
		return ofp_arp_processing(pkt);
	default:
		return OFP_PKT_CONTINUE;
	}
}


enum ofp_return_code
ipv4_transport_classifier(odp_packet_t *pkt, uint8_t ip_proto)
{
	struct ofp_ip *ip = (struct ofp_ip *)odp_packet_l3_ptr(*pkt, NULL);

	OFP_DBG("ip_proto=%d pr_input=%p",
		ip_proto, ofp_inetsw[ofp_ip_protox[ip_proto]].pr_input);

	return ofp_inetsw[ofp_ip_protox[ip_proto]].pr_input(pkt, ip->ip_hl << 2);
}

/*
 * input function returns:
 * ret == OFP_PKT_CONTINUE && nxt != OFP_IPPROTO_SP	- process next header
 * ret == OFP_PKT_CONTINUE && nxt == OFP_IPPROTO_SP	- go to slow path
 * ret != OFP_PKT_CONTINUE				- perform default action
 */

#ifdef INET6
enum ofp_return_code
ipv6_transport_classifier(odp_packet_t *pkt, uint8_t ip6_nxt)
{
	int nxt = ip6_nxt;
	int offset = sizeof(struct ofp_ip6_hdr);
	enum ofp_return_code ret = OFP_PKT_CONTINUE;

	while (ret == OFP_PKT_CONTINUE && nxt != OFP_IPPROTO_SP)
		ret = ofp_inet6sw[ofp_ip6_protox[nxt]].pr_input(pkt,
				&offset, &nxt);

	return ret;
}
#endif /*INET6*/

static enum ofp_return_code pkt_reassembly(odp_packet_t *pkt)
{
	OFP_UPDATE_PACKET_STAT(rx_ip_frag, 1);

	*pkt = ofp_ip_reass(*pkt);
	if (*pkt == ODP_PACKET_INVALID)
		return OFP_PKT_PROCESSED;

	OFP_UPDATE_PACKET_STAT(rx_ip_reass, 1);

	return OFP_PKT_CONTINUE;
}

enum ofp_return_code ofp_udp4_processing(odp_packet_t *pkt)
{
	struct ofp_ip *ip = (struct ofp_ip *)odp_packet_l3_ptr(*pkt, NULL);
	int frag_res = 0;

	if (odp_unlikely(ofp_cksum_iph(ip, ip->ip_hl)))
		return OFP_PKT_DROP;

	if (odp_be_to_cpu_16(ip->ip_off) & 0x3fff) {
		frag_res = pkt_reassembly(pkt);
		if (frag_res != OFP_PKT_CONTINUE)
			return frag_res;

		ip = (struct ofp_ip *)odp_packet_l3_ptr(*pkt, NULL);
	}

	return ofp_inetsw[ofp_ip_protox_udp].pr_input(pkt, ip->ip_hl << 2);
}

enum ofp_return_code ofp_tcp4_processing(odp_packet_t *pkt)
{
	struct ofp_ip *ip = (struct ofp_ip *)odp_packet_l3_ptr(*pkt, NULL);
	int frag_res = 0;

	if (odp_unlikely(ofp_cksum_iph(ip, ip->ip_hl)))
		return OFP_PKT_DROP;

	if (odp_be_to_cpu_16(ip->ip_off) & 0x3fff) {
		frag_res = pkt_reassembly(pkt);
		if (frag_res != OFP_PKT_CONTINUE)
			return frag_res;

		ip = (struct ofp_ip *)odp_packet_l3_ptr(*pkt, NULL);
	}

	return ofp_inetsw[ofp_ip_protox_tcp].pr_input(pkt, ip->ip_hl << 2);
}

static inline enum ofp_return_code ofp_ip_output_common_inline(odp_packet_t pkt,
							       struct ofp_nh_entry *nh,
							       int is_local_out);

enum ofp_return_code ofp_ip_output_common(odp_packet_t pkt,
					  struct ofp_nh_entry *nh,
					  int is_local_out)
{
	return ofp_ip_output_common_inline(pkt, nh, is_local_out);
}

enum ofp_return_code ofp_ipv4_processing(odp_packet_t *pkt)
{
	int frag_res = 0, res;
	int protocol = IS_IPV4;
	uint32_t flags;
	struct ofp_ip *ip;
	struct ofp_nh_entry *nh;
	struct ofp_ifnet *dev = odp_packet_user_ptr(*pkt);
	uint32_t is_ours;

	ip = (struct ofp_ip *)odp_packet_l3_ptr(*pkt, NULL);

	if (odp_unlikely(ip == NULL)) {
		OFP_DBG("ip is NULL");
		return OFP_PKT_DROP;
	}

	if (odp_unlikely(ofp_if_type(dev) == OFP_IFT_VXLAN)) {
		struct ofp_packet_user_area *ua;

		/* Look for the correct device. */
		ua = ofp_packet_user_area(*pkt);
		dev = ofp_get_ifnet(VXLAN_PORTS, ua->vxlan.vni);
		if (!dev)
			return OFP_PKT_DROP;
	}

	if (odp_unlikely(ip->ip_v != OFP_IPVERSION))
		return OFP_PKT_DROP;

	if (ofp_packet_user_area(*pkt)->chksum_flags
		& OFP_L3_CHKSUM_STATUS_VALID) {
		switch (odp_packet_l3_chksum_status(*pkt)) {
		case ODP_PACKET_CHKSUM_OK:
			break;
		case ODP_PACKET_CHKSUM_UNKNOWN:
			/* Checksum was not validated by HW */
			if (odp_unlikely(ofp_cksum_iph(ip, ip->ip_hl)))
				return OFP_PKT_DROP;
			break;
		case ODP_PACKET_CHKSUM_BAD:
			return OFP_PKT_DROP;
			break;
		}
		ofp_packet_user_area(*pkt)->chksum_flags &=
			~OFP_L3_CHKSUM_STATUS_VALID;
	} else if (odp_unlikely(ofp_cksum_iph(ip, ip->ip_hl)))
		return OFP_PKT_DROP;

	/* TODO: handle broadcast */
	if (dev->bcast_addr == ip->ip_dst.s_addr)
		return OFP_PKT_DROP;

	OFP_DBG("Device IP: %s, Packet Dest IP: %s",
		ofp_print_ip_addr(dev->ip_addr),
		ofp_print_ip_addr(ip->ip_dst.s_addr));

	is_ours = dev->ip_addr == ip->ip_dst.s_addr ||
		OFP_IN_MULTICAST(odp_be_to_cpu_32(ip->ip_dst.s_addr));

	if (!is_ours) {
		/* This may be for some other local interface. */
		nh = ofp_get_next_hop(dev->vrf, ip->ip_dst.s_addr, &flags);
		if (nh)
			is_ours = nh->flags & OFP_RTF_LOCAL;
	}

	if (is_ours) {
		if (odp_be_to_cpu_16(ip->ip_off) & 0x3fff) {
			frag_res = pkt_reassembly(pkt);
			if (frag_res != OFP_PKT_CONTINUE)
				return frag_res;

			ip = (struct ofp_ip *)odp_packet_l3_ptr(*pkt, NULL);
		}

		OFP_HOOK(OFP_HOOK_LOCAL, *pkt, &protocol, &res);
		if (res != OFP_PKT_CONTINUE) {
			OFP_DBG("OFP_HOOK_LOCAL returned %d", res);
			return res;
		}

		OFP_HOOK(OFP_HOOK_LOCAL_IPv4, *pkt, NULL, &res);
		if (res != OFP_PKT_CONTINUE) {
			OFP_DBG("OFP_HOOK_LOCAL_IPv4 returned %d", res);
			return res;
		}

		return ipv4_transport_classifier(pkt, ip->ip_p);

	}

	OFP_HOOK(OFP_HOOK_FWD_IPv4, *pkt, nh, &res);
	if (res != OFP_PKT_CONTINUE) {
		OFP_DBG("OFP_HOOK_FWD_IPv4 returned %d", res);
		return res;
	}

	if (nh == NULL) {
		OFP_DBG("nh is NULL, vrf=%d dest=%x", dev->vrf, ip->ip_dst.s_addr);
		return OFP_PKT_CONTINUE;
	}

	if (ip->ip_ttl <= 1) {
		OFP_DBG("OFP_ICMP_TIMXCEED");
		ofp_icmp_error(*pkt, OFP_ICMP_TIMXCEED,
				OFP_ICMP_TIMXCEED_INTRANS, 0, 0);
		return OFP_PKT_DROP;
	}

	/*
	 * Decrement TTL and incrementally change the IP header checksum.
	 */
	ip->ip_ttl--;
	uint16_t a = ~odp_cpu_to_be_16(1 << 8);
	if (ip->ip_sum >= a)
		ip->ip_sum -= a;
	else
		ip->ip_sum += odp_cpu_to_be_16(1 << 8);

#ifdef OFP_SEND_ICMP_REDIRECT
	/* 1. The interface on which the packet comes into the router is the
	 * same interface on which the packet gets routed out.
	 * 2. The subnet or network of the source IP address is on the same
	 * subnet or network of the next-hop IP address of the routed packet.
	 * 3. Stack configured to send redirects.
	 */
#define INET_SUBNET_PREFIX(addr)				\
	(odp_be_to_cpu_32(addr) & ((~0) << (32 - dev->masklen)))

	if (nh->port == dev->port &&
		(INET_SUBNET_PREFIX(ip->ip_src.s_addr) ==
		INET_SUBNET_PREFIX(nh->gw))) {

		OFP_DBG("send OFP_ICMP_REDIRECT");
		ofp_icmp_error(*pkt, OFP_ICMP_REDIRECT,
				OFP_ICMP_REDIRECT_HOST, nh->gw, 0);
	}
#endif

	return ofp_ip_output_common_inline(*pkt, nh, 0);
}

#ifdef INET6
enum ofp_return_code ofp_ipv6_processing(odp_packet_t *pkt)
{
	int res;
	int protocol = IS_IPV6;
	uint32_t flags;
	struct ofp_ip6_hdr *ipv6;
	struct ofp_nh6_entry *nh;
	struct ofp_ifnet *dev = odp_packet_user_ptr(*pkt);
	int is_ours = 0;

	ipv6 = (struct ofp_ip6_hdr *)odp_packet_l3_ptr(*pkt, NULL);

	if (odp_unlikely(ipv6 == NULL))
		return OFP_PKT_DROP;

	/* is ipv6->dst_addr one of my IPv6 addresses from this interface*/
	if (ofp_ip6_equal(dev->ip6_addr, ipv6->ip6_dst.ofp_s6_addr) ||
		OFP_IN6_IS_SOLICITED_NODE_MC(ipv6->ip6_dst, dev->ip6_addr) ||
		(memcmp((const void *)((uintptr_t)dev->link_local + 8),
		(const void *)((uintptr_t)ipv6->ip6_dst.ofp_s6_addr + 8),
			2 * sizeof(uint32_t)) == 0)) {

			is_ours = 1;
	}
	/* check if it's ours for another ipv6 address */
	if (!is_ours) {
		nh = ofp_get_next_hop6(dev->vrf, ipv6->ip6_dst.ofp_s6_addr, &flags);
		if (nh && (nh->flags & OFP_RTF_LOCAL))
			is_ours = 1;
	}

	if (is_ours) {
		OFP_HOOK(OFP_HOOK_LOCAL, *pkt, &protocol, &res);
		if (res != OFP_PKT_CONTINUE) {
			OFP_DBG("OFP_HOOK_LOCAL returned %d", res);
			return res;
		}

		OFP_HOOK(OFP_HOOK_LOCAL_IPv6, *pkt, NULL, &res);
		if (res != OFP_PKT_CONTINUE) {
			OFP_DBG("OFP_HOOK_LOCAL_IPv6 returned %d", res);
			return res;
		}

		return ipv6_transport_classifier(pkt, ipv6->ofp_ip6_nxt);

	}

	OFP_HOOK(OFP_HOOK_FWD_IPv6, *pkt, NULL, &res);
	if (res != OFP_PKT_CONTINUE) {
		OFP_DBG("OFP_HOOK_FWD_IPv6 returned %d", res);
		return res;
	}

	nh = ofp_get_next_hop6(dev->vrf, ipv6->ip6_dst.ofp_s6_addr, &flags);
	if (nh == NULL)
		return OFP_PKT_CONTINUE;

	return ofp_ip6_output(*pkt, nh);
}
#endif /* INET6 */

enum ofp_return_code ofp_gre_processing(odp_packet_t *pkt)
{
	int frag_res = 0;
	struct ofp_ip *ip = (struct ofp_ip *)odp_packet_l3_ptr(*pkt, NULL);

	if (odp_unlikely(ofp_cksum_iph(ip, ip->ip_hl)))
		return OFP_PKT_DROP;

	if (odp_be_to_cpu_16(ip->ip_off) & 0x3fff) {
		frag_res = pkt_reassembly(pkt);
		if (frag_res != OFP_PKT_CONTINUE)
			return frag_res;

		ip = (struct ofp_ip *)odp_packet_l3_ptr(*pkt, NULL);
	}

	return ofp_inetsw[ofp_ip_protox_gre].pr_input(pkt, ip->ip_hl << 2);
}

enum ofp_return_code send_pkt_loop(struct ofp_ifnet *dev,
	odp_packet_t pkt)
{
	if (odp_queue_enq(ofp_get_ifnet(dev->port, 0)->loopq_def,
		odp_packet_to_event(pkt)))
		return OFP_PKT_DROP;
	return OFP_PKT_PROCESSED;
}

enum ofp_return_code ofp_arp_processing(odp_packet_t *pkt)
{
	struct ofp_arphdr *arp;
	struct ofp_ifnet *dev = odp_packet_user_ptr(*pkt);
	struct ofp_ifnet *outdev = dev;
	uint16_t vlan = dev->vlan;
	uint8_t inner_from_mac[OFP_ETHER_ADDR_LEN];
	uint32_t is_ours;

	arp = (struct ofp_arphdr *)odp_packet_l3_ptr(*pkt, NULL);

	if (odp_unlikely(arp == NULL)) {
		OFP_DBG("arp is NULL");
		return OFP_PKT_DROP;
	}

	/* save the received arp info */
	if (odp_be_to_cpu_16(arp->op) == OFP_ARPOP_REPLY)
		ofp_add_mac(dev, arp->ip_src, arp->eth_src);

	OFP_DBG("Device IP: %s, Packet Dest IP: %s",
		ofp_print_ip_addr(dev->ip_addr),
		ofp_print_ip_addr(arp->ip_dst));

	/* Check for VXLAN interface */
	if (odp_unlikely(ofp_if_type(dev) == OFP_IFT_VXLAN)) {
		ofp_vxlan_update_devices(*pkt, arp, &vlan, &dev, &outdev,
					 inner_from_mac);
	}

	is_ours = dev->ip_addr && dev->ip_addr == (ofp_in_addr_t)(arp->ip_dst);
	if (!is_ours && !global_param->arp.check_interface) {
		/* This may be for some other local interface. */
		uint32_t flags;
		struct ofp_nh_entry *nh;
		nh = ofp_get_next_hop(dev->vrf, arp->ip_dst, &flags);
		if (nh)
			is_ours = nh->flags & OFP_RTF_LOCAL;
	}
	/* on our interface an ARP request */
	if (is_ours &&
	    odp_be_to_cpu_16(arp->op) == OFP_ARPOP_REQUEST) {
		struct ofp_arphdr tmp;
		struct ofp_ether_header tmp_eth;
		struct ofp_ether_vlan_header tmp_eth_vlan;
		void *l2_addr = odp_packet_l2_ptr(*pkt, NULL);
		struct ofp_ether_header *eth =
			(struct ofp_ether_header *)l2_addr;
		struct ofp_ether_vlan_header *eth_vlan =
			(struct ofp_ether_vlan_header *)l2_addr;

		ofp_add_mac(dev, arp->ip_src, arp->eth_src);
		if (vlan)
			tmp_eth_vlan = *eth_vlan;
		else
			tmp_eth = *eth;

		OFP_DBG("Reply to ARPOP_REQ from ip %s"
#ifdef SP
			"on IF %d"
#endif
			" mac %s ip %s",
			ofp_print_ip_addr(arp->ip_src),
#ifdef SP
			dev->linux_index,
#endif
			ofp_print_mac(dev->mac),
			ofp_print_ip_addr(arp->ip_dst));
		tmp = *arp;
		tmp.ip_dst = arp->ip_src;
		tmp.ip_src = arp->ip_dst;
		memcpy(&tmp.eth_dst, &arp->eth_src, OFP_ETHER_ADDR_LEN);
		memcpy(&tmp.eth_src, dev->mac, OFP_ETHER_ADDR_LEN);
		tmp.op = odp_cpu_to_be_16(OFP_ARPOP_REPLY);
		*arp = tmp;

		if (vlan) {
			memcpy(tmp_eth_vlan.evl_dhost, &arp->eth_dst,
				OFP_ETHER_ADDR_LEN);
			memcpy(tmp_eth_vlan.evl_shost, &arp->eth_src,
				OFP_ETHER_ADDR_LEN);
			*eth_vlan = tmp_eth_vlan;
		} else {
			memcpy(tmp_eth.ether_dhost, &arp->eth_dst,
				OFP_ETHER_ADDR_LEN);
			memcpy(tmp_eth.ether_shost, &arp->eth_src,
				OFP_ETHER_ADDR_LEN);
			*eth = tmp_eth;
		}

		if (odp_unlikely(ofp_if_type(dev) == OFP_IFT_VXLAN)) {
			/* Restore the original vxlan header and
			   update the addresses */
			ofp_vxlan_restore_and_update_header
				(*pkt, outdev, inner_from_mac);
		}

		return send_pkt_out(outdev, *pkt);
	}
	return OFP_PKT_CONTINUE;
}

#define ETH_WITH_VLAN(dev) ((dev)->vlan && ofp_if_type(dev) != VXLAN_PORTS)

static void send_arp_request(struct ofp_ifnet *dev, uint32_t gw)
{
	char buf[sizeof(struct ofp_ether_vlan_header) +
		sizeof(struct ofp_arphdr)];
	struct ofp_arphdr *arp;
	struct ofp_ether_header *e1 = (struct ofp_ether_header *)buf;
	struct ofp_ether_vlan_header *e2 =
					(struct ofp_ether_vlan_header *)buf;
	size_t size;
	odp_packet_t pkt;

	memset(buf, 0, sizeof(buf));
	memset(e1->ether_dhost, 0xff, OFP_ETHER_ADDR_LEN);
	memcpy(e1->ether_shost, dev->mac, OFP_ETHER_ADDR_LEN);

	if (ETH_WITH_VLAN(dev)) {
		arp = (struct ofp_arphdr *) (e2 + 1);
		e2->evl_encap_proto = odp_cpu_to_be_16(OFP_ETHERTYPE_VLAN);
		e2->evl_tag = odp_cpu_to_be_16(dev->vlan);
		e2->evl_proto = odp_cpu_to_be_16(OFP_ETHERTYPE_ARP);
		size = sizeof(*arp) + sizeof(*e2);
	} else {
		arp = (struct ofp_arphdr *) (e1 + 1);
		e1->ether_type = odp_cpu_to_be_16(OFP_ETHERTYPE_ARP);
		size = sizeof(*arp) + sizeof(*e1);
	}

	arp->hrd = odp_cpu_to_be_16(OFP_ARPHDR_ETHER);
	arp->pro = odp_cpu_to_be_16(OFP_ETHERTYPE_IP);
	arp->hln = OFP_ETHER_ADDR_LEN;
	arp->pln = sizeof(struct ofp_in_addr);
	arp->op  = odp_cpu_to_be_16(OFP_ARPOP_REQUEST);
	memcpy(arp->eth_src, e1->ether_shost, OFP_ETHER_ADDR_LEN);
	arp->ip_src = dev->ip_addr;
	memcpy(arp->eth_dst, e1->ether_dhost, OFP_ETHER_ADDR_LEN);
	arp->ip_dst = gw;

	pkt = ofp_packet_alloc(size);
	if (pkt == ODP_PACKET_INVALID) {
		OFP_ERR("ofp_packet_alloc failed");
		return;
	}

	memcpy(odp_packet_data(pkt), buf, size);

	if (odp_unlikely(ofp_if_type(dev) == OFP_IFT_VXLAN)) {
		ofp_vxlan_send_arp_request(pkt, dev);
		return;
	}

	odp_packet_has_eth_set(pkt, 1);
	odp_packet_has_arp_set(pkt, 1);
	odp_packet_l2_offset_set(pkt, 0);
	odp_packet_l3_offset_set(pkt, size - sizeof(struct ofp_arphdr));

	if (send_pkt_out(dev, pkt) == OFP_PKT_DROP)
		odp_packet_free(pkt);
}

enum ofp_return_code ofp_send_frame(struct ofp_ifnet *dev, odp_packet_t pkt)
{
	struct ofp_ether_header *eth, eth_tmp;
	struct ofp_ether_vlan_header *eth_vlan, eth_vlan_tmp;
	uint32_t pkt_len, eth_hdr_len;
	enum ofp_return_code rc;

	if (ofp_if_type(dev) == OFP_IFT_GRE) {
		OFP_ERR("Send frame on GRE port");
		return OFP_PKT_DROP;
	}

	ofp_packet_user_area_reset(pkt);

	/* Contsruct ethernet header */
	eth = odp_packet_l2_ptr(pkt, NULL);
	eth_vlan = odp_packet_l2_ptr(pkt, NULL);

	if (odp_be_to_cpu_16(eth->ether_type) == OFP_ETHERTYPE_VLAN) {
		if (dev->vlan) {
			/* change vlan */
			eth_vlan->evl_tag = odp_cpu_to_be_16(dev->vlan);
		} else {
			/* remove existing vlan */
			eth_vlan_tmp = *eth_vlan;
			eth = odp_packet_pull_head(pkt, 4);
			if (!eth) {
				OFP_ERR("odp_packet_pull_head failed");
				return OFP_PKT_DROP;
			}

			odp_packet_l3_offset_set(pkt,
						 odp_packet_l3_offset(pkt) - 4);
			ofp_copy_mac(eth->ether_dhost, eth_vlan_tmp.evl_dhost);
			ofp_copy_mac(eth->ether_shost, eth_vlan_tmp.evl_shost);
			eth->ether_type = eth_vlan_tmp.evl_proto;
		}
	} else {
		if (dev->vlan) {
			/* insert vlan */
			eth_tmp = *eth;
			eth_vlan = odp_packet_push_head(pkt, 4);
			if (!eth_vlan) {
				OFP_ERR("odp_packet_push_head failed");
				return OFP_PKT_DROP;
			}

			odp_packet_l3_offset_set(pkt,
						 odp_packet_l3_offset(pkt) + 4);
			ofp_copy_mac(eth_vlan->evl_dhost, eth_tmp.ether_dhost);
			ofp_copy_mac(eth_vlan->evl_shost, eth_tmp.ether_shost);
			eth_vlan->evl_encap_proto =
				odp_cpu_to_be_16(OFP_ETHERTYPE_VLAN);
			eth_vlan->evl_tag = odp_cpu_to_be_16(dev->vlan);
			eth_vlan->evl_proto = eth_tmp.ether_type;
		}
	}

	if (dev->vlan)
		eth_hdr_len = OFP_ETHER_HDR_LEN + OFP_ETHER_VLAN_ENCAP_LEN;
	else
		eth_hdr_len = OFP_ETHER_HDR_LEN;

	pkt_len = odp_packet_len(pkt) - eth_hdr_len;

	if (pkt_len > dev->if_mtu) {
		OFP_ERR("Packet size bigger than MTU: %d %d", pkt_len,
			dev->if_mtu);
		return OFP_PKT_DROP;
	}

	rc = send_pkt_out(dev, pkt);
	if (rc != OFP_PKT_PROCESSED)
		return rc;

	return ofp_send_pending_pkt();
}

static enum ofp_return_code ofp_fragment_pkt(odp_packet_t pkt,
					     struct ip_out *odata)
{
	struct ofp_ip *ip, *ip_new;
	int pl_len, seg_len, pl_pos, flen, hwlen;
	uint16_t frag, frag_new;
	uint8_t *payload_new;
	uint32_t payload_offset;
	odp_packet_t pkt_new;
	int ret = OFP_PKT_PROCESSED;

	ip = (struct ofp_ip *)odp_packet_l3_ptr(pkt, NULL);

	/*
	 * Copy fragment IP options into a separate buffer, which is
	 * copied into each fragment, except the first one.
	 */
	int ip_hlen = ip->ip_hl<<2;
	int iopts_len = ip_hlen - sizeof(struct ofp_ip);
	uint8_t fopts[(iopts_len+3)&0xfffc];
	uint8_t *iopts = (uint8_t *)(ip + 1);
	int iopts_pos = 0, fopts_len = 0;

	while (iopts_pos < iopts_len) {
		int opt_len = 1;

		switch (OFP_IPOPT_NUMBER(iopts[iopts_pos])) {
		case OFP_IPOPT_EOL:
		case OFP_IPOPT_NOP:
			break;
		default:
			opt_len = iopts[iopts_pos+1];
			if (opt_len > iopts_len - iopts_pos)
				opt_len = iopts_len - iopts_pos;
			if (OFP_IPOPT_COPIED(iopts[iopts_pos])) {
				memcpy(fopts + fopts_len, iopts + iopts_pos, opt_len);
				fopts_len += opt_len;
			}
		}
		iopts_pos += opt_len;
	}

	while (fopts_len & 3) fopts[fopts_len++] = 0;

	pl_len = odp_be_to_cpu_16(ip->ip_len) - ip_hlen;
	pl_pos = 0;
	frag = odp_be_to_cpu_16(ip->ip_off);
	payload_offset = odp_packet_l3_offset(pkt) + ip_hlen;

	OFP_UPDATE_PACKET_STAT(tx_eth_frag, 1);

	int first = 1;

	while (pl_pos < pl_len) {
		int f_ip_hl = ip->ip_hl;

		if (!first) f_ip_hl = (sizeof(struct ofp_ip) + fopts_len) >> 2;

		int f_ip_hlen = f_ip_hl<<2;

		seg_len = (odata->dev_out->if_mtu - f_ip_hlen) & 0xfff8;
		flen = (pl_len - pl_pos) > seg_len ?
			seg_len : (pl_len - pl_pos);
		hwlen = flen + f_ip_hlen;

		pkt_new = ofp_packet_alloc(hwlen);
		if (pkt_new == ODP_PACKET_INVALID) {
			OFP_ERR("ofp_packet_alloc failed");
			return OFP_PKT_DROP;
		}
		odp_packet_user_ptr_set(pkt_new, odp_packet_user_ptr(pkt));
		*ofp_packet_user_area(pkt_new) = *ofp_packet_user_area(pkt);

		odp_packet_l2_offset_set(pkt_new, 0);
		odp_packet_l3_offset_set(pkt_new, 0);
		ip_new = odp_packet_l3_ptr(pkt_new, NULL);

		*ip_new = *ip;

		if (first)
			memcpy(ip_new + 1, ip + 1, ip_hlen - sizeof(struct ofp_ip));
		else
			memcpy(ip_new + 1, fopts, fopts_len);

		ip_new->ip_hl = f_ip_hl;

		payload_new = (uint8_t *)ip_new + f_ip_hlen;

		if (odp_packet_copy_to_mem(pkt, payload_offset + pl_pos,
					    flen, payload_new) < 0) {
			OFP_ERR("odp_packet_copy_to_mem failed");
			odp_packet_free(pkt_new);
			return OFP_PKT_DROP;
		};

		ip_new->ip_len = odp_cpu_to_be_16(flen + f_ip_hlen);

		frag_new = frag + pl_pos/8;
		pl_pos += flen;
		if (pl_pos < pl_len)
			frag_new |= OFP_IP_MF;
		ip_new->ip_off = odp_cpu_to_be_16(frag_new);

		odata->ip = ip_new;
		odata->insert_checksum = 1;
		ret = ofp_ip_output_continue(pkt_new, odata);
		if (ret == OFP_PKT_DROP) {
			odp_packet_free(pkt_new);
			return OFP_PKT_DROP;
		}

		first = 0;
	}

	odp_packet_free(pkt);
	return OFP_PKT_PROCESSED;
}

/*
 * Prepare a packet for L2 header prepend and output. The packet is pulled
 * or pushed as necessary so that there is exactly l2_size bytes in the
 * beginning of the packet before the data pointed to by the L3 offset.
 *
 * After return
 *    - L2 offset is undefined
 *    - L3 offset points to the same data as before the call
 *    - Value of L3 offset is l2_size
 *    - If packet was pushed or pulled, L4 offset is set to l2size + hlen
 *
 * Returns pointer to the L3 data or NULL if trimming failed.
 *
 */
static inline void *trim_for_output(odp_packet_t pkt, uint32_t l2_size,
				    uint32_t hlen)
{
	void *l2_addr;
	uint32_t l3_offset = odp_packet_l3_offset(pkt);

	if (l3_offset == l2_size) {
		l2_addr = odp_packet_data(pkt);
	} else if (l3_offset > l2_size) {
		l2_addr = odp_packet_pull_head(pkt, l3_offset - l2_size);
		odp_packet_l3_offset_set(pkt, l2_size);
		odp_packet_l4_offset_set(pkt, l2_size + hlen);
	} else {
		l2_addr = odp_packet_push_head(pkt, l2_size - l3_offset);
		odp_packet_l3_offset_set(pkt, l2_size);
		odp_packet_l4_offset_set(pkt, l2_size + hlen);
	}
	return l2_addr;
}

/*
 * Trim packet data beyond the end of L3 payload
 * (i.e. from the offset (L3 offset + l3_len) to the end of the packet).
 */
static inline void trim_tail(odp_packet_t pkt, uint32_t l3_len)
{
	uint32_t l3_offset = odp_packet_l3_offset(pkt);
	uint32_t len = odp_packet_len(pkt);

	if (len > l3_offset + l3_len)
		odp_packet_pull_tail(pkt, len - l3_offset - l3_len);
}

static enum ofp_return_code ofp_ip_output_add_eth(odp_packet_t pkt,
						  struct ip_out *odata)
{
	uint32_t l2_size;
	void *l2_addr;
	struct ofp_ether_header *eth;
	uint32_t addr;
	uint32_t is_link_local = 0;

	trim_tail(pkt, odp_be_to_cpu_16(odata->ip->ip_len));

	if (!odata->gw) { /* link local */
		odata->gw = odata->ip->ip_dst.s_addr;
		is_link_local = 1;
	}

	if (!ETH_WITH_VLAN(odata->dev_out))
		l2_size = sizeof(struct ofp_ether_header);
	else
		l2_size = sizeof(struct ofp_ether_vlan_header);

	l2_addr = trim_for_output(pkt, l2_size, odata->ip->ip_hl * 4);
	if (odp_unlikely(l2_addr == NULL)) {
		OFP_DBG("l2_addr == NULL");
		return OFP_PKT_DROP;
	}

	eth = l2_addr;
	addr = odp_be_to_cpu_32(odata->ip->ip_dst.s_addr);

	if (OFP_IN_MULTICAST(addr)) {
		eth->ether_dhost[0] = 0x01;
		eth->ether_dhost[1] = 0x00;
		eth->ether_dhost[2] = 0x5e;
		eth->ether_dhost[3] = (addr >> 16) & 0x7f;
		eth->ether_dhost[4] = (addr >> 8) & 0xff;
		eth->ether_dhost[5] = addr & 0xff;
	} else if (odata->dev_out->ip_addr == odata->ip->ip_dst.s_addr ||
		   ofp_if_type(odata->dev_out) == OFP_IFT_LOOP) {
		odata->is_local_address = 1;
		ofp_copy_mac(eth->ether_dhost, odata->dev_out->mac);
	} else if (ofp_get_mac(odata->dev_out, odata->nh,
			       odata->gw, is_link_local,
			       eth->ether_dhost) < 0) {
		send_arp_request(odata->dev_out, odata->gw);
		return ofp_arp_save_ipv4_pkt(pkt, odata->nh,
					     odata->gw, odata->dev_out);
	}
	ofp_copy_mac(eth->ether_shost, odata->dev_out->mac);

	if (!ETH_WITH_VLAN(odata->dev_out)) {
		eth->ether_type = odp_cpu_to_be_16(OFP_ETHERTYPE_IP);
	} else {
		struct ofp_ether_vlan_header *eth_vlan = l2_addr;

		eth_vlan->evl_encap_proto = odp_cpu_to_be_16(
							OFP_ETHERTYPE_VLAN);
		eth_vlan->evl_tag = odp_cpu_to_be_16(odata->dev_out->vlan);
		eth_vlan->evl_proto = odp_cpu_to_be_16(OFP_ETHERTYPE_IP);
	}

	return OFP_PKT_CONTINUE;
}


static inline enum ofp_return_code ofp_ip_output_send(odp_packet_t pkt,
						      struct ip_out *odata)
{
	if (odata->is_local_address) {
		return send_pkt_loop(odata->dev_out, pkt);
	} else {
		return send_pkt_out(odata->dev_out, pkt);
	}
}

static enum ofp_return_code ofp_ip_output_find_route(struct ip_out *odata)
{
	uint32_t flags;

	if (!odata->nh) {
		odata->nh = ofp_get_next_hop(odata->vrf, odata->ip->ip_dst.s_addr, &flags);
		if (!odata->nh)
			return OFP_PKT_DROP;
	}

	OFP_DBG("Found Route IP: %s NH: %s ARP Idx: %u",
		ofp_print_ip_addr(odata->ip->ip_dst.s_addr),
		ofp_print_ip_addr(odata->nh->gw),
		odata->nh->arp_ent_idx);
	odata->gw = odata->nh->gw;

	odata->dev_out = ofp_get_ifnet(odata->nh->port, odata->nh->vlan);

	if (!odata->dev_out) {
		OFP_DBG("!dev_out");
		return OFP_PKT_DROP;
	}

	/* User has not filled in the source addess */
	if (odata->ip->ip_src.s_addr == 0)
		odata->ip->ip_src.s_addr = odata->dev_out->ip_addr;

	return OFP_PKT_CONTINUE;
}

enum ofp_return_code ofp_ip_send(odp_packet_t pkt,
				 struct ofp_nh_entry *nh_param)
{
	ofp_packet_user_area_reset(pkt);
	return ofp_ip_output(pkt, nh_param);
}

enum ofp_return_code ofp_ip_output_recurse(odp_packet_t pkt,
					   struct ofp_nh_entry *nh)
{
	struct ofp_packet_user_area *ua = ofp_packet_user_area(pkt);

	if (odp_likely(ua->recursion_count++ < OFP_IP_OUTPUT_MAX_RECURSION))
		return ofp_ip_output(pkt, nh);

	OFP_DBG("Too many nested tunnels. Dropping outbound packet.");
	return OFP_PKT_DROP;
}

static void ofp_udp_checksum_insert(odp_packet_t pkt)
{
	uint32_t *len = 0;
	void *l4_ptr = odp_packet_l4_ptr(pkt, len);
	if(l4_ptr != NULL) {
		struct ofp_udphdr *udp = (struct ofp_udphdr *)l4_ptr;
		udp->uh_sum = 0;
		udp->uh_sum = ofp_in4_cksum(pkt);
		if (udp->uh_sum == 0)
			udp->uh_sum = 0xffff;
	}
}

static void ofp_tcp_checksum_insert(odp_packet_t pkt)
{
	uint32_t *len = 0;
	void *l4_ptr = odp_packet_l4_ptr(pkt, len);
	if(l4_ptr != NULL) {
		struct ofp_tcphdr *tcp = (struct ofp_tcphdr *)l4_ptr;
		tcp->th_sum = 0;
		tcp->th_sum = ofp_in4_cksum(pkt);
	}
}

static inline void ofp_l4_chksum_insert(odp_packet_t pkt,
					uint32_t offload_flags)
{
	struct ofp_packet_user_area *ua = ofp_packet_user_area(pkt);

	if (ua->chksum_flags & OFP_UDP_CHKSUM_INSERT) {
		if (!(offload_flags & OFP_IF_UDP_TX_CHKSUM))
			ofp_udp_checksum_insert(pkt);
		else
			odp_packet_l4_chksum_insert(pkt, 1);
		ua->chksum_flags &= ~OFP_UDP_CHKSUM_INSERT;
	} else if (ua->chksum_flags & OFP_TCP_CHKSUM_INSERT) {
		if (!(offload_flags & OFP_IF_TCP_TX_CHKSUM))
			ofp_tcp_checksum_insert(pkt);
		else
			odp_packet_l4_chksum_insert(pkt, 1);
		ua->chksum_flags &= ~OFP_TCP_CHKSUM_INSERT;
	}
}

static inline void ofp_chksum_insert(odp_packet_t pkt,
				     struct ofp_ip *ip,
				     uint32_t offload_flags)
{
	ofp_l4_chksum_insert(pkt, offload_flags);

	if (!(offload_flags & OFP_IF_IPV4_TX_CHKSUM)) {
		ip->ip_sum = 0;
		ip->ip_sum = ofp_cksum_iph(ip, ip->ip_hl);
	}
}

static inline enum ofp_return_code ofp_ip_output_common_inline(odp_packet_t pkt,
							       struct ofp_nh_entry *nh_param,
							       int is_local_out)
{
	struct ofp_ifnet *send_ctx = odp_packet_user_ptr(pkt);
	struct ip_out odata;
	enum ofp_return_code ret;
	struct ofp_ip *ip;

	OFP_HOOK(OFP_HOOK_OUT_IPv4, pkt, NULL, &ret);
	if (ret != OFP_PKT_CONTINUE) {
		OFP_DBG("OFP_HOOK_OUT_IPv4 returned %d", ret);
		return ret;
	}

	ip = odp_packet_l3_ptr(pkt, NULL);
	if (odp_unlikely(ip == NULL)) {
		odp_packet_l3_offset_set(pkt, 0);
		ip = odp_packet_l3_ptr(pkt, NULL);
	}
	odata.ip = ip;
	odata.dev_out = NULL;
	odata.vrf = send_ctx ? send_ctx->vrf : 0;
	odata.is_local_address = 0;
	odata.nh = nh_param;
	odata.insert_checksum = is_local_out;

	if ((ret = ofp_ip_output_find_route(&odata)) != OFP_PKT_CONTINUE)
		return ret;

	if (is_local_out)
		ofp_ip_id_assign(odata.ip);

	/* Fragmentation */
	if (odp_be_to_cpu_16(odata.ip->ip_len) > odata.dev_out->if_mtu) {
		OFP_DBG("Fragmentation required");
		if (odp_be_to_cpu_16(odata.ip->ip_off) & OFP_IP_DF) {
			ofp_icmp_error(pkt, OFP_ICMP_UNREACH,
				       OFP_ICMP_UNREACH_NEEDFRAG,
				       0, odata.dev_out->if_mtu);
			return OFP_PKT_DROP;
		}
		ofp_l4_chksum_insert(pkt, 0);
		return ofp_fragment_pkt(pkt, &odata);
	}
	return ofp_ip_output_continue(pkt, &odata);
}

static inline enum ofp_return_code ofp_ip_output_continue(odp_packet_t pkt,
						   struct ip_out *odata)
{
	enum ofp_return_code ret;

	if (odata->insert_checksum) {
		ofp_chksum_insert(pkt, odata->ip,
				  odata->dev_out->chksum_offload_flags);
	}

	switch (ofp_if_type(odata->dev_out)) {
	case OFP_IFT_GRE:
		return ofp_output_ipv4_to_gre(pkt, odata->dev_out);
		break;
	case OFP_IFT_VXLAN:
		if ((ret = ofp_ip_output_add_eth(pkt, odata)) != OFP_PKT_CONTINUE)
			return ret;
		return ofp_ip_output_vxlan(pkt, odata->dev_out);
	}

	if ((ret = ofp_ip_output_add_eth(pkt, odata)) != OFP_PKT_CONTINUE)
		return ret;

	return ofp_ip_output_send(pkt, odata);
}

enum ofp_return_code  ofp_ip_output_opt(odp_packet_t pkt, odp_packet_t opt,
	struct ofp_nh_entry *nh_param, int flags,
	struct ofp_ip_moptions *imo, struct inpcb *inp)
{
	(void)flags;
	(void)inp;
	struct ofp_nh_entry nh;
	struct ofp_ip *ip = (struct ofp_ip *)odp_packet_data(pkt), ip0;

	ip->ip_v = OFP_IPVERSION;
	ip->ip_hl = sizeof(*ip) >> 2;
	ip->ip_ttl = 255;
	ip->ip_off = 0;

	if (opt != ODP_PACKET_INVALID) {
		struct ofp_ipoption *p = (struct ofp_ipoption *)odp_packet_data(opt);
		int optlen = odp_packet_len(opt) - sizeof(p->ipopt_dst);

		if (optlen + ip->ip_len <= OFP_IP_MAXPACKET) {
			if (p->ipopt_dst.s_addr)
				ip->ip_dst = p->ipopt_dst;

			ip0 = *ip;
			odp_packet_push_head(pkt, optlen);
			ip = (struct ofp_ip *)odp_packet_data(pkt);
			*ip = ip0;
			memcpy(ip + 1, p->ipopt_list, optlen);
			ip->ip_v = OFP_IPVERSION;
			ip->ip_hl = (sizeof(struct ofp_ip) + optlen) >> 2;
			ip->ip_len += optlen;
		}
	}

	if (OFP_IN_MULTICAST(odp_be_to_cpu_32(ip->ip_dst.s_addr))) {
		if (imo != NULL) {
			ip->ip_ttl = imo->imo_multicast_ttl;
			if (imo->imo_multicast_vif != -1)
				ip->ip_src.s_addr =
					/* HJo ip_mcast_src ?
					   ip_mcast_src(imo->imo_multicast_vif) :*/
					OFP_INADDR_ANY;
		} else
			ip->ip_ttl = OFP_IP_DEFAULT_MULTICAST_TTL;

		if (imo != NULL && imo->imo_multicast_ifp != NULL) {
			nh.port = imo->imo_multicast_ifp->port;
			nh.vlan = imo->imo_multicast_ifp->vlan;
			nh.gw = ip->ip_dst.s_addr;
			nh_param = &nh;
			ip->ip_src.s_addr = imo->imo_multicast_ifp->ip_addr;
		}

	}

	ip->ip_len = odp_cpu_to_be_16(ip->ip_len);

	odp_packet_l2_offset_set(pkt, 0);
	odp_packet_l3_offset_set(pkt, 0);

	return ofp_ip_output(pkt, nh_param);
}

#ifdef INET6

enum ofp_return_code ofp_ip6_send(odp_packet_t pkt,
				  struct ofp_nh6_entry *nh_param)
{
	ofp_packet_user_area_reset(pkt);
	return ofp_ip6_output(pkt, nh_param);
}

enum ofp_return_code ofp_ip6_output(odp_packet_t pkt,
	struct ofp_nh6_entry *nh_param)
{
	struct ofp_ip6_hdr *ip6;
	uint32_t l2_size;
	uint32_t hlen;
	void *l2_addr;
	uint32_t flags;
	struct ofp_nh6_entry *nh;
	uint16_t vlan;
	struct ofp_ifnet *send_ctx = odp_packet_user_ptr(pkt);
	struct ofp_ifnet *dev_out = NULL;
	int vrf = send_ctx ? send_ctx->vrf : 0;
	uint8_t is_local_address = 0;
	uint8_t *mac = NULL;
	enum ofp_return_code ret;

	if (odp_packet_l3_offset(pkt) == ODP_PACKET_OFFSET_INVALID)
		odp_packet_l3_offset_set(pkt, 0);

	OFP_HOOK(OFP_HOOK_OUT_IPv6, pkt, NULL, &ret);
	if (ret != OFP_PKT_CONTINUE) {
		OFP_DBG("OFP_HOOK_OUT_IPv6 returned %d", ret);
		return ret;
	}

	ip6 = (struct ofp_ip6_hdr *) odp_packet_l3_ptr(pkt, NULL);
	if (odp_unlikely(ip6 == NULL))
		return OFP_PKT_DROP;

	if (nh_param) {
		nh = nh_param;
		vlan = nh->vlan;
	} else {
		nh = ofp_get_next_hop6(vrf,
					 ip6->ip6_dst.ofp_s6_addr, &flags);
		if (nh) {
			vlan = nh->vlan;
		} else
			return OFP_PKT_DROP;
	}

	dev_out = ofp_get_ifnet(nh->port, vlan);

	if (!dev_out)
		return OFP_PKT_DROP;

	/* GRE */
	if (ofp_if_type(dev_out) == OFP_IFT_GRE)
		return ofp_output_ipv6_to_gre(pkt, dev_out);

	if (!vlan)
		l2_size = sizeof(struct ofp_ether_header);
	else
		l2_size = sizeof(struct ofp_ether_vlan_header);

	hlen = 0;
	if (odp_packet_l4_offset(pkt) != ODP_PACKET_OFFSET_INVALID)
		hlen = odp_packet_l4_offset(pkt) - odp_packet_l3_offset(pkt);
	l2_addr = trim_for_output(pkt, l2_size, hlen);
	if (odp_unlikely(l2_addr == NULL))
		return OFP_PKT_DROP;

	/* MAC address for the destination */
	if (ofp_ip6_equal(dev_out->ip6_addr, ip6->ip6_dst.ofp_s6_addr) ||
	    ofp_if_type(dev_out) == OFP_IFT_LOOP) {
		is_local_address = 1;
		mac = dev_out->mac;
	} else {
		mac = nh->mac;

		if (!(((uint32_t *)mac)[0] || mac[4] || mac[5])) {
			ofp_set_route6_params(OFP_ROUTE6_ADD, 0 /*vrf*/,
					      dev_out->vlan, dev_out->port,
					      ip6->ip6_dst.ofp_s6_addr,
					      128 /*masklen*/,
					      ofp_in6addr_any.ofp_s6_addr,
					      OFP_RTF_HOST);

			if (ofp_nd6_ns_output(dev_out, nh->gw,
				ip6->ip6_dst.ofp_s6_addr) == OFP_PKT_DROP) {
				OFP_ERR("MAC not set: gw = %x %x", nh->gw[0],
					nh->gw[15]);
				return OFP_PKT_DROP;
			}
			return ofp_route_save_ipv6_pkt(pkt,
				&ip6->ip6_dst.ofp_s6_addr[0],
				dev_out);
		}
	}

	if (!vlan) {
		struct ofp_ether_header *eth =
			(struct ofp_ether_header *)l2_addr;

		memcpy(eth->ether_dhost, mac, OFP_ETHER_ADDR_LEN);
		memcpy(eth->ether_shost, dev_out->mac, OFP_ETHER_ADDR_LEN);
		eth->ether_type = odp_cpu_to_be_16(OFP_ETHERTYPE_IPV6);
	} else {
		struct ofp_ether_vlan_header *eth_vlan =
			(struct ofp_ether_vlan_header *)l2_addr;

		memcpy(eth_vlan->evl_dhost, mac, OFP_ETHER_ADDR_LEN);
		memcpy(eth_vlan->evl_shost, dev_out->mac, OFP_ETHER_ADDR_LEN);
		eth_vlan->evl_encap_proto =
				odp_cpu_to_be_16(OFP_ETHERTYPE_VLAN);
		eth_vlan->evl_tag = odp_cpu_to_be_16(vlan);
		eth_vlan->evl_proto = odp_cpu_to_be_16(OFP_ETHERTYPE_IPV6);
	}

	if (is_local_address) {
		return send_pkt_loop(dev_out, pkt);
	} else {
		return send_pkt_out(dev_out, pkt);
	}
}
#endif /* INET6 */

enum ofp_return_code ofp_packet_input(odp_packet_t pkt,
	odp_queue_t in_queue, ofp_pkt_processing_func pkt_func)
{
	struct ofp_ifnet *ifnet = NULL;
	odp_pktio_t pktio;
	int res;

	/* Packets from VXLAN interfaces do not have an outq even
	 * they have a valid pktio. Use loopback context instead. */
	if (in_queue != ODP_QUEUE_INVALID)
		ifnet = (struct ofp_ifnet *)odp_queue_context(in_queue);

	if (odp_likely(ifnet == NULL)) {
		pktio = odp_packet_input(pkt);
		if (odp_likely(pktio != ODP_PKTIO_INVALID)) {
			/* pkt received from eth interface */
			ifnet = ofp_get_ifnet_pktio(pktio);
		} else {
			/* loopback and cunit error */
			odp_packet_free(pkt);
			return OFP_PKT_DROP;
		}
	}

	odp_packet_user_ptr_set(pkt, ifnet);

	/*
	 * Packets from VXLAN ifnets are looped from OFP and have
	 * data stored in the user area.
	 */
	if (ofp_if_type(ifnet) != OFP_IFT_VXLAN) {
		ofp_packet_user_area_reset(pkt);
	}

	if (ifnet->chksum_offload_flags & OFP_IF_IPV4_RX_CHKSUM)
		ofp_packet_user_area(pkt)->chksum_flags |=
			OFP_L3_CHKSUM_STATUS_VALID;

	if (ifnet->chksum_offload_flags & 
		(OFP_IF_UDP_RX_CHKSUM | OFP_IF_TCP_RX_CHKSUM))
		ofp_packet_user_area(pkt)->chksum_flags |=
			OFP_L4_CHKSUM_STATUS_VALID;

	OFP_DEBUG_PACKET(OFP_DEBUG_PKT_RECV_NIC, pkt, ifnet->port);

	OFP_UPDATE_PACKET_STAT(rx_fp, 1);

	OFP_UPDATE_PACKET_LATENCY_STAT(1);

	/* data link layer processing */
	res = pkt_func(&pkt);

	if (res == OFP_PKT_DROP)
		odp_packet_free(pkt);

	if (res != OFP_PKT_CONTINUE)
		return res;

	/* Enqueue the packet for slowpath */
	return ofp_sp_input(pkt, ifnet);
}

enum ofp_return_code ofp_sp_input(odp_packet_t pkt,
	struct ofp_ifnet *ifnet)
{
#ifdef SP
	/* Virtual iface may not have spq. */
	if (!ifnet->spq_def) {
		odp_packet_free(pkt);
		return OFP_PKT_DROP;
	}

	if (odp_queue_enq(ifnet->spq_def, odp_packet_to_event(pkt)) < 0) {
		odp_packet_free(pkt);
		return OFP_PKT_DROP;
	}
	return OFP_PKT_PROCESSED;
#else
	(void)ifnet;

	odp_packet_free(pkt);
	return OFP_PKT_DROP;
#endif
}
