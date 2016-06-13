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
#include "api/ofp_init.h"

extern odp_pool_t ofp_packet_pool;

void *default_event_dispatcher(void *arg)
{
	odp_event_t ev;
	odp_packet_t pkt;
	odp_queue_t in_queue;
	odp_event_t events[OFP_EVT_RX_BURST_SIZE];
	int event_idx = 0;
	int event_cnt = 0;
	ofp_pkt_processing_func pkt_func = (ofp_pkt_processing_func)arg;
	odp_bool_t *is_running = NULL;

	if (ofp_init_local()) {
		OFP_ERR("ofp_init_local failed");
		return NULL;
	}

	is_running = ofp_get_processing_state();
	if (is_running == NULL) {
		OFP_ERR("ofp_get_processing_state failed");
		ofp_term_local();
		return NULL;
	}

	/* PER CORE DISPATCHER */
	while (*is_running) {
		event_cnt = odp_schedule_multi(&in_queue, ODP_SCHED_WAIT,
					 events, OFP_EVT_RX_BURST_SIZE);
		for (event_idx = 0; event_idx < event_cnt; event_idx++) {
			ev = events[event_idx];

			if (ev == ODP_EVENT_INVALID)
				continue;

			if (odp_event_type(ev) == ODP_EVENT_TIMEOUT) {
				ofp_timer_handle(ev);
				continue;
			}

			if (odp_event_type(ev) == ODP_EVENT_PACKET) {
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

			OFP_ERR("Unexpected event type: %u", odp_event_type(ev));

			/* Free events by type */
			if (odp_event_type(ev) == ODP_EVENT_BUFFER) {
				odp_buffer_free(odp_buffer_from_event(ev));
				continue;
			}

			if (odp_event_type(ev) == ODP_EVENT_CRYPTO_COMPL) {
				odp_crypto_compl_free(
					odp_crypto_compl_from_event(ev));
				continue;
			}

		}
		ofp_send_pending_pkt();
	}

	if (ofp_term_local())
		OFP_ERR("ofp_term_local failed");

	return NULL;
}

enum ofp_return_code ofp_eth_vlan_processing(odp_packet_t pkt)
{
	uint16_t vlan = 0, ethtype;
	struct ofp_ether_header *eth;
	struct ofp_ifnet *ifnet = odp_packet_user_ptr(pkt);

	eth = (struct ofp_ether_header *)odp_packet_l2_ptr(pkt, NULL);
#ifndef OFP_PERFORMANCE
	if (odp_unlikely(eth == NULL)) {
		OFP_DBG("eth is NULL");
		return OFP_PKT_DROP;
	}

	if (odp_unlikely(odp_packet_l3_ptr(pkt, NULL) == NULL ||
		(uintptr_t) odp_packet_l3_ptr(pkt, NULL) !=
			(uintptr_t)odp_packet_l2_ptr(pkt, NULL) +
				sizeof(struct ofp_ether_header))) {
		OFP_DBG("odp_packet_l3_offset_set");
		odp_packet_l3_offset_set(pkt, sizeof(struct ofp_ether_header));
	}
#endif
	ethtype = odp_be_to_cpu_16(eth->ether_type);

	if (ethtype == OFP_ETHERTYPE_VLAN) {
		struct ofp_ether_vlan_header *vlan_hdr;

		vlan_hdr = (struct ofp_ether_vlan_header *)eth;
		vlan = OFP_EVL_VLANOFTAG(odp_be_to_cpu_16(vlan_hdr->evl_tag));
		ethtype = odp_be_to_cpu_16(vlan_hdr->evl_proto);
		ifnet = ofp_get_ifnet(ifnet->port, vlan);
		if (!ifnet)
			return OFP_PKT_DROP;
		if (odp_likely(ifnet->port != VXLAN_PORTS))
			odp_packet_user_ptr_set(pkt, ifnet);
#ifndef OFP_PERFORMANCE
		odp_packet_l3_offset_set(pkt, sizeof(struct ofp_ether_vlan_header));
#endif
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
ipv4_transport_classifier(odp_packet_t pkt, uint8_t ip_proto)
{
	struct ofp_ip *ip = (struct ofp_ip *)odp_packet_l3_ptr(pkt, NULL);

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
ipv6_transport_classifier(odp_packet_t pkt, uint8_t ip6_nxt)
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

enum ofp_return_code ofp_udp4_processing(odp_packet_t pkt)
{
	struct ofp_ip *ip = (struct ofp_ip *)odp_packet_l3_ptr(pkt, NULL);

	if (odp_unlikely(ofp_cksum_buffer((uint16_t *) ip, ip->ip_hl<<2)))
		return OFP_PKT_DROP;

	if (odp_be_to_cpu_16(ip->ip_off) & 0x3fff) {
		OFP_UPDATE_PACKET_STAT(rx_ip_frag, 1);

		pkt = ofp_ip_reass(pkt);
		if (pkt == ODP_PACKET_INVALID)
			return OFP_PKT_ON_HOLD;

		OFP_UPDATE_PACKET_STAT(rx_ip_reass, 1);

		ip = (struct ofp_ip *)odp_packet_l3_ptr(pkt, NULL);
	}

	return ofp_inetsw[ofp_ip_protox_udp].pr_input(pkt, ip->ip_hl << 2);
}

enum ofp_return_code ofp_tcp4_processing(odp_packet_t pkt)
{
	struct ofp_ip *ip = (struct ofp_ip *)odp_packet_l3_ptr(pkt, NULL);

	if (odp_unlikely(ofp_cksum_buffer((uint16_t *) ip, ip->ip_hl<<2)))
		return OFP_PKT_DROP;

	if (odp_be_to_cpu_16(ip->ip_off) & 0x3fff) {
		OFP_UPDATE_PACKET_STAT(rx_ip_frag, 1);

		pkt = ofp_ip_reass(pkt);
		if (pkt == ODP_PACKET_INVALID)
			return OFP_PKT_ON_HOLD;

		OFP_UPDATE_PACKET_STAT(rx_ip_reass, 1);

		ip = (struct ofp_ip *)odp_packet_l3_ptr(pkt, NULL);
	}

	return ofp_inetsw[ofp_ip_protox_tcp].pr_input(pkt, ip->ip_hl << 2);
}

enum ofp_return_code ofp_ipv4_processing(odp_packet_t pkt)
{
	int res;
	int protocol = IS_IPV4;
	uint32_t flags;
	struct ofp_ip *ip;
	struct ofp_nh_entry *nh;
	struct ofp_ifnet *dev = odp_packet_user_ptr(pkt);
	uint32_t is_ours;

	ip = (struct ofp_ip *)odp_packet_l3_ptr(pkt, NULL);

	if (odp_unlikely(ip == NULL)) {
		OFP_DBG("ip is NULL");
		return OFP_PKT_DROP;
	}

	if (odp_unlikely(!PHYS_PORT(dev->port))) {
		switch (dev->port) {
		case GRE_PORTS:
		case LOCAL_PORTS:
			/* Doesn't happen. */
			break;
		case VXLAN_PORTS: {
			/* Look for the correct device. */
			struct vxlan_user_data *saved = odp_packet_user_area(pkt);
			dev = ofp_get_ifnet(VXLAN_PORTS, saved->vni);
			if (!dev)
				return OFP_PKT_DROP;
			break;
		}
		}
	}

#ifndef OFP_PERFORMANCE
	if (odp_unlikely(ip->ip_v != OFP_IPVERSION))
		return OFP_PKT_DROP;
	if (odp_unlikely(ofp_cksum_buffer((uint16_t *) ip, ip->ip_hl<<2)))
		return OFP_PKT_DROP;

	/* TODO: handle broadcast */
	if (dev->bcast_addr == ip->ip_dst.s_addr)
		return OFP_PKT_DROP;
#endif

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
			OFP_UPDATE_PACKET_STAT(rx_ip_frag, 1);

			pkt = ofp_ip_reass(pkt);
			if (pkt == ODP_PACKET_INVALID)
				return OFP_PKT_ON_HOLD;

			OFP_UPDATE_PACKET_STAT(rx_ip_reass, 1);

			ip = (struct ofp_ip *)odp_packet_l3_ptr(pkt, NULL);
		}

		OFP_HOOK(OFP_HOOK_LOCAL, pkt, &protocol, &res);
		if (res != OFP_PKT_CONTINUE) {
			OFP_DBG("OFP_HOOK_LOCAL returned %d", res);
			return res;
		}

		OFP_HOOK(OFP_HOOK_LOCAL_IPv4, pkt, NULL, &res);
		if (res != OFP_PKT_CONTINUE) {
			OFP_DBG("OFP_HOOK_LOCAL_IPv4 returned %d", res);
			return res;
		}

		return ipv4_transport_classifier(pkt, ip->ip_p);
	}

	OFP_HOOK(OFP_HOOK_FWD_IPv4, pkt, nh, &res);
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
		ofp_icmp_error(pkt, OFP_ICMP_TIMXCEED,
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
		ofp_icmp_error(pkt, OFP_ICMP_REDIRECT,
				OFP_ICMP_REDIRECT_HOST, nh->gw, 0);
	}
#endif

	return ofp_ip_output(pkt, nh);
}

#ifdef INET6
enum ofp_return_code ofp_ipv6_processing(odp_packet_t pkt)
{
	int res;
	int protocol = IS_IPV6;
	uint32_t flags;
	struct ofp_ip6_hdr *ipv6;
	struct ofp_nh6_entry *nh;
	struct ofp_ifnet *dev = odp_packet_user_ptr(pkt);

	ipv6 = (struct ofp_ip6_hdr *)odp_packet_l3_ptr(pkt, NULL);

	if (odp_unlikely(ipv6 == NULL))
		return OFP_PKT_DROP;

	/* is ipv6->dst_addr one of my IPv6 addresses from this interface*/
	if (ofp_ip6_equal(dev->ip6_addr, ipv6->ip6_dst.ofp_s6_addr) ||
		OFP_IN6_IS_SOLICITED_NODE_MC(ipv6->ip6_dst, dev->ip6_addr) ||
		(memcmp((const void *)((uintptr_t)dev->link_local + 8),
		(const void *)((uintptr_t)ipv6->ip6_dst.ofp_s6_addr + 8),
			2 * sizeof(uint32_t)) == 0)) {

		OFP_HOOK(OFP_HOOK_LOCAL, pkt, &protocol, &res);
		if (res != OFP_PKT_CONTINUE) {
			OFP_DBG("OFP_HOOK_LOCAL returned %d", res);
			return res;
		}

		OFP_HOOK(OFP_HOOK_LOCAL_IPv6, pkt, NULL, &res);
		if (res != OFP_PKT_CONTINUE) {
			OFP_DBG("OFP_HOOK_LOCAL_IPv6 returned %d", res);
			return res;
		}

		return ipv6_transport_classifier(pkt, ipv6->ofp_ip6_nxt);

	}

	OFP_HOOK(OFP_HOOK_FWD_IPv6, pkt, NULL, &res);
	if (res != OFP_PKT_CONTINUE) {
		OFP_DBG("OFP_HOOK_FWD_IPv6 returned %d", res);
		return res;
	}

	nh = ofp_get_next_hop6(dev->vrf, ipv6->ip6_dst.ofp_s6_addr, &flags);
	if (nh == NULL)
		return OFP_PKT_CONTINUE;

	return ofp_ip6_output(pkt, nh);
}
#endif /* INET6 */

enum ofp_return_code ofp_gre_processing(odp_packet_t pkt)
{
	struct ofp_ip *ip = (struct ofp_ip *)odp_packet_l3_ptr(pkt, NULL);

	if (odp_unlikely(ofp_cksum_buffer((uint16_t *) ip, ip->ip_hl<<2)))
		return OFP_PKT_DROP;

	if (odp_be_to_cpu_16(ip->ip_off) & 0x3fff) {
		OFP_UPDATE_PACKET_STAT(rx_ip_frag, 1);

		pkt = ofp_ip_reass(pkt);
		if (pkt == ODP_PACKET_INVALID)
			return OFP_PKT_ON_HOLD;

		OFP_UPDATE_PACKET_STAT(rx_ip_reass, 1);

		ip = (struct ofp_ip *)odp_packet_l3_ptr(pkt, NULL);
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

enum ofp_return_code ofp_arp_processing(odp_packet_t pkt)
{
	struct ofp_arphdr *arp;
	struct ofp_ifnet *dev = odp_packet_user_ptr(pkt);
	struct ofp_ifnet *outdev = dev;
	uint16_t vlan = dev->vlan;
	uint8_t inner_from_mac[OFP_ETHER_ADDR_LEN];
	uint32_t is_ours;

	arp = (struct ofp_arphdr *)odp_packet_l3_ptr(pkt, NULL);

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
	if (odp_unlikely(!PHYS_PORT(dev->port))) {
		switch (dev->port) {
		case GRE_PORTS:
			/* Never happens. */
			break;
		case VXLAN_PORTS: {
			ofp_vxlan_update_devices(pkt, arp, &vlan, &dev, &outdev,
						 inner_from_mac);
			break;
		}
		} /* switch */
	}

	is_ours = dev->ip_addr && dev->ip_addr == (ofp_in_addr_t)(arp->ip_dst);
	if (!is_ours) {
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
		void *l2_addr = odp_packet_l2_ptr(pkt, NULL);
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

		if (odp_unlikely(!PHYS_PORT(dev->port))) {
			switch (dev->port) {
			case GRE_PORTS:
				/* Never happens. */
				break;
			case VXLAN_PORTS: {
				/* Restore the original vxlan header and
				   update the addresses */
				ofp_vxlan_restore_and_update_header
					(pkt, outdev, inner_from_mac);
				break;
			}
			} /* switch */
		} /* not phys port */

		return send_pkt_out(outdev, pkt);
	}
	return OFP_PKT_CONTINUE;
}

#define ETH_WITH_VLAN(_dev) (_dev->vlan && _dev->port != VXLAN_PORTS)
#define ETH_WITHOUT_VLAN(_vlan, _port) (_vlan == 0 || _port == VXLAN_PORTS)

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

	pkt = odp_packet_alloc(ofp_packet_pool, size);
	if (pkt == ODP_PACKET_INVALID) {
		OFP_ERR("odp_packet_alloc falied");
		return;
	}

	memcpy(odp_packet_data(pkt), buf, size);

	if (odp_unlikely(dev->port == VXLAN_PORTS)) {
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

	if (dev->port == GRE_PORTS) {
		OFP_ERR("Send frame on GRE port");
		return OFP_PKT_DROP;
	}

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
			      struct ofp_ifnet *dev_out,
			      uint8_t is_local_address)
{
	struct ofp_ip *ip, *ip_new;
	uint16_t vlan = dev_out->vlan;
	int tot_len, pl_len, seg_len, pl_pos, flen, hwlen;
	uint16_t frag, frag_new;
	uint8_t *payload_new;
	uint32_t payload_offset;
	odp_pool_t pkt_pool;
	odp_packet_t pkt_new;
	struct ofp_ether_header *eth, *eth_new;
	struct ofp_ether_vlan_header *eth_vlan, *eth_new_vlan;
	int ret = OFP_PKT_PROCESSED;


	if (!vlan)
		eth = odp_packet_l2_ptr(pkt, NULL);
	else
		eth_vlan = odp_packet_l2_ptr(pkt, NULL);

	ip = (struct ofp_ip *)odp_packet_l3_ptr(pkt, NULL);

	pkt_pool = ofp_packet_pool;
	tot_len = odp_be_to_cpu_16(ip->ip_len);
	pl_len = tot_len - (ip->ip_hl<<2);
	seg_len = (dev_out->if_mtu - sizeof(struct ofp_ip)) & 0xfff8;
	pl_pos = 0;
	frag = odp_be_to_cpu_16(ip->ip_off);
	payload_offset = odp_packet_l3_offset(pkt) + (ip->ip_hl<<2);

	OFP_UPDATE_PACKET_STAT(tx_eth_frag, 1);

	while (pl_pos < pl_len) {
		flen = (pl_len - pl_pos) > seg_len ?
			seg_len : (pl_len - pl_pos);
		hwlen = flen + sizeof(struct ofp_ip) +
			(vlan ? sizeof(struct ofp_ether_vlan_header) :
			 sizeof(struct ofp_ether_header));

		pkt_new = odp_packet_alloc(pkt_pool, hwlen);
		if (pkt_new == ODP_PACKET_INVALID) {
			OFP_ERR("odp_packet_alloc failed");
			return OFP_PKT_DROP;
		}
		odp_packet_user_ptr_set(pkt_new, odp_packet_user_ptr(pkt));

		odp_packet_l2_offset_set(pkt_new, 0);
		if (vlan) {
			eth_new_vlan = odp_packet_l2_ptr(pkt_new, NULL);
			*eth_new_vlan = *eth_vlan;
			ip_new = (struct ofp_ip *)(eth_new_vlan + 1);
			odp_packet_l3_offset_set(pkt_new,
						 OFP_ETHER_HDR_LEN +
						 OFP_ETHER_VLAN_ENCAP_LEN);
		} else {
			eth_new = odp_packet_l2_ptr(pkt_new, NULL);
			*eth_new = *eth;
			ip_new = (struct ofp_ip *)(eth_new + 1);
			odp_packet_l3_offset_set(pkt_new,
						 OFP_ETHER_HDR_LEN);
		}

		*ip_new = *ip;

		payload_new = (uint8_t *)(ip_new + 1);

		if (odp_packet_copy_to_mem(pkt, payload_offset + pl_pos,
					    flen, payload_new) < 0) {
			OFP_ERR("odp_packet_copy_to_mem failed");
			return OFP_PKT_DROP;
		};

		ip_new->ip_len = odp_cpu_to_be_16(flen + sizeof(*ip_new));

		frag_new = frag + pl_pos/8;
		pl_pos += flen;
		if (pl_pos < pl_len)
			frag_new |= OFP_IP_MF;
		ip_new->ip_off = odp_cpu_to_be_16(frag_new);

		ip_new->ip_sum = 0;
		ip_new->ip_sum = ofp_cksum_buffer((uint16_t *)ip_new,
					       sizeof(*ip_new));

		if (is_local_address)
			ret  = send_pkt_loop(dev_out, pkt_new);
		else
			ret = send_pkt_out(dev_out, pkt_new);

		if (ret == OFP_PKT_DROP) {
			odp_packet_free(pkt_new);
			return OFP_PKT_DROP;
		}
	}

	odp_packet_free(pkt);
	return OFP_PKT_PROCESSED;
}

static enum ofp_return_code ofp_output_ipv4_to_gre(
	odp_packet_t pkt, struct ofp_ifnet *dev_gre,
	uint16_t vrfid,	struct ofp_nh_entry **nh_new)
{
	struct ofp_ip	*ip;
	struct ofp_greip *greip;
	uint32_t flags;
	uint8_t	l2_size = 0;
	int32_t	offset;

	*nh_new = ofp_get_next_hop(vrfid, dev_gre->ip_remote, &flags);

	if (*nh_new == NULL)
		return OFP_PKT_DROP;

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
	greip->gi_i.ip_id = ip->ip_id;
	greip->gi_i.ip_off = 0;
	greip->gi_i.ip_ttl = ip->ip_ttl;
	greip->gi_i.ip_p = OFP_IPPROTO_GRE;
	greip->gi_i.ip_sum = 0;
	greip->gi_i.ip_src.s_addr = dev_gre->ip_local;
	greip->gi_i.ip_dst.s_addr = dev_gre->ip_remote;

	return OFP_PKT_CONTINUE;
}

static enum ofp_return_code ofp_gre_update_target(odp_packet_t pkt,
						  struct ip_out *odata)
{
	struct ofp_nh_entry *nh_new = NULL;

	if (ofp_output_ipv4_to_gre(pkt, odata->dev_out, odata->vrf,
				   &nh_new) == OFP_PKT_DROP)
		return OFP_PKT_DROP;

	odata->nh = nh_new;
	odata->gw = odata->nh->gw;
	odata->vlan = odata->nh->vlan;
	odata->out_port = odata->nh->port;
	odata->ip = odp_packet_l3_ptr(pkt, NULL);

	odata->dev_out = ofp_get_ifnet(odata->out_port, odata->vlan);
	if (!odata->dev_out)
		return OFP_PKT_DROP;

	return OFP_PKT_CONTINUE;
}

static enum ofp_return_code ofp_ip_output_add_eth(odp_packet_t pkt,
						  struct ip_out *odata)
{
	uint8_t l2_size = 0;
	void *l2_addr;

	if (!odata->gw) /* link local */
		odata->gw = odata->ip->ip_dst.s_addr;

	if (ETH_WITHOUT_VLAN(odata->vlan, odata->out_port))
		l2_size = sizeof(struct ofp_ether_header);
	else
		l2_size = sizeof(struct ofp_ether_vlan_header);

	if (odp_packet_l2_offset(pkt) + l2_size == odp_packet_l3_offset(pkt)) {
		l2_addr = odp_packet_l2_ptr(pkt, NULL);
	} else if (odp_packet_l3_offset(pkt) >= l2_size) {
		odp_packet_l2_offset_set(pkt,
					odp_packet_l3_offset(pkt) - l2_size);
		l2_addr = odp_packet_l2_ptr(pkt, NULL);
	} else {
		l2_addr = odp_packet_push_head(pkt,
					l2_size - odp_packet_l3_offset(pkt));
		odp_packet_l2_offset_set(pkt, 0);
		odp_packet_l3_offset_set(pkt, l2_size);
		odp_packet_l4_offset_set(pkt, l2_size + (odata->ip->ip_hl<<2));
	}

	if (odp_unlikely(l2_addr == NULL)) {
		OFP_DBG("l2_addr == NULL");
		return OFP_PKT_DROP;
	}

	if (ETH_WITHOUT_VLAN(odata->vlan, odata->out_port)) {
		struct ofp_ether_header *eth =
				(struct ofp_ether_header *)l2_addr;
		uint32_t addr = odp_be_to_cpu_32(odata->ip->ip_dst.s_addr);

		if (OFP_IN_MULTICAST(addr)) {
			eth->ether_dhost[0] = 0x01;
			eth->ether_dhost[1] = 0x00;
			eth->ether_dhost[2] = 0x5e;
			eth->ether_dhost[3] = (addr >> 16) & 0x7f;
			eth->ether_dhost[4] = (addr >> 8) & 0xff;
			eth->ether_dhost[5] = addr & 0xff;
		} else if (odata->dev_out->ip_addr == odata->ip->ip_dst.s_addr ||
			   odata->dev_out->port == LOCAL_PORTS) {
			odata->is_local_address = 1;
			ofp_copy_mac(eth->ether_dhost, &(odata->dev_out->mac[0]));
		} else if (ofp_get_mac(odata->dev_out, odata->gw, eth->ether_dhost) < 0) {
			send_arp_request(odata->dev_out, odata->gw);
			return ofp_arp_save_ipv4_pkt(pkt, odata->nh,
						     odata->gw, odata->dev_out);
		}

		ofp_copy_mac(eth->ether_shost, odata->dev_out->mac);
		eth->ether_type = odp_cpu_to_be_16(OFP_ETHERTYPE_IP);
	} else {
		struct ofp_ether_vlan_header *eth_vlan =
			(struct ofp_ether_vlan_header *)l2_addr;
		uint32_t addr = odp_be_to_cpu_32(odata->ip->ip_dst.s_addr);

		if (OFP_IN_MULTICAST(addr)) {
			eth_vlan->evl_dhost[0] = 0x01;
			eth_vlan->evl_dhost[1] = 0x00;
			eth_vlan->evl_dhost[2] = 0x5e;
			eth_vlan->evl_dhost[3] = (addr >> 16) & 0x7f;
			eth_vlan->evl_dhost[4] = (addr >> 8) & 0xff;
			eth_vlan->evl_dhost[5] = addr & 0xff;
		} else if (odata->dev_out->ip_addr == odata->ip->ip_dst.s_addr ||
			   odata->dev_out->port == LOCAL_PORTS) {
			odata->is_local_address = 1;
			ofp_copy_mac(eth_vlan->evl_dhost, odata->dev_out->mac);
		} else if (ofp_get_mac(odata->dev_out,
				odata->gw, eth_vlan->evl_dhost) < 0) {
			send_arp_request(odata->dev_out, odata->gw);
			return ofp_arp_save_ipv4_pkt(pkt, odata->nh,
						     odata->gw, odata->dev_out);
		}

		ofp_copy_mac(eth_vlan->evl_shost, odata->dev_out->mac);
		eth_vlan->evl_encap_proto = odp_cpu_to_be_16(
							OFP_ETHERTYPE_VLAN);
		eth_vlan->evl_tag = odp_cpu_to_be_16(odata->vlan);
		eth_vlan->evl_proto = odp_cpu_to_be_16(OFP_ETHERTYPE_IP);
	}

	return OFP_PKT_CONTINUE;
}


static enum ofp_return_code ofp_ip_output_send(odp_packet_t pkt,
					       struct ip_out *odata)
{
	/* Fragmentation */
	if (odp_be_to_cpu_16(odata->ip->ip_len) > odata->dev_out->if_mtu) {
		OFP_DBG("Fragmentation required");
		if (odp_be_to_cpu_16(odata->ip->ip_off) & OFP_IP_DF) {
			ofp_icmp_error(pkt, OFP_ICMP_UNREACH,
					OFP_ICMP_UNREACH_NEEDFRAG,
					0, odata->dev_out->if_mtu);
			return OFP_PKT_DROP;
		}
		return ofp_fragment_pkt(pkt, odata->dev_out, odata->is_local_address);
	}

#ifndef OFP_PERFORMANCE
	odata->ip->ip_sum = 0;
	odata->ip->ip_sum = ofp_cksum_buffer((uint16_t *)odata->ip, odata->ip->ip_hl<<2);
#endif
	if (odata->is_local_address) {
		return send_pkt_loop(odata->dev_out, pkt);
	} else {
		return send_pkt_out(odata->dev_out, pkt);
	}
}

static enum ofp_return_code ofp_ip_output_find_route(odp_packet_t pkt,
						     struct ip_out *odata)
{
	uint32_t flags;

	if (odp_packet_l3_offset(pkt) == ODP_PACKET_OFFSET_INVALID)
		odp_packet_l3_offset_set(pkt, 0);
	odata->ip = (struct ofp_ip *) odp_packet_l3_ptr(pkt, NULL);
	if (odp_unlikely(odata->ip == NULL)) {
		OFP_DBG("ip is NULL");
		return OFP_PKT_DROP;
	}

	if (!odata->nh) {
		odata->nh = ofp_get_next_hop(odata->vrf, odata->ip->ip_dst.s_addr, &flags);
		if (!odata->nh)
			return OFP_PKT_DROP;
	}

	odata->gw = odata->nh->gw;
	odata->vlan = odata->nh->vlan;
	odata->out_port = odata->nh->port;

	odata->dev_out = ofp_get_ifnet(odata->out_port, odata->vlan);

	if (!odata->dev_out) {
		OFP_DBG("!dev_out");
		return OFP_PKT_DROP;
	}

	/* User has not filled in the source addess */
	if (odata->ip->ip_src.s_addr == 0)
		odata->ip->ip_src.s_addr = odata->dev_out->ip_addr;

	return OFP_PKT_CONTINUE;
}

enum ofp_return_code ofp_ip_output(odp_packet_t pkt,
	struct ofp_nh_entry *nh_param)
{
	struct ofp_ifnet *send_ctx = odp_packet_user_ptr(pkt);
	struct ip_out odata;
	enum ofp_return_code ret;

	OFP_HOOK(OFP_HOOK_OUT_IPv4, pkt, NULL, &ret);
	if (ret != OFP_PKT_CONTINUE) {
		OFP_DBG("OFP_HOOK_OUT_IPv4 returned %d", ret);
		return ret;
	}

	odata.dev_out = NULL;
	odata.vrf = send_ctx ? send_ctx->vrf : 0;
	odata.is_local_address = 0;
	odata.nh = nh_param;

	if ((ret = ofp_ip_output_find_route(pkt, &odata)) != OFP_PKT_CONTINUE)
		return ret;

	switch (odata.out_port) {
	case GRE_PORTS:
		if ((ret = ofp_gre_update_target(pkt, &odata)) != OFP_PKT_CONTINUE)
			return ret;
		break;
	case VXLAN_PORTS:
		if ((ret = ofp_ip_output_add_eth(pkt, &odata)) != OFP_PKT_CONTINUE)
			return ret;
		if ((ret = ofp_ip_output_vxlan(pkt, &odata)) != OFP_PKT_CONTINUE)
			return ret;
		if ((ret = ofp_ip_output_find_route(pkt, &odata)) != OFP_PKT_CONTINUE)
			return ret;
		break;
	}

	if ((ret = ofp_ip_output_add_eth(pkt, &odata)) != OFP_PKT_CONTINUE)
			return ret;

	return ofp_ip_output_send(pkt, &odata);
}

enum ofp_return_code  ofp_ip_output_opt(odp_packet_t pkt, odp_packet_t opt,
	struct ofp_nh_entry *nh_param, int flags,
	struct ofp_ip_moptions *imo, struct inpcb *inp)
{
	(void)flags;
	(void)inp;
	struct ofp_nh_entry nh;
	struct ofp_ip *ip = (struct ofp_ip *)odp_packet_data(pkt), ip0;
	static uint16_t ip_newid = 0;

	ip->ip_v = OFP_IPVERSION;
	ip->ip_hl = sizeof(*ip) >> 2;
	ip->ip_ttl = 255;
	ip->ip_off = 0;
	ip->ip_id = ip_newid++;

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
static enum ofp_return_code ofp_output_ipv6_to_gre(
	odp_packet_t pkt, struct ofp_ifnet *dev_gre,
	uint16_t vrfid,	struct ofp_nh_entry **nh_new)
{
	struct ofp_ip6_hdr *ip6;
	struct ofp_greip *greip;
	uint32_t flags;
	uint8_t	l2_size = 0;
	int32_t	offset;
	static uint16_t	id = 0;

	*nh_new = ofp_get_next_hop(vrfid, dev_gre->ip_remote, &flags);

	if (*nh_new == NULL)
		return OFP_PKT_DROP;

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
	greip->gi_i.ip_id = odp_cpu_to_be_16(id++);
	greip->gi_i.ip_off = 0;
	greip->gi_i.ip_ttl = ip6->ofp_ip6_hlim;
	greip->gi_i.ip_p = OFP_IPPROTO_GRE;
	greip->gi_i.ip_sum = 0;
	greip->gi_i.ip_src.s_addr = dev_gre->ip_local;
	greip->gi_i.ip_dst.s_addr = dev_gre->ip_remote;

	odp_packet_has_ipv6_set(pkt, 0);
	odp_packet_has_ipv4_set(pkt, 1);

	return OFP_PKT_CONTINUE;
}

enum ofp_return_code ofp_ip6_output(odp_packet_t pkt,
	struct ofp_nh6_entry *nh_param)
{
	struct ofp_ip6_hdr *ip6;
	uint8_t l2_size;
	void *l2_addr;
	uint32_t flags;
	struct ofp_nh_entry *nh4 = NULL;
	struct ofp_nh6_entry *nh;
	uint16_t vlan;
	int out_port;
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
		out_port = nh->port;
	} else {
		nh = ofp_get_next_hop6(vrf,
					 ip6->ip6_dst.ofp_s6_addr, &flags);
		if (nh) {
			vlan = nh->vlan;
			out_port = nh->port;
		} else
			return OFP_PKT_DROP;
	}

	dev_out = ofp_get_ifnet(out_port, vlan);

	if (!dev_out)
		return OFP_PKT_DROP;

	/* GRE */
	if (out_port == GRE_PORTS) {
		if (ofp_output_ipv6_to_gre(pkt, dev_out, vrf,
					     &nh4) == OFP_PKT_DROP)
			return OFP_PKT_DROP;

		return ofp_ip_output(pkt, nh4);
	}

	if (!vlan)
		l2_size = sizeof(struct ofp_ether_header);
	else
		l2_size = sizeof(struct ofp_ether_vlan_header);

	if (odp_packet_l3_offset(pkt) >= l2_size) {
		odp_packet_l2_offset_set(pkt,
					odp_packet_l3_offset(pkt) - l2_size);
		l2_addr = odp_packet_l2_ptr(pkt, NULL);
	} else {
		int hlen = 0;

		if (odp_packet_l4_offset(pkt) != ODP_PACKET_OFFSET_INVALID)
			hlen = odp_packet_l4_offset(pkt) -
				odp_packet_l3_offset(pkt);

		l2_addr = odp_packet_push_head(pkt,
					l2_size - odp_packet_l3_offset(pkt));
		odp_packet_l2_offset_set(pkt, 0);
		odp_packet_l3_offset_set(pkt, l2_size);
		odp_packet_l4_offset_set(pkt, l2_size + hlen);
	}

	if (odp_unlikely(l2_addr == NULL))
		return OFP_PKT_DROP;

	/* MAC address for the destination */
	if (ofp_ip6_equal(dev_out->ip6_addr, ip6->ip6_dst.ofp_s6_addr) ||
	    dev_out->port == LOCAL_PORTS) {
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

	OFP_DEBUG_PACKET(OFP_DEBUG_PKT_RECV_NIC, pkt, ifnet->port);

	OFP_UPDATE_PACKET_STAT(rx_fp, 1);

	OFP_UPDATE_PACKET_LATENCY_STAT(1);

	/* data link layer processing */
	res = pkt_func(pkt);

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
