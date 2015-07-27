/* Copyright (c) 2014, Nokia
 * Copyright (c) 2014, ENEA Software AB
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef OFP_TESTMODE_AUTO
#define OFP_TESTMODE_AUTO 1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>

#if OFP_TESTMODE_AUTO
#include <CUnit/Automated.h>
#else
#include <CUnit/Basic.h>
#endif

#include <odp.h>
#include <ofpi.h>
#include <ofpi_log.h>
#include <ofpi_portconf.h>
#include <ofpi_route.h>
#include <ofpi_rt_lookup.h>
#include <ofpi_avl.h>
#include <ofpi_arp.h>
#include <ofpi_pkt_processing.h>
#include <ofpi_timer.h>
#include <ofpi_hook.h>
#include <ofpi_util.h>
#include <ofpi_debug.h>

#include "test_raw_frames.h"

#define fail_with_odp(msg) do { OFP_ERR(msg); CU_FAIL(msg); } while (0)

/*
 * Test data
 */
static uint8_t test_frame[140] = {
0x40, 0x01, 0xec, 0x36, 0x93, 0x18, 0xc8, 0x35,
0xb8, 0x28, 0x91, 0x3e, 0x08, 0x00, 0x45, 0x00,
0x00, 0x7a, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
0xf0, 0x71, 0x0a, 0x00, 0x1a, 0x01, 0x0a, 0x00,
0x1c, 0x01, 0x00, 0xa1, 0xff, 0xfe, 0x00, 0x66,
0xd4, 0xc3, 0x30, 0x5c, 0x02, 0x01, 0x01, 0x04,
0x06, 0x4e, 0x45, 0x54, 0x4d, 0x41, 0x4e, 0xa2,
0x4f, 0x02, 0x03, 0x0f, 0xb0, 0xc7, 0x02, 0x01,
0x00, 0x02, 0x01, 0x00, 0x30, 0x42, 0x30, 0x14,
0x06, 0x0f, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x81,
0x41, 0x81, 0x31, 0x01, 0x02, 0x02, 0x01, 0x07,
0x00, 0x02, 0x01, 0x01, 0x30, 0x14, 0x06, 0x0f,
0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0x41, 0x81,
0x31, 0x01, 0x02, 0x02, 0x01, 0x08, 0x00, 0x02,
0x01, 0x00, 0x30, 0x14, 0x06, 0x0f, 0x2b, 0x06,
0x01, 0x04, 0x01, 0x81, 0x41, 0x81, 0x31, 0x01,
0x02, 0x02, 0x01, 0x09, 0x00, 0x02, 0x01, 0x00,
0xa9, 0x59, 0xcd, 0x58
};

static uint8_t test_frame_vlan[144] = {
0x40, 0x01, 0xec, 0x36, 0x93, 0x18, 0xc8, 0x35,
0xb8, 0x28, 0x91, 0x3e, 0x81, 0x00, 0x00, 0xA1, 0x08, 0x00, 0x45, 0x00,
0x00, 0x7a, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
0xf0, 0x71, 0x0a, 0x00, 0x1a, 0x01, 0x0a, 0x00,
0x1c, 0x01, 0x00, 0xa1, 0xff, 0xfe, 0x00, 0x66,
0xd4, 0xc3, 0x30, 0x5c, 0x02, 0x01, 0x01, 0x04,
0x06, 0x4e, 0x45, 0x54, 0x4d, 0x41, 0x4e, 0xa2,
0x4f, 0x02, 0x03, 0x0f, 0xb0, 0xc7, 0x02, 0x01,
0x00, 0x02, 0x01, 0x00, 0x30, 0x42, 0x30, 0x14,
0x06, 0x0f, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x81,
0x41, 0x81, 0x31, 0x01, 0x02, 0x02, 0x01, 0x07,
0x00, 0x02, 0x01, 0x01, 0x30, 0x14, 0x06, 0x0f,
0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0x41, 0x81,
0x31, 0x01, 0x02, 0x02, 0x01, 0x08, 0x00, 0x02,
0x01, 0x00, 0x30, 0x14, 0x06, 0x0f, 0x2b, 0x06,
0x01, 0x04, 0x01, 0x81, 0x41, 0x81, 0x31, 0x01,
0x02, 0x02, 0x01, 0x09, 0x00, 0x02, 0x01, 0x00,
0xa9, 0x59, 0xcd, 0x58
};

#define SHM_PKT_POOL_SIZE      (32*2048)
#define SHM_PKT_POOL_BUF_SIZE  3000

static uint32_t port = 0, vlan = 0, vrf = 0, def_mtu = 1500;
static uint32_t dev_ip = 0x650AA8C0;   /* C0.A8.0A.65 = 192.168.10.101 */
static uint8_t dev_mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
static uint8_t dev_vlan_mac[6] = {0x11, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
static struct ofp_ifnet *dev, *dev_vlan;
static uint8_t orig_pkt_data[SHM_PKT_POOL_BUF_SIZE];
uint16_t greid = 100;
static uint32_t tun_rem_ip = 0x660AA8C0;   /* C0.A8.0A.66 = 192.168.10.102 */
static uint8_t tun_rem_mac[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
static uint32_t tun_addr = 0x010A0A0A;   /* 0A.0A.0A.01 = 10.10.10.1 */
static uint32_t tun_p2p = 0x020A0A0A;   /* 0A.0A.0A.02 = 10.10.10.2 */
static uint16_t tun_mask = 32; /* p-t-p */

/*
 * INIT
 */
static void init_ifnet(void)
{
	char str[256];

	ofp_config_interface_up_v4(port, vlan, vrf, dev_ip, 24);

	/* port 0 */
	dev = ofp_get_ifnet(port, vlan);
	memcpy(dev->mac, dev_mac, OFP_ETHER_ADDR_LEN);
	dev->if_mtu = def_mtu;
#ifdef SP
	dev->linux_index = port + 3; /* an if index of Linux != port val */
	ofp_update_ifindex_lookup_tab(dev);
#endif /* SP */

	dev->pkt_pool = odp_pool_lookup("packet_pool");

	sprintf(str, "out default queue:%d", port);
	dev->outq_def = odp_queue_create(str,
					 ODP_QUEUE_TYPE_POLL,
					 NULL);
	if (dev->outq_def == ODP_QUEUE_INVALID) {
		fail_with_odp("Out default queue create failed.\n");
		return;
	}

	/* port 0 vlan 1 */
	ofp_config_interface_up_v4(port, vlan + 1, vrf, dev_ip + 1, 24);

	dev_vlan = ofp_get_ifnet(port, vlan + 1);
	memcpy(dev_vlan->mac, dev_vlan_mac, OFP_ETHER_ADDR_LEN);
	dev_vlan->if_mtu = def_mtu;
#ifdef SP
	dev_vlan->linux_index = port + 4; /* an if index of Linux != port val */
	ofp_update_ifindex_lookup_tab(dev_vlan);
#endif /* SP */

	dev_vlan->pkt_pool = odp_pool_lookup("packet_pool");

	sprintf(str, "out default queue:%d", port);
	dev_vlan->outq_def = odp_queue_create(str,
					      ODP_QUEUE_TYPE_POLL,
					      NULL);
	if (dev_vlan->outq_def == ODP_QUEUE_INVALID) {
		fail_with_odp("Out default queue create failed.\n");
		return;
	}

	/* Tunnels */
	ofp_config_interface_up_tun(GRE_PORTS, 100, 0, dev_ip, tun_rem_ip,
				      tun_p2p, tun_addr, tun_mask);

	/* No nexthop for tunnel remote address */
	ofp_config_interface_up_tun(GRE_PORTS, 200, 0, dev_ip, 0x08070605,
				      tun_p2p + 1, tun_addr + 1, tun_mask);
}

static int
init_suite(void)
{
	odp_pool_t pool;
	odp_pool_param_t pool_params;
	ofp_pkt_hook pkt_hook[OFP_HOOK_MAX];

	/* Init ODP before calling anything else */
	if (odp_init_global(NULL, NULL)) {
		OFP_ERR("Error: ODP global init failed.\n");
		return -1;
	}

	/* Init this thread */
	if (odp_init_local()) {
		OFP_ERR("Error: ODP local init failed.\n");
		return -1;
	}

	ofp_portconf_alloc_shared_memory();
	ofp_route_alloc_shared_memory();
	ofp_rt_lookup_alloc_shared_memory();
	ofp_avl_alloc_shared_memory();
	ofp_arp_alloc_shared_memory();
	ofp_pcap_alloc_shared_memory();
	ofp_timer_init(OFP_TIMER_RESOLUTION_US,
			 OFP_TIMER_MIN_US,
			 OFP_TIMER_MAX_US,
			 OFP_TIMER_TMO_COUNT);

	memset(pkt_hook, 0, sizeof(pkt_hook));
	ofp_hook_alloc_shared_memory(&pkt_hook[0]);

	ofp_init_ifnet_data();
	ofp_route_init();
	ofp_arp_global_init();
	ofp_arp_local_init();

	pool_params.pkt.seg_len = SHM_PKT_POOL_BUF_SIZE;
	pool_params.pkt.len = SHM_PKT_POOL_BUF_SIZE;
	pool_params.pkt.num = SHM_PKT_POOL_SIZE/SHM_PKT_POOL_BUF_SIZE;
	pool_params.type = ODP_POOL_PACKET;

	pool = odp_pool_create("packet_pool", ODP_SHM_NULL,
		&pool_params);

	if (pool == ODP_POOL_INVALID) {
		OFP_ERR("Error: packet pool create failed.\n");
		return -1;
	}

	odp_shm_print_all();
	odp_pool_print(pool);

	init_ifnet();

	ofp_arp_ipv4_insert(tun_rem_ip, tun_rem_mac, dev);

	return 0;
}

static int
clean_suite(void)
{
	return 0;
}

static int
create_odp_packet_ip4(odp_packet_t *opkt, uint8_t *pkt_data, int plen,
		      uint32_t dst_addr)
{
	odp_pool_t pool;
	uint8_t *buf;
	odp_packet_t pkt = ODP_PACKET_INVALID;
	struct ofp_ether_header *eth;
	struct ofp_ip *iphdr;
	uint32_t eth_len;

	memset(orig_pkt_data, 0x0, sizeof(orig_pkt_data));

	pool = odp_pool_lookup("packet_pool");
	if (pool == ODP_POOL_INVALID) {
		fail_with_odp("ODP packet_pool not found\n");
		return -1;
	}

	pkt = odp_packet_alloc(pool, plen);
	if (pkt == ODP_PACKET_INVALID) {
		fail_with_odp("ODP packet alloc failed");
		return -1;
	}

	buf = odp_packet_data(pkt);

	if (odp_packet_copydata_in(pkt, 0, plen, pkt_data) < 0) {
		fail_with_odp("Packet data copy failed\n");
		return -1;
	};

	iphdr = (struct ofp_ip *)&buf[OFP_ETHER_HDR_LEN];

	/* changes to the default packet. Recalculate ip checksum */
	if (dst_addr) {
		iphdr->ip_dst.s_addr = dst_addr;
		iphdr->ip_sum = 0;
		iphdr->ip_sum =
			ofp_in_cksum((uint16_t *)iphdr, iphdr->ip_hl<<2);
	}
	/* END OF changes to the default packet */

	eth = (struct ofp_ether_header *)buf;
	if (eth->ether_type == odp_cpu_to_be_16(OFP_ETHERTYPE_VLAN))
		eth_len = OFP_ETHER_HDR_LEN + OFP_ETHER_VLAN_ENCAP_LEN;
	else
		eth_len = OFP_ETHER_HDR_LEN;

	odp_packet_has_eth_set(pkt, 1);
	odp_packet_has_l2_set(pkt, 1);
	odp_packet_has_ipv4_set(pkt, 1);
	odp_packet_l2_offset_set(pkt, 0);
	odp_packet_l3_offset_set(pkt, eth_len);
	odp_packet_l4_offset_set(pkt, eth_len + (iphdr->ip_hl<<2));

	*opkt = pkt;

	odp_packet_copydata_out(pkt, 0, plen, orig_pkt_data);

	return 0;
}

static int
create_odp_packet_ip6(odp_packet_t *opkt, uint8_t *pkt_data, int plen)
{
	odp_pool_t pool;
	odp_packet_t pkt = ODP_PACKET_INVALID;

	memset(orig_pkt_data, 0x0, sizeof(orig_pkt_data));

	pool = odp_pool_lookup("packet_pool");
	if (pool == ODP_POOL_INVALID) {
		fail_with_odp("ODP packet_pool not found\n");
		return -1;
	}

	pkt = odp_packet_alloc(pool, plen);
	if (pkt == ODP_PACKET_INVALID) {
		fail_with_odp("ODP packet alloc failed");
		return -1;
	}

	if (odp_packet_copydata_in(pkt, 0, plen, pkt_data) < 0) {
		fail_with_odp("Packet data copy failed\n");
		return -1;
	};

	odp_packet_has_eth_set(pkt, 1);
	odp_packet_has_l2_set(pkt, 1);
	odp_packet_has_ipv6_set(pkt, 1);
	odp_packet_l2_offset_set(pkt, 0);
	odp_packet_l3_offset_set(pkt, OFP_ETHER_HDR_LEN);

	*opkt = pkt;

	odp_packet_copydata_out(pkt, 0, plen, orig_pkt_data);

	return 0;
}

/*
 * Tests
 */
static void
test_packet_output_gre(void)
{
	odp_packet_t pkt = ODP_PACKET_INVALID;
	odp_event_t ev;
	int res;
	struct ofp_ether_header *eth;
	struct ofp_ip *ip;
	struct ofp_ip *ip_orig;
	struct ofp_greip *greip;

	if (create_odp_packet_ip4(&pkt, test_frame, sizeof(test_frame),
				  tun_p2p)) {
		CU_FAIL("Fail to create packet");
		return;
	}

	/*
	 * Packet's destination is GRE tunnel's p2p address, next hop is GRE
	 * interface. GRE+IP header is prepended. Packet's new destination is
	 * link local. Packet is put into output queue.
	 */
	res = ofp_ip_output(pkt, NULL);
	CU_ASSERT_EQUAL(res, OFP_PKT_PROCESSED);

	ev = odp_queue_deq(dev->outq_def);
	CU_ASSERT_NOT_EQUAL_FATAL(ev, ODP_EVENT_INVALID);

	pkt = odp_packet_from_event(ev);
	CU_ASSERT_EQUAL_FATAL(odp_packet_len(pkt),
			      sizeof(test_frame) + 20 + 4);

	eth = odp_packet_l2_ptr(pkt, NULL);
	if (memcmp(eth->ether_dhost, tun_rem_mac, OFP_ETHER_ADDR_LEN))
		CU_FAIL("Bad destination mac address.");
	if (memcmp(eth->ether_shost, dev->mac, OFP_ETHER_ADDR_LEN))
		CU_FAIL("Bad source mac address.");

	ip = odp_packet_l3_ptr(pkt, NULL);
	CU_ASSERT_EQUAL(ip->ip_src.s_addr, dev_ip);
	CU_ASSERT_EQUAL(ip->ip_dst.s_addr, tun_rem_ip);
	CU_ASSERT_EQUAL(ip->ip_p, OFP_IPPROTO_GRE);

	greip = (struct ofp_greip *)ip;
	CU_ASSERT_EQUAL(greip->gi_g.flags, 0);
	CU_ASSERT_EQUAL(greip->gi_g.ptype,
			odp_cpu_to_be_16(OFP_ETHERTYPE_IP));

	/* inner ip */
	ip = (struct ofp_ip *)(greip + 1);
	ip_orig = (struct ofp_ip *)(&orig_pkt_data[OFP_ETHER_HDR_LEN]);
	if (memcmp(ip, ip_orig, odp_be_to_cpu_16(ip_orig->ip_len)))
		CU_FAIL("Inner IP packet error.");
}

static void
test_packet_output_gre_no_nexthop(void)
{
	odp_packet_t pkt = ODP_PACKET_INVALID;
	odp_event_t ev;
	int res;

	if (create_odp_packet_ip4(&pkt, test_frame, sizeof(test_frame),
				  tun_p2p + 1)) {
		CU_FAIL("Fail to create packet");
		return;
	}

	/*
	 * Packet's destination is GRE tunnel's p2p address, no next hop
	 * is found for tunnel destination address, packet is dropped.
	 */
	res = ofp_ip_output(pkt, NULL);
	CU_ASSERT_EQUAL(res, OFP_PKT_DROP);

	ev = odp_queue_deq(dev->outq_def);
	CU_ASSERT_EQUAL_FATAL(ev, ODP_EVENT_INVALID);
}

#ifdef INET6
static void
test_packet_output_ipv6_to_gre(void)
{
	odp_packet_t pkt = ODP_PACKET_INVALID;
	odp_event_t ev;
	int res;
	struct ofp_route_msg msg;
	struct ofp_in6_addr addr6;
	struct ofp_ether_header *eth;
	struct ofp_ip6_hdr *ip6, *ip6_orig;
	struct ofp_ip *ip;
	struct ofp_greip *greip;

	(void)tcp_frame;
	(void)icmp_frame;
	(void)arp_frame;
	(void)icmp6_frame;

	if (create_odp_packet_ip6(&pkt, ip6udp_frame, sizeof(ip6udp_frame))) {
		CU_FAIL("Fail to create packet");
		return;
	}

	ip6 = odp_packet_l3_ptr(pkt, NULL);
	addr6.__u6_addr.__u6_addr16[0] =
		ip6->ip6_dst.__u6_addr.__u6_addr16[0];

	memset(&msg, 0, sizeof(msg));
	msg.type = OFP_ROUTE6_ADD;
	msg.vrf = 0;
	memcpy(msg.dst6, &addr6, 16);
	msg.masklen = 64;
	/* gw = 0 */
	msg.port = GRE_PORTS;
	msg.vlan = 100;
	ofp_set_route(&msg);

	res = ofp_ip6_output(pkt, NULL);
	CU_ASSERT_EQUAL(res, OFP_PKT_PROCESSED);

	ev = odp_queue_deq(dev->outq_def);
	CU_ASSERT_NOT_EQUAL_FATAL(ev, ODP_EVENT_INVALID);

	pkt = odp_packet_from_event(ev);
	CU_ASSERT_EQUAL_FATAL(odp_packet_len(pkt),
			      sizeof(ip6udp_frame) + 20 + 4);

	eth = odp_packet_l2_ptr(pkt, NULL);
	if (memcmp(eth->ether_dhost, tun_rem_mac, OFP_ETHER_ADDR_LEN))
		CU_FAIL("Bad destination mac address.");
	if (memcmp(eth->ether_shost, dev->mac, OFP_ETHER_ADDR_LEN))
		CU_FAIL("Bad source mac address.");

	ip = odp_packet_l3_ptr(pkt, NULL);
	CU_ASSERT_EQUAL(ip->ip_src.s_addr, dev_ip);
	CU_ASSERT_EQUAL(ip->ip_dst.s_addr, tun_rem_ip);
	CU_ASSERT_EQUAL(ip->ip_p, OFP_IPPROTO_GRE);

	greip = (struct ofp_greip *)ip;
	CU_ASSERT_EQUAL(greip->gi_g.flags, 0);
	CU_ASSERT_EQUAL(greip->gi_g.ptype,
			odp_cpu_to_be_16(OFP_ETHERTYPE_IPV6));

	/* inner ip */
	ip6 = (struct ofp_ip6_hdr *)(greip + 1);
	ip6_orig = (struct ofp_ip6_hdr *)
		(&orig_pkt_data[OFP_ETHER_HDR_LEN]);
	if (memcmp(ip6, ip6_orig,
		   odp_be_to_cpu_16(ip6_orig->ofp_ip6_plen) + sizeof(*ip6)))
		CU_FAIL("Inner IP packet error.");
}
#endif

static void
test_send_frame_packet_len_bigger_than_mtu(void)
{
	odp_packet_t pkt = ODP_PACKET_INVALID;
	odp_event_t ev;
	uint32_t old_mtu;
	int res;

	if (create_odp_packet_ip4(&pkt, test_frame, sizeof(test_frame), 0)) {
		CU_FAIL("Fail to create packet");
		return;
	}

	old_mtu = dev->if_mtu;
	dev->if_mtu = 120;

	res = ofp_send_frame(dev, pkt);
	CU_ASSERT_EQUAL(res, OFP_PKT_DROP);

	dev->if_mtu = old_mtu;

	ev = odp_queue_deq(dev->outq_def);
	CU_ASSERT_EQUAL_FATAL(ev, ODP_EVENT_INVALID);
}

static void
test_send_frame_novlan_to_novlan(void)
{
	odp_packet_t pkt = ODP_PACKET_INVALID;
	odp_event_t ev;
	int res;

	if (create_odp_packet_ip4(&pkt, test_frame, sizeof(test_frame), 0)) {
		CU_FAIL("Fail to create packet");
		return;
	}

	res = ofp_send_frame(dev, pkt);
	CU_ASSERT_EQUAL(res, OFP_PKT_PROCESSED);

	ev = odp_queue_deq(dev->outq_def);
	CU_ASSERT_NOT_EQUAL_FATAL(ev, ODP_EVENT_INVALID);

	pkt = odp_packet_from_event(ev);
	CU_ASSERT_EQUAL_FATAL(odp_packet_len(pkt), sizeof(test_frame));

	if (memcmp(odp_packet_l2_ptr(pkt, NULL), test_frame,
		   sizeof(test_frame)))
		CU_FAIL("Frame data mismatch.");
}

static void
test_send_frame_novlan_to_vlan(void)
{
	odp_packet_t pkt = ODP_PACKET_INVALID;
	odp_event_t ev;
	struct ofp_ether_vlan_header *eth_vlan;
	uint8_t *buf;
	int res;

	if (create_odp_packet_ip4(&pkt, test_frame, sizeof(test_frame), 0)) {
		CU_FAIL("Fail to create packet");
		return;
	}

	res = ofp_send_frame(dev_vlan, pkt);
	CU_ASSERT_EQUAL(res, OFP_PKT_PROCESSED);

	ev = odp_queue_deq(dev->outq_def);
	CU_ASSERT_NOT_EQUAL_FATAL(ev, ODP_EVENT_INVALID);

	pkt = odp_packet_from_event(ev);
	CU_ASSERT_EQUAL_FATAL(odp_packet_len(pkt), sizeof(test_frame) + 4);

	eth_vlan = odp_packet_l2_ptr(pkt, NULL);
	if (memcmp(eth_vlan, test_frame, 2 * OFP_ETHER_ADDR_LEN))
		CU_FAIL("Frame data mismatch.");

	CU_ASSERT_EQUAL(eth_vlan->evl_encap_proto,
			odp_cpu_to_be_16(OFP_ETHERTYPE_VLAN));
	CU_ASSERT_EQUAL(eth_vlan->evl_tag,
			odp_cpu_to_be_16(dev_vlan->vlan));

	buf = (uint8_t *)eth_vlan;
	if (memcmp(&buf[16], &test_frame[12],
		   sizeof(test_frame) - 2 * OFP_ETHER_ADDR_LEN))
		CU_FAIL("Frame data mismatch.");
}

static void
test_send_frame_vlan_to_novlan(void)
{
	odp_packet_t pkt = ODP_PACKET_INVALID;
	odp_event_t ev;
	int res;

	if (create_odp_packet_ip4(&pkt, test_frame_vlan,
				  sizeof(test_frame_vlan), 0)) {
		CU_FAIL("Fail to create packet");
		return;
	}

	res = ofp_send_frame(dev, pkt);
	CU_ASSERT_EQUAL(res, OFP_PKT_PROCESSED);

	ev = odp_queue_deq(dev->outq_def);
	CU_ASSERT_NOT_EQUAL_FATAL(ev, ODP_EVENT_INVALID);

	pkt = odp_packet_from_event(ev);
	CU_ASSERT_EQUAL_FATAL(odp_packet_len(pkt), sizeof(test_frame));

	if (memcmp(odp_packet_l2_ptr(pkt, NULL), test_frame,
		   sizeof(test_frame)))
		CU_FAIL("Frame data mismatch.");
}

static void
test_send_frame_vlan_to_vlan(void)
{
	odp_packet_t pkt = ODP_PACKET_INVALID;
	odp_event_t ev;
	uint8_t check_buf[144];
	int res;

	if (create_odp_packet_ip4(&pkt, test_frame_vlan,
				  sizeof(test_frame_vlan), 0)) {
		CU_FAIL("Fail to create packet");
		return;
	}

	memcpy(check_buf, test_frame_vlan, sizeof(test_frame_vlan));
	check_buf[15] = dev_vlan->vlan;

	res = ofp_send_frame(dev_vlan, pkt);
	CU_ASSERT_EQUAL(res, OFP_PKT_PROCESSED);

	ev = odp_queue_deq(dev->outq_def);
	CU_ASSERT_NOT_EQUAL_FATAL(ev, ODP_EVENT_INVALID);

	pkt = odp_packet_from_event(ev);
	CU_ASSERT_EQUAL_FATAL(odp_packet_len(pkt), sizeof(test_frame_vlan));

	if (memcmp(odp_packet_l2_ptr(pkt, NULL), check_buf,
		   sizeof(test_frame_vlan)))
		CU_FAIL("Frame data mismatch.");
}

/*
 * Main
 */
int
main(void)
{
	CU_pSuite ptr_suite = NULL;
	int nr_of_failed_tests = 0;
	int nr_of_failed_suites = 0;

	/* Initialize the CUnit test registry */
	if (CUE_SUCCESS != CU_initialize_registry())
		return CU_get_error();

	/* add a suite to the registry */
	ptr_suite = CU_add_suite("ofp packet out", init_suite, clean_suite);
	if (NULL == ptr_suite) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if (NULL == CU_ADD_TEST(ptr_suite,
				test_packet_output_gre)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if (NULL == CU_ADD_TEST(ptr_suite,
				test_packet_output_gre_no_nexthop)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
#ifdef INET6
	if (NULL == CU_ADD_TEST(ptr_suite,
				test_packet_output_ipv6_to_gre)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
#endif

	if (NULL == CU_ADD_TEST(ptr_suite,
				test_send_frame_packet_len_bigger_than_mtu)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite,
				test_send_frame_novlan_to_novlan)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite,
				test_send_frame_novlan_to_vlan)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite,
				test_send_frame_vlan_to_novlan)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite,
				test_send_frame_vlan_to_vlan)) {
		CU_cleanup_registry();
		return CU_get_error();
	}


#if OFP_TESTMODE_AUTO
	CU_set_output_filename("CUnit-PKT-OUT");
	CU_automated_run_tests();
#else
	/* Run all tests using the CUnit Basic interface */
	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
#endif

	nr_of_failed_tests = CU_get_number_of_tests_failed();
	nr_of_failed_suites = CU_get_number_of_suites_failed();
	CU_cleanup_registry();

	return (nr_of_failed_suites > 0 ?
		nr_of_failed_suites : nr_of_failed_tests);
}
