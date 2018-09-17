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

#include <odp_api.h>
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

#include "ofp_route_arp.h"

/*
 * Test data
 */
static uint32_t dst_ipaddr = 0x650AA8C0; /* C0.A8.0A.65 = 192.168.10.101 */
/* Frame IP/UDP/SNMP (136 bytes) */
static uint8_t test_frame[] = {
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
0x02, 0x02, 0x01, 0x09, 0x00, 0x02, 0x01, 0x00
};

/* Frame IP/GRE/IP/ICMP (138 bytes) */
static uint8_t gre_frame[138] = {
0xc2, 0x01, 0x57, 0x75, 0x00, 0x00, 0xc2, 0x00, /* ..Wu.... */
0x57, 0x75, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00, /* Wu....E. */
0x00, 0x7c, 0x00, 0x0a, 0x00, 0x00, 0xff, 0x2f, /* .|...../ */
0xa7, 0x46, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, /* .F...... */
0x00, 0x02, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00, /* ......E. */
0x00, 0x64, 0x00, 0x0a, 0x00, 0x00, 0xff, 0x01, /* .d...... */
0xb5, 0x89, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, /* ........ */
0x02, 0x02, 0x08, 0x00, 0xbf, 0xd4, 0x00, 0x02, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, /* ........ */
0xbe, 0x70, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, /* .p...... */
0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, /* ........ */
0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, /* ........ */
0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, /* ........ */
0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, /* ........ */
0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, /* ........ */
0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, /* ........ */
0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, /* ........ */
0xab, 0xcd                                      /* .. */
};

/*
 * Helpers
 */
#define fail_with_odp(msg) do { OFP_ERR(msg); CU_FAIL(msg); } while (0)

#define OFP_TEST_FAIL		0xFFFF
#define OFP_TEST_LOCAL_HOOK	0xFF01
#define OFP_TEST_LOCAL_IPv4_HOOK	0xFF02
#define OFP_TEST_LOCAL_UDPv4_HOOK	0xFF03

#define TEST_LOCAL_HOOK		0x8001
#define TEST_FORWARD_HOOK	0x8002
#define TEST_LOCAL_HOOK_GRE     0x8003
#define TEST_LOCAL_HOOK_GRE_APP 0x8004
#define TEST_GRE_HOOK		0x8005
#define TEST_LOCAL_IPv4_HOOK		0x8006
#define TEST_LOCAL_UDPv4_HOOK		0x8007
/* global identifier for a testcase */
static int my_test_val;
/* save the packet that was sent as input to ofp_packet_input */
static uint8_t in_pkt_data[1024];
static struct ofp_ifnet *ifnet;
static odp_queue_t interface_queue[16];
static uint32_t port, vlan, vrf, local_ip;
static uint32_t tun_rem_ip = 0x660AA8C0;   /* C0.A8.0A.66 = 192.168.10.102 */
static uint32_t tun_addr = 0x010A0A0A;   /* 0A.0A.0A.01 = 10.10.10.1 */
static uint32_t tun_p2p = 0x020A0A0A;   /* 0A.0A.0A.02 = 10.10.10.2 */
static uint16_t tun_mask = 32; /* p-t-p */

static enum ofp_return_code fastpath_ip4_forward_hook(odp_packet_t pkt,
		void *nh)
{
	(void) pkt;
	(void) nh;
	if (my_test_val == TEST_FORWARD_HOOK) {
		CU_PASS("fastpath_ip4_forward_hook\n");
		return OFP_PKT_CONTINUE;
	} else
		return OFP_TEST_FAIL;
}

static enum ofp_return_code fastpath_ip6_forward_hook(odp_packet_t pkt,
		void  *nh)
{
	(void) pkt;
	(void) nh;
	return OFP_TEST_FAIL;
}

static enum ofp_return_code fastpath_local_hook(odp_packet_t pkt,
		void *arg)
{
	int protocol = *(int *)arg;
	(void) pkt;
	if (my_test_val == TEST_LOCAL_HOOK) {
		CU_ASSERT_EQUAL(protocol, IS_IPV4);

		CU_ASSERT_EQUAL(odp_packet_len(pkt), sizeof(test_frame));
		if (memcmp((uint8_t *)odp_packet_data(pkt) +
			odp_packet_l3_offset(pkt),
			in_pkt_data + OFP_ETHER_HDR_LEN,
			odp_packet_len(pkt) - OFP_ETHER_HDR_LEN))
			CU_FAIL("Corrupt data");

		return OFP_TEST_LOCAL_HOOK;
	} else if (my_test_val == TEST_LOCAL_HOOK_GRE) {
		/* GRE packet is offered to local hook, then
		   after processing to forward hook */
		my_test_val = TEST_FORWARD_HOOK;
		return OFP_PKT_CONTINUE;
	} else if (my_test_val == TEST_LOCAL_HOOK_GRE_APP) {
		/* GRE packet is offered to local hook, then
		   after tunnel is not found to GRE hook */
		my_test_val = TEST_GRE_HOOK;
		return OFP_PKT_CONTINUE;
	} else if (my_test_val == TEST_LOCAL_IPv4_HOOK)
		return OFP_PKT_CONTINUE;
	else if (my_test_val == TEST_LOCAL_UDPv4_HOOK)
		return OFP_PKT_CONTINUE;
	else
		return OFP_TEST_FAIL;
}

static enum ofp_return_code fastpath_local_IPv4_hook(odp_packet_t pkt,
		void *arg)
{
	(void)pkt;
	(void)arg;

	if (my_test_val == TEST_LOCAL_IPv4_HOOK)
		return OFP_TEST_LOCAL_IPv4_HOOK;
	return OFP_PKT_CONTINUE;
}

static enum ofp_return_code fastpath_local_UDPv4_hook(odp_packet_t pkt,
		void *arg)
{
	(void)pkt;
	(void)arg;

	if (my_test_val == TEST_LOCAL_UDPv4_HOOK)
		return OFP_TEST_LOCAL_UDPv4_HOOK;
	return OFP_PKT_CONTINUE;
}

static enum ofp_return_code fastpath_gre_hook(odp_packet_t pkt, void *nh)
{
	(void) pkt;
	(void) nh;
	if (my_test_val == TEST_GRE_HOOK) {
		CU_PASS("fastpath_GRE_hook\n");
		return OFP_PKT_CONTINUE;
	} else {
		return OFP_TEST_FAIL;
	}
}
/*
 * INIT
 */
static void
test_init_ifnet(void)
{
	char str[256];

	ofp_config_interface_up_v4(port, vlan, vrf, local_ip, 24);

	ifnet = ofp_get_ifnet(port, vlan);
	ifnet->pkt_pool = odp_pool_lookup("packet_pool");

#ifdef SP
	ifnet->linux_index = port + 3; /* an if index of Linux != port val */
	ofp_update_ifindex_lookup_tab(ifnet);

	sprintf(str, "slow path stack port:%d", port);
	ifnet->spq_def = odp_queue_create(str, NULL);
	if (ifnet->spq_def == ODP_QUEUE_INVALID) {
		fail_with_odp("Slow path queue create failed.\n");
		return;
	}
#endif

	sprintf(str, "out default queue:%d", port);
	ifnet->outq_def = odp_queue_create(str, NULL);
	if (ifnet->outq_def == ODP_QUEUE_INVALID) {
		fail_with_odp("Out default queue create failed.\n");
		return;
	}

	ifnet->out_queue_num = 1;
	ifnet->out_queue_type = OFP_OUT_QUEUE_TYPE_QUEUE;

	sprintf(str, "interface queue:%d", port);
	interface_queue[port] =
			odp_queue_create(str, NULL);
	if (interface_queue[port] == ODP_QUEUE_INVALID) {
		OFP_ERR("Poll queue create failed.\n");
		return;
	}
	odp_queue_context_set(interface_queue[port], ifnet, sizeof(ifnet));

	ofp_config_interface_up_tun(GRE_PORTS, 100 + port, vrf, local_ip,
				      tun_rem_ip, tun_p2p, tun_addr,
				      tun_mask);
}

static int
init_suite(void)
{
	ofp_global_param_t params;
	odp_instance_t instance;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, NULL, NULL)) {
		OFP_ERR("Error: ODP global init failed.\n");
		return -1;
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		OFP_ERR("Error: ODP local init failed.\n");
		return -1;
	}

	ofp_init_global_param(&params);
	params.enable_nl_thread = 0;
	params.num_vrf = 2;
	memset(params.pkt_hook, 0, sizeof(params.pkt_hook));
	params.pkt_hook[OFP_HOOK_LOCAL]    = fastpath_local_hook;
	params.pkt_hook[OFP_HOOK_LOCAL_IPv4]    = fastpath_local_IPv4_hook;
	params.pkt_hook[OFP_HOOK_LOCAL_UDPv4]    = fastpath_local_UDPv4_hook;
	params.pkt_hook[OFP_HOOK_FWD_IPv4] = fastpath_ip4_forward_hook;
	params.pkt_hook[OFP_HOOK_FWD_IPv6] = fastpath_ip6_forward_hook;
	params.pkt_hook[OFP_HOOK_GRE]	    = fastpath_gre_hook;

	(void) ofp_init_global(instance, &params);

	ofp_init_local();

	return 0;
}

static int
clean_suite(void)
{
	return 0;
}

static int
create_odp_packet_ip4(odp_packet_t *opkt, uint8_t *pkt_data, int plen,
		      uint32_t dst_addr, uint32_t src_addr)
{
	odp_pool_t pool;
	uint8_t *buf;
	odp_packet_t pkt = ODP_PACKET_INVALID;
	struct ofp_ip *iphdr;

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

	memcpy(buf, pkt_data, plen);

	iphdr = (struct ofp_ip *)&buf[14];

	/* changes to the default packet. Recalculate ip checksum */
	if (dst_addr)
		iphdr->ip_dst.s_addr = dst_addr;
	if (src_addr)
		iphdr->ip_src.s_addr = src_addr;
	if (dst_addr || src_addr) {
		iphdr->ip_sum = 0;
		iphdr->ip_sum =
			ofp_cksum_buffer((uint16_t *)iphdr, iphdr->ip_hl<<2);
	}
	/* END OF changes to the default packet */

	odp_packet_has_eth_set(pkt, 1);
	odp_packet_has_ipv4_set(pkt, 1);
	odp_packet_l2_offset_set(pkt, 0);
	odp_packet_l3_offset_set(pkt, OFP_ETHER_HDR_LEN);
	odp_packet_l4_offset_set(pkt, OFP_ETHER_HDR_LEN + (iphdr->ip_hl<<2));

	*opkt = pkt;

	memcpy(in_pkt_data, buf, plen);
	return 0;
}

static void
test_ofp_add_route(uint32_t port, uint32_t vrf, uint32_t vlan,
			uint32_t destination, uint32_t mask_len,
			uint32_t rt_dst_len, uint32_t gw)
{
	/* add/test only IPv4 routes and not IPv6 or DEFAULT routes(rt_dst=0)*/
	CU_ASSERT_EQUAL(rt_dst_len, 4);
	if (rt_dst_len == 4) {
		ofp_set_route_params(OFP_ROUTE_ADD, vrf, vlan, port,
				     destination, mask_len, gw,
				     gw ? OFP_RTF_GATEWAY : OFP_RTF_NET);
	}


	uint32_t flags;
	struct ofp_nh_entry *node =
			ofp_get_next_hop(vrf, destination, &flags);

	CU_ASSERT_EQUAL(node->gw, gw);
	CU_ASSERT_EQUAL(node->port, port);
	CU_ASSERT_EQUAL(node->vlan, vlan);
}


static void
test_ofp_packet_input_local_hook(void)
{
	odp_packet_t pkt;
	int res;

	/* Call ofp_packet_input with a pkt with destination ip
	 * that matches the local ip on ifnet.
	 * The packet is terminated in local hook */
	my_test_val = TEST_LOCAL_HOOK;
	ifnet->ip_addr_info[0].ip_addr = dst_ipaddr;
	if (create_odp_packet_ip4(&pkt, test_frame, sizeof(test_frame),
				  dst_ipaddr, 0)) {
		CU_FAIL("Fail to create packet");
		return;
	}

	res = ofp_packet_input(pkt, interface_queue[port],
		ofp_eth_vlan_processing);
	CU_ASSERT_EQUAL(res, OFP_TEST_LOCAL_HOOK);
#ifdef SP
	CU_ASSERT_EQUAL(odp_queue_deq(ifnet->spq_def), ODP_EVENT_INVALID);
#endif /* SP */
	CU_ASSERT_EQUAL(odp_queue_deq(ifnet->outq_def), ODP_EVENT_INVALID);
	ifnet->ip_addr_info[0].ip_addr = 0;
	CU_PASS("ofp_packet_input_local_hook");
}

static void
test_ofp_packet_input_local_IPv4_hook(void)
{
	odp_packet_t pkt;
	int res;

	/* Call ofp_packet_input with a pkt with destination ip
	 * that matches the local ip on ifnet.
	 * The packet is terminated in local IPv4 hook */
	my_test_val = TEST_LOCAL_IPv4_HOOK;
	ifnet->ip_addr_info[0].ip_addr = dst_ipaddr;
	if (create_odp_packet_ip4(&pkt, test_frame, sizeof(test_frame),
				  dst_ipaddr, 0)) {
		CU_FAIL("Fail to create packet");
		return;
	}

	res = ofp_packet_input(pkt, interface_queue[port],
		ofp_eth_vlan_processing);
	CU_ASSERT_EQUAL(res, OFP_TEST_LOCAL_IPv4_HOOK);
#ifdef SP
	CU_ASSERT_EQUAL(odp_queue_deq(ifnet->spq_def), ODP_EVENT_INVALID);
#endif /* SP */
	CU_ASSERT_EQUAL(odp_queue_deq(ifnet->outq_def), ODP_EVENT_INVALID);
	ifnet->ip_addr_info[0].ip_addr = 0;
	CU_PASS("ofp_packet_input_local_IPv4_hook");
}

static void
test_ofp_packet_input_local_UDPv4_hook(void)
{
	odp_packet_t pkt;
	int res;

	/* Call ofp_packet_input with a pkt with destination ip
	 * that matches the local ip on ifnet.
	 * The packet is terminated in local UDPv4 hook */
	my_test_val = TEST_LOCAL_UDPv4_HOOK;
	ifnet->ip_addr_info[0].ip_addr = dst_ipaddr;
	if (create_odp_packet_ip4(&pkt, test_frame, sizeof(test_frame),
				  dst_ipaddr, 0)) {
		CU_FAIL("Fail to create packet");
		return;
	}

	res = ofp_packet_input(pkt, interface_queue[port],
		ofp_eth_vlan_processing);
	CU_ASSERT_EQUAL(res, OFP_TEST_LOCAL_UDPv4_HOOK);
#ifdef SP
	CU_ASSERT_EQUAL(odp_queue_deq(ifnet->spq_def), ODP_EVENT_INVALID);
#endif /* SP */
	CU_ASSERT_EQUAL(odp_queue_deq(ifnet->outq_def), ODP_EVENT_INVALID);
	ifnet->ip_addr_info[0].ip_addr = 0;
	CU_PASS("ofp_packet_input_local_UDPv4_hook");
}

#ifdef SP
static void
test_ofp_packet_input_to_sp(void)
{
	odp_packet_t pkt;
	odp_event_t ev;
	int res;

	my_test_val = TEST_FORWARD_HOOK;
	/* Call ofp_packet_input using a pkt with destination ip
	 * that does NOT match the local ip on ifnet and NO route is found.
	 * The packet is forwarded to slow path queue. */
	if (create_odp_packet_ip4(&pkt, test_frame, sizeof(test_frame), 0, 0)) {
		CU_FAIL("Fail to create packet");
		return;
	}

	res = ofp_packet_input(pkt, interface_queue[port],
		ofp_eth_vlan_processing);

	CU_ASSERT_EQUAL(res, OFP_PKT_PROCESSED);

	CU_ASSERT_NOT_EQUAL_FATAL(ev = odp_queue_deq(ifnet->spq_def),
			    ODP_EVENT_INVALID);
	CU_ASSERT_EQUAL(odp_queue_deq(ifnet->spq_def), ODP_EVENT_INVALID);
	CU_ASSERT_EQUAL(odp_queue_deq(ifnet->outq_def), ODP_EVENT_INVALID);

	if (memcmp(odp_packet_data(odp_packet_from_event(ev)),
		   in_pkt_data, sizeof(test_frame)))
		CU_FAIL("corrupt data sent to slow path");
	odp_packet_free(odp_packet_from_event(ev));
	CU_PASS("ofp_packet_input_to_sp");
}
#endif /* SP */

static void
test_ofp_packet_input_send_arp(void)
{
	odp_packet_t pkt;
	odp_event_t ev;
	int res;

	/*
	 * Remove route to local ip address
	 */
	ofp_set_route_params(OFP_ROUTE_DEL, 0, 0, 0,
			     dst_ipaddr, 32, 0, 0);

	/* Call ofp_packet_input using a pkt with destination ip
	 * that does NOT match the local ip on ifnet and a route is found.
	 * No ARP is found for gateway IP so an ARP req is sent.
	 * Function returns OFP_PKT_DROP and packet can be reused.*/
	my_test_val = TEST_FORWARD_HOOK;

	test_ofp_add_route(port, vrf, vlan, dst_ipaddr, 24, 4,
			dst_ipaddr + 1);

	if (create_odp_packet_ip4(&pkt, test_frame, sizeof(test_frame),
				  dst_ipaddr, 0)) {
		CU_FAIL("Fail to create packet");
		return;
	}

	res = ofp_packet_input(pkt, interface_queue[port],
		ofp_eth_vlan_processing);
#ifdef OFP_USE_LIBCK
	/* Saving pkt not implemented in arp ck */
	CU_ASSERT_EQUAL(res, OFP_PKT_DROP);
#else
	CU_ASSERT_EQUAL(res, OFP_PKT_PROCESSED);
#endif
	res = ofp_send_pending_pkt();
	CU_ASSERT_EQUAL(res, OFP_PKT_PROCESSED);
	odp_packet_free(pkt);

	CU_ASSERT_NOT_EQUAL_FATAL(ev = odp_queue_deq(ifnet->outq_def),
			    ODP_EVENT_INVALID);
	CU_ASSERT_EQUAL(odp_queue_deq(ifnet->outq_def), ODP_EVENT_INVALID);
#ifdef SP
	CU_ASSERT_EQUAL(odp_queue_deq(ifnet->spq_def), ODP_EVENT_INVALID);
#endif /* SP */

	pkt = odp_packet_from_event(ev);
	CU_ASSERT_NOT_EQUAL_FATAL(pkt, ODP_PACKET_INVALID);
	CU_ASSERT_EQUAL(odp_packet_has_arp(pkt), 1);
	CU_ASSERT_EQUAL(odp_packet_has_vlan(pkt), 0);
	CU_ASSERT_EQUAL(odp_packet_len(pkt), sizeof(struct ofp_arphdr) +
		sizeof(struct ofp_ether_header));
	odp_packet_free(odp_packet_from_event(ev));
	ofp_arp_init_tables_pkt_list(); /* to clean saved packet */
	CU_PASS("ofp_packet_input_send_arp");
}

static void
test_ofp_packet_input_forwarding_to_output(void)
{
	odp_packet_t pkt;
	odp_event_t ev;
	int res;

	/* Call ofp_packet_input using a pkt with destination ip
	 * that does NOT match the local ip on ifnet and a route is found.
	 * ARP is found for gateway IP.
	 * Function returns OFP_PKT_PROCESSED and
	 * packet is forwarded to ofp_ip_output.*/
	unsigned char ll_addr[13] = "123456789012";

	my_test_val = TEST_FORWARD_HOOK;

	CU_ASSERT_EQUAL(
		ofp_ipv4_lookup_mac(dst_ipaddr + 1, ll_addr, ifnet), -1);
	CU_ASSERT_EQUAL(
		ofp_add_mac(ifnet, dst_ipaddr + 1, ll_addr), 0);

	if (create_odp_packet_ip4(&pkt, test_frame, sizeof(test_frame),
				  dst_ipaddr, 0)) {
		CU_FAIL("Fail to create packet");
		return;
	}

	res = ofp_packet_input(pkt, interface_queue[port],
		ofp_eth_vlan_processing);
	CU_ASSERT_EQUAL(res, OFP_PKT_PROCESSED);

	res = ofp_send_pending_pkt();
	CU_ASSERT_EQUAL(res, OFP_PKT_PROCESSED);

	CU_ASSERT_NOT_EQUAL_FATAL(ev = odp_queue_deq(ifnet->outq_def),
			    ODP_EVENT_INVALID);
	CU_ASSERT_EQUAL(odp_queue_deq(ifnet->outq_def), ODP_EVENT_INVALID);

#ifdef SP
	CU_ASSERT_EQUAL(odp_queue_deq(ifnet->spq_def), ODP_EVENT_INVALID);
#endif /* SP */

	CU_ASSERT_EQUAL(odp_packet_len(pkt), sizeof(test_frame));

	pkt = odp_packet_from_event(ev);
	struct ofp_ip *ip_in_pkt_data =
		(struct ofp_ip *)(in_pkt_data + OFP_ETHER_HDR_LEN);
	ip_in_pkt_data->ip_ttl--;

#ifdef OFP_PERFORMANCE
        /*checksum is not filled on ip_output*/
        ip_in_pkt_data->ip_sum =
                ((struct ofp_ip *)odp_packet_l3_ptr(pkt, NULL))->ip_sum;
#else
        ip_in_pkt_data->ip_sum = 0;
        ip_in_pkt_data->ip_sum = ofp_cksum_buffer((uint16_t *)ip_in_pkt_data,
                                        ip_in_pkt_data->ip_hl<<2);

#endif

	if (memcmp((uint8_t *)odp_packet_data(pkt) + odp_packet_l3_offset(pkt),
		   in_pkt_data + OFP_ETHER_HDR_LEN,
		   sizeof(test_frame) - OFP_ETHER_HDR_LEN))
		CU_FAIL("corrupt l3 + data forwarded");
	struct ofp_ether_header *eth =
		(struct ofp_ether_header *)odp_packet_l2_ptr(pkt, NULL);

	if (memcmp(eth->ether_dhost, ll_addr, OFP_ETHER_ADDR_LEN))
		CU_FAIL("Bad destination mac address on the forwarded packet");
	CU_ASSERT_EQUAL(eth->ether_type, odp_cpu_to_be_16(OFP_ETHERTYPE_IP));

	CU_PASS("ofp_packet_input_forwarding_to_output");
}

static void
test_ofp_packet_input_gre_processed_inner_pkt_forwarded(void)
{
	odp_packet_t pkt;
	odp_event_t ev;
	int res;
	struct ofp_ether_header *eth;
	struct ofp_ip *ip;
	struct ofp_ip *ip_encap;
	uint32_t dst_ip;
	uint8_t dst_mac_addr[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};

	my_test_val = TEST_LOCAL_HOOK_GRE;
	/* Call ofp_packet_input using a GRE pkt with destination ip
	 * that matches the local ip on ifnet, tunnel found, GRE processed.
	 * Inner packet does not match local ip, route found,
	 * packet forwarded */

	ifnet->ip_addr_info[0].ip_addr = local_ip;
	if (create_odp_packet_ip4(&pkt, gre_frame, sizeof(gre_frame),
				  local_ip, tun_rem_ip)) {
		CU_FAIL("Fail to create packet");
		return;
	}

	ip_encap = (struct ofp_ip *)&in_pkt_data[38];

	dst_ip = local_ip + 10;
	test_ofp_add_route(port, vrf, vlan, ip_encap->ip_dst.s_addr, 24, 4,
			     dst_ip);
	ofp_add_mac(ifnet, dst_ip, dst_mac_addr);

	res = ofp_packet_input(pkt, interface_queue[port],
				 ofp_eth_vlan_processing);

	CU_ASSERT_EQUAL(res, OFP_PKT_PROCESSED);

	res = ofp_send_pending_pkt();
	CU_ASSERT_EQUAL(res, OFP_PKT_PROCESSED);

	CU_ASSERT_NOT_EQUAL_FATAL(ev = odp_queue_deq(ifnet->outq_def),
				  ODP_EVENT_INVALID);
#ifdef SP
	CU_ASSERT_EQUAL(odp_queue_deq(ifnet->spq_def), ODP_EVENT_INVALID);
#endif
	CU_ASSERT_EQUAL(odp_queue_deq(ifnet->outq_def), ODP_EVENT_INVALID);

	pkt = odp_packet_from_event(ev);
	eth = odp_packet_data(pkt);
	ip = odp_packet_l3_ptr(pkt, NULL);

	if (memcmp(eth->ether_dhost, dst_mac_addr, OFP_ETHER_ADDR_LEN))
		CU_FAIL("Bad destination mac address.");
	if (memcmp(eth->ether_shost, ifnet->mac, OFP_ETHER_ADDR_LEN))
		CU_FAIL("Bad source mac address.");

	CU_ASSERT_EQUAL(ip->ip_src.s_addr, ip_encap->ip_src.s_addr);
	CU_ASSERT_EQUAL(ip->ip_dst.s_addr, ip_encap->ip_dst.s_addr);

	if (memcmp(ip + (ip->ip_hl << 2), ip_encap + (ip->ip_hl << 2),
		   odp_be_to_cpu_16(ip_encap->ip_len) - (ip->ip_hl << 2)))
		CU_FAIL("corrupt l3 + data");

	odp_packet_free(odp_packet_from_event(ev));
	ifnet->ip_addr_info[0].ip_addr = 0;
	CU_PASS("ofp_packet_input_gre_processed_inner_pkt_to_sp");
}

static void test_ofp_packet_input_gre_orig_pkt_to_sp(void)
{
	odp_packet_t pkt;
	int res;
#ifdef SP
	odp_event_t ev;
#endif

	my_test_val = TEST_LOCAL_HOOK_GRE_APP;
	/* Call ofp_packet_input using a GRE pkt with destination ip
	 * that matches the local ip on ifnet, tunnel not found,
	 * packet offered to GRE hook, returns continue.
	 * Full packet sent to slowpath */

	ifnet->ip_addr_info[0].ip_addr = local_ip;
	if (create_odp_packet_ip4(&pkt, gre_frame, sizeof(gre_frame),
				  local_ip, tun_rem_ip + 1)) {
		CU_FAIL("Fail to create packet");
		return;
	}

	res = ofp_packet_input(pkt, interface_queue[port],
				 ofp_eth_vlan_processing);

#ifdef SP
	CU_ASSERT_EQUAL(res, OFP_PKT_PROCESSED);

	CU_ASSERT_NOT_EQUAL_FATAL(ev = odp_queue_deq(ifnet->spq_def),
				  ODP_EVENT_INVALID);
	CU_ASSERT_EQUAL(odp_queue_deq(ifnet->spq_def), ODP_EVENT_INVALID);
	CU_ASSERT_EQUAL(odp_queue_deq(ifnet->outq_def), ODP_EVENT_INVALID);

	if (memcmp(odp_packet_data(odp_packet_from_event(ev)),
		   in_pkt_data, sizeof(gre_frame)))
		CU_FAIL("corrupt data sent to slow path");

	odp_packet_free(odp_packet_from_event(ev));
	ifnet->ip_addr_info[0].ip_addr = 0;
	CU_PASS("ofp_packet_input_gre_orig_pkt_to_sp");
#else
	CU_ASSERT_EQUAL(res, OFP_PKT_DROP);
	CU_ASSERT_EQUAL(odp_queue_deq(ifnet->outq_def), ODP_EVENT_INVALID);
#endif
}

static void test_init_packet_input_basic(void)
{
	port = 0;
	vlan = 0;
	vrf = 0;
	local_ip = dst_ipaddr;
}

static void test_init_packet_input_vrf(void)
{
	port = 1;
	vlan = 0;
	vrf = 1;
	local_ip = dst_ipaddr / 2;
	tun_rem_ip += 1;
	tun_p2p += 1;
	tun_addr += 1;
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

	(void)gre_frame;

	/* Initialize the CUnit test registry */
	if (CUE_SUCCESS != CU_initialize_registry())
		return CU_get_error();

	/* add a suite to the registry */
	ptr_suite = CU_add_suite("ofp packet input", init_suite, clean_suite);
	if (NULL == ptr_suite) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if (NULL == CU_ADD_TEST(ptr_suite,
				test_init_packet_input_basic)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if (NULL == CU_ADD_TEST(ptr_suite,
				test_init_ifnet)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if (NULL == CU_ADD_TEST(ptr_suite,
				test_ofp_packet_input_local_hook)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite,
				test_ofp_packet_input_local_IPv4_hook)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite,
				test_ofp_packet_input_local_UDPv4_hook)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
#ifdef SP
	if (NULL == CU_ADD_TEST(ptr_suite,
				test_ofp_packet_input_to_sp)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
#endif /* SP */
	if (NULL == CU_ADD_TEST(ptr_suite,
				test_ofp_packet_input_send_arp)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if (NULL == CU_ADD_TEST(ptr_suite,
				test_ofp_packet_input_forwarding_to_output)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if (NULL == CU_ADD_TEST(ptr_suite,
				test_ofp_packet_input_gre_processed_inner_pkt_forwarded)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if (NULL == CU_ADD_TEST(ptr_suite,
				test_ofp_packet_input_gre_orig_pkt_to_sp)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	ptr_suite = CU_add_suite("test VRF", NULL , NULL);
	if (NULL == ptr_suite) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite,
				test_init_packet_input_vrf)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite,
				test_init_ifnet)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

#ifdef SP
	if (NULL == CU_ADD_TEST(ptr_suite,
				test_ofp_packet_input_to_sp)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
#endif /* SP */

	if (NULL == CU_ADD_TEST(ptr_suite,
				test_ofp_packet_input_send_arp)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if (NULL == CU_ADD_TEST(ptr_suite,
				test_ofp_packet_input_forwarding_to_output)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if (NULL == CU_ADD_TEST(ptr_suite,
				test_ofp_packet_input_gre_processed_inner_pkt_forwarded)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if (NULL == CU_ADD_TEST(ptr_suite,
				test_ofp_packet_input_gre_orig_pkt_to_sp)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

#if OFP_TESTMODE_AUTO
	CU_set_output_filename("CUnit-PKT-IN");
	CU_automated_run_tests();
#else
	/* Run all tests using the CUnit Basic interface */
	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
#endif

	nr_of_failed_tests = CU_get_number_of_tests_failed();
	nr_of_failed_suites = CU_get_number_of_suites_failed();
	CU_cleanup_registry();

	ofp_term_local();

	return (nr_of_failed_suites > 0 ?
		nr_of_failed_suites : nr_of_failed_tests);
}
