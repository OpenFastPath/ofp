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

#include "fragmented_packet.h"

#define fail_with_odp(msg) do { OFP_ERR(msg); CU_FAIL(msg); } while (0)

/*
 * Test data
 */

#define PKT_BUF_SIZE  3000

static uint32_t port = 0, vlan = 0, vrf = 0, def_mtu = 1500;
static uint32_t dev_ip = 0x650AA8C0;   /* C0.A8.0A.65 = 192.168.10.101 */
static uint8_t dev_mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
static uint32_t dst_ipaddr = 0x660AA8C0; /* C0.A8.0A.66 = 192.168.10.102 */
static uint8_t dst_mac[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
static uint8_t orig_pkt_data[PKT_BUF_SIZE];
static struct ofp_nh_entry nexthop;
static struct ofp_ifnet *dev;

/*
 * Helpers
 */

static void init_ifnet(void)
{
	char str[256];

	ofp_config_interface_up_v4(port, vlan, vrf, dev_ip, 24);

	dev = ofp_get_ifnet(port, vlan);
	memcpy(dev->mac, dev_mac, OFP_ETHER_ADDR_LEN);
	dev->if_mtu = def_mtu;
#ifdef SP
	dev->linux_index = port + 3; /* an if index of Linux != port val */
	ofp_update_ifindex_lookup_tab(dev);
#endif /* SP */

	dev->pkt_pool = odp_pool_lookup("packet_pool");

	sprintf(str, "out default queue:%d", port);
	dev->outq_def = odp_queue_create(str, NULL);
	if (dev->outq_def == ODP_QUEUE_INVALID) {
		fail_with_odp("Out default queue create failed.\n");
		return;
	}

	dev->out_queue_num = 1;
	dev->out_queue_type = OFP_OUT_QUEUE_TYPE_QUEUE;
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
	(void) ofp_init_global(instance, &params);

	ofp_init_local();

	init_ifnet();

	ofp_add_mac(dev, dst_ipaddr, dst_mac);

	nexthop.gw = dst_ipaddr;
	nexthop.vlan = vlan;
	nexthop.port = port;
	/*Next Hop expects a ARP index for gw address*/
	ofp_ipv4_lookup_arp_entry_idx(nexthop.gw,
				      vrf, &nexthop.arp_ent_idx);

	return 0;
}

static int
clean_suite(void)
{
	ofp_term_local();
	return 0;
}

static int
create_odp_packet_ip4(odp_packet_t *opkt, uint8_t *pkt_data, int plen,
		      uint32_t dst_addr)
{
	odp_pool_t pool;
	uint8_t *buf;
	odp_packet_t pkt = ODP_PACKET_INVALID;
	struct ofp_ip *iphdr;

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

	if (odp_packet_copy_from_mem(pkt, 0, plen, pkt_data) < 0) {
		fail_with_odp("Packet data copy failed\n");
		return -1;
	};

	iphdr = (struct ofp_ip *)&buf[OFP_ETHER_HDR_LEN];

	/* changes to the default packet. Recalculate ip checksum */
	if (dst_addr) {
		iphdr->ip_dst.s_addr = dst_addr;
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

	memcpy(orig_pkt_data, pkt_data, plen);

	return 0;
}

static void assert_ip_header(struct ofp_ip *ip, struct ofp_ip *ip_orig,
			     uint16_t len, uint16_t mf, uint16_t fr_off)
{
	CU_ASSERT_EQUAL(ip->ip_hl, ip_orig->ip_hl);
	CU_ASSERT_EQUAL(ip->ip_v, ip_orig->ip_v);
	CU_ASSERT_EQUAL(ip->ip_tos, ip_orig->ip_tos);
	CU_ASSERT_EQUAL(ip->ip_len, odp_cpu_to_be_16(len));
	CU_ASSERT_EQUAL(ip->ip_id, ip_orig->ip_id);
	if (mf)
		CU_ASSERT((odp_be_to_cpu_16(ip->ip_off) & OFP_IP_MF) > 0)
	else
		CU_ASSERT((odp_be_to_cpu_16(ip->ip_off) & OFP_IP_MF) == 0)
	CU_ASSERT_EQUAL(odp_be_to_cpu_16(ip->ip_off) & OFP_IP_OFFMASK,
			fr_off);
	CU_ASSERT_EQUAL(ip->ip_ttl, ip_orig->ip_ttl);
	CU_ASSERT_EQUAL(ip->ip_p, ip_orig->ip_p);
	CU_ASSERT_EQUAL(ip->ip_src.s_addr, ip_orig->ip_src.s_addr);
	CU_ASSERT_EQUAL(ip->ip_dst.s_addr, ip_orig->ip_dst.s_addr);
}

static enum ofp_return_code send_packet(odp_packet_t pkt)
{
	/*
	 * Send packets as if they were forwarded to avoid the stack
	 * touching the ID field of the IP header.
	 */
	return ofp_ip_output_common(pkt, &nexthop, 0, OFP_IPSEC_SA_INVALID);
}

static void send_packet_and_check(odp_packet_t pkt)
{
	int res;

	res = send_packet(pkt);
	CU_ASSERT_EQUAL(res, OFP_PKT_PROCESSED);

	res = ofp_send_pending_pkt();
	CU_ASSERT_EQUAL(res, OFP_PKT_PROCESSED);
}

/*
 * Tests
 */

static void test_packet_size_is_less_then_mtu(void)
{
	odp_packet_t pkt_orig, pkt_sent;
	odp_event_t ev;
	struct ofp_ether_header *eth;

	if (create_odp_packet_ip4(&pkt_orig, pkt1_frag1,
				  sizeof(pkt1_frag1), 0)) {
		CU_FAIL("Fail to create packet");
		return;
	}

	send_packet_and_check(pkt_orig);

	ev = odp_queue_deq(dev->outq_def);
	CU_ASSERT_NOT_EQUAL_FATAL(ev, ODP_EVENT_INVALID);
	CU_ASSERT_EQUAL_FATAL(odp_queue_deq(dev->outq_def), ODP_EVENT_INVALID);

	pkt_sent = odp_packet_from_event(ev);
	CU_ASSERT_EQUAL_FATAL(odp_packet_len(pkt_sent), sizeof(pkt1_frag1));

	eth = odp_packet_l2_ptr(pkt_sent, NULL);
	if (memcmp(eth->ether_dhost, dst_mac, OFP_ETHER_ADDR_LEN))
		CU_FAIL("Bad destination mac address.");
	if (memcmp(eth->ether_shost, dev->mac, OFP_ETHER_ADDR_LEN))
		CU_FAIL("Bad source mac address.");
	if (memcmp(odp_packet_l3_ptr(pkt_sent, NULL),
		   &orig_pkt_data[OFP_ETHER_HDR_LEN],
		   sizeof(pkt1_frag1) - OFP_ETHER_HDR_LEN))
		CU_FAIL("corrupt l3 + data forwarded");
	CU_PASS("Correct packet");

	odp_packet_free(pkt_sent);
}

static void test_dont_fragment_set_pkt_dropped(void)
{
	odp_packet_t pkt;
	odp_event_t ev;
	int res;
	struct ofp_ip *ip;

	if (create_odp_packet_ip4(&pkt, pkt1_full,
				  sizeof(pkt1_full), 0)) {
		CU_FAIL("Fail to create packet");
		return;
	}

	ip = odp_packet_l3_ptr(pkt, NULL);
	ip->ip_off |= odp_cpu_to_be_16(OFP_IP_DF);

	res = ofp_ip_send(pkt, &nexthop);
	CU_ASSERT_EQUAL(res, OFP_PKT_DROP);

	ev = odp_queue_deq(dev->outq_def);
	CU_ASSERT_EQUAL(ev, ODP_EVENT_INVALID);

	odp_packet_free(pkt);
}


static void test_packet_to_two_fragments(void)
{
	odp_packet_t pkt_orig, pkt_sent;
	odp_event_t ev;
	struct ofp_ether_header *eth;
	struct ofp_ip *ip;
	struct ofp_ip *ip_orig;
	uint16_t pl_pos, pl_len, orig_pl_len, pktlen;

	if (create_odp_packet_ip4(&pkt_orig, pkt1_full, sizeof(pkt1_full), 0)) {
		CU_FAIL("Fail to create packet");
		return;
	}

	send_packet_and_check(pkt_orig);

	/* ASSERT 1st fragment */
	ev = odp_queue_deq(dev->outq_def);
	CU_ASSERT_NOT_EQUAL_FATAL(ev, ODP_EVENT_INVALID);

	pkt_sent = odp_packet_from_event(ev);
	CU_ASSERT_EQUAL_FATAL(odp_packet_len(pkt_sent),
			      dev->if_mtu + OFP_ETHER_HDR_LEN);

	eth = odp_packet_l2_ptr(pkt_sent, NULL);
	if (memcmp(eth->ether_dhost, dst_mac, OFP_ETHER_ADDR_LEN))
		CU_FAIL("Bad destination mac address.");
	if (memcmp(eth->ether_shost, dev->mac, OFP_ETHER_ADDR_LEN))
		CU_FAIL("Bad source mac address.");

	ip = odp_packet_l3_ptr(pkt_sent, NULL);
	ip_orig = (struct ofp_ip *)(&orig_pkt_data[OFP_ETHER_HDR_LEN]);
	orig_pl_len = odp_be_to_cpu_16(ip_orig->ip_len) - (ip_orig->ip_hl<<2);

	assert_ip_header(ip, ip_orig, dev->if_mtu, 1, 0); /* MF, off=0 */

	pl_len = dev->if_mtu - (ip->ip_hl<<2);
	if (memcmp((uint8_t *)ip + (ip->ip_hl<<2),
		   (uint8_t *)ip_orig + (ip_orig->ip_hl<<2),
		   pl_len))
		CU_FAIL("corrupt l3 + data forwarded");
	pl_pos = pl_len;
	CU_PASS("Correct packet");

	odp_packet_free(pkt_sent);

	/* ASSERT 2nd fragment */
	ev = odp_queue_deq(dev->outq_def);
	CU_ASSERT_NOT_EQUAL_FATAL(ev, ODP_EVENT_INVALID);

	pkt_sent = odp_packet_from_event(ev);
	pl_len = orig_pl_len - pl_pos;
	pktlen = pl_len + OFP_ETHER_HDR_LEN + sizeof(struct ofp_ip);
	CU_ASSERT_EQUAL_FATAL(odp_packet_len(pkt_sent), pktlen); /* 1062 */

	eth = odp_packet_l2_ptr(pkt_sent, NULL);
	if (memcmp(eth->ether_dhost, dst_mac, OFP_ETHER_ADDR_LEN))
		CU_FAIL("Bad destination mac address.");
	if (memcmp(eth->ether_shost, dev->mac, OFP_ETHER_ADDR_LEN))
		CU_FAIL("Bad source mac address.");

	ip = odp_packet_l3_ptr(pkt_sent, NULL);

	assert_ip_header(ip, ip_orig, pl_len + sizeof(struct ofp_ip),
			 0, pl_pos/8); /* 1048, MF, 1480 */

	if (memcmp((uint8_t *)ip + (ip->ip_hl<<2),
		   (uint8_t *)ip_orig + (ip_orig->ip_hl<<2) + pl_pos,
		   pl_len))
		CU_FAIL("corrupt l3 + data forwarded");
	CU_PASS("Correct packet");

	odp_packet_free(pkt_sent);

	/* no more fragments */
	ev = odp_queue_deq(dev->outq_def);
	CU_ASSERT_EQUAL(ev, ODP_EVENT_INVALID);
}

static void test_packet_to_many_fragments(void)
{
	odp_packet_t pkt_orig, pkt_sent;
	odp_event_t ev;
	struct ofp_ether_header *eth;
	struct ofp_ip *ip;
	struct ofp_ip *ip_orig;
	uint16_t pl_pos, pl_len, orig_pl_len, pktlen, seglen;

	dev->if_mtu = 820;
	seglen = dev->if_mtu - sizeof(struct ofp_ip);

	if (create_odp_packet_ip4(&pkt_orig, pkt1_full, sizeof(pkt1_full), 0)) {
		CU_FAIL("Fail to create packet");
		return;
	}

	send_packet_and_check(pkt_orig);

	/* ASSERT 1st fragment */
	ev = odp_queue_deq(dev->outq_def);
	CU_ASSERT_NOT_EQUAL_FATAL(ev, ODP_EVENT_INVALID);

	pkt_sent = odp_packet_from_event(ev);
	CU_ASSERT_EQUAL_FATAL(odp_packet_len(pkt_sent),
			      dev->if_mtu + OFP_ETHER_HDR_LEN);

	eth = odp_packet_l2_ptr(pkt_sent, NULL);
	if (memcmp(eth->ether_dhost, dst_mac, OFP_ETHER_ADDR_LEN))
		CU_FAIL("Bad destination mac address.");
	if (memcmp(eth->ether_shost, dev->mac, OFP_ETHER_ADDR_LEN))
		CU_FAIL("Bad source mac address.");

	ip = odp_packet_l3_ptr(pkt_sent, NULL);
	ip_orig = (struct ofp_ip *)(&orig_pkt_data[OFP_ETHER_HDR_LEN]);
	orig_pl_len = odp_be_to_cpu_16(ip_orig->ip_len) - (ip_orig->ip_hl<<2);

	assert_ip_header(ip, ip_orig, dev->if_mtu, 1, 0);

	pl_len = dev->if_mtu - (ip->ip_hl<<2);
	if (memcmp((uint8_t *)ip + (ip->ip_hl<<2),
		   (uint8_t *)ip_orig + (ip_orig->ip_hl<<2),
		   pl_len))
		CU_FAIL("corrupt l3 + data forwarded");
	pl_pos = pl_len;
	CU_PASS("Correct packet");

	odp_packet_free(pkt_sent);

	/* ASSERT 2nd fragment */
	ev = odp_queue_deq(dev->outq_def);
	CU_ASSERT_NOT_EQUAL_FATAL(ev, ODP_EVENT_INVALID);

	pkt_sent = odp_packet_from_event(ev);
	pl_len = orig_pl_len - pl_pos;
	pl_len = (pl_len < seglen) ? pl_len : seglen;
	pktlen = pl_len + OFP_ETHER_HDR_LEN + sizeof(struct ofp_ip);
	CU_ASSERT_EQUAL_FATAL(odp_packet_len(pkt_sent), pktlen);

	eth = odp_packet_l2_ptr(pkt_sent, NULL);
	if (memcmp(eth->ether_dhost, dst_mac, OFP_ETHER_ADDR_LEN))
		CU_FAIL("Bad destination mac address.");
	if (memcmp(eth->ether_shost, dev->mac, OFP_ETHER_ADDR_LEN))
		CU_FAIL("Bad source mac address.");

	ip = odp_packet_l3_ptr(pkt_sent, NULL);

	assert_ip_header(ip, ip_orig, pl_len + sizeof(struct ofp_ip),
			 1, pl_pos/8);

	if (memcmp((uint8_t *)ip + (ip->ip_hl<<2),
		   (uint8_t *)ip_orig + (ip_orig->ip_hl<<2) + pl_pos,
		   pl_len))
		CU_FAIL("corrupt l3 + data forwarded");
	CU_PASS("Correct packet");
	pl_pos += pl_len;

	odp_packet_free(pkt_sent);

	/* ASSERT 3rd fragment */
	ev = odp_queue_deq(dev->outq_def);
	CU_ASSERT_NOT_EQUAL_FATAL(ev, ODP_EVENT_INVALID);

	pkt_sent = odp_packet_from_event(ev);
	pl_len = orig_pl_len - pl_pos;
	pl_len = (pl_len < seglen) ? pl_len : seglen;
	pktlen = pl_len + OFP_ETHER_HDR_LEN + sizeof(struct ofp_ip);
	CU_ASSERT_EQUAL_FATAL(odp_packet_len(pkt_sent), pktlen);

	eth = odp_packet_l2_ptr(pkt_sent, NULL);
	if (memcmp(eth->ether_dhost, dst_mac, OFP_ETHER_ADDR_LEN))
		CU_FAIL("Bad destination mac address.");
	if (memcmp(eth->ether_shost, dev->mac, OFP_ETHER_ADDR_LEN))
		CU_FAIL("Bad source mac address.");

	ip = odp_packet_l3_ptr(pkt_sent, NULL);

	assert_ip_header(ip, ip_orig, pl_len + sizeof(struct ofp_ip),
			 1, pl_pos/8);

	if (memcmp((uint8_t *)ip + (ip->ip_hl<<2),
		   (uint8_t *)ip_orig + (ip_orig->ip_hl<<2) + pl_pos,
		   pl_len))
		CU_FAIL("corrupt l3 + data forwarded");
	CU_PASS("Correct packet");
	pl_pos += pl_len;

	odp_packet_free(pkt_sent);

	/* ASSERT 4th fragment */
	ev = odp_queue_deq(dev->outq_def);
	CU_ASSERT_NOT_EQUAL_FATAL(ev, ODP_EVENT_INVALID);

	pkt_sent = odp_packet_from_event(ev);
	pl_len = orig_pl_len - pl_pos;
	pl_len = (pl_len < seglen) ? pl_len : seglen;
	pktlen = pl_len + OFP_ETHER_HDR_LEN + sizeof(struct ofp_ip);
	CU_ASSERT_EQUAL_FATAL(odp_packet_len(pkt_sent), pktlen);

	eth = odp_packet_l2_ptr(pkt_sent, NULL);
	if (memcmp(eth->ether_dhost, dst_mac, OFP_ETHER_ADDR_LEN))
		CU_FAIL("Bad destination mac address.");
	if (memcmp(eth->ether_shost, dev->mac, OFP_ETHER_ADDR_LEN))
		CU_FAIL("Bad source mac address.");

	ip = odp_packet_l3_ptr(pkt_sent, NULL);

	assert_ip_header(ip, ip_orig, pl_len + sizeof(struct ofp_ip),
			 0, pl_pos/8);

	if (memcmp((uint8_t *)ip + (ip->ip_hl<<2),
		   (uint8_t *)ip_orig + (ip_orig->ip_hl<<2) + pl_pos,
		   pl_len))
		CU_FAIL("corrupt l3 + data forwarded");
	CU_PASS("Correct packet");
	pl_pos += pl_len;

	odp_packet_free(pkt_sent);

	/* no more fragments */
	ev = odp_queue_deq(dev->outq_def);
	CU_ASSERT_EQUAL(ev, ODP_EVENT_INVALID);

	dev->if_mtu = def_mtu;
}

static void test_fragment_fragmented_to_two(void)
{
	odp_packet_t pkt_orig, pkt_sent;
	odp_event_t ev;
	struct ofp_ether_header *eth;
	struct ofp_ip *ip;
	struct ofp_ip *ip_orig;
	uint16_t pl_pos, pl_len, orig_pl_len, pktlen, start_offset;

	dev->if_mtu = 620;

	if (create_odp_packet_ip4(&pkt_orig, pkt1_frag2,
				  sizeof(pkt1_frag2), 0)) {
		CU_FAIL("Fail to create packet");
		return;
	}

	send_packet_and_check(pkt_orig);

	/* ASSERT 1st fragment */
	ev = odp_queue_deq(dev->outq_def);
	CU_ASSERT_NOT_EQUAL_FATAL(ev, ODP_EVENT_INVALID);

	pkt_sent = odp_packet_from_event(ev);
	CU_ASSERT_EQUAL_FATAL(odp_packet_len(pkt_sent),
			      dev->if_mtu + OFP_ETHER_HDR_LEN);

	eth = odp_packet_l2_ptr(pkt_sent, NULL);
	if (memcmp(eth->ether_dhost, dst_mac, OFP_ETHER_ADDR_LEN))
		CU_FAIL("Bad destination mac address.");
	if (memcmp(eth->ether_shost, dev->mac, OFP_ETHER_ADDR_LEN))
		CU_FAIL("Bad source mac address.");

	ip = odp_packet_l3_ptr(pkt_sent, NULL);
	ip_orig = (struct ofp_ip *)(&orig_pkt_data[OFP_ETHER_HDR_LEN]);
	orig_pl_len = odp_be_to_cpu_16(ip_orig->ip_len) - (ip_orig->ip_hl<<2);
	start_offset = odp_be_to_cpu_16(ip_orig->ip_off) & OFP_IP_OFFMASK;

	assert_ip_header(ip, ip_orig, dev->if_mtu, 1, start_offset);

	pl_len = dev->if_mtu - (ip->ip_hl<<2);
	if (memcmp((uint8_t *)ip + (ip->ip_hl<<2),
		   (uint8_t *)ip_orig + (ip_orig->ip_hl<<2),
		   pl_len))
		CU_FAIL("corrupt l3 + data forwarded");
	pl_pos = pl_len;
	CU_PASS("Correct packet");

	odp_packet_free(pkt_sent);

	/* ASSERT 2nd fragment */
	ev = odp_queue_deq(dev->outq_def);
	CU_ASSERT_NOT_EQUAL_FATAL(ev, ODP_EVENT_INVALID);

	pkt_sent = odp_packet_from_event(ev);
	pl_len = orig_pl_len - pl_pos;
	pktlen = pl_len + OFP_ETHER_HDR_LEN + sizeof(struct ofp_ip);
	CU_ASSERT_EQUAL_FATAL(odp_packet_len(pkt_sent), pktlen);

	eth = odp_packet_l2_ptr(pkt_sent, NULL);
	if (memcmp(eth->ether_dhost, dst_mac, OFP_ETHER_ADDR_LEN))
		CU_FAIL("Bad destination mac address.");
	if (memcmp(eth->ether_shost, dev->mac, OFP_ETHER_ADDR_LEN))
		CU_FAIL("Bad source mac address.");

	ip = odp_packet_l3_ptr(pkt_sent, NULL);

	assert_ip_header(ip, ip_orig, pl_len + sizeof(struct ofp_ip),
			 0, start_offset + pl_pos/8);

	if (memcmp((uint8_t *)ip + (ip->ip_hl<<2),
		   (uint8_t *)ip_orig + (ip_orig->ip_hl<<2) + pl_pos,
		   pl_len))
		CU_FAIL("corrupt l3 + data forwarded");
	CU_PASS("Correct packet");

	odp_packet_free(pkt_sent);

	/* no more fragments */
	ev = odp_queue_deq(dev->outq_def);
	CU_ASSERT_EQUAL(ev, ODP_EVENT_INVALID);

	dev->if_mtu = def_mtu;
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
	ptr_suite = CU_add_suite("ofp fragmentation", init_suite, clean_suite);
	if (NULL == ptr_suite) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if (NULL == CU_ADD_TEST(ptr_suite,
				test_packet_size_is_less_then_mtu)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if (NULL == CU_ADD_TEST(ptr_suite,
				test_dont_fragment_set_pkt_dropped)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if (NULL == CU_ADD_TEST(ptr_suite,
				test_packet_to_two_fragments)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if (NULL == CU_ADD_TEST(ptr_suite,
				test_packet_to_many_fragments)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if (NULL == CU_ADD_TEST(ptr_suite,
				test_fragment_fragmented_to_two)) {
		CU_cleanup_registry();
		return CU_get_error();
	}


#if OFP_TESTMODE_AUTO
	CU_set_output_filename("CUnit-fragmentation");
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
