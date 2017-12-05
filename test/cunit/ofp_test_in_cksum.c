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
#include <ofpi_ethernet.h>
#include "ofpi.h"
#include "ofpi_log.h"
#include "../../src/ofp_in_cksum.c"
#include "fragmented_packet.h"
#include "cksum_packets.h"

/*
 * Test data
 */
char testFileName[] = "testbuf.txt";
uint32_t ipaddr = 0x650AA8C0; /* C0.A8.0A.65 = 192.168.10.101 */
uint8_t ip6addr[16] = {
0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef
};
uint8_t macaddr[6] = { 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA };

/*
 * INIT
 */
static int
init_suite(void)
{
	odp_pool_param_t pool_params;
	odp_pool_t pool;
	odp_instance_t instance;

	(void)pkt1_frag1;
	(void)pkt1_frag2;

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

	odp_pool_param_init(&pool_params);
	pool_params.pkt.len = SHM_PKT_POOL_BUFFER_SIZE;
	pool_params.pkt.num = SHM_PKT_POOL_NB_PKTS;
	pool_params.type = ODP_POOL_PACKET;

	pool = odp_pool_create("packet_pool", &pool_params);
	if (pool == ODP_POOL_INVALID) {
		OFP_ERR("Error: packet pool create failed.\n");
		return -1;
	}

	odp_pool_print(pool);

	return 0;
}

static int
clean_suite(void)
{
	return 0;
}

/*
 * Helpers
 */
#define fail_with_odp(msg) do { OFP_ERR(msg); CU_FAIL(msg); } while (0)

static int
create_odp_packet_ip4(odp_packet_t *opkt, uint8_t *pkt_data, int plen)
{
	odp_pool_t pool;
	odp_packet_t pkt = ODP_PACKET_INVALID;

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

	if (odp_packet_copy_from_mem(pkt, 0, plen, pkt_data) < 0) {
		fail_with_odp("Packet data copy failed\n");
		return -1;
	};

	odp_packet_has_eth_set(pkt, 1);
	odp_packet_has_ipv4_set(pkt, 1);
	odp_packet_l2_offset_set(pkt, 0);
	odp_packet_l3_offset_set(pkt, OFP_ETHER_HDR_LEN);

	*opkt = pkt;

	return 0;
}

/*
 * Testcases
 */
static void
test_ofp_cksum_buffer__ip4_addr(void)
{
	uint16_t res = ofp_cksum_buffer((uint16_t *)&ipaddr, sizeof(ipaddr));

	CU_ASSERT_EQUAL(res, 0xF234);
}

static void
test_ofp_cksum_buffer_odd_len_icmp(void)
{
	odp_packet_t pkt;
	struct ofp_ip *ip;
	struct ofp_icmp *icmp;
	uint16_t res, ip_hl;

	if (create_odp_packet_ip4(&pkt, odd_len_icmp, sizeof(odd_len_icmp))) {
		CU_FAIL("Fail to create packet");
		return;
	}

	ip = odp_packet_l3_ptr(pkt, NULL);
	ip_hl = ip->ip_hl << 2;
	icmp = (struct ofp_icmp *)((uint8_t *)ip + ip_hl);
	icmp->icmp_cksum = 0;

	res = ofp_cksum_buffer((uint16_t *)icmp,
			     odp_be_to_cpu_16(ip->ip_len) - ip_hl);

	CU_ASSERT_EQUAL(res, 0x84F7);
}

static void
test___ofp_cksum(void)
{
	odp_packet_t pkt;
	struct ofp_ip *ip;
	struct ofp_icmp *icmp;
	uint16_t res, ip_hl;

	if (create_odp_packet_ip4(&pkt, pkt1_full, sizeof(pkt1_full))) {
		CU_FAIL("Fail to create packet");
		return;
	}

	ip = odp_packet_l3_ptr(pkt, NULL);
	ip_hl = ip->ip_hl << 2;
	icmp = (struct ofp_icmp *)((uint8_t *)ip + ip_hl);
	icmp->icmp_cksum = 0;

	res = __ofp_cksum(pkt,
			    odp_packet_l3_offset(pkt) + ip_hl,
			    odp_be_to_cpu_16(ip->ip_len) - ip_hl);

	CU_ASSERT_EQUAL(res, 0xA8ED);
}

static void
test_ofp_cksum(void)
{
	odp_packet_t pkt;
	struct ofp_ip *ip;
	struct ofp_icmp *icmp;
	uint16_t res, ip_hl;

	if (create_odp_packet_ip4(&pkt, pkt1_full, sizeof(pkt1_full))) {
		CU_FAIL("Fail to create packet");
		return;
	}

	ip = odp_packet_l3_ptr(pkt, NULL);
	ip_hl = ip->ip_hl << 2;
	icmp = (struct ofp_icmp *)((uint8_t *)ip + ip_hl);
	icmp->icmp_cksum = 0;

	res = ofp_cksum(pkt,
			  odp_packet_l3_offset(pkt) + ip_hl,
			  odp_be_to_cpu_16(ip->ip_len) - ip_hl);

	CU_ASSERT_EQUAL(res, 0x5712);
}

static void
test___ofp_in4_cksum(void)
{
	odp_packet_t pkt;
	struct ofp_ip *ip;
	struct ofp_udphdr *udp;
	uint16_t res, ip_hl;

	if (create_odp_packet_ip4(&pkt, udp_packet, sizeof(udp_packet))) {
		CU_FAIL("Fail to create packet");
		return;
	}

	ip = odp_packet_l3_ptr(pkt, NULL);
	ip_hl = ip->ip_hl << 2;
	udp = (struct ofp_udphdr *)((uint8_t *)ip + ip_hl);
	udp->uh_sum = 0;

	res = ofp_in4_cksum(pkt);

	CU_ASSERT_EQUAL(res, 0x4d2d);
}

static void
test_ofp_in4_cksum(void)
{
	odp_packet_t pkt;
	struct ofp_ip *ip;
	struct ofp_udphdr *udp;
	uint16_t res, ip_hl;

	if (create_odp_packet_ip4(&pkt, udp_packet, sizeof(udp_packet))) {
		CU_FAIL("Fail to create packet");
		return;
	}

	ip = odp_packet_l3_ptr(pkt, NULL);
	ip_hl = ip->ip_hl << 2;
	udp = (struct ofp_udphdr *)((uint8_t *)ip + ip_hl);
	udp->uh_sum = 0;

	res = ofp_in4_cksum(pkt);

	CU_ASSERT_EQUAL(res, 0x4d2d);
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
	ptr_suite = CU_add_suite("ofp util", init_suite, clean_suite);
	if (NULL == ptr_suite) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite,
				test_ofp_cksum_buffer__ip4_addr)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite,
				test_ofp_cksum_buffer_odd_len_icmp)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite, test___ofp_cksum)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite, test_ofp_cksum)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite, test___ofp_in4_cksum)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite, test_ofp_in4_cksum)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

#if OFP_TESTMODE_AUTO
	CU_set_output_filename("CUnit-Util");
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
