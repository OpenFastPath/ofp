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
#include <ofpi_ethernet.h>
#include "test_raw_frames.h"
#include "ofpi.h"
#include "ofpi_debug.h"
#include "../../src/ofp_debug_print.c"


/*
 * Test data
 */
char testFileName[] = "testbuf.txt";
char pcap_file_name[] = "test.pcap";
uint32_t ipaddr = 0x650AA8C0; /* C0.A8.0A.65 = 192.168.10.101 */
uint8_t ip6addr[16] = {
0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef
};
uint8_t macaddr[6] = { 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA };
uint8_t pcap_header[24] = {
0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00
};

/*
 * INIT
 */
static int
init_suite(void)
{
	odp_pool_param_t pool_params;
	odp_pool_t pool;
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


	pool_params.pkt.seg_len = SHM_PKT_POOL_BUFFER_SIZE;
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
	uint8_t *buf;
	odp_packet_t pkt;
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

	odp_packet_has_eth_set(pkt, 1);
	odp_packet_has_ipv4_set(pkt, 1);
	odp_packet_l2_offset_set(pkt, 0);
	odp_packet_l3_offset_set(pkt, OFP_ETHER_HDR_LEN);
	odp_packet_l4_offset_set(pkt, OFP_ETHER_HDR_LEN + (iphdr->ip_hl<<2));

	*opkt = pkt;

	return 0;
}

static char *get_packet_start(char *buff_txt)
{
	char *pkt_txt;

	pkt_txt = strstr(buff_txt, "CUnit-Util");
	if (pkt_txt == NULL)
		return NULL;

	while ((*pkt_txt != '\n') &&
		(*pkt_txt != 0))
		pkt_txt++;

	if (*pkt_txt == 0)
		pkt_txt = NULL;
	else
		pkt_txt++;

	return pkt_txt;
}

/*
 * Testcases
 */
static void
test_print_arp(void)
{
#define BUFLEN 46
	char res[BUFLEN];
	FILE *f;

	memset(res, 0x0, BUFLEN);

	f = fopen(testFileName, "w");
	print_arp(f, (char *)(&arp_frame[L2_HEADER_NO_VLAN_SIZE]));
	fclose(f);

	f = fopen(testFileName, "r");
	if (fgets(res, BUFLEN, f) != NULL) {
		CU_ASSERT_STRING_EQUAL(
			res,
			"ARP 1  192.168.56.101 -> 192.168.56.102 ");
	} else {
		CU_FAIL("Cannot read output file.");
	}
	fclose(f);
#undef BUFLEN
}

static void
test_print_ipv6__ip6udp_frame(void)
{
#define BUFLEN 120
	char res[BUFLEN];
	FILE *f;

	memset(res, 0x0, BUFLEN);

	f = fopen(testFileName, "w");
	print_ipv6(f, (char *)(&ip6udp_frame[L2_HEADER_NO_VLAN_SIZE]));
	fclose(f);

	f = fopen(testFileName, "r");
	if (fgets(res, BUFLEN, f) != NULL) {
		CU_ASSERT_STRING_EQUAL(
			res,
			"IPv6 UDP: len=44  fe80:0000:0000:0000:0222:68ff:fe0f:"
			"ba87 port 5353 -> ff02:0000:0000:0000:0000:0000:0000:"
			"00fb port 535");
	} else {
		CU_FAIL("Cannot read output file.");
	}
	fclose(f);
#undef BUFLEN
}

static void
test_print_ipv6__icmp6_frame(void)
{
#define BUFLEN 190
	char res[BUFLEN];
	FILE *f;

	memset(res, 0x0, BUFLEN);

	f = fopen(testFileName, "w");
	print_ipv6(f, (char *)(&icmp6_frame[L2_HEADER_NO_VLAN_SIZE]));
	fclose(f);

	f = fopen(testFileName, "r");
	if (fread(res, 1, BUFLEN, f)) {
		CU_ASSERT_STRING_EQUAL(
			res,
			"IPv6 ICMP: len=24 type=Neighbor-Solicitation target=fe80:0000:0000:0000:c51b:dd4f:db50:54d7 code=0\n"
			"  0000:0000:0000:0000:0000:0000:0000:0000 -> ff02:0000:0000:0000:0000:0001:ff50:54d7 ");
	} else {
		CU_FAIL("Cannot read output file.");
	}
	fclose(f);
#undef BUFLEN
}

static void
test_print_ipv4__tcpframe(void)
{
#define BUFLEN 200
	char res[BUFLEN];
	FILE *f;

	memset(res, 0x0, BUFLEN);

	f = fopen(testFileName, "w");
	print_ipv4(f, (char *)(&tcp_frame[L2_HEADER_NO_VLAN_SIZE]));
	fclose(f);

	f = fopen(testFileName, "r");
	if (fgets(res, BUFLEN, f) != NULL) {
		CU_ASSERT_STRING_EQUAL(
			res,
			"IP len=92 TCP 192.168.56.101:53662 -> 192.168.56.102:22\n");
	} else {
		CU_FAIL("Cannot read output file.");
	}
	fclose(f);
#undef BUFLEN
}

static void
test_print_ipv4__icmpframe(void)
{
#define BUFLEN 70
	char res[BUFLEN];
	FILE *f;

	memset(res, 0x0, BUFLEN);

	f = fopen(testFileName, "w");
	print_ipv4(f, (char *)(&icmp_frame[L2_HEADER_NO_VLAN_SIZE]));
	fclose(f);

	f = fopen(testFileName, "r");
	if (fgets(res, BUFLEN, f) != NULL) {
		CU_ASSERT_STRING_EQUAL(
			res,
			"IP ICMP: echo  192.168.56.101 -> 192.168.56.102  id=256 seq=15616");
	} else {
		CU_FAIL("Cannot read output file.");
	}
	fclose(f);
#undef BUFLEN
}

static void
test_ofp_print_packet(void)
{
#define BUFLEN 250
	char res[BUFLEN + 1];
	char *pkt_txt;
	FILE *f;
	odp_packet_t pkt;

	memset(res, 0x0, BUFLEN);

	if (create_odp_packet_ip4(&pkt, tcp_frame, sizeof(tcp_frame))) {
		CU_FAIL("Cannot create packet.");
		return;
	}

	/* outputs to packets.txt */
	ofp_print_packet("CUnit-Util", pkt);

	f = fopen(DEFAULT_DEBUG_TXT_FILE_NAME, "r");
	if (fread(res, 1, BUFLEN, f)) {
		pkt_txt = get_packet_start(res);
		if (pkt_txt == NULL) {
			CU_FAIL("Packet not found.");
			fclose(f);
			return;
		}
		CU_ASSERT_STRING_EQUAL(
			pkt_txt,
			" 08:00:27:00:a8:1e -> 08:00:27:ae:3e:d3\n"
			"  IP len=92 TCP 192.168.56.101:53662 "
			"-> 192.168.56.102:22\n"
			"   seq=0x3fc97a8a ack=0xee1651e9 off=5\n"
			"   flags=PA win=16383 sum=0xb5f0 urp=0\n");
	} else {
		CU_FAIL("Cannot read output file.");
	}
	fclose(f);
#undef BUFLEN
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
	ptr_suite = CU_add_suite("ofp debug print", init_suite, clean_suite);
	if (NULL == ptr_suite) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite, test_print_arp)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite, test_print_ipv6__ip6udp_frame)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite, test_print_ipv6__icmp6_frame)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite, test_print_ipv4__tcpframe)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite, test_print_ipv4__icmpframe)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite, test_ofp_print_packet)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

#if OFP_TESTMODE_AUTO
	CU_set_output_filename("CUnit-Debug-print");
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
