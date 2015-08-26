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
#include <unistd.h>

#if OFP_TESTMODE_AUTO
#include <CUnit/Automated.h>
#else
#include <CUnit/Basic.h>
#endif

#include <odp.h>
#include <ofpi_ethernet.h>
#include "test_raw_frames.h"
#include "ofpi.h"
#include "ofpi_log.h"
#include "ofpi_debug.h"

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
#define SHM_PKT_POOL_SIZE      (32*2048)
#define SHM_PKT_POOL_BUF_SIZE  1856

static int
init_suite(void)
{
	odp_pool_param_t pool_params;
	odp_pool_t pool;

	/* Init ODP before calling anything else */
	if (odp_init_global(NULL, NULL)) {
		OFP_ERR("Error: ODP global init failed.\n");
		return -1;
	}

	/* Init this thread */
	if (odp_init_local(ODP_THREAD_CONTROL)) {
		OFP_ERR("Error: ODP local init failed.\n");
		return -1;
	}

	ofp_pcap_alloc_shared_memory();
	ofp_pcap_init_global();

	pool_params.pkt.seg_len = SHM_PKT_POOL_BUF_SIZE;
	pool_params.pkt.len = SHM_PKT_POOL_BUF_SIZE;
	pool_params.pkt.num = SHM_PKT_POOL_SIZE/SHM_PKT_POOL_BUF_SIZE;
	pool_params.type = ODP_POOL_PACKET;

	pool = odp_pool_create("packet_pool", &pool_params);
	if (pool == ODP_POOL_INVALID) {
		OFP_ERR("Error: packet pool create failed.\n");
		return -1;
	}

	odp_shm_print_all();
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

#define PCAP_TIMESTAMP_LEN 8
#define PCAP_PKT_SIZE_LEN 8

static int
assert_pcap_pkt(uint8_t *buf, unsigned buf_size, unsigned *offset,
		const uint8_t *ref_buf, unsigned ref_len)
{
	union{
		uint32_t ul[2];
		uint8_t b[8];
	} pkt_size;

	if (*offset + PCAP_TIMESTAMP_LEN + PCAP_PKT_SIZE_LEN + ref_len >
	    buf_size) {
		CU_FAIL("PCAP dump failed - buf_size to small");
		return -1;
	}

	/* don't check timestamp */
	*offset += PCAP_TIMESTAMP_LEN;

	pkt_size.ul[0] = ref_len;
	pkt_size.ul[1] = ref_len;
	if (memcmp(&buf[*offset], pkt_size.b, PCAP_PKT_SIZE_LEN)) {
		CU_FAIL("PCAP dump failed - pkt_size");
		return -1;
	}
	CU_PASS("PCAP dump");

	*offset += PCAP_PKT_SIZE_LEN;

	if (memcmp(&buf[*offset], ref_buf, ref_len)) {
		CU_FAIL("PCAP dump failed - ref_buf");
		return -1;
	}
	CU_PASS("PCAP dump");

	*offset += ref_len;

	return 0;
}

/*
 * Testcases
 */

static void
test_pcap(void)
{
	odp_packet_t pkt;
	int port = 22;
	unsigned fsize, l, offset = 0;
	uint8_t *buf;

	/* INIT */
	ofp_debug_capture_ports = 1 << port;
	ofp_debug_flags = OFP_DEBUG_PRINT_RECV_NIC |
			    OFP_DEBUG_PRINT_SEND_NIC |
			    OFP_DEBUG_CAPTURE;

	/* TEST */
	ofp_set_capture_file(pcap_file_name);

	if (create_odp_packet_ip4(&pkt, tcp_frame, sizeof(tcp_frame)))
		goto err;
	ofp_save_packet_to_pcap_file(OFP_DEBUG_PRINT_RECV_NIC, pkt, port);

	if (create_odp_packet_ip4(&pkt, arp_frame, sizeof(arp_frame)))
		goto err;
	ofp_save_packet_to_pcap_file(OFP_DEBUG_PRINT_RECV_NIC, pkt, port);

	if (create_odp_packet_ip4(&pkt, icmp_frame, sizeof(icmp_frame)))
		goto err;
	ofp_save_packet_to_pcap_file(OFP_DEBUG_PRINT_RECV_NIC, pkt, port);

	(void)ip6udp_frame;
	(void)icmp6_frame;

	/* ASSERT */
	FILE *f = fopen(pcap_file_name, "rb");

	fseek(f, 0, SEEK_END);
	fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	buf = (uint8_t *)malloc(fsize);
	l = fread(buf, 1, fsize, f);

	fclose(f);

	if (l < sizeof(pcap_header) ||
	    memcmp(&buf[offset], pcap_header, sizeof(pcap_header))) {
		CU_FAIL("PCAP header failed")
		goto err;
	} else {
		CU_PASS("PCAP header passed")
	}
	offset += sizeof(pcap_header);

	if (assert_pcap_pkt(buf, fsize, &offset, tcp_frame, sizeof(tcp_frame)))
		goto err;

	if (assert_pcap_pkt(buf, fsize, &offset, arp_frame, sizeof(arp_frame)))
		goto err;

	if (assert_pcap_pkt(buf, fsize, &offset, icmp_frame,
			    sizeof(icmp_frame)))
		goto err;

err:
	ofp_debug_capture_ports = 0;
	ofp_debug_flags = ofp_debug_flags ^ OFP_DEBUG_CAPTURE;
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
	ptr_suite = CU_add_suite("ofp capture", init_suite, clean_suite);
	if (NULL == ptr_suite) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite, test_pcap)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

#if OFP_TESTMODE_AUTO
	CU_set_output_filename("CUnit-PCAP");
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
