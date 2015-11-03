/* Copyright (c) 2014, Nokia
 * Copyright (c) 2014, ENEA Software AB
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

//#define OFP_TESTMODE_AUTO 1

#if defined(OFP_TESTMODE_AUTO)
#include <CUnit/Automated.h>
#else
#include <CUnit/Basic.h>
#endif

#include "ofpi.h"
#include "ofpi_arp.h"

#include "ofp_log.h"

#include "odp/barrier.h"
#include "odp/helper/linux.h"
#include "odp/init.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#define SHM_PKT_POOL_SIZE      (32*2048)
#define SHM_PKT_POOL_BUF_SIZE  3000

static const char *pool_name = "packet_pool";

static int init_suite(void)
{
	odp_pool_param_t pool_params;
	ofp_pkt_hook pkt_hook[OFP_HOOK_MAX];
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

	memset(pkt_hook, 0, sizeof(pkt_hook));

	pool_params.pkt.seg_len = SHM_PKT_POOL_BUF_SIZE;
	pool_params.pkt.len     = SHM_PKT_POOL_BUF_SIZE;
	pool_params.pkt.num     = SHM_PKT_POOL_SIZE / SHM_PKT_POOL_BUF_SIZE;
	pool_params.type        = ODP_POOL_PACKET;

	(void) ofp_init_pre_global(pool_name, &pool_params,
			pkt_hook, &pool);

	return 0;
}

/* Test insert, lookup, and remove. */
static void test_arp(void)
{
	struct ofp_ifnet dev0;
	struct in_addr ip;
	uint8_t mac[OFP_ETHER_ADDR_LEN] = { 0x00, 0xFF, 0x00, 0x00, 0xFF, 0x00, };

	/* The buffer passed into ofp_ipv4_lookup_mac() must be 8 bytes since
	 * a 64-bit operation is currently being used to copy a MAC address.
	 */
	uint8_t mac_result[OFP_ETHER_ADDR_LEN + 2];

	CU_ASSERT(0 == ofp_init_local());

	memset(&dev0, 0, sizeof(dev0));
	CU_ASSERT(0 != inet_aton("1.1.1.1", &ip));

	CU_ASSERT(-1 == ofp_ipv4_lookup_mac(ip.s_addr, mac_result, &dev0));

	CU_ASSERT(0 == ofp_arp_ipv4_insert(ip.s_addr, mac, &dev0));

	memset(mac_result, 0xFF, OFP_ETHER_ADDR_LEN);
	CU_ASSERT(0 == ofp_ipv4_lookup_mac(ip.s_addr, mac_result, &dev0));
	CU_ASSERT(0 == memcmp(mac, mac_result, OFP_ETHER_ADDR_LEN));

	CU_ASSERT(0 == ofp_arp_ipv4_remove(ip.s_addr, &dev0));
	CU_ASSERT(-1 == ofp_ipv4_lookup_mac(ip.s_addr, mac_result, &dev0));
}

/* TODO: Test arp timeout, reply/response */

int main(void)
{
	CU_pSuite ptr_suite = NULL;
	int nr_of_failed_tests = 0;
	int nr_of_failed_suites = 0;

	/* Initialize the CUnit test registry */
	if (CUE_SUCCESS != CU_initialize_registry())
		return CU_get_error();

	/* add a suite to the registry */
	ptr_suite = CU_add_suite("ofp errno", init_suite, NULL);
	if (NULL == ptr_suite) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite, test_arp)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

#if defined(OFP_TESTMODE_AUTO)
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
