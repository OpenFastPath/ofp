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

#include "odp.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#undef ARP_AGE_INTERVAL
#define ARP_AGE_INTERVAL 1

#undef ARP_ENTRY_TIMEOUT
#define ARP_ENTRY_TIMEOUT 2

#define ALLOW_UNUSED_LOCAL(x) false ? (void)x : (void)0

static const char *pool_name = "packet_pool";

static odp_atomic_u32_t still_running;
static odph_linux_pthread_t pp_thread_handle;
void *pp_thread(void *arg);

static int init_suite(void)
{
	odp_pool_param_t pool_params;
	ofp_pkt_hook pkt_hook[OFP_HOOK_MAX];
	odp_pool_t pool;
	odph_linux_thr_params_t thr_params;
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

	memset(pkt_hook, 0, sizeof(pkt_hook));

	pool_params.pkt.seg_len = SHM_PKT_POOL_BUFFER_SIZE;
	pool_params.pkt.len     = SHM_PKT_POOL_BUFFER_SIZE;
	pool_params.pkt.num     = SHM_PKT_POOL_NB_PKTS;
	pool_params.type        = ODP_POOL_PACKET;

	(void) ofp_init_pre_global(pool_name, &pool_params, pkt_hook, &pool,
				   ARP_AGE_INTERVAL, ARP_ENTRY_TIMEOUT,
				   ODP_SCHED_GROUP_ALL);

	/*
	 * Start a packet processing thread to service timer events.
	 */
	odp_atomic_store_u32(&still_running, 1);

	odp_cpumask_t cpumask;
	odp_cpumask_zero(&cpumask);
	odp_cpumask_set(&cpumask, 0x1);
	thr_params.start = pp_thread;
	thr_params.arg = NULL;
	thr_params.thr_type = ODP_THREAD_WORKER;
	thr_params.instance = instance;
	odph_linux_pthread_create(&pp_thread_handle,
				&cpumask,
				&thr_params);

	return 0;
}

static int end_suite(void)
{
	odp_atomic_store_u32(&still_running, 0);

	odph_linux_pthread_join(&pp_thread_handle, 1);

	return 0;
}

void *pp_thread(void *arg)
{
	ALLOW_UNUSED_LOCAL(arg);
	if (ofp_init_local()) {
		OFP_ERR("ofp_init_local failed");
		return NULL;
	}

	while (odp_atomic_load_u32(&still_running)) {
		odp_event_t event;
		odp_queue_t source_queue;

		event = odp_schedule(&source_queue, ODP_SCHED_WAIT);

		if (odp_event_type(event) != ODP_EVENT_TIMEOUT) {
			OFP_ERR("Unexpected event type %d",
				odp_event_type(event));
			continue;
		}

		ofp_timer_handle(event);
	}
	return NULL;
}

static void test_arp(void)
{
	struct ofp_ifnet mock_ifnet;
	struct in_addr ip;
	uint8_t mac[OFP_ETHER_ADDR_LEN] = { 0x00, 0xFF, 0x00, 0x00, 0xFF, 0x00, };

	/* The buffer passed into ofp_ipv4_lookup_mac() must be 8 bytes since
	 * a 64-bit operation is currently being used to copy a MAC address.
	 */
	uint8_t mac_result[OFP_ETHER_ADDR_LEN + 2];

	CU_ASSERT(0 == ofp_init_local());

	memset(&mock_ifnet, 0, sizeof(mock_ifnet));
	CU_ASSERT(0 != inet_aton("1.1.1.1", &ip));

	/* Test entry insert, lookup, and remove. */
	CU_ASSERT(-1 == ofp_ipv4_lookup_mac(ip.s_addr, mac_result, &mock_ifnet));

	CU_ASSERT(0 == ofp_arp_ipv4_insert(ip.s_addr, mac, &mock_ifnet));

	memset(mac_result, 0xFF, OFP_ETHER_ADDR_LEN);
	CU_ASSERT(0 == ofp_ipv4_lookup_mac(ip.s_addr, mac_result, &mock_ifnet));
	CU_ASSERT(0 == memcmp(mac, mac_result, OFP_ETHER_ADDR_LEN));

	CU_ASSERT(0 == ofp_arp_ipv4_remove(ip.s_addr, &mock_ifnet));
	CU_ASSERT(-1 == ofp_ipv4_lookup_mac(ip.s_addr, mac_result, &mock_ifnet));

	/* Test entry is aged out. */
	CU_ASSERT(0 == ofp_arp_ipv4_insert(ip.s_addr, mac, &mock_ifnet));
	OFP_INFO("Inserted ARP entry");
	sleep(ARP_AGE_INTERVAL + ARP_ENTRY_TIMEOUT);
	CU_ASSERT(-1 == ofp_ipv4_lookup_mac(ip.s_addr, mac_result, &mock_ifnet));

	/* Test entry is aged out after a few hits. */
	CU_ASSERT(0 == ofp_arp_ipv4_insert(ip.s_addr, mac, &mock_ifnet));
	OFP_INFO("Inserted ARP entry");
	sleep(ARP_AGE_INTERVAL);
	CU_ASSERT(0 == ofp_ipv4_lookup_mac(ip.s_addr, mac_result, &mock_ifnet));
	sleep(ARP_AGE_INTERVAL);
	CU_ASSERT(0 == ofp_ipv4_lookup_mac(ip.s_addr, mac_result, &mock_ifnet));
	sleep(ARP_AGE_INTERVAL + ARP_ENTRY_TIMEOUT);
	CU_ASSERT(-1 == ofp_ipv4_lookup_mac(ip.s_addr, mac_result, &mock_ifnet));
}

int main(void)
{
	CU_pSuite ptr_suite = NULL;
	int nr_of_failed_tests = 0;
	int nr_of_failed_suites = 0;

	/* Initialize the CUnit test registry */
	if (CUE_SUCCESS != CU_initialize_registry())
		return CU_get_error();

	/* add a suite to the registry */
	ptr_suite = CU_add_suite("ofp errno", init_suite, end_suite);
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
