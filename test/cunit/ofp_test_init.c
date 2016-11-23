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
#include <ofp_init.h>
#include <ofp_cli.h>

odp_instance_t instance;

static int
init_suite(void)
{
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

	return 0;
}

static int
clean_suite(void)
{
	int rc = 0;

	if (odp_term_local() < 0) {
		OFP_ERR("Error: ODP local termination failed.\n");
		rc = -1;
	}
	if (odp_term_global(instance) < 0) {
		OFP_ERR("Error: ODP global termination failed.\n");
		rc = -1;
	}

	return rc;
}

static void
test_global_resources_init_cleanup(void)
{
	odp_pool_param_t pool_params;
	ofp_pkt_hook pkt_hook[OFP_HOOK_MAX];
	odp_pool_t pool;

	memset(pkt_hook, 0, sizeof(pkt_hook));
	pool_params.pkt.seg_len = SHM_PKT_POOL_BUFFER_SIZE;
	pool_params.pkt.len     = SHM_PKT_POOL_BUFFER_SIZE;
	pool_params.pkt.num     = SHM_PKT_POOL_NB_PKTS;
	pool_params.type        = ODP_POOL_PACKET;

	CU_ASSERT_EQUAL(ofp_init_pre_global(
				"packet_pool", &pool_params, pkt_hook, &pool,
				ARP_AGE_INTERVAL, ARP_ENTRY_TIMEOUT,
				ODP_SCHED_GROUP_ALL), 0);

	CU_ASSERT_EQUAL(ofp_term_post_global("packet_pool"), 0);
}

static void
test_global_init_cleanup(void)
{
	static ofp_init_global_t oig;

	CU_ASSERT_EQUAL(ofp_init_global(instance, &oig), 0);

	ofp_start_cli_thread(instance, oig.linux_core_id, NULL);

	CU_ASSERT_EQUAL(ofp_term_global(), 0);
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
	ptr_suite = CU_add_suite("ofp packet input", init_suite, clean_suite);
	if (NULL == ptr_suite) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if (NULL == CU_ADD_TEST(ptr_suite,
				test_global_resources_init_cleanup)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if (NULL == CU_ADD_TEST(ptr_suite,
				test_global_init_cleanup)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

#if OFP_TESTMODE_AUTO
	CU_set_output_filename("CUnit-INIT");
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
