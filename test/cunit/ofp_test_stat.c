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

#if OFP_TESTMODE_AUTO
#include <CUnit/Automated.h>
#else
#include <CUnit/Basic.h>
#endif

#include <odp.h>
#include "../../src/ofp_stat.c"

/*
 * INIT
 */
static int
init_suite(void)
{
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

	if (ofp_stat_init_global()) {
		OFP_ERR("Error: Fail to initialize statistics.\n");
		return -1;
	}

	odp_shm_print_all();

	return 0;
}

static int
clean_suite(void)
{
	return 0;
}

/*
 * Testcases
 */
static void
test_ofp_stat_lookup_shared_memory(void)
{
	ofp_stat_lookup_shared_memory();
	/* ODP_ABORT if problem happens */

	CU_PASS("Stat shm lookup successful");
}

static void
test_packet_statistics(void)
{
	struct ofp_packet_stat *st;

	st = ofp_get_packet_statistics();
	CU_ASSERT_EQUAL(st->per_thr[odp_thread_id()].rx_fp, 0);

	OFP_UPDATE_PACKET_STAT(rx_fp, 4);
	CU_ASSERT_EQUAL(st->per_thr[odp_thread_id()].rx_fp, 4);
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
	ptr_suite = CU_add_suite("ofp stat", init_suite, clean_suite);
	if (NULL == ptr_suite) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if (NULL == CU_ADD_TEST(ptr_suite,
				test_ofp_stat_lookup_shared_memory)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite, test_packet_statistics)) {
		CU_cleanup_registry();
		return CU_get_error();
	}


#if OFP_TESTMODE_AUTO
	CU_set_output_filename("CUnit-Stat");
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
