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

#include <odp_api.h>
#include "odp/helper/odph_api.h"

#include "ofp_errno.h"
#include "ofpi.h"

#include <unistd.h>

static odp_instance_t instance;

static int init_suite(void)
{
	/* Must be called to create threads via ODP. */
	if (odp_init_global(&instance, NULL, NULL) < 0) {
		CU_FAIL("Error: odp_init_global failed");
		return -1;
	}
	return 0;
}

static int
clean_suite(void)
{
	if (odp_term_global(instance))
		OFP_ERR("Error: ODP global term failed.\n");

	return 0;
}

static void test_strerrno(void)
{
	CU_ASSERT_STRING_EQUAL(ofp_strerror(OFP_EALREADY), "Operation already in progress");
	CU_ASSERT_STRING_EQUAL(ofp_strerror(OFP_ELAST+1), "");
}

/* Test that threads can only read/write their own ofp_errno. ODP threads are
 * not required to test this functionality, but use them anyway.
 */
int other_thread(void *arg);
static void test_tls_errno(void)
{
	odp_cpumask_t cpumask;
	odph_thread_t threads;
	odp_barrier_t barrier__;
	odp_barrier_t *barrier;
	odph_thread_param_t thr_params;
	odph_thread_common_param_t thr_common;

	CU_ASSERT(1 == odp_cpumask_default_worker(&cpumask, 1));

	barrier = &barrier__;
	odp_barrier_init(barrier, 2);

	odph_thread_param_init(&thr_params);
	thr_params.start = other_thread;
	thr_params.arg = (void *)barrier;
	thr_params.thr_type = ODP_THREAD_CONTROL;
	odph_thread_common_param_init(&thr_common);
	thr_common.instance = instance;
	thr_common.cpumask = &cpumask;
	thr_common.share_param = 1;

	CU_ASSERT(odph_thread_create(&threads, &thr_common, &thr_params, 1) == 1);

	/* Initialize this thread's ofp_errno. */
	ofp_errno = 0;

	/* Test 1 - Test that an assignment to the current thread's ofp_errno
	*           does not modify the ofp_errno of other_thread.
	*/
	odp_barrier_wait(barrier);
	ofp_errno = OFP_EIO;
	odp_barrier_wait(barrier);
	CU_ASSERT_EQUAL(ofp_errno, OFP_EIO);

	/* Test 2 - Test both threads. */
	odp_barrier_wait(barrier);
	ofp_errno = OFP_EPERM;
	odp_barrier_wait(barrier);
	CU_ASSERT_EQUAL(ofp_errno, OFP_EPERM);

	odph_thread_join(&threads, 1);
}

int other_thread(void *arg)
{
	odp_barrier_t *barrier = (odp_barrier_t *)arg;

	/* Initialize this thread's ofp_errno. */
	ofp_errno = 0;

	/* Test 1 */
	odp_barrier_wait(barrier);
	/* ... */
	odp_barrier_wait(barrier);
	CU_ASSERT_EQUAL(ofp_errno, 0);

	/* Test 2 */
	odp_barrier_wait(barrier);
	ofp_errno = OFP_ENOENT;
	odp_barrier_wait(barrier);
	CU_ASSERT_EQUAL(ofp_errno, OFP_ENOENT);

	return 0;
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
	ptr_suite = CU_add_suite("ofp errno", init_suite, clean_suite);
	if (NULL == ptr_suite) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite, test_strerrno)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite, test_tls_errno)) {
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
