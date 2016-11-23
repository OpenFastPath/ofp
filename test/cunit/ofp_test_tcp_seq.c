/* Copyright (c) 2015, ENEA Software AB
 * Copyright (c) 2015, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <unistd.h>
#include <CUnit/Basic.h>

#include "odp.h"

#include "ofp_init.h"
#include "ofpi_tcp_seq.h"

static void test_when_timer_is_not_initialized_tick_count_is_zero(void)
{
	CU_ASSERT(tcp_ts_getticks() == 0);
}

static void initialize_odp(void);
static void initialize_ofp_timer(int resolution_us);
static void wait_until_timer_expires(int resolution_us);
static uint32_t getticks(void);
static uint32_t one_tick_in_ms(int resolution_us);
static void terminate_ofp_timer(void);
static void terminate_odp(void);
static void test_tick_count_is_increased_after_timer_expires(void)
{
	const int resolution_us = OFP_TIMER_RESOLUTION_US*2;

	initialize_odp();
	initialize_ofp_timer(resolution_us);

	wait_until_timer_expires(resolution_us);
	CU_ASSERT(getticks() <= one_tick_in_ms(resolution_us));

	terminate_ofp_timer();
	terminate_odp();
}

static char *const_cast(const char *str)
{
	return (char *)(uintptr_t)str;
}

odp_instance_t instance;

int main(void)
{
	CU_TestInfo tests[] = {
		{ const_cast("When timer is not initialized tick count is zero"),
		  test_when_timer_is_not_initialized_tick_count_is_zero },
		{ const_cast("Tick count is increased after timer expires"),
		  test_tick_count_is_increased_after_timer_expires },
		CU_TEST_INFO_NULL,
	};

	CU_SuiteInfo suites[] = {
		CU_SUITE_INFO_NULL,
		CU_SUITE_INFO_NULL,
	};
	suites[0].pName = const_cast("ofpi tcp seq");
	suites[0].pTests = tests;

	if (CU_initialize_registry() != CUE_SUCCESS)
		return CU_get_error();

	if (CU_register_suites(suites) != CUE_SUCCESS) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();

	const int nr_of_failed_tests = CU_get_number_of_tests_failed();
	const int nr_of_failed_suites = CU_get_number_of_suites_failed();

	CU_cleanup_registry();

	return (nr_of_failed_suites > 0 ?
		nr_of_failed_suites : nr_of_failed_tests);
}

void initialize_odp(void)
{
	CU_ASSERT_FALSE_FATAL(odp_init_global(&instance, NULL, NULL));
	CU_ASSERT_FALSE_FATAL(odp_init_local(instance, ODP_THREAD_WORKER));
}

void initialize_ofp_timer(int resolution_us)
{
	/*
	 * ODP uses POSIX 'timer_create' function to create an interval timer
	 * that causes Valgrind errors:
	 * https://bugs.launchpad.net/ubuntu/+source/glibc/+bug/483594
	 */
	CU_ASSERT_FALSE_FATAL(ofp_timer_init_global(resolution_us,
						    OFP_TIMER_MIN_US,
						    OFP_TIMER_MAX_US,
						    OFP_TIMER_TMO_COUNT,
						    ODP_SCHED_GROUP_ALL));
}

void wait_until_timer_expires(int resolution_us)
{
	usleep(resolution_us);
}

uint32_t getticks(void)
{
	const __useconds_t one_ms = 1E3;
	uint32_t ticks;

	while ((ticks = tcp_ts_getticks()) == 0)
		usleep(one_ms);

	return ticks;
}

static uint32_t one_tick_in_ms(int resolution_us)
{
	return (resolution_us / 1E3);
}

void terminate_ofp_timer(void)
{
	/*
	 * The test may crash with SIGSEGV at this point. The timer in ODP side
	 * is using threads to handle timeouts and is passing a pointer to the
	 * timeout handler that may or may not be valid when the timer triggers.
	 */
	ofp_timer_term_global();
}

void terminate_odp(void)
{
	odp_term_local();
	odp_term_global(instance);
}
