/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#ifndef OFP_TESTMODE_AUTO
#define OFP_TESTMODE_AUTO 1
#endif

#include "ofpi_rt_lookup.h"
#include <stdint.h>

#if OFP_TESTMODE_AUTO
#include <CUnit/Automated.h>
#else
#include <CUnit/Basic.h>
#endif

static void set_bit(uint8_t *p, int index, int bit);
static int set_nth_from_left(int n);
static void test_three_lowest_bits_define_shift_from_left(void)
{
	uint8_t p[] = { 0 };
	int bit;

	for (bit = 0; bit < 8; ++bit, p[0] = 0) {
		set_bit(p, 0, bit);
		CU_ASSERT(p[0] == set_nth_from_left(bit));
	}
}

static void test_bits_after_first_three_define_index(void)
{
	uint8_t p[] = { 0, 0, 0, 0 };
	const int bit = set_nth_from_left(0);
	int i;

	for (i = 0; i < 4; ++i) {
		set_bit(p, i, 0);
		CU_ASSERT(p[i] == bit);
	}
}

static int set_n_from_left(int n);
static void test_when_setting_bits_existing_are_preserved(void)
{
	uint8_t p[] = { 0 };
	int bit;

	for (bit = 0; bit < 8; ++bit) {
		set_bit(p, 0, bit);
		CU_ASSERT(p[0] == set_n_from_left(bit));
	}
}

static int bit_set(uint8_t *p, int index, int bit);
static void test_single_bit_is_set(void)
{
	uint8_t p[] = { 0 };
	int bit;
	int b;

	for (bit = 0; bit < 8; ++bit)
		for (p[0] = set_nth_from_left(bit), b = 0; b < 8; ++b)
			CU_ASSERT(bit_set(p, 0, b) == (b == bit ? p[0] : 0));
}

static void test_none_and_all_bits_set(void)
{
	uint8_t p[] = { 0,  255 };
	int bit;

	for (bit = 0; bit < 8; ++bit) {
		CU_ASSERT(bit_set(p, 0, bit) == 0);
		CU_ASSERT(bit_set(p, 1, bit) == set_nth_from_left(bit));
	}
}

static int reset_n_from_left(int n);
static void test_when_resetting_bits_existing_are_preserved(void)
{
	uint8_t p[] = { 255 };
	int bit;

	for (bit = 0; bit < 8; ++bit) {
		ofp_rt_reset_bit(p, bit);
		CU_ASSERT(p[0] == reset_n_from_left(bit));
	}
}

static void test_search_with_missing_root(void)
{
	struct ofp_rtl6_tree tree = { NULL };

	CU_ASSERT_PTR_NULL(ofp_rtl_search6(&tree, NULL));
}

static void test_search_returns_latest_match(void)
{
	struct ofp_rtl6_node root;
	struct ofp_rtl6_node left;
	struct ofp_rtl6_node right;
	struct ofp_rtl6_tree tree = { &root };
	uint8_t addr = set_nth_from_left(1);

	root.flags = OFP_RTL_FLAGS_VALID_DATA;
	root.left = &left;

	left.flags = OFP_RTL_FLAGS_VALID_DATA;
	left.right = &right;

	right.flags = 0;
	right.left = NULL;

	CU_ASSERT_PTR_EQUAL(ofp_rtl_search6(&tree, &addr), &left.data);
}

static char *const_cast(const char *str)
{
	return (char *)(uintptr_t)str;
}

int main(void)
{
	if (CU_initialize_registry() != CUE_SUCCESS)
		return CU_get_error();

	CU_TestInfo tests[] = {
		{ const_cast("Three lowest bits define shift from left"),
		  test_three_lowest_bits_define_shift_from_left },
		{ const_cast("Bits after the first three define index"),
		  test_bits_after_first_three_define_index },
		{ const_cast("When setting bits existing bits are preserved"),
		  test_when_setting_bits_existing_are_preserved },
		{ const_cast("Single bit is set"),
		  test_single_bit_is_set },
		{ const_cast("None and all bits are set"),
		  test_none_and_all_bits_set },
		{ const_cast("When resetting bits existing are preserved"),
		  test_when_resetting_bits_existing_are_preserved },
		{ const_cast("Search with missing root"),
		  test_search_with_missing_root },
		{ const_cast("Search returns latest match"),
		    test_search_returns_latest_match },
		CU_TEST_INFO_NULL,
	};

	CU_SuiteInfo suites[] = {
		CU_SUITE_INFO_NULL,
		CU_SUITE_INFO_NULL,
	};
	suites[0].pName = const_cast("ofp rt lookup");
	suites[0].pTests = tests;

	if (CU_register_suites(suites) != CUE_SUCCESS) {
		CU_cleanup_registry();
		return CU_get_error();
	}

#if OFP_TESTMODE_AUTO
	CU_set_output_filename("CUnit-Rt-lookup");
	CU_automated_run_tests();
#else
	/* Run all tests using the CUnit Basic interface */
	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
#endif

	const int nr_of_failed_tests = CU_get_number_of_tests_failed();
	const int nr_of_failed_suites = CU_get_number_of_suites_failed();

	CU_cleanup_registry();

	return (nr_of_failed_suites > 0 ?
		nr_of_failed_suites : nr_of_failed_tests);
}

void set_bit(uint8_t *p, int index, int bit)
{
	ofp_rt_set_bit(p, bit + index*8);
}

int set_nth_from_left(int n)
{
	return(128 >> n);
}

int set_n_from_left(int n)
{
	if (n < 0)
		return 0;

	return set_nth_from_left(n) | set_n_from_left(n - 1);
}

int reset_n_from_left(int n)
{
	return(255 ^ set_n_from_left(n));
}

int bit_set(uint8_t *p, int index, int bit)
{
	return ofp_rt_bit_set(p, bit + index*8);
}
