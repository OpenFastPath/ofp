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
#include <arpa/inet.h>
#include <stdint.h>

#if OFP_TESTMODE_AUTO
#include <CUnit/Automated.h>
#else
#include <CUnit/Basic.h>
#endif

static void test_insert_returns_data_when_allocation_fails(void)
{
	struct ofp_rtl_node root = { 0 };
	struct ofp_rtl_tree tree = { 0, &root };
	const uint32_t masklen = IPV4_FIRST_LEVEL + 1;
	struct ofp_nh_entry data;
	enum ofp_log_level_s log_level = ofp_loglevel;

	ofp_loglevel = OFP_LOG_DISABLED;

	CU_ASSERT_PTR_EQUAL(ofp_rtl_insert(&tree, 0, masklen, &data), &data);
	CU_ASSERT_EQUAL(root.ref, 1);

	ofp_loglevel = log_level;
}

static void test_insert_does_nothing_when_current_mask_is_bigger(void)
{
	struct ofp_rtl_node root[] = { { 0 }, { 0 } };
	struct ofp_rtl_tree tree = { 0, root };
	const uint32_t masklen = IPV4_FIRST_LEVEL - 1;
	struct ofp_nh_entry data = { 0 };

	root[0].masklen = IPV4_FIRST_LEVEL;
	data.port = 1234;

	CU_ASSERT_PTR_NULL(ofp_rtl_insert(&tree, 0, masklen, &data));
	CU_ASSERT_EQUAL(root[0].ref, 1);
	CU_ASSERT_EQUAL(root[0].data[0].port, 0);
	CU_ASSERT_EQUAL(root[0].masklen, IPV4_FIRST_LEVEL);

	CU_ASSERT_EQUAL(root[1].ref, 0);
	CU_ASSERT_EQUAL(root[1].data[0].port, data.port);
	CU_ASSERT_EQUAL(root[1].masklen, masklen);
}

static void test_insert_with_second_level_mask_updates_unset_mask(void)
{
	struct ofp_rtl_node node = { 0 };
	struct ofp_rtl_node root = { 0 };
	struct ofp_rtl_tree tree = { 0, &root };
	const uint32_t masklen = IPV4_FIRST_LEVEL + IPV4_LEVEL;
	struct ofp_nh_entry data = { 0 };

	node.masklen = masklen + 1;
	root.next = &node;
	data.port = 4321;

	CU_ASSERT_PTR_NULL(ofp_rtl_insert(&tree, 0, masklen, &data));
	CU_ASSERT_PTR_EQUAL(root.next, &node);
	CU_ASSERT_EQUAL(root.ref, 1);
	CU_ASSERT_EQUAL(root.data[0].port, 0);
	CU_ASSERT_EQUAL(root.masklen, masklen);

	CU_ASSERT_EQUAL(node.ref, 1);
	CU_ASSERT_EQUAL(node.data[0].port, data.port);
	CU_ASSERT_EQUAL(node.masklen, masklen);
}

void *shm;
static void *allocator(const char *name, uint64_t size);
static void test_insert_with_second_level_mask_allocates_new_nodes(void)
{
	struct ofp_rtl_node root = { 0 };
	struct ofp_rtl_tree tree = { 0, &root };
	uint32_t masklen = IPV4_FIRST_LEVEL + IPV4_LEVEL;
	struct ofp_nh_entry data = { 0 };

	root.masklen = 1;

	ofp_rt_set_allocator(allocator);
	ofp_rt_lookup_init_global();

	CU_ASSERT_PTR_NULL(ofp_rtl_insert(&tree, 0, masklen, &data));
	CU_ASSERT_PTR_NOT_NULL_FATAL(root.next);
	CU_ASSERT_EQUAL(root.next->ref, 1);
	CU_ASSERT_EQUAL(root.masklen, 1);

	CU_ASSERT_EQUAL(root.next[0].masklen, masklen);
	CU_ASSERT_EQUAL(root.next[1].masklen, 0);

	free(shm);
	ofp_rt_set_allocator(NULL);
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
		{ const_cast("Insert returns data when allocation fails"),
		  test_insert_returns_data_when_allocation_fails },
		{ const_cast("Insert does nothing when current mask is bigger"),
		  test_insert_does_nothing_when_current_mask_is_bigger },
		{ const_cast("Insert with second level mask updates unset mask"),
		  test_insert_with_second_level_mask_updates_unset_mask },
		{ const_cast("Insert with second level mask allocates new nodes"),
		  test_insert_with_second_level_mask_allocates_new_nodes },
		CU_TEST_INFO_NULL,
	};

	CU_SuiteInfo suites[] = {
		CU_SUITE_INFO_NULL,
		CU_SUITE_INFO_NULL,
	};
	suites[0].pName = const_cast("ofp rt mtrie lookup");
	suites[0].pTests = tests;

	if (CU_register_suites(suites) != CUE_SUCCESS) {
		CU_cleanup_registry();
		return CU_get_error();
	}

#if OFP_TESTMODE_AUTO
	CU_set_output_filename("CUnit-Rt-mtrie-lookup");
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

void *allocator(const char *name, uint64_t size)
{
	(void)name;
	shm = malloc(size);
	return shm;
}
