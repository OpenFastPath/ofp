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

void *shm;
static void *allocator(const char *name, uint64_t size);
static int setup(void)
{
	ofp_rt_set_allocator(allocator);
	ofp_rt_lookup_init_global();
	return 0;
}

static int teardown(void)
{
	free(shm);
	ofp_rt_set_allocator(NULL);
	return 0;
}

static enum ofp_log_level_s disable_logging(void);
static void restore_logging(enum ofp_log_level_s log_level);
static int only_ref_count_changed(struct ofp_rtl_node *node, uint8_t masklen);
static void test_insert_returns_data_when_allocation_fails(void)
{
	struct ofp_rtl_node root = { 0 };
	struct ofp_rtl_tree tree = { 0, &root };
	const uint32_t masklen = IPV4_FIRST_LEVEL + 1;
	struct ofp_nh_entry data;
	const enum ofp_log_level_s log_level = disable_logging();

	CU_ASSERT_PTR_EQUAL(ofp_rtl_insert(&tree, 0, masklen, &data), &data);
	CU_ASSERT_TRUE(only_ref_count_changed(&root, masklen));

	restore_logging(log_level);
}

static int only_ref_count_not_changed(struct ofp_rtl_node *node,
				      uint8_t masklen, uint16_t port);
static void test_insert_does_nothing_when_current_mask_is_bigger(void)
{
	struct ofp_rtl_node root[] = { { 0 }, { 0 } };
	struct ofp_rtl_tree tree = { 0, root };
	const uint32_t masklen = IPV4_FIRST_LEVEL - 1;
	struct ofp_nh_entry data = { 0 };

	root[0].masklen = IPV4_FIRST_LEVEL;
	data.port = 1234;

	CU_ASSERT_PTR_NULL(ofp_rtl_insert(&tree, 0, masklen, &data));
	CU_ASSERT_TRUE(only_ref_count_changed(&root[0], masklen));
	CU_ASSERT_TRUE(only_ref_count_not_changed(&root[1], masklen, data.port));
}

static int ref_count_mask_changed(struct ofp_rtl_node *node, uint8_t masklen);
static int ref_count_mask_data_changed(struct ofp_rtl_node *node,
				       uint8_t masklen, uint16_t port);
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
	CU_ASSERT_TRUE(ref_count_mask_changed(&root, masklen));
	CU_ASSERT_TRUE(ref_count_mask_data_changed(&node, masklen, data.port));
}

static void test_insert_with_second_level_mask_allocates_new_nodes(void)
{
	struct ofp_rtl_node root = { 0 };
	struct ofp_rtl_tree tree = { 0, &root };
	uint32_t masklen = IPV4_FIRST_LEVEL + IPV4_LEVEL;
	struct ofp_nh_entry data = { 0 };

	root.masklen = 1;

	setup();

	CU_ASSERT_PTR_NULL(ofp_rtl_insert(&tree, 0, masklen, &data));
	CU_ASSERT_PTR_NOT_NULL_FATAL(root.next);
	CU_ASSERT_TRUE(only_ref_count_changed(&root, masklen));

	CU_ASSERT_EQUAL(root.next[0].masklen, masklen);
	CU_ASSERT_EQUAL(root.next[1].masklen, 0);

	teardown();
}

static void test_print_nothing_when_no_rules_added(void)
{
	setup();
	ofp_rt_rule_print(0, 0, NULL);
	teardown();
}

static void add_rules(void);
static void add_rule(uint16_t vrf, uint32_t masklen, uint16_t port);
static const char *print_rule(uint16_t vrf);
static void test_adding_rule_updates_existing(void)
{
	setup();

	add_rules();
	add_rule(1, 1, 2);

	CU_ASSERT_STRING_EQUAL("[1,1,2][1,2,1]", print_rule(1));

	teardown();
}

static void remove_rule(uint16_t vrf, uint32_t masklen);
static void test_adding_rule_uses_first_unused_slot(void)
{
	setup();

	add_rules();
	remove_rule(2, 1);
	add_rule(1, 3, 2);

	CU_ASSERT_STRING_EQUAL("[1,1,1][1,3,2][1,2,1]", print_rule(1));

	teardown();
}

static void test_removing_unset_rule_does_nothing(void)
{
	const enum ofp_log_level_s log_level = disable_logging();

	setup();

	add_rules();
	remove_rule(2, 2);

	CU_ASSERT_STRING_EQUAL("[0,0,0]", print_rule(0));
	CU_ASSERT_STRING_EQUAL("[1,1,1][1,2,1]", print_rule(1));
	CU_ASSERT_STRING_EQUAL("[2,1,1]", print_rule(2));

	teardown();
	restore_logging(log_level);
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
		{ const_cast("Print nothing when no rules added"),
		  test_print_nothing_when_no_rules_added },
		{ const_cast("When adding rule existing is updated"),
		  test_adding_rule_updates_existing },
		{ const_cast("When adding rule first unused slot is used"),
		  test_adding_rule_uses_first_unused_slot },
		{ const_cast("Removing unset rule does nothing"),
		  test_removing_unset_rule_does_nothing },
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

enum ofp_log_level_s disable_logging(void)
{
	const enum ofp_log_level_s previous = ofp_loglevel;

	ofp_loglevel = OFP_LOG_DISABLED;
	return previous;
}

void restore_logging(enum ofp_log_level_s log_level)
{
	ofp_loglevel = log_level;
}

int only_ref_count_changed(struct ofp_rtl_node *node, uint8_t masklen)
{
	return (node->ref == 1 &&
		node->masklen != masklen &&
		node->data[0].port == 0);
}

int only_ref_count_not_changed(struct ofp_rtl_node *node,
			       uint8_t masklen, uint16_t port)
{
	return (node->ref == 0 &&
		node->masklen == masklen &&
		node->data[0].port == port);
}

int ref_count_mask_changed(struct ofp_rtl_node *node, uint8_t masklen)
{
	return ref_count_mask_data_changed(node, masklen, 0);
}

int ref_count_mask_data_changed(struct ofp_rtl_node *node,
				uint8_t masklen, uint16_t port)
{
	return (node->ref == 1 &&
		node->masklen == masklen &&
		node->data[0].port == port);
}

void add_rules(void)
{
	add_rule(0, 0, 0);
	add_rule(1, 1, 1);
	add_rule(2, 1, 1);
	add_rule(1, 2, 1);
}

void add_rule(uint16_t vrf, uint32_t masklen, uint16_t port)
{
	struct ofp_nh_entry data = { 0 };

	data.port = port;
	ofp_rt_rule_add(vrf, 0, masklen, &data);
}

char print_buffer[256];
int print_index;
static void rule_printer(int fd, uint32_t key, int level,
			 struct ofp_nh_entry *data)
{
	(void)key;
	print_index += snprintf(&print_buffer[print_index],
				sizeof(print_buffer) - print_index,
				"[%d,%d,%u]", fd, level, data->port);
}

const char *print_rule(uint16_t vrf)
{
	print_index = 0;
	ofp_rt_rule_print(vrf, vrf, rule_printer);
	print_buffer[print_index] = '\0';
	return print_buffer;
}

void remove_rule(uint16_t vrf, uint32_t masklen)
{
	ofp_rt_rule_remove(vrf, 0, masklen);
}
