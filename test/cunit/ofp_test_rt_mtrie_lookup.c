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
#include "ofpi_shared_mem.h"
#include "ofpi_log.h"
#include "ofp_cunit_version.h"
#include "ofpi_avl.h"

#if OFP_TESTMODE_AUTO
#include <CUnit/Automated.h>
#else
#include <CUnit/Basic.h>
#endif

#ifndef CU_HAS_TEST_SETUP_AND_TEARDOWN
#define SETUP setup()
#define SETUP_WITH_SHM setup_with_shm()
#define TEARDOWN_WITH_SHM teardown_with_shm()
#else
#define SETUP
#define SETUP_WITH_SHM
#define TEARDOWN_WITH_SHM
#endif

enum ofp_log_level_s log_level;
void *shm, *shm_avl, *shm_rt_lookup;
struct ofp_rtl_node root[] = { { 0 }, { 0 } };
struct ofp_rtl_tree tree = { 0, root };
struct ofp_nh_entry data = { 0 };
const uint32_t addr_be = 256; /* This address will yield node index '1' */
const uint32_t FIRST_LEVEL_MASK = IPV4_FIRST_LEVEL;
const uint32_t SECOND_LEVEL_MASK = IPV4_FIRST_LEVEL + IPV4_LEVEL;
const uint32_t TWO_SUBNETS = -1;

static enum ofp_log_level_s disable_logging(void);
static int init(void)
{
	log_level = disable_logging();
	return 0;
}

static void restore_logging(enum ofp_log_level_s log_level);
static int cleanup(void)
{
	restore_logging(log_level);
	return 0;
}

void ofp_init_global_param_from_file(ofp_global_param_t *params, const char *filename);
ofp_global_param_t ofp_global_param;
extern __thread ofp_global_param_t *global_param;
static void prevent_freeing_of(struct ofp_rtl_node *root);
static void setup(void)
{
	memset(&root, 0, sizeof(root));
	prevent_freeing_of(root);
	tree.vrf = 1;
	data.port = 313;
	global_param = &ofp_global_param;
	ofp_init_global_param_from_file(global_param, "");
}

static void *allocator(const char *name, uint64_t size);
static void setup_with_shm(void)
{
	setup();
	ofp_set_custom_allocator(allocator);
	ofp_avl_init_global();
	shm_avl = shm;
	ofp_rt_lookup_init_global();
	shm_rt_lookup = shm;
}

static void teardown_with_shm(void)
{
	free(shm_avl);
	free(shm_rt_lookup);
	ofp_set_custom_allocator(NULL);
}

static struct ofp_nh_entry *insert_route(uint32_t masklen);
static int reference_count_increased(struct ofp_rtl_node *node);
static int route_not_set(struct ofp_rtl_node *node);
static void test_insert_returns_data_when_allocation_fails(void)
{
	SETUP;

	CU_ASSERT_PTR_EQUAL(insert_route(SECOND_LEVEL_MASK), &data);

	CU_ASSERT_TRUE(reference_count_increased(root));
	CU_ASSERT_TRUE(route_not_set(root));
}

static void set_mask(struct ofp_rtl_node *node, uint32_t masklen);
static int route_set(struct ofp_rtl_node *node, uint32_t masklen);
static int route_partly_set(struct ofp_rtl_node *node, uint32_t masklen);
static void test_insert_does_nothing_when_current_mask_is_bigger(void)
{
	const uint32_t masklen = FIRST_LEVEL_MASK + TWO_SUBNETS;

	SETUP;

	set_mask(&root[0], masklen - 1);
	set_mask(&root[1], masklen + 1);

	CU_ASSERT_PTR_NULL(insert_route(masklen));

	CU_ASSERT_TRUE(reference_count_increased(&root[0]));
	CU_ASSERT_TRUE(route_set(&root[0], masklen));

	CU_ASSERT_FALSE(reference_count_increased(&root[1]));
	CU_ASSERT_TRUE(route_partly_set(&root[1], masklen + 1));
}

static void set_next(struct ofp_rtl_node *node, struct ofp_rtl_node *next);
static struct ofp_rtl_node *get_next(struct ofp_rtl_node *node);
static void test_insert_with_second_level_mask_updates_unset_mask(void)
{
	struct ofp_rtl_node node = { 0 };
	const uint32_t masklen = SECOND_LEVEL_MASK;

	SETUP;

	set_mask(&node, masklen + 1);
	set_next(&root[1], &node);

	CU_ASSERT_PTR_NULL(insert_route(masklen));
	CU_ASSERT_PTR_EQUAL(get_next(&root[1]), &node);

	CU_ASSERT_TRUE(reference_count_increased(&root[0]));
	CU_ASSERT_TRUE(route_not_set(&root[0]));

	CU_ASSERT_FALSE(reference_count_increased(&root[1]));
	CU_ASSERT_TRUE(route_partly_set(&root[1], masklen));

	CU_ASSERT_TRUE(reference_count_increased(&node));
	CU_ASSERT_TRUE(route_set(&node, masklen));
}

static void test_insert_with_second_level_mask_allocates_new_nodes(void)
{
	struct ofp_rtl_node *node;
	const uint32_t masklen = SECOND_LEVEL_MASK;

	SETUP_WITH_SHM;

	set_mask(&root[1], 1);

	CU_ASSERT_PTR_NULL(insert_route(masklen));

	node = get_next(&root[1]);
	CU_ASSERT_PTR_NOT_NULL_FATAL(node);

	CU_ASSERT_TRUE(reference_count_increased(&root[0]));
	CU_ASSERT_TRUE(route_not_set(&root[0]));

	CU_ASSERT_FALSE(reference_count_increased(&root[1]));
	CU_ASSERT_TRUE(route_partly_set(&root[1], 1));

	CU_ASSERT_TRUE(reference_count_increased(&node[0]));
	CU_ASSERT_TRUE(route_set(&node[0], masklen));

	CU_ASSERT_TRUE(route_not_set(&node[1]));

	TEARDOWN_WITH_SHM;
}

static const char *print_rule(uint16_t vrf);
static void test_print_nothing_when_no_rules_added(void)
{
	SETUP_WITH_SHM;

	CU_ASSERT_STRING_EQUAL("", print_rule(0));

	TEARDOWN_WITH_SHM;
}

static void add_rules(void);
static void add_rule(uint16_t vrf, uint32_t masklen, uint16_t port);
static void test_adding_rule_updates_existing(void)
{
	SETUP_WITH_SHM;

	add_rules();
	add_rule(1, 1, 2);

	CU_ASSERT_STRING_EQUAL("[1,1,2][1,2,1]", print_rule(1));

	TEARDOWN_WITH_SHM;
}

static void remove_rule(uint16_t vrf, uint32_t masklen);

static void test_rules_add_search_remove(void)
{
	SETUP_WITH_SHM;

	/*add and check*/
	CU_ASSERT_STRING_EQUAL("", print_rule(0));
	CU_ASSERT_STRING_EQUAL("", print_rule(1));
	CU_ASSERT_STRING_EQUAL("", print_rule(2));
	add_rule(0, 8, 0);
	CU_ASSERT_STRING_EQUAL("[0,8,0]", print_rule(0));
	CU_ASSERT_STRING_EQUAL("", print_rule(1));
	CU_ASSERT_STRING_EQUAL("", print_rule(2));
	add_rule(1, 8, 1);
	CU_ASSERT_STRING_EQUAL("[0,8,0]", print_rule(0));
	CU_ASSERT_STRING_EQUAL("[1,8,1]", print_rule(1));
	CU_ASSERT_STRING_EQUAL("", print_rule(2));
	add_rule(2, 8, 2);
	CU_ASSERT_STRING_EQUAL("[0,8,0]", print_rule(0));
	CU_ASSERT_STRING_EQUAL("[1,8,1]", print_rule(1));
	CU_ASSERT_STRING_EQUAL("[2,8,2]", print_rule(2));
	add_rule(0, 16, 0);
	CU_ASSERT_STRING_EQUAL("[0,8,0][0,16,0]", print_rule(0));
	CU_ASSERT_STRING_EQUAL("[1,8,1]", print_rule(1));
	CU_ASSERT_STRING_EQUAL("[2,8,2]", print_rule(2));
	add_rule(1, 16, 1);
	CU_ASSERT_STRING_EQUAL("[0,8,0][0,16,0]", print_rule(0));
	CU_ASSERT_STRING_EQUAL("[1,8,1][1,16,1]", print_rule(1));
	CU_ASSERT_STRING_EQUAL("[2,8,2]", print_rule(2));
	add_rule(2, 16, 2);
	CU_ASSERT_STRING_EQUAL("[0,8,0][0,16,0]", print_rule(0));
	CU_ASSERT_STRING_EQUAL("[1,8,1][1,16,1]", print_rule(1));
	CU_ASSERT_STRING_EQUAL("[2,8,2][2,16,2]", print_rule(2));
	add_rule(0, 24, 0);
	CU_ASSERT_STRING_EQUAL("[0,8,0][0,16,0][0,24,0]", print_rule(0));
	CU_ASSERT_STRING_EQUAL("[1,8,1][1,16,1]", print_rule(1));
	CU_ASSERT_STRING_EQUAL("[2,8,2][2,16,2]", print_rule(2));
	add_rule(1, 24, 1);
	CU_ASSERT_STRING_EQUAL("[0,8,0][0,16,0][0,24,0]", print_rule(0));
	CU_ASSERT_STRING_EQUAL("[1,8,1][1,16,1][1,24,1]", print_rule(1));
	CU_ASSERT_STRING_EQUAL("[2,8,2][2,16,2]", print_rule(2));
	add_rule(2, 24, 2);
	CU_ASSERT_STRING_EQUAL("[0,8,0][0,16,0][0,24,0]", print_rule(0));
	CU_ASSERT_STRING_EQUAL("[1,8,1][1,16,1][1,24,1]", print_rule(1));
	CU_ASSERT_STRING_EQUAL("[2,8,2][2,16,2][2,24,2]", print_rule(2));
	/*remove and check*/
	remove_rule(0, 8);
	CU_ASSERT_STRING_EQUAL("[0,16,0][0,24,0]", print_rule(0));
	CU_ASSERT_STRING_EQUAL("[1,8,1][1,16,1][1,24,1]", print_rule(1));
	CU_ASSERT_STRING_EQUAL("[2,8,2][2,16,2][2,24,2]", print_rule(2));
	remove_rule(1, 16);
	CU_ASSERT_STRING_EQUAL("[0,16,0][0,24,0]", print_rule(0));
	CU_ASSERT_STRING_EQUAL("[1,8,1][1,24,1]", print_rule(1));
	CU_ASSERT_STRING_EQUAL("[2,8,2][2,16,2][2,24,2]", print_rule(2));
	remove_rule(2, 24);
	CU_ASSERT_STRING_EQUAL("[0,16,0][0,24,0]", print_rule(0));
	CU_ASSERT_STRING_EQUAL("[1,8,1][1,24,1]", print_rule(1));
	CU_ASSERT_STRING_EQUAL("[2,8,2][2,16,2]", print_rule(2));
	/*re-add and check*/
	add_rule(0, 17, 17);
	CU_ASSERT_STRING_EQUAL("[0,16,0][0,17,17][0,24,0]", print_rule(0));
	CU_ASSERT_STRING_EQUAL("[1,8,1][1,24,1]", print_rule(1));
	CU_ASSERT_STRING_EQUAL("[2,8,2][2,16,2]", print_rule(2));
	add_rule(1, 25, 25);
	CU_ASSERT_STRING_EQUAL("[0,16,0][0,17,17][0,24,0]", print_rule(0));
	CU_ASSERT_STRING_EQUAL("[1,8,1][1,24,1][1,25,25]", print_rule(1));
	CU_ASSERT_STRING_EQUAL("[2,8,2][2,16,2]", print_rule(2));
	add_rule(2, 7, 7);
	CU_ASSERT_STRING_EQUAL("[0,16,0][0,17,17][0,24,0]", print_rule(0));
	CU_ASSERT_STRING_EQUAL("[1,8,1][1,24,1][1,25,25]", print_rule(1));
	CU_ASSERT_STRING_EQUAL("[2,7,7][2,8,2][2,16,2]", print_rule(2));
	/*remove all and check*/
	remove_rule(0, 16);
	remove_rule(0, 17);
	remove_rule(0, 24);
	remove_rule(1, 8);
	remove_rule(1, 24);
	remove_rule(1, 25);
	remove_rule(2, 7);
	remove_rule(2, 8);
	remove_rule(2, 16);
	CU_ASSERT_STRING_EQUAL("", print_rule(0));
	CU_ASSERT_STRING_EQUAL("", print_rule(1));
	CU_ASSERT_STRING_EQUAL("", print_rule(2));

	TEARDOWN_WITH_SHM;
}

static void test_adding_rule_when_rule_table_full(void)
{
	uint32_t i;

	SETUP_WITH_SHM;

	add_rule(0, 24, 0);
	add_rule(0, 16, 0);
	for (i = 0; i < OFP_ROUTES-2; ++i)
		add_rule(2+i, 24, 0);

	add_rule(1, 1, 1);

	CU_ASSERT_STRING_EQUAL("", print_rule(1));

	TEARDOWN_WITH_SHM;
}

static void test_removing_unset_rule_does_nothing(void)
{
	SETUP_WITH_SHM;

	add_rules();
	remove_rule(2, 2);

	CU_ASSERT_STRING_EQUAL("[0,0,0]", print_rule(0));
	CU_ASSERT_STRING_EQUAL("[1,1,1][1,2,1]", print_rule(1));
	CU_ASSERT_STRING_EQUAL("[2,1,1]", print_rule(2));

	TEARDOWN_WITH_SHM;
}

static struct ofp_nh_entry *remove_route(uint32_t masklen);
static void test_remove_does_nothing_when_no_rule_added(void)
{
	SETUP_WITH_SHM;

	CU_ASSERT_PTR_NULL(remove_route(0));

	TEARDOWN_WITH_SHM;
}

static void increase_reference_count(struct ofp_rtl_node *node);
static void test_remove_with_second_level_mask_does_nothing_when_mask_not_set(void)
{
	const uint32_t masklen = SECOND_LEVEL_MASK;

	SETUP_WITH_SHM;

	increase_reference_count(root);

	add_rule(tree.vrf, masklen, 0);
	CU_ASSERT_PTR_NULL(remove_route(masklen));
	CU_ASSERT_FALSE(reference_count_increased(root));

	TEARDOWN_WITH_SHM;
}

static void set_route(struct ofp_rtl_node *node, uint32_t masklen);
static int route_cleared(struct ofp_rtl_node *node);
static void test_remove_route_not_reinserted(void)
{
	struct ofp_nh_entry *removed;
	const uint32_t masklen = FIRST_LEVEL_MASK + TWO_SUBNETS;

	SETUP_WITH_SHM;

	increase_reference_count(&root[0]);
	set_route(&root[0], masklen);
	set_route(&root[1], masklen);
	add_rule(tree.vrf, masklen, data.port);

	removed = remove_route(masklen);

	CU_ASSERT_PTR_NOT_NULL_FATAL(removed);
	CU_ASSERT_EQUAL(removed->port, data.port);

	CU_ASSERT_FALSE(reference_count_increased(&root[0]));
	CU_ASSERT_TRUE(route_cleared(&root[0]));

	CU_ASSERT_FALSE(reference_count_increased(&root[1]));
	CU_ASSERT_TRUE(route_cleared(&root[1]));

	TEARDOWN_WITH_SHM;
}

static void test_remove_route_with_second_level_mask_not_reinserted(void)
{
	struct ofp_rtl_node node[] = { { 0 }, { 0 } };
	const uint32_t masklen = SECOND_LEVEL_MASK + TWO_SUBNETS;

	SETUP_WITH_SHM;

	increase_reference_count(&root[0]);
	increase_reference_count(&node[0]);
	set_mask(&root[1], masklen);
	set_route(&node[0], masklen);
	set_route(&node[1], masklen);
	set_next(&root[1], node);

	add_rule(tree.vrf, masklen, data.port);

	CU_ASSERT_PTR_NOT_NULL(remove_route(masklen));

	CU_ASSERT_FALSE(reference_count_increased(&root[0]));

	CU_ASSERT_PTR_NULL(get_next(&root[1]));
	CU_ASSERT_TRUE(route_not_set(&root[1]));

	CU_ASSERT_FALSE(reference_count_increased(&node[0]));
	/*
	 * 'next' is set to NULL since the ref count dropped to 0
	 * and node was freed
	 */
	CU_ASSERT_PTR_NULL(get_next(&node[0]));
	CU_ASSERT_TRUE(route_set(&node[0], SECOND_LEVEL_MASK + 1));

	CU_ASSERT_FALSE(reference_count_increased(&node[1]));
	CU_ASSERT_PTR_NULL(get_next(&node[1]));
	CU_ASSERT_TRUE(route_set(&node[1], 0));

	TEARDOWN_WITH_SHM;
}

static void test_remove_route_reinserted_when_covering_rule_exist(void)
{
	struct ofp_nh_entry *removed;
	const uint32_t masklen = FIRST_LEVEL_MASK;

	SETUP_WITH_SHM;

	increase_reference_count(&root[0]);
	set_route(&root[1], masklen);
	add_rule(tree.vrf, masklen, data.port);
	/*
	 * below as a covering rule to
	 * make the removed route reinserted according to the covering rule
	 */
	add_rule(tree.vrf, masklen-1, data.port);

	removed = remove_route(masklen);

	CU_ASSERT_PTR_NOT_NULL_FATAL(removed);
	CU_ASSERT_EQUAL(removed->port, data.port);

	CU_ASSERT_TRUE(reference_count_increased(&root[0]));
	CU_ASSERT_TRUE(route_set(&root[0], masklen-1));

	CU_ASSERT_FALSE(reference_count_increased(&root[1]));
	CU_ASSERT_TRUE(route_set(&root[1], masklen-1));

	TEARDOWN_WITH_SHM;
}

static void test_remove_route_with_second_level_mask_reinserted_when_covering_rule_exist(void)
{
	struct ofp_rtl_node node[] = { { 0 }, { 0 } };
	const uint32_t masklen = SECOND_LEVEL_MASK;
	struct ofp_rtl_node *nodep;

	SETUP_WITH_SHM;

	increase_reference_count(&root[0]);
	increase_reference_count(&node[0]);
	set_mask(&root[1], masklen);
	set_route(&node[0], masklen);
	set_next(&root[1], node);

	add_rule(tree.vrf, masklen, data.port);
	/*
	 * below as a covering rule to
	 * make the removed route reinserted according to the covering rule
	 */
	add_rule(tree.vrf, masklen-1, data.port);

	CU_ASSERT_PTR_NOT_NULL(remove_route(masklen));

	CU_ASSERT_TRUE(reference_count_increased(&root[0]));

	nodep = get_next(&root[1]);
	CU_ASSERT_PTR_NOT_NULL_FATAL(nodep);
	CU_ASSERT_TRUE(route_partly_set(&root[1], masklen-1));

	CU_ASSERT_TRUE(reference_count_increased(&nodep[0]));
	CU_ASSERT_TRUE(route_set(&nodep[0], masklen-1));

	CU_ASSERT_FALSE(reference_count_increased(&nodep[1]));
	CU_ASSERT_TRUE(route_set(&tree.root[1].next[1], masklen-1));

	TEARDOWN_WITH_SHM;
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
		CU_TEST_INFO_NULL
	};

	CU_TestInfo tests_with_shm[] = {
		{ const_cast("Insert with second level mask allocates new nodes"),
		  test_insert_with_second_level_mask_allocates_new_nodes },
		{ const_cast("Print nothing when no rules added"),
		  test_print_nothing_when_no_rules_added },
		{ const_cast("When adding rule existing is updated"),
		  test_adding_rule_updates_existing },
		{ const_cast("Add remove and search rules"),
		  test_rules_add_search_remove },
		{ const_cast("Add rule when rule table is full"),
		  test_adding_rule_when_rule_table_full },
		{ const_cast("Removing unset rule does nothing"),
		  test_removing_unset_rule_does_nothing },
		{ const_cast("Remove does nothing when no rule is added"),
		  test_remove_does_nothing_when_no_rule_added },
		{ const_cast("Remove with second level mask does nothing when mask is not set"),
		  test_remove_with_second_level_mask_does_nothing_when_mask_not_set },
		{ const_cast("Remove route and not re-inserted"),
		  test_remove_route_not_reinserted },
		{ const_cast("Remove route with second level mask and not re-inserted"),
		  test_remove_route_with_second_level_mask_not_reinserted },
		{ const_cast("Remove route reinserted when there exists a different rule covering the rule being deleted"),
		  test_remove_route_reinserted_when_covering_rule_exist},
		{ const_cast("Remove route with second level mask reinserted when there exists a different rule covering the rule being deleted"),
		  test_remove_route_with_second_level_mask_reinserted_when_covering_rule_exist},
		CU_TEST_INFO_NULL,
	};

	CU_SuiteInfo suites[] = {
		CU_SUITE_INFO_NULL,
		CU_SUITE_INFO_NULL,
		CU_SUITE_INFO_NULL,
	};
	suites[0].pInitFunc = init;
	suites[0].pCleanupFunc = cleanup;
#ifdef CU_HAS_TEST_SETUP_AND_TEARDOWN
	suites[0].pSetUpFunc = setup;
#endif
	suites[0].pName = const_cast("ofp rt mtrie lookup");
	suites[0].pTests = tests;

	suites[1].pInitFunc = init;
	suites[1].pCleanupFunc = cleanup;
#ifdef CU_HAS_TEST_SETUP_AND_TEARDOWN
	suites[1].pSetUpFunc = setup_with_shm;
	suites[1].pTearDownFunc = teardown_with_shm;
#endif
	suites[1].pName = const_cast("ofp rt mtrie lookup with shared memory");
	suites[1].pTests = tests_with_shm;

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

void prevent_freeing_of(struct ofp_rtl_node *root)
{
	root->root = 1;
}

void *allocator(const char *name, uint64_t size)
{
	(void)name;
	shm = malloc(size);
	return shm;
}

struct ofp_nh_entry *insert_route(uint32_t masklen)
{
	return ofp_rtl_insert(&tree, addr_be, masklen, &data);
}

int reference_count_increased(struct ofp_rtl_node *node)
{
	return (node->ref == 1);
}

int route_not_set(struct ofp_rtl_node *node)
{
	return (node->masklen == 0 && node->data[0].port == 0);
}

int route_cleared(struct ofp_rtl_node *node)
{
	return (node->masklen == 0);
}

void set_mask(struct ofp_rtl_node *node, uint32_t masklen)
{
	node->masklen = masklen;
}

int route_set(struct ofp_rtl_node *node, uint32_t masklen)
{
	return (node->masklen == masklen && node->data[0].port == data.port);
}

int route_partly_set(struct ofp_rtl_node *node, uint32_t masklen)
{
	return (node->masklen == masklen && node->data[0].port == 0);
}

void set_next(struct ofp_rtl_node *node, struct ofp_rtl_node *next)
{
	node->next = next;
}

struct ofp_rtl_node *get_next(struct ofp_rtl_node *node)
{
	return node->next;
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
	ofp_rt_rule_add(vrf, addr_be, masklen, &data);
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
	ofp_rt_rule_remove(vrf, addr_be, masklen);
}

struct ofp_nh_entry *remove_route(uint32_t masklen)
{
	return ofp_rtl_remove(&tree, addr_be, masklen);
}

void increase_reference_count(struct ofp_rtl_node *node)
{
	node->ref = 1;
}

void set_route(struct ofp_rtl_node *node, uint32_t masklen)
{
	set_mask(node, masklen);
	node->data[0].port = data.port;
}
