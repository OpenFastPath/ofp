/* Copyright (c) 2015, ENEA Software AB
 * Copyright (c) 2015, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#include <stdlib.h>
#include <arpa/inet.h>
#include <CUnit/Basic.h>

#include "ofpi_portconf.h"
#include "api/ofp_in.h"
#include "api/ofp_sysctl.h"
#include "ofpi_tree.h"
#include "ofpi_in_var.h"

#define MATCHING_IP 123
#define UNMATCHING_IP 321

static struct ofp_ip_msource ip_to_msource(const char *ip);
static void test_compare_multicast_source_address(void)
{
	struct ofp_ip_msource smaller = ip_to_msource("127.0.0.1");
	struct ofp_ip_msource bigger = ip_to_msource("192.168.1.1");

	CU_ASSERT(ip_msource_cmp(&smaller, &bigger) == -1);
	CU_ASSERT(ip_msource_cmp(&smaller, &smaller) == 0);
	CU_ASSERT(ip_msource_cmp(&bigger,  &bigger) == 0);
	CU_ASSERT(ip_msource_cmp(&bigger,  &smaller) == 1);
}

static void test_multicast_is_excluded_by_all_listeners(void)
{
	struct ofp_in_multi multicast_group;
	struct ofp_ip_msource multicast_source;
	uint8_t t = 0;

	multicast_group.inm_st[t].iss_ex = multicast_source.ims_st[t].ex = 1;

	CU_ASSERT(ims_get_mode(&multicast_group, &multicast_source, t) ==
		OFP_MCAST_EXCLUDE);
}

static void
test_multicast_is_not_excluded_by_any_and_included_by_some_listeners(void)
{
	struct ofp_in_multi multicast_group;
	struct ofp_ip_msource multicast_source;
	uint8_t t = 1;

	multicast_group.inm_st[t].iss_ex = 0;
	multicast_source.ims_st[t].ex = 0;
	multicast_source.ims_st[t].in = 1;

	CU_ASSERT(ims_get_mode(&multicast_group, &multicast_source, ++t) ==
		OFP_MCAST_INCLUDE);
}

static void test_multicast_is_excluded_and_included_by_some_listeners(void)
{
	struct ofp_in_multi multicast_group;
	struct ofp_ip_msource multicast_source;
	uint8_t t = 0;

	multicast_group.inm_st[t].iss_ex = 2;
	multicast_source.ims_st[t].ex = 1;
	multicast_source.ims_st[t].in = 1;

	CU_ASSERT(ims_get_mode(&multicast_group, &multicast_source, t) ==
		OFP_MCAST_UNDEFINED);
}

static void test_multicast_is_not_excluded_nor_included_by_listeners(void)
{
	struct ofp_in_multi multicast_group;
	struct ofp_ip_msource multicast_source;
	uint8_t t = 0;

	multicast_group.inm_st[t].iss_ex = 0;
	multicast_source.ims_st[t].ex = 0;
	multicast_source.ims_st[t].in = 0;

	CU_ASSERT(ims_get_mode(&multicast_group, &multicast_source, t) ==
		OFP_MCAST_UNDEFINED);
}

static void add_multicast_address(struct ofp_ifnet *ifp,
				  struct ofp_ifmultiaddr *multicast_address);
static void test_multicast_group_lookup_without_addresses(void)
{
	struct ofp_ifnet ifp = { 0 };
	struct ofp_in_addr ina;

	add_multicast_address(&ifp, NULL);

	CU_ASSERT_PTR_NULL(inm_lookup_locked(&ifp, ina));
}

static struct ofp_ifmultiaddr *new_unspecified_multicast_address(void);
static void release_ifnet(struct ofp_ifnet *ifp);
static void test_multicast_group_lookup_without_ip_addresses(void)
{
	struct ofp_ifnet ifp = { 0 };
	struct ofp_in_addr ina = { 0 };

	add_multicast_address(&ifp, new_unspecified_multicast_address());

	CU_ASSERT_PTR_NULL(inm_lookup_locked(&ifp, ina));
	release_ifnet(&ifp);
}

static struct ofp_ifmultiaddr *new_ip_multicast_address(void);
static void test_multicast_group_lookup_with_unmatching_ip_address(void)
{
	struct ofp_ifnet ifp = { 0 };
	struct ofp_in_addr ina;

	add_multicast_address(&ifp, new_ip_multicast_address());
	ina.s_addr = UNMATCHING_IP;

	CU_ASSERT_PTR_NULL(inm_lookup_locked(&ifp, ina));
	release_ifnet(&ifp);
}

static void test_multicast_group_lookup_with_matching_ip_address(void)
{
	struct ofp_ifnet ifp = { 0 };
	struct ofp_in_addr ina;

	add_multicast_address(&ifp, new_unspecified_multicast_address());
	add_multicast_address(&ifp, new_ip_multicast_address());
	ina.s_addr = MATCHING_IP;

	CU_ASSERT_PTR_NOT_NULL(inm_lookup_locked(&ifp, ina));
	release_ifnet(&ifp);
}

static void test_multicast_group_lookup_with_lock(void)
{
	struct ofp_ifnet ifp = { 0 };
	struct ofp_in_addr ina = { 0 };

	CU_ASSERT_PTR_NULL(inm_lookup(&ifp, ina));
}

static void test_increase_multicast_group_reference_count(void)
{
	struct ofp_in_multi multicast_group;

	multicast_group.inm_refcount = 0;

	inm_acquire_locked(&multicast_group);
	CU_ASSERT(multicast_group.inm_refcount == 1);
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
		{ const_cast("Compare multicast source address"),
		  test_compare_multicast_source_address },
		{ const_cast("Multicast is excluded by all listeners"),
		  test_multicast_is_excluded_by_all_listeners },
		{ const_cast("Multicast is excluded and included by some listeners"),
		  test_multicast_is_excluded_and_included_by_some_listeners },
		{ const_cast("Multicast is not excluded by any and included by some listeners"),
		  test_multicast_is_not_excluded_by_any_and_included_by_some_listeners },
		{ const_cast("Multicast is not excluded nor included by listeners"),
		  test_multicast_is_not_excluded_nor_included_by_listeners },
		{ const_cast("Multicast group lookup without addresses"),
		  test_multicast_group_lookup_without_addresses },
		{ const_cast("Multicast group lookup without ip addresses"),
		  test_multicast_group_lookup_without_ip_addresses },
		{ const_cast("Multicast group lookup with unmatching ip address"),
		  test_multicast_group_lookup_with_unmatching_ip_address },
		{ const_cast("Multicast group lookup with matching ip address"),
		  test_multicast_group_lookup_with_matching_ip_address },
		{ const_cast("Multicast group lookup with lock"),
		  test_multicast_group_lookup_with_lock },
		{ const_cast("Increase multicast group reference count"),
		  test_increase_multicast_group_reference_count },
		CU_TEST_INFO_NULL,
	};

	CU_SuiteInfo suites[] = {
		CU_SUITE_INFO_NULL,
		CU_SUITE_INFO_NULL,
	};
	suites[0].pName = const_cast("ofp in var");
	suites[0].pTests = tests;

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

struct ofp_ip_msource ip_to_msource(const char *ip)
{
	struct sockaddr_in address;
	struct ofp_ip_msource s;

	inet_pton(AF_INET, ip, &(address.sin_addr));
	s.ims_haddr = odp_be_to_cpu_32(address.sin_addr.s_addr);
	return s;
}

static void add_first_multicast_address(struct ofp_ifnet *ifp,
					struct ofp_ifmultiaddr *first);
static void add_next_multicast_address(struct ofp_ifmultiaddr *first,
					struct ofp_ifmultiaddr *next);
void add_multicast_address(struct ofp_ifnet *ifp,
			   struct ofp_ifmultiaddr *multicast_address)
{
	struct ofp_ifmultiaddr *first = ifp->if_multiaddrs.tqh_first;

	if (!first)
		add_first_multicast_address(ifp, multicast_address);
	else
		add_next_multicast_address(first, multicast_address);
}

void add_first_multicast_address(struct ofp_ifnet *ifp,
				 struct ofp_ifmultiaddr *first)
{
	ifp->if_multiaddrs.tqh_first = first;
}

void add_next_multicast_address(struct ofp_ifmultiaddr *first,
				struct ofp_ifmultiaddr *next)
{
	first->ifma_link.tqe_next = next;
}

static struct ofp_ifmultiaddr *new_multicast_address(void);
static struct ofp_sockaddr *new_unspecified_address(void);
struct ofp_ifmultiaddr *new_unspecified_multicast_address(void)
{
	struct ofp_ifmultiaddr *multicast_address = new_multicast_address();

	multicast_address->ifma_addr = new_unspecified_address();
	return multicast_address;
}

static struct ofp_in_multi *new_multicast_group(void);
struct ofp_ifmultiaddr *new_multicast_address(void)
{
	void *p = malloc(sizeof(struct ofp_ifmultiaddr));
	struct ofp_ifmultiaddr *multicast_address = (struct ofp_ifmultiaddr *)p;

	multicast_address->ifma_link.tqe_next = NULL;
	multicast_address->ifma_protospec = new_multicast_group();
	return multicast_address;
}

struct ofp_in_multi *new_multicast_group(void)
{
	void *p = malloc(sizeof(struct ofp_in_multi));
	struct ofp_in_multi *multicast_group = (struct ofp_in_multi *)p;

	multicast_group->inm_addr.s_addr = MATCHING_IP;
	return multicast_group;
}

static struct ofp_sockaddr *new_address(void);
struct ofp_sockaddr *new_unspecified_address(void)
{
	struct ofp_sockaddr *address = new_address();

	address->sa_family = OFP_AF_UNSPEC;
	return address;
}

struct ofp_sockaddr *new_address(void)
{
	return (struct ofp_sockaddr *)malloc(sizeof(struct ofp_sockaddr));
}

static void
release_multicast_address(struct ofp_ifmultiaddr *multicast_address);
void release_ifnet(struct ofp_ifnet *ifp)
{
	release_multicast_address(ifp->if_multiaddrs.tqh_first);
}

void release_multicast_address(struct ofp_ifmultiaddr *multicast_address)
{
	if (!multicast_address)
		return;

	release_multicast_address(multicast_address->ifma_link.tqe_next);
	free(multicast_address->ifma_addr);
	free(multicast_address->ifma_protospec);
	free(multicast_address);
}

static struct ofp_sockaddr *new_ip_address(void);
struct ofp_ifmultiaddr *new_ip_multicast_address(void)
{
	struct ofp_ifmultiaddr *multicast_address = new_multicast_address();

	multicast_address->ifma_addr = new_ip_address();
	return multicast_address;
}

struct ofp_sockaddr *new_ip_address(void)
{
	struct ofp_sockaddr *address = new_address();

	address->sa_family = OFP_AF_INET;
	return address;
}
