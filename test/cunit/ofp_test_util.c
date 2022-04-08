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

#include <odp_api.h>
#include <ofpi_ethernet.h>
#include "ofpi_log.h"
#include "../../src/ofp_util.c"

/*
 * Test data
 */
char testFileName[] = "testbuf.txt";
uint32_t ipaddr = 0x650AA8C0; /* C0.A8.0A.65 = 192.168.10.101 */
uint8_t ip6addr[16] = {
0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef
};
uint8_t macaddr[6] = { 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA };

static odp_instance_t instance;

/*
 * INIT
 */
static int
init_suite(void)
{
	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, NULL, NULL)) {
		printf("Error: ODP global init failed.\n");
		return -1;
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		printf("Error: ODP local init failed.\n");
		return -1;
	}
	return 0;
}

static int
clean_suite(void)
{
	if (odp_term_local())
		OFP_ERR("Error: ODP local term failed.\n");

	if (odp_term_global(instance))
		OFP_ERR("Error: ODP global term failed.\n");

	return 0;
}

/*
 * Testcases
 */

static void
test_ofp_print_mac(void)
{
	char *res = ofp_print_mac(macaddr);

	CU_ASSERT_STRING_EQUAL(res, " ff:ee:dd:cc:bb:aa");
}

static void
test_ofp_print_ip_addr(void)
{
	char *res = ofp_print_ip_addr(ipaddr);

	CU_ASSERT_STRING_EQUAL(res, "192.168.10.101");
}

static void
test_ofp_print_ip6_addr(void)
{
	char *res = ofp_print_ip6_addr(ip6addr);

	CU_ASSERT_STRING_EQUAL(res, "dead:beef:dead:beef:dead:beef:dead:beef");
}

static void
test_ofp_hex_to_num(void)
{
	int res;
	char str[] = "08F7e0";

	res = ofp_hex_to_num(str);
	CU_ASSERT_EQUAL(res, 0x8F7e0);
}

static void
test_ofp_mac_to_link_local(void)
{
	uint8_t linklocal[16];
	uint8_t ref[16] = { 0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
			    0xfd, 0xee, 0xdd, 0xff, 0xfe, 0xcc, 0xbb, 0xaa };

	ofp_mac_to_link_local(macaddr, linklocal);

	if (memcmp(linklocal, ref, 16))
		CU_FAIL("memcmp failed")
	else
		CU_PASS("memcmp")
}

static void
test_ofp_ip6_masklen_to_mask(void)
{
	uint8_t mask[16];
	uint8_t ref[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8,
			    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

	ofp_ip6_masklen_to_mask(61, mask);

	if (memcmp(mask, ref, 16))
		CU_FAIL("memcmp failed")
	else
		CU_PASS("memcmp")
}

static void
test_ofp_mask_length(void)
{
	int res;
	unsigned long mask = 0xFFFFFC00; /* L.E.: 00 FC FF FF */

	res = ofp_mask_length(32, (uint8_t *)&mask);

	CU_ASSERT_EQUAL(res, 22);
}

static void
test_ofp_name_to_port_vlan(void)
{
	char devname[] = "fp4.100";
	int port, vlan;

	port = ofp_name_to_port_vlan(devname, &vlan);

	CU_ASSERT_EQUAL(port, 4);
	CU_ASSERT_EQUAL(vlan, 100);

	strcpy(devname, "gre101");
	port = ofp_name_to_port_vlan(devname, &vlan);

	CU_ASSERT_EQUAL(port, GRE_PORTS);
	CU_ASSERT_EQUAL(vlan, 101);

}

static void
test_ofp_port_vlan_to_ifnet_name(void)
{
	int port = 4;
	int vlan = 100;
	char *res = (char *)malloc(20);

	memset(res, 0x0, 20);

	res = ofp_port_vlan_to_ifnet_name(port, vlan);

	CU_ASSERT_STRING_EQUAL(res, "fp4.100");
}

static void
test_ofp_sendf(void)
{
#define BUFLEN 15
	char res[BUFLEN];
	int fd, l;
	FILE *f;

	memset(res, 0x0, BUFLEN);

	fd = open(testFileName,
		  O_WRONLY | O_CREAT | O_TRUNC,
		  S_IWRITE | S_IREAD);
	l = ofp_sendf(fd, "%s %d", "Hello ODP!", 0xA);
	close(fd);

	CU_ASSERT_EQUAL(l, 13);

	f = fopen(testFileName, "r");
	if (fgets(res, BUFLEN, f) != NULL)
		CU_ASSERT_STRING_EQUAL(res, "Hello ODP! 10")
	else
		CU_FAIL("Cannot read output file.")

	fclose(f);
#undef BUFLEN
}

static void test_ofp_has_mac(void)
{
	int res;
	uint8_t empty[6];

	memset(empty, 0, sizeof(empty));
	res = ofp_has_mac(empty);
	CU_ASSERT_EQUAL(res, 0);

	res = ofp_has_mac(macaddr);
	CU_ASSERT_EQUAL(res, 1);
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
	ptr_suite = CU_add_suite("ofp util", init_suite, clean_suite);
	if (NULL == ptr_suite) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite, test_ofp_print_mac)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite, test_ofp_print_ip_addr)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite, test_ofp_print_ip6_addr)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite, test_ofp_hex_to_num)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite, test_ofp_mac_to_link_local)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite, test_ofp_ip6_masklen_to_mask)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite, test_ofp_mask_length)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite, test_ofp_name_to_port_vlan)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite,
				test_ofp_port_vlan_to_ifnet_name)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite, test_ofp_sendf)) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite, test_ofp_has_mac)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

#if OFP_TESTMODE_AUTO
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
