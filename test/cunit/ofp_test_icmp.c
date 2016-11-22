/* Copyright (c) 2016, Nokia
 * Copyright (c) 2016, ENEA Software AB
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef OFP_TESTMODE_AUTO
#define OFP_TESTMODE_AUTO 1
#endif

#include "ofpi_icmp.h"
#include <stdint.h>
#include "api/ofp_log.h"
#include "ofpi_protosw.h"

#if OFP_TESTMODE_AUTO
#include <CUnit/Automated.h>
#else
#include <CUnit/Basic.h>
#endif

enum ofp_log_level_s log_level;
pr_ctlinput_t *ctlinput_bkp;
static odp_packet_t icmp = { 0 };
static struct ofp_ip ip = { 0 };
static struct ofp_icmp icp = { 0 };
static int command;

static enum ofp_log_level_s disable_logging(void);
static void ctlinput_spy(int cmd, struct ofp_sockaddr *sa, void *vip);
static int init(void)
{
	log_level = disable_logging();
	ctlinput_bkp = ofp_inetsw[0].pr_ctlinput;
	ofp_inetsw[0].pr_ctlinput = ctlinput_spy;
	return 0;
}

static void restore_logging(enum ofp_log_level_s log_level);
static int cleanup(void)
{
	ofp_inetsw[0].pr_ctlinput = ctlinput_bkp;
	restore_logging(log_level);
	return 0;
}

static void set_packet_length(uint16_t length);
static int icmp_dropped(void);
static void test_icmp_packet_too_short(void)
{
	set_packet_length(OFP_ICMP_MINLEN - 1);

	CU_ASSERT_TRUE(icmp_dropped());
}

static void set_packet_minimum_length(void);
static int icmp_dropped_for_bad_type(uint8_t icmp_type);
static void test_invalid_icmp_type(void)
{
	set_packet_minimum_length();

	CU_ASSERT_TRUE(icmp_dropped_for_bad_type(OFP_ICMP_MAXTYPE));
	CU_ASSERT_TRUE(icmp_dropped_for_bad_type(OFP_ICMP_MAXTYPE + 1));
}

static void set_icmp_type(uint8_t icmp_type);
static int icmp_dropped_for_bad_code(uint8_t icmp_code);
static void test_icmp_destination_unreachable_with_invalid_code(void)
{
	set_packet_minimum_length();
	set_icmp_type(OFP_ICMP_UNREACH);

	CU_ASSERT_TRUE(icmp_dropped_for_bad_code(OFP_ICMP_MAXTYPE + 1));
}

static void set_icmp_code(uint8_t icmp_code);
static int icmp_dropped_for_too_short(uint16_t length);
static void test_icmp_destination_unreachable_packet_too_short(void)
{
	set_icmp_type(OFP_ICMP_UNREACH);
	set_icmp_code(OFP_ICMP_UNREACH_NET);

	CU_ASSERT_TRUE(icmp_dropped_for_too_short(OFP_ICMP_MINLEN));
	CU_ASSERT_TRUE(icmp_dropped_for_too_short(OFP_ICMP_ADVLENMIN));
}

static void set_minimum_header_length(void);
static int icmp_delivered(uint8_t icmp_code, int cmd);
static void test_icmp_destination_unreachable(void)
{
	set_packet_length(OFP_ICMP_ADVLENMIN);
	set_minimum_header_length();
	set_icmp_type(OFP_ICMP_UNREACH);

	CU_ASSERT_TRUE(icmp_delivered(OFP_ICMP_UNREACH_NET, OFP_PRC_UNREACH_NET));
	CU_ASSERT_TRUE(icmp_delivered(OFP_ICMP_UNREACH_NEEDFRAG, OFP_PRC_MSGSIZE));
	CU_ASSERT_TRUE(icmp_delivered(OFP_ICMP_UNREACH_PROTOCOL, OFP_PRC_UNREACH_PORT));
	CU_ASSERT_TRUE(icmp_delivered(OFP_ICMP_UNREACH_NET_PROHIB, OFP_PRC_UNREACH_ADMIN_PROHIB));
}

static void test_icmp_time_exceeded_with_invalid_code(void)
{
	set_packet_minimum_length();
	set_icmp_type(OFP_ICMP_TIMXCEED);

	CU_ASSERT_TRUE(icmp_dropped_for_bad_code(2));
}

static void test_icmp_time_exceeded(void)
{
	set_packet_length(OFP_ICMP_ADVLENMIN);
	set_minimum_header_length();
	set_icmp_type(OFP_ICMP_TIMXCEED);

	CU_ASSERT_TRUE(icmp_delivered(0, OFP_PRC_TIMXCEED_INTRANS));
	CU_ASSERT_TRUE(icmp_delivered(1, OFP_PRC_TIMXCEED_REASS));
}

static void test_icmp_bad_ip_header_with_invalid_code(void)
{
	set_packet_minimum_length();
	set_icmp_type(OFP_ICMP_PARAMPROB);

	CU_ASSERT_TRUE(icmp_dropped_for_bad_code(2));
}

static void test_icmp_bad_ip_header(void)
{
	set_packet_length(OFP_ICMP_ADVLENMIN);
	set_minimum_header_length();
	set_icmp_type(OFP_ICMP_PARAMPROB);

	CU_ASSERT_TRUE(icmp_delivered(1, OFP_PRC_PARAMPROB));
}

static void test_icmp_packet_lost_with_invalid_code(void)
{
	set_packet_minimum_length();
	set_icmp_type(OFP_ICMP_SOURCEQUENCH);

	CU_ASSERT_TRUE(icmp_dropped_for_bad_code(1));
}

static void test_icmp_packet_lost(void)
{
	set_packet_length(OFP_ICMP_ADVLENMIN);
	set_minimum_header_length();
	set_icmp_type(OFP_ICMP_SOURCEQUENCH);

	CU_ASSERT_TRUE(icmp_delivered(0, OFP_PRC_QUENCH));
}

static int icmp_reflected(uint8_t icmp_type);
static void test_icmp_echo(void)
{
	set_packet_minimum_length();

	CU_ASSERT_TRUE(icmp_reflected(OFP_ICMP_ECHO));
}

static void test_icmp_timestamp_request_too_short(void)
{
	set_icmp_type(OFP_ICMP_TSTAMP);

	CU_ASSERT_TRUE(icmp_dropped_for_too_short(OFP_ICMP_TSLEN - 1));
}

static void test_icmp_timestamp_request(void)
{
	set_packet_length(OFP_ICMP_TSLEN);

	CU_ASSERT_TRUE(icmp_reflected(OFP_ICMP_TSTAMP));
}

static void test_icmp_address_mask_request(void)
{
	set_packet_minimum_length();
	set_icmp_type(OFP_ICMP_MASKREQ);

	CU_ASSERT_TRUE(icmp_dropped());
}

static void test_icmp_redirect(void)
{
	set_packet_minimum_length();
	set_icmp_type(OFP_ICMP_REDIRECT);

	CU_ASSERT_TRUE(icmp_dropped());
}

static char *const_cast(const char *str)
{
	return (char *)(uintptr_t)str;
}

int main(void)
{
	if (CU_initialize_registry() != CUE_SUCCESS)
		return CU_get_error();

	CU_SuiteInfo suites[2] = { CU_SUITE_INFO_NULL };
	CU_TestInfo test[] = {
		{ const_cast("Packet too short"),
		  test_icmp_packet_too_short },
		{ const_cast("Invalid ICMP type"),
		  test_invalid_icmp_type },
		{ const_cast("Destination unreachable with invalid code"),
		  test_icmp_destination_unreachable_with_invalid_code },
		{ const_cast("Destination unreachable packet is too short"),
		  test_icmp_destination_unreachable_packet_too_short },
		{ const_cast("Destination unreachable"),
		  test_icmp_destination_unreachable },
		{ const_cast("Time exceeded with invalid code"),
		  test_icmp_time_exceeded_with_invalid_code },
		{ const_cast("Time exceeded"),
		  test_icmp_time_exceeded },
		{ const_cast("Bad IP header with invalid code"),
		  test_icmp_bad_ip_header_with_invalid_code },
		{ const_cast("Bad IP header"),
		  test_icmp_bad_ip_header },
		{ const_cast("Packet lost with invalid code"),
		  test_icmp_packet_lost_with_invalid_code },
		{ const_cast("Packet lost"),
		  test_icmp_packet_lost },
		{ const_cast("Echo"),
		  test_icmp_echo },
		{ const_cast("Timestamp request is too short"),
		  test_icmp_timestamp_request_too_short },
		{ const_cast("Timestamp request"),
		  test_icmp_timestamp_request },
		{ const_cast("Address mask request"),
		  test_icmp_address_mask_request },
		{ const_cast("Redirect"),
		  test_icmp_redirect },
		CU_TEST_INFO_NULL
	};

	suites[0].pName = const_cast("ofp icmp");
	suites[0].pInitFunc = init;
	suites[0].pTests = test;
	suites[0].pCleanupFunc = cleanup;

	if (CU_register_suites(suites) != CUE_SUCCESS) {
		CU_cleanup_registry();
		return CU_get_error();
	}

#if OFP_TESTMODE_AUTO
	CU_set_output_filename("CUnit-icmp");
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

void ctlinput_spy(int cmd, struct ofp_sockaddr *sa, void *vip)
{
	(void)sa;
	(void)vip;
	command = cmd;
}

void restore_logging(enum ofp_log_level_s log_level)
{
	ofp_loglevel = log_level;
}

void set_packet_length(uint16_t length)
{
	ip.ip_len = odp_cpu_to_be_16(length);
}

void set_packet_minimum_length(void)
{
	set_packet_length(OFP_ICMP_MINLEN);
}

int icmp_dropped(void)
{
	return _ofp_icmp_input(icmp, &ip, &icp, NULL) == OFP_PKT_DROP;
}

int icmp_dropped_for_bad_type(uint8_t icmp_type)
{
	set_icmp_type(icmp_type);
	return icmp_dropped();
}

void set_icmp_type(uint8_t icmp_type)
{
	icp.icmp_type = icmp_type;
}

int icmp_dropped_for_bad_code(uint8_t icmp_code)
{
	set_icmp_code(icmp_code);
	return icmp_dropped();
}

void set_icmp_code(uint8_t icmp_code)
{
	icp.icmp_code = icmp_code;
}

int icmp_dropped_for_too_short(uint16_t length)
{
	set_packet_length(length);
	return icmp_dropped();
}

void set_minimum_header_length(void)
{
	icp.ofp_icmp_ip.ip_hl = sizeof(struct ofp_ip) >> 2;
}

int icmp_delivered(uint8_t icmp_code, int cmd)
{
	set_icmp_code(icmp_code);
	return icmp_dropped() && command == cmd;
}

static enum ofp_return_code
icmp_reflect_dummy(odp_packet_t pkt)
{
	(void)pkt;
	return OFP_PKT_PROCESSED;
}

int icmp_reflected(uint8_t icmp_type)
{
	set_icmp_type(icmp_type);
	return _ofp_icmp_input(icmp, &ip, &icp, icmp_reflect_dummy) == OFP_PKT_PROCESSED;
}
