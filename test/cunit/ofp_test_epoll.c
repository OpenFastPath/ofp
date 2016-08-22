/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef OFP_TESTMODE_AUTO
#define OFP_TESTMODE_AUTO 1
#endif

#include "ofp_epoll.h"
#include "ofpi_epoll.h"
#include <stdint.h>
#include "ofp_errno.h"
#include "ofpi_socketvar.h"
#include "ofp_cunit_version.h"

#if OFP_TESTMODE_AUTO
#include <CUnit/Automated.h>
#else
#include <CUnit/Basic.h>
#endif

#ifndef CU_HAS_SETUP_AND_TEARDOWN
#define SETUP_NON_BLOCKING setup_non_blocking()
#else
#define SETUP_NON_BLOCKING
#endif

#define LENGTH(array) \
	sizeof(array)/sizeof(*array)
#define FOREACH(item, array) \
	int i, l, breaked; \
	for (i = 0, l = LENGTH(array), breaked = 0; i < l && !breaked; ++i, breaked = !breaked) \
		for (item = &array[i]; !breaked; breaked = !breaked)


static const int epfd = OFP_SOCK_NUM_OFFSET;
static const int fd = OFP_SOCK_NUM_OFFSET + 1;
static struct socket epoll = { 0 };
static struct socket non_epoll = { 0 };
static struct ofp_epoll_event event = { 0 };
static struct ofp_epoll_event events[1];

static void test_create_with_invalid_size(void)
{
	ofp_errno = 0;

	CU_ASSERT_EQUAL(ofp_epoll_create(0), -1);
	CU_ASSERT_EQUAL(ofp_errno, OFP_EINVAL);
}

static int failing_socket_creator(void);
static void test_create_with_failing_socket_creator(void)
{
	ofp_errno = 0;

	CU_ASSERT_EQUAL(_ofp_epoll_create(1, failing_socket_creator), -1);
	CU_ASSERT_EQUAL(ofp_errno, OFP_ENOMEM);
}

static int epoll_create(void);
static int is_epoll_socket(struct socket *socket);
static int is_epoll_set_initialized(struct socket *epoll);
static void test_create_epoll_fd(void)
{
	CU_ASSERT_EQUAL(epoll_create(), epfd);
	CU_ASSERT_TRUE(is_epoll_socket(&epoll));
	CU_ASSERT_TRUE(is_epoll_set_initialized(&epoll));
}

static void test_control_with_fd_as_epoll_fd(void)
{
	ofp_errno = 0;

	CU_ASSERT_EQUAL(ofp_epoll_ctl(epfd, OFP_EPOLL_CTL_ADD, epfd, &event), -1);
	CU_ASSERT_EQUAL(ofp_errno, OFP_EINVAL);
}

static struct socket *null_socket_getter(int fd);
static void test_control_with_bad_epoll_fd(void)
{
	ofp_set_socket_getter(null_socket_getter);
	ofp_errno = 0;

	CU_ASSERT_EQUAL(ofp_epoll_ctl(-1, OFP_EPOLL_CTL_ADD, fd, &event), -1);
	CU_ASSERT_EQUAL(ofp_errno, OFP_EBADF);
}

static struct socket *dummy_socket_getter(int fd);
static void test_control_with_non_epoll_fd(void)
{
	ofp_set_socket_getter(dummy_socket_getter);
	ofp_errno = 0;

	CU_ASSERT_EQUAL(_ofp_epoll_ctl(&non_epoll, OFP_EPOLL_CTL_ADD, fd, &event), -1);
	CU_ASSERT_EQUAL(ofp_errno, OFP_EINVAL);
}

static void test_control_with_bad_fd(void)
{
	ofp_set_socket_getter(null_socket_getter);
	ofp_errno = 0;

	CU_ASSERT_EQUAL(_ofp_epoll_ctl(&epoll, OFP_EPOLL_CTL_ADD, -1, &event), -1);
	CU_ASSERT_EQUAL(ofp_errno, OFP_EBADF);
}

static void test_control_with_invalid_op(void)
{
	ofp_set_socket_getter(dummy_socket_getter);
	ofp_errno = 0;

	CU_ASSERT_EQUAL(_ofp_epoll_ctl(&epoll, 0, fd, &event), -1);
	CU_ASSERT_EQUAL(ofp_errno, OFP_EINVAL);
}

static void test_wait_with_bad_epoll_fd(void)
{
	ofp_set_socket_getter(null_socket_getter);
	ofp_errno = 0;

	CU_ASSERT_EQUAL(ofp_epoll_wait(-1, events, 1, 0), -1);
	CU_ASSERT_EQUAL(ofp_errno, OFP_EBADF);
}

static void test_wait_with_non_epoll_fd(void)
{
	ofp_errno = 0;

	CU_ASSERT_EQUAL(_ofp_epoll_wait(&non_epoll, events, 1, 0), -1);
	CU_ASSERT_EQUAL(ofp_errno, OFP_EINVAL);
}

static void test_wait_with_invalid_max_events(void)
{
	ofp_errno = 0;

	CU_ASSERT_EQUAL(_ofp_epoll_wait(&epoll, events, 0, 0), -1);
	CU_ASSERT_EQUAL(ofp_errno, OFP_EINVAL);
}

static void test_wait_with_null_events(void)
{
	ofp_errno = 0;

	CU_ASSERT_EQUAL(_ofp_epoll_wait(&epoll, NULL, 1, 0), -1);
	CU_ASSERT_EQUAL(ofp_errno, OFP_EFAULT);
}

static int epoll_wait(int maxevents);
static void test_wait_with_no_registered_fds(void)
{
	CU_ASSERT_EQUAL(epoll_wait(1), 0);
}

static int add_fd(int fd);
static void setup_non_blocking(void)
{
	epoll_create();
	add_fd(fd);
	add_fd(fd + 1);
	ofp_errno = 0;
}

static int delete_fd(int fd);
static void test_delete_unregistered_fd(void)
{
	SETUP_NON_BLOCKING;

	CU_ASSERT_EQUAL(delete_fd(epfd), -1);
	CU_ASSERT_EQUAL(ofp_errno, OFP_ENOENT);
}

static int modify_fd(int fd);
static void test_modify_unregistered_fd(void)
{
	SETUP_NON_BLOCKING;

	CU_ASSERT_EQUAL(modify_fd(epfd), -1);
	CU_ASSERT_EQUAL(ofp_errno, OFP_ENOENT);
}

static void test_add_registered_fd(void)
{
	SETUP_NON_BLOCKING;

	CU_ASSERT_EQUAL(add_fd(fd), -1);
	CU_ASSERT_EQUAL(ofp_errno, OFP_EEXIST);

	CU_ASSERT_EQUAL(add_fd(fd + 1), -1);
	CU_ASSERT_EQUAL(ofp_errno, OFP_EEXIST);
}

static void test_delete_registered_fd(void)
{
	SETUP_NON_BLOCKING;

	CU_ASSERT_EQUAL(delete_fd(fd), 0);
	CU_ASSERT_EQUAL(delete_fd(fd), -1);

	CU_ASSERT_EQUAL(delete_fd(fd + 1), 0);
	CU_ASSERT_EQUAL(delete_fd(fd + 1), -1);
}

static void test_modify_registered_fd(void)
{
	SETUP_NON_BLOCKING;

	CU_ASSERT_EQUAL(modify_fd(fd), 0);
}

static char *const_cast(const char *str)
{
	return (char *)(uintptr_t)str;
}

int main(void)
{
	if (CU_initialize_registry() != CUE_SUCCESS)
		return CU_get_error();

	CU_SuiteInfo suites[5] = { CU_SUITE_INFO_NULL };

	CU_TestInfo create[] = {
		{ const_cast("Create will fail when called with non-positive size"),
		  test_create_with_invalid_size },
		{ const_cast("Create will fail when socket creation fails"),
		  test_create_with_failing_socket_creator },
		{ const_cast("Create epoll instance"),
		  test_create_epoll_fd },
		CU_TEST_INFO_NULL
	};

	CU_TestInfo control[] = {
		{ const_cast("Control will fail when fd is same as epoll fd"),
		  test_control_with_fd_as_epoll_fd },
		{ const_cast("Control will fail when called with bad epoll fd"),
		  test_control_with_bad_epoll_fd },
		{ const_cast("Control will fail when called with non-epoll fd"),
		  test_control_with_non_epoll_fd },
		{ const_cast("Control will fail when called with bad fd"),
		  test_control_with_bad_fd },
		{ const_cast("Control will fail when called with invalid op"),
		  test_control_with_invalid_op },
		CU_TEST_INFO_NULL
	};

	CU_TestInfo wait[] = {
		{ const_cast("Wait will fail when called with bad epoll fd"),
		  test_wait_with_bad_epoll_fd },
		{ const_cast("Wait will fail when called with non-epoll fd"),
		  test_wait_with_non_epoll_fd },
		{ const_cast("Wait will fail when called with non-positive maxevents"),
		  test_wait_with_invalid_max_events },
		{ const_cast("Wait will fail when called with invalid events"),
		  test_wait_with_null_events },
		{ const_cast("Wait will return zero with no registered fds"),
		  test_wait_with_no_registered_fds },
		CU_TEST_INFO_NULL
	};

	CU_TestInfo non_blocking_operations[] = {
		{ const_cast("Control will fail when deleting unregistered fd"),
		  test_delete_unregistered_fd },
		{ const_cast("Control will fail when modifying unregistered fd"),
		  test_modify_unregistered_fd },
		{ const_cast("Control will fail when adding registered fd"),
		  test_add_registered_fd },
		{ const_cast("Delete registered fd from epoll instance"),
		  test_delete_registered_fd },
		{ const_cast("Modify registered fd in epoll instance"),
		  test_modify_registered_fd },
		CU_TEST_INFO_NULL
	};


	suites[0].pName = const_cast("ofp epoll - create");
	suites[0].pTests = create;
	suites[1].pName = const_cast("ofp epoll - control");
	suites[1].pTests = control;
	suites[2].pName = const_cast("ofp epoll - wait");
	suites[2].pTests = wait;
	suites[3].pName = const_cast("ofp epoll - non-blocking operations");
#ifdef CU_HAS_SETUP_AND_TEARDOWN
	suites[3].pSetUpFunc = setup_non_blocking;
#endif
	suites[3].pTests = non_blocking_operations;

	if (CU_register_suites(suites) != CUE_SUCCESS) {
		CU_cleanup_registry();
		return CU_get_error();
	}

#if OFP_TESTMODE_AUTO
	CU_set_output_filename("CUnit-epoll");
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

int failing_socket_creator(void)
{
	ofp_errno = OFP_ENOMEM;
	return -1;
}

static int epoll_socket_creator(void)
{
	int *epoll_set;

	epoll.so_number = epfd;
	epoll.so_type = OFP_SOCK_EPOLL;

	FOREACH(epoll_set, epoll.epoll_set)
		*epoll_set = -1;

	return epoll.so_number;
}

int epoll_create(void)
{
	return _ofp_epoll_create(1, epoll_socket_creator);
}

int is_epoll_socket(struct socket *socket)
{
	return (socket->so_type == OFP_SOCK_EPOLL);
}

int is_epoll_set_initialized(struct socket *epoll)
{
	int *epoll_set;

	FOREACH(epoll_set, epoll->epoll_set)
		if (*epoll_set != -1)
			return 0;

	return 1;
}

struct socket *dummy_socket_getter(int fd)
{
	(void)fd;
	return &non_epoll;
}

struct socket *null_socket_getter(int fd)
{
	(void)fd;
	return NULL;
}

int epoll_wait(int maxevents)
{
	return _ofp_epoll_wait(&epoll, events, maxevents, 0);
}

static int epoll_control(int op, int fd)
{
	ofp_set_socket_getter(dummy_socket_getter);
	return _ofp_epoll_ctl(&epoll, op, fd, &event);
}

int add_fd(int fd)
{
	return epoll_control(OFP_EPOLL_CTL_ADD, fd);
}

int delete_fd(int fd)
{
	return epoll_control(OFP_EPOLL_CTL_DEL, fd);
}

int modify_fd(int fd)
{
	return epoll_control(OFP_EPOLL_CTL_MOD, fd);
}
