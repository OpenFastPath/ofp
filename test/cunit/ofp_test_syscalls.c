/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef OFP_TESTMODE_AUTO
#define OFP_TESTMODE_AUTO 1
#endif

#include "ofp_socket.h"
#include "ofpi_syscalls.h"
#include "ofpi_socketvar.h"
#include "ofpi_protosw.h"
#include "ofpi_shared_mem.h"
#include "ofp_cunit_version.h"

#if OFP_TESTMODE_AUTO
#include <CUnit/Automated.h>
#else
#include <CUnit/Basic.h>
#endif

#ifndef CU_HAS_SETUP_AND_TEARDOWN
#define SETUP setup_with_shm()
#define TEARDOWN teardown_with_shm()
#else
#define SETUP
#define TEARDOWN
#endif

void *shm;
odp_pool_t ofp_packet_pool;
int (*pru_attach)(struct socket *so, int proto, struct thread *td);
int sleeper_called;
uint32_t sleeper_timeout;

static int pru_attach_stub(struct socket *so, int proto, struct thread *td);
static int init(void)
{
	struct protosw *prp = ofp_pffindproto(OFP_AF_INET, 0, OFP_SOCK_STREAM);

	pru_attach = prp->pr_usrreqs->pru_attach;
	prp->pr_usrreqs->pru_attach = pru_attach_stub;
	return 0;
}

static int cleanup(void)
{
	struct protosw *prp = ofp_pffindproto(OFP_AF_INET, 0, OFP_SOCK_STREAM);

	prp->pr_usrreqs->pru_attach = pru_attach;
	return 0;
}

static void *allocator(const char *name, uint64_t size);
static void setup_with_shm(void)
{
	ofp_set_custom_allocator(allocator);
	ofp_socket_init_global(ofp_packet_pool);
	sleeper_called = 0;
	sleeper_timeout = 0;
}

static void teardown_with_shm(void)
{
	free(shm);
	ofp_set_custom_allocator(NULL);
}

static void test_null_fd_set(void)
{
	const int fd = OFP_SOCK_NUM_OFFSET;

	OFP_FD_ZERO(NULL);
	OFP_FD_SET(fd, NULL);
	CU_ASSERT_FALSE(OFP_FD_ISSET(fd, NULL));
	OFP_FD_CLR(fd, NULL);
}

static void test_add_fd_to_set(void)
{
	const int fd = OFP_SOCK_NUM_OFFSET;
	ofp_fd_set set;

	OFP_FD_ZERO(&set);
	CU_ASSERT_FALSE(OFP_FD_ISSET(fd, &set));

	OFP_FD_SET(fd, &set);
	CU_ASSERT_TRUE(OFP_FD_ISSET(fd, &set));
}

static void test_clear_fd_from_set(void)
{
	const int fd = OFP_SOCK_NUM_OFFSET + OFP_NUM_SOCKETS_MAX - 1;
	ofp_fd_set set;

	OFP_FD_ZERO(&set);
	CU_ASSERT_FALSE(OFP_FD_ISSET(fd, &set));

	OFP_FD_SET(fd, &set);
	CU_ASSERT_TRUE(OFP_FD_ISSET(fd, &set));

	OFP_FD_CLR(fd, &set);
	CU_ASSERT_FALSE(OFP_FD_ISSET(fd, &set));
}

static void test_clear_unset_fd_from_set(void)
{
        const int fd = OFP_SOCK_NUM_OFFSET;
        ofp_fd_set set;

        OFP_FD_ZERO(&set);
        OFP_FD_CLR(fd, &set);
        CU_ASSERT_FALSE(OFP_FD_ISSET(fd, &set));
}

static int sleeper_spy(void *channel, odp_rwlock_t *mtx, int priority,
		       const char *wmesg, uint32_t timeout);
static void test_select_as_portable_sleep(void)
{
	struct ofp_timeval timeout = { 1, 1 };

	CU_ASSERT_EQUAL(_ofp_select(0, NULL, NULL, NULL, &timeout, sleeper_spy), 0);
	CU_ASSERT_EQUAL(sleeper_timeout, 1 * US_PER_SEC + 1)
}

static void test_select_returns_immediately(void)
{
	SETUP;

	struct ofp_timeval timeout = { 0, 0 };

	CU_ASSERT_EQUAL(_ofp_select(0, NULL, NULL, NULL, &timeout, sleeper_spy), 0);
	CU_ASSERT_FALSE(sleeper_called);

	TEARDOWN;
}

static int select_readfds(int nfds, ofp_fd_set *readfds);
static void test_select_times_out(void)
{
	SETUP;

	const int accepting = OFP_SOCK_NUM_OFFSET + OFP_NUM_SOCKETS_MAX - 1;
	const int listening = OFP_SOCK_NUM_OFFSET;
	ofp_fd_set set;

	OFP_FD_ZERO(&set);
	OFP_FD_SET(accepting, &set);
	OFP_FD_SET(listening, &set);

	CU_ASSERT_EQUAL(select_readfds(accepting + 1, &set), 0);
	CU_ASSERT_FALSE(OFP_FD_ISSET(accepting, &set));
	CU_ASSERT_FALSE(OFP_FD_ISSET(listening, &set));

	TEARDOWN;
}

static void set_accepting_socket(int fd);
static void set_accepting_socket_readable(int fd);
static void test_select_with_accepting_socket_readable(void)
{
	SETUP;

	const int fd = ofp_socket(OFP_AF_INET, OFP_SOCK_STREAM, 0);
	ofp_fd_set set;

	OFP_FD_ZERO(&set);
	OFP_FD_SET(fd, &set);

	set_accepting_socket(fd);
	set_accepting_socket_readable(fd);

	CU_ASSERT_EQUAL(select_readfds(fd + 1, &set), 1);
	CU_ASSERT_TRUE(OFP_FD_ISSET(fd, &set));

	TEARDOWN;
}

static void set_listening_socket_readable(int fd);
static void test_select_with_listening_socket_readable(void)
{
	SETUP;

	const int fd = ofp_socket(OFP_AF_INET, OFP_SOCK_STREAM, 0);
	ofp_fd_set set;

	OFP_FD_ZERO(&set);
	OFP_FD_SET(fd, &set);

	set_listening_socket_readable(fd);

	CU_ASSERT_EQUAL(select_readfds(fd + 1, &set), 1);
	CU_ASSERT_TRUE(OFP_FD_ISSET(fd, &set));

	TEARDOWN;
}

static void test_select_with_multiple_readable_fds(void)
{
	SETUP;

	const int accepting = ofp_socket(OFP_AF_INET, OFP_SOCK_STREAM, 0);
	const int listening = ofp_socket(OFP_AF_INET, OFP_SOCK_STREAM, 0);
	ofp_fd_set set;

	OFP_FD_ZERO(&set);
	OFP_FD_SET(accepting, &set);
	OFP_FD_SET(listening, &set);

	set_accepting_socket(accepting);
	set_accepting_socket_readable(accepting);
	set_listening_socket_readable(listening);

	CU_ASSERT_EQUAL(select_readfds(listening + 1, &set), 2);

	TEARDOWN;
}

static void test_select_with_already_readable_fd(void)
{
	SETUP;

	const int fd = ofp_socket(OFP_AF_INET, OFP_SOCK_STREAM, 0);
	ofp_fd_set set;

	OFP_FD_ZERO(&set);
	OFP_FD_SET(fd, &set);

	set_listening_socket_readable(fd);

	CU_ASSERT_EQUAL(_ofp_select(fd + 1, &set, NULL, NULL, NULL, sleeper_spy), 1);
	CU_ASSERT_FALSE(sleeper_called);

	TEARDOWN;
}

static int sleeper_fake(void *channel, odp_rwlock_t *mtx, int priority,
			const char *wmesg, uint32_t timeout);
static void test_select_with_sleep_interrupting_fd(void)
{
	SETUP;

	const int fd = ofp_socket(OFP_AF_INET, OFP_SOCK_STREAM, 0);
	ofp_fd_set set;

	OFP_FD_ZERO(&set);
	OFP_FD_SET(fd, &set);

	CU_ASSERT_EQUAL(_ofp_select(fd + 1, &set, NULL, NULL, NULL, sleeper_fake), 1);
	CU_ASSERT_TRUE(OFP_FD_ISSET(fd, &set));

	TEARDOWN;
}

static char *const_cast(const char *str)
{
	return (char *)(uintptr_t)str;
}

int main(void)
{
	if (CU_initialize_registry() != CUE_SUCCESS)
		return CU_get_error();

	CU_TestInfo fd_set[] = {
		{ const_cast("NULL fd set"), test_null_fd_set },
		{ const_cast("Add fd to set"), test_add_fd_to_set },
		{ const_cast("Remove fd from set"), test_clear_fd_from_set },
		{ const_cast("Remove unset fd from set"), test_clear_unset_fd_from_set },
		  CU_TEST_INFO_NULL
	};

	CU_TestInfo select[] = {
		{ const_cast("Select as portable way to sleep"),
		  test_select_as_portable_sleep },
		{ const_cast("Select will return immediately with zero timeout"),
		  test_select_returns_immediately },
		{ const_cast("Fd set is cleared when select times out"),
		  test_select_times_out },
		{ const_cast("Select leaves the fd in set when accepting socket is readable"),
		  test_select_with_accepting_socket_readable },
		{ const_cast("Select leaves the fd in set when listening socket is readable"),
		  test_select_with_listening_socket_readable },
		{ const_cast("Select returns the number of readable fds"),
		  test_select_with_multiple_readable_fds },
		{ const_cast("Select will not sleep if an fd is already readable"),
		  test_select_with_already_readable_fd },
		{ const_cast("Select returns the number of readable fds after sleep"),
		  test_select_with_sleep_interrupting_fd },
		CU_TEST_INFO_NULL
	};

	CU_SuiteInfo suites[] = {
		CU_SUITE_INFO_NULL,
		CU_SUITE_INFO_NULL,
		CU_SUITE_INFO_NULL
	};

	suites[0].pInitFunc = init;
	suites[0].pCleanupFunc = cleanup;
	suites[0].pName = const_cast("ofp syscall - fd set");
	suites[0].pTests = fd_set;

	suites[1].pInitFunc = init;
	suites[1].pCleanupFunc = cleanup;
#ifdef CU_HAS_TEST_SETUP_AND_TEARDOWN
	suites[1].pSetUpFunc = setup_with_shm;
	suites[1].pTearDownFunc = teardown_with_shm;
#endif
	suites[1].pName = const_cast("ofp syscall - select");
	suites[1].pTests = select;

	if (CU_register_suites(suites) != CUE_SUCCESS) {
		CU_cleanup_registry();
		return CU_get_error();
	}

#if OFP_TESTMODE_AUTO
	CU_set_output_filename("CUnit-syscalls");
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

int pru_attach_stub(struct socket *so, int proto, struct thread *td)
{
	(void)so;
	(void)proto;
	(void)td;
	return 0;
}

void *allocator(const char *name, uint64_t size)
{
	(void)name;
	shm = malloc(size);
	return shm;
}

int sleeper_spy(void *channel, odp_rwlock_t *mtx, int priority,
		const char *wmesg, uint32_t timeout)
{
	(void)channel;
	(void)mtx;
	(void)priority;
	(void)wmesg;
	sleeper_timeout = timeout;
	sleeper_called = 1;
	return 0;
}

static int sleeper_stub(void *channel, odp_rwlock_t *mtx, int priority,
			const char *wmesg, uint32_t timeout)
{
	(void)channel;
	(void)mtx;
	(void)priority;
	(void)wmesg;
	(void)timeout;
	return 0;
}

int select_readfds(int nfds, ofp_fd_set *readfds)
{
	return _ofp_select(nfds, readfds, NULL, NULL, NULL, sleeper_stub);
}

void set_accepting_socket(int fd)
{
	struct socket *socket = ofp_get_sock_by_fd(fd);

	socket->so_options = OFP_SO_ACCEPTCONN;
}

void set_accepting_socket_readable(int fd)
{
	struct socket *socket = ofp_get_sock_by_fd(fd);

	socket->so_comp.tqh_first = (struct socket *)1;
}

void set_listening_socket_readable(int fd)
{
	struct socket *socket = ofp_get_sock_by_fd(fd);

	socket->so_rcv.sb_cc = 1;
}

int sleeper_fake(void *channel, odp_rwlock_t *mtx, int priority,
		 const char *wmesg, uint32_t timeout)
{
	(void)channel;
	(void)mtx;
	(void)priority;
	(void)wmesg;
	(void)timeout;
	set_listening_socket_readable(OFP_SOCK_NUM_OFFSET);
	return 0;
}
