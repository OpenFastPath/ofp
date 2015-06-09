/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include "ofp.h"
#include "socket_send_recv_tcp.h"
#include "socket_util.h"

int send_tcp4_local_ip(int fd)
{
	struct ofp_sockaddr_in addr = {0};
	const char *buf = "socket_test";

	addr.sin_len = sizeof(struct ofp_sockaddr_in);
	addr.sin_family = OFP_AF_INET;
	addr.sin_port = odp_cpu_to_be_16(TEST_PORT + 1);
	addr.sin_addr.s_addr = IP4(192, 168, 100, 1);

	if (ofp_connect(fd, (struct ofp_sockaddr *)&addr,
			sizeof(addr)) == -1) {
		OFP_ERR("Faild to connect (errno = %d)\n", ofp_errno);
		return -1;
	}

	sleep(1); /* ToFix: connect is not blocking*/

	if (ofp_send(fd, buf, strlen(buf) + 1, 0) == -1) {
		OFP_ERR("Faild to send (errno = %d)\n", ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}

int send_tcp4_any(int fd)
{
	struct ofp_sockaddr_in addr = {0};
	const char *buf = "socket_test";

	addr.sin_len = sizeof(struct ofp_sockaddr_in);
	addr.sin_family = OFP_AF_INET;
	addr.sin_port = odp_cpu_to_be_16(TEST_PORT + 1);
	addr.sin_addr.s_addr = OFP_INADDR_ANY;

	if (ofp_connect(fd, (struct ofp_sockaddr *)&addr,
			sizeof(addr)) == -1) {
		OFP_ERR("Faild to connect (errno = %d)\n", ofp_errno);
		return -1;
	}

	sleep(1); /* ToFix: connect is not blocking*/

	if (ofp_send(fd, buf, strlen(buf) + 1, 0) == -1) {
		OFP_ERR("Faild to send (errno = %d)\n", ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}

#ifdef INET6
int send_tcp6_local_ip(int fd)
{
	struct ofp_sockaddr_in6 addr = {0};
	const char *buf = "socket_test";

	addr.sin6_len = sizeof(struct ofp_sockaddr_in6);
	addr.sin6_family = OFP_AF_INET6;
	addr.sin6_port = odp_cpu_to_be_16(TEST_PORT + 1);
	inet_pton(AF_INET6, "fd00:1baf::1", (void *)&addr.sin6_addr);

	if (ofp_connect(fd, (struct ofp_sockaddr *)&addr,
			sizeof(addr)) == -1) {
		OFP_ERR("Faild to connect (errno = %d)\n", ofp_errno);
		return -1;
	}

	sleep(1); /* ToFix: connect is not blocking*/

	if (ofp_send(fd, buf, strlen(buf) + 1, 0) == -1) {
		OFP_ERR("Faild to send (errno = %d)\n", ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}

int send_tcp6_any(int fd)
{
	struct ofp_sockaddr_in6 addr = {0};
	const char *buf = "socket_test";

	addr.sin6_len = sizeof(struct ofp_sockaddr_in6);
	addr.sin6_family = OFP_AF_INET6;
	addr.sin6_port = odp_cpu_to_be_16(TEST_PORT + 1);
	addr.sin6_addr = ofp_in6addr_any;

	if (ofp_connect(fd, (struct ofp_sockaddr *)&addr,
			sizeof(addr)) == -1) {
		OFP_ERR("Faild to connect (errno = %d)\n", ofp_errno);
		return -1;
	}

	sleep(1); /* ToFix: connect is not blocking*/

	if (ofp_send(fd, buf, strlen(buf) + 1, 0) == -1) {
		OFP_ERR("Faild to send (errno = %d)\n", ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}
#endif /*INET6*/

int receive_tcp(int fd)
{
	char buf[20];
	int len = sizeof(buf);
	int fd_accepted = -1;

	fd_accepted = ofp_accept(fd, NULL, NULL);

	if (fd_accepted == -1) {
		OFP_ERR("Faild to accept connection (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	len = ofp_recv(fd_accepted, buf, sizeof(buf), 0);
	if (len == -1) {
		OFP_ERR("Faild to recv (errno = %d)\n",
			ofp_errno);
		ofp_close(fd_accepted);
		return -1;
	}
	buf[len] = 0;
	OFP_INFO("Data (%s, len = %d) was received.\n", buf, len);

	if (ofp_close(fd_accepted) == -1) {
		OFP_ERR("Faild to close accepted socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}

