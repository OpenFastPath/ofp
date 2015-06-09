/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include "ofp.h"
#include "socket_connect_udp.h"
#include "socket_util.h"

int connect_udp4(int fd)
{
	struct ofp_sockaddr_in addr = {0};

	addr.sin_len = sizeof(struct ofp_sockaddr_in);
	addr.sin_family = OFP_AF_INET;
	addr.sin_port = odp_cpu_to_be_16(TEST_PORT + 2);
	addr.sin_addr.s_addr = IP4(192, 168, 100, 1);

	if (ofp_connect(fd, (const struct ofp_sockaddr *)&addr,
		sizeof(struct ofp_sockaddr_in)) == -1) {
		OFP_ERR("Faild to connect socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}
int connect_bind_udp4(int fd)
{
	struct ofp_sockaddr_in addr = {0};

	addr.sin_len = sizeof(struct ofp_sockaddr_in);
	addr.sin_family = OFP_AF_INET;
	addr.sin_port = odp_cpu_to_be_16(TEST_PORT + 1);
	addr.sin_addr.s_addr = IP4(192, 168, 100, 1);

	if (ofp_bind(fd, (const struct ofp_sockaddr *)&addr,
		sizeof(struct ofp_sockaddr_in)) == -1) {
		OFP_ERR("Faild to bind socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	addr.sin_len = sizeof(struct ofp_sockaddr_in);
	addr.sin_family = OFP_AF_INET;
	addr.sin_port = odp_cpu_to_be_16(TEST_PORT + 3);
	addr.sin_addr.s_addr = IP4(192, 168, 100, 1);

	if (ofp_connect(fd, (const struct ofp_sockaddr *)&addr,
		sizeof(struct ofp_sockaddr_in)) == -1) {
		OFP_ERR("Faild to connect socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}

int connect_shutdown_udp4(int fd)
{
	struct ofp_sockaddr_in addr = {0};

	addr.sin_len = sizeof(struct ofp_sockaddr_in);
	addr.sin_family = OFP_AF_INET;
	addr.sin_port = odp_cpu_to_be_16(TEST_PORT + 2);
	addr.sin_addr.s_addr = IP4(192, 168, 100, 1);

	if (ofp_connect(fd, (const struct ofp_sockaddr *)&addr,
		sizeof(struct ofp_sockaddr_in)) == -1) {
		OFP_ERR("Faild to connect socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	if (ofp_shutdown(fd, OFP_SHUT_RDWR) == -1) {
		OFP_ERR("Faild to shutdown socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}

int connect_shutdown_bind_udp4(int fd)
{
	struct ofp_sockaddr_in addr = {0};

	addr.sin_len = sizeof(struct ofp_sockaddr_in);
	addr.sin_family = OFP_AF_INET;
	addr.sin_port = odp_cpu_to_be_16(TEST_PORT + 1);
	addr.sin_addr.s_addr = IP4(192, 168, 100, 1);

	if (ofp_bind(fd, (const struct ofp_sockaddr *)&addr,
		sizeof(struct ofp_sockaddr_in)) == -1) {
		OFP_ERR("Faild to bind socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	addr.sin_len = sizeof(struct ofp_sockaddr_in);
	addr.sin_family = OFP_AF_INET;
	addr.sin_port = odp_cpu_to_be_16(TEST_PORT + 3);
	addr.sin_addr.s_addr = IP4(192, 168, 100, 1);

	if (ofp_connect(fd, (const struct ofp_sockaddr *)&addr,
		sizeof(struct ofp_sockaddr_in)) == -1) {
		OFP_ERR("Faild to connect socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	if (ofp_shutdown(fd, OFP_SHUT_RDWR) == -1) {
		OFP_ERR("Faild to shutdown socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}


#ifdef INET6
int connect_udp6(int fd)
{
	struct ofp_sockaddr_in6 addr = {0};

	addr.sin6_len = sizeof(struct ofp_sockaddr_in6);
	addr.sin6_family = OFP_AF_INET6;
	addr.sin6_port = odp_cpu_to_be_16(TEST_PORT + 2);
	inet_pton(AF_INET6, "fd00:1baf::1", (void *)&addr.sin6_addr);

	if (ofp_connect(fd, (const struct ofp_sockaddr *)&addr,
		sizeof(struct ofp_sockaddr_in6)) == -1) {
		OFP_ERR("Faild to connect socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}

int connect_bind_udp6(int fd)
{
	struct ofp_sockaddr_in6 addr = {0};

	addr.sin6_len = sizeof(struct ofp_sockaddr_in6);
	addr.sin6_family = OFP_AF_INET6;
	addr.sin6_port = odp_cpu_to_be_16(TEST_PORT + 1);
	inet_pton(AF_INET6, "fd00:1baf::1", (void *)&addr.sin6_addr);

	if (ofp_bind(fd, (const struct ofp_sockaddr *)&addr,
		sizeof(addr)) == -1) {
		OFP_ERR("Faild to bind socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	addr.sin6_len = sizeof(struct ofp_sockaddr_in6);
	addr.sin6_family = OFP_AF_INET6;
	addr.sin6_port = odp_cpu_to_be_16(TEST_PORT + 3);
	inet_pton(AF_INET6, "fd00:1baf::1", (void *)&addr.sin6_addr);

	if (ofp_connect(fd, (const struct ofp_sockaddr *)&addr,
		sizeof(struct ofp_sockaddr_in6)) == -1) {
		OFP_ERR("Faild to connect socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}

int connect_shutdown_udp6(int fd)
{
	struct ofp_sockaddr_in6 addr = {0};

	addr.sin6_len = sizeof(struct ofp_sockaddr_in6);
	addr.sin6_family = OFP_AF_INET6;
	addr.sin6_port = odp_cpu_to_be_16(TEST_PORT + 2);
	inet_pton(AF_INET6, "fd00:1baf::1", (void *)&addr.sin6_addr);

	if (ofp_connect(fd, (const struct ofp_sockaddr *)&addr,
		sizeof(struct ofp_sockaddr_in6)) == -1) {
		OFP_ERR("Faild to connect socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	if (ofp_shutdown(fd, OFP_SHUT_RDWR) == -1) {
		OFP_ERR("Faild to shutdown socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}

int connect_shutdown_bind_udp6(int fd)
{
	struct ofp_sockaddr_in6 addr = {0};

	addr.sin6_len = sizeof(struct ofp_sockaddr_in6);
	addr.sin6_family = OFP_AF_INET6;
	addr.sin6_port = odp_cpu_to_be_16(TEST_PORT + 1);
	inet_pton(AF_INET6, "fd00:1baf::1", (void *)&addr.sin6_addr);

	if (ofp_bind(fd, (const struct ofp_sockaddr *)&addr,
		sizeof(addr)) == -1) {
		OFP_ERR("Faild to bind socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	addr.sin6_len = sizeof(struct ofp_sockaddr_in6);
	addr.sin6_family = OFP_AF_INET6;
	addr.sin6_port = odp_cpu_to_be_16(TEST_PORT + 3);
	inet_pton(AF_INET6, "fd00:1baf::1", (void *)&addr.sin6_addr);

	if (ofp_connect(fd, (const struct ofp_sockaddr *)&addr,
		sizeof(struct ofp_sockaddr_in6)) == -1) {
		OFP_ERR("Faild to connect socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	if (ofp_shutdown(fd, OFP_SHUT_RDWR) == -1) {
		OFP_ERR("Faild to shutdown socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}

int connect_shutdown_udp6_any(int fd)
{
	struct ofp_sockaddr_in6 addr = {0};

	addr.sin6_len = sizeof(struct ofp_sockaddr_in6);
	addr.sin6_family = OFP_AF_INET6;
	addr.sin6_port = odp_cpu_to_be_16(TEST_PORT + 2);
	addr.sin6_addr = ofp_in6addr_any;

	if (ofp_connect(fd, (const struct ofp_sockaddr *)&addr,
		sizeof(struct ofp_sockaddr_in6)) == -1) {
		OFP_ERR("Faild to connect socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	if (ofp_shutdown(fd, OFP_SHUT_RDWR) == -1) {
		OFP_ERR("Faild to shutdown socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}

int connect_shutdown_bind_udp6_any(int fd)
{
	struct ofp_sockaddr_in6 addr = {0};

	addr.sin6_len = sizeof(struct ofp_sockaddr_in6);
	addr.sin6_family = OFP_AF_INET6;
	addr.sin6_port = odp_cpu_to_be_16(TEST_PORT + 1);
	addr.sin6_addr = ofp_in6addr_any;

	if (ofp_bind(fd, (const struct ofp_sockaddr *)&addr,
		sizeof(addr)) == -1) {
		OFP_ERR("Faild to bind socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	addr.sin6_len = sizeof(struct ofp_sockaddr_in6);
	addr.sin6_family = OFP_AF_INET6;
	addr.sin6_port = odp_cpu_to_be_16(TEST_PORT + 3);
	addr.sin6_addr = ofp_in6addr_any;

	if (ofp_connect(fd, (const struct ofp_sockaddr *)&addr,
		sizeof(struct ofp_sockaddr_in6)) == -1) {
		OFP_ERR("Faild to connect socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	if (ofp_shutdown(fd, OFP_SHUT_RDWR) == -1) {
		OFP_ERR("Faild to shutdown socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}
#endif /* INET6 */
