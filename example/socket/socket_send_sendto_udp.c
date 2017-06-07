/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include "ofp.h"
#include "socket_send_sendto_udp.h"
#include "socket_util.h"

int init_udp_bind_local_ip(int *pfd_thread1, int *pfd_thread2)
{
	struct ofp_sockaddr_in addr = {0};

	*pfd_thread1 = ofp_socket(OFP_AF_INET, OFP_SOCK_DGRAM,
				OFP_IPPROTO_UDP);
	if (*pfd_thread1 == -1) {
		OFP_ERR("Faild to create SEND socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	addr.sin_len = sizeof(struct ofp_sockaddr_in);
	addr.sin_family = OFP_AF_INET;
	addr.sin_port = odp_cpu_to_be_16(TEST_PORT);
	addr.sin_addr.s_addr = IP4(192, 168, 100, 1);

	if (ofp_bind(*pfd_thread1, (const struct ofp_sockaddr *)&addr,
		sizeof(struct ofp_sockaddr_in)) == -1) {
		OFP_ERR("Faild to bind socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	*pfd_thread2 = ofp_socket(OFP_AF_INET, OFP_SOCK_DGRAM,
				OFP_IPPROTO_UDP);
	if (*pfd_thread2 == -1) {
		OFP_ERR("Faild to create RCV socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	addr.sin_len = sizeof(struct ofp_sockaddr_in);
	addr.sin_family = OFP_AF_INET;
	addr.sin_port = odp_cpu_to_be_16(TEST_PORT + 1);
	addr.sin_addr.s_addr = IP4(192, 168, 100, 1);

	if (ofp_bind(*pfd_thread2, (const struct ofp_sockaddr *)&addr,
		sizeof(struct ofp_sockaddr_in)) == -1) {
		OFP_ERR("Faild to bind socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	return 0;
}
int init_udp_bind_any(int *pfd_thread1, int *pfd_thread2)
{
	struct ofp_sockaddr_in addr = {0};


	*pfd_thread1 = ofp_socket(OFP_AF_INET, OFP_SOCK_DGRAM,
			OFP_IPPROTO_UDP);
	if (*pfd_thread1 == -1) {
		OFP_ERR("Faild to create SEND socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	addr.sin_len = sizeof(struct ofp_sockaddr_in);
	addr.sin_family = OFP_AF_INET;
	addr.sin_port = odp_cpu_to_be_16(TEST_PORT);
	addr.sin_addr.s_addr = OFP_INADDR_ANY;

	if (ofp_bind(*pfd_thread1, (const struct ofp_sockaddr *)&addr,
		sizeof(struct ofp_sockaddr_in)) == -1) {
		OFP_ERR("Faild to bind socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	*pfd_thread2 = ofp_socket(OFP_AF_INET, OFP_SOCK_DGRAM,
			OFP_IPPROTO_UDP);
	if (*pfd_thread2 == -1) {
		OFP_ERR("Faild to create RCV socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	addr.sin_len = sizeof(struct ofp_sockaddr_in);
	addr.sin_family = OFP_AF_INET;
	addr.sin_port = odp_cpu_to_be_16(TEST_PORT + 1);
	addr.sin_addr.s_addr = OFP_INADDR_ANY;

	if (ofp_bind(*pfd_thread2, (const struct ofp_sockaddr *)&addr,
		sizeof(struct ofp_sockaddr_in)) == -1) {
		OFP_ERR("Faild to bind socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	return 0;
}

#ifdef INET6
int init_udp6_bind_local_ip(int *pfd_thread1, int *pfd_thread2)
{
	struct ofp_sockaddr_in6 addr = {0};

	*pfd_thread1 = ofp_socket(OFP_AF_INET6, OFP_SOCK_DGRAM, 0);
	if (*pfd_thread1 == -1) {
		OFP_ERR("Faild to create socket 1 (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	addr.sin6_len = sizeof(struct ofp_sockaddr_in6);
	addr.sin6_family = OFP_AF_INET6;
	addr.sin6_port = odp_cpu_to_be_16(TEST_PORT);
	inet_pton(AF_INET6, "fd00:1baf::1", (void *)&addr.sin6_addr);

	if (ofp_bind(*pfd_thread1, (const struct ofp_sockaddr *)&addr,
		sizeof(addr)) == -1) {
		OFP_ERR("Faild to bind socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	*pfd_thread2 = ofp_socket(OFP_AF_INET6, OFP_SOCK_DGRAM, 0);
	if (*pfd_thread2 == -1) {
		OFP_ERR("Faild to create socket 2 (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	addr.sin6_len = sizeof(struct ofp_sockaddr_in6);
	addr.sin6_family = OFP_AF_INET6;
	addr.sin6_port = odp_cpu_to_be_16(TEST_PORT + 1);
	inet_pton(AF_INET6, "fd00:1baf::1", (void *)&addr.sin6_addr);

	if (ofp_bind(*pfd_thread2, (const struct ofp_sockaddr *)&addr,
		sizeof(addr)) == -1) {
		OFP_ERR("Faild to bind socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	return 0;
}

int init_udp6_bind_any(int *pfd_thread1, int *pfd_thread2)
{
	struct ofp_sockaddr_in6 addr = {0};

	*pfd_thread1 = ofp_socket(OFP_AF_INET6, OFP_SOCK_DGRAM, 0);
	if (*pfd_thread1 == -1) {
		OFP_ERR("Faild to create socket 1 (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	addr.sin6_len = sizeof(struct ofp_sockaddr_in6);
	addr.sin6_family = OFP_AF_INET6;
	addr.sin6_port = odp_cpu_to_be_16(TEST_PORT);
	addr.sin6_addr = ofp_in6addr_any;

	if (ofp_bind(*pfd_thread1, (const struct ofp_sockaddr *)&addr,
		sizeof(addr)) == -1) {
		OFP_ERR("Faild to bind socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	*pfd_thread2 = ofp_socket(OFP_AF_INET6, OFP_SOCK_DGRAM, 0);
	if (*pfd_thread2 == -1) {
		OFP_ERR("Faild to create socket 2 (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	addr.sin6_len = sizeof(struct ofp_sockaddr_in6);
	addr.sin6_family = OFP_AF_INET6;
	addr.sin6_port = odp_cpu_to_be_16(TEST_PORT + 1);
	addr.sin6_addr = ofp_in6addr_any;

	if (ofp_bind(*pfd_thread2, (const struct ofp_sockaddr *)&addr,
		sizeof(addr)) == -1) {
		OFP_ERR("Faild to bind socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	return 0;
}
#endif /* INET6 */

int send_ip4_udp_local_ip(int fd)
{
	struct ofp_sockaddr_in addr = {0};
	const char *buf = "socket_test";

	addr.sin_len = sizeof(struct ofp_sockaddr_in);
	addr.sin_family = OFP_AF_INET;
	addr.sin_port = odp_cpu_to_be_16(TEST_PORT + 1);
	addr.sin_addr.s_addr = IP4(192, 168, 100, 1);

	if ((ofp_connect(fd, (const struct ofp_sockaddr *)&addr,
		sizeof(struct ofp_sockaddr_in)) == -1) &&
		(ofp_errno != OFP_EINPROGRESS)) {
		OFP_ERR("Faild to connect socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	if (ofp_send(fd, buf, strlen(buf), 0) == -1) {
		OFP_ERR("Faild to send data(errno = %d)\n", ofp_errno);
		return -1;
	}
	OFP_INFO("Data (%s) sent successfully.\n", buf);

	OFP_INFO("SUCCESS.\n");
	return 0;
}
int sendto_ip4_udp_local_ip(int fd)
{
	struct ofp_sockaddr_in dest_addr = {0};
	const char *buf = "socket_test";

	dest_addr.sin_len = sizeof(struct ofp_sockaddr_in);
	dest_addr.sin_family = OFP_AF_INET;
	dest_addr.sin_port = odp_cpu_to_be_16(TEST_PORT);
	dest_addr.sin_addr.s_addr = IP4(192, 168, 100, 1);

	if (ofp_sendto(fd, buf, strlen(buf), 0,
		(struct ofp_sockaddr *)&dest_addr,
		sizeof(dest_addr)) == -1) {
		OFP_ERR("Faild to send data(errno = %d)\n", ofp_errno);
		return -1;
	}
	OFP_INFO("Data (%s) sent successfully.\n", buf);

	OFP_INFO("SUCCESS.\n");
	return 0;
}

int send_ip4_udp_any(int fd)
{
	struct ofp_sockaddr_in addr = {0};
	const char *buf = "socket_test";

	addr.sin_len = sizeof(struct ofp_sockaddr_in);
	addr.sin_family = OFP_AF_INET;
	addr.sin_port = odp_cpu_to_be_16(TEST_PORT + 1);
	addr.sin_addr.s_addr = OFP_INADDR_ANY;

	if ((ofp_connect(fd, (const struct ofp_sockaddr *)&addr,
		sizeof(struct ofp_sockaddr_in)) == -1) &&
		(ofp_errno != OFP_EINPROGRESS)) {
		OFP_ERR("Faild to connect socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	if (ofp_send(fd, buf, strlen(buf), 0) == -1) {
		OFP_ERR("Faild to send data(errno = %d)\n", ofp_errno);
		return -1;
	}

	OFP_INFO("Data (%s) sent successfully.\n", buf);

	OFP_INFO("SUCCESS.\n");
	return 0;
}
int sendto_ip4_udp_any(int fd)
{
	struct ofp_sockaddr_in dest_addr = {0};
	const char *buf = "socket_test";

	dest_addr.sin_len = sizeof(struct ofp_sockaddr_in);
	dest_addr.sin_family = OFP_AF_INET;
	dest_addr.sin_port = odp_cpu_to_be_16(TEST_PORT);
	dest_addr.sin_addr.s_addr = OFP_INADDR_ANY;

	if (ofp_sendto(fd, buf, strlen(buf), 0,
		(struct ofp_sockaddr *)&dest_addr,
		sizeof(dest_addr)) == -1) {
		OFP_ERR("Faild to send data(errno = %d)\n", ofp_errno);
		return -1;
	}

	OFP_INFO("Data (%s) sent successfully.\n", buf);

	OFP_INFO("SUCCESS.\n");
	return 0;
}

#ifdef INET6
int send_ip6_udp_local_ip(int fd)
{
	struct ofp_sockaddr_in6 addr = {0};
	const char *buf = "socket_test";

	addr.sin6_len = sizeof(struct ofp_sockaddr_in6);
	addr.sin6_family = OFP_AF_INET6;
	addr.sin6_port = odp_cpu_to_be_16(TEST_PORT + 1);
	inet_pton(AF_INET6, "fd00:1baf::1", (void *)&addr.sin6_addr);

	if ((ofp_connect(fd, (const struct ofp_sockaddr *)&addr,
		sizeof(struct ofp_sockaddr_in6)) == -1) &&
		(ofp_errno != OFP_EINPROGRESS)) {
		OFP_ERR("Faild to connect socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}
	if (ofp_send(fd, buf, strlen(buf), 0) == -1) {
		OFP_ERR("Faild to send data(errno = %d)\n", ofp_errno);
		return -1;
	}

	OFP_INFO("Data (%s) sent successfully.\n", buf);

	OFP_INFO("SUCCESS.\n");
	return 0;
}
int sendto_ip6_udp_local_ip(int fd)
{
	struct ofp_sockaddr_in6 dest_addr = {0};
	const char *buf = "socket_snd2";

	dest_addr.sin6_len = sizeof(struct ofp_sockaddr_in6);
	dest_addr.sin6_family = OFP_AF_INET6;
	dest_addr.sin6_port = odp_cpu_to_be_16(TEST_PORT);
	inet_pton(AF_INET6, "fd00:1baf::1", (void *)&dest_addr.sin6_addr);

	if (ofp_sendto(fd, buf, strlen(buf), 0,
		(struct ofp_sockaddr *)&dest_addr,
		sizeof(dest_addr)) == -1) {
		OFP_ERR("Faild to send data(errno = %d)\n", ofp_errno);
		return -1;
	}

	OFP_INFO("Data (%s) sent successfully.\n", buf);

	OFP_INFO("SUCCESS.\n");
	return 0;
}

int send_ip6_udp_any(int fd)
{
	struct ofp_sockaddr_in6 addr = {0};
	const char *buf = "socket_test";

	addr.sin6_len = sizeof(struct ofp_sockaddr_in6);
	addr.sin6_family = OFP_AF_INET6;
	addr.sin6_port = odp_cpu_to_be_16(TEST_PORT + 1);
	addr.sin6_addr = ofp_in6addr_any;

	if ((ofp_connect(fd, (const struct ofp_sockaddr *)&addr,
		sizeof(struct ofp_sockaddr_in6)) == -1) &&
		(ofp_errno != OFP_EINPROGRESS)) {
		OFP_ERR("Faild to connect socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	if (ofp_send(fd, buf, strlen(buf), 0) == -1) {
		OFP_ERR("Faild to send data(errno = %d)\n", ofp_errno);
		return -1;
	}

	OFP_INFO("Data (%s) sent successfully.\n", buf);

	OFP_INFO("SUCCESS.\n");
	return 0;
}

int sendto_ip6_udp_any(int fd)
{
	struct ofp_sockaddr_in6 dest_addr = {0};
	const char *buf = "socket_test";

	dest_addr.sin6_len = sizeof(struct ofp_sockaddr_in6);
	dest_addr.sin6_family = OFP_AF_INET6;
	dest_addr.sin6_port = odp_cpu_to_be_16(TEST_PORT);
	dest_addr.sin6_addr = ofp_in6addr_any;

	if (ofp_sendto(fd, buf, strlen(buf), 0,
		(struct ofp_sockaddr *)&dest_addr,
		sizeof(dest_addr)) == -1) {
		OFP_ERR("Faild to send data(errno = %d)\n", ofp_errno);
		return -1;
	}

	OFP_INFO("Data (%s) sent successfully.\n", buf);

	OFP_INFO("SUCCESS.\n");
	return 0;
}
#endif /* INET6 */
