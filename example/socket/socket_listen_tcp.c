/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include "ofp.h"
#include "socket_listen_tcp.h"
#include "socket_util.h"

int init_tcp_bind_local_ip(int *pfd_thread1, int *pfd_thread2)
{
	struct ofp_sockaddr_in addr = {0};
	int optval = 1;

	*pfd_thread1 = ofp_socket(OFP_AF_INET, OFP_SOCK_STREAM,
				OFP_IPPROTO_TCP);
	if (*pfd_thread1 == -1) {
		OFP_ERR("Faild to create SEND socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	optval = 1;
	ofp_setsockopt(*pfd_thread1, OFP_SOL_SOCKET, OFP_SO_REUSEADDR,
		&optval, sizeof(optval));
	ofp_setsockopt(*pfd_thread1, OFP_SOL_SOCKET, OFP_SO_REUSEPORT,
		&optval, sizeof(optval));

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

	*pfd_thread2 = ofp_socket(OFP_AF_INET, OFP_SOCK_STREAM,
				OFP_IPPROTO_TCP);
	if (*pfd_thread2 == -1) {
		OFP_ERR("Faild to create RCV socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	optval = 1;
	ofp_setsockopt(*pfd_thread2, OFP_SOL_SOCKET, OFP_SO_REUSEADDR,
		&optval, sizeof(optval));
	ofp_setsockopt(*pfd_thread2, OFP_SOL_SOCKET, OFP_SO_REUSEPORT,
		&optval, sizeof(optval));

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

#ifdef INET6
int init_tcp6_bind_local_ip(int *pfd_thread1, int *pfd_thread2)
{
	struct ofp_sockaddr_in6 addr = {0};

	*pfd_thread1 = ofp_socket(OFP_AF_INET6, OFP_SOCK_STREAM, 0);
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

	*pfd_thread2 = ofp_socket(OFP_AF_INET6, OFP_SOCK_STREAM, 0);
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
#endif /* INET6 */

int listen_tcp(int fd)
{
	if (ofp_listen(fd, 10) == -1) {
		OFP_ERR("Faild to listen (errno = %d)\n", ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}
