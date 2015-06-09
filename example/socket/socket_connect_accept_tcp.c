/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include "ofp.h"
#include "socket_connect_accept_tcp.h"
#include "socket_util.h"

int init_tcp_bind_listen_local_ip(int *pfd_thread1, int *pfd_thread2)
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

	if (ofp_listen(*pfd_thread2, 10) == -1) {
		OFP_ERR("Faild to listen (errno = %d)\n", ofp_errno);
		return -1;
	}

	return 0;
}

int init_tcp_bind_listen_any(int *pfd_thread1, int *pfd_thread2)
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
	addr.sin_addr.s_addr = OFP_INADDR_ANY;

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
	addr.sin_addr.s_addr = OFP_INADDR_ANY;

	if (ofp_bind(*pfd_thread2, (const struct ofp_sockaddr *)&addr,
		sizeof(struct ofp_sockaddr_in)) == -1) {
		OFP_ERR("Faild to bind socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	if (ofp_listen(*pfd_thread2, 10) == -1) {
		OFP_ERR("Faild to listen (errno = %d)\n", ofp_errno);
		return -1;
	}

	return 0;
}

#ifdef INET6
int init_tcp6_bind_listen_local_ip(int *pfd_thread1, int *pfd_thread2)
{
	struct ofp_sockaddr_in6 addr = {0};
	int optval = 1;

	*pfd_thread1 = ofp_socket(OFP_AF_INET6, OFP_SOCK_STREAM, 0);
	if (*pfd_thread1 == -1) {
		OFP_ERR("Faild to create socket 1 (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	optval = 1;
	ofp_setsockopt(*pfd_thread1, OFP_SOL_SOCKET, OFP_SO_REUSEADDR,
		&optval, sizeof(optval));
	ofp_setsockopt(*pfd_thread1, OFP_SOL_SOCKET, OFP_SO_REUSEPORT,
		&optval, sizeof(optval));

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

	optval = 1;
	ofp_setsockopt(*pfd_thread2, OFP_SOL_SOCKET, OFP_SO_REUSEADDR,
		&optval, sizeof(optval));
	ofp_setsockopt(*pfd_thread2, OFP_SOL_SOCKET, OFP_SO_REUSEPORT,
		&optval, sizeof(optval));

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

	if (ofp_listen(*pfd_thread2, 10) == -1) {
		OFP_ERR("Faild to listen (errno = %d)\n", ofp_errno);
		return -1;
	}

	return 0;
}

int init_tcp6_bind_listen_any(int *pfd_thread1, int *pfd_thread2)
{
	struct ofp_sockaddr_in6 addr = {0};
	int optval = 1;

	*pfd_thread1 = ofp_socket(OFP_AF_INET6, OFP_SOCK_STREAM, 0);
	if (*pfd_thread1 == -1) {
		OFP_ERR("Faild to create socket 1 (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	optval = 1;
	ofp_setsockopt(*pfd_thread1, OFP_SOL_SOCKET, OFP_SO_REUSEADDR,
		&optval, sizeof(optval));
	ofp_setsockopt(*pfd_thread1, OFP_SOL_SOCKET, OFP_SO_REUSEPORT,
		&optval, sizeof(optval));

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

	*pfd_thread2 = ofp_socket(OFP_AF_INET6, OFP_SOCK_STREAM, 0);
	if (*pfd_thread2 == -1) {
		OFP_ERR("Faild to create socket 2 (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	optval = 1;
	ofp_setsockopt(*pfd_thread2, OFP_SOL_SOCKET, OFP_SO_REUSEADDR,
		&optval, sizeof(optval));
	ofp_setsockopt(*pfd_thread2, OFP_SOL_SOCKET, OFP_SO_REUSEPORT,
		&optval, sizeof(optval));

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

	if (ofp_listen(*pfd_thread2, 10) == -1) {
		OFP_ERR("Faild to listen (errno = %d)\n", ofp_errno);
		return -1;
	}

	return 0;
}
#endif /* INET6 */

int connect_tcp4_local_ip(int fd)
{
	struct ofp_sockaddr_in addr = {0};

	addr.sin_len = sizeof(struct ofp_sockaddr_in);
	addr.sin_family = OFP_AF_INET;
	addr.sin_port = odp_cpu_to_be_16(TEST_PORT + 1);
	addr.sin_addr.s_addr = IP4(192, 168, 100, 1);

	if (ofp_connect(fd, (struct ofp_sockaddr *)&addr,
			sizeof(addr)) == -1) {
		OFP_ERR("Faild to connect (errno = %d)\n", ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}

int connect_tcp4_any(int fd)
{
	struct ofp_sockaddr_in addr = {0};

	addr.sin_len = sizeof(struct ofp_sockaddr_in);
	addr.sin_family = OFP_AF_INET;
	addr.sin_port = odp_cpu_to_be_16(TEST_PORT + 1);
	addr.sin_addr.s_addr = OFP_INADDR_ANY;

	if (ofp_connect(fd, (struct ofp_sockaddr *)&addr,
			sizeof(addr)) == -1) {
		OFP_ERR("Faild to connect (errno = %d)\n", ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}

int accept_tcp4(int fd)
{
	struct ofp_sockaddr_in addr = {0};
	ofp_socklen_t addr_len = sizeof(addr);
	int fd_accepted = -1;

	fd_accepted = ofp_accept(fd, (struct ofp_sockaddr *)&addr,
			&addr_len);

	if (fd_accepted == -1) {
		OFP_ERR("Faild to accept connection (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	if (addr_len != sizeof(struct ofp_sockaddr_in)) {
		OFP_ERR("Faild to accept: invalid address size %d\n",
			addr_len);
		return -1;
	}

	OFP_INFO("Address: 0x%x, port: %d.\n",
		odp_be_to_cpu_32(addr.sin_addr.s_addr),
		odp_be_to_cpu_16(addr.sin_port));

	if (ofp_close(fd_accepted) == -1) {
		OFP_ERR("Faild to close accepted socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}

int accept_tcp4_null_addr(int fd)
{
	int fd_accepted;

	fd_accepted = ofp_accept(fd, NULL, NULL);

	if (fd_accepted == -1) {
		OFP_ERR("Faild to accept connection (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	if (ofp_close(fd_accepted) == -1) {
		OFP_ERR("Faild to close accepted socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}


#ifdef INET6
int connect_tcp6_local_ip(int fd)
{
	struct ofp_sockaddr_in6 addr = {0};

	addr.sin6_len = sizeof(struct ofp_sockaddr_in6);
	addr.sin6_family = OFP_AF_INET6;
	addr.sin6_port = odp_cpu_to_be_16(TEST_PORT + 1);
	inet_pton(AF_INET6, "fd00:1baf::1", (void *)&addr.sin6_addr);

	if (ofp_connect(fd, (struct ofp_sockaddr *)&addr,
			sizeof(addr)) == -1) {
		OFP_ERR("Faild to connect (errno = %d)\n", ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}

int connect_tcp6_any(int fd)
{
	struct ofp_sockaddr_in6 addr = {0};

	addr.sin6_len = sizeof(struct ofp_sockaddr_in6);
	addr.sin6_family = OFP_AF_INET6;
	addr.sin6_port = odp_cpu_to_be_16(TEST_PORT + 1);
	addr.sin6_addr = ofp_in6addr_any;

	if (ofp_connect(fd, (struct ofp_sockaddr *)&addr,
			sizeof(addr)) == -1) {
		OFP_ERR("Faild to connect (errno = %d)\n", ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}

int accept_tcp6(int fd)
{
	struct ofp_sockaddr_in6 addr = {0};
	ofp_socklen_t addr_len = sizeof(addr);
	int fd_accepted = -1;

	fd_accepted = ofp_accept(fd, (struct ofp_sockaddr *)&addr,
				&addr_len);
	if (fd_accepted == -1) {
		OFP_ERR("Faild to accept connection (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	if (addr_len != sizeof(struct ofp_sockaddr_in6)) {
		OFP_ERR("Faild to accept: invalid address size %d\n",
			addr_len);
		return -1;
	}

	OFP_INFO("Address: %x:%x:%x:%x, port: %d.\n",
		odp_be_to_cpu_32(addr.sin6_addr.ofp_s6_addr32[0]),
		odp_be_to_cpu_32(addr.sin6_addr.ofp_s6_addr32[1]),
		odp_be_to_cpu_32(addr.sin6_addr.ofp_s6_addr32[2]),
		odp_be_to_cpu_32(addr.sin6_addr.ofp_s6_addr32[3]),
		odp_be_to_cpu_16(addr.sin6_port));

	if (ofp_close(fd_accepted) == -1) {
		OFP_ERR("Faild to close accepted socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}

int accept_tcp6_null_addr(int fd)
{
	int fd_accepted = -1;

	fd_accepted = ofp_accept(fd, NULL, NULL);
	if (fd_accepted == -1) {
		OFP_ERR("Faild to accept connection (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	if (ofp_close(fd_accepted) == -1) {
		OFP_ERR("Faild to close accepted socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}
#endif /* INET6 */

