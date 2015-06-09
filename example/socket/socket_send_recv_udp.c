/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include "ofp.h"
#include "socket_send_recv_udp.h"
#include "socket_util.h"

int init_udp_local_ip(int *pfd_thread1, int *pfd_thread2)
{
	struct ofp_sockaddr_in addr = {0};


	*pfd_thread1 = ofp_socket(OFP_AF_INET, OFP_SOCK_DGRAM,
				OFP_IPPROTO_UDP);
	if (*pfd_thread1 == -1) {
		OFP_ERR("Faild to create SEND socket (errno = %d)\n",
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

int init_udp_any(int *pfd_thread1, int *pfd_thread2)
{
	struct ofp_sockaddr_in addr = {0};


	*pfd_thread1 = ofp_socket(OFP_AF_INET, OFP_SOCK_DGRAM,
			OFP_IPPROTO_UDP);
	if (*pfd_thread1 == -1) {
		OFP_ERR("Faild to create SEND socket (errno = %d)\n",
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

int send_udp_local_ip(int fd)
{
	const char *buf = "socket_test";
	struct ofp_sockaddr_in dest_addr = {0};

	dest_addr.sin_len = sizeof(struct ofp_sockaddr_in);
	dest_addr.sin_family = OFP_AF_INET;
	dest_addr.sin_port = odp_cpu_to_be_16(TEST_PORT + 1);
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

int recv_udp(int fd)
{
	char buf[20];
	int len = sizeof(buf);

	len = ofp_recv(fd, buf, len, 0);
	if (len == -1) {
		OFP_ERR("Faild to rcv data(errno = %d)\n", ofp_errno);
		return -1;
	}

	buf[len] = 0;
	OFP_INFO("Data (%s, len = %d) was received.\n", buf, len);

	OFP_INFO("SUCCESS.\n");
	return 0;
}

int send_udp_any(int fd)
{
	const char *buf = "socket_test";
	struct ofp_sockaddr_in dest_addr = {0};

	dest_addr.sin_len = sizeof(struct ofp_sockaddr_in);
	dest_addr.sin_family = OFP_AF_INET;
	dest_addr.sin_port = odp_cpu_to_be_16(TEST_PORT + 1);
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

int recvfrom_udp(int fd)
{
	char buf[20];
	int len = sizeof(buf);
	struct ofp_sockaddr_in addr = {0};
	ofp_socklen_t addr_len = 0;

	len = ofp_recvfrom(fd, buf, len, 0,
			(struct ofp_sockaddr *)&addr, &addr_len);
	if (len == -1) {
		OFP_ERR("Faild to rcv data(errno = %d)\n", ofp_errno);
		return -1;
	}

	buf[len] = 0;
	OFP_INFO("Data (%s, len = %d) was received.\n", buf, len);

	if (addr_len != sizeof(addr)) {
		OFP_ERR("Faild to rcv source address: %d (errno = %d)\n",
			addr_len, ofp_errno);
		return -1;
	}

	OFP_INFO("Data was received on address 0x%x, port = %d.\n",
		odp_be_to_cpu_32(addr.sin_addr.s_addr),
		odp_be_to_cpu_16(addr.sin_port));
	OFP_INFO("SUCCESS.\n");
	return 0;
}

int recvfrom_udp_null_addr(int fd)
{
	char buf[20];
	int len = sizeof(buf);

	len = ofp_recvfrom(fd, buf, len, 0, NULL, NULL);
	if (len == -1) {
		OFP_ERR("Faild to rcv data(errno = %d)\n", ofp_errno);
		return -1;
	}

	buf[len] = 0;
	OFP_INFO("Data (%s, len = %d) was received.\n", buf, len);

	OFP_INFO("SUCCESS.\n");
	return 0;
}

#ifdef INET6
int send_udp6_local_ip(int fd)
{
	struct ofp_sockaddr_in6 dest_addr = {0};
	const char *buf = "socket_snd2";

	dest_addr.sin6_len = sizeof(struct ofp_sockaddr_in6);
	dest_addr.sin6_family = OFP_AF_INET6;
	dest_addr.sin6_port = odp_cpu_to_be_16(TEST_PORT + 1);
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

int send_udp6_any(int fd)
{
	struct ofp_sockaddr_in6 dest_addr = {0};
	const char *buf = "socket_test";

	dest_addr.sin6_len = sizeof(struct ofp_sockaddr_in6);
	dest_addr.sin6_family = OFP_AF_INET6;
	dest_addr.sin6_port = odp_cpu_to_be_16(TEST_PORT + 1);
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

int recvfrom_udp6(int fd)
{
	char buf[20];
	int len = sizeof(buf);
	struct ofp_sockaddr_in6 addr = {0};
	ofp_socklen_t addr_len = 0;

	len = ofp_recvfrom(fd, buf, len, 0,
			(struct ofp_sockaddr *)&addr, &addr_len);
	if (len == -1) {
		OFP_ERR("Faild to rcv data(errno = %d)\n", ofp_errno);
		return -1;
	}

	buf[len] = 0;
	OFP_INFO("Data (%s, len = %d) was received.\n", buf, len);

	if (addr_len != sizeof(addr)) {
		OFP_ERR("Faild to rcv source address: %d (errno = %d)\n",
			addr_len, ofp_errno);
		return -1;
	}

	OFP_INFO("Data was received on address %x:%x:%x:%x, port = %d.\n",
		odp_be_to_cpu_32(addr.sin6_addr.ofp_s6_addr32[0]),
		odp_be_to_cpu_32(addr.sin6_addr.ofp_s6_addr32[1]),
		odp_be_to_cpu_32(addr.sin6_addr.ofp_s6_addr32[2]),
		odp_be_to_cpu_32(addr.sin6_addr.ofp_s6_addr32[3]),
		odp_be_to_cpu_16(addr.sin6_port));
	OFP_INFO("SUCCESS.\n");
	return 0;
}
#endif /*INET6*/
