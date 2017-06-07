/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include "ofp.h"
#include "socket_sigevent.h"
#include "socket_util.h"

int recv_send_udp_local_ip(int fd)
{
	char buf[20];
	int len = sizeof(buf);
	struct ofp_sockaddr_in dest_addr = {0};

	len = ofp_recv(fd, buf, len, 0);
	if (len == -1) {
		OFP_ERR("Faild to rcv data(errno = %d)\n", ofp_errno);
		return -1;
	}

	buf[len] = 0;
	OFP_INFO("Data (%s, len = %d) was received.\n", buf, len);

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

static void notify_udp_ipv4(union ofp_sigval sv);
int socket_sigevent_udp4(int fd)
{
	struct ofp_sigevent ev;
	struct ofp_sock_sigval ss;
	struct ofp_sockaddr_in dest_addr = {0};
	const char *buf = "sigevent_test";

	ss.sockfd = fd;
	ss.event = OFP_EVENT_INVALID;
	ss.pkt = ODP_PACKET_INVALID;

	ev.ofp_sigev_notify = OFP_SIGEV_HOOK;
	ev.ofp_sigev_notify_function = notify_udp_ipv4;
	ev.ofp_sigev_value.sival_ptr = &ss;
	ofp_socket_sigevent(&ev);

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
	sleep(2);
	return 0;
}

static void notify_udp_ipv4(union ofp_sigval sv)
{
	struct ofp_sockaddr_in addr = {0};
	ofp_socklen_t addr_len = sizeof(addr);
	int data_len = 0;
	uint8_t *data = NULL;
	struct ofp_sock_sigval *ss;
	int i;

	ss = (struct ofp_sock_sigval *)sv.sival_ptr;

	data = ofp_udp_packet_parse(ss->pkt, &data_len,
		(struct ofp_sockaddr *)&addr,
		&addr_len);

	OFP_INFO("UDP data received: size %d, data: ", data_len);

	for (i = 0; i < data_len; i++)
		OFP_LOG_NO_CTX(OFP_LOG_INFO, "%c", data[i]);

	OFP_LOG_NO_CTX(OFP_LOG_INFO, "\n");

	if (addr_len != sizeof(addr)) {
		OFP_ERR("Faild to rcv source address: %d (errno = %d)\n",
			addr_len, ofp_errno);
		return;
	}

	OFP_INFO("Data was received from address 0x%x, port = %d.\n",
		odp_be_to_cpu_32(addr.sin_addr.s_addr),
		odp_be_to_cpu_16(addr.sin_port));
	/*
	 * Mark ss->pkt invalid to indicate it was released or reused by us.
	 */
	odp_packet_free(ss->pkt);
	ss->pkt = ODP_PACKET_INVALID;
	OFP_INFO("SUCCESS.\n");
}

#ifdef INET6
int recv_send_udp6_local_ip(int fd)
{
	char buf[20];
	int len = sizeof(buf);
	struct ofp_sockaddr_in6 dest_addr = {0};

	len = ofp_recv(fd, buf, len, 0);
	if (len == -1) {
		OFP_ERR("Faild to rcv data(errno = %d)\n", ofp_errno);
		return -1;
	}

	buf[len] = 0;
	OFP_INFO("Data (%s, len = %d) was received.\n", buf, len);

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

static void notify_udp_ipv6(union ofp_sigval sv);
int socket_sigevent_udp6(int fd)
{
	struct ofp_sigevent ev;
	struct ofp_sock_sigval ss;
	struct ofp_sockaddr_in6 dest_addr = {0};
	const char *buf = "sigevent_test";

	ss.sockfd = fd;
	ss.event = OFP_EVENT_INVALID;
	ss.pkt = ODP_PACKET_INVALID;

	ev.ofp_sigev_notify = OFP_SIGEV_HOOK;
	ev.ofp_sigev_notify_function = notify_udp_ipv6;
	ev.ofp_sigev_value.sival_ptr = &ss;
	ofp_socket_sigevent(&ev);

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

	sleep(2);
	return 0;
}

static void notify_udp_ipv6(union ofp_sigval sv)
{
	struct ofp_sockaddr_in6 addr = {0};
	ofp_socklen_t addr_len = sizeof(addr);
	int data_len = 0;
	uint8_t *data = NULL;
	struct ofp_sock_sigval *ss;
	int i;

	ss = (struct ofp_sock_sigval *)sv.sival_ptr;

	data = ofp_udp_packet_parse(ss->pkt, &data_len,
		(struct ofp_sockaddr *)&addr,
		&addr_len);

	OFP_INFO("UDP data received: size %d, data: ", data_len);

	for (i = 0; i < data_len; i++)
		OFP_LOG_NO_CTX(OFP_LOG_INFO, "%c", data[i]);

	OFP_LOG_NO_CTX(OFP_LOG_INFO, "\n");

	if (addr_len != sizeof(addr)) {
		OFP_ERR("Faild to rcv source address: %d (errno = %d)\n",
			addr_len, ofp_errno);
		return;
	}

	OFP_INFO("Address: %x:%x:%x:%x, port: %d.\n",
		odp_be_to_cpu_32(addr.sin6_addr.ofp_s6_addr32[0]),
		odp_be_to_cpu_32(addr.sin6_addr.ofp_s6_addr32[1]),
		odp_be_to_cpu_32(addr.sin6_addr.ofp_s6_addr32[2]),
		odp_be_to_cpu_32(addr.sin6_addr.ofp_s6_addr32[3]),
		odp_be_to_cpu_16(addr.sin6_port));
	/*
	 * Mark ss->pkt invalid to indicate it was released or reused by us.
	 */
	ss->pkt = ODP_PACKET_INVALID;
	OFP_INFO("SUCCESS.\n");
}
#endif /* INET6 */

int connect_recv_send_tcp_local_ip(int fd)
{
	struct ofp_sockaddr_in addr = {0};
	char buf[20];
	int len = sizeof(buf);

	addr.sin_len = sizeof(struct ofp_sockaddr_in);
	addr.sin_family = OFP_AF_INET;
	addr.sin_port = odp_cpu_to_be_16(TEST_PORT + 1);
	addr.sin_addr.s_addr = IP4(192, 168, 100, 1);

	if ((ofp_connect(fd, (struct ofp_sockaddr *)&addr,
			sizeof(addr)) == -1) &&
		(ofp_errno != OFP_EINPROGRESS)) {
		OFP_ERR("Faild to connect (errno = %d)\n", ofp_errno);
		return -1;
	}

	len = ofp_recv(fd, buf, len, 0);
	if (len == -1) {
		OFP_ERR("Faild to rcv data(errno = %d)\n", ofp_errno);
		return -1;
	}

	len = ofp_send(fd, buf, len, 0);
	if (len == -1) {
		OFP_ERR("Faild to send data. (errno = %d)\n", ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}

#ifdef INET6
int connect_recv_send_tcp6_local_ip(int fd)
{
	struct ofp_sockaddr_in6 addr = {0};
	char buf[20];
	int len = sizeof(buf);

	addr.sin6_len = sizeof(struct ofp_sockaddr_in6);
	addr.sin6_family = OFP_AF_INET6;
	addr.sin6_port = odp_cpu_to_be_16(TEST_PORT + 1);
	inet_pton(AF_INET6, "fd00:1baf::1", (void *)&addr.sin6_addr);

	if ((ofp_connect(fd, (struct ofp_sockaddr *)&addr,
			sizeof(addr)) == -1) &&
		(ofp_errno != OFP_EINPROGRESS)) {
		OFP_ERR("Faild to connect (errno = %d)\n", ofp_errno);
		return -1;
	}

	len = ofp_recv(fd, buf, len, 0);
	if (len == -1) {
		OFP_ERR("Faild to rcv data(errno = %d)\n", ofp_errno);
		return -1;
	}

	len = ofp_send(fd, buf, len, 0);
	if (len == -1) {
		OFP_ERR("Faild to send data. (errno = %d)\n", ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}
#endif /*INET6*/

static void notify_tcp_rcv(union ofp_sigval sv);
int socket_sigevent_tcp_rcv(int fd)
{
	struct ofp_sigevent ev;
	struct ofp_sock_sigval ss;
	const char *buf = "socket_test";
	int len = 0;
	int fd_accept = -1;

	fd_accept = ofp_accept(fd, NULL, NULL);
	if (fd == -1) {
		OFP_ERR("Faild to accept connection (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	ss.sockfd = fd_accept;
	ss.event = OFP_EVENT_INVALID;
	ss.pkt = ODP_PACKET_INVALID;

	ev.ofp_sigev_notify = OFP_SIGEV_HOOK;
	ev.ofp_sigev_notify_function = notify_tcp_rcv;
	ev.ofp_sigev_value.sival_ptr = &ss;
	if (ofp_socket_sigevent(&ev) == -1) {
		OFP_ERR("Faild to set sigevent(errno = %d)\n", ofp_errno);
		return -1;
	}

	len = ofp_send(fd_accept, buf, strlen(buf) + 1, 0);
	if (len == -1) {
		OFP_ERR("Faild to send data. (errno = %d)\n", ofp_errno);
		return -1;
	}
	sleep(3);
	ofp_close(fd_accept);
	OFP_INFO("Socket sigevent set.\n");
	return 0;
}

static void notify_tcp_rcv(union ofp_sigval sv)
{
	struct ofp_sock_sigval *ss;
	uint8_t *data = NULL;
	int data_len = 0;
	int i;

	ss = (struct ofp_sock_sigval *)sv.sival_ptr;
	data = odp_packet_data(ss->pkt);
	data_len = odp_packet_len(ss->pkt);

	OFP_INFO("TCP data received: size %d, data: ", data_len);

	for (i = 0; i < data_len; i++)
		OFP_LOG_NO_CTX(OFP_LOG_INFO, "%c", data[i]);

	OFP_LOG_NO_CTX(OFP_LOG_INFO, "\n");

	OFP_INFO("SUCCESS.\n");
}

int connect_tcp_delayed_local_ip(int fd)
{
	struct ofp_sockaddr_in addr = {0};

	sleep(1); /*Let the other side to init.*/

	addr.sin_len = sizeof(struct ofp_sockaddr_in);
	addr.sin_family = OFP_AF_INET;
	addr.sin_port = odp_cpu_to_be_16(TEST_PORT + 1);
	addr.sin_addr.s_addr = IP4(192, 168, 100, 1);

	if ((ofp_connect(fd, (struct ofp_sockaddr *)&addr,
			sizeof(addr)) == -1) &&
		(ofp_errno != OFP_EINPROGRESS)) {
		OFP_ERR("Faild to connect (errno = %d)\n", ofp_errno);
		return -1;
	}

	sleep(1); /* ToFix: connect is not blocking*/

	OFP_INFO("SUCCESS.\n");
	return 0;
}

#ifdef INET6
int connect_tcp6_delayed_local_ip(int fd)
{
	struct ofp_sockaddr_in6 addr = {0};

	sleep(1); /*Let the other side to init.*/

	addr.sin6_len = sizeof(struct ofp_sockaddr_in6);
	addr.sin6_family = OFP_AF_INET6;
	addr.sin6_port = odp_cpu_to_be_16(TEST_PORT + 1);
	inet_pton(AF_INET6, "fd00:1baf::1", (void *)&addr.sin6_addr);

	if ((ofp_connect(fd, (struct ofp_sockaddr *)&addr,
			sizeof(addr)) == -1) &&
		(ofp_errno != OFP_EINPROGRESS)) {
		OFP_ERR("Faild to connect (errno = %d)\n", ofp_errno);
		return -1;
	}

	sleep(1); /* ToFix: connect is not blocking*/

	OFP_INFO("SUCCESS.\n");
	return 0;
}
#endif /* INET6 */

static void notify_tcp_accept(union ofp_sigval sv);
int socket_sigevent_tcp_accept(int fd)
{
	struct ofp_sigevent ev;
	struct ofp_sock_sigval ss;
	int fd_accept = -1;

	ss.sockfd = fd;
	ss.event = OFP_EVENT_INVALID;
	ss.pkt = ODP_PACKET_INVALID;

	ev.ofp_sigev_notify = OFP_SIGEV_HOOK;
	ev.ofp_sigev_notify_function = notify_tcp_accept;
	ev.ofp_sigev_value.sival_ptr = &ss;
	if (ofp_socket_sigevent(&ev) == -1) {
		OFP_ERR("Faild to set sigevent(errno = %d)\n", ofp_errno);
		return -1;
	}
	OFP_INFO("Socket sigevent set.\n");

	fd_accept = ofp_accept(fd, NULL, NULL);
	if (fd_accept == -1) {
		OFP_ERR("Faild to accept connection (errno = %d)\n",
			ofp_errno);
		return -1;
	}
	if (ofp_close(fd_accept) == -1) {
		OFP_ERR("Faild to close connection (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	return 0;
}

static void notify_tcp_accept(union ofp_sigval sv)
{
	struct ofp_sock_sigval *ss;

	ss = (struct ofp_sock_sigval *)sv.sival_ptr;
	OFP_INFO("TCP Connection received on socket %d: %d created.\n",
		ss->sockfd,
		ss->sockfd2);

	OFP_INFO("SUCCESS.\n");
}

