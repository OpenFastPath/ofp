/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include "ofp.h"
#include "socket_select.h"
#include "socket_util.h"

int select_recv_udp(int fd)
{

	char buf[20];
	int len = sizeof(buf);
	struct ofp_timeval timeout;
	int ret_select = 0;
	ofp_fd_set read_fd;

	OFP_FD_ZERO(&read_fd);
	OFP_FD_SET(fd, &read_fd);

	timeout.tv_sec = 1;
	timeout.tv_usec = 0;

	ret_select = ofp_select(fd + 1, &read_fd, NULL, NULL, &timeout);
	if (ret_select == -1) {
		OFP_ERR("Faild to select (errno = %d)\n", ofp_errno);
		return -1;
	}
	if (ret_select != 1) {
		OFP_ERR("Faild to select: invalid value returned %d\n",
			ret_select);
		return -1;
	}

	if (!OFP_FD_ISSET(fd, &read_fd)) {
		OFP_ERR("Faild: socket is not selected\n");
		return -1;
	}

	OFP_INFO("ofp_select() returned %d; socket is selected.\n",
		ret_select);

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

int select_recv_tcp(int fd)
{
	char buf[20];
	int len = sizeof(buf);
	int fd_accepted = -1;
	struct ofp_timeval timeout;
	int ret_select = 0;
	ofp_fd_set read_fd;

	OFP_FD_ZERO(&read_fd);
	OFP_FD_SET(fd, &read_fd);

	timeout.tv_sec = 0;
	timeout.tv_usec = 200000;

	ret_select = ofp_select(fd + 1, &read_fd, NULL, NULL, &timeout);
	if (ret_select == -1) {
		OFP_ERR("Faild to select (errno = %d)\n", ofp_errno);
		return -1;
	}
	if (ret_select != 1) {
		OFP_ERR("Faild to select: invalid value returned %d\n",
			ret_select);
		return -1;
	}

	if (!OFP_FD_ISSET(fd, &read_fd)) {
		OFP_ERR("Faild: socket is not selected\n");
		return -1;
	}
	OFP_INFO("ofp_select() returned %d; socket is selected.\n",
		ret_select);

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

int select_recv_udp_2(int fd)
{
	char buf[20];
	int len = sizeof(buf);
	struct ofp_timeval timeout;
	int ret_select = 0;
	ofp_fd_set read_fd;
	struct ofp_sockaddr_in addr;
	int fd2 = ofp_socket(OFP_AF_INET, OFP_SOCK_DGRAM,
				OFP_IPPROTO_UDP);
	int fd3 = ofp_socket(OFP_AF_INET, OFP_SOCK_DGRAM,
				OFP_IPPROTO_UDP);

	addr.sin_len = sizeof(struct ofp_sockaddr_in);
	addr.sin_family = OFP_AF_INET;
	addr.sin_port = odp_cpu_to_be_16(TEST_PORT + 2);
	addr.sin_addr.s_addr = OFP_INADDR_ANY;

	if (ofp_bind(fd3, (const struct ofp_sockaddr *)&addr,
		sizeof(struct ofp_sockaddr_in)) == -1) {
		OFP_ERR("Faild to bind socket (errno = %d)\n",
			ofp_errno);
		ofp_close(fd2);
		ofp_close(fd3);
		return -1;
	}

	strcpy(buf, "socket_2");
	if (ofp_sendto(fd2, buf, strlen(buf), 0,
		(struct ofp_sockaddr *)&addr,
		sizeof(addr)) == -1) {
		OFP_ERR("Faild to send data(errno = %d)\n", ofp_errno);
		ofp_close(fd2);
		ofp_close(fd3);
		return -1;
	}

	OFP_FD_ZERO(&read_fd);
	OFP_FD_SET(fd, &read_fd);
	OFP_FD_SET(fd3, &read_fd);

	timeout.tv_sec = 1;
	timeout.tv_usec = 0;

	ret_select = ofp_select(fd + 1, &read_fd, NULL, NULL, &timeout);
	if (ret_select == -1) {
		OFP_ERR("Faild to select (errno = %d)\n", ofp_errno);
		ofp_close(fd2);
		ofp_close(fd3);
		return -1;
	}

	if (!OFP_FD_ISSET(fd, &read_fd)) {
		OFP_ERR("Faild: socket is not selected\n");
		return -1;
	}
	if (!OFP_FD_ISSET(fd3, &read_fd)) {
		OFP_ERR("Faild: socket is not selected\n");
		return -1;
	}
	OFP_INFO("ofp_select() returned %d; sockets are selected.\n",
		ret_select);

	len = ofp_recv(fd, buf, len, 0);
	if (len == -1) {
		OFP_ERR("Faild to rcv data(errno = %d)\n", ofp_errno);
		ofp_close(fd2);
		ofp_close(fd3);
		return -1;
	}

	buf[len] = 0;
	OFP_INFO("Data1 (%s, len = %d) was received.\n", buf, len);

	len = ofp_recv(fd3, buf, sizeof(buf), 0);
	if (len == -1) {
		OFP_ERR("Faild to rcv data(errno = %d)\n", ofp_errno);
		ofp_close(fd2);
		ofp_close(fd3);
		return -1;
	}

	buf[len] = 0;
	OFP_INFO("Data2 (%s, len = %d) was received.\n", buf, len);

	ofp_close(fd2);
	ofp_close(fd3);

	OFP_INFO("SUCCESS.\n");
	return 0;
}

