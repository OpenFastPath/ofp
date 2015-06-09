/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include "ofp.h"
#include "socket_create_close.h"

int create_close_udp(int fd)
{
	fd = ofp_socket(OFP_AF_INET, OFP_SOCK_DGRAM, OFP_IPPROTO_UDP);
	if (fd == -1) {
		OFP_ERR("Faild to create socket (errno = %d)\n", ofp_errno);
		return -1;
	}

	if (ofp_close(fd) == -1) {
		OFP_ERR("Faild to close socket (errno = %d)\n", ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}

int create_close_udp_noproto(int fd)
{
	fd = ofp_socket(OFP_AF_INET, OFP_SOCK_DGRAM, 0);
	if (fd == -1) {
		OFP_ERR("Faild to create socket (errno = %d)\n", ofp_errno);
		return -1;
	}

	if (ofp_close(fd) == -1) {
		OFP_ERR("Faild to close socket (errno = %d)\n", ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}

int create_close_tcp(int fd)
{
	fd = ofp_socket(OFP_AF_INET, OFP_SOCK_STREAM, OFP_IPPROTO_TCP);
	if (fd == -1) {
		OFP_ERR("Faild to create socket (errno = %d)\n", ofp_errno);
		return -1;
	}

	if (ofp_close(fd) == -1) {
		OFP_ERR("Faild to close socket (errno = %d)\n", ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}

int create_close_tcp_noproto(int fd)
{
	fd = ofp_socket(OFP_AF_INET, OFP_SOCK_STREAM, 0);
	if (fd == -1) {
		OFP_ERR("Faild to create socket (errno = %d)\n", ofp_errno);
		return -1;
	}

	if (ofp_close(fd) == -1) {
		OFP_ERR("Faild to close socket (errno = %d)\n", ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}

#ifdef INET6
int create_close_udp6(int fd)
{
	fd = ofp_socket(OFP_AF_INET6, OFP_SOCK_DGRAM, OFP_IPPROTO_UDP);
	if (fd == -1) {
		OFP_ERR("Faild to create socket (errno = %d)\n", ofp_errno);
		return -1;
	}

	if (ofp_close(fd) == -1) {
		OFP_ERR("Faild to close socket (errno = %d)\n", ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}

int create_close_udp6_noproto(int fd)
{
	fd = ofp_socket(OFP_AF_INET6, OFP_SOCK_DGRAM, 0);
	if (fd == -1) {
		OFP_ERR("Faild to create socket (errno = %d)\n", ofp_errno);
		return -1;
	}

	if (ofp_close(fd) == -1) {
		OFP_ERR("Faild to close socket (errno = %d)\n", ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}

int create_close_tcp6(int fd)
{
	fd = ofp_socket(OFP_AF_INET6, OFP_SOCK_STREAM, OFP_IPPROTO_TCP);
	if (fd == -1) {
		OFP_ERR("Faild to create socket (errno = %d)\n", ofp_errno);
		return -1;
	}

	if (ofp_close(fd) == -1) {
		OFP_ERR("Faild to close socket (errno = %d)\n", ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}

int create_close_tcp6_noproto(int fd)
{
	fd = ofp_socket(OFP_AF_INET6, OFP_SOCK_STREAM, 0);
	if (fd == -1) {
		OFP_ERR("Faild to create socket (errno = %d)\n", ofp_errno);
		return -1;
	}

	if (ofp_close(fd) == -1) {
		OFP_ERR("Faild to close socket (errno = %d)\n", ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}
#endif /* INET6 */

