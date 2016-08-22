/* Copyright (c) 2016, Nokia
 * Copyright (c) 2016, ENEA Software AB
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "ofp_epoll.h"
#include "ofpi_epoll.h"
#include "ofp_errno.h"

static int (*epoll_socket_creator)(void);

int ofp_epoll_create(int size)
{
	return _ofp_epoll_create(size, epoll_socket_creator);
}

static inline int failure(int err)
{
	ofp_errno = err;
	return -1;
}

int _ofp_epoll_create(int size, int(*create_socket)(void))
{
	if (size < 1)
		return failure(OFP_EINVAL);

	return create_socket();
}

static struct socket *(*get_socket)(int fd);

int ofp_epoll_ctl(int epfd, int op, int fd, struct ofp_epoll_event *event)
{
	if (epfd == fd)
		return failure(OFP_EINVAL);

	return _ofp_epoll_ctl(get_socket(epfd), op, fd, event);
}

static inline int is_epoll_socket(struct socket *epoll)
{
	return (epoll->so_type == OFP_SOCK_EPOLL);
}

int _ofp_epoll_ctl(struct socket *epoll, int op, int fd, struct ofp_epoll_event *event)
{
	(void)event;

	if (!epoll || !get_socket(fd))
		return failure(OFP_EBADF);

	if (!is_epoll_socket(epoll))
		return failure(OFP_EINVAL);

	switch (op) {
	case OFP_EPOLL_CTL_ADD:
		return 0;
	case OFP_EPOLL_CTL_DEL:
	case OFP_EPOLL_CTL_MOD:
		return failure(OFP_ENOENT);
	default:
		ofp_errno = OFP_EINVAL;
	}

	return -1;
}

void ofp_set_socket_getter(struct socket*(*socket_getter)(int fd))
{
	get_socket = socket_getter;
}
