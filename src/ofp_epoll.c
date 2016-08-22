/* Copyright (c) 2016, Nokia
 * Copyright (c) 2016, ENEA Software AB
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "ofp_epoll.h"
#include "ofpi_epoll.h"
#include "ofp_errno.h"

#define LENGTH(array) \
	sizeof(array)/sizeof(*array)
#define FOREACH(item, array) \
	int i, l, breaked; \
	for (i = 0, l = LENGTH(array), breaked = 0; i < l && !breaked; ++i, breaked = !breaked) \
		for (item = &array[i]; !breaked; breaked = !breaked)

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

static inline int is_fd(int *epoll_set, int fd)
{
	return (*epoll_set == fd);
}

static inline int *find_fd(struct socket *epoll, int fd)
{
	int *epoll_set;

	FOREACH(epoll_set, epoll->epoll_set)
		if (is_fd(epoll_set, fd))
			return epoll_set;

	return NULL;
}

static inline int is_registered(struct socket *epoll, int fd)
{
	return (find_fd(epoll, fd) != NULL);
}

static inline void set_fd(int *epoll_set, int fd)
{
	*epoll_set = fd;
}

static inline int modify_epoll_set(struct socket *epoll, int old_fd, int new_fd)
{
	set_fd(find_fd(epoll, old_fd), new_fd);
	return 0;
}

static int ofp_epoll_ctl_add(struct socket *epoll, int fd)
{
	if (is_registered(epoll, fd))
		return failure(OFP_EEXIST);

	return modify_epoll_set(epoll, -1, fd);
}

static int ofp_epoll_ctl_del(struct socket *epoll, int fd)
{
	if (!is_registered(epoll, fd))
		return failure(OFP_ENOENT);

	return modify_epoll_set(epoll, fd, -1);
}

static int ofp_epoll_ctl_mod(struct socket *epoll, int fd)
{
	if (!is_registered(epoll, fd))
		return failure(OFP_ENOENT);

	return 0;
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
		return ofp_epoll_ctl_add(epoll, fd);
	case OFP_EPOLL_CTL_DEL:
		return ofp_epoll_ctl_del(epoll, fd);
	case OFP_EPOLL_CTL_MOD:
		return ofp_epoll_ctl_mod(epoll, fd);
	default:
		ofp_errno = OFP_EINVAL;
	}

	return -1;
}

int ofp_epoll_wait(int epfd, struct ofp_epoll_event *events, int maxevents, int timeout)
{
	return _ofp_epoll_wait(get_socket(epfd), events, maxevents, timeout);
}

int _ofp_epoll_wait(struct socket *epoll, struct ofp_epoll_event *events, int maxevents, int timeout)
{
	(void)timeout;

	if (!epoll)
		return failure(OFP_EBADF);

	if (!is_epoll_socket(epoll) || maxevents < 1)
		return failure(OFP_EINVAL);

	if (!events)
		return failure(OFP_EFAULT);

	return 0;
}

void ofp_set_socket_getter(struct socket*(*socket_getter)(int fd))
{
	get_socket = socket_getter;
}
