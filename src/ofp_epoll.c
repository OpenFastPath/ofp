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

static inline int get_fd(struct epoll_set *epoll_set)
{
	return epoll_set->fd;
}

static inline int is_fd(struct epoll_set *epoll_set, int fd)
{
	return (get_fd(epoll_set) == fd);
}

static inline struct epoll_set *find_fd(struct socket *epoll, int fd)
{
	struct epoll_set *epoll_set;

	FOREACH(epoll_set, epoll->epoll_set)
		if (is_fd(epoll_set, fd))
			return epoll_set;

	return NULL;
}

static inline int is_registered(struct socket *epoll, int fd)
{
	return (find_fd(epoll, fd) != NULL);
}

static inline void set_fd(struct epoll_set *epoll_set, int fd, struct ofp_epoll_event *event)
{
	epoll_set->fd = fd;
	epoll_set->event = *event;
}

static inline int modify_epoll_set(struct socket *epoll, int old_fd, int new_fd, struct ofp_epoll_event *event)
{
	set_fd(find_fd(epoll, old_fd), new_fd, event);
	return 0;
}

static int ofp_epoll_ctl_add(struct socket *epoll, int fd, struct ofp_epoll_event *event)
{
	if (is_registered(epoll, fd))
		return failure(OFP_EEXIST);

	return modify_epoll_set(epoll, -1, fd, event);
}

static int ofp_epoll_ctl_del(struct socket *epoll, int fd)
{
	struct ofp_epoll_event event = { 0 };

	if (!is_registered(epoll, fd))
		return failure(OFP_ENOENT);

	return modify_epoll_set(epoll, fd, -1, &event);
}

static int ofp_epoll_ctl_mod(struct socket *epoll, int fd, struct ofp_epoll_event *event)
{
	if (!is_registered(epoll, fd))
		return failure(OFP_ENOENT);

	return modify_epoll_set(epoll, fd, fd, event);
}

int _ofp_epoll_ctl(struct socket *epoll, int op, int fd, struct ofp_epoll_event *event)
{
	if (!epoll || !get_socket(fd))
		return failure(OFP_EBADF);

	if (!is_epoll_socket(epoll))
		return failure(OFP_EINVAL);

	switch (op) {
	case OFP_EPOLL_CTL_ADD:
		return ofp_epoll_ctl_add(epoll, fd, event);
	case OFP_EPOLL_CTL_DEL:
		return ofp_epoll_ctl_del(epoll, fd);
	case OFP_EPOLL_CTL_MOD:
		return ofp_epoll_ctl_mod(epoll, fd, event);
	default:
		ofp_errno = OFP_EINVAL;
	}

	return -1;
}

int ofp_epoll_wait(int epfd, struct ofp_epoll_event *events, int maxevents, int timeout)
{
	return _ofp_epoll_wait(get_socket(epfd), events, maxevents, timeout);
}

static inline int is_fd_set(struct epoll_set *epoll_set)
{
	return !is_fd(epoll_set, -1);
}

static int (*is_ready)(int fd);

static inline struct ofp_epoll_event get_event(struct epoll_set *epoll_set)
{
	return epoll_set->event;
}

static int available_events(struct socket *epoll, struct ofp_epoll_event *events, int maxevents)
{
	struct epoll_set *epoll_set;
	int ready = 0;

	FOREACH(epoll_set, epoll->epoll_set)
		if (ready < maxevents && is_fd_set(epoll_set) && is_ready(get_fd(epoll_set)))
			events[ready++] = get_event(epoll_set);

	return ready;
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

	return available_events(epoll, events, maxevents);
}

void ofp_set_socket_getter(struct socket*(*socket_getter)(int fd))
{
	get_socket = socket_getter;
}

void ofp_set_is_ready_checker(int(*is_ready_checker)(int fd))
{
	is_ready = is_ready_checker;
}
