/* Copyright (c) 2016, Nokia
 * Copyright (c) 2016, ENEA Software AB
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "netwrap_epoll.h"
#include "netwrap_common.h"
#include "netwrap_errno.h"
#include "ofp.h"
#include <errno.h>
#include <sys/epoll.h>

static int setup_epoll_wrappers_called;

static int (*libc_epoll_create)(int size);

static int (*libc_epoll_ctl)(int epfd, int op, int fd, struct epoll_event *event);

static int (*libc_epoll_wait)(int epfd, struct epoll_event *events, int maxevents, int timeout);


void setup_epoll_wrappers(void)
{
	LIBC_FUNCTION(epoll_create);
	LIBC_FUNCTION(epoll_ctl);
	LIBC_FUNCTION(epoll_wait);
	setup_epoll_wrappers_called = 1;
}

int epoll_create(int size)
{
	int epfd = -1;

	if (setup_epoll_wrappers_called) {
		epfd = ofp_epoll_create(size);

		if (epfd == -1)
			errno = NETWRAP_ERRNO(ofp_errno);
		else
			errno = 0;
	} else {
		LIBC_FUNCTION(epoll_create);

		if (libc_epoll_create)
			epfd = libc_epoll_create(size);
		else {
			errno = EACCES;
			epfd = -1;
		}
	}

	return epfd;
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
	if (IS_OFP_SOCKET(epfd)) {
		struct ofp_epoll_event ofp_event = { event->events, { .u64 = event->data.u64 } };

		if (ofp_epoll_ctl(epfd, op, fd, &ofp_event) == 0)
			return 0;

		errno = NETWRAP_ERRNO(ofp_errno);
		return -1;
	}

	if (libc_epoll_ctl)
		return libc_epoll_ctl(epfd, op, fd, event);

	LIBC_FUNCTION(epoll_ctl);
	if (libc_epoll_ctl)
		return libc_epoll_ctl(epfd, op, fd, event);

	errno = EACCES;
	return -1;
}

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
	if (IS_OFP_SOCKET(epfd)) {
		struct ofp_epoll_event ofp_events[maxevents];
		const int ready = ofp_epoll_wait(epfd, ofp_events, maxevents, timeout);
		int i;

		if (ready == -1)
			errno = NETWRAP_ERRNO(ofp_errno);

		for (i = 0; i < ready; ++i) {
			events[i].events = ofp_events[i].events;
			events[i].data.u64 = ofp_events[i].data.u64;
		}

		return ready;
	}

	if (libc_epoll_wait)
		return libc_epoll_wait(epfd, events, maxevents, timeout);

	LIBC_FUNCTION(epoll_wait);
	if (libc_epoll_wait)
		return libc_epoll_wait(epfd, events, maxevents, timeout);

	errno = EACCES;
	return -1;
}
