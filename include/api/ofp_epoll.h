/* Copyright (c) 2016, Nokia
 * Copyright (c) 2016, ENEA Software AB
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFP_EPOLL_H__
#define __OFP_EPOLL_H__

#include <stdint.h>

#if __GNUC__ >= 4
#pragma GCC visibility push(default)
#endif

typedef union ofp_epoll_data {
	void    *ptr;
	int      fd;
	uint32_t u32;
	uint64_t u64;
} ofp_epoll_data_t;

struct ofp_epoll_event {
	uint32_t events;
	ofp_epoll_data_t data;
};

enum OFP_EPOLL_EVENTS {
	OFP_EPOLLIN = 0x001,
#define OFP_EPOLLIN OFP_EPOLLIN
};

#define OFP_EPOLL_CTL_ADD 1
#define OFP_EPOLL_CTL_DEL 2
#define OFP_EPOLL_CTL_MOD 3

int ofp_epoll_create(int size);

int ofp_epoll_ctl(int epfd, int op, int fd, struct ofp_epoll_event *event);

int ofp_epoll_wait(int epfd, struct ofp_epoll_event *events, int maxevents, int timeout);

#if __GNUC__ >= 4
#pragma GCC visibility pop
#endif

#endif
