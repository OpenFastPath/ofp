/* Copyright (c) 2016, Nokia
 * Copyright (c) 2016, ENEA Software AB
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFPI_EPOLL_H__
#define __OFPI_EPOLL_H__

#include "ofpi_socketvar.h"

int _ofp_epoll_create(int size, int(*create_socket)(void));

int _ofp_epoll_ctl(struct socket *epoll, int op, int fd, struct ofp_epoll_event *event);

void ofp_set_socket_getter(struct socket*(*socket_getter)(int fd));

#endif
