/* Copyright (c) 2016, Nokia
 * Copyright (c) 2016, ENEA Software AB
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFPI_EPOLL_H__
#define __OFPI_EPOLL_H__

int _ofp_epoll_create(int size, int(*create_socket)(void));

#endif
