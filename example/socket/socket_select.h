/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef __SOCKET_SELECT_H__
#define __SOCKET_SELECT_H__

int select_recv_udp(int fd);
int select_recv_tcp(int fd);

int select_recv_udp_2(int fd);

#endif /* __SOCKET_SELECT_H__ */

