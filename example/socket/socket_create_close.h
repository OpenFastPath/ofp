/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef __SOCKET_CREATE_CLOSE_H__
#define __SOCKET_CREATE_CLOSE_H__

int create_close_udp(int fd);
int create_close_udp_noproto(int fd);

int create_close_tcp(int fd);
int create_close_tcp_noproto(int fd);

#ifdef INET6
int create_close_udp6(int fd);
int create_close_udp6_noproto(int fd);

int create_close_tcp6(int fd);
int create_close_tcp6_noproto(int fd);
#endif /* INET6 */

#endif /* __SOCKET_CREATE_CLOSE_H__ */

