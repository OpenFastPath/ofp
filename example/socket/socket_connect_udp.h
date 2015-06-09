/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef __SOCKET_CONNECT_UDP_H__
#define __SOCKET_CONNECT_UDP_H__

int connect_udp4(int fd);
int connect_bind_udp4(int fd);
int connect_shutdown_udp4(int fd);
int connect_shutdown_bind_udp4(int fd);

#ifdef INET6
int connect_udp6(int fd);
int connect_bind_udp6(int fd);

int connect_shutdown_udp6(int fd);
int connect_shutdown_bind_udp6(int fd);

int connect_shutdown_udp6_any(int fd);
int connect_shutdown_bind_udp6_any(int fd);
#endif /* INET6 */


#endif /* __SOCKET_CONNECT_UDP_H__ */

