/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef __SOCKET_LISTEN_TCP_H__
#define __SOCKET_LISTEN_TCP_H__

int init_tcp_bind_local_ip(int *pfd_thread1, int *pfd_thread2);

#ifdef INET6
int init_tcp6_bind_local_ip(int *pfd_thread1, int *pfd_thread2);
#endif /* INET6 */

int listen_tcp(int fd);

#endif /* __SOCKET_LISTEN_TCP_H__ */

