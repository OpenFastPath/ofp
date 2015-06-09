/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef __SOCKET_CONNECT_ACCEPT_H__
#define __SOCKET_CONNECT_ACCEPT_H__

int init_tcp_bind_listen_local_ip(int *pfd_thread1, int *pfd_thread2);
int init_tcp_bind_listen_any(int *pfd_thread1, int *pfd_thread2);

#ifdef INET6
int init_tcp6_bind_listen_local_ip(int *pfd_thread1, int *pfd_thread2);
int init_tcp6_bind_listen_any(int *pfd_thread1, int *pfd_thread2);
#endif /* INET6 */

int connect_tcp4_local_ip(int fd);
int connect_tcp4_any(int fd);

int accept_tcp4(int fd);
int accept_tcp4_null_addr(int fd);

#ifdef INET6
int connect_tcp6_local_ip(int fd);
int connect_tcp6_any(int fd);

int accept_tcp6(int fd);
int accept_tcp6_null_addr(int fd);
#endif /* INET6 */

#endif /* __SOCKET_CONNECT_ACCEPT_H__ */

