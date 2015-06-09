/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef __SOCKET_BIND_H__
#define __SOCKET_BIND_H__

int init_udp_create_socket(int *pfd_thread1, int *pfd_thread2);
int init_tcp_create_socket(int *pfd_thread1, int *pfd_thread2);

#ifdef INET6
int init_udp6_create_socket(int *pfd_thread1, int *pfd_thread2);
int init_tcp6_create_socket(int *pfd_thread1, int *pfd_thread2);
#endif /* INET6 */

int bind_ip4_local_ip(int fd);
int bind_ip4_any(int fd);

#ifdef INET6
int bind_ip6_local_ip(int fd);
int bind_ip6_any(int fd);
#endif /* INET6 */

#endif /* __SOCKET_BIND_H__ */
