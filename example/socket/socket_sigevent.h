/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef __SOCKET_SIGEVENT_H__
#define __SOCKET_SIGEVENT_H__

int recv_send_udp_local_ip(int fd);
int socket_sigevent_udp4(int fd);

#ifdef INET6
int recv_send_udp6_local_ip(int fd);
int socket_sigevent_udp6(int fd);
#endif /* INET6 */

int connect_recv_send_tcp_local_ip(int fd);
#ifdef INET6
int connect_recv_send_tcp6_local_ip(int fd);
#endif /* INET6 */
int socket_sigevent_tcp_rcv(int fd);

int connect_tcp_delayed_local_ip(int fd);
#ifdef INET6
int connect_tcp6_delayed_local_ip(int fd);
#endif /* INET6 */
int socket_sigevent_tcp_accept(int fd);

#endif /* __SOCKET_SIGEVENT_H__ */

