/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef __SOCKET_SEND_RECV_UDP_H__
#define __SOCKET_SEND_RECV_UDP_H__

int init_udp_local_ip(int *pfd_thread1, int *pfd_thread2);
int init_udp_any(int *pfd_thread1, int *pfd_thread2);

int send_udp_local_ip(int fd);
int send_udp_any(int fd);
int recv_udp(int fd);
int recvfrom_udp(int fd);
int recvfrom_udp_null_addr(int fd);

#ifdef INET6
int send_udp6_local_ip(int fd);
int send_udp6_any(int fd);
int recvfrom_udp6(int fd);
#endif /* INET6 */

#endif /* __SOCKET_SEND_RECV_UDP_H__ */

