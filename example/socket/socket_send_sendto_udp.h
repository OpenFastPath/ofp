/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef __SOCKET_SEND_SENDTO_UDP_H__
#define __SOCKET_SEND_SENDTO_UDP_H__

int init_udp_bind_local_ip(int *pfd_thread1, int *pfd_thread2);
int init_udp_bind_any(int *pfd_thread1, int *pfd_thread2);

#ifdef INET6
int init_udp6_bind_local_ip(int *pfd_thread1, int *pfd_thread2);
int init_udp6_bind_any(int *pfd_thread1, int *pfd_thread2);
#endif /* INET6 */

int send_ip4_udp_local_ip(int fd);
int sendto_ip4_udp_local_ip(int fd);
int send_ip4_udp_any(int fd);
int sendto_ip4_udp_any(int fd);

#ifdef INET6
int send_ip6_udp_local_ip(int fd);
int sendto_ip6_udp_local_ip(int fd);
int send_ip6_udp_any(int fd);
int sendto_ip6_udp_any(int fd);
#endif /* INET6 */

#endif /* __SOCKET_SEND_SENDTO_UDP_H__ */

