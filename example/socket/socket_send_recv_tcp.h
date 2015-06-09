/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef __SOCKET_SEND_RECV_TCP_H__
#define __SOCKET_SEND_RECV_TCP_H__

int send_tcp4_local_ip(int fd);
int send_tcp4_any(int fd);

#ifdef INET6
int send_tcp6_local_ip(int fd);
int send_tcp6_any(int fd);
#endif /* INET6 */

int receive_tcp(int fd);

#endif /* __SOCKET_SEND_RECV_TCP_H__ */

