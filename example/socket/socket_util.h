/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef __SOCKET_UTIL_H__
#define __SOCKET_UTIL_H__

#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define TEST_PORT 54321

#define IP4(a, b, c, d) (a|(b<<8)|(c<<16)|(d<<24))

#endif /*__SOCKET_UTIL_H__*/

