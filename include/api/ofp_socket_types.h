/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef __OFP_SOCKET_TYPES_H__
#define __OFP_SOCKET_TYPES_H__

#include "odp.h"

#if __GNUC__ >= 4
#pragma GCC visibility push(default)
#endif

typedef uint8_t	__ofp_sa_family_t;
typedef uint32_t	__ofp_socklen_t;
typedef long		__ofp_suseconds_t;	/* microseconds (signed) */
typedef unsigned int	__ofp_useconds_t;	/* microseconds (unsigned) */
typedef int		__ofp_cpuwhich_t;	/* which parameter for cpuset.*/
typedef int		__ofp_cpulevel_t;	/* level parameter for cpuset.*/
typedef int		__ofp_cpusetid_t;	/* cpuset identifier. */
typedef uint32_t	__ofp_gid_t;
typedef uint32_t	__ofp_pid_t;
typedef uint32_t	__ofp_uid_t;
typedef int64_t	__ofp_ssize_t;
typedef int64_t	__ofp_off_t;

#if __GNUC__ >= 4
#pragma GCC visibility pop
#endif

#endif /* __OFP_SOCKET_TYPES_H__ */

