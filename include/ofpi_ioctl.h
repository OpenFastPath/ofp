/*-
 * Copyright (c) 2014 ENEA Software AB
 * Copyright (c) 2014 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _OFPI_IOCTL_H_
#define _OFPI_IOCTL_H_

#include "api/ofp_ioctl.h"

extern odp_rwlock_t ofp_in_ifaddr_lock;
struct thread;
struct ofp_ucred;

int ofp_soo_ioctl(struct socket *so, uint32_t cmd, void *data,
	      struct ofp_ucred *active_cred, struct thread *td);
int ofp_in_control(struct socket *so, uint32_t cmd, char * data, struct ofp_ifnet *ifp,
	       struct thread *td);

#endif
