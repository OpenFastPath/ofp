/*
 * Copyright (c) 2016, Nokia
 * Copyright (c) 2016, Enea Software AB
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#ifndef __OFPI_SYSCALLS_H__
#define __OFPI_SYSCALLS_H__

int _ofp_select(int nfds, ofp_fd_set *readfds, ofp_fd_set *writefds,
		ofp_fd_set *exceptfds, struct ofp_timeval *timeout,
		int (*sleeper)(void *channel, odp_rwlock_t *mtx, int priority,
			       const char *wmesg, uint32_t timeout));

#endif
