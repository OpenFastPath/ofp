/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "netwrap_common.h"
#include <unistd.h>
#include <odp_api.h>
#include "ofp.h"
#include "netwrap_fork.h"
#include "netwrap_errno.h"

static pid_t (*libc_vfork)(void);
static pid_t (*libc_fork)(void);

static int setup_fork_wrappers_called;

void setup_fork_wrappers(void)
{
	LIBC_FUNCTION(fork);
	LIBC_FUNCTION(vfork);

	setup_fork_wrappers_called = 1;
}

extern odp_instance_t netwrap_proc_instance;
pid_t fork(void)
{
	pid_t netwrap_pid;
	static int recursive;

	if (setup_fork_wrappers_called) {
		pid_t pid;

		if (recursive) {
			if (!libc_fork) {
				errno = EACCES;
				return -1;
			}
			return (*libc_fork)();
		}

		recursive = 1;

		pid = fork();

		recursive = 0;

		if (pid < 0)
			netwrap_pid = -1;
		else if (pid == 0) {	/* child*/
			netwrap_pid = 0;
			ofp_init_local();
		} else				/* parent */
			netwrap_pid = pid;
	} else if (libc_fork)
		netwrap_pid = (*libc_fork)();
	else {
		LIBC_FUNCTION(fork);

		if (libc_fork)
			netwrap_pid = (*libc_fork)();
		else {
			netwrap_pid = -1;
			errno = EACCES;
		}
	}

	/*printf("Fork called on core '%d' returned %d\n", odp_cpu_id(),
		netwrap_pid);*/
	return netwrap_pid;
}
