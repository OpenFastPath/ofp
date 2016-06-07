/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "netwrap_common.h"
#include "odp.h"
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
		odph_linux_process_t odph_proc[1];
		int fork_value;
		odph_linux_thr_params_t thr_params;

		if (recursive) {
			if (!libc_fork) {
				errno = EACCES;
				return -1;
			}
			return (*libc_fork)();
		}

		recursive = 1;
		thr_params.start = NULL;
		thr_params.arg = NULL;
		thr_params.thr_type = ODP_THREAD_CONTROL;
		thr_params.instance = netwrap_proc_instance;
		fork_value = odph_linux_process_fork(odph_proc, odp_cpu_id(),
			&thr_params);
		recursive = 0;

		if (fork_value < 0)
			netwrap_pid = -1;
		else if (fork_value == 0) {	/* child*/
			netwrap_pid = 0;
			ofp_init_local();
		} else				/* parent */
			netwrap_pid = odph_proc[0].pid;
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
