/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <stdio.h>
#include <signal.h>
#include "linux_sigaction.h"

static int linux_sigaction(int signum, void (*sig_func)(int))
{
	sigset_t sigmask_all;
	struct sigaction sigact = {
		.sa_handler = sig_func,
		.sa_mask = { { 0 } },
		.sa_flags = 0 ,
		};

	if (sigfillset(&sigmask_all)) {
		printf("Error: sigfillset failed.\n");
		return -1;
	}
	sigact.sa_mask = sigmask_all;

	if (sigaction(signum, &sigact, NULL)) {
		printf("Error: sigaction failed.\n");
		return -1;
	}

	return 0;
}

int ofp_sigactions_set(void (*sig_func)(int))
{
	if (linux_sigaction(SIGINT, sig_func)) {
		printf("Error: ODP sighandler setup failed: SIGINT.\n");
		return -1;
	}

	if (linux_sigaction(SIGQUIT, sig_func)) {
		printf("Error: ODP sighandler setup failed: SIGQUIT.\n");
		return -1;
	}

	if (linux_sigaction(SIGTERM, sig_func)) {
		printf("Error: ODP sighandler setup failed: SIGQUIT.\n");
		return -1;
	}

	return 0;
}
