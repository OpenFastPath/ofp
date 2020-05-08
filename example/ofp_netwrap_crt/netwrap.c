/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>

#include "netwrap_socket.h"
#include "netwrap_sockopt.h"
#include "netwrap_ioctl.h"
#include "netwrap_fork.h"
#include "netwrap_select.h"
#include "netwrap_uio.h"
#include "netwrap_sendfile.h"
#include "netwrap_epoll.h"
#include "netwrap_common.h"

__attribute__((constructor)) static void setup_wrappers(void)
{
	if (setup_common_vars())
		return;
	setup_socket_wrappers();
	setup_sockopt_wrappers();
	setup_ioctl_wrappers();
	setup_fork_wrappers();
	setup_select_wrappers();
	setup_uio_wrappers();
	setup_sendfile_wrappers();
	setup_epoll_wrappers();
}
