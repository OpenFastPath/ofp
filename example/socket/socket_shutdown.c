/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include "ofp.h"
#include "socket_shutdown.h"
#include "socket_util.h"


int shutdown_socket(int fd)
{
	if (ofp_shutdown(fd, OFP_SHUT_RDWR) == -1) {
		OFP_ERR("Faild to shutdown socket (errno = %d)\n",
			ofp_errno);
		return -1;
	}

	OFP_INFO("SUCCESS.\n");
	return 0;
}
