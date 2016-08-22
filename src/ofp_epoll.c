/* Copyright (c) 2016, Nokia
 * Copyright (c) 2016, ENEA Software AB
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "ofp_epoll.h"
#include "ofpi_epoll.h"
#include "ofp_errno.h"

static int (*epoll_socket_creator)(void);

int ofp_epoll_create(int size)
{
	return _ofp_epoll_create(size, epoll_socket_creator);
}

static inline int failure(int err)
{
	ofp_errno = err;
	return -1;
}

int _ofp_epoll_create(int size, int(*create_socket)(void))
{
	if (size < 1)
		return failure(OFP_EINVAL);

	return create_socket();
}
