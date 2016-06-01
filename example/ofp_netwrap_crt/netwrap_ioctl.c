/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "netwrap_common.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include "odp.h"
#include "ofp.h"
#include "netwrap_ioctl.h"
#include "netwrap_errno.h"

static int (*libc_ioctl)(int, unsigned long int, ...);

void setup_ioctl_wrappers(void)
{
	LIBC_FUNCTION(ioctl);
}

int ioctl(int fd, unsigned long int request, ...)
{
	int ioctl_value;
	va_list ap;
	void *p;

	va_start(ap, request);
	p = va_arg(ap, void *);
	va_end(ap);

	if (IS_OFP_SOCKET(fd)) {
		int ofp_request;

		if (request == FIONREAD)
			ofp_request = OFP_FIONREAD;
		else if (request == FIONBIO)
			ofp_request = OFP_FIONBIO;
		else if (request == FIOASYNC)
			ofp_request = OFP_FIOASYNC;
		/*else if (request == FIONWRITE)
			ofp_request = OFP_FIONWRITE;
		else if (request == FIONSPACE)
			ofp_request = OFP_FIONSPACE;*/
		else {
			errno = EINVAL;
			return -1;
		}
		ioctl_value = ofp_ioctl(fd, ofp_request, p);
		errno = NETWRAP_ERRNO(ofp_errno);
	} else if (libc_ioctl)
		ioctl_value = (*libc_ioctl)(fd, request, p);
	else {
		LIBC_FUNCTION(ioctl);
		if (libc_ioctl)
			ioctl_value = (*libc_ioctl)(fd, request, p);
		else {
			ioctl_value = -1;
			errno = EACCES;
		}
	}

	/*printf("Ioctl called on socket '%d' returned %d\n", fd,
		ioctl_value);*/
	return ioctl_value;
}
