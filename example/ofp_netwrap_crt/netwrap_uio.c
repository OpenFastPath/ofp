/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "netwrap_common.h"
#include <sys/uio.h>
#include <unistd.h>
#include "odp.h"
#include "ofp.h"
#include "netwrap_uio.h"
#include "netwrap_errno.h"

static ssize_t (*libc_writev)(int, const struct iovec *, int);

void setup_uio_wrappers(void)
{
	LIBC_FUNCTION(writev);
}


ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
{
	ssize_t writev_value = -1;

	if (IS_OFP_SOCKET(fd)) {
		int i;
		ssize_t writev_sum = 0;
		ssize_t iov_len;
		ssize_t iov_snt;
		char *iov_base;
		ofp_ssize_t ofp_send_res;


		for (i = 0; i < iovcnt; i++) {
			iov_len = iov[i].iov_len;
			iov_snt = 0;
			iov_base = (char *)iov[i].iov_base;

			while (iov_snt < iov_len) {
				ofp_send_res = ofp_send(fd, iov_base + iov_snt,
					iov_len - iov_snt, 0);

				if (ofp_send_res <= 0) {
					if (ofp_send_res == 0 ||
						ofp_errno == OFP_EAGAIN) {
						usleep(100);
						continue;
					}
					errno = NETWRAP_ERRNO(ofp_errno);
					return -1;
				}
				iov_snt += ofp_send_res;
			}
			writev_sum += iov_len;
		}
		writev_value = writev_sum;
	} else if (libc_writev)
		writev_value = (*libc_writev)(fd, iov, iovcnt);
	else {
		LIBC_FUNCTION(writev);

		if (libc_writev)
			writev_value = (*libc_writev)(fd, iov, iovcnt);
		else {
			writev_value = -1;
			errno = EACCES;
		}
	}

	return writev_value;
}
