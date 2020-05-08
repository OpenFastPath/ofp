/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "netwrap_common.h"
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <odp_api.h>
#include "ofp.h"
#include "netwrap_select.h"
#include "netwrap_errno.h"

static int (*libc_select)(int, fd_set *, fd_set *, fd_set *,
	struct timeval *);


void setup_select_wrappers(void)
{
	LIBC_FUNCTION(select);
}

int select(int nfds, fd_set *readfds, fd_set *writefds,
	fd_set *exceptfds, struct timeval *timeout)
{
	int select_value;

	if (IS_OFP_SOCKET((nfds - 1))) {
		ofp_fd_set ofp_readfds, ofp_readfds_bku;
		struct ofp_timeval ofp_timeout_local;
		struct ofp_timeval *ofp_timeout;
		int i;
		uint32_t period_usec = 0;
		uint32_t temp_period_usec = 0;

		(void)writefds;
		(void)exceptfds;

		if (!readfds) {
			errno = EBADF;
			return -1;
		}

		OFP_FD_ZERO(&ofp_readfds_bku);
		for (i = ofp_global_params.socket.sd_offset; i < nfds; i++)
			if (FD_ISSET(i, readfds))
				OFP_FD_SET(i, &ofp_readfds_bku);

		ofp_timeout = &ofp_timeout_local;
		ofp_timeout_local.tv_sec = 0;
		ofp_timeout_local.tv_usec = 0;

		if (timeout)
			period_usec = timeout->tv_sec * 1000000UL +
				timeout->tv_usec;

		do {
			memcpy(&ofp_readfds, &ofp_readfds_bku,
					sizeof(ofp_readfds));
			select_value = ofp_select(nfds, &ofp_readfds, NULL,
				NULL, ofp_timeout);
			if (select_value)
				break;
			else if (!timeout)
				continue;
			else {
				usleep(100);
				temp_period_usec += 100;
				if (temp_period_usec > period_usec) {
					select_value = 0;
					break;
				}
			}

		} while (1);
		errno = NETWRAP_ERRNO(ofp_errno);

		if (select_value > 0) {
			for (i = ofp_global_params.socket.sd_offset;
			     i < nfds; i++)
				if (FD_ISSET(i, readfds) &&
					!OFP_FD_ISSET(i, &ofp_readfds))
						FD_CLR(i, readfds);
		} else if (select_value == 0)
			FD_ZERO(readfds);

		if (!ofp_errno && timeout) {
			timeout->tv_sec = ofp_timeout_local.tv_sec;
			timeout->tv_usec = ofp_timeout_local.tv_usec;
		}
	} else if (libc_select)
		select_value = (*libc_select)(nfds, readfds, writefds,
			exceptfds, timeout);
	else {
		LIBC_FUNCTION(select);

		if (libc_select)
			select_value = (*libc_select)(nfds, readfds, writefds,
				exceptfds, timeout);
		else {
			select_value = -1;
			errno = EACCES;
		}
	}

	/*printf("Select called with max fd = %d returned %d\n",
		nfds, select_value);*/
	return select_value;
}
