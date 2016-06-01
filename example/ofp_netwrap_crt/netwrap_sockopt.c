/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "netwrap_common.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include "odp.h"
#include "ofp.h"
#include "netwrap_sockopt.h"
#include "netwrap_errno.h"

static int (*libc_setsockopt)(int, int, int, const void*, socklen_t);
static int (*libc_getsockopt)(int, int, int, void*, socklen_t*);

void setup_sockopt_wrappers(void)
{
	LIBC_FUNCTION(setsockopt);
	LIBC_FUNCTION(getsockopt);
}

int setsockopt(int sockfd, int level, int opt_name, const void *opt_val,
	socklen_t opt_len)
{
	int setsockopt_value;

	if (IS_OFP_SOCKET(sockfd)) {
		int ofp_level;
		int ofp_opt_name;

		if (level == SOL_SOCKET) {
			ofp_level = OFP_SOL_SOCKET;

			switch (opt_name) {
			case SO_LINGER:
				ofp_opt_name = OFP_SO_LINGER;
				break;
			case SO_DEBUG:
				ofp_opt_name = OFP_SO_DEBUG;
				break;
			case SO_KEEPALIVE:
				ofp_opt_name = OFP_SO_KEEPALIVE;
				break;
			case SO_DONTROUTE:
				ofp_opt_name = OFP_SO_DONTROUTE;
				break;
			/*case SO_USELOOPBACK:
				ofp_opt_name = OFP_SO_USELOOPBACK;
				break;*/
			case SO_BROADCAST:
				ofp_opt_name = OFP_SO_BROADCAST;
				break;
			case SO_REUSEADDR:
				ofp_opt_name = OFP_SO_REUSEADDR;
				break;
			case SO_REUSEPORT:
				ofp_opt_name = OFP_SO_REUSEPORT;
				break;
			case SO_OOBINLINE:
				ofp_opt_name = OFP_SO_OOBINLINE;
				break;
			case SO_TIMESTAMP:
				ofp_opt_name = OFP_SO_TIMESTAMP;
				break;
			/*case SO_BINTIME:
				ofp_opt_name = OFP_SO_BINTIME;
				break;
			case SO_NOSIGPIPE:
				ofp_opt_name = OFP_SO_NOSIGPIPE;
				break;
			case SO_NO_DDP:
				ofp_opt_name = OFP_SO_NO_DDP;
				break;
			case SO_NO_OFFLOAD:
				ofp_opt_name = OFP_SO_NO_OFFLOAD;
				break;
			case SO_SETFIB:
				ofp_opt_name = OFP_SO_SETFIB;
				break;
			case SO_USER_COOKIE:
				ofp_opt_name = OFP_SO_USER_COOKIE;
				break;*/
			case SO_SNDBUF:
				ofp_opt_name = OFP_SO_SNDBUF;
				break;
			case SO_RCVBUF:
				ofp_opt_name = OFP_SO_RCVBUF;
				break;
			case SO_SNDLOWAT:
				ofp_opt_name = OFP_SO_SNDLOWAT;
				break;
			case SO_RCVLOWAT:
				ofp_opt_name = OFP_SO_RCVLOWAT;
				break;
			case SO_SNDTIMEO:
				ofp_opt_name = OFP_SO_SNDTIMEO;
				break;
			case SO_RCVTIMEO:
				ofp_opt_name = OFP_SO_RCVTIMEO;
				break;
			/*case SO_LABEL:
				ofp_opt_name = OFP_SO_LABEL;
				break;*/
			default:
				errno = EOPNOTSUPP;
				return -1;
			};
		} else {
			ofp_level = level;
			ofp_opt_name = opt_name;
		}


		setsockopt_value = ofp_setsockopt(sockfd, ofp_level,
			ofp_opt_name, opt_val, opt_len);
		errno = NETWRAP_ERRNO(ofp_errno);
	} else if (libc_setsockopt)
		setsockopt_value = (*libc_setsockopt)(sockfd, level, opt_name,
			opt_val, opt_len);
	else {
		LIBC_FUNCTION(setsockopt);

		if (libc_setsockopt)
			setsockopt_value = (*libc_setsockopt)(sockfd, level,
				opt_name, opt_val, opt_len);
		else {
			setsockopt_value = -1;
			errno = EACCES;
		}
	}

	return setsockopt_value;
}


int getsockopt(int sockfd, int level, int opt_name, void *opt_val,
	socklen_t *opt_len)
{
	int getsockopt_value = -1;

	if (IS_OFP_SOCKET(sockfd)) {
		int ofp_level;
		int ofp_opt_name;

		if (level == SOL_SOCKET) {
			ofp_level = OFP_SOL_SOCKET;

			switch (opt_name) {
			case SO_LINGER:
				ofp_opt_name = OFP_SO_LINGER;
				break;
			case SO_DEBUG:
				ofp_opt_name = OFP_SO_DEBUG;
				break;
			case SO_KEEPALIVE:
				ofp_opt_name = OFP_SO_KEEPALIVE;
				break;
			case SO_DONTROUTE:
				ofp_opt_name = OFP_SO_DONTROUTE;
				break;
			/*case SO_USELOOPBACK:
				ofp_opt_name = OFP_SO_USELOOPBACK;
				break;*/
			case SO_BROADCAST:
				ofp_opt_name = OFP_SO_BROADCAST;
				break;
			case SO_REUSEADDR:
				ofp_opt_name = OFP_SO_REUSEADDR;
				break;
			case SO_REUSEPORT:
				ofp_opt_name = OFP_SO_REUSEPORT;
				break;
			case SO_OOBINLINE:
				ofp_opt_name = OFP_SO_OOBINLINE;
				break;
			case SO_ACCEPTCONN:
				ofp_opt_name = OFP_SO_ACCEPTCONN;
				break;
			case SO_TIMESTAMP:
				ofp_opt_name = OFP_SO_TIMESTAMP;
				break;
			/*case SO_BINTIME:
				ofp_opt_name = OFP_SO_BINTIME;
				break;
			case SO_NOSIGPIPE:
				ofp_opt_name = OFP_SO_NOSIGPIPE;
				break;
			case SO_SETFIB:
				ofp_opt_name = OFP_SO_SETFIB;
				break;
			case SO_USER_COOKIE:
				ofp_opt_name = OFP_SO_USER_COOKIE;
				break;*/
			case SO_SNDBUF:
				ofp_opt_name = OFP_SO_SNDBUF;
				break;
			case SO_RCVBUF:
				ofp_opt_name = OFP_SO_RCVBUF;
				break;
			case SO_SNDLOWAT:
				ofp_opt_name = OFP_SO_SNDLOWAT;
				break;
			case SO_RCVLOWAT:
				ofp_opt_name = OFP_SO_RCVLOWAT;
				break;
			case SO_SNDTIMEO:
				ofp_opt_name = OFP_SO_SNDTIMEO;
				break;
			case SO_RCVTIMEO:
				ofp_opt_name = OFP_SO_RCVTIMEO;
				break;
			/*case SO_LABEL:
				ofp_opt_name = OFP_SO_LABEL;
				break;*/
			case SO_TYPE:
				ofp_opt_name = OFP_SO_TYPE;
				break;
			case SO_PROTOCOL:
				ofp_opt_name = OFP_SO_PROTOCOL;
				break;
			case SO_ERROR:
				ofp_opt_name = OFP_SO_ERROR;
				break;
			/*case SO_LISTENQLIMIT:
				ofp_opt_name = OFP_SO_LISTENQLIMIT;
				break;
			case SO_LISTENQLEN:
				ofp_opt_name = OFP_SO_LISTENQLEN;
				break;
			case SO_LISTENINCQLEN:
				ofp_opt_name = OFP_SO_LISTENINCQLEN;
				break;*/
			default:
				errno = EOPNOTSUPP;
				return -1;
			};
		} else {
			ofp_level = level;
			ofp_opt_name = opt_name;
		}

		getsockopt_value = ofp_getsockopt(sockfd, ofp_level,
			ofp_opt_name, opt_val, opt_len);
		errno = NETWRAP_ERRNO(ofp_errno);
	} else if (libc_getsockopt)
		getsockopt_value = (*libc_getsockopt)(sockfd, level, opt_name,
			opt_val, opt_len);
	else {
		LIBC_FUNCTION(getsockopt);

		if (libc_getsockopt)
			getsockopt_value = (*libc_getsockopt)(sockfd, level,
					opt_name, opt_val, opt_len);
		else {
			getsockopt_value = -1;
			errno = EACCES;
		}
	}
	return getsockopt_value;
}
