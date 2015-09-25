/* Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/*-
 * Copyright (c) 1982, 1986, 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)in.h	8.3 (Berkeley) 1/3/94
 * $FreeBSD: release/9.1.0/sys/netinet/in.h 237910 2012-07-01 08:47:15Z tuexen $
 */
#ifndef __OFPI_IN_H__
#define __OFPI_IN_H__

#include "ofpi_portconf.h"
#include "ofpi_queue.h"
#include "api/ofp_in.h"

#include "ofpi_in6.h"

extern uint8_t ofp_inetctlerrmap[];

union ofp_sockaddr_store {
	struct ofp_sockaddr_in addr;
#ifdef INET6
	struct ofp_sockaddr_in6 addr6;
#endif /* INET6 */
};

/*
 * The following structure is private; do not use it from user applications.
 * It is used to communicate IP_MSFILTER/IPV6_MSFILTER information between
 * the RFC 3678 libc functions and the kernel.
 */
struct __msfilterreq {
	uint32_t		 msfr_ifindex;	/* interface index */
	uint32_t		 msfr_fmode;	/* filter mode for group */
	uint32_t		 msfr_nsrcs;	/* # of sources in msfr_srcs */
	struct ofp_sockaddr_storage_2	 msfr_group;	/* group address */
	struct ofp_sockaddr_storage_2	*msfr_srcs;	/* pointer to the first member
						 * of a contiguous array of
						 * sources to filter in full.
						 */
};

int ofp_getsum(const odp_packet_t pkt, unsigned int off, unsigned int len);

#endif /* __OFPI_IN_H__ */
