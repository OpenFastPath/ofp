/* Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/*-
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	$KAME: in6.h,v 1.89 2001/05/27 13:28:35 itojun Exp $
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
 * $FreeBSD: release/9.1.0/sys/netinet6/in6.h 238227 2012-07-08 10:29:01Z bz $
 */

#ifndef __OFP_IN6_H__
#define __OFP_IN6_H__

#include "ofp_socket_types.h"

#if __GNUC__ >= 4
#pragma GCC visibility push(default)
#endif

#ifndef OFP__SOCKLEN_T_DECLARED
typedef	__ofp_socklen_t	ofp_socklen_t;
#define OFP__SOCKLEN_T_DECLARED
#endif /* OFP__SOCKLEN_T_DECLARED */

/*
 * IPv6 address
 */
struct ofp_in6_addr {
	union {
		uint8_t		__u6_addr8[16];
		uint16_t	__u6_addr16[8];
		uint32_t	__u6_addr32[4];
	} __u6_addr;			/* 128-bit IP6 address */
};

#define ofp_s6_addr   __u6_addr.__u6_addr8
#define ofp_s6_addr16 __u6_addr.__u6_addr16
#define ofp_s6_addr32 __u6_addr.__u6_addr32
#define OFP_INET6_ADDRSTRLEN	46

/*
 * Socket address for IPv6
 */
struct ofp_sockaddr_in6 {
	uint8_t			sin6_len;	/* length of this struct */
	ofp_sa_family_t	sin6_family;	/* AF_INET6 */
	ofp_in_port_t		sin6_port;	/* Transport layer port # */
	uint32_t		sin6_flowinfo;	/* IP6 flow information */
	struct ofp_in6_addr	sin6_addr;	/* IP6 address */
	uint32_t		sin6_scope_id;	/* scope zone index */
};

/*
 * Local definition for masks
 */
#define OFP_IN6MASK0	{{{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } } }
#define OFP_IN6MASK32	{{{ 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, \
			    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } }
#define OFP_IN6MASK64	{{{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, \
			    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } }
#define OFP_IN6MASK96	{{{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, \
			    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 } } }
#define OFP_IN6MASK128 {{{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, \
			    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } } }

extern const struct ofp_sockaddr_in6 ofp_sa6_any;

extern const struct ofp_in6_addr ofp_in6mask0;
extern const struct ofp_in6_addr ofp_in6mask32;
extern const struct ofp_in6_addr ofp_in6mask64;
extern const struct ofp_in6_addr ofp_in6mask96;
extern const struct ofp_in6_addr ofp_in6mask128;

/*
 * Macros started with IPV6_ADDR is KAME local
 */
#if ODP_BYTE_ORDER == ODP_BIG_ENDIAN
#define OFP_IPV6_ADDR_INT32_ONE	1
#define OFP_IPV6_ADDR_INT32_TWO	2
#define OFP_IPV6_ADDR_INT32_MNL	0xff010000
#define OFP_IPV6_ADDR_INT32_MLL	0xff020000
#define OFP_IPV6_ADDR_INT32_SMP	0x0000ffff
#define OFP_IPV6_ADDR_INT16_ULL	0xfe80
#define OFP_IPV6_ADDR_INT16_USL	0xfec0
#define OFP_IPV6_ADDR_INT16_MLL	0xff02
#elif ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
#define OFP_IPV6_ADDR_INT32_ONE	0x01000000
#define OFP_IPV6_ADDR_INT32_TWO	0x02000000
#define OFP_IPV6_ADDR_INT32_MNL	0x000001ff
#define OFP_IPV6_ADDR_INT32_MLL	0x000002ff
#define OFP_IPV6_ADDR_INT32_SMP	0xffff0000
#define OFP_IPV6_ADDR_INT16_ULL	0x80fe
#define OFP_IPV6_ADDR_INT16_USL	0xc0fe
#define OFP_IPV6_ADDR_INT16_MLL	0x02ff
#endif

/*
 * Definition of some useful macros to handle IP6 addresses
 */
#define OFP_IN6ADDR_ANY_INIT \
	{{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } }
#define OFP_IN6ADDR_LOOPBACK_INIT \
	{{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } } }
#define OFP_IN6ADDR_NODELOCAL_ALLNODES_INIT \
	{{{ 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } } }
#define OFP_IN6ADDR_INTFACELOCAL_ALLNODES_INIT \
	{{{ 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } } }
#define OFP_IN6ADDR_LINKLOCAL_ALLNODES_INIT \
	{{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } } }
#define OFP_IN6ADDR_LINKLOCAL_ALLROUTERS_INIT \
	{{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 } } }
#define OFP_IN6ADDR_LINKLOCAL_ALLV2ROUTERS_INIT \
	{{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16 } } }

extern const struct ofp_in6_addr ofp_in6addr_any;
extern const struct ofp_in6_addr ofp_in6addr_loopback;
extern const struct ofp_in6_addr ofp_in6addr_nodelocal_allnodes;
extern const struct ofp_in6_addr ofp_in6addr_linklocal_allnodes;
extern const struct ofp_in6_addr ofp_in6addr_linklocal_allrouters;
extern const struct ofp_in6_addr ofp_in6addr_linklocal_allv2routers;

/*
 * Equality
 * NOTE: Some of kernel programming environment (for example, openbsd/sparc)
 * does not supply memcmp().  For userland memcmp() is preferred as it is
 * in ANSI standard.
 */
#define OFP_IN6_ARE_ADDR_EQUAL(a, b)			\
	(memcmp(&(a)->ofp_s6_addr[0], &(b)->ofp_s6_addr[0],\
		sizeof(struct ofp_in6_addr)) == 0)

/*
 * Unspecified
 */
#define OFP_IN6_IS_ADDR_UNSPECIFIED(a)	\
	(((a)->ofp_s6_addr32[0] == 0) &&      \
	 ((a)->ofp_s6_addr32[1] == 0) &&      \
	 ((a)->ofp_s6_addr32[2] == 0) &&      \
	 ((a)->ofp_s6_addr32[3] == 0))

/*
 * Loopback
 */
#define OFP_IN6_IS_ADDR_LOOPBACK(a)		\
	(((a)->ofp_s6_addr32[0] == 0) &&\
	 ((a)->ofp_s6_addr32[1] == 0) &&\
	 ((a)->ofp_s6_addr32[2] == 0) &&\
	 ((a)->ofp_s6_addr32[3] == odp_be_to_cpu_32(1)))

/*
 * IPv4 compatible
 */
#define OFP_IN6_IS_ADDR_V4COMPAT(a)		\
	((*(const uint32_t *)(const void *)(&(a)->ofp_s6_addr[0]) == 0) &&\
	 (*(const uint32_t *)(const void *)(&(a)->ofp_s6_addr[4]) == 0) &&\
	 (*(const uint32_t *)(const void *)(&(a)->ofp_s6_addr[8]) == 0) &&\
	 (*(const uint32_t *)(const void *)(&(a)->ofp_s6_addr[12]) != 0) &&\
	 (*(const uint32_t *)(const void *)(&(a)->ofp_s6_addr[12]) !=\
						odp_be_to_cpu_32(1)))

/*
 * Mapped
 */
#define OFP_IN6_IS_ADDR_V4MAPPED(a) \
	((a)->ofp_s6_addr[0] == 0 &&	\
	 (a)->ofp_s6_addr[4] == 0 &&	\
	 (a)->ofp_s6_addr[8] == odp_be_to_cpu_32(0x0000ffff))

/*
 * KAME Scope Values
 */
#define OFP_IPV6_ADDR_SCOPE_NODELOCAL	0x01
#define OFP_IPV6_ADDR_SCOPE_INTFACELOCAL	0x01
#define OFP_IPV6_ADDR_SCOPE_LINKLOCAL	0x02
#define OFP_IPV6_ADDR_SCOPE_SITELOCAL	0x05
#define OFP_IPV6_ADDR_SCOPE_ORGLOCAL	0x08	/* just used in this file */
#define OFP_IPV6_ADDR_SCOPE_GLOBAL		0x0e

/*
 * Unicast Scope
 * Note that we must check topmost 10 bits only, not 16 bits (see RFC2373).
 */
#define OFP_IN6_IS_ADDR_LINKLOCAL(a)	\
	(((a)->ofp_s6_addr[0] == 0xfe) && \
	(((a)->ofp_s6_addr[1] & 0xc0) == 0x80))
#define OFP_IN6_IS_ADDR_SITELOCAL(a)	\
	(((a)->ofp_s6_addr[0] == 0xfe) && \
	(((a)->ofp_s6_addr[1] & 0xc0) == 0xc0))

/*
 * Multicast
 */
#define OFP_IN6_IS_ADDR_MULTICAST(a)	((a)->ofp_s6_addr[0] == 0xff)
#define OFP_IPV6_ADDR_MC_SCOPE(a)		((a)->ofp_s6_addr[1] & 0x0f)

/*
 * Multicast Scope
 */
#define OFP_IN6_IS_ADDR_MC_LINKLOCAL(a)	\
	(OFP_IN6_IS_ADDR_MULTICAST(a) &&	\
	 (OFP_IPV6_ADDR_MC_SCOPE(a) == OFP_IPV6_ADDR_SCOPE_LINKLOCAL))

#define OFP_IN6_IS_ADDR_MC_INTFACELOCAL(a)	\
	(OFP_IN6_IS_ADDR_MULTICAST(a) &&	\
	 (OFP_IPV6_ADDR_MC_SCOPE(a) == OFP_IPV6_ADDR_SCOPE_INTFACELOCAL))
/*
 * KAME Scope
 */
#define OFP_IN6_IS_SCOPE_LINKLOCAL(a)	\
	((OFP_IN6_IS_ADDR_LINKLOCAL(a)) ||	\
	 (OFP_IN6_IS_ADDR_MC_LINKLOCAL(a)))

#define OFP_IPV6_RTHDR_LOOSE     0 /* this hop need not be a neighbor. XXX old spec */
#define OFP_IPV6_RTHDR_STRICT    1 /* this hop must be a neighbor. XXX old spec */
#define OFP_IPV6_RTHDR_TYPE_0    0 /* IPv6 routing header type 0 */

/*
 * Argument structure for IPV6_JOIN_GROUP and IPV6_LEAVE_GROUP.
 */
struct ofp_ipv6_mreq {
	struct ofp_in6_addr	ipv6mr_multiaddr;
	unsigned int	ipv6mr_interface;
};

/*
 * IPV6_PKTINFO: Packet information(RFC2292 sec 5)
 */
struct ofp_in6_pktinfo {
	struct ofp_in6_addr	ipi6_addr;	/* src/dst IPv6 address */
	unsigned int	ipi6_ifindex;	/* send/recv interface index */
};

/*
 * Control structure for IPV6_RECVPATHMTU socket option.
 */
struct ofp_ip6_mtuinfo {
	struct ofp_sockaddr_in6 ip6m_addr;	/* or sockaddr_storage? */
	uint32_t ip6m_mtu;
};

int ofp_in6_cksum(odp_packet_t, uint8_t, uint32_t, uint32_t);

#if __GNUC__ >= 4
#pragma GCC visibility pop
#endif

#endif /* __OFP_IN6_H__ */
