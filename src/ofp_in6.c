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
 *	$KAME: in6.c,v 1.259 2002/01/21 11:37:50 keiichi Exp $
 */

/*-
 * Copyright (c) 1982, 1986, 1991, 1993
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
 *	@(#)in.c	8.2 (Berkeley) 11/15/93
 */

#include "ofpi_in.h"
#include "ofpi_in6.h"
#include "ofpi_ip6_var.h"
#include "ofpi_socket.h"
#include "ofpi_protosw.h"
#include "api/ofp_types.h"
#include "api/ofp_route_arp.h"
#include "api/ofp_errno.h"
#include "ofpi_vnet.h"

VNET_DEFINE(int, ip6_use_defzone) = 1;

/*
 * Definitions of some costant IP6 addresses.
 */
const struct ofp_in6_addr ofp_in6addr_any = OFP_IN6ADDR_ANY_INIT;
const struct ofp_in6_addr ofp_in6addr_loopback =
	OFP_IN6ADDR_LOOPBACK_INIT;
const struct ofp_in6_addr ofp_in6addr_nodelocal_allnodes =
	OFP_IN6ADDR_NODELOCAL_ALLNODES_INIT;
const struct ofp_in6_addr ofp_in6addr_linklocal_allnodes =
	OFP_IN6ADDR_LINKLOCAL_ALLNODES_INIT;
const struct ofp_in6_addr ofp_in6addr_linklocal_allrouters =
	OFP_IN6ADDR_LINKLOCAL_ALLROUTERS_INIT;
const struct ofp_in6_addr ofp_in6addr_linklocal_allv2routers =
	OFP_IN6ADDR_LINKLOCAL_ALLV2ROUTERS_INIT;

const struct ofp_in6_addr ofp_in6mask0 = OFP_IN6MASK0;
const struct ofp_in6_addr ofp_in6mask32 = OFP_IN6MASK32;
const struct ofp_in6_addr ofp_in6mask64 = OFP_IN6MASK64;
const struct ofp_in6_addr ofp_in6mask96 = OFP_IN6MASK96;
const struct ofp_in6_addr ofp_in6mask128 = OFP_IN6MASK128;

const struct ofp_sockaddr_in6 ofp_sa6_any = {
	sizeof(ofp_sa6_any), OFP_AF_INET6, 0, 0, OFP_IN6ADDR_ANY_INIT, 0};

/*
 * Convert sockaddr_in6 to sockaddr_in.  Original sockaddr_in6 must be
 * v4 mapped addr or v4 compat addr
 */
void
ofp_in6_sin6_2_sin(struct ofp_sockaddr_in *sin, struct ofp_sockaddr_in6 *sin6)
{

	bzero(sin, sizeof(*sin));
	sin->sin_len = sizeof(struct ofp_sockaddr_in);
	sin->sin_family = OFP_AF_INET;
	sin->sin_port = sin6->sin6_port;
	sin->sin_addr.s_addr = sin6->sin6_addr.ofp_s6_addr32[3];
}

/* Convert sockaddr_in to sockaddr_in6 in v4 mapped addr format. */
void
ofp_in6_sin_2_v4mapsin6(struct ofp_sockaddr_in *sin, struct ofp_sockaddr_in6 *sin6)
{
	bzero(sin6, sizeof(*sin6));
	sin6->sin6_len = sizeof(struct ofp_sockaddr_in6);
	sin6->sin6_family = OFP_AF_INET6;
	sin6->sin6_port = sin->sin_port;
	sin6->sin6_addr.ofp_s6_addr32[0] = 0;
	sin6->sin6_addr.ofp_s6_addr32[1] = 0;
	sin6->sin6_addr.ofp_s6_addr32[2] = OFP_IPV6_ADDR_INT32_SMP;
	sin6->sin6_addr.ofp_s6_addr32[3] = sin->sin_addr.s_addr;
}

/* Convert sockaddr_in6 into sockaddr_in. */
void
ofp_in6_sin6_2_sin_in_sock(struct ofp_sockaddr *nam)
{
	struct ofp_sockaddr_in *sin_p;
	struct ofp_sockaddr_in6 sin6;

	/*
	 * Save original sockaddr_in6 addr and convert it
	 * to sockaddr_in.
	 */
	sin6 = *(struct ofp_sockaddr_in6 *)nam;
	sin_p = (struct ofp_sockaddr_in *)nam;
	ofp_in6_sin6_2_sin(sin_p, &sin6);
}

uint32_t
ofp_ip6_randomid(void)
{
	uint32_t result  = 0;

	odp_random_data((uint8_t *)&result, sizeof(result), 0);

	return result;
}

uint32_t
ofp_ip6_randomflowlabel(void)
{
	uint32_t result  = 0;

	odp_random_data((uint8_t *)&result, sizeof(result), 0);

	return result & 0xfffff;
}

int
ofp_in6_selectsrc(struct ofp_sockaddr_in6 *dstsock, void *opts,
    struct inpcb *inp, void *ro, struct ofp_ucred *cred,
    struct ofp_ifnet **ifpp, struct ofp_in6_addr *srcp)
{
	struct ofp_nh6_entry* nh;
	struct ofp_ifnet *ifp = NULL;

	(void)opts;
	(void)ro;
	(void)cred;

	/* if interface is specified and has IPv6 address, just use it*/
	if(ifpp) {
		if(*ifpp != NULL && ofp_ip6_is_set((*ifpp)->ip6_addr)) {
			memcpy(srcp->ofp_s6_addr, (*ifpp)->ip6_addr, 16);
			return 0;
		}
		*ifpp = NULL;
	}

	/*
	 * if the socket has already bound the source, just use it.
	 */
	if (inp != NULL && !OFP_IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr)) {
		memcpy(srcp, &inp->in6p_laddr, sizeof(*srcp));
		return (0);
	}

	/*
	 * if destination is loopback then source is loopback too.
	 */
	 if (OFP_IN6_IS_ADDR_LOOPBACK(&(dstsock->sin6_addr))) {
	 	*srcp = dstsock->sin6_addr;
	 	return 0;
	 }

	/*
	 * If the address is not specified, choose the best one based on
	 * the outgoing interface and the destination address.
	 */
	/* get the outgoing interface */

	nh = ofp_get_next_hop6(0, dstsock->sin6_addr.ofp_s6_addr, NULL);
	if (!nh) {
		OFP_ERR("route not found\n");
		return OFP_EHOSTUNREACH;
	}

	ifp = ofp_get_ifnet(nh->port, nh->vlan);
	if (ifp && ofp_ip6_is_set(ifp->ip6_addr)) {
		memcpy(srcp->ofp_s6_addr, ifp->ip6_addr, 16);
		if(ifpp)
			*ifpp = ifp;
		return 0;
	}

	return OFP_EHOSTUNREACH;
}

/*
 * Return the scope identifier or zero.
 */
uint16_t
ofp_in6_getscope(struct ofp_in6_addr *in6)
{

	if (OFP_IN6_IS_SCOPE_LINKLOCAL(in6) ||
		OFP_IN6_IS_ADDR_MC_INTFACELOCAL(in6))
		return (in6->ofp_s6_addr16[1]);

	return (0);
}

/*
 * Clear the embedded scope identifier.  Return 0 if the original address
 * is intact; return non 0 if the address is modified.
 */
int ofp_in6_clearscope(struct ofp_in6_addr *in6)
{
	int modified = 0;

	if (OFP_IN6_IS_SCOPE_LINKLOCAL(in6) ||
		OFP_IN6_IS_ADDR_MC_INTFACELOCAL(in6)) {
		if (in6->ofp_s6_addr16[1] != 0)
			modified = 1;
		in6->ofp_s6_addr16[1] = 0;
	}

	return modified;
}


/*
 * System control for IP6
 */

uint8_t ofp_inet6ctlerrmap[OFP_PRC_NCMDS] = {
	0,		0,		0,		0,
	0,		OFP_EMSGSIZE,	OFP_EHOSTDOWN,	OFP_EHOSTUNREACH,
	OFP_EHOSTUNREACH,	OFP_EHOSTUNREACH,	OFP_ECONNREFUSED,
	OFP_ECONNREFUSED,
	OFP_EMSGSIZE,	OFP_EHOSTUNREACH,	0,		0,
	0,		0,		0,		0,
	OFP_ENOPROTOOPT
};
