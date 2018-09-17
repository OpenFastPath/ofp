/*-
 * Copyright (c) 1982, 1986, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * Copyright (C) 2001 WIDE Project.  All rights reserved.
 * Copyright (c) 2015 Nokia Solutions and Networks
 * Copyright (c) 2015 Enea Software AB
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
 *	@(#)in.c	8.4 (Berkeley) 1/9/95
 */

#include <odp_api.h>
#include "ofpi_in.h"
#include "ofpi_in_pcb.h"
#include "ofpi_udp.h"
#include "ofpi_protosw.h"
#include "ofpi_socketvar.h"
#include "ofpi_sockstate.h"
#include "ofpi_errno.h"
#include "ofpi_portconf.h"
#include "ofpi_socket.h"
#include "ofpi_ioctl.h"

static int in_mask2len(struct ofp_in_addr *);
static void in_len2mask(struct ofp_in_addr *, int);
static int in_lifaddr_ioctl(struct socket *, uint64_t, char *,
			    struct ofp_ifnet *, struct thread *);

#if 0
static VNET_DEFINE(int, sameprefixcarponly);
#define	V_sameprefixcarponly		VNET(sameprefixcarponly)
SYSCTL_VNET_INT(_net_inet_ip, OID_AUTO, same_prefix_carp_only, CTLFLAG_RW,
	&VNET_NAME(sameprefixcarponly), 0,
	"Refuse to create same prefixes on different interfaces");

VNET_DECLARE(struct inpcbinfo, ripcbinfo);
#define	V_ripcbinfo			VNET(ripcbinfo)

VNET_DECLARE(struct arpstat, arpstat);  /* ARP statistics, see if_arp.h */
#define	V_arpstat		VNET(arpstat)
#endif

uint8_t ofp_inetctlerrmap[OFP_PRC_NCMDS] = {
	0,		0,		0,		0,
	0,		OFP_EMSGSIZE,	OFP_EHOSTDOWN,	OFP_EHOSTUNREACH,
	OFP_EHOSTUNREACH,	OFP_EHOSTUNREACH,	OFP_ECONNREFUSED,
	OFP_ECONNREFUSED,
	OFP_EMSGSIZE,	OFP_EHOSTUNREACH,	0,		0,
	0,		0,		OFP_EHOSTUNREACH,	0,
	OFP_ENOPROTOOPT,	OFP_ECONNREFUSED
};

static int
in_mask2len(struct ofp_in_addr *mask)
{
	int x, y;
	uint8_t *p;

	p = (uint8_t *)mask;
	for (x = 0; x < (int)sizeof(*mask); x++) {
		if (p[x] != 0xff)
			break;
	}
	y = 0;
	if (x < (int)sizeof(*mask)) {
		for (y = 0; y < 8; y++) {
			if ((p[x] & (0x80 >> y)) == 0)
				break;
		}
	}
	return (x * 8 + y);
}

static void
in_len2mask(struct ofp_in_addr *mask, int len)
{
	int i;
	uint8_t *p;

	p = (uint8_t *)mask;
	bzero(mask, sizeof(*mask));
	for (i = 0; i < len / 8; i++)
		p[i] = 0xff;
	if (len % 8)
		p[i] = (0xff00 >> (len % 8)) & 0xff;
}

/*
 * Generic internet control operations (ofp_ioctl's).
 *
 * ifp is NULL if not an interface-specific ofp_ioctl.
 */
/* ARGSUSED */
int
ofp_in_control(struct socket *so, uint32_t cmd, char *data, struct ofp_ifnet *ifp,
	   struct thread *td)
{
	register struct ofp_ifreq *ifr = (struct ofp_ifreq *)data;
	struct ofp_in_aliasreq *ifra = (struct ofp_in_aliasreq *)data;
	struct ofp_in_tunreq *treq = (struct ofp_in_tunreq *)data;
	int error;

	/*
	 * Filter out ioctls we implement directly; forward the rest on to
	 * in_lifaddr_ioctl() and ifp->if_ioctl().
	 */
	switch (cmd) {
	case OFP_SIOCGIFCONF:
		ofp_get_interfaces((struct ofp_ifconf *)data);
		return 0;

	case OFP_SIOCGIFTUN:
		if (ifp == NULL)
			return (OFP_EINVAL);

		treq->iftun_addr.sin_addr.s_addr = ifp->ip_addr_info[0].ip_addr;
		treq->iftun_p2p_addr.sin_addr.s_addr = ifp->ip_p2p;
		treq->iftun_local_addr.sin_addr.s_addr = ifp->ip_local;
		treq->iftun_remote_addr.sin_addr.s_addr = ifp->ip_remote;
		treq->iftun_vrf = ifp->vrf;
		return 0;

	case OFP_SIOCAIFADDR:
	case OFP_SIOCDIFADDR:
	case OFP_SIOCGIFADDR:
	case OFP_SIOCGIFBRDADDR:
	case OFP_SIOCGIFDSTADDR:
	case OFP_SIOCGIFNETMASK:
	case OFP_SIOCSIFADDR:
	case OFP_SIOCSIFBRDADDR:
	case OFP_SIOCSIFDSTADDR:
	case OFP_SIOCSIFNETMASK:
	case OFP_SIOCGIFFIB:
	case OFP_SIOCSIFFIB:
		break;

	case OFP_SIOCALIFADDR:
		if (ifp == NULL)
			return (OFP_EINVAL);
		return in_lifaddr_ioctl(so, cmd, data, ifp, td);

	case OFP_SIOCDLIFADDR:
		if (ifp == NULL)
			return (OFP_EINVAL);
		return in_lifaddr_ioctl(so, cmd, data, ifp, td);

	case OFP_SIOCGLIFADDR:
		if (ifp == NULL)
			return (OFP_EINVAL);
		return in_lifaddr_ioctl(so, cmd, data, ifp, td);

	default:
		return (OFP_EOPNOTSUPP);
	}

	if (ifp == NULL)
		return (OFP_EADDRNOTAVAIL);

	error = 0;

	uint32_t if_addr = ifp->ip_addr_info[0].ip_addr;
	uint32_t if_bcast = ifp->ip_addr_info[0].bcast_addr;
	uint32_t if_p2p = ifp->ip_p2p;
	int if_masklen = ifp->ip_addr_info[0].masklen;
	int vrf = ifp->vrf;

	switch (cmd) {
	case OFP_SIOCAIFADDR:
	case OFP_SIOCSIFADDR:
		if_addr = ifra->ifra_addr.sin_addr.s_addr;
		if_masklen = in_mask2len(&ifra->ifra_mask.sin_addr);
		break;
	case OFP_SIOCSIFNETMASK:
		if_masklen = in_mask2len(&ifra->ifra_mask.sin_addr);
		break;
	case OFP_SIOCSIFDSTADDR:
		if_p2p = ifra->ifra_addr.sin_addr.s_addr;
		break;
	case OFP_SIOCSIFBRDADDR:
		if_bcast = ((struct ofp_sockaddr_in *)
			    &ifr->ifr_broadaddr)->sin_addr.s_addr;
		break;
	case OFP_SIOCSIFFIB:
		vrf = ifr->ifr_fib;
		break;
	}

	switch (cmd) {
	case OFP_SIOCAIFADDR:
	case OFP_SIOCSIFADDR:
	case OFP_SIOCSIFNETMASK:
	case OFP_SIOCSIFFIB:
		if (ofp_if_type(ifp) == OFP_IFT_GRE) {
			ofp_config_interface_up_tun
				(ifp->port, ifp->vlan,
				 vrf, ifp->ip_local,
				 ifp->ip_remote, if_p2p,
				 if_addr, if_masklen);
		} else {
			ofp_config_interface_down(ifp->port, ifp->vlan);
			ofp_config_interface_up_v4(ifp->port, ifp->vlan, vrf,
						     if_addr, if_masklen);
		}
		break;
	case OFP_SIOCDIFADDR:
		if (ifra->ifra_addr.sin_family == OFP_AF_INET) {
			ofp_config_interface_down(ifp->port, ifp->vlan);
		}
		break;
	case OFP_SIOCSIFDSTADDR:
		ifp->ip_p2p = if_p2p;
		break;
	case OFP_SIOCSIFBRDADDR:
		ifp->ip_addr_info[0].bcast_addr = if_bcast;
		break;
	}

	/*
	 * Most paths in this switch return directly or via out.  Only paths
	 * that remove the address break in order to hit common removal code.
	 */
	switch (cmd) {
	case OFP_SIOCGIFADDR:
		((struct ofp_sockaddr_in *)&ifr->ifr_addr)->sin_addr.s_addr
			= ifp->ip_addr_info[0].ip_addr;
		goto out;

	case OFP_SIOCGIFBRDADDR:
		((struct ofp_sockaddr_in *)&ifr->ifr_dstaddr)->sin_addr.s_addr
			= ifp->ip_addr_info[0].bcast_addr;
		goto out;

	case OFP_SIOCGIFDSTADDR:
#if 0 // HJo
		if ((ifp->if_flags & IFF_POINTOPOINT) == 0) {
			error = OFP_EINVAL;
			goto out;
		}
#endif
		((struct ofp_sockaddr_in *)&ifr->ifr_dstaddr)->sin_addr.s_addr
			= ifp->ip_p2p;
		goto out;

	case OFP_SIOCGIFNETMASK:
		((struct ofp_sockaddr_in *)&ifr->ifr_addr)->sin_addr.s_addr =
			odp_cpu_to_be_32(0xFFFFFFFFULL << (32 - ifp->ip_addr_info[0].masklen));
		goto out;

	case OFP_SIOCGIFFIB:
		ifr->ifr_fib = ifp->vrf;
		goto out;

	case OFP_SIOCSIFADDR:
	case OFP_SIOCSIFBRDADDR:
	case OFP_SIOCSIFDSTADDR:
	case OFP_SIOCSIFNETMASK:
	case OFP_SIOCAIFADDR:
	case OFP_SIOCDIFADDR:
	case OFP_SIOCSIFFIB:
		goto out;

	default:
		panic("ofp_in_control: unsupported ofp_ioctl");
	}

out:
	return (error);
}

/*
 * SIOC[GAD]LIFADDR.
 *	SIOCGLIFADDR: get first address. (?!?)
 *	SIOCGLIFADDR with IFLR_PREFIX:
 *		get first address that matches the specified prefix.
 *	SIOCALIFADDR: add the specified address.
 *	SIOCALIFADDR with IFLR_PREFIX:
 *		OFP_EINVAL since we can't deduce hostid part of the address.
 *	SIOCDLIFADDR: delete the specified address.
 *	SIOCDLIFADDR with IFLR_PREFIX:
 *		delete the first address that matches the specified prefix.
 * return values:
 *	OFP_EINVAL on invalid parameters
 *	OFP_EADDRNOTAVAIL on prefix match failed/specified address not found
 *	other values may be returned from in_ioctl()
 */
static int
in_lifaddr_ioctl(struct socket *so, uint64_t cmd, char * data,
		 struct ofp_ifnet *ifp, struct thread *td)
{
	struct ofp_if_laddrreq *iflr = (struct ofp_if_laddrreq *)data;

	/* sanity checks */
	if (data == NULL || ifp == NULL) {
		panic("invalid argument to in_lifaddr_ioctl");
		/*NOTRECHED*/
	}

	switch (cmd) {
	case OFP_SIOCGLIFADDR:
		/* address must be specified on GET with IFLR_PREFIX */
		if ((iflr->flags & IFLR_PREFIX) == 0)
			break;
		/*FALLTHROUGH*/
	case OFP_SIOCALIFADDR:
	case OFP_SIOCDLIFADDR:
		/* address must be specified on ADD and DELETE */
		if (iflr->addr.ss_family != OFP_AF_INET)
			return (OFP_EINVAL);
		if (iflr->addr.ss_len != sizeof(struct ofp_sockaddr_in))
			return (OFP_EINVAL);
		/* XXX need improvement */
		if (iflr->dstaddr.ss_family
		 && iflr->dstaddr.ss_family != OFP_AF_INET)
			return (OFP_EINVAL);
		if (iflr->dstaddr.ss_family
		 && iflr->dstaddr.ss_len != sizeof(struct ofp_sockaddr_in))
			return (OFP_EINVAL);
		break;
	default: /*shouldn't happen*/
		return (OFP_EOPNOTSUPP);
	}
	if (sizeof(struct ofp_in_addr) * 8 < iflr->prefixlen)
		return (OFP_EINVAL);

	switch (cmd) {
	case OFP_SIOCALIFADDR:
	    {
		struct ofp_in_aliasreq ifra;

		if (iflr->flags & IFLR_PREFIX)
			return (OFP_EINVAL);

		/* copy args to in_aliasreq, perform ofp_ioctl(SIOCAIFADDR). */
		bzero(&ifra, sizeof(ifra));
		bcopy(iflr->iflr_name, ifra.ifra_name,
			sizeof(ifra.ifra_name));

		bcopy(&iflr->addr, &ifra.ifra_addr, iflr->addr.ss_len);

		if (iflr->dstaddr.ss_family) {	/*XXX*/
			bcopy(&iflr->dstaddr, &ifra.ifra_dstaddr,
				iflr->dstaddr.ss_len);
		}

		ifra.ifra_mask.sin_family = OFP_AF_INET;
		ifra.ifra_mask.sin_len = sizeof(struct ofp_sockaddr_in);
		in_len2mask(&ifra.ifra_mask.sin_addr, iflr->prefixlen);

		return (ofp_in_control(so, OFP_SIOCAIFADDR, (char *)&ifra, ifp, td));
	    }
	case OFP_SIOCGLIFADDR:
	case OFP_SIOCDLIFADDR:
		break;
	}

	return (OFP_EOPNOTSUPP);	/*just for safety*/
}
