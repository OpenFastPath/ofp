/*-
 * Copyright (c) 1982, 1986, 1988, 1990, 1993, 1995
 *	The Regents of the University of California.
 * Copyright (c) 2008 Robert N. M. Watson
 * Copyright (c) 2010-2011 Juniper Networks, Inc.
 * Copyright (c) 2014, Nokia
 * Copyright (c) 2014, Enea Software AB
 * All rights reserved.
 *
 * Portions of this software were developed by Robert N. M. Watson under
 * contract to Juniper Networks, Inc.
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
 *	@(#)udp_usrreq.c	8.6 (Berkeley) 5/23/95
 */

#include <strings.h>
#include <string.h>

#include "ofpi_errno.h"
#include "odp.h"

#include "ofpi_errno.h"
#include "ofpi_tree.h"
#include "ofpi_in.h"
#include "ofpi_ip.h"
#include "ofpi_ip6.h"
#include "ofpi_udp.h"
#include "ofpi_icmp.h"
//#include "ofpi_socket.h"

//#include "ofp_packet.h"

#include "ofpi_sysctl.h"
#include "ofpi_in_pcb.h"
#include "ofpi_udp_var.h"
#include "ofpi_socketvar.h"
#include "ofpi_ip_var.h"
#include "ofpi_sockbuf.h"
#include "ofpi_socket.h"
#include "ofpi_sockstate.h"
#include "ofpi_protosw.h"
#include "ofpi_ethernet.h"
#include "ofpi_ioctl.h"
#include "ofpi_in_var.h"
#include "ofpi_vxlan.h"

#include "ofpi_pkt_processing.h"
#include "ofpi_log.h"
#include "ofpi_debug.h"
#include "ofpi_hook.h"
#include "ofpi_util.h"

extern odp_pool_t ofp_packet_pool;

#define UDPSTAT_INC(x)
#define log(...)

#ifndef UDBHASHSIZE
#define	UDBHASHSIZE	128
#endif

#define	CSUM_DATA_VALID		0x0400		/* csum_data field is valid */
#define	CSUM_PSEUDO_HDR		0x0800		/* csum_data has pseudo hdr */

#define	M_BCAST		0x00000200 /* send/received as link-level broadcast */
#define	M_MCAST		0x00000400 /* send/received as link-level multicast */


int		ofp_udp_cksum = 1;
int		ofp_udp_log_in_vain = 0;
int		ofp_udp_blackhole = 0;
uint64_t	ofp_udp_sendspace = 9216;		/* really max datagram size */
uint64_t	ofp_udp_recvspace = 40 * (1024 + sizeof(struct ofp_sockaddr_in6));
int		ofp_max_linkhdr;
VNET_DEFINE(int, ofp_ip_defttl) = 255;

struct inpcbhead ofp_udb;		/* from udp_var.h */
struct inpcbinfo ofp_udbinfo;
struct ofp_udpstat ofp_udpstat;		/* from udp_var.h */

static void	udp_detach(struct socket *so);
static int	udp_output(struct inpcb *, odp_packet_t , struct ofp_sockaddr *,
		    odp_packet_t , struct thread *);


OFP_SYSCTL_INT(_net_inet_udp, UDPCTL_CHECKSUM, checksum, OFP_CTLFLAG_RW,
	   &ofp_udp_cksum, 0, "compute udp checksum");

OFP_SYSCTL_INT(_net_inet_udp, OFP_OID_AUTO, log_in_vain, OFP_CTLFLAG_RW,
	   &ofp_udp_log_in_vain, 0, "Log all incoming UDP packets");

OFP_SYSCTL_INT(_net_inet_udp, OFP_OID_AUTO, blackhole, OFP_CTLFLAG_RW,
	   &ofp_udp_blackhole, 0,
	   "Do not send port unreachables for refused connects");

OFP_SYSCTL_ULONG(_net_inet_udp, UDPCTL_MAXDGRAM, maxdgram, OFP_CTLFLAG_RW,
	     &ofp_udp_sendspace, 0, "Maximum outgoing UDP datagram size");

OFP_SYSCTL_ULONG(_net_inet_udp, UDPCTL_RECVSPACE, recvspace, OFP_CTLFLAG_RW,
	     &ofp_udp_recvspace, 0, "Maximum space for incoming UDP datagrams");

static int
udp_inpcb_init(void *mem, int size, int flags)
{
	struct inpcb *inp;

	(void)size;
	(void)flags;

	inp = mem;
	INP_LOCK_INIT(inp, "inp", "udpinp");
	return (0);
}

void
ofp_udp_init(void)
{
	INP_INFO_LOCK_INIT(&ofp_udbinfo, 0);

	ofp_in_pcbinfo_init(&ofp_udbinfo, "udp", &ofp_udb, UDBHASHSIZE, UDBHASHSIZE,
			"udp_inpcb", udp_inpcb_init, NULL, 0);
}

void
ofp_udp_destroy(void)
{
	struct inpcb *inp, *inp_temp;

	OFP_LIST_FOREACH_SAFE(inp, ofp_udbinfo.ipi_listhead, inp_list,
			inp_temp) {
		if (inp->inp_socket) {
			ofp_sbdestroy(&inp->inp_socket->so_snd,
					inp->inp_socket);
			ofp_sbdestroy(&inp->inp_socket->so_rcv,
					inp->inp_socket);
		}

		uma_zfree(ofp_udbinfo.ipi_zone, inp);
	}

	ofp_in_pcbinfo_destroy(&ofp_udbinfo);
	uma_zdestroy(ofp_udbinfo.ipi_zone);
}

/*
 * Subroutine of ofp_udp_input(), which appends the provided mbuf chain to the
 * passed pcb/socket.  The caller must provide a sockaddr_in via udp_in that
 * contains the source address.  If the socket ends up being an IPv6 socket,
 * udp_append() will convert to a sockaddr_in6 before passing the address
 * into the socket code.
 */
static void
udp_append(struct inpcb *inp, struct ofp_ip *ip, odp_packet_t n, int off,
	   struct ofp_sockaddr_in *udp_in)
{
	struct ofp_sockaddr *append_sa;
	struct socket *so;
	odp_packet_t opts = ODP_PACKET_INVALID;
	struct ofp_sockaddr_in6 udp_in6;
	struct udpcb *up;

	(void)ip;
	(void)udp_in6;

	INP_LOCK_ASSERT(inp);

	/*
	 * Engage the tunneling protocol.
	 */
	up = intoudpcb(inp);
	if (up->u_tun_func != NULL) {
		(*up->u_tun_func)(n, off, inp);
		return;
	}

	if (n == ODP_PACKET_INVALID) {
		OFP_ERR("n == ODP_PACKET_INVALID");
		return;
	}

	off += sizeof(struct ofp_udphdr);

	if (inp->inp_flags & INP_CONTROLOPTS ||
	    inp->inp_socket->so_options & (OFP_SO_TIMESTAMP | OFP_SO_BINTIME)) {
#ifdef _INET6
		if (inp->inp_vflag & INP_IPV6)
			(void)ip6_savecontrol_v4(inp, n, &opts, NULL);
		else
			ip_savecontrol(inp, &opts, ip, n);
#endif
	}
#ifdef _INET6
	if (inp->inp_vflag & INP_IPV6) {
		bzero(&udp_in6, sizeof(udp_in6));
		udp_in6.sin6_len = sizeof(udp_in6);
		udp_in6.sin6_family = OFP_AF_INET6;
		in6_sin_2_v4mapsin6(udp_in, &udp_in6);
		append_sa = (struct ofp_sockaddr *)&udp_in6;
	} else
#endif
		append_sa = (struct ofp_sockaddr *)udp_in;
	//odp_packet_seg_pull_head(n, odp_packet_seg(n, 0), off);
	//odp_packet_adj(n, off);

	so = inp->inp_socket;

	/* save sender data where L2 & L3 headers used to be */
	memcpy(odp_packet_l2_ptr(n, NULL), append_sa, append_sa->sa_len);

	/* Offer to event function */
	if (packet_accepted_as_event(so, n))
		return;

	SOCKBUF_LOCK(&so->so_rcv);
	if (ofp_sbappendaddr_locked(&so->so_rcv, n, opts) == 0) {
		SOCKBUF_UNLOCK(&so->so_rcv);
		odp_packet_free(n);
		if (opts != ODP_PACKET_INVALID)
			odp_packet_free(opts);
		UDPSTAT_INC(udps_fullsock);
	} else {
		sorwakeup_locked(so);
	}
}

/*
 * Return 1 if the address might be a local broadcast address.
 */
static int
ofp_in_broadcast(struct ofp_in_addr in, struct ofp_ifnet *ifp)
{
	if (in.s_addr == OFP_INADDR_BROADCAST ||
	    in.s_addr == OFP_INADDR_ANY)
		return 1;

	/* HJo FIX:
	 * Look if address is bcast addr of an interface.
	 */
	(void)ifp;
	return 0;
}

enum ofp_return_code
ofp_udp_input(odp_packet_t m, int off)
{

	int iphlen = off;
	int protocol = IS_IPV4_UDP;
	struct ofp_ip *ip;
	struct ofp_udphdr *uh;
	struct ofp_ifnet *ifp;
	struct inpcb *inp;
	//int len;
	enum ofp_return_code res;
#ifndef SP
	struct ofp_ip save_ip;
#endif /* SP*/
	struct ofp_sockaddr_in udp_in;

	OFP_HOOK(OFP_HOOK_LOCAL, m, &protocol, &res);
	if (res != OFP_PKT_CONTINUE)
		return res;

	OFP_HOOK(OFP_HOOK_LOCAL_UDPv4, m, NULL, &res);
	if (res != OFP_PKT_CONTINUE)
		return res;

	/* Offer to VXLAN handler. */
	res = ofp_vxlan_input(m);
	if (res != OFP_PKT_CONTINUE)
		return res;

	ifp = odp_packet_user_ptr(m);
	UDPSTAT_INC(udps_ipackets);

	/*
	 * Strip IP options, if any; should skip this, make available to
	 * user, and use on returned packets, but we don't yet have a way to
	 * check the checksum with options still present.
	 */
#if 0 /* HJo: FIX */
	if (iphlen > sizeof (struct ofp_ip)) {
		ip_stripoptions(m, (odp_packet_t )0);
		iphlen = sizeof(struct ofp_ip);
	}
#endif
	/*
	 * Get IP and UDP header together in first mbuf.
	 */
	ip = (struct ofp_ip *)odp_packet_l3_ptr(m, NULL);
	if (odp_packet_len(m) < iphlen + sizeof(struct ofp_udphdr)) {
#if 0
		if ((m = odp_packet_ensure_contiguous(m, iphlen +
			      sizeof(struct ofp_udphdr))) == 0) {
			UDPSTAT_INC(udps_hdrops);
			return;
		}
		ip = (struct ofp_ip *)odp_packet_data(m);
#else
		return OFP_PKT_CONTINUE;
#endif
	}
	uh = (struct ofp_udphdr *)((char *)ip + iphlen);

	/*
	 * Destination port of 0 is illegal, based on RFC768.
	 */
	if (uh->uh_dport == 0)
		goto badunlocked;

	/*
	 * Construct ofp_sockaddr format source address.  Stuff source address
	 * and datagram in user buffer.
	 */
	bzero(&udp_in, sizeof(udp_in));
	udp_in.sin_len = sizeof(udp_in);
	udp_in.sin_family = OFP_AF_INET;
	udp_in.sin_port = uh->uh_sport;
	udp_in.sin_addr = ip->ip_src;

	/*
	 * Make mbuf data length reflect UDP length.  If not enough data to
	 * reflect UDP length, drop.
	 */
#if 0
	len = odp_be_to_cpu_16((uint16_t)uh->uh_ulen);

	if (ip->ip_len != len) {
		if (len > ip->ip_len || len < sizeof(struct ofp_udphdr)) {
			UDPSTAT_INC(udps_badlen);
			goto badunlocked;
		}
		//odp_packet_seg_pull_head(m, odp_packet_seg(m, 0), len - ip->ip_len);
		odp_packet_adj(m, len - ip->ip_len);
		/* ip->ip_len = len; */
	}
#endif

#ifndef SP
	/*
	 * Save a copy of the IP header in case we want restore it for
	 * sending an ICMP error message in response.
	 */
	if (!ofp_udp_blackhole)
		save_ip = *ip;
	else
		memset(&save_ip, 0, sizeof(save_ip));
#endif /*SP*/
	/*
	 * Checksum extended UDP header and data.
	 */

	if (uh->uh_sum) {
#ifdef OFP_IPv4_UDP_CSUM_VALIDATE
#if 1
		uint16_t uh_sum;

		uh_sum = ofp_in4_cksum(m);
		if (uh_sum)
			goto badunlocked;
#else
		uint16_t uh_sum;

		if (odp_packet_csum_flags(m) & CSUM_DATA_VALID) {
			if (odp_packet_csum_flags(m) & CSUM_PSEUDO_HDR)
				uh_sum = odp_packet_csum_data(m);
			else
				uh_sum = in_pseudo(ip->ip_src.s_addr,
				    ip->ip_dst.s_addr, odp_cpu_to_be_32((uint16_t)len +
				    odp_packet_csum_data(m) + OFP_IPPROTO_UDP));
			uh_sum ^= 0xffff;
		} else {
			char b[9];

			bcopy(((struct ipovly *)ip)->ih_x1, b, 9);
			bzero(((struct ipovly *)ip)->ih_x1, 9);
			((struct ipovly *)ip)->ih_len = uh->uh_ulen;
			uh_sum = in_cksum(m, len + sizeof (struct ofp_ip));
			bcopy(b, ((struct ipovly *)ip)->ih_x1, 9);
		}
		if (uh_sum) {
			UDPSTAT_INC(udps_badsum);
			odp_packet_free(m));
			return(0);
		}
#endif
#endif /*OFP_IPv4_UDP_CSUM_VALIDATE*/
	} else {
		UDPSTAT_INC(udps_nosum);
	}

	if (OFP_IN_MULTICAST(odp_be_to_cpu_32(ip->ip_dst.s_addr)) ||
	    ofp_in_broadcast(ip->ip_dst, ifp)) {
		struct inpcb *last;
		struct ofp_ip_moptions *imo;

		INP_INFO_RLOCK(&ofp_udbinfo);
		last = NULL;
		OFP_LIST_FOREACH(inp, &ofp_udb, inp_list) {
			if (inp->inp_lport != uh->uh_dport)
				continue;
#ifdef _INET6
			if ((inp->inp_vflag & INP_IPV4) == 0)
				continue;
#endif
			if (inp->inp_laddr.s_addr != OFP_INADDR_ANY &&
			    inp->inp_laddr.s_addr != ip->ip_dst.s_addr)
				continue;
			if (inp->inp_faddr.s_addr != OFP_INADDR_ANY &&
			    inp->inp_faddr.s_addr != ip->ip_src.s_addr)
				continue;
			if (inp->inp_fport != 0 &&
			    inp->inp_fport != uh->uh_sport)
				continue;

			INP_RLOCK(inp);

			/*
			 * XXXRW: Because we weren't holding either the inpcb
			 * or the hash lock when we checked for a match
			 * before, we should probably recheck now that the
			 * inpcb lock is held.
			 */

			/*
			 * Handle socket delivery policy for any-source
			 * and source-specific multicast. [RFC3678]
			 */
			imo = inp->inp_moptions;
			if (OFP_IN_MULTICAST(odp_be_to_cpu_32(ip->ip_dst.s_addr))) {
				struct ofp_sockaddr_in	 group;
				int			 blocked;
				if (imo == NULL) {
					INP_RUNLOCK(inp);
					continue;
				}
				bzero(&group, sizeof(struct ofp_sockaddr_in));
				group.sin_len = sizeof(struct ofp_sockaddr_in);
				group.sin_family = OFP_AF_INET;
				group.sin_addr = ip->ip_dst;

				blocked = ofp_imo_multi_filter(imo, ifp,
					(struct ofp_sockaddr *)&group,
					(struct ofp_sockaddr *)&udp_in);
				if (blocked != OFP_MCAST_PASS) {
					if (blocked == OFP_MCAST_NOTGMEMBER)
						IPSTAT_INC(ips_notmember);
					if (blocked == OFP_MCAST_NOTSMEMBER ||
					    blocked == OFP_MCAST_MUTED) {
						UDPSTAT_INC(udps_filtermcast);
					}
					INP_RUNLOCK(inp);
					continue;
				}
			}

			if (last != NULL) {
				odp_packet_t n;

				n = odp_packet_copy(m, ofp_packet_pool);
				udp_append(last, ip, n, iphlen, &udp_in);
				INP_RUNLOCK(last);
			}
			last = inp;
			/*
			 * Don't look for additional matches if this one does
			 * not have either the OFP_SO_REUSEPORT or OFP_SO_REUSEADDR
			 * socket options set.  This heuristic avoids
			 * searching through all pcbs in the common case of a
			 * non-shared port.  It assumes that an application
			 * will never clear these options after setting them.
			 */
			if ((last->inp_socket->so_options &
			    (OFP_SO_REUSEPORT|OFP_SO_REUSEADDR)) == 0)
				break;
		}

		if (last == NULL) {
			/*
			 * No matching pcb found; discard datagram.  (No need
			 * to send an ICMP Port Unreachable for a broadcast
			 * or multicast datgram.)
			 */
			UDPSTAT_INC(udps_noportbcast);
			if (inp)
				INP_RUNLOCK(inp);
			INP_INFO_RUNLOCK(&ofp_udbinfo);
			goto badunlocked;
		}
		udp_append(last, ip, m, iphlen, &udp_in);
		INP_RUNLOCK(last);
		INP_INFO_RUNLOCK(&ofp_udbinfo);
		return OFP_PKT_PROCESSED;
	} /* Multicast */

	/*
	 * Locate pcb for datagram.
	 */
	inp = ofp_in_pcblookup(&ofp_udbinfo, ip->ip_src, uh->uh_sport,
			   ip->ip_dst, uh->uh_dport, INPLOOKUP_WILDCARD |
			   INPLOOKUP_RLOCKPCB, ifp);

	if (inp == NULL) {
		if (ofp_udp_log_in_vain) {
			/* LOG */
			OFP_INFO("Connection attempt to UDP %s:%d from %s:%d",
				  ofp_print_ip_addr(ip->ip_dst.s_addr),
				  odp_be_to_cpu_16(uh->uh_dport),
				  ofp_print_ip_addr(ip->ip_src.s_addr),
				  odp_be_to_cpu_16(uh->uh_sport));
		}
		UDPSTAT_INC(udps_noport);
		/* HJo
		if (odp_packet_flags(m) & (M_BCAST | M_MCAST)) {
			UDPSTAT_INC(udps_noportbcast);
			goto badunlocked;
		}
		*/
		if (ofp_udp_blackhole)
			goto badunlocked;
#if 0
		if (badport_bandlim(BANDLIM_ICMP_UNREACH) < 0)
			goto badunlocked;
#endif

#ifndef SP
		*ip = save_ip;
		ip->ip_len += iphlen;
		ofp_icmp_error(m, OFP_ICMP_UNREACH, OFP_ICMP_UNREACH_PORT, 0, 0);
		return OFP_PKT_PROCESSED;
#else
		return OFP_PKT_CONTINUE;
#endif /* SP */
	}

	/*
	 * Check the minimum TTL for socket.
	 */
	INP_RLOCK_ASSERT(inp);
	if (inp->inp_ip_minttl && inp->inp_ip_minttl > ip->ip_ttl) {
		INP_RUNLOCK(inp);
		odp_packet_free(m);
		return OFP_PKT_PROCESSED;
	}

	udp_append(inp, ip, m, iphlen, &udp_in);
	INP_RUNLOCK(inp);
	return OFP_PKT_PROCESSED;

badunlocked:
	OFP_WARN("badunlocked");
	return OFP_PKT_DROP;
}

/*
 * Notify a udp user of an asynchronous error; just wake up so that they can
 * collect error status.
 */
struct inpcb *
ofp_udp_notify(struct inpcb *inp, int err)
{
	/*
	 * While ofp_udp_ctlinput() always calls ofp_udp_notify() with a read lock
	 * when invoking it directly, in_pcbnotifyall() currently uses write
	 * locks due to sharing code with TCP.  For now, accept either a read
	 * or a write lock, but a read lock is sufficient.
	 */
	INP_LOCK_ASSERT(inp);

	inp->inp_socket->so_error = err;
	sorwakeup(inp->inp_socket);
	sowwakeup(inp->inp_socket);
	return (inp);
}

void
ofp_udp_ctlinput(int cmd, struct ofp_sockaddr *sa, void *vip)
{
	struct ofp_ip *ip = vip;
	struct ofp_udphdr *uh;
	struct ofp_in_addr faddr;
	struct inpcb *inp;

	faddr = ((struct ofp_sockaddr_in *)sa)->sin_addr;
	if (sa->sa_family != OFP_AF_INET || faddr.s_addr == OFP_INADDR_ANY)
		return;

	/*
	 * Redirects don't need to be handled up here.
	 */
	if (OFP_PRC_IS_REDIRECT(cmd))
		return;

	/*
	 * Hostdead is ugly because it goes linearly through all PCBs.
	 *
	 * XXX: We never get this from ICMP, otherwise it makes an excellent
	 * DoS attack on machines with many connections.
	 */
	if (cmd == OFP_PRC_HOSTDEAD)
		ip = NULL;
	else if ((unsigned)cmd >= OFP_PRC_NCMDS || ofp_inetctlerrmap[cmd] == 0)
		return;
	if (ip != NULL) {
		uh = (struct ofp_udphdr *)((char *)ip + (ip->ip_hl << 2));
		inp = ofp_in_pcblookup(&ofp_udbinfo, faddr, uh->uh_dport,
		    ip->ip_src, uh->uh_sport, INPLOOKUP_RLOCKPCB, NULL);
		if (inp != NULL) {
			INP_RLOCK_ASSERT(inp);
			if (inp->inp_socket != NULL)
				ofp_udp_notify(inp, ofp_inetctlerrmap[cmd]);
			INP_RUNLOCK(inp);
		}
	} else
		ofp_in_pcbnotifyall(&ofp_udbinfo, faddr, ofp_inetctlerrmap[cmd],
		    ofp_udp_notify);
}

#if 0
static int
udp_pcblist(OFP_SYSCTL_HANDLER_ARGS)
{
	int error, i, n;
	struct inpcb *inp, **inp_list;
	inp_gen_t gencnt;
	struct xinpgen xig;

	/*
	 * The process of preparing the PCB list is too time-consuming and
	 * resource-intensive to repeat twice on every request.
	 */
	if (req->oldptr == 0) {
		n = ofp_udbinfo.ipi_count;
		n += imax(n / 8, 10);
		req->oldidx = 2 * (sizeof xig) + n * sizeof(struct xinpcb);
		return (0);
	}

	if (req->newptr != 0)
		return (OFP_EPERM);

	/*
	 * OK, now we're committed to doing something.
	 */
	INP_INFO_RLOCK(&ofp_udbinfo);
	gencnt = V_udbinfo.ipi_gencnt;
	n = V_udbinfo.ipi_count;
	INP_INFO_RUNLOCK(&ofp_udbinfo);

	error = sysctl_wire_old_buffer(req, 2 * (sizeof xig)
		+ n * sizeof(struct xinpcb));
	if (error != 0)
		return (error);

	xig.xig_len = sizeof xig;
	xig.xig_count = n;
	xig.xig_gen = gencnt;
	xig.xig_sogen = so_gencnt;
	error = SYSCTL_OUT(req, &xig, sizeof xig);
	if (error)
		return (error);

	inp_list = malloc(n * sizeof *inp_list, M_TEMP, M_WAITOK);
	if (inp_list == 0)
		return (OFP_ENOMEM);

	INP_INFO_RLOCK(&ofp_udbinfo);
	for (inp = OFP_LIST_FIRST(V_udbinfo.ipi_listhead), i = 0; inp && i < n;
	     inp = OFP_LIST_NEXT(inp, inp_list)) {
		INP_WLOCK(inp);
		if (inp->inp_gencnt <= gencnt &&
		    cr_canseeinpcb(req->td->td_ucred, inp) == 0) {
			ofp_in_pcbref(inp);
			inp_list[i++] = inp;
		}
		INP_WUNLOCK(inp);
	}
	INP_INFO_RUNLOCK(&ofp_udbinfo);
	n = i;

	error = 0;
	for (i = 0; i < n; i++) {
		inp = inp_list[i];
		INP_RLOCK(inp);
		if (inp->inp_gencnt <= gencnt) {
			struct xinpcb xi;

			bzero(&xi, sizeof(xi));
			xi.xi_len = sizeof xi;
			/* XXX should avoid extra copy */
			bcopy(inp, &xi.xi_inp, sizeof *inp);
			if (inp->inp_socket)
				sotoxsocket(inp->inp_socket, &xi.xi_socket);
			xi.xi_inp.inp_gencnt = inp->inp_gencnt;
			INP_RUNLOCK(inp);
			error = SYSCTL_OUT(req, &xi, sizeof xi);
		} else
			INP_RUNLOCK(inp);
	}
	INP_INFO_WLOCK(&ofp_udbinfo);
	for (i = 0; i < n; i++) {
		inp = inp_list[i];
		INP_RLOCK(inp);
		if (!ofp_in_pcbrele_rlocked(inp))
			INP_RUNLOCK(inp);
	}
	INP_INFO_WUNLOCK(&ofp_udbinfo);

	if (!error) {
		/*
		 * Give the user an updated idea of our state.  If the
		 * generation differs from what we told her before, she knows
		 * that something happened while we were processing this
		 * request, and it might be necessary to retry.
		 */
		INP_INFO_RLOCK(&ofp_udbinfo);
		xig.xig_gen = V_udbinfo.ipi_gencnt;
		xig.xig_sogen = so_gencnt;
		xig.xig_count = V_udbinfo.ipi_count;
		INP_INFO_RUNLOCK(&ofp_udbinfo);
		error = SYSCTL_OUT(req, &xig, sizeof xig);
	}
	free(inp_list, M_TEMP);
	return (error);
}

OFP_SYSCTL_PROC(_net_inet_udp, UDPCTL_PCBLIST, pcblist,
    OFP_CTLTYPE_OPAQUE | OFP_CTLFLAG_RD, NULL, 0,
    udp_pcblist, "S,xinpcb", "List of active UDP sockets");
#endif

#if 0
static int
udp_getcred(OFP_SYSCTL_HANDLER_ARGS)
{
	struct xucred xuc;
	struct ofp_sockaddr_in addrs[2];
	struct inpcb *inp;
	int error;

	error = priv_check(req->td, PRIV_NETINET_GETCRED);
	if (error)
		return (error);
	error = SYSCTL_IN(req, addrs, sizeof(addrs));
	if (error)
		return (error);
	inp = ofp_in_pcblookup(&ofp_udbinfo, addrs[1].sin_addr, addrs[1].sin_port,
	    addrs[0].sin_addr, addrs[0].sin_port,
	    INPLOOKUP_WILDCARD | INPLOOKUP_RLOCKPCB, NULL);
	if (inp != NULL) {
		INP_RLOCK_ASSERT(inp);
		if (inp->inp_socket == NULL)
			error = OFP_ENOENT;
		if (error == 0)
			error = cr_canseeinpcb(req->td->td_ucred, inp);
		if (error == 0)
			cru2x(inp->inp_cred, &xuc);
		INP_RUNLOCK(inp);
	} else
		error = OFP_ENOENT;
	if (error == 0)
		error = SYSCTL_OUT(req, &xuc, sizeof(struct xucred));
	return (error);
}

OFP_SYSCTL_PROC(_net_inet_udp, OFP_OID_AUTO, getcred,
    OFP_CTLTYPE_OPAQUE|OFP_CTLFLAG_RW|OFP_CTLFLAG_PRISON, 0, 0,
    udp_getcred, "S,xucred", "Get the xucred of a UDP connection");
#endif

int
ofp_udp_ctloutput(struct socket *so, struct sockopt *sopt)
{
	int error = 0;
	(void)so;
	(void)sopt;
	//int optval;
	struct inpcb *inp;

	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("%s: inp == NULL", __func__));
	INP_WLOCK(inp);
	if (sopt->sopt_level != OFP_IPPROTO_UDP) {
#if 0
		if (INP_CHECK_SOCKAF(so, OFP_AF_INET6)) {
			INP_WUNLOCK(inp);
			error = ofp_ip6_ctloutput(so, sopt);
		}
		else
#endif
		{
			INP_WUNLOCK(inp);
			error = ofp_ip_ctloutput(so, sopt);
		}
		return (error);
	}

#if 0
	switch (sopt->sopt_dir) {
	case SOPT_SET:
		switch (sopt->sopt_name) {
		case OFP_UDP_ENCAP:
			INP_WUNLOCK(inp);
			error = sooptcopyin(sopt, &optval, sizeof optval,
					    sizeof optval);
			if (error)
				break;
			inp = sotoinpcb(so);
			KASSERT(inp != NULL, ("%s: inp == NULL", __func__));
			INP_WLOCK(inp);
			switch (optval) {
			case 0:
				/* Clear all UDP encap. */
				break;
			default:
				error = OFP_EINVAL;
				break;
			}
			INP_WUNLOCK(inp);
			break;
		default:
			INP_WUNLOCK(inp);
			error = OFP_ENOPROTOOPT;
			break;
		}
		break;
	case SOPT_GET:
		switch (sopt->sopt_name) {
		default:
			INP_WUNLOCK(inp);
			error = OFP_ENOPROTOOPT;
			break;
		}
		break;
	}
#endif
	return (error);
}

#define goto_release do { if (1) OFP_INFO("GOTO release"); goto release; } while (0)

#define	UH_WLOCKED	2
#define	UH_RLOCKED	1
#define	UH_UNLOCKED	0
static int
udp_output(struct inpcb *inp, odp_packet_t m, struct ofp_sockaddr *addr,
	   odp_packet_t control, struct thread *td)
{
	int error = 0;
	int len = odp_packet_len(m);
	struct ofp_in_addr faddr, laddr;
	struct ofp_cmsghdr *cm;
	struct ofp_sockaddr_in *sin, src;
	int ipflags;
	uint16_t fport, lport;
	int unlock_udbinfo;
	uint8_t tos;

	/*
	 * udp_output() may need to temporarily bind or connect the current
	 * inpcb.  As such, we don't know up front whether we will need the
	 * pcbinfo lock or not.  Do any work to decide what is needed up
	 * front before acquiring any locks.
	 */
	if (len + sizeof(struct udpiphdr) > OFP_IP_MAXPACKET) {
		if (control != ODP_PACKET_INVALID)
			odp_packet_free(control);
		odp_packet_free(m);
		return (OFP_EMSGSIZE);
	}

	src.sin_family = 0;
	INP_RLOCK(inp);
	tos = inp->inp_ip_tos;
	if (control != ODP_PACKET_INVALID) {
		/*
		 * XXX: Currently, we assume all the optional information is
		 * stored in a single mbuf.
		 */

		uint8_t *ctl_p = odp_packet_data(control);
		unsigned int ctl_len = odp_packet_len(control);

		for (; ctl_len > 0;
		     ctl_p += OFP_CMSG_ALIGN(cm->cmsg_len),
			     ctl_len -= OFP_CMSG_ALIGN(cm->cmsg_len)) {
			cm = (struct ofp_cmsghdr *)ctl_p;
			if (ctl_len < sizeof(*cm) || cm->cmsg_len == 0
			    || cm->cmsg_len > ctl_len) {
				error = OFP_EINVAL;
				break;
			}
			if (cm->cmsg_level != OFP_IPPROTO_IP)
				continue;

			switch (cm->cmsg_type) {
			case OFP_IP_SENDSRCADDR:
				if (cm->cmsg_len !=
				    OFP_CMSG_LEN(sizeof(struct ofp_in_addr))) {
					error = OFP_EINVAL;
					break;
				}
				bzero(&src, sizeof(src));
				src.sin_family = OFP_AF_INET;
				src.sin_len = sizeof(src);
				src.sin_port = inp->inp_lport;
				src.sin_addr =
				    *(struct ofp_in_addr *)OFP_CMSG_DATA(cm);
				break;

			case OFP_IP_TOS:
				if (cm->cmsg_len != OFP_CMSG_LEN(sizeof(uint8_t))) {
					error = OFP_EINVAL;
					break;
				}
				tos = *(uint8_t *)OFP_CMSG_DATA(cm);
				break;

			default:
				error = OFP_ENOPROTOOPT;
				break;
			}
			if (error)
				break;
		}

		odp_packet_free(control);
	}
	if (error) {
		INP_RUNLOCK(inp);
		odp_packet_free(m);
		return (error);
	}

	/*
	 * Depending on whether or not the application has bound or connected
	 * the socket, we may have to do varying levels of work.  The optimal
	 * case is for a connected UDP socket, as a global lock isn't
	 * required at all.
	 *
	 * In order to decide which we need, we require stability of the
	 * inpcb binding, which we ensure by acquiring a read lock on the
	 * inpcb.  This doesn't strictly follow the lock order, so we play
	 * the trylock and retry game; note that we may end up with more
	 * conservative locks than required the second time around, so later
	 * assertions have to accept that.  Further analysis of the number of
	 * misses under contention is required.
	 *
	 * XXXRW: Check that hash locking update here is correct.
	 */
	sin = (struct ofp_sockaddr_in *)addr;
	if (sin != NULL &&
	    (inp->inp_laddr.s_addr == OFP_INADDR_ANY && inp->inp_lport == 0)) {
		INP_RUNLOCK(inp);
		INP_WLOCK(inp);
		INP_HASH_WLOCK(&ofp_udbinfo);
		unlock_udbinfo = UH_WLOCKED;
	} else if ((sin != NULL && (
	    (sin->sin_addr.s_addr == OFP_INADDR_ANY) ||
	    (sin->sin_addr.s_addr == OFP_INADDR_BROADCAST) ||
	    (inp->inp_laddr.s_addr == OFP_INADDR_ANY) ||
	    (inp->inp_lport == 0))) ||
	    (src.sin_family == OFP_AF_INET)) {
		INP_HASH_RLOCK(&ofp_udbinfo);
		unlock_udbinfo = UH_RLOCKED;
	} else
		unlock_udbinfo = UH_UNLOCKED;

	/*
	 * If the IP_SENDSRCADDR control message was specified, override the
	 * source address for this datagram.  Its use is invalidated if the
	 * address thus specified is incomplete or clobbers other inpcbs.
	 */
	laddr = inp->inp_laddr;
	lport = inp->inp_lport;
	if (src.sin_family == OFP_AF_INET) {
		INP_HASH_LOCK_ASSERT(&ofp_udbinfo);
		if ((lport == 0) ||
		    (laddr.s_addr == OFP_INADDR_ANY &&
		     src.sin_addr.s_addr == OFP_INADDR_ANY)) {
			error = OFP_EINVAL;
			goto_release;
		}
		error = ofp_in_pcbbind_setup(inp, (struct ofp_sockaddr *)&src,
		    &laddr.s_addr, &lport, td->td_ucred);
		if (error)
			goto_release;
	}

	/*
	 * If a UDP socket has been connected, then a local address/port will
	 * have been selected and bound.
	 *
	 * If a UDP socket has not been connected to, then an explicit
	 * destination address must be used, in which case a local
	 * address/port may not have been selected and bound.
	 */
	if (sin != NULL) {
		INP_LOCK_ASSERT(inp);
		if (inp->inp_faddr.s_addr != OFP_INADDR_ANY) {
			error = OFP_EISCONN;
			goto_release;
		}

		/*
		 * If a local address or port hasn't yet been selected, or if
		 * the destination address needs to be rewritten due to using
		 * a special INADDR_ constant, invoke ofp_in_pcbconnect_setup()
		 * to do the heavy lifting.  Once a port is selected, we
		 * commit the binding back to the socket; we also commit the
		 * binding of the address if in jail.
		 *
		 * If we already have a valid binding and we're not
		 * requesting a destination address rewrite, use a fast path.
		 */
		if (inp->inp_laddr.s_addr == OFP_INADDR_ANY ||
		    inp->inp_lport == 0 ||
		    sin->sin_addr.s_addr == OFP_INADDR_ANY ||
		    sin->sin_addr.s_addr == OFP_INADDR_BROADCAST) {
			INP_HASH_LOCK_ASSERT(&ofp_udbinfo);
			error = ofp_in_pcbconnect_setup(inp, addr, &laddr.s_addr,
			    &lport, &faddr.s_addr, &fport, NULL,
			    td->td_ucred);
			if (error)
				goto_release;

			/*
			 * XXXRW: Why not commit the port if the address is
			 * !OFP_INADDR_ANY?
			 */
			/* Commit the local port if newly assigned. */
			if (inp->inp_laddr.s_addr == OFP_INADDR_ANY &&
			    inp->inp_lport == 0) {
				INP_WLOCK_ASSERT(inp);
				INP_HASH_WLOCK_ASSERT(&ofp_udbinfo);
#if 0
				/*
				 * Remember addr if jailed, to prevent
				 * rebinding.
				 */
				if (prison_flag(td->td_ucred, PR_IP4))
					inp->inp_laddr = laddr;
#endif
				inp->inp_lport = lport;
				if (ofp_in_pcbinshash(inp) != 0) {
					inp->inp_lport = 0;
					error = OFP_EAGAIN;
					goto_release;
				}
				inp->inp_flags |= INP_ANONPORT;
			}
		} else {
			faddr = sin->sin_addr;
			fport = sin->sin_port;
		}
	} else {
		INP_LOCK_ASSERT(inp);
		faddr = inp->inp_faddr;
		fport = inp->inp_fport;
		if (faddr.s_addr == OFP_INADDR_ANY) {
			error = OFP_ENOTCONN;
			goto_release;
		}
	}

	/*
	 * Calculate data length and get a mbuf for UDP, IP, and possible
	 * link-layer headers.  Immediate slide the data pointer back forward
	 * since we won't use that space at this layer.
	 */
	struct ofp_ip *ip = odp_packet_push_head(m, sizeof(struct udpiphdr));
	if (!ip) {
		error = OFP_ENOBUFS;
		goto release;
	}

	odp_packet_l3_offset_set(m, 0);
	odp_packet_l4_offset_set(m, sizeof(struct ofp_ip));

	struct ofp_udphdr *udp = (struct ofp_udphdr *) (ip + 1);
	static uint16_t id = 0;

	ip->ip_hl = 5;
	ip->ip_v = OFP_IPVERSION;
	ip->ip_tos = tos;
	ip->ip_len = odp_cpu_to_be_16(len + sizeof(struct ofp_ip) +
				      sizeof(struct ofp_udphdr));
	ip->ip_id = odp_cpu_to_be_16(id++);
	ip->ip_off = 0;
	ip->ip_ttl = inp->inp_ip_ttl;
	ip->ip_p = OFP_IPPROTO_UDP;
	ip->ip_src.s_addr = laddr.s_addr;
	ip->ip_dst.s_addr = faddr.s_addr;
	ip->ip_sum = 0;

	udp->uh_sport = lport;
	udp->uh_dport = fport;
	udp->uh_ulen = odp_cpu_to_be_16(len + sizeof(struct ofp_udphdr));
	udp->uh_sum = 0;

	/*
	 * Set the Don't Fragment bit in the IP header.
	 */
	if (inp->inp_flags & INP_DONTFRAG)
		ip->ip_off |= OFP_IP_DF;

	ipflags = 0;

	if (inp->inp_socket->so_options & OFP_SO_DONTROUTE)
		ipflags |= IP_ROUTETOIF;
	if (inp->inp_socket->so_options & OFP_SO_BROADCAST)
		ipflags |= IP_ALLOWBROADCAST;
	if (inp->inp_flags & INP_ONESBCAST)
		ipflags |= IP_SENDONES;

	/*
	 * Set up UDP checksum.
	 */
#ifdef OFP_IPv4_UDP_CSUM_COMPUTE
	if (ofp_udp_cksum) {
#if 1
		udp->uh_sum = 0;
		udp->uh_sum = ofp_in4_cksum(m);
		if (udp->uh_sum == 0)
			udp->uh_sum = 0xffff;
#else
		if (inp->inp_flags & INP_ONESBCAST)
			faddr.s_addr = OFP_INADDR_BROADCAST;
		ui->ui_sum = in_pseudo(ui->ui_src.s_addr, faddr.s_addr,
		    odp_cpu_to_be_16((uint16_t)len + sizeof(struct ofp_udphdr) + OFP_IPPROTO_UDP));

		odp_packet_csum_flags(m) = CSUM_UDP;
		odp_packet_set_csum_data(m, offsetof(struct ofp_udphdr, uh_sum));
#endif
	} else
#endif /*OFP_IPv4_UDP_CSUM_COMPUTE*/
	{
		udp->uh_sum = 0;
		UDPSTAT_INC(udps_opackets);
	}

	if (unlock_udbinfo == UH_WLOCKED)
		INP_HASH_WUNLOCK(&ofp_udbinfo);
	else if (unlock_udbinfo == UH_RLOCKED) {
		INP_HASH_RUNLOCK(&ofp_udbinfo);
	}

#if 0
	error = ofp_ip_output(m, inp->inp_options, NULL, ipflags,
				inp->inp_moptions, inp);
#else
	if (ofp_ip_output(m, NULL) == OFP_PKT_DROP)
		error = OFP_EIO;
	else
		error = 0;
#endif
	if (unlock_udbinfo == UH_WLOCKED)
		INP_WUNLOCK(inp);
	else
		INP_RUNLOCK(inp);
	return (error);

release:
	if (unlock_udbinfo == UH_WLOCKED) {
		INP_HASH_WUNLOCK(&ofp_udbinfo);
		INP_WUNLOCK(inp);
	} else if (unlock_udbinfo == UH_RLOCKED) {
		INP_HASH_RUNLOCK(&ofp_udbinfo);
		INP_RUNLOCK(inp);
	} else
		INP_RUNLOCK(inp);
	odp_packet_free(m);

	return (error);
}

static void
udp_abort(struct socket *so)
{
	struct inpcb *inp;

	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("udp_abort: inp == NULL"));
	INP_WLOCK(inp);
	if (inp->inp_faddr.s_addr != OFP_INADDR_ANY) {
		INP_HASH_WLOCK(&ofp_udbinfo);
		ofp_in_pcbdisconnect(inp);
		inp->inp_laddr.s_addr = OFP_INADDR_ANY;
		INP_HASH_WUNLOCK(&ofp_udbinfo);
		ofp_soisdisconnected(so);
	}
	INP_WUNLOCK(inp);
}

static int
udp_attach(struct socket *so, int proto, struct thread *td)
{
	struct inpcb *inp;
	int error;

	(void)proto;
	(void)td;

	inp = sotoinpcb(so);
	KASSERT(inp == NULL, ("udp_attach: inp != NULL"));

	/* HJo: Constant space reserved.
	error = ofp_soreserve(so, ofp_udp_sendspace, ofp_udp_recvspace);
	if (error)
		return (error);
	*/

	INP_INFO_WLOCK(&ofp_udbinfo);

	error = ofp_in_pcballoc(so, &ofp_udbinfo);
	if (error) {
		INP_INFO_WUNLOCK(&ofp_udbinfo);
		return (error);
	}

	inp = sotoinpcb(so);
	inp->inp_vflag |= INP_IPV4;
	inp->inp_ip_ttl = ofp_ip_defttl;

	/* HJo: Replaced by static allocation.
	error = udp_newudpcb(inp);
	if (error) {
		ofp_in_pcbdetach(inp);
		ofp_in_pcbfree(inp);
		INP_INFO_WUNLOCK(&ofp_udbinfo);
		return (error);
	}
	*/
	inp->inp_ppcb = &inp->ppcb_space.udp_ppcb;

	INP_WUNLOCK(inp);
	INP_INFO_WUNLOCK(&ofp_udbinfo);
	return (0);
}

#if 0
int
udp_set_kernel_tunneling(struct socket *so, udp_tun_func_t f)
{
	struct inpcb *inp;
	struct udpcb *up;

	KASSERT(so->so_type == OFP_SOCK_DGRAM,
	    ("udp_set_kernel_tunneling: !dgram"));
	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("udp_set_kernel_tunneling: inp == NULL"));
	INP_WLOCK(inp);
	up = intoudpcb(inp);
	if (up->u_tun_func != NULL) {
		INP_WUNLOCK(inp);
		return (OFP_EBUSY);
	}
	up->u_tun_func = f;
	INP_WUNLOCK(inp);
	return (0);
}
#endif

static int
udp_bind(struct socket *so, struct ofp_sockaddr *nam, struct thread *td)
{
	struct inpcb *inp;
	int error;
	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("udp_bind: inp == NULL"));
	INP_WLOCK(inp);
	INP_HASH_WLOCK(&ofp_udbinfo);
	error = ofp_in_pcbbind(inp, nam, td->td_ucred);
	INP_HASH_WUNLOCK(&ofp_udbinfo);
	INP_WUNLOCK(inp);
	return (error);
}

static void
udp_close(struct socket *so)
{
	struct inpcb *inp;

	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("udp_close: inp == NULL"));
	INP_WLOCK(inp);
	if (inp->inp_faddr.s_addr != OFP_INADDR_ANY) {
		INP_HASH_WLOCK(&ofp_udbinfo);
		ofp_in_pcbdisconnect(inp);
		inp->inp_laddr.s_addr = OFP_INADDR_ANY;
		INP_HASH_WUNLOCK(&ofp_udbinfo);
		ofp_soisdisconnected(so);
	}
	INP_WUNLOCK(inp);
}

static int
udp_connect(struct socket *so, struct ofp_sockaddr *nam, struct thread *td)
{
	struct inpcb *inp;
	int error;

	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("udp_connect: inp == NULL"));
	INP_WLOCK(inp);
	if (inp->inp_faddr.s_addr != OFP_INADDR_ANY) {
		INP_WUNLOCK(inp);
		return (OFP_EISCONN);
	}

	/* HJo:
	error = prison_remote_ip4(td->td_ucred, &sin->sin_addr);
	if (error != 0) {
		INP_WUNLOCK(inp);
		return (error);
	}
	*/
	INP_HASH_WLOCK(&ofp_udbinfo);
	error = ofp_in_pcbconnect(inp, nam, td->td_ucred);
	INP_HASH_WUNLOCK(&ofp_udbinfo);
	if (error == 0)
		ofp_soisconnected(so);
	INP_WUNLOCK(inp);
	return (error);
}

static void
udp_detach(struct socket *so)
{
	struct inpcb *inp;
	struct udpcb *up;

	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("udp_detach: inp == NULL"));
	KASSERT(inp->inp_faddr.s_addr == OFP_INADDR_ANY,
	    ("udp_detach: not disconnected"));
	INP_INFO_WLOCK(&ofp_udbinfo);
	INP_WLOCK(inp);
	up = intoudpcb(inp);
	KASSERT(up != NULL, ("%s: up == NULL", __func__));
	inp->inp_ppcb = NULL;
	ofp_in_pcbdetach(inp);
	ofp_in_pcbfree(inp);
	INP_INFO_WUNLOCK(&ofp_udbinfo);
}

static int
udp_disconnect(struct socket *so)
{
	struct inpcb *inp;

	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("udp_disconnect: inp == NULL"));
	INP_WLOCK(inp);
	if (inp->inp_faddr.s_addr == OFP_INADDR_ANY) {
		INP_WUNLOCK(inp);
		return (OFP_ENOTCONN);
	}
	INP_HASH_WLOCK(&ofp_udbinfo);
	ofp_in_pcbdisconnect(inp);
	inp->inp_laddr.s_addr = OFP_INADDR_ANY;
	INP_HASH_WUNLOCK(&ofp_udbinfo);
	OFP_SOCK_LOCK(so);
#if 1 /* HJo: FIX */
	so->so_state &= ~SS_ISCONNECTED;		/* XXX */
#endif
	OFP_SOCK_UNLOCK(so);
	INP_WUNLOCK(inp);
	return (0);
}

static int
udp_send(struct socket *so, int flags, odp_packet_t m, struct ofp_sockaddr *addr,
    odp_packet_t control, struct thread *td)
{
	struct inpcb *inp;

	(void)flags;

	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("udp_send: inp == NULL"));
	return (udp_output(inp, m, addr, control, td));
}

int
ofp_udp_shutdown(struct socket *so)
{
	struct inpcb *inp;

	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("ofp_udp_shutdown: inp == NULL"));
	INP_WLOCK(inp);
	ofp_socantsendmore(so);
	INP_WUNLOCK(inp);
	return (0);
}

struct pr_usrreqs ofp_udp_usrreqs = {
	.pru_abort =		udp_abort,
	.pru_attach =		udp_attach,
	.pru_bind =		udp_bind,
	.pru_connect =		udp_connect,
	.pru_control =		ofp_in_control,
	.pru_detach =		udp_detach,
	.pru_disconnect =	udp_disconnect,
	.pru_peeraddr =		ofp_in_getpeeraddr,
	.pru_send =		udp_send,
	.pru_soreceive =	ofp_soreceive_dgram,
	.pru_sosend =		ofp_sosend_dgram,
	.pru_shutdown =		ofp_udp_shutdown,
	.pru_sockaddr =		ofp_in_getsockaddr,
	.pru_sosetlabel =	ofp_in_pcbsosetlabel,
	.pru_close =		udp_close,
};
