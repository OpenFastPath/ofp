/*-
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * Copyright (c) 2010-2011 Juniper Networks, Inc.
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
 *	$KAME: udp6_usrreq.c,v 1.27 2001/05/21 05:45:10 jinmei Exp $
 *	$KAME: udp6_output.c,v 1.31 2001/05/21 16:39:15 jinmei Exp $
 */

/*-
 * Copyright (c) 1982, 1986, 1988, 1990, 1993, 1995
 *	The Regents of the University of California.
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
#if 0
#include <sys/cdefs.h>
__FBSDID("$FreeBSD: release/9.1.0/sys/netinet6/udp6_usrreq.c 238247 2012-07-08 14:21:36Z bz $");

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>

#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp_var.h>
#include <netinet/ip_var.h>

#ifdef IPSEC
#include <netipsec/ipsec.h>
#include <netipsec/ipsec6.h>
#endif /* IPSEC */

#include <security/mac/mac_framework.h>
#endif


#include <odp.h>
#include "api/ofp_types.h"
#include "api/ofp_errno.h"
#include "ofpi_socket.h"
#include "ofpi_socketvar.h"
#include "ofpi_sockopt.h"
#include "ofpi_sockstate.h"
#include "ofpi_protosw.h"
#include "ofpi_in.h"
#include "ofpi_in_pcb.h"
#include "ofpi_udp.h"
#include "ofpi_udp_var.h"
#include "ofpi_ip.h"

#include "ofpi_ip6protosw.h"
#include "ofpi_ip6_var.h"
#include "ofpi_in6_pcb.h"
#include "ofpi_ip6.h"
#include "ofpi_udp6_var.h"
#include "ofpi_icmp6.h"
#include "ofpi_pkt_processing.h"
#include "ofpi_hook.h"
#include "ofpi_util.h"

/*
 * UDP protocol implementation.
 * Per RFC 768, August, 1980.
 */

#define UDPSTAT_INC(x)

#define log(...)

extern struct protosw	ofp_inetsw[];
extern struct inpcbinfo ofp_udbinfo;

extern int ofp_udp_log_in_vain;
extern int ofp_udp_blackhole;

#if 0
static void		udp6_detach(struct socket *so);
#endif

static void
udp6_append(struct inpcb *inp, odp_packet_t pkt, int off,
    struct ofp_sockaddr_in6 *fromsa)
{
	struct socket *so;
	odp_packet_t opts = ODP_PACKET_INVALID;

	(void)off;

	INP_LOCK_ASSERT(inp);

#ifdef IPSEC
	/* Check AH/ESP integrity. */
	if (ipsec6_in_reject(n, inp)) {
		m_freem(n);
		V_ipsec6stat.in_polvio++;
		return;
	}
#endif /* IPSEC */
#ifdef MAC
	if (mac_inpcb_check_deliver(inp, n) != 0) {
		m_freem(n);
		return;
	}
#endif

#if 0
	if (inp->inp_flags & INP_CONTROLOPTS ||
	    inp->inp_socket->so_options & SO_TIMESTAMP)
		ip6_savecontrol(inp, n, &opts);
	m_adj(n, off + sizeof(struct udphdr));
#endif

	so = inp->inp_socket;

	/* save sender data where L2 & L3 headers used to be */
	memcpy(odp_packet_l2_ptr(pkt, NULL), fromsa, ((struct ofp_sockaddr *)fromsa)->sa_len);

	/* Offer to event function */
	if (packet_accepted_as_event(so, pkt))
		return;

	SOCKBUF_LOCK(&so->so_rcv);
	if (ofp_sbappendaddr_locked(&so->so_rcv, pkt, opts) == 0) {
		SOCKBUF_UNLOCK(&so->so_rcv);
		odp_packet_free(pkt);
		if (opts != ODP_PACKET_INVALID)
			odp_packet_free(opts);
		UDPSTAT_INC(udps_fullsock);
	} else
		sorwakeup_locked(so);
}

enum ofp_return_code
ofp_udp6_input(odp_packet_t pkt, int *offp, int *nxt)
{
	int off = *offp;
	int protocol = IS_IPV6_UDP;
	struct ofp_ifnet *ifp;
	struct ofp_ip6_hdr *ip6;
	struct ofp_udphdr *uh;
	enum ofp_return_code res = OFP_PKT_CONTINUE;
	int plen, ulen;
	/*uint16_t uh_sum;*/
	struct ofp_sockaddr_in6 fromsa;
	struct inpcb *inp;
	struct udpcb *up;
	int uh_sum;

#if 0
#ifdef IPFIREWALL_FORWARD
	struct m_tag *fwd_tag;
#endif
#endif
	*nxt = OFP_IPPROTO_DONE;

	OFP_HOOK(OFP_HOOK_LOCAL, pkt, &protocol, &res);
	if (res != OFP_PKT_CONTINUE)
		return res;

	OFP_HOOK(OFP_HOOK_LOCAL_UDPv6, pkt, NULL, &res);
	if (res != OFP_PKT_CONTINUE)
		return res;

	ifp = odp_packet_user_ptr(pkt);
	ip6 = (struct ofp_ip6_hdr *)odp_packet_l3_ptr(pkt, NULL);
	if (odp_packet_len(pkt) < off + sizeof(struct ofp_udphdr))
		return OFP_PKT_DROP;

	odp_packet_l4_offset_set(pkt, odp_packet_l3_offset(pkt) + off);

	uh = (struct ofp_udphdr *)((uint8_t *)ip6 + off);

	UDPSTAT_INC(udps_ipackets);

	/*
	 * Destination port of 0 is illegal, based on RFC768.
	 */
	if (uh->uh_dport == 0)
		goto badunlocked;

	plen = odp_be_to_cpu_16(ip6->ofp_ip6_plen) - off + sizeof(*ip6);
	ulen = odp_be_to_cpu_16((u_short)uh->uh_ulen);

	if (plen != ulen) {
		UDPSTAT_INC(udps_badlen);
		goto badunlocked;
	}

	/*
	 * Checksum extended UDP header and data.
	 */
	if (uh->uh_sum == 0) {
		UDPSTAT_INC(udps_nosum);
		goto badunlocked;
	}

	uh_sum = ofp_in6_cksum(pkt, OFP_IPPROTO_UDP, off, ulen);
	if (uh_sum != 0) {
		UDPSTAT_INC(udps_badsum);
		goto badunlocked;
	}
	/*
	 * Construct sockaddr format source address.
	 */
	ofp_init_sin6(&fromsa, pkt);
	fromsa.sin6_port = uh->uh_sport;

#if 0
	if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
		struct inpcb *last;
		struct ip6_moptions *imo;

		INP_INFO_RLOCK(&V_udbinfo);
		/*
		 * In the event that laddr should be set to the link-local
		 * address (this happens in RIPng), the multicast address
		 * specified in the received packet will not match laddr.  To
		 * handle this situation, matching is relaxed if the
		 * receiving interface is the same as one specified in the
		 * socket and if the destination multicast address matches
		 * one of the multicast groups specified in the socket.
		 */

		/*
		 * KAME note: traditionally we dropped udpiphdr from mbuf
		 * here.  We need udphdr for IPsec processing so we do that
		 * later.
		 */
		last = NULL;
		OFP_LIST_FOREACH(inp, &V_udb, inp_list) {
			if ((inp->inp_vflag & INP_IPV6) == 0)
				continue;
			if (inp->inp_lport != uh->uh_dport)
				continue;
			if (inp->inp_fport != 0 &&
			    inp->inp_fport != uh->uh_sport)
				continue;
			if (!IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr)) {
				if (!IN6_ARE_ADDR_EQUAL(&inp->in6p_laddr,
							&ip6->ip6_dst))
					continue;
			}
			if (!IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_faddr)) {
				if (!IN6_ARE_ADDR_EQUAL(&inp->in6p_faddr,
							&ip6->ip6_src) ||
				    inp->inp_fport != uh->uh_sport)
					continue;
			}

			/*
			 * XXXRW: Because we weren't holding either the inpcb
			 * or the hash lock when we checked for a match
			 * before, we should probably recheck now that the
			 * inpcb lock is (supposed to be) held.
			 */

			/*
			 * Handle socket delivery policy for any-source
			 * and source-specific multicast. [RFC3678]
			 */
			imo = inp->in6p_moptions;
			if (imo && IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
				struct sockaddr_in6	 mcaddr;
				int			 blocked;

				INP_RLOCK(inp);

				bzero(&mcaddr, sizeof(struct sockaddr_in6));
				mcaddr.sin6_len = sizeof(struct sockaddr_in6);
				mcaddr.sin6_family = AF_INET6;
				mcaddr.sin6_addr = ip6->ip6_dst;

				blocked = im6o_mc_filter(imo, ifp,
					(struct sockaddr *)&mcaddr,
					(struct sockaddr *)&fromsa);
				if (blocked != MCAST_PASS) {
					if (blocked == MCAST_NOTGMEMBER)
						IP6STAT_INC(ip6s_notmember);
					if (blocked == MCAST_NOTSMEMBER ||
					    blocked == MCAST_MUTED)
						UDPSTAT_INC(udps_filtermcast);
					INP_RUNLOCK(inp); /* XXX */
					continue;
				}

				INP_RUNLOCK(inp);
			}
			if (last != NULL) {
				struct mbuf *n;

				if ((n = m_copy(m, 0, M_COPYALL)) != NULL) {
					INP_RLOCK(last);
					up = intoudpcb(last);
					if (up->u_tun_func == NULL) {
						udp6_append(last, n, off, &fromsa);
					} else {
						/*
						 * Engage the tunneling
						 * protocol we will have to
						 * leave the info_lock up,
						 * since we are hunting
						 * through multiple UDP's.
						 *
						 */
						(*up->u_tun_func)(n, off, last);
					}
					INP_RUNLOCK(last);
				}
			}
			last = inp;
			/*
			 * Don't look for additional matches if this one does
			 * not have either the SO_REUSEPORT or SO_REUSEADDR
			 * socket options set.  This heuristic avoids
			 * searching through all pcbs in the common case of a
			 * non-shared port.  It assumes that an application
			 * will never clear these options after setting them.
			 */
			if ((last->inp_socket->so_options &
			     (SO_REUSEPORT|SO_REUSEADDR)) == 0)
				break;
		}

		if (last == NULL) {
			/*
			 * No matching pcb found; discard datagram.  (No need
			 * to send an ICMP Port Unreachable for a broadcast
			 * or multicast datgram.)
			 */
			UDPSTAT_INC(udps_noport);
			UDPSTAT_INC(udps_noportmcast);
			goto badheadlocked;
		}
		INP_RLOCK(last);
		INP_INFO_RUNLOCK(&V_udbinfo);
		up = intoudpcb(last);
		if (up->u_tun_func == NULL) {
			udp6_append(last, m, off, &fromsa);
		} else {
			/*
			 * Engage the tunneling protocol.
			 */
			(*up->u_tun_func)(m, off, last);
		}
		INP_RUNLOCK(last);
		return (IPPROTO_PKT_PROCESSED);
	}
#endif
	/*
	 * Locate pcb for datagram.
	 */
#if 0
#ifdef IPFIREWALL_FORWARD
	/*
	 * Grab info from PACKET_TAG_IPFORWARD tag prepended to the chain.
	 */
	fwd_tag = m_tag_find(m, PACKET_TAG_IPFORWARD, NULL);
	if (fwd_tag != NULL) {
		struct sockaddr_in6 *next_hop6;

		next_hop6 = (struct sockaddr_in6 *)(fwd_tag + 1);

		/*
		 * Transparently forwarded. Pretend to be the destination.
		 * Already got one like this?
		 */
		inp = in6_pcblookup_mbuf(&V_udbinfo,
		    &ip6->ip6_src, uh->uh_sport, &ip6->ip6_dst, uh->uh_dport,
		    INPLOOKUP_RLOCKPCB, m->m_pkthdr.rcvif, m);
		if (!inp) {
			/*
			 * It's new.  Try to find the ambushing socket.
			 * Because we've rewritten the destination address,
			 * any hardware-generated hash is ignored.
			 */
			inp = in6_pcblookup(&V_udbinfo, &ip6->ip6_src,
			    uh->uh_sport, &next_hop6->sin6_addr,
			    next_hop6->sin6_port ? htons(next_hop6->sin6_port) :
			    uh->uh_dport, INPLOOKUP_WILDCARD |
			    INPLOOKUP_RLOCKPCB, m->m_pkthdr.rcvif);
		}
		/* Remove the tag from the packet. We don't need it anymore. */
		m_tag_delete(m, fwd_tag);
	} else
#endif /* IPFIREWALL_FORWARD */
#endif

	inp = ofp_in6_pcblookup(&ofp_udbinfo, &ip6->ip6_src,
		    uh->uh_sport, &ip6->ip6_dst, uh->uh_dport,
		    INPLOOKUP_WILDCARD | INPLOOKUP_RLOCKPCB, ifp);

	if (inp == NULL) {
		if (ofp_udp_log_in_vain) {
			OFP_INFO(
			    "Connection attempt to UDP [%s]:%d from [%s]:%d",
			    ofp_print_ip6_addr((uint8_t *)&ip6->ip6_dst),
			    odp_be_to_cpu_16(uh->uh_dport),
			    ofp_print_ip6_addr((uint8_t *)&ip6->ip6_src),
			    odp_be_to_cpu_16(uh->uh_sport));
		}

		UDPSTAT_INC(udps_noport);
#if 0
		if (m->m_flags & M_MCAST) {
			OFP_INFO("UDP6: M_MCAST is set in a unicast packet");
			UDPSTAT_INC(udps_noportmcast);
			goto badunlocked;
		}
#endif

		if (ofp_udp_blackhole)
			goto badunlocked;

#if 0
		if (badport_bandlim(BANDLIM_ICMP6_UNREACH) < 0)
			goto badunlocked;
#endif

#ifndef SP
		ofp_icmp6_error(pkt, OFP_ICMP6_DST_UNREACH,
				OFP_ICMP6_DST_UNREACH_NOPORT, 0);

		*nxt = OFP_IPPROTO_DONE;
		return OFP_PKT_PROCESSED;
#else
		*nxt = OFP_IPPROTO_SP;
		return OFP_PKT_CONTINUE;
#endif
	}
	INP_RLOCK_ASSERT(inp);

	up = intoudpcb(inp);
	if (up->u_tun_func == NULL) {
		udp6_append(inp, pkt, off, &fromsa);
	} else {
		/*
		 * Engage the tunneling protocol.
		 */

		(*up->u_tun_func)(pkt, off, inp);
	}

	INP_RUNLOCK(inp);
	return OFP_PKT_PROCESSED;

#if 0
badheadlocked:
	INP_INFO_RUNLOCK(&ofp_udbinfo);
#endif
badunlocked:
	return OFP_PKT_DROP;
}

void
ofp_udp6_ctlinput(int cmd, struct ofp_sockaddr *sa, void *d)
{
	struct ofp_udphdr uh;
	struct ofp_ip6_hdr *ip6;
	odp_packet_t m;
	struct ofp_ip6ctlparam *ip6cp = NULL;
	int off = 0;
	const struct ofp_sockaddr_in6 *sa6_src = NULL;
	void *cmdarg;
	struct inpcb *(*notify)(struct inpcb *, int) = ofp_udp_notify;
	struct udp_portonly {
		uint16_t uh_sport;
		uint16_t uh_dport;
	} *uhp;


	if (sa->sa_family != OFP_AF_INET6 ||
	    sa->sa_len != sizeof(struct ofp_sockaddr_in6))
		return;
	if ((unsigned)cmd >= OFP_PRC_NCMDS)
		return;
	if (OFP_PRC_IS_REDIRECT(cmd))
		notify = ofp_in6_rtchange, d = NULL;
	else if (cmd == OFP_PRC_HOSTDEAD)
		d = NULL;
	else if (ofp_inet6ctlerrmap[cmd] == 0)
		return;
	/* if the parameter is from icmp6, decode it. */
	if (d != NULL) {
		ip6cp = (struct ofp_ip6ctlparam *)d;
		m = ip6cp->ip6c_m;
		ip6 = ip6cp->ip6c_ip6;
		off = ip6cp->ip6c_off;
		cmdarg = ip6cp->ip6c_cmdarg;
		sa6_src = ip6cp->ip6c_src;
	} else {
		m = ODP_PACKET_INVALID;
		ip6 = NULL;
		cmdarg = NULL;
		sa6_src = &ofp_sa6_any;
	}

	if (ip6) {
		/*
		 * XXX: We assume that when IPV6 is non NULL,
		 * M and OFF are valid.
		 */
#if 0
		/* Check if we can safely examine src and dst ports. */
		if (m->m_pkthdr.len < off + sizeof(*uhp))
			return;
#endif

		bzero(&uh, sizeof(uh));
		memcpy(&uh, (uint8_t *)odp_packet_l3_ptr(m, NULL) + off,
			sizeof(*uhp));
		(void)ofp_in6_pcbnotify(&ofp_udbinfo, sa, uh.uh_dport,
			(struct ofp_sockaddr *)ip6cp->ip6c_src, uh.uh_sport,
			 cmd, cmdarg, notify);
	} else
		(void)ofp_in6_pcbnotify(&ofp_udbinfo, sa, 0,
			(const struct ofp_sockaddr *)sa6_src, 0,
			cmd, cmdarg, notify);
}

#if 0
static int
udp6_getcred(OFP_SYSCTL_HANDLER_ARGS)
{
	struct xucred xuc;
	struct sockaddr_in6 addrs[2];
	struct inpcb *inp;
	int error;

	error = priv_check(req->td, PRIV_NETINET_GETCRED);
	if (error)
		return (error);

	if (req->newlen != sizeof(addrs))
		return (OFP_EINVAL);
	if (req->oldlen != sizeof(struct xucred))
		return (OFP_EINVAL);
	error = SYSCTL_IN(req, addrs, sizeof(addrs));
	if (error)
		return (error);
	if ((error = sa6_embedscope(&addrs[0], V_ip6_use_defzone)) != 0 ||
	    (error = sa6_embedscope(&addrs[1], V_ip6_use_defzone)) != 0) {
		return (error);
	}
	inp = in6_pcblookup(&V_udbinfo, &addrs[1].sin6_addr,
	    addrs[1].sin6_port, &addrs[0].sin6_addr, addrs[0].sin6_port,
	    INPLOOKUP_WILDCARD | INPLOOKUP_RLOCKPCB, NULL);
	if (inp != NULL) {
		INP_RLOCK_ASSERT(inp);
		if (inp->inp_socket == NULL)
			error = OFP_ENOENT;
		if (error == 0)
			error = cr_canseesocket(req->td->td_ucred,
			    inp->inp_socket);
		if (error == 0)
			cru2x(inp->inp_cred, &xuc);
		INP_RUNLOCK(inp);
	} else
		error = OFP_ENOENT;
	if (error == 0)
		error = SYSCTL_OUT(req, &xuc, sizeof(struct xucred));
	return (error);
}

OFP_SYSCTL_PROC(_net_inet6_udp6, OFP_OID_AUTO, getcred, OFP_CTLTYPE_OPAQUE|OFP_CTLFLAG_RW, 0,
    0, udp6_getcred, "S,xucred", "Get the xucred of a UDP6 connection");
#endif

static int
udp6_output(struct inpcb *inp, odp_packet_t m, struct ofp_sockaddr *addr6,
    odp_packet_t control, struct thread *td)
{
	uint32_t ulen = (uint16_t)odp_packet_len(m);
	uint32_t plen = sizeof(struct ofp_udphdr) + ulen;
	struct ofp_ip6_hdr *ip6;
	struct ofp_udphdr *udp6;
	struct ofp_in6_addr *laddr, *faddr, in6a;
	struct ofp_sockaddr_in6 *sin6 = NULL;
	struct ofp_ifnet *oifp = NULL;
	/*int scope_ambiguous = 0;*/
	u_short fport;
	int error = 0;
	/*struct ofp_ip6_pktopts *optp, opt;*/
	int af = OFP_AF_INET6, hlen = sizeof(struct ofp_ip6_hdr);
	struct ofp_sockaddr_in6 tmp;

	INP_WLOCK_ASSERT(inp);
	INP_HASH_WLOCK_ASSERT(inp->inp_pcbinfo);

	if (addr6) {
		/* addr6 has been validated in udp6_send(). */
		sin6 = (struct ofp_sockaddr_in6 *)addr6;

		/* protect *sin6 from overwrites */
		tmp = *sin6;
		sin6 = &tmp;

		/*
		 * Application should provide a proper zone ID or the use of
		 * default zone IDs should be enabled.  Unfortunately, some
		 * applications do not behave as it should, so we need a
		 * workaround.  Even if an appropriate ID is not determined,
		 * we'll see if we can determine the outgoing interface.  If we
		 * can, determine the zone ID based on the interface below.
		 */
#if 0 /* No scope check */
		if (sin6->sin6_scope_id == 0 && !V_ip6_use_defzone)
			scope_ambiguous = 1;
		if ((error = sa6_embedscope(sin6, V_ip6_use_defzone)) != 0)
			return (error);
#endif
	}
#if 0 /* no packet options*/
	if (control != ODP_PACKET_INVALID) {
		if ((error = ip6_setpktopts(control, &opt,
		    inp->in6p_outputopts, td->td_ucred, IPPROTO_UDP)) != 0)
			goto release;
		optp = &opt;
	} else
		optp = inp->in6p_outputopts;
#endif

	if (sin6) {
		faddr = &sin6->sin6_addr;

		/*
		 * IPv4 version of udp_output calls in_pcbconnect in this case,
		 * which needs splnet and affects performance.
		 * Since we saw no essential reason for calling in_pcbconnect,
		 * we get rid of such kind of logic, and call in6_selectsrc
		 * and in6_pcbsetport in order to fill in the local address
		 * and the local port.
		 */
		if (sin6->sin6_port == 0) {
			error = OFP_EADDRNOTAVAIL;
			goto release;
		}

		if (!OFP_IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_faddr)) {
			/* how about ::ffff:0.0.0.0 case? */
			error = OFP_EISCONN;
			goto release;
		}

		fport = sin6->sin6_port; /* allow 0 port */

		if (OFP_IN6_IS_ADDR_V4MAPPED(faddr)) {
			if ((inp->inp_flags & IN6P_IPV6_V6ONLY)) {
				/*
				 * I believe we should explicitly discard the
				 * packet when mapped addresses are disabled,
				 * rather than send the packet as an IPv6 one.
				 * If we chose the latter approach, the packet
				 * might be sent out on the wire based on the
				 * default route, the situation which we'd
				 * probably want to avoid.
				 * (20010421 jinmei@kame.net)
				 */
				error = OFP_EINVAL;
				goto release;
			}
			if (!OFP_IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr) &&
			    !OFP_IN6_IS_ADDR_V4MAPPED(&inp->in6p_laddr)) {
				/*
				 * when remote addr is an IPv4-mapped address,
				 * local addr should not be an IPv6 address,
				 * since you cannot determine how to map IPv6
				 * source address to IPv4.
				 */
				error = OFP_EINVAL;
				goto release;
			}

			af = OFP_AF_INET;
		}

		if (!OFP_IN6_IS_ADDR_V4MAPPED(faddr)) {
			if (OFP_IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
				OFP_IFNET_LOCK_READ(ifaddr6_list);
				if (!OFP_TAILQ_EMPTY(ofp_get_ifaddr6head())) {
					memcpy(in6a.ofp_s6_addr,
						OFP_TAILQ_FIRST(ofp_get_ifaddr6head())->ip6_addr,
						16);
					faddr = &in6a;
					error = 0;
				}
				OFP_IFNET_UNLOCK_READ(ifaddr6_list);
			} else
				error = ofp_in6_selectsrc(sin6, NULL, inp,
					NULL, td->td_ucred, &oifp, &in6a);
			if (error)
				goto release;
			(void)oifp;
#if 0
			if (oifp && scope_ambiguous &&
			    (error = in6_setscope(&sin6->sin6_addr,
			    oifp, NULL))) {
				goto release;
			}
#endif
			laddr = &in6a;
		} else
			laddr = &inp->in6p_laddr;	/* XXX */

		if (laddr == NULL) {
			if (error == 0)
				error = OFP_EADDRNOTAVAIL;
			goto release;
		}
		if (inp->inp_lport == 0 &&
		    (error = ofp_in6_pcbsetport(laddr, inp, td->td_ucred)) != 0) {
			/* Undo an address bind that may have occurred. */
			inp->in6p_laddr = ofp_in6addr_any;
			goto release;
		}
	} else {
		if (OFP_IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_faddr)) {
			error = OFP_ENOTCONN;
			goto release;
		}
		if (OFP_IN6_IS_ADDR_V4MAPPED(&inp->in6p_faddr)) {
			if ((inp->inp_flags & IN6P_IPV6_V6ONLY)) {
				/*
				 * XXX: this case would happen when the
				 * application sets the V6ONLY flag after
				 * connecting the foreign address.
				 * Such applications should be fixed,
				 * so we bark here.
				 */
				log(LOG_INFO, "udp6_output: IPV6_V6ONLY "
				    "option was set for a connected socket\n");
				error = OFP_EINVAL;
				goto release;
			} else
				af = OFP_AF_INET;
		}
		laddr = &inp->in6p_laddr;
		faddr = &inp->in6p_faddr;
		fport = inp->inp_fport;
	}

	if (af == OFP_AF_INET)
		hlen = sizeof(struct ofp_ip);

	switch (af) {
	case OFP_AF_INET6:
/* fill ipv6 header */
		ip6 = odp_packet_push_head(m, sizeof(struct ofp_udphdr) + hlen);
		if (!ip6) {
			error = OFP_ENOBUFS;
			goto release;
		}
		odp_packet_l3_offset_set(m, 0);
		odp_packet_l4_offset_set(m, hlen);

		ip6->ofp_ip6_flow	= inp->inp_flow & OFP_IPV6_FLOWINFO_MASK;
		ip6->ofp_ip6_vfc 	= 0;
		ip6->ofp_ip6_vfc	&= ~OFP_IPV6_VERSION_MASK;
		ip6->ofp_ip6_vfc	|= OFP_IPV6_VERSION;
		ip6->ofp_ip6_plen	= odp_cpu_to_be_16((uint16_t) plen);
		ip6->ofp_ip6_nxt	= OFP_IPPROTO_UDP;
		ip6->ofp_ip6_hlim	= inp->in6p_hops;
		ip6->ip6_src	= *laddr;
		ip6->ip6_dst	= *faddr;

/* fill udp header */
		udp6 = (struct ofp_udphdr *) (ip6 + 1);
		udp6->uh_sport = inp->inp_lport; /* lport is always set in the PCB */
		udp6->uh_dport = fport;
		if (plen <= 0xffff)
			udp6->uh_ulen = odp_cpu_to_be_16((uint16_t)plen);
		else
			udp6->uh_ulen = 0;
		udp6->uh_sum = 0;
		udp6->uh_sum = (uint16_t)ofp_in6_cksum(m, OFP_IPPROTO_UDP,
			sizeof(struct ofp_ip6_hdr),
			plen);
		UDPSTAT_INC(udps_opackets);
#if 0
		error = ip6_output(m, optp, NULL, flags, inp->in6p_moptions,
		    NULL, inp);
#else
		if (ofp_ip6_output(m, NULL) ==  OFP_PKT_DROP)
			error = OFP_EIO;
		else
			error = 0;
#endif
		break;
	case OFP_AF_INET:
		error = OFP_EAFNOSUPPORT;
		goto release;
	}
	goto releaseopt;
release:
	odp_packet_free(m);
releaseopt:
	if (control != ODP_PACKET_INVALID) {
#if 0
		ip6_clearpktopts(&opt, -1);
#endif
		odp_packet_free(control);
	}

	return (error);
}


static void
udp6_abort(struct socket *so)
{
	struct inpcb *inp;

	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("udp6_abort: inp == NULL"));

	if (inp->inp_vflag & INP_IPV4) {
		struct pr_usrreqs *pru;

		pru = ofp_inetsw[ofp_ip_protox[OFP_IPPROTO_UDP]].pr_usrreqs;
		(*pru->pru_abort)(so);
		return;
	}

	INP_WLOCK(inp);
	if (!OFP_IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_faddr)) {
		INP_HASH_WLOCK(&ofp_udbinfo);
		ofp_in6_pcbdisconnect(inp);
		inp->in6p_laddr = ofp_in6addr_any;
		INP_HASH_WUNLOCK(&ofp_udbinfo);
		ofp_soisdisconnected(so);
	}
	INP_WUNLOCK(inp);
}

static int
udp6_attach(struct socket *so, int proto, struct thread *td)
{
	struct inpcb *inp;
	int error;

	(void)proto;
	(void)td;

	inp = sotoinpcb(so);
	KASSERT(inp == NULL, ("udp6_attach: inp != NULL"));

	/* Constant space reserved. ??
	if (so->so_snd.sb_hiwat == 0 || so->so_rcv.sb_hiwat == 0) {
		error = soreserve(so, udp_sendspace, udp_recvspace);
		if (error)
			return (error);
	}*/

	INP_INFO_WLOCK(&ofp_udbinfo);

	error = ofp_in_pcballoc(so, &ofp_udbinfo);
	if (error) {
		INP_INFO_WUNLOCK(&ofp_udbinfo);
		return (error);
	}

	inp = (struct inpcb *)so->so_pcb;
	inp->inp_vflag |= INP_IPV6;
	if ((inp->inp_flags & IN6P_IPV6_V6ONLY) == 0)
		inp->inp_vflag |= INP_IPV4;

	inp->in6p_hops = V_ip6_defhlim;
	inp->in6p_cksum = -1;	/* just to be sure */
	/*
	 * XXX: ugly!!
	 * IPv4 TTL initialization is necessary for an IPv6 socket as well,
	 * because the socket may be bound to an IPv6 wildcard address,
	 * which may match an IPv4-mapped IPv6 address.
	 */
	inp->inp_ip_ttl = V_ip_defttl;

	/* Replaced by static allocation.
	error = udp_newudpcb(inp);
	if (error) {
		in_pcbdetach(inp);
		in_pcbfree(inp);
		INP_INFO_WUNLOCK(&V_udbinfo);
		return (error);
	}
	*/
	inp->inp_ppcb = &inp->ppcb_space.udp_ppcb;

	INP_WUNLOCK(inp);
	INP_INFO_WUNLOCK(&ofp_udbinfo);

	return (0);
}


static int
udp6_bind(struct socket *so, struct ofp_sockaddr *nam, struct thread *td)
{
	struct inpcb *inp;
	int error;

	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("udp6_bind: inp == NULL"));

	INP_WLOCK(inp);
	INP_HASH_WLOCK(&ofp_udbinfo);
	inp->inp_vflag &= ~INP_IPV4;
	inp->inp_vflag |= INP_IPV6;
	if ((inp->inp_flags & IN6P_IPV6_V6ONLY) == 0) {
		struct ofp_sockaddr_in6 *sin6_p;

		sin6_p = (struct ofp_sockaddr_in6 *)nam;

		if (OFP_IN6_IS_ADDR_UNSPECIFIED(&sin6_p->sin6_addr))
			inp->inp_vflag |= INP_IPV4;
		else if (OFP_IN6_IS_ADDR_V4MAPPED(&sin6_p->sin6_addr)) {
			struct ofp_sockaddr_in sin;

			ofp_in6_sin6_2_sin(&sin, sin6_p);
			inp->inp_vflag |= INP_IPV4;
			inp->inp_vflag &= ~INP_IPV6;
			error = ofp_in_pcbbind(inp,
				(struct ofp_sockaddr *)&sin,
				td->td_ucred);
			goto out;
		}
	}

	error = ofp_in6_pcbbind(inp, nam, td->td_ucred);
out:
	INP_HASH_WUNLOCK(&ofp_udbinfo);
	INP_WUNLOCK(inp);
	return (error);
}

static void
udp6_close(struct socket *so)
{
	struct inpcb *inp;

	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("udp6_close: inp == NULL"));

	if (inp->inp_vflag & INP_IPV4) {
		struct pr_usrreqs *pru;

		pru = ofp_inetsw[ofp_ip_protox[OFP_IPPROTO_UDP]].pr_usrreqs;
		(*pru->pru_disconnect)(so);
		return;
	}

	INP_WLOCK(inp);
	if (!OFP_IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_faddr)) {
		INP_HASH_WLOCK(&ofp_udbinfo);
		ofp_in6_pcbdisconnect(inp);
		inp->in6p_laddr = ofp_in6addr_any;
		INP_HASH_WUNLOCK(&ofp_udbinfo);
		ofp_soisdisconnected(so);
	}
	INP_WUNLOCK(inp);
}

static int
udp6_connect(struct socket *so, struct ofp_sockaddr *nam, struct thread *td)
{
	struct inpcb *inp;
	struct ofp_sockaddr_in6 *sin6;
	int error;

	inp = sotoinpcb(so);
	sin6 = (struct ofp_sockaddr_in6 *)nam;
	KASSERT(inp != NULL, ("udp6_connect: inp == NULL"));

	/*
	 * XXXRW: Need to clarify locking of v4/v6 flags.
	 */
	INP_WLOCK(inp);

	if (OFP_IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
		struct ofp_sockaddr_in sin;

		if ((inp->inp_flags & IN6P_IPV6_V6ONLY) != 0) {
			error = OFP_EINVAL;
			goto out;
		}
		if (inp->inp_faddr.s_addr != OFP_INADDR_ANY) {
			error = OFP_EISCONN;
			goto out;
		}
		ofp_in6_sin6_2_sin(&sin, sin6);
		inp->inp_vflag |= INP_IPV4;
		inp->inp_vflag &= ~INP_IPV6;
#if 0
		error = prison_remote_ip4(td->td_ucred, &sin.sin_addr);
		if (error != 0)
			goto out;
#endif /* 0 */
		INP_HASH_WLOCK(&ofp_udbinfo);
		error = ofp_in_pcbconnect(inp, (struct ofp_sockaddr *)&sin,
		    td->td_ucred);
		INP_HASH_WUNLOCK(&ofp_udbinfo);
		if (error == 0)
			ofp_soisconnected(so);
		goto out;
	}

	if (!OFP_IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_faddr)) {
		error = OFP_EISCONN;
		goto out;
	}
	inp->inp_vflag &= ~INP_IPV4;
	inp->inp_vflag |= INP_IPV6;
#if 0
	error = prison_remote_ip6(td->td_ucred, &sin6->sin6_addr);
	if (error != 0)
		goto out;
#endif
	INP_HASH_WLOCK(&ofp_udbinfo);
	error = ofp_in6_pcbconnect(inp, nam, td->td_ucred);
	INP_HASH_WUNLOCK(&ofp_udbinfo);
	if (error == 0)
		ofp_soisconnected(so);
out:
	INP_WUNLOCK(inp);
	return (error);
}

static void
udp6_detach(struct socket *so)
{
	struct inpcb *inp;
	struct udpcb *up;

	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("udp6_detach: inp == NULL"));

	INP_INFO_WLOCK(&ofp_udbinfo);
	INP_WLOCK(inp);
	up = intoudpcb(inp);
	KASSERT(up != NULL, ("%s: up == NULL", __func__));
	ofp_in_pcbdetach(inp);
	ofp_in_pcbfree(inp);
	INP_INFO_WUNLOCK(&ofp_udbinfo);
}


static int
udp6_disconnect(struct socket *so)
{
	struct inpcb *inp;

	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("udp6_disconnect: inp == NULL"));

	if (inp->inp_vflag & INP_IPV4) {
		struct pr_usrreqs *pru;

		pru = ofp_inetsw[ofp_ip_protox[OFP_IPPROTO_UDP]].pr_usrreqs;
		(void)(*pru->pru_disconnect)(so);
		return (0);
	}


	INP_WLOCK(inp);

	if (OFP_IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_faddr)) {
		INP_WUNLOCK(inp);
		return OFP_ENOTCONN;
	}

	INP_HASH_WLOCK(&ofp_udbinfo);
	ofp_in6_pcbdisconnect(inp);
	inp->in6p_laddr = ofp_in6addr_any;
	INP_HASH_WUNLOCK(&ofp_udbinfo);
	OFP_SOCK_LOCK(so);
	so->so_state &= ~SS_ISCONNECTED;		/* XXX */
	OFP_SOCK_UNLOCK(so);
	INP_WUNLOCK(inp);
	return (0);
}

static int
udp6_send(struct socket *so, int flags, odp_packet_t m,
    struct ofp_sockaddr *addr, odp_packet_t control, struct thread *td)
{
	struct inpcb *inp;
	int error = 0;

	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("udp6_send: inp == NULL"));

	INP_WLOCK(inp);
	if (addr) {
		if (addr->sa_len != sizeof(struct ofp_sockaddr_in6)) {
			error = OFP_EINVAL;
			goto bad;
		}
		if (addr->sa_family != OFP_AF_INET6) {
			error = OFP_EAFNOSUPPORT;
			goto bad;
		}
	}

	if ((inp->inp_flags & IN6P_IPV6_V6ONLY) == 0) {
		int hasv4addr;
		struct ofp_sockaddr_in6 *sin6 = 0;

		if (addr == 0)
			hasv4addr = (inp->inp_vflag & INP_IPV4);
		else {
			sin6 = (struct ofp_sockaddr_in6 *)addr;
			hasv4addr = OFP_IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)
			    ? 1 : 0;
		}
		if (hasv4addr) {
			struct pr_usrreqs *pru;

			/*
			 * XXXRW: We release UDP-layer locks before calling
			 * udp_send() in order to avoid recursion.  However,
			 * this does mean there is a short window where inp's
			 * fields are unstable.  Could this lead to a
			 * potential race in which the factors causing us to
			 * select the UDPv4 output routine are invalidated?
			 */
			INP_WUNLOCK(inp);
			if (sin6)
				ofp_in6_sin6_2_sin_in_sock(addr);
			pru = ofp_inetsw[
				ofp_ip_protox[OFP_IPPROTO_UDP]].pr_usrreqs;
			/* addr will just be freed in sendit(). */
			return ((*pru->pru_send)(so, flags, m, addr, control,
			    td));

		}
	}

	INP_HASH_WLOCK(&ofp_udbinfo);
	error = udp6_output(inp, m, addr, control, td);
	INP_HASH_WUNLOCK(&ofp_udbinfo);

	INP_WUNLOCK(inp);
	return (error);

bad:
	INP_WUNLOCK(inp);
	odp_packet_free(m);
	return (error);
}

struct pr_usrreqs ofp_udp6_usrreqs = {
	.pru_abort =		udp6_abort,
	.pru_attach =		udp6_attach,
	.pru_bind =		udp6_bind,
	.pru_connect =		udp6_connect,
	.pru_control =		NULL, /*in6_control,*/
	.pru_detach =		udp6_detach,
	.pru_disconnect =	udp6_disconnect,
	.pru_peeraddr =		NULL, /*in6_mapped_peeraddr,*/
	.pru_send =		udp6_send,
	.pru_shutdown =		ofp_udp_shutdown,
	.pru_sockaddr =		NULL, /*in6_mapped_sockaddr,*/
	.pru_soreceive =	ofp_soreceive_dgram,
	.pru_sosend =		ofp_sosend_dgram,
	.pru_sosetlabel =	NULL, /*in_pcbsosetlabel,*/
	.pru_close =		udp6_close
};
