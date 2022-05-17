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
 *	$KAME: icmp6.c,v 1.211 2001/04/04 05:56:20 itojun Exp $
 */

/*-
 * Copyright (c) 1982, 1986, 1988, 1993
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
 *	@(#)ip_icmp.c	8.2 (Berkeley) 1/4/94
 */

#include "ofpi.h"
#include "ofpi_log.h"
#include "ofpi_util.h"
#include "ofpi_protosw.h"
#include "ofpi_route.h"
#include "ofpi_ip6.h"
#include "ofpi_ip6_var.h"
#include "ofpi_ip6protosw.h"
#include "ofpi_icmp6.h"
#include "ofpi_pkt_processing.h"

#if 0
#include <sys/cdefs.h>
__FBSDID("$FreeBSD: release/9.1.0/sys/netinet6/icmp6.c 238242 2012-07-08 12:34:12Z bz $");

#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_ipsec.h"

#include <sys/param.h>
#include <sys/domain.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/proc.h>

#include <sys/signalvar.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sx.h>
#include <sys/syslog.h>
#include <sys/systm.h>
#include <sys/time.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_llatbl.h>
#include <net/if_types.h>
#include <net/vnet.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp_var.h>

#include <netinet6/in6_ifattach.h>
#include <netinet6/in6_pcb.h>
#include <netinet6/ip6_var.h>
#include <netinet6/scope6_var.h>
#include <netinet6/mld6_var.h>
#include <netinet6/nd6.h>
#include <netinet6/send.h>

#ifdef IPSEC
#include <netipsec/ipsec.h>
#include <netipsec/key.h>
#endif
#endif /* 0*/

#if 0
extern struct domain inet6domain;

VNET_DEFINE(struct icmp6stat, icmp6stat);

VNET_DECLARE(struct inpcbinfo, ripcbinfo);
VNET_DECLARE(struct inpcbhead, ripcb);
VNET_DECLARE(int, icmp6errppslim);
static VNET_DEFINE(int, icmp6errpps_count) = 0;
static VNET_DEFINE(struct timeval, icmp6errppslim_last);
VNET_DECLARE(int, icmp6_nodeinfo);

#define	V_ripcbinfo			VNET(ripcbinfo)
#define	V_ripcb				VNET(ripcb)
#define	V_icmp6errppslim		VNET(icmp6errppslim)
#define	V_icmp6errpps_count		VNET(icmp6errpps_count)
#define	V_icmp6errppslim_last		VNET(icmp6errppslim_last)
#define	V_icmp6_nodeinfo		VNET(icmp6_nodeinfo)

static void icmp6_errcount(struct icmp6errstat *, int, int);
static int icmp6_rip6_input(struct mbuf **, int);
static int icmp6_ratelimit(const struct in6_addr *, const int, const int);
static const char *icmp6_redirect_diag __P((struct in6_addr *,
	struct in6_addr *, struct in6_addr *));
static struct mbuf *ni6_input(struct mbuf *, int);
static struct mbuf *ni6_nametodns(const char *, int, int);
static int ni6_dnsmatch(const char *, int, const char *, int);
static int ni6_addrs __P((struct icmp6_nodeinfo *, struct mbuf *,
			  struct ifnet **, struct in6_addr *));
static int ni6_store_addrs __P((struct icmp6_nodeinfo *, struct icmp6_nodeinfo *,
				struct ifnet *, int));
#endif /* 0*/
static int icmp6_notify_error(odp_packet_t, int, int, int);



#if 0
/*
 * Kernel module interface for updating icmp6stat.  The argument is an index
 * into icmp6stat treated as an array of u_quad_t.  While this encodes the
 * general layout of icmp6stat into the caller, it doesn't encode its
 * location, so that future changes to add, for example, per-CPU stats
 * support won't cause binary compatibility problems for kernel modules.
 */
void
kmod_icmp6stat_inc(int statnum)
{

	(*((u_quad_t *)&V_icmp6stat + statnum))++;
}

static void
icmp6_errcount(struct icmp6errstat *stat, int type, int code)
{
	switch (type) {
	case ICMP6_DST_UNREACH:
		switch (code) {
		case ICMP6_DST_UNREACH_NOROUTE:
			stat->icp6errs_dst_unreach_noroute++;
			return;
		case ICMP6_DST_UNREACH_ADMIN:
			stat->icp6errs_dst_unreach_admin++;
			return;
		case ICMP6_DST_UNREACH_BEYONDSCOPE:
			stat->icp6errs_dst_unreach_beyondscope++;
			return;
		case ICMP6_DST_UNREACH_ADDR:
			stat->icp6errs_dst_unreach_addr++;
			return;
		case ICMP6_DST_UNREACH_NOPORT:
			stat->icp6errs_dst_unreach_noport++;
			return;
		}
		break;
	case ICMP6_PACKET_TOO_BIG:
		stat->icp6errs_packet_too_big++;
		return;
	case ICMP6_TIME_EXCEEDED:
		switch (code) {
		case ICMP6_TIME_EXCEED_TRANSIT:
			stat->icp6errs_time_exceed_transit++;
			return;
		case ICMP6_TIME_EXCEED_REASSEMBLY:
			stat->icp6errs_time_exceed_reassembly++;
			return;
		}
		break;
	case ICMP6_PARAM_PROB:
		switch (code) {
		case ICMP6_PARAMPROB_HEADER:
			stat->icp6errs_paramprob_header++;
			return;
		case ICMP6_PARAMPROB_NEXTHEADER:
			stat->icp6errs_paramprob_nextheader++;
			return;
		case ICMP6_PARAMPROB_OPTION:
			stat->icp6errs_paramprob_option++;
			return;
		}
		break;
	case ND_REDIRECT:
		stat->icp6errs_redirect++;
		return;
	}
	stat->icp6errs_unknown++;
}
#endif
/*
 * A wrapper function for icmp6_error() necessary when the erroneous packet
 * may not contain enough scope zone information.
 */
void
ofp_icmp6_error2(odp_packet_t m, int type, int code, int param,
	struct ofp_ifnet *ifp)
{
	struct ofp_ip6_hdr *ip6;

	if (ifp == NULL)
		return;

	if (odp_packet_len(m) < odp_packet_l3_offset(m) +
		sizeof(struct ofp_ip6_hdr))
			return;

	ip6 = (struct ofp_ip6_hdr *)odp_packet_l3_ptr(m, NULL);
	(void)ip6;
#if 0
	/*ToDo: add in6_setscope()*/
	if (in6_setscope(&ip6->ip6_src, ifp, NULL) != 0)
		return;
	if (in6_setscope(&ip6->ip6_dst, ifp, NULL) != 0)
		return;
#endif
	ofp_icmp6_error(m, type, code, param);
}
/*
 * Generate an error packet of type error in response to bad IP6 packet.
 */
void
ofp_icmp6_error(odp_packet_t m, int type, int code, int param)
{
	struct ofp_ip6_hdr *oip6;
	int oip6_len;
	int oip6_cpy_len;
	odp_packet_t pkt;
	uint32_t preplen;
	struct ofp_ip6_hdr *nip6;
	struct ofp_icmp6_hdr *nicmp6;

	/*ICMP6STAT_INC(icp6s_error);*/

	/* count per-type-code statistics */
	/*icmp6_errcount(&V_icmp6stat.icp6s_outerrhist, type, code);*/

	if (odp_packet_len(m) < odp_packet_l3_offset(m) +
		sizeof(struct ofp_ip6_hdr))
			goto freeit;


	oip6 = (struct ofp_ip6_hdr *)odp_packet_l3_ptr(m, NULL);
	oip6_len = odp_be_to_cpu_16(oip6->ofp_ip6_plen) +
		sizeof(struct ofp_ip6_hdr);

	/*
	 * If the destination address of the erroneous packet is a multicast
	 * address, or the packet was sent using link-layer multicast,
	 * we should basically suppress sending an error (RFC 2463, Section
	 * 2.4).
	 * We have two exceptions (the item e.2 in that section):
	 * - the Packet Too Big message can be sent for path MTU discovery.
	 * - the Parameter Problem Message that can be allowed an icmp6 error
	 *   in the option type field.  This check has been done in
	 *   ip6_unknown_opt(), so we can just check the type and code.
	 */
	if (OFP_IN6_IS_ADDR_MULTICAST(&oip6->ip6_dst) &&
	    (type != OFP_ICMP6_PACKET_TOO_BIG &&
	     (type != OFP_ICMP6_PARAM_PROB ||
	      code != OFP_ICMP6_PARAMPROB_OPTION)))
		goto freeit;

	/*
	 * RFC 2463, 2.4 (e.5): source address check.
	 * XXX: the case of anycast source?
	 */
	if (OFP_IN6_IS_ADDR_UNSPECIFIED(&oip6->ip6_src) ||
	    OFP_IN6_IS_ADDR_MULTICAST(&oip6->ip6_src))
		goto freeit;
#if 0
	/*
	 * If we are about to send ICMPv6 against ICMPv6 error/redirect,
	 * don't do it.
	 */
	int off;
	int nxt;

	nxt = -1;
	off = ip6_lasthdr(m, 0, IPPROTO_IPV6, &nxt);
	if (off >= 0 && nxt == IPPROTO_ICMPV6) {
		struct icmp6_hdr *icp;

#ifndef PULLDOWN_TEST
		IP6_EXTHDR_CHECK(m, 0, off + sizeof(struct icmp6_hdr), );
		icp = (struct icmp6_hdr *)(mtod(m, caddr_t) + off);
#else
		IP6_EXTHDR_GET(icp, struct icmp6_hdr *, m, off,
			sizeof(*icp));
		if (icp == NULL) {
			ICMP6STAT_INC(icp6s_tooshort);
			return;
		}
#endif
		if (icp->icmp6_type < ICMP6_ECHO_REQUEST ||
		    icp->icmp6_type == ND_REDIRECT) {
			/*
			 * ICMPv6 error
			 * Special case: for redirect (which is
			 * informational) we must not send icmp6 error.
			 */
			ICMP6STAT_INC(icp6s_canterror);
			goto freeit;
		} else {
			/* ICMPv6 informational - send the error */
		}
	} else {
		/* non-ICMPv6 - send the error */
	}
#endif


#if 0
	/* Finally, do rate limitation check. */
	if (icmp6_ratelimit(&oip6->ip6_src, type, code)) {
		ICMP6STAT_INC(icp6s_toofreq);
		goto freeit;
	}
#endif
	/*
	 * OK, ICMP6 can be generated.
	 */

	preplen = sizeof(struct ofp_ip6_hdr) + sizeof(struct ofp_icmp6_hdr);

	oip6_cpy_len = oip6_len;
	if (oip6_cpy_len > OFP_ICMPV6_PLD_MAXLEN)
		oip6_cpy_len = OFP_ICMPV6_PLD_MAXLEN;

	pkt  = ofp_packet_alloc_from_pool(odp_packet_pool(m),
		odp_packet_l3_offset(m) + preplen + oip6_cpy_len);
	if (pkt == ODP_PACKET_INVALID)
		goto freeit;

	odp_packet_l2_offset_set(pkt, odp_packet_l2_offset(m));
	odp_packet_l3_offset_set(pkt, odp_packet_l3_offset(m));

	memcpy((uint8_t *)odp_packet_l3_ptr(pkt, NULL) + preplen,
		odp_packet_l3_ptr(m, NULL),
		oip6_cpy_len);
	odp_packet_free(m);

	oip6 = (struct ofp_ip6_hdr *)((uint8_t *)odp_packet_l3_ptr(pkt, NULL) +
			preplen);

	nip6 = (struct ofp_ip6_hdr *)odp_packet_l3_ptr(pkt, NULL);
	nip6->ip6_src  = oip6->ip6_src;
	nip6->ip6_dst  = oip6->ip6_dst;
	nip6->ofp_ip6_plen = odp_cpu_to_be_16(sizeof(struct ofp_icmp6_hdr) +
				oip6_cpy_len);

	ofp_in6_clearscope(&oip6->ip6_src);
	ofp_in6_clearscope(&oip6->ip6_dst);

	nicmp6 = (struct ofp_icmp6_hdr *)(nip6 + 1);
	nicmp6->icmp6_type = type;
	nicmp6->icmp6_code = code;
	nicmp6->ofp_icmp6_pptr = odp_cpu_to_be_32((uint32_t)param);

	/*ICMP6STAT_INC(icp6s_outhist[type]);*/
	ofp_icmp6_reflect(pkt, sizeof(struct ofp_ip6_hdr));

	return;
 freeit:
	/*
	 * If we can't tell whether or not we can generate ICMP6, free it.
	 */
	odp_packet_free(m);

}


/*
 * Process a received ICMP6 message.
 */
enum ofp_return_code
ofp_icmp6_input(odp_packet_t *m, int *offp, int *nxt)
{
	/*struct ofp_ether_header *eth;*/
	struct ofp_ip6_hdr *ip6;
	int ip6len;
	struct ofp_icmp6_hdr *icmp6;
	uint32_t icmp6len;
	int off = *offp;
	int code, sum;
	struct ofp_ifnet *ifp;

	*nxt = OFP_IPPROTO_DONE;
	ifp = odp_packet_user_ptr(*m);
	(void)ifp;
	/*eth = (struct ofp_ether_header *) odp_packet_l2_ptr(m, NULL);*/

	OFP_IP6_EXTHDR_CHECK(*m, off, sizeof(struct ofp_icmp6_hdr),
		OFP_PKT_DROP);

	/*
	 * Locate icmp6 structure in packet, and check
	 * that not corrupted and of at least minimum length
	 */

	ip6 = (struct ofp_ip6_hdr *)odp_packet_l3_ptr(*m, NULL);
	ip6len = sizeof(struct ofp_ip6_hdr) +
		odp_be_to_cpu_16(ip6->ofp_ip6_plen);
	(void)ip6len;

#if 0
	/*
	 * Check multicast group membership.
	 * Note: SSM filters are not applied for ICMPv6 traffic.
	 */
	if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
		struct in6_multi	*inm;

		inm = in6m_lookup(ifp, &ip6->ip6_dst);
		if (inm == NULL) {
			IP6STAT_INC(ip6s_notmember);
			in6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_discard);
			goto freeit;
		}
	}
#endif
	/*
	 * calculate the checksum
	 */
	icmp6 = (struct ofp_icmp6_hdr *)((uint8_t *)ip6 + *offp);
	icmp6len = odp_packet_len(*m)  - odp_packet_l3_offset(*m) - off;
	if (icmp6len < sizeof(struct ofp_icmp6_hdr)) {
		/*ICMP6STAT_INC(icp6s_tooshort);*/
		goto freeit;
	}

	code = icmp6->icmp6_code;

	sum = ofp_in6_cksum(*m, OFP_IPPROTO_ICMPV6, off, icmp6len);
	if (sum != 0) {
		OFP_ERR("ICMP6 checksum error(%d|%x) %s",
		    icmp6->icmp6_type, sum,
		    ofp_print_ip6_addr(&ip6->ip6_src.ofp_s6_addr[0]));
		/*ICMP6STAT_INC(icp6s_checksum);*/
		goto freeit;
	}
#if 0
	if (faithprefix_p != NULL && (*faithprefix_p)(&ip6->ip6_dst)) {
		/*
		 * Deliver very specific ICMP6 type only.
		 * This is important to deliver TOOBIG.  Otherwise PMTUD
		 * will not work.
		 */
		switch (icmp6->icmp6_type) {
		case ICMP6_DST_UNREACH:
		case ICMP6_PACKET_TOO_BIG:
		case ICMP6_TIME_EXCEEDED:
			break;
		default:
			goto freeit;
		}
	}

	ICMP6STAT_INC(icp6s_inhist[icmp6->icmp6_type]);
	icmp6_ifstat_inc(ifp, ifs6_in_msg);
	if (icmp6->icmp6_type < ICMP6_INFOMSG_MASK)
		icmp6_ifstat_inc(ifp, ifs6_in_error);
#endif

	switch (icmp6->icmp6_type) {
	case OFP_ICMP6_DST_UNREACH:
		ofp_icmp6_ifstat_inc(ifp, ifs6_in_dstunreach);
		switch (code) {
		case OFP_ICMP6_DST_UNREACH_NOROUTE:
			code = OFP_PRC_UNREACH_NET;
			break;
		case OFP_ICMP6_DST_UNREACH_ADMIN:
			ofp_icmp6_ifstat_inc(ifp, ifs6_in_adminprohib);
			code = OFP_PRC_UNREACH_PROTOCOL;
			break;
		case OFP_ICMP6_DST_UNREACH_ADDR:
			code = OFP_PRC_HOSTDEAD;
			break;
		case OFP_ICMP6_DST_UNREACH_BEYONDSCOPE:
			/* I mean "source address was incorrect." */
			code = OFP_PRC_PARAMPROB;
			break;
		case OFP_ICMP6_DST_UNREACH_NOPORT:
			code = OFP_PRC_UNREACH_PORT;
			break;
		default:
			goto badcode;
		}
		goto deliver;

	case OFP_ICMP6_PACKET_TOO_BIG:
		ofp_icmp6_ifstat_inc(ifp, ifs6_in_pkttoobig);

		/* validation is made in icmp6_mtudisc_update */

		code = OFP_PRC_MSGSIZE;

		/*
		 * Updating the path MTU will be done after examining
		 * intermediate extension headers.
		 */
		goto deliver;

	case OFP_ICMP6_TIME_EXCEEDED:
		ofp_icmp6_ifstat_inc(ifp, ifs6_in_timeexceed);
		switch (code) {
		case OFP_ICMP6_TIME_EXCEED_TRANSIT:
			code = OFP_PRC_TIMXCEED_INTRANS;
			break;
		case OFP_ICMP6_TIME_EXCEED_REASSEMBLY:
			code = OFP_PRC_TIMXCEED_REASS;
			break;
		default:
			goto badcode;
		}
		goto deliver;

	case OFP_ICMP6_PARAM_PROB:
		ofp_icmp6_ifstat_inc(ifp, ifs6_in_paramprob);
		switch (code) {
		case OFP_ICMP6_PARAMPROB_NEXTHEADER:
			code = OFP_PRC_UNREACH_PROTOCOL;
			break;
		case OFP_ICMP6_PARAMPROB_HEADER:
		case OFP_ICMP6_PARAMPROB_OPTION:
			code = OFP_PRC_PARAMPROB;
			break;
		default:
			goto badcode;
		}
		goto deliver;

	case OFP_ICMP6_ECHO_REQUEST:
		ofp_icmp6_ifstat_inc(ifp, ifs6_in_echo);
		if (code != 0)
			goto badcode;

		icmp6->icmp6_type = OFP_ICMP6_ECHO_REPLY;
		icmp6->icmp6_code = 0;

		ofp_icmp6_reflect(*m, off);

		return OFP_PKT_PROCESSED;

	case OFP_ICMP6_ECHO_REPLY:
		ofp_icmp6_ifstat_inc(ifp, ifs6_in_echoreply);
		if (code != 0)
			goto badcode;

		return OFP_PKT_PROCESSED;
#if 0
	case MLD_LISTENER_QUERY:
	case MLD_LISTENER_REPORT:
	case MLD_LISTENER_DONE:
	case MLDV2_LISTENER_REPORT:
		/*
		 * Drop MLD traffic which is not link-local, has a hop limit
		 * of greater than 1 hop, or which does not have the
		 * IPv6 HBH Router Alert option.
		 * As IPv6 HBH options are stripped in ip6_input() we must
		 * check an mbuf header flag.
		 * XXX Should we also sanity check that these messages
		 * were directed to a link-local multicast prefix?
		 */
		if ((ip6->ip6_hlim != 1) || (m->m_flags & M_RTALERT_MLD) == 0)
			goto freeit;
		if (mld_input(m, off, icmp6len) != 0)
			return (IPPROTO_DONE);
		/* m stays. */
		break;

	case ICMP6_WRUREQUEST:	/* ICMP6_FQDN_QUERY */
	    {
		enum { WRU, FQDN } mode;

		if (!V_icmp6_nodeinfo)
			break;

		if (icmp6len == sizeof(struct icmp6_hdr) + 4)
			mode = WRU;
		else if (icmp6len >= sizeof(struct icmp6_nodeinfo))
			mode = FQDN;
		else
			goto badlen;

		if (mode == FQDN) {
#ifndef PULLDOWN_TEST
			IP6_EXTHDR_CHECK(m, off, sizeof(struct icmp6_nodeinfo),
			    IPPROTO_DONE);
#endif
			n = m_copy(m, 0, M_COPYALL);
			if (n)
				n = ni6_input(n, off);
			/* XXX meaningless if n == NULL */
			noff = sizeof(struct ip6_hdr);
		} else {
			struct prison *pr;
			u_char *p;
			int maxlen, maxhlen, hlen;

			/*
			 * XXX: this combination of flags is pointless,
			 * but should we keep this for compatibility?
			 */
			if ((V_icmp6_nodeinfo & 5) != 5)
				break;

			if (code != 0)
				goto badcode;
			maxlen = sizeof(*nip6) + sizeof(*nicmp6) + 4;
			if (maxlen >= MCLBYTES) {
				/* Give up remote */
				break;
			}
			MGETHDR(n, M_DONTWAIT, m->m_type);
			if (n && maxlen > MHLEN) {
				MCLGET(n, M_DONTWAIT);
				if ((n->m_flags & M_EXT) == 0) {
					m_free(n);
					n = NULL;
				}
			}
			if (n && !m_dup_pkthdr(n, m, M_DONTWAIT)) {
				/*
				 * Previous code did a blind M_COPY_PKTHDR
				 * and said "just for rcvif".  If true, then
				 * we could tolerate the dup failing (due to
				 * the deep copy of the tag chain).  For now
				 * be conservative and just fail.
				 */
				m_free(n);
				n = NULL;
			}
			if (n == NULL) {
				/* Give up remote */
				break;
			}
			n->m_pkthdr.rcvif = NULL;
			n->m_len = 0;
			maxhlen = M_TRAILINGSPACE(n) - maxlen;
			pr = curthread->td_ucred->cr_prison;
			mtx_lock(&pr->pr_mtx);
			hlen = strlen(pr->pr_hostname);
			if (maxhlen > hlen)
				maxhlen = hlen;
			/*
			 * Copy IPv6 and ICMPv6 only.
			 */
			nip6 = mtod(n, struct ip6_hdr *);
			bcopy(ip6, nip6, sizeof(struct ip6_hdr));
			nicmp6 = (struct icmp6_hdr *)(nip6 + 1);
			bcopy(icmp6, nicmp6, sizeof(struct icmp6_hdr));
			p = (u_char *)(nicmp6 + 1);
			bzero(p, 4);
			/* meaningless TTL */
			bcopy(pr->pr_hostname, p + 4, maxhlen);
			mtx_unlock(&pr->pr_mtx);
			noff = sizeof(struct ip6_hdr);
			n->m_pkthdr.len = n->m_len = sizeof(struct ip6_hdr) +
				sizeof(struct icmp6_hdr) + 4 + maxhlen;
			nicmp6->icmp6_type = ICMP6_WRUREPLY;
			nicmp6->icmp6_code = 0;
		}
		if (n) {
			ICMP6STAT_INC(icp6s_reflect);
			ICMP6STAT_INC(icp6s_outhist[ICMP6_WRUREPLY]);
			icmp6_reflect(n, noff);
		}
		break;
	    }

	case ICMP6_WRUREPLY:
		if (code != 0)
			goto badcode;
		break;

	case ND_ROUTER_SOLICIT:
		icmp6_ifstat_inc(ifp, ifs6_in_routersolicit);
		if (code != 0)
			goto badcode;
		if (icmp6len < sizeof(struct nd_router_solicit))
			goto badlen;
		if ((n = m_copym(m, 0, M_COPYALL, M_DONTWAIT)) == NULL) {
			/* give up local */

			/* Send incoming SeND packet to user space. */
			if (send_sendso_input_hook != NULL) {
				IP6_EXTHDR_CHECK(m, off,
				    icmp6len, IPPROTO_DONE);
				error = send_sendso_input_hook(m, ifp,
				    SND_IN, ip6len);
				/* -1 == no app on SEND socket */
				if (error == 0)
					return (IPPROTO_DONE);
				nd6_rs_input(m, off, icmp6len);
			} else
				nd6_rs_input(m, off, icmp6len);
			m = NULL;
			goto freeit;
		}
		if (send_sendso_input_hook != NULL) {
			IP6_EXTHDR_CHECK(n, off,
			    icmp6len, IPPROTO_DONE);
                        error = send_sendso_input_hook(n, ifp,
			    SND_IN, ip6len);
			if (error == 0)
				goto freeit;
			/* -1 == no app on SEND socket */
			nd6_rs_input(n, off, icmp6len);
		} else
			nd6_rs_input(n, off, icmp6len);
		/* m stays. */
		break;

	case ND_ROUTER_ADVERT:
		icmp6_ifstat_inc(ifp, ifs6_in_routeradvert);
		if (code != 0)
			goto badcode;
		if (icmp6len < sizeof(struct nd_router_advert))
			goto badlen;
		if ((n = m_copym(m, 0, M_COPYALL, M_DONTWAIT)) == NULL) {

			/* Send incoming SeND-protected/ND packet to user space. */
			if (send_sendso_input_hook != NULL) {
				error = send_sendso_input_hook(m, ifp,
				    SND_IN, ip6len);
				if (error == 0)
					return (IPPROTO_DONE);
				nd6_ra_input(m, off, icmp6len);
			} else
				nd6_ra_input(m, off, icmp6len);
			m = NULL;
			goto freeit;
		}
		if (send_sendso_input_hook != NULL) {
			error = send_sendso_input_hook(n, ifp,
			    SND_IN, ip6len);
			if (error == 0)
				goto freeit;
			nd6_ra_input(n, off, icmp6len);
		} else
			nd6_ra_input(n, off, icmp6len);
		/* m stays. */
		break;
#endif
	case OFP_ND_NEIGHBOR_SOLICIT:
		ofp_icmp6_ifstat_inc(ifp, ifs6_in_neighborsolicit);
		if (code != 0)
			goto badcode;
		if (icmp6len < sizeof(struct ofp_nd_neighbor_solicit))
			goto badlen;
		ofp_nd6_ns_input(*m, off, icmp6len);
#ifndef SP
		if (icmp6len < (sizeof(struct ofp_nd_neighbor_solicit)  + 8) &&
			(icmp6_data(icmp6)[20] !=
				OFP_ND_OPT_SOURCE_LINKADDR)
			goto badlen;

		ofp_nd6_na_output(ifp, ip6->ip6_src.ofp_s6_addr,
			&icmp6_data(icmp6)[4],
			&icmp6_data(icmp6)[22]);

		odp_packet_free(*m);

		return OFP_PKT_PROCESSED;
#else
		break;
#endif

	case OFP_ND_NEIGHBOR_ADVERT:
		ofp_icmp6_ifstat_inc(ifp, ifs6_in_neighboradvert);
		if (code != 0)
			goto badcode;
		if (icmp6len < sizeof(struct ofp_nd_neighbor_advert))
			goto badlen;
		ofp_nd6_na_input(*m, off, icmp6len);
		break;
#if 0
	case ND_REDIRECT:
		icmp6_ifstat_inc(ifp, ifs6_in_redirect);
		if (code != 0)
			goto badcode;
		if (icmp6len < sizeof(struct nd_redirect))
			goto badlen;
		if ((n = m_copym(m, 0, M_COPYALL, M_DONTWAIT)) == NULL) {
			if (send_sendso_input_hook != NULL) {
				error = send_sendso_input_hook(m, ifp,
				    SND_IN, ip6len);
		 		if (error == 0)
					return (IPPROTO_DONE);
			    icmp6_redirect_input(m, off);
			} else
				icmp6_redirect_input(m, off);
			m = NULL;
			goto freeit;
		}
		if (send_sendso_input_hook != NULL) {
			error = send_sendso_input_hook(n, ifp,
			    SND_IN, ip6len);
			if (error == 0)
				goto freeit;
			icmp6_redirect_input(n, off);
		} else
			icmp6_redirect_input(n, off);
		/* m stays. */
		break;
#endif
	case OFP_ICMP6_ROUTER_RENUMBERING:
		if (code != OFP_ICMP6_ROUTER_RENUMBERING_COMMAND &&
		    code != OFP_ICMP6_ROUTER_RENUMBERING_RESULT)
			goto badcode;
		if (icmp6len < sizeof(struct ofp_icmp6_router_renum))
			goto badlen;
		break;

	default:
		OFP_DBG("Unknown type %d(src=%s, dst=%s)",
			icmp6->icmp6_type,
			ofp_print_ip6_addr(&ip6->ip6_src.ofp_s6_addr[0]),
			ofp_print_ip6_addr(&ip6->ip6_dst.ofp_s6_addr[0]));

		return OFP_PKT_CONTINUE; /* send to SP*/
	}

	return OFP_PKT_CONTINUE; /* send to SP*/

deliver:
	if (icmp6_notify_error(*m, off, icmp6len, code) != 0)
		goto freeit;

	return OFP_PKT_DROP;

badcode:
badlen:
freeit:
	return OFP_PKT_DROP;
}

static int
icmp6_notify_error(odp_packet_t m, int off, int icmp6len, int code)
{
	struct ofp_ip6_hdr *ip6;
	uint32_t ip6len;
	struct ofp_icmp6_hdr *icmp6;
	struct ofp_ip6_hdr *eip6;
	struct ofp_sockaddr_in6 icmp6src, icmp6dst;
#if 0
	uint32_t notifymtu;
#endif

	if ((uint32_t)icmp6len < sizeof(struct ofp_icmp6_hdr) +
		sizeof(struct ofp_ip6_hdr)) {
		/*ICMP6STAT_INC(icp6s_tooshort);*/
		goto freeit;
	}

	ip6 = (struct ofp_ip6_hdr *)odp_packet_l3_ptr(m, &ip6len);
	if (ip6 == NULL)
		goto freeit;

	/* check continuity of headers: IPv6(+opts) + ICMP6 + IPv6 */
	if (ip6len  < off + sizeof(struct ofp_icmp6_hdr) +
		sizeof(struct ofp_ip6_hdr))
		goto freeit;

	icmp6 = (struct ofp_icmp6_hdr *)((uint8_t *)ip6 + off);
	eip6 = (struct ofp_ip6_hdr *)(icmp6 + 1);

	{
		void (*ctlfunc)(int, struct ofp_sockaddr *, void *);
		uint8_t nxt = eip6->ofp_ip6_nxt;
		struct ofp_ip6ctlparam ip6cp;
		struct ofp_in6_addr *finaldst = NULL;
		int eoff = off + sizeof(struct ofp_icmp6_hdr) +
		    sizeof(struct ofp_ip6_hdr);
		struct ofp_ip6_frag *fh;
		struct ofp_ip6_rthdr *rth;
		struct ofp_ip6_rthdr0 *rth0;
		int rthlen;
#if 0
		int icmp6type = icmp6->icmp6_type;
#endif

		/* Detect the upper level protocol */
		while (1) { /* XXX: should avoid infinite loop explicitly? */
			struct ofp_ip6_ext *eh;

			switch (nxt) {
			case OFP_IPPROTO_HOPOPTS:
			case OFP_IPPROTO_DSTOPTS:
			case OFP_IPPROTO_AH:
				if (ip6len < eoff + sizeof(struct ofp_ip6_ext))
					goto freeit;
				eh = (struct ofp_ip6_ext *)((uint8_t *)
					odp_packet_l3_ptr(m, NULL) + eoff);

				if (nxt == OFP_IPPROTO_AH)
					eoff += (eh->ip6e_len + 2) << 2;
				else
					eoff += (eh->ip6e_len + 1) << 3;
				nxt = eh->ip6e_nxt;
				break;

			case OFP_IPPROTO_ROUTING:
				/*
				 * When the erroneous packet contains a
				 * routing header, we should examine the
				 * header to determine the final destination.
				 * Otherwise, we can't properly update
				 * information that depends on the final
				 * destination (e.g. path MTU).
				 */
				if (ip6len < eoff +
					sizeof(struct ofp_ip6_rthdr))
					goto freeit;
				rth = (struct ofp_ip6_rthdr *)((uint8_t *)
					odp_packet_l3_ptr(m, NULL) + eoff);

				rthlen = (rth->ip6r_len + 1) << 3;
				/*
				 * XXX: currently there is no
				 * officially defined type other
				 * than type-0.
				 * Note that if the segment left field
				 * is 0, all intermediate hops must
				 * have been passed.
				 */

				if (rth->ip6r_segleft &&
				    rth->ip6r_type == OFP_IPV6_RTHDR_TYPE_0) {
					int hops;

					if (ip6len < (uint32_t)eoff + rthlen)
						goto freeit;
					rth0 = (struct ofp_ip6_rthdr0 *)
					((uint8_t *)odp_packet_l3_ptr(m, NULL) +
						eoff);
					/* just ignore a bogus header */
					hops = rth0->ip6r0_len/2;
					if ((rth0->ip6r0_len % 2) == 0 && hops)
						finaldst =
							(struct ofp_in6_addr *)
							(rth0 + 1) +
							(hops - 1);
				}

				eoff += rthlen;
				nxt = rth->ip6r_nxt;
				break;
			case OFP_IPPROTO_FRAGMENT:
				if (ip6len < eoff + sizeof(struct ofp_ip6_frag))
					goto freeit;
				fh = (struct ofp_ip6_frag *)
					((uint8_t *)odp_packet_l3_ptr(m, NULL) +
					 eoff);

				/*
				 * Data after a fragment header is meaningless
				 * unless it is the first fragment, but
				 * we'll go to the notify label for path MTU
				 * discovery.
				 */
				if (fh->ip6f_offlg & OFP_IP6F_OFF_MASK)
					goto notify;

				eoff += sizeof(struct ofp_ip6_frag);
				nxt = fh->ip6f_nxt;
				break;
			default:
				/*
				 * This case includes ESP and the No Next
				 * Header.  In such cases going to the notify
				 * label does not have any meaning
				 * (i.e. ctlfunc will be NULL), but we go
				 * anyway since we might have to update
				 * path MTU information.
				 */
				goto notify;
			}
		}
notify:
		bzero(&icmp6dst, sizeof(icmp6dst));

		icmp6dst.sin6_len = sizeof(struct ofp_sockaddr_in6);
		icmp6dst.sin6_family = OFP_AF_INET6;
		if (finaldst == NULL)
			icmp6dst.sin6_addr = eip6->ip6_dst;
		else
			icmp6dst.sin6_addr = *finaldst;
#if 0
		if (in6_setscope(&icmp6dst.sin6_addr, m->m_pkthdr.rcvif, NULL))
			goto freeit;
#endif
		bzero(&icmp6src, sizeof(icmp6src));
		icmp6src.sin6_len = sizeof(struct ofp_sockaddr_in6);
		icmp6src.sin6_family = OFP_AF_INET6;
		icmp6src.sin6_addr = eip6->ip6_src;
#if 0
		if (in6_setscope(&icmp6src.sin6_addr, m->m_pkthdr.rcvif, NULL))
			goto freeit;
#endif
		icmp6src.sin6_flowinfo =
		    (eip6->ofp_ip6_flow & OFP_IPV6_FLOWLABEL_MASK);

		if (finaldst == NULL)
			finaldst = &eip6->ip6_dst;

		ip6cp.ip6c_m = m;
		ip6cp.ip6c_icmp6 = icmp6;
		ip6cp.ip6c_ip6 = (struct ofp_ip6_hdr *)(icmp6 + 1);
		ip6cp.ip6c_off = eoff;
		ip6cp.ip6c_finaldst = finaldst;
		ip6cp.ip6c_src = &icmp6src;
		ip6cp.ip6c_nxt = nxt;
#if 0
		m_addr_changed(m);

		if (icmp6type == ICMP6_PACKET_TOO_BIG) {
			notifymtu = odp_be_to_cpu_32(icmp6->icmp6_mtu);
			ip6cp.ip6c_cmdarg = (void *)&notifymtu;
			icmp6_mtudisc_update(&ip6cp, 1);	/*XXX*/
		}
#endif
		ctlfunc = (void (*)(int, struct ofp_sockaddr *, void *))
		    (ofp_inet6sw[ofp_ip6_protox[nxt]].pr_ctlinput);
		if (ctlfunc)
			(void)(*ctlfunc)(code,
				(struct ofp_sockaddr *)&icmp6dst,
				&ip6cp);
	}

	return (0);

freeit:
	return (-1);
}

#if 0
void
icmp6_mtudisc_update(struct ip6ctlparam *ip6cp, int validated)
{
	struct in6_addr *dst = ip6cp->ip6c_finaldst;
	struct icmp6_hdr *icmp6 = ip6cp->ip6c_icmp6;
	struct mbuf *m = ip6cp->ip6c_m;	/* will be necessary for scope issue */
	u_int mtu = odp_be_to_cpu_32(icmp6->icmp6_mtu);
	struct in_conninfo inc;

#if 0
	/*
	 * RFC2460 section 5, last paragraph.
	 * even though minimum link MTU for IPv6 is IPV6_MMTU,
	 * we may see ICMPv6 too big with mtu < IPV6_MMTU
	 * due to packet translator in the middle.
	 * see ip6_output() and ip6_getpmtu() "alwaysfrag" case for
	 * special handling.
	 */
	if (mtu < IPV6_MMTU)
		return;
#endif

	/*
	 * we reject ICMPv6 too big with abnormally small value.
	 * XXX what is the good definition of "abnormally small"?
	 */
	if (mtu < sizeof(struct ip6_hdr) + sizeof(struct ip6_frag) + 8)
		return;

	if (!validated)
		return;

	/*
	 * In case the suggested mtu is less than IPV6_MMTU, we
	 * only need to remember that it was for above mentioned
	 * "alwaysfrag" case.
	 * Try to be as close to the spec as possible.
	 */
	if (mtu < IPV6_MMTU)
		mtu = IPV6_MMTU - 8;

	bzero(&inc, sizeof(inc));
	inc.inc_flags |= INC_ISIPV6;
	inc.inc6_faddr = *dst;
	if (in6_setscope(&inc.inc6_faddr, m->m_pkthdr.rcvif, NULL))
		return;

	if (mtu < tcp_maxmtu6(&inc, NULL)) {
		tcp_hc_updatemtu(&inc, mtu);
		ICMP6STAT_INC(icp6s_pmtuchg);
	}
}

/*
 * Process a Node Information Query packet, based on
 * draft-ietf-ipngwg-icmp-name-lookups-07.
 *
 * Spec incompatibilities:
 * - IPv6 Subject address handling
 * - IPv4 Subject address handling support missing
 * - Proxy reply (answer even if it's not for me)
 * - joins NI group address at in6_ifattach() time only, does not cope
 *   with hostname changes by sethostname(3)
 */
static struct mbuf *
ni6_input(struct mbuf *m, int off)
{
	struct icmp6_nodeinfo *ni6, *nni6;
	struct mbuf *n = NULL;
	struct prison *pr;
	uint16_t qtype;
	int subjlen;
	int replylen = sizeof(struct ip6_hdr) + sizeof(struct icmp6_nodeinfo);
	struct ni_reply_fqdn *fqdn;
	int addrs;		/* for NI_QTYPE_NODEADDR */
	struct ifnet *ifp = NULL; /* for NI_QTYPE_NODEADDR */
	struct in6_addr in6_subj; /* subject address */
	struct ip6_hdr *ip6;
	int oldfqdn = 0;	/* if 1, return pascal string (03 draft) */
	char *subj = NULL;
	struct in6_ifaddr *ia6 = NULL;

	ip6 = mtod(m, struct ip6_hdr *);
#ifndef PULLDOWN_TEST
	ni6 = (struct icmp6_nodeinfo *)(mtod(m, caddr_t) + off);
#else
	IP6_EXTHDR_GET(ni6, struct icmp6_nodeinfo *, m, off, sizeof(*ni6));
	if (ni6 == NULL) {
		/* m is already reclaimed */
		return (NULL);
	}
#endif

	/*
	 * Validate IPv6 source address.
	 * The default configuration MUST be to refuse answering queries from
	 * global-scope addresses according to RFC4602.
	 * Notes:
	 *  - it's not very clear what "refuse" means; this implementation
	 *    simply drops it.
	 *  - it's not very easy to identify global-scope (unicast) addresses
	 *    since there are many prefixes for them.  It should be safer
	 *    and in practice sufficient to check "all" but loopback and
	 *    link-local (note that site-local unicast was deprecated and
	 *    ULA is defined as global scope-wise)
	 */
	if ((V_icmp6_nodeinfo & ICMP6_NODEINFO_GLOBALOK) == 0 &&
	    !IN6_IS_ADDR_LOOPBACK(&ip6->ip6_src) &&
	    !IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_src))
		goto bad;

	/*
	 * Validate IPv6 destination address.
	 *
	 * The Responder must discard the Query without further processing
	 * unless it is one of the Responder's unicast or anycast addresses, or
	 * a link-local scope multicast address which the Responder has joined.
	 * [RFC4602, Section 5.]
	 */
	if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
		if (!IN6_IS_ADDR_MC_LINKLOCAL(&ip6->ip6_dst))
			goto bad;
		/* else it's a link-local multicast, fine */
	} else {		/* unicast or anycast */
		if ((ia6 = ip6_getdstifaddr(m)) == NULL)
			goto bad; /* XXX impossible */

		if ((ia6->ia6_flags & IN6_IFF_TEMPORARY) &&
		    !(V_icmp6_nodeinfo & ICMP6_NODEINFO_TMPADDROK)) {
			ifa_free(&ia6->ia_ifa);
			nd6log((LOG_DEBUG, "ni6_input: ignore node info to "
				"a temporary address in %s:%d",
			       __FILE__, __LINE__));
			goto bad;
		}
		ifa_free(&ia6->ia_ifa);
	}

	/* validate query Subject field. */
	qtype = odp_be_to_cpu_16(ni6->ni_qtype);
	subjlen = m->m_pkthdr.len - off - sizeof(struct icmp6_nodeinfo);
	switch (qtype) {
	case NI_QTYPE_NOOP:
	case NI_QTYPE_SUPTYPES:
		/* 07 draft */
		if (ni6->ni_code == ICMP6_NI_SUBJ_FQDN && subjlen == 0)
			break;
		/* FALLTHROUGH */
	case NI_QTYPE_FQDN:
	case NI_QTYPE_NODEADDR:
	case NI_QTYPE_IPV4ADDR:
		switch (ni6->ni_code) {
		case ICMP6_NI_SUBJ_IPV6:
#if ICMP6_NI_SUBJ_IPV6 != 0
		case 0:
#endif
			/*
			 * backward compatibility - try to accept 03 draft
			 * format, where no Subject is present.
			 */
			if (qtype == NI_QTYPE_FQDN && ni6->ni_code == 0 &&
			    subjlen == 0) {
				oldfqdn++;
				break;
			}
#if ICMP6_NI_SUBJ_IPV6 != 0
			if (ni6->ni_code != ICMP6_NI_SUBJ_IPV6)
				goto bad;
#endif

			if (subjlen != sizeof(struct in6_addr))
				goto bad;

			/*
			 * Validate Subject address.
			 *
			 * Not sure what exactly "address belongs to the node"
			 * means in the spec, is it just unicast, or what?
			 *
			 * At this moment we consider Subject address as
			 * "belong to the node" if the Subject address equals
			 * to the IPv6 destination address; validation for
			 * IPv6 destination address should have done enough
			 * check for us.
			 *
			 * We do not do proxy at this moment.
			 */
			/* m_pulldown instead of copy? */
			m_copydata(m, off + sizeof(struct icmp6_nodeinfo),
			    subjlen, (caddr_t)&in6_subj);
			if (in6_setscope(&in6_subj, m->m_pkthdr.rcvif, NULL))
				goto bad;

			subj = (char *)&in6_subj;
			if (IN6_ARE_ADDR_EQUAL(&ip6->ip6_dst, &in6_subj))
				break;

			/*
			 * XXX if we are to allow other cases, we should really
			 * be careful about scope here.
			 * basically, we should disallow queries toward IPv6
			 * destination X with subject Y,
			 * if scope(X) > scope(Y).
			 * if we allow scope(X) > scope(Y), it will result in
			 * information leakage across scope boundary.
			 */
			goto bad;

		case ICMP6_NI_SUBJ_FQDN:
			/*
			 * Validate Subject name with gethostname(3).
			 *
			 * The behavior may need some debate, since:
			 * - we are not sure if the node has FQDN as
			 *   hostname (returned by gethostname(3)).
			 * - the code does wildcard match for truncated names.
			 *   however, we are not sure if we want to perform
			 *   wildcard match, if gethostname(3) side has
			 *   truncated hostname.
			 */
			pr = curthread->td_ucred->cr_prison;
			mtx_lock(&pr->pr_mtx);
			n = ni6_nametodns(pr->pr_hostname,
			    strlen(pr->pr_hostname), 0);
			mtx_unlock(&pr->pr_mtx);
			if (!n || n->m_next || n->m_len == 0)
				goto bad;
			IP6_EXTHDR_GET(subj, char *, m,
			    off + sizeof(struct icmp6_nodeinfo), subjlen);
			if (subj == NULL)
				goto bad;
			if (!ni6_dnsmatch(subj, subjlen, mtod(n, const char *),
			    n->m_len)) {
				goto bad;
			}
			m_freem(n);
			n = NULL;
			break;

		case ICMP6_NI_SUBJ_IPV4:	/* XXX: to be implemented? */
		default:
			goto bad;
		}
		break;
	}

	/* refuse based on configuration.  XXX ICMP6_NI_REFUSED? */
	switch (qtype) {
	case NI_QTYPE_FQDN:
		if ((V_icmp6_nodeinfo & ICMP6_NODEINFO_FQDNOK) == 0)
			goto bad;
		break;
	case NI_QTYPE_NODEADDR:
	case NI_QTYPE_IPV4ADDR:
		if ((V_icmp6_nodeinfo & ICMP6_NODEINFO_NODEADDROK) == 0)
			goto bad;
		break;
	}

	/* guess reply length */
	switch (qtype) {
	case NI_QTYPE_NOOP:
		break;		/* no reply data */
	case NI_QTYPE_SUPTYPES:
		replylen += sizeof(uint32_t);
		break;
	case NI_QTYPE_FQDN:
		/* XXX will append an mbuf */
		replylen += offsetof(struct ni_reply_fqdn, ni_fqdn_namelen);
		break;
	case NI_QTYPE_NODEADDR:
		addrs = ni6_addrs(ni6, m, &ifp, (struct in6_addr *)subj);
		if ((replylen += addrs * (sizeof(struct in6_addr) +
		    sizeof(uint32_t))) > MCLBYTES)
			replylen = MCLBYTES; /* XXX: will truncate pkt later */
		break;
	case NI_QTYPE_IPV4ADDR:
		/* unsupported - should respond with unknown Qtype? */
		break;
	default:
		/*
		 * XXX: We must return a reply with the ICMP6 code
		 * `unknown Qtype' in this case.  However we regard the case
		 * as an FQDN query for backward compatibility.
		 * Older versions set a random value to this field,
		 * so it rarely varies in the defined qtypes.
		 * But the mechanism is not reliable...
		 * maybe we should obsolete older versions.
		 */
		qtype = NI_QTYPE_FQDN;
		/* XXX will append an mbuf */
		replylen += offsetof(struct ni_reply_fqdn, ni_fqdn_namelen);
		oldfqdn++;
		break;
	}

	/* allocate an mbuf to reply. */
	MGETHDR(n, M_DONTWAIT, m->m_type);
	if (n == NULL) {
		m_freem(m);
		return (NULL);
	}
	M_MOVE_PKTHDR(n, m); /* just for recvif and FIB */
	if (replylen > MHLEN) {
		if (replylen > MCLBYTES) {
			/*
			 * XXX: should we try to allocate more? But MCLBYTES
			 * is probably much larger than IPV6_MMTU...
			 */
			goto bad;
		}
		MCLGET(n, M_DONTWAIT);
		if ((n->m_flags & M_EXT) == 0) {
			goto bad;
		}
	}
	n->m_pkthdr.len = n->m_len = replylen;

	/* copy mbuf header and IPv6 + Node Information base headers */
	bcopy(mtod(m, caddr_t), mtod(n, caddr_t), sizeof(struct ip6_hdr));
	nni6 = (struct icmp6_nodeinfo *)(mtod(n, struct ip6_hdr *) + 1);
	bcopy((caddr_t)ni6, (caddr_t)nni6, sizeof(struct icmp6_nodeinfo));

	/* qtype dependent procedure */
	switch (qtype) {
	case NI_QTYPE_NOOP:
		nni6->ni_code = ICMP6_NI_SUCCESS;
		nni6->ni_flags = 0;
		break;
	case NI_QTYPE_SUPTYPES:
	{
		uint32_t v;
		nni6->ni_code = ICMP6_NI_SUCCESS;
		nni6->ni_flags = odp_cpu_to_be_16(0x0000);	/* raw bitmap */
		/* supports NOOP, SUPTYPES, FQDN, and NODEADDR */
		v = (uint32_t)odp_cpu_to_be_32(0x0000000f);
		bcopy(&v, nni6 + 1, sizeof(uint32_t));
		break;
	}
	case NI_QTYPE_FQDN:
		nni6->ni_code = ICMP6_NI_SUCCESS;
		fqdn = (struct ni_reply_fqdn *)(mtod(n, caddr_t) +
		    sizeof(struct ip6_hdr) + sizeof(struct icmp6_nodeinfo));
		nni6->ni_flags = 0; /* XXX: meaningless TTL */
		fqdn->ni_fqdn_ttl = 0;	/* ditto. */
		/*
		 * XXX do we really have FQDN in hostname?
		 */
		pr = curthread->td_ucred->cr_prison;
		mtx_lock(&pr->pr_mtx);
		n->m_next = ni6_nametodns(pr->pr_hostname,
		    strlen(pr->pr_hostname), oldfqdn);
		mtx_unlock(&pr->pr_mtx);
		if (n->m_next == NULL)
			goto bad;
		/* XXX we assume that n->m_next is not a chain */
		if (n->m_next->m_next != NULL)
			goto bad;
		n->m_pkthdr.len += n->m_next->m_len;
		break;
	case NI_QTYPE_NODEADDR:
	{
		int lenlim, copied;

		nni6->ni_code = ICMP6_NI_SUCCESS;
		n->m_pkthdr.len = n->m_len =
		    sizeof(struct ip6_hdr) + sizeof(struct icmp6_nodeinfo);
		lenlim = M_TRAILINGSPACE(n);
		copied = ni6_store_addrs(ni6, nni6, ifp, lenlim);
		/* XXX: reset mbuf length */
		n->m_pkthdr.len = n->m_len = sizeof(struct ip6_hdr) +
		    sizeof(struct icmp6_nodeinfo) + copied;
		break;
	}
	default:
		break;		/* XXX impossible! */
	}

	nni6->ni_type = ICMP6_NI_REPLY;
	m_freem(m);
	return (n);

  bad:
	m_freem(m);
	if (n)
		m_freem(n);
	return (NULL);
}

/*
 * make a mbuf with DNS-encoded string.  no compression support.
 *
 * XXX names with less than 2 dots (like "foo" or "foo.section") will be
 * treated as truncated name (two \0 at the end).  this is a wild guess.
 *
 * old - return pascal string if non-zero
 */
static struct mbuf *
ni6_nametodns(const char *name, int namelen, int old)
{
	struct mbuf *m;
	char *cp, *ep;
	const char *p, *q;
	int i, len, nterm;

	if (old)
		len = namelen + 1;
	else
		len = MCLBYTES;

	/* because MAXHOSTNAMELEN is usually 256, we use cluster mbuf */
	MGET(m, M_DONTWAIT, MT_DATA);
	if (m && len > MLEN) {
		MCLGET(m, M_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0)
			goto fail;
	}
	if (!m)
		goto fail;
	m->m_next = NULL;

	if (old) {
		m->m_len = len;
		*mtod(m, char *) = namelen;
		bcopy(name, mtod(m, char *) + 1, namelen);
		return m;
	} else {
		m->m_len = 0;
		cp = mtod(m, char *);
		ep = mtod(m, char *) + M_TRAILINGSPACE(m);

		/* if not certain about my name, return empty buffer */
		if (namelen == 0)
			return m;

		/*
		 * guess if it looks like shortened hostname, or FQDN.
		 * shortened hostname needs two trailing "\0".
		 */
		i = 0;
		for (p = name; p < name + namelen; p++) {
			if (*p && *p == '.')
				i++;
		}
		if (i < 2)
			nterm = 2;
		else
			nterm = 1;

		p = name;
		while (cp < ep && p < name + namelen) {
			i = 0;
			for (q = p; q < name + namelen && *q && *q != '.'; q++)
				i++;
			/* result does not fit into mbuf */
			if (cp + i + 1 >= ep)
				goto fail;
			/*
			 * DNS label length restriction, RFC1035 page 8.
			 * "i == 0" case is included here to avoid returning
			 * 0-length label on "foo..bar".
			 */
			if (i <= 0 || i >= 64)
				goto fail;
			*cp++ = i;
			bcopy(p, cp, i);
			cp += i;
			p = q;
			if (p < name + namelen && *p == '.')
				p++;
		}
		/* termination */
		if (cp + nterm >= ep)
			goto fail;
		while (nterm-- > 0)
			*cp++ = '\0';
		m->m_len = cp - mtod(m, char *);
		return m;
	}

	panic("should not reach here");
	/* NOTREACHED */

 fail:
	if (m)
		m_freem(m);
	return NULL;
}

/*
 * check if two DNS-encoded string matches.  takes care of truncated
 * form (with \0\0 at the end).  no compression support.
 * XXX upper/lowercase match (see RFC2065)
 */
static int
ni6_dnsmatch(const char *a, int alen, const char *b, int blen)
{
	const char *a0, *b0;
	int l;

	/* simplest case - need validation? */
	if (alen == blen && bcmp(a, b, alen) == 0)
		return 1;

	a0 = a;
	b0 = b;

	/* termination is mandatory */
	if (alen < 2 || blen < 2)
		return 0;
	if (a0[alen - 1] != '\0' || b0[blen - 1] != '\0')
		return 0;
	alen--;
	blen--;

	while (a - a0 < alen && b - b0 < blen) {
		if (a - a0 + 1 > alen || b - b0 + 1 > blen)
			return 0;

		if ((signed char)a[0] < 0 || (signed char)b[0] < 0)
			return 0;
		/* we don't support compression yet */
		if (a[0] >= 64 || b[0] >= 64)
			return 0;

		/* truncated case */
		if (a[0] == 0 && a - a0 == alen - 1)
			return 1;
		if (b[0] == 0 && b - b0 == blen - 1)
			return 1;
		if (a[0] == 0 || b[0] == 0)
			return 0;

		if (a[0] != b[0])
			return 0;
		l = a[0];
		if (a - a0 + 1 + l > alen || b - b0 + 1 + l > blen)
			return 0;
		if (bcmp(a + 1, b + 1, l) != 0)
			return 0;

		a += 1 + l;
		b += 1 + l;
	}

	if (a - a0 == alen && b - b0 == blen)
		return 1;
	else
		return 0;
}

/*
 * calculate the number of addresses to be returned in the node info reply.
 */
static int
ni6_addrs(struct icmp6_nodeinfo *ni6, struct mbuf *m, struct ifnet **ifpp,
    struct in6_addr *subj)
{
	struct ifnet *ifp;
	struct in6_ifaddr *ifa6;
	struct ifaddr *ifa;
	int addrs = 0, addrsofif, iffound = 0;
	int niflags = ni6->ni_flags;

	if ((niflags & NI_NODEADDR_FLAG_ALL) == 0) {
		switch (ni6->ni_code) {
		case ICMP6_NI_SUBJ_IPV6:
			if (subj == NULL) /* must be impossible... */
				return (0);
			break;
		default:
			/*
			 * XXX: we only support IPv6 subject address for
			 * this Qtype.
			 */
			return (0);
		}
	}

	IFNET_RLOCK_NOSLEEP();
	TAILQ_FOREACH(ifp, &V_ifnet, if_list) {
		addrsofif = 0;
		IF_ADDR_RLOCK(ifp);
		TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
			if (ifa->ifa_addr->sa_family != AF_INET6)
				continue;
			ifa6 = (struct in6_ifaddr *)ifa;

			if ((niflags & NI_NODEADDR_FLAG_ALL) == 0 &&
			    IN6_ARE_ADDR_EQUAL(subj, &ifa6->ia_addr.sin6_addr))
				iffound = 1;

			/*
			 * IPv4-mapped addresses can only be returned by a
			 * Node Information proxy, since they represent
			 * addresses of IPv4-only nodes, which perforce do
			 * not implement this protocol.
			 * [icmp-name-lookups-07, Section 5.4]
			 * So we don't support NI_NODEADDR_FLAG_COMPAT in
			 * this function at this moment.
			 */

			/* What do we have to do about ::1? */
			switch (in6_addrscope(&ifa6->ia_addr.sin6_addr)) {
			case IPV6_ADDR_SCOPE_LINKLOCAL:
				if ((niflags & NI_NODEADDR_FLAG_LINKLOCAL) == 0)
					continue;
				break;
			case IPV6_ADDR_SCOPE_SITELOCAL:
				if ((niflags & NI_NODEADDR_FLAG_SITELOCAL) == 0)
					continue;
				break;
			case IPV6_ADDR_SCOPE_GLOBAL:
				if ((niflags & NI_NODEADDR_FLAG_GLOBAL) == 0)
					continue;
				break;
			default:
				continue;
			}

			/*
			 * check if anycast is okay.
			 * XXX: just experimental.  not in the spec.
			 */
			if ((ifa6->ia6_flags & IN6_IFF_ANYCAST) != 0 &&
			    (niflags & NI_NODEADDR_FLAG_ANYCAST) == 0)
				continue; /* we need only unicast addresses */
			if ((ifa6->ia6_flags & IN6_IFF_TEMPORARY) != 0 &&
			    (V_icmp6_nodeinfo & ICMP6_NODEINFO_TMPADDROK) == 0) {
				continue;
			}
			addrsofif++; /* count the address */
		}
		IF_ADDR_RUNLOCK(ifp);
		if (iffound) {
			*ifpp = ifp;
			IFNET_RUNLOCK_NOSLEEP();
			return (addrsofif);
		}

		addrs += addrsofif;
	}
	IFNET_RUNLOCK_NOSLEEP();

	return (addrs);
}

static int
ni6_store_addrs(struct icmp6_nodeinfo *ni6, struct icmp6_nodeinfo *nni6,
    struct ifnet *ifp0, int resid)
{
	struct ifnet *ifp;
	struct in6_ifaddr *ifa6;
	struct ifaddr *ifa;
	struct ifnet *ifp_dep = NULL;
	int copied = 0, allow_deprecated = 0;
	u_char *cp = (u_char *)(nni6 + 1);
	int niflags = ni6->ni_flags;
	uint32_t ltime;

	if (ifp0 == NULL && !(niflags & NI_NODEADDR_FLAG_ALL))
		return (0);	/* needless to copy */

	IFNET_RLOCK_NOSLEEP();
	ifp = ifp0 ? ifp0 : TAILQ_FIRST(&V_ifnet);
  again:

	for (; ifp; ifp = TAILQ_NEXT(ifp, if_list)) {
		IF_ADDR_RLOCK(ifp);
		TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
			if (ifa->ifa_addr->sa_family != AF_INET6)
				continue;
			ifa6 = (struct in6_ifaddr *)ifa;

			if ((ifa6->ia6_flags & IN6_IFF_DEPRECATED) != 0 &&
			    allow_deprecated == 0) {
				/*
				 * prefererred address should be put before
				 * deprecated addresses.
				 */

				/* record the interface for later search */
				if (ifp_dep == NULL)
					ifp_dep = ifp;

				continue;
			} else if ((ifa6->ia6_flags & IN6_IFF_DEPRECATED) == 0 &&
			    allow_deprecated != 0)
				continue; /* we now collect deprecated addrs */

			/* What do we have to do about ::1? */
			switch (in6_addrscope(&ifa6->ia_addr.sin6_addr)) {
			case IPV6_ADDR_SCOPE_LINKLOCAL:
				if ((niflags & NI_NODEADDR_FLAG_LINKLOCAL) == 0)
					continue;
				break;
			case IPV6_ADDR_SCOPE_SITELOCAL:
				if ((niflags & NI_NODEADDR_FLAG_SITELOCAL) == 0)
					continue;
				break;
			case IPV6_ADDR_SCOPE_GLOBAL:
				if ((niflags & NI_NODEADDR_FLAG_GLOBAL) == 0)
					continue;
				break;
			default:
				continue;
			}

			/*
			 * check if anycast is okay.
			 * XXX: just experimental.  not in the spec.
			 */
			if ((ifa6->ia6_flags & IN6_IFF_ANYCAST) != 0 &&
			    (niflags & NI_NODEADDR_FLAG_ANYCAST) == 0)
				continue;
			if ((ifa6->ia6_flags & IN6_IFF_TEMPORARY) != 0 &&
			    (V_icmp6_nodeinfo & ICMP6_NODEINFO_TMPADDROK) == 0) {
				continue;
			}

			/* now we can copy the address */
			if (resid < sizeof(struct in6_addr) +
			    sizeof(uint32_t)) {
				IF_ADDR_RUNLOCK(ifp);
				/*
				 * We give up much more copy.
				 * Set the truncate flag and return.
				 */
				nni6->ni_flags |= NI_NODEADDR_FLAG_TRUNCATE;
				IFNET_RUNLOCK_NOSLEEP();
				return (copied);
			}

			/*
			 * Set the TTL of the address.
			 * The TTL value should be one of the following
			 * according to the specification:
			 *
			 * 1. The remaining lifetime of a DHCP lease on the
			 *    address, or
			 * 2. The remaining Valid Lifetime of a prefix from
			 *    which the address was derived through Stateless
			 *    Autoconfiguration.
			 *
			 * Note that we currently do not support stateful
			 * address configuration by DHCPv6, so the former
			 * case can't happen.
			 */
			if (ifa6->ia6_lifetime.ia6t_expire == 0)
				ltime = ND6_INFINITE_LIFETIME;
			else {
				if (ifa6->ia6_lifetime.ia6t_expire >
				    time_second)
					ltime = odp_cpu_to_be_32(ifa6->ia6_lifetime.ia6t_expire - time_second);
				else
					ltime = 0;
			}

			bcopy(&ltime, cp, sizeof(uint32_t));
			cp += sizeof(uint32_t);

			/* copy the address itself */
			bcopy(&ifa6->ia_addr.sin6_addr, cp,
			    sizeof(struct in6_addr));
			in6_clearscope((struct in6_addr *)cp); /* XXX */
			cp += sizeof(struct in6_addr);

			resid -= (sizeof(struct in6_addr) + sizeof(uint32_t));
			copied += (sizeof(struct in6_addr) + sizeof(uint32_t));
		}
		IF_ADDR_RUNLOCK(ifp);
		if (ifp0)	/* we need search only on the specified IF */
			break;
	}

	if (allow_deprecated == 0 && ifp_dep != NULL) {
		ifp = ifp_dep;
		allow_deprecated = 1;

		goto again;
	}

	IFNET_RUNLOCK_NOSLEEP();

	return (copied);
}

/*
 * XXX almost dup'ed code with rip6_input.
 */
static int
icmp6_rip6_input(struct mbuf **mp, int off)
{
	struct mbuf *m = *mp;
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
	struct inpcb *in6p;
	struct inpcb *last = NULL;
	struct sockaddr_in6 fromsa;
	struct icmp6_hdr *icmp6;
	struct mbuf *opts = NULL;

#ifndef PULLDOWN_TEST
	/* this is assumed to be safe. */
	icmp6 = (struct icmp6_hdr *)((caddr_t)ip6 + off);
#else
	IP6_EXTHDR_GET(icmp6, struct icmp6_hdr *, m, off, sizeof(*icmp6));
	if (icmp6 == NULL) {
		/* m is already reclaimed */
		return (IPPROTO_DONE);
	}
#endif

	/*
	 * XXX: the address may have embedded scope zone ID, which should be
	 * hidden from applications.
	 */
	bzero(&fromsa, sizeof(fromsa));
	fromsa.sin6_family = AF_INET6;
	fromsa.sin6_len = sizeof(struct sockaddr_in6);
	fromsa.sin6_addr = ip6->ip6_src;
	if (sa6_recoverscope(&fromsa)) {
		m_freem(m);
		return (IPPROTO_DONE);
	}

	INP_INFO_RLOCK(&V_ripcbinfo);
	LIST_FOREACH(in6p, &V_ripcb, inp_list) {
		if ((in6p->inp_vflag & INP_IPV6) == 0)
			continue;
		if (in6p->inp_ip_p != IPPROTO_ICMPV6)
			continue;
		if (!IN6_IS_ADDR_UNSPECIFIED(&in6p->in6p_laddr) &&
		   !IN6_ARE_ADDR_EQUAL(&in6p->in6p_laddr, &ip6->ip6_dst))
			continue;
		if (!IN6_IS_ADDR_UNSPECIFIED(&in6p->in6p_faddr) &&
		   !IN6_ARE_ADDR_EQUAL(&in6p->in6p_faddr, &ip6->ip6_src))
			continue;
		INP_RLOCK(in6p);
		if (ICMP6_FILTER_WILLBLOCK(icmp6->icmp6_type,
		    in6p->in6p_icmp6filt)) {
			INP_RUNLOCK(in6p);
			continue;
		}
		if (last != NULL) {
			struct	mbuf *n = NULL;

			/*
			 * Recent network drivers tend to allocate a single
			 * mbuf cluster, rather than to make a couple of
			 * mbufs without clusters.  Also, since the IPv6 code
			 * path tries to avoid m_pullup(), it is highly
			 * probable that we still have an mbuf cluster here
			 * even though the necessary length can be stored in an
			 * mbuf's internal buffer.
			 * Meanwhile, the default size of the receive socket
			 * buffer for raw sockets is not so large.  This means
			 * the possibility of packet loss is relatively higher
			 * than before.  To avoid this scenario, we copy the
			 * received data to a separate mbuf that does not use
			 * a cluster, if possible.
			 * XXX: it is better to copy the data after stripping
			 * intermediate headers.
			 */
			if ((m->m_flags & M_EXT) && m->m_next == NULL &&
			    m->m_len <= MHLEN) {
				MGET(n, M_DONTWAIT, m->m_type);
				if (n != NULL) {
					if (m_dup_pkthdr(n, m, M_NOWAIT)) {
						bcopy(m->m_data, n->m_data,
						      m->m_len);
						n->m_len = m->m_len;
					} else {
						m_free(n);
						n = NULL;
					}
				}
			}
			if (n != NULL ||
			    (n = m_copy(m, 0, (int)M_COPYALL)) != NULL) {
				if (last->inp_flags & INP_CONTROLOPTS)
					ip6_savecontrol(last, n, &opts);
				/* strip intermediate headers */
				m_adj(n, off);
				SOCKBUF_LOCK(&last->inp_socket->so_rcv);
				if (sbappendaddr_locked(
				    &last->inp_socket->so_rcv,
				    (struct sockaddr *)&fromsa, n, opts)
				    == 0) {
					/* should notify about lost packet */
					m_freem(n);
					if (opts) {
						m_freem(opts);
					}
					SOCKBUF_UNLOCK(
					    &last->inp_socket->so_rcv);
				} else
					sorwakeup_locked(last->inp_socket);
				opts = NULL;
			}
			INP_RUNLOCK(last);
		}
		last = in6p;
	}
	INP_INFO_RUNLOCK(&V_ripcbinfo);
	if (last != NULL) {
		if (last->inp_flags & INP_CONTROLOPTS)
			ip6_savecontrol(last, m, &opts);
		/* strip intermediate headers */
		m_adj(m, off);

		/* avoid using mbuf clusters if possible (see above) */
		if ((m->m_flags & M_EXT) && m->m_next == NULL &&
		    m->m_len <= MHLEN) {
			struct mbuf *n;

			MGET(n, M_DONTWAIT, m->m_type);
			if (n != NULL) {
				if (m_dup_pkthdr(n, m, M_NOWAIT)) {
					bcopy(m->m_data, n->m_data, m->m_len);
					n->m_len = m->m_len;

					m_freem(m);
					m = n;
				} else {
					m_freem(n);
					n = NULL;
				}
			}
		}
		SOCKBUF_LOCK(&last->inp_socket->so_rcv);
		if (sbappendaddr_locked(&last->inp_socket->so_rcv,
		    (struct sockaddr *)&fromsa, m, opts) == 0) {
			m_freem(m);
			if (opts)
				m_freem(opts);
			SOCKBUF_UNLOCK(&last->inp_socket->so_rcv);
		} else
			sorwakeup_locked(last->inp_socket);
		INP_RUNLOCK(last);
	} else {
		m_freem(m);
		IP6STAT_DEC(ip6s_delivered);
	}
	return IPPROTO_DONE;
}
#endif /*0*/
/*
 * Reflect the ip6 packet back to the source.
 * OFF points to the icmp6 header, counted from the L3 offset.
 */
void
ofp_icmp6_reflect(odp_packet_t m, size_t off)
{
	int plen;
	struct ofp_ip6_hdr *ip6;
	struct ofp_icmp6_hdr *icmp6;
	int icmp6len;
	struct ofp_in6_addr origdst, src, *srcp = NULL;
	struct ofp_ifnet *outif = NULL;
	struct ofp_nh6_entry *nh6 = NULL;

	/* too short to reflect */
	if (off < sizeof(struct ofp_ip6_hdr)) {
		OFP_DBG("Too short to reflect: off=%lx, sizeof(ip6)=%lx",
		    (u_long)off, (u_long)sizeof(struct ofp_ip6_hdr));
		goto bad;
	}

	icmp6len = odp_packet_len(m)  - odp_packet_l3_offset(m) - off;
	ip6 = (struct ofp_ip6_hdr *)odp_packet_l3_ptr(m, NULL);

	/*
	 * If there are extra headers between IPv6 and ICMPv6, strip
	 * off that header first.
	 */

	if (off > sizeof(struct ofp_ip6_hdr)) {

		int i;
		uint8_t *paddr = (uint8_t *)(ip6 + 1);
		size_t l = off - sizeof(struct ofp_ip6_hdr);

		for(i = 0; i < icmp6len; i++)
			*(paddr + i) = *(paddr + i + l);
		odp_packet_pull_tail(m, l);
		off -= l;
	}

	plen = odp_packet_len(m) - odp_packet_l3_offset(m) -
		sizeof(struct ofp_ip6_hdr);

	icmp6 = (struct ofp_icmp6_hdr *)(ip6 + 1);


	origdst = ip6->ip6_dst;
	/*
	 * ip6_input() drops a packet if its src is multicast.
	 * So, the src is never multicast.
	 */
	ip6->ip6_dst = ip6->ip6_src;

	/*
	 * If the incoming packet was addressed directly to us (i.e. unicast),
	 * use dst as the src for the reply.
	 * The IN6_IFF_NOTREADY case should be VERY rare, but is possible
	 * (for example) when we encounter an error while forwarding procedure
	 * destined to a duplicated address of ours.
	 * Note that ip6_getdstifaddr() may fail if we are in an error handling
	 * procedure of an outgoing packet of our own, in which case we need
	 * to search in the ifaddr list.
	 */

	outif = NULL;
	srcp = NULL;
	if (!OFP_IN6_IS_ADDR_MULTICAST(&origdst)) {
		nh6 = ofp_get_next_hop6(0, &ip6->ip6_dst.ofp_s6_addr[0], 0);
		if (nh6) {
			outif = ofp_get_ifnet(nh6->port, nh6->vlan);
			memcpy(&src.ofp_s6_addr[0], outif->ip6_addr, 16);
			srcp = &src;
		}
	}

	if (srcp == NULL) {
		int e;
		struct ofp_sockaddr_in6 sin6;

		/*
		 * This case matches to multicasts, our anycast, or unicasts
		 * that we do not own.  Select a source address based on the
		 * source address of the erroneous packet.
		 */
		bzero(&sin6, sizeof(sin6));
		sin6.sin6_family = OFP_AF_INET6;
		sin6.sin6_len = sizeof(sin6);
		sin6.sin6_addr = ip6->ip6_dst; /* zone ID should be embedded */

		e = ofp_in6_selectsrc(&sin6, NULL, NULL, NULL, NULL, &outif, &src);
		if (e) {
			OFP_DBG("Source cannot be determined: "
				"dst=%s, error=%d",
				ofp_print_ip6_addr(
					&sin6.sin6_addr.ofp_s6_addr[0]), e);
			goto bad;
		}
		srcp = &src;
	}


	ip6->ip6_src = *srcp;
	ip6->ofp_ip6_flow = 0;
	ip6->ofp_ip6_vfc &= ~OFP_IPV6_VERSION_MASK;
	ip6->ofp_ip6_vfc |= OFP_IPV6_VERSION;
	ip6->ofp_ip6_nxt = OFP_IPPROTO_ICMPV6;
	ip6->ofp_ip6_hlim = V_ip6_defhlim;


	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum = ofp_in6_cksum(m, OFP_IPPROTO_ICMPV6,
	    sizeof(struct ofp_ip6_hdr), plen);

	(void) ofp_ip6_output(m, nh6);

	return;

 bad:
	odp_packet_free(m);
	return;
}

#if 0
void
icmp6_fasttimo(void)
{

	mld_fasttimo();
}

void
icmp6_slowtimo(void)
{

	mld_slowtimo();
}

static const char *
icmp6_redirect_diag(struct in6_addr *src6, struct in6_addr *dst6,
    struct in6_addr *tgt6)
{
	static char buf[1024];
	char ip6bufs[INET6_ADDRSTRLEN];
	char ip6bufd[INET6_ADDRSTRLEN];
	char ip6buft[INET6_ADDRSTRLEN];
	snprintf(buf, sizeof(buf), "(src=%s dst=%s tgt=%s)",
	    ip6_sprintf(ip6bufs, src6), ip6_sprintf(ip6bufd, dst6),
	    ip6_sprintf(ip6buft, tgt6));
	return buf;
}

void
icmp6_redirect_input(struct mbuf *m, int off)
{
	struct ifnet *ifp;
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
	struct nd_redirect *nd_rd;
	int icmp6len = odp_be_to_cpu_16(ip6->ip6_plen);
	char *lladdr = NULL;
	int lladdrlen = 0;
	struct rtentry *rt = NULL;
	int is_router;
	int is_onlink;
	struct in6_addr src6 = ip6->ip6_src;
	struct in6_addr redtgt6;
	struct in6_addr reddst6;
	union nd_opts ndopts;
	char ip6buf[INET6_ADDRSTRLEN];

	M_ASSERTPKTHDR(m);
	KASSERT(m->m_pkthdr.rcvif != NULL, ("%s: no rcvif", __func__));

	ifp = m->m_pkthdr.rcvif;

	/* XXX if we are router, we don't update route by icmp6 redirect */
	if (V_ip6_forwarding)
		goto freeit;
	if (!V_icmp6_rediraccept)
		goto freeit;

#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK(m, off, icmp6len,);
	nd_rd = (struct nd_redirect *)((caddr_t)ip6 + off);
#else
	IP6_EXTHDR_GET(nd_rd, struct nd_redirect *, m, off, icmp6len);
	if (nd_rd == NULL) {
		ICMP6STAT_INC(icp6s_tooshort);
		return;
	}
#endif
	redtgt6 = nd_rd->nd_rd_target;
	reddst6 = nd_rd->nd_rd_dst;

	if (in6_setscope(&redtgt6, m->m_pkthdr.rcvif, NULL) ||
	    in6_setscope(&reddst6, m->m_pkthdr.rcvif, NULL)) {
		goto freeit;
	}

	/* validation */
	if (!IN6_IS_ADDR_LINKLOCAL(&src6)) {
		nd6log((LOG_ERR,
		    "ICMP6 redirect sent from %s rejected; "
		    "must be from linklocal\n",
		    ip6_sprintf(ip6buf, &src6)));
		goto bad;
	}
	if (ip6->ip6_hlim != 255) {
		nd6log((LOG_ERR,
		    "ICMP6 redirect sent from %s rejected; "
		    "hlim=%d (must be 255)\n",
		    ip6_sprintf(ip6buf, &src6), ip6->ip6_hlim));
		goto bad;
	}
    {
	/* ip6->ip6_src must be equal to gw for icmp6->icmp6_reddst */
	struct sockaddr_in6 sin6;
	struct in6_addr *gw6;

	bzero(&sin6, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_len = sizeof(struct sockaddr_in6);
	bcopy(&reddst6, &sin6.sin6_addr, sizeof(reddst6));
	rt = in6_rtalloc1((struct sockaddr *)&sin6, 0, 0UL, RT_DEFAULT_FIB);
	if (rt) {
		if (rt->rt_gateway == NULL ||
		    rt->rt_gateway->sa_family != AF_INET6) {
			RTFREE_LOCKED(rt);
			nd6log((LOG_ERR,
			    "ICMP6 redirect rejected; no route "
			    "with inet6 gateway found for redirect dst: %s\n",
			    icmp6_redirect_diag(&src6, &reddst6, &redtgt6)));
			goto bad;
		}

		gw6 = &(((struct sockaddr_in6 *)rt->rt_gateway)->sin6_addr);
		if (bcmp(&src6, gw6, sizeof(struct in6_addr)) != 0) {
			RTFREE_LOCKED(rt);
			nd6log((LOG_ERR,
			    "ICMP6 redirect rejected; "
			    "not equal to gw-for-src=%s (must be same): "
			    "%s\n",
			    ip6_sprintf(ip6buf, gw6),
			    icmp6_redirect_diag(&src6, &reddst6, &redtgt6)));
			goto bad;
		}
	} else {
		nd6log((LOG_ERR,
		    "ICMP6 redirect rejected; "
		    "no route found for redirect dst: %s\n",
		    icmp6_redirect_diag(&src6, &reddst6, &redtgt6)));
		goto bad;
	}
	RTFREE_LOCKED(rt);
	rt = NULL;
    }
	if (IN6_IS_ADDR_MULTICAST(&reddst6)) {
		nd6log((LOG_ERR,
		    "ICMP6 redirect rejected; "
		    "redirect dst must be unicast: %s\n",
		    icmp6_redirect_diag(&src6, &reddst6, &redtgt6)));
		goto bad;
	}

	is_router = is_onlink = 0;
	if (IN6_IS_ADDR_LINKLOCAL(&redtgt6))
		is_router = 1;	/* router case */
	if (bcmp(&redtgt6, &reddst6, sizeof(redtgt6)) == 0)
		is_onlink = 1;	/* on-link destination case */
	if (!is_router && !is_onlink) {
		nd6log((LOG_ERR,
		    "ICMP6 redirect rejected; "
		    "neither router case nor onlink case: %s\n",
		    icmp6_redirect_diag(&src6, &reddst6, &redtgt6)));
		goto bad;
	}
	/* validation passed */

	icmp6len -= sizeof(*nd_rd);
	nd6_option_init(nd_rd + 1, icmp6len, &ndopts);
	if (nd6_options(&ndopts) < 0) {
		nd6log((LOG_INFO, "%s: invalid ND option, rejected: %s\n",
		    __func__, icmp6_redirect_diag(&src6, &reddst6, &redtgt6)));
		/* nd6_options have incremented stats */
		goto freeit;
	}

	if (ndopts.nd_opts_tgt_lladdr) {
		lladdr = (char *)(ndopts.nd_opts_tgt_lladdr + 1);
		lladdrlen = ndopts.nd_opts_tgt_lladdr->nd_opt_len << 3;
	}

	if (lladdr && ((ifp->if_addrlen + 2 + 7) & ~7) != lladdrlen) {
		nd6log((LOG_INFO, "%s: lladdrlen mismatch for %s "
		    "(if %d, icmp6 packet %d): %s\n",
		    __func__, ip6_sprintf(ip6buf, &redtgt6),
		    ifp->if_addrlen, lladdrlen - 2,
		    icmp6_redirect_diag(&src6, &reddst6, &redtgt6)));
		goto bad;
	}

	/* RFC 2461 8.3 */
	nd6_cache_lladdr(ifp, &redtgt6, lladdr, lladdrlen, ND_REDIRECT,
	    is_onlink ? ND_REDIRECT_ONLINK : ND_REDIRECT_ROUTER);

	if (!is_onlink) {	/* better router case.  perform rtredirect. */
		/* perform rtredirect */
		struct sockaddr_in6 sdst;
		struct sockaddr_in6 sgw;
		struct sockaddr_in6 ssrc;
		u_int fibnum;

		bzero(&sdst, sizeof(sdst));
		bzero(&sgw, sizeof(sgw));
		bzero(&ssrc, sizeof(ssrc));
		sdst.sin6_family = sgw.sin6_family = ssrc.sin6_family = AF_INET6;
		sdst.sin6_len = sgw.sin6_len = ssrc.sin6_len =
			sizeof(struct sockaddr_in6);
		bcopy(&redtgt6, &sgw.sin6_addr, sizeof(struct in6_addr));
		bcopy(&reddst6, &sdst.sin6_addr, sizeof(struct in6_addr));
		bcopy(&src6, &ssrc.sin6_addr, sizeof(struct in6_addr));
		for (fibnum = 0; fibnum < rt_numfibs; fibnum++)
			in6_rtredirect((struct sockaddr *)&sdst,
			    (struct sockaddr *)&sgw, (struct sockaddr *)NULL,
			    RTF_GATEWAY | RTF_HOST, (struct sockaddr *)&ssrc,
			    fibnum);
	}
	/* finally update cached route in each socket via pfctlinput */
    {
	struct sockaddr_in6 sdst;

	bzero(&sdst, sizeof(sdst));
	sdst.sin6_family = AF_INET6;
	sdst.sin6_len = sizeof(struct sockaddr_in6);
	bcopy(&reddst6, &sdst.sin6_addr, sizeof(struct in6_addr));
	pfctlinput(PRC_REDIRECT_HOST, (struct sockaddr *)&sdst);
#ifdef IPSEC
	key_sa_routechange((struct sockaddr *)&sdst);
#endif /* IPSEC */
    }

 freeit:
	m_freem(m);
	return;

 bad:
	ICMP6STAT_INC(icp6s_badredirect);
	m_freem(m);
}

void
icmp6_redirect_output(struct mbuf *m0, struct rtentry *rt)
{
	struct ifnet *ifp;	/* my outgoing interface */
	struct in6_addr *ifp_ll6;
	struct in6_addr *router_ll6;
	struct ip6_hdr *sip6;	/* m0 as struct ip6_hdr */
	struct mbuf *m = NULL;	/* newly allocated one */
	struct m_tag *mtag;
	struct ip6_hdr *ip6;	/* m as struct ip6_hdr */
	struct nd_redirect *nd_rd;
	struct llentry *ln = NULL;
	size_t maxlen;
	u_char *p;
	struct ifnet *outif = NULL;
	struct sockaddr_in6 src_sa;

	icmp6_errcount(&V_icmp6stat.icp6s_outerrhist, ND_REDIRECT, 0);

	/* if we are not router, we don't send icmp6 redirect */
	if (!V_ip6_forwarding)
		goto fail;

	/* sanity check */
	if (!m0 || !rt || !(rt->rt_flags & RTF_UP) || !(ifp = rt->rt_ifp))
		goto fail;

	/*
	 * Address check:
	 *  the source address must identify a neighbor, and
	 *  the destination address must not be a multicast address
	 *  [RFC 2461, sec 8.2]
	 */
	sip6 = mtod(m0, struct ip6_hdr *);
	bzero(&src_sa, sizeof(src_sa));
	src_sa.sin6_family = AF_INET6;
	src_sa.sin6_len = sizeof(src_sa);
	src_sa.sin6_addr = sip6->ip6_src;
	if (nd6_is_addr_neighbor(&src_sa, ifp) == 0)
		goto fail;
	if (IN6_IS_ADDR_MULTICAST(&sip6->ip6_dst))
		goto fail;	/* what should we do here? */

	/* rate limit */
	if (icmp6_ratelimit(&sip6->ip6_src, ND_REDIRECT, 0))
		goto fail;

	/*
	 * Since we are going to append up to 1280 bytes (= IPV6_MMTU),
	 * we almost always ask for an mbuf cluster for simplicity.
	 * (MHLEN < IPV6_MMTU is almost always true)
	 */
#if IPV6_MMTU >= MCLBYTES
# error assumption failed about IPV6_MMTU and MCLBYTES
#endif
	MGETHDR(m, M_DONTWAIT, MT_HEADER);
	if (m && IPV6_MMTU >= MHLEN)
		MCLGET(m, M_DONTWAIT);
	if (!m)
		goto fail;
	M_SETFIB(m, rt->rt_fibnum);
	m->m_pkthdr.rcvif = NULL;
	m->m_len = 0;
	maxlen = M_TRAILINGSPACE(m);
	maxlen = min(IPV6_MMTU, maxlen);
	/* just for safety */
	if (maxlen < sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) +
	    ((sizeof(struct nd_opt_hdr) + ifp->if_addrlen + 7) & ~7)) {
		goto fail;
	}

	{
		/* get ip6 linklocal address for ifp(my outgoing interface). */
		struct in6_ifaddr *ia;
		if ((ia = in6ifa_ifpforlinklocal(ifp,
						 IN6_IFF_NOTREADY|
						 IN6_IFF_ANYCAST)) == NULL)
			goto fail;
		ifp_ll6 = &ia->ia_addr.sin6_addr;
		/* XXXRW: reference released prematurely. */
		ifa_free(&ia->ia_ifa);
	}

	/* get ip6 linklocal address for the router. */
	if (rt->rt_gateway && (rt->rt_flags & RTF_GATEWAY)) {
		struct sockaddr_in6 *sin6;
		sin6 = (struct sockaddr_in6 *)rt->rt_gateway;
		router_ll6 = &sin6->sin6_addr;
		if (!IN6_IS_ADDR_LINKLOCAL(router_ll6))
			router_ll6 = (struct in6_addr *)NULL;
	} else
		router_ll6 = (struct in6_addr *)NULL;

	/* ip6 */
	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_flow = 0;
	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc |= IPV6_VERSION;
	/* ip6->ip6_plen will be set later */
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	ip6->ip6_hlim = 255;
	/* ip6->ip6_src must be linklocal addr for my outgoing if. */
	bcopy(ifp_ll6, &ip6->ip6_src, sizeof(struct in6_addr));
	bcopy(&sip6->ip6_src, &ip6->ip6_dst, sizeof(struct in6_addr));

	/* ND Redirect */
	nd_rd = (struct nd_redirect *)(ip6 + 1);
	nd_rd->nd_rd_type = ND_REDIRECT;
	nd_rd->nd_rd_code = 0;
	nd_rd->nd_rd_reserved = 0;
	if (rt->rt_flags & RTF_GATEWAY) {
		/*
		 * nd_rd->nd_rd_target must be a link-local address in
		 * better router cases.
		 */
		if (!router_ll6)
			goto fail;
		bcopy(router_ll6, &nd_rd->nd_rd_target,
		    sizeof(nd_rd->nd_rd_target));
		bcopy(&sip6->ip6_dst, &nd_rd->nd_rd_dst,
		    sizeof(nd_rd->nd_rd_dst));
	} else {
		/* make sure redtgt == reddst */
		bcopy(&sip6->ip6_dst, &nd_rd->nd_rd_target,
		    sizeof(nd_rd->nd_rd_target));
		bcopy(&sip6->ip6_dst, &nd_rd->nd_rd_dst,
		    sizeof(nd_rd->nd_rd_dst));
	}

	p = (u_char *)(nd_rd + 1);

	if (!router_ll6)
		goto nolladdropt;

	{
		/* target lladdr option */
		int len;
		struct nd_opt_hdr *nd_opt;
		char *lladdr;

		IF_AFDATA_LOCK(ifp);
		ln = nd6_lookup(router_ll6, 0, ifp);
		IF_AFDATA_UNLOCK(ifp);
		if (ln == NULL)
			goto nolladdropt;

		len = sizeof(*nd_opt) + ifp->if_addrlen;
		len = (len + 7) & ~7;	/* round by 8 */
		/* safety check */
		if (len + (p - (u_char *)ip6) > maxlen)
			goto nolladdropt;

		if (ln->la_flags & LLE_VALID) {
			nd_opt = (struct nd_opt_hdr *)p;
			nd_opt->nd_opt_type = ND_OPT_TARGET_LINKADDR;
			nd_opt->nd_opt_len = len >> 3;
			lladdr = (char *)(nd_opt + 1);
			bcopy(&ln->ll_addr, lladdr, ifp->if_addrlen);
			p += len;
		}
	}
nolladdropt:
	if (ln != NULL)
		LLE_RUNLOCK(ln);

	m->m_pkthdr.len = m->m_len = p - (u_char *)ip6;

	/* just to be safe */
#ifdef M_DECRYPTED	/*not openbsd*/
	if (m0->m_flags & M_DECRYPTED)
		goto noredhdropt;
#endif
	if (p - (u_char *)ip6 > maxlen)
		goto noredhdropt;

	{
		/* redirected header option */
		int len;
		struct nd_opt_rd_hdr *nd_opt_rh;

		/*
		 * compute the maximum size for icmp6 redirect header option.
		 * XXX room for auth header?
		 */
		len = maxlen - (p - (u_char *)ip6);
		len &= ~7;

		/* This is just for simplicity. */
		if (m0->m_pkthdr.len != m0->m_len) {
			if (m0->m_next) {
				m_freem(m0->m_next);
				m0->m_next = NULL;
			}
			m0->m_pkthdr.len = m0->m_len;
		}

		/*
		 * Redirected header option spec (RFC2461 4.6.3) talks nothing
		 * about padding/truncate rule for the original IP packet.
		 * From the discussion on IPv6imp in Feb 1999,
		 * the consensus was:
		 * - "attach as much as possible" is the goal
		 * - pad if not aligned (original size can be guessed by
		 *   original ip6 header)
		 * Following code adds the padding if it is simple enough,
		 * and truncates if not.
		 */
		if (m0->m_next || m0->m_pkthdr.len != m0->m_len)
			panic("assumption failed in %s:%d", __FILE__,
			    __LINE__);

		if (len - sizeof(*nd_opt_rh) < m0->m_pkthdr.len) {
			/* not enough room, truncate */
			m0->m_pkthdr.len = m0->m_len = len -
			    sizeof(*nd_opt_rh);
		} else {
			/* enough room, pad or truncate */
			size_t extra;

			extra = m0->m_pkthdr.len % 8;
			if (extra) {
				/* pad if easy enough, truncate if not */
				if (8 - extra <= M_TRAILINGSPACE(m0)) {
					/* pad */
					m0->m_len += (8 - extra);
					m0->m_pkthdr.len += (8 - extra);
				} else {
					/* truncate */
					m0->m_pkthdr.len -= extra;
					m0->m_len -= extra;
				}
			}
			len = m0->m_pkthdr.len + sizeof(*nd_opt_rh);
			m0->m_pkthdr.len = m0->m_len = len -
			    sizeof(*nd_opt_rh);
		}

		nd_opt_rh = (struct nd_opt_rd_hdr *)p;
		bzero(nd_opt_rh, sizeof(*nd_opt_rh));
		nd_opt_rh->nd_opt_rh_type = ND_OPT_REDIRECTED_HEADER;
		nd_opt_rh->nd_opt_rh_len = len >> 3;
		p += sizeof(*nd_opt_rh);
		m->m_pkthdr.len = m->m_len = p - (u_char *)ip6;

		/* connect m0 to m */
		m_tag_delete_chain(m0, NULL);
		m0->m_flags &= ~M_PKTHDR;
		m->m_next = m0;
		m->m_pkthdr.len = m->m_len + m0->m_len;
		m0 = NULL;
	}
noredhdropt:;
	if (m0) {
		m_freem(m0);
		m0 = NULL;
	}

	/* XXX: clear embedded link IDs in the inner header */
	in6_clearscope(&sip6->ip6_src);
	in6_clearscope(&sip6->ip6_dst);
	in6_clearscope(&nd_rd->nd_rd_target);
	in6_clearscope(&nd_rd->nd_rd_dst);

	ip6->ip6_plen = odp_cpu_to_be_16(m->m_pkthdr.len - sizeof(struct ip6_hdr));

	nd_rd->nd_rd_cksum = 0;
	nd_rd->nd_rd_cksum = in6_cksum(m, IPPROTO_ICMPV6,
	    sizeof(*ip6), odp_be_to_cpu_16(ip6->ip6_plen));

        if (send_sendso_input_hook != NULL) {
		mtag = m_tag_get(PACKET_TAG_ND_OUTGOING, sizeof(unsigned short),
			M_NOWAIT);
		if (mtag == NULL)
			goto fail;
		*(unsigned short *)(mtag + 1) = nd_rd->nd_rd_type;
		m_tag_prepend(m, mtag);
	}

	/* send the packet to outside... */
	ip6_output(m, NULL, NULL, 0, NULL, &outif, NULL);
	if (outif) {
		icmp6_ifstat_inc(outif, ifs6_out_msg);
		icmp6_ifstat_inc(outif, ifs6_out_redirect);
	}
	ICMP6STAT_INC(icp6s_outhist[ND_REDIRECT]);

	return;

fail:
	if (m)
		m_freem(m);
	if (m0)
		m_freem(m0);
}

/*
 * ICMPv6 socket option processing.
 */
int
icmp6_ctloutput(struct socket *so, struct sockopt *sopt)
{
	int error = 0;
	int optlen;
	struct inpcb *inp = sotoinpcb(so);
	int level, op, optname;

	if (sopt) {
		level = sopt->sopt_level;
		op = sopt->sopt_dir;
		optname = sopt->sopt_name;
		optlen = sopt->sopt_valsize;
	} else
		level = op = optname = optlen = 0;

	if (level != IPPROTO_ICMPV6) {
		return EINVAL;
	}

	switch (op) {
	case PRCO_SETOPT:
		switch (optname) {
		case ICMP6_FILTER:
		    {
			struct icmp6_filter ic6f;

			if (optlen != sizeof(ic6f)) {
				error = EMSGSIZE;
				break;
			}
			error = sooptcopyin(sopt, &ic6f, optlen, optlen);
			if (error == 0) {
				INP_WLOCK(inp);
				*inp->in6p_icmp6filt = ic6f;
				INP_WUNLOCK(inp);
			}
			break;
		    }

		default:
			error = ENOPROTOOPT;
			break;
		}
		break;

	case PRCO_GETOPT:
		switch (optname) {
		case ICMP6_FILTER:
		    {
			struct icmp6_filter ic6f;

			INP_RLOCK(inp);
			ic6f = *inp->in6p_icmp6filt;
			INP_RUNLOCK(inp);
			error = sooptcopyout(sopt, &ic6f, sizeof(ic6f));
			break;
		    }

		default:
			error = ENOPROTOOPT;
			break;
		}
		break;
	}

	return (error);
}

/*
 * Perform rate limit check.
 * Returns 0 if it is okay to send the icmp6 packet.
 * Returns 1 if the router SHOULD NOT send this icmp6 packet due to rate
 * limitation.
 *
 * XXX per-destination/type check necessary?
 *
 * dst - not used at this moment
 * type - not used at this moment
 * code - not used at this moment
 */
static int
icmp6_ratelimit(const struct in6_addr *dst, const int type,
    const int code)
{
	int ret;

	ret = 0;	/* okay to send */

	/* PPS limit */
	if (!ppsratecheck(&V_icmp6errppslim_last, &V_icmp6errpps_count,
	    V_icmp6errppslim)) {
		/* The packet is subject to rate limit */
		ret++;
	}

	return ret;
}

#endif
