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
#include "ofpi_pkt_processing.h"
#include "ofpi_protosw.h"
#include "ofpi_socket.h"
#include "ofpi_route.h"
#include "ofpi_portconf.h"
#include "ofpi_log.h"
#include "ofpi_util.h"
/* ODP should have support to get time and date like gettimeofday from Linux*/
#include <sys/time.h>
/*
#include <sys/cdefs.h>
__FBSDID("$FreeBSD: release/9.1.0/sys/netinet/ip_icmp.c 237913 2012-07-01 09:00:29Z tuexen $");
*/

/*
 * ICMP routines: error generation, receive packet processing, and
 * routines to turnaround packets back to the originator, and
 * host table maintenance routines.
 */
/*
static VNET_DEFINE(int, icmplim) = 200;
#define	V_icmplim			VNET(icmplim)
SYSCTL_VNET_INT(_net_inet_icmp, ICMPCTL_ICMPLIM, icmplim, CTLFLAG_RW,
	&VNET_NAME(icmplim), 0,
	"Maximum number of ICMP responses per second");

static VNET_DEFINE(int, icmplim_output) = 1;
#define	V_icmplim_output		VNET(icmplim_output)
SYSCTL_VNET_INT(_net_inet_icmp, OID_AUTO, icmplim_output, CTLFLAG_RW,
	&VNET_NAME(icmplim_output), 0,
	"Enable rate limiting of ICMP responses");

#ifdef INET
VNET_DEFINE(struct icmpstat, icmpstat);
SYSCTL_VNET_STRUCT(_net_inet_icmp, ICMPCTL_STATS, stats, CTLFLAG_RW,
	&VNET_NAME(icmpstat), icmpstat, "");

static VNET_DEFINE(int, icmpmaskrepl) = 0;
#define	V_icmpmaskrepl			VNET(icmpmaskrepl)
SYSCTL_VNET_INT(_net_inet_icmp, ICMPCTL_MASKREPL, maskrepl, CTLFLAG_RW,
	&VNET_NAME(icmpmaskrepl), 0,
	"Reply to ICMP Address Mask Request packets.");

static VNET_DEFINE(u_int, icmpmaskfake) = 0;
#define	V_icmpmaskfake			VNET(icmpmaskfake)
SYSCTL_VNET_UINT(_net_inet_icmp, OID_AUTO, maskfake, CTLFLAG_RW,
	&VNET_NAME(icmpmaskfake), 0,
	"Fake reply to ICMP Address Mask Request packets.");

static VNET_DEFINE(int, drop_redirect) = 0;
#define	V_drop_redirect			VNET(drop_redirect)
SYSCTL_VNET_INT(_net_inet_icmp, OID_AUTO, drop_redirect, CTLFLAG_RW,
	&VNET_NAME(drop_redirect), 0,
	"Ignore ICMP redirects");

static VNET_DEFINE(int, log_redirect) = 0;
#define	V_log_redirect			VNET(log_redirect)
SYSCTL_VNET_INT(_net_inet_icmp, OID_AUTO, log_redirect, CTLFLAG_RW,
	&VNET_NAME(log_redirect), 0,
	"Log ICMP redirects to the console");

static VNET_DEFINE(char, reply_src[IFNAMSIZ]);
#define	V_reply_src			VNET(reply_src)
SYSCTL_VNET_STRING(_net_inet_icmp, OID_AUTO, reply_src, CTLFLAG_RW,
	&VNET_NAME(reply_src), IFNAMSIZ,
	"icmp reply source for non-local packets.");

static VNET_DEFINE(int, icmp_rfi) = 0;
#define	V_icmp_rfi			VNET(icmp_rfi)
SYSCTL_VNET_INT(_net_inet_icmp, OID_AUTO, reply_from_interface, CTLFLAG_RW,
	&VNET_NAME(icmp_rfi), 0,
	"ICMP reply from incoming interface for non-local packets");

static VNET_DEFINE(int, icmp_quotelen) = 8;
#define	V_icmp_quotelen			VNET(icmp_quotelen)
SYSCTL_VNET_INT(_net_inet_icmp, OID_AUTO, quotelen, CTLFLAG_RW,
	&VNET_NAME(icmp_quotelen), 0,
	"Number of bytes from original packet to quote in ICMP reply");
*/
/*
 * ICMP broadcast echo sysctl
 */
/*
static VNET_DEFINE(int, icmpbmcastecho) = 0;
#define	V_icmpbmcastecho		VNET(icmpbmcastecho)
SYSCTL_VNET_INT(_net_inet_icmp, OID_AUTO, bmcastecho, CTLFLAG_RW,
	&VNET_NAME(icmpbmcastecho), 0,
	"");
*/

#ifdef ICMPPRINTFS
int	icmpprintfs = 0;
#endif

static enum ofp_return_code icmp_reflect(odp_packet_t pkt);
static void	icmp_send(odp_packet_t pkt, struct ofp_nh_entry *nh);

extern	struct protosw inetsw[];

/*
 * Return milliseconds since 00:00 GMT in network format.
 */
static uint32_t
iptime(void)
{
	struct timeval tv;
	uint32_t t;
	gettimeofday(&tv, NULL);

	t = (tv.tv_sec % (24*60*60)) * 1000 + tv.tv_usec / 1000;
	return (odp_cpu_to_be_32(t));
}



/*
 * Kernel module interface for updating icmpstat.  The argument is an index
 * into icmpstat treated as an array of u_long.  While this encodes the
 * general layout of icmpstat into the caller, it doesn't encode its
 * location, so that future changes to add, for example, per-CPU stats
 * support won't cause binary compatibility problems for kernel modules.
 */
/*
void
kmod_icmpstat_inc(int statnum)
{

	(*((u_long *)&V_icmpstat + statnum))++;
}
*/

/*
 * Generate an error packet of type error
 * in response to bad packet ip.
 */
enum ofp_return_code
ofp_icmp_error(odp_packet_t pkt_in, int type, int code, uint32_t dest, int mtu)
{
	register struct ofp_ip *ip_in = (struct ofp_ip *)odp_packet_l3_ptr(pkt_in, NULL);
	register unsigned ip_hlen = ip_in->ip_hl << 2;
	/* ip header + icmp type+code+checksum(4B) + ip addr(4B) + ip header + 8B of original data */
	const uint16_t icmp_len = (ip_hlen * 2) + 16;
	ip_in->ip_sum = 0;
	ip_in->ip_sum = ofp_cksum_iph(ip_in, ip_in->ip_hl);

	if ((uint16_t)type > OFP_ICMP_MAXTYPE)
		OFP_ERR("Illegal ICMP type: %d", type);

#ifdef ICMPPRINTFS
	if (icmpprintfs)
		OFP_DBG("icmp_error(%p, %x, %d)", oip, type, code);
#endif
/*	if (type != ICMP_REDIRECT)
		ICMPSTAT_INC(icps_error);*/

	/*
	 * Don't send error:
	 *  if the original packet was encrypted.
	 *  if not the first fragment of message.
	 *  in response to a multicast or broadcast packet.
	 *  if the old packet protocol was an ICMP error message.
	 */

	if ((odp_be_to_cpu_16(ip_in->ip_off) & OFP_IP_OFFMASK))
		goto freeit;
/*	if (n->m_flags & (M_BCAST|M_MCAST))
		goto freeit;*/
	if (ip_in->ip_p == OFP_IPPROTO_ICMP && type != OFP_ICMP_REDIRECT &&
		odp_packet_len(pkt_in) >= ip_hlen + OFP_ICMP_MINLEN &&
		!OFP_ICMP_INFOTYPE(((struct ofp_icmp *)
			((uintptr_t)ip_in + ip_hlen))->icmp_type)) {
		/*ICMPSTAT_INC(icps_oldicmp);*/
		goto freeit;
	}
	/*
	 * Calculate length to quote from original packet and
	 * prevent the ICMP mbuf from overflowing.
	 * Unfortunatly this is non-trivial since ip_forward()
	 * sends us truncated packets.
	 */
/*	if (oip->ip_p == IPPROTO_TCP) {
		struct tcphdr *th;
		int tcphlen;

		if (oiphlen + sizeof(struct tcphdr) > n->m_len &&
		    n->m_next == NULL)
			goto stdreply;
		if (n->m_len < oiphlen + sizeof(struct tcphdr) &&
		    ((n = m_pullup(n, oiphlen + sizeof(struct tcphdr))) == NULL))
			goto freeit;
		th = (struct tcphdr *)((caddr_t)oip + oiphlen);
		tcphlen = th->th_off << 2;
		if (tcphlen < sizeof(struct tcphdr))
			goto freeit;
		if (oip->ip_len < oiphlen + tcphlen)
			goto freeit;
		if (oiphlen + tcphlen > n->m_len && n->m_next == NULL)
			goto stdreply;
		if (n->m_len < oiphlen + tcphlen &&
		    ((n = m_pullup(n, oiphlen + tcphlen)) == NULL))
			goto freeit;
		icmpelen = max(tcphlen, min(V_icmp_quotelen, oip->ip_len - oiphlen));
	} else
stdreply:	icmpelen = max(8, min(V_icmp_quotelen, ip_in->ip_len - ip_hlen));
#ifdef MAC
	mac_netinet_icmp_reply(n, m);
#endif
*/
	odp_packet_t pkt = ofp_packet_alloc_from_pool(odp_packet_pool(pkt_in),
				icmp_len + odp_packet_l3_offset(pkt_in) -
				odp_packet_l2_offset(pkt_in));
	if (pkt == ODP_PACKET_INVALID)
		goto freeit;
	/*TODO Sometimes above odp_packet_alloc will invalidate the pkt_in*/
	if (odp_packet_l3_ptr(pkt_in, NULL) == NULL) {
		odp_packet_free(pkt);
		goto freeit;
	}

	odp_packet_l2_offset_set(pkt, odp_packet_l2_offset(pkt_in));
	odp_packet_l3_offset_set(pkt, odp_packet_l3_offset(pkt_in));

	memcpy(odp_packet_l3_ptr(pkt, NULL),
		odp_packet_l3_ptr(pkt_in, NULL),
		icmp_len);

	struct ofp_ip *ip = (struct ofp_ip *)odp_packet_l3_ptr(pkt, NULL);
	struct ofp_icmp *icp = (struct ofp_icmp *)((uint8_t *)ip + ip_hlen);
	/*
	 * Copy the quotation into ICMP message and
	 * convert quoted IP header back to network representation.
	 */
	memcpy(&icp->ofp_icmp_ip, ip_in, ip_hlen);
	memcpy((void *)((uintptr_t)(&icp->ofp_icmp_ip) + ip_hlen),
		(void *)((uintptr_t)ip_in + ip_hlen),
		(8 > (ip_in->ip_len - ip_hlen)) ? (ip_in->ip_len - ip_hlen) :8);

	icp->icmp_type = type;

	if (type == OFP_ICMP_REDIRECT)
		icp->ofp_icmp_gwaddr.s_addr = dest;
	else {
		icp->ofp_icmp_void = 0;
		/*
		 * The following assignments assume an overlay with the
		 * just zeroed icmp_void field.
		 */
		if (type == OFP_ICMP_PARAMPROB) {
			icp->ofp_icmp_pptr = code;
			code = 0;
		} else if (type == OFP_ICMP_UNREACH &&
			code == OFP_ICMP_UNREACH_NEEDFRAG && mtu) {
			icp->ofp_icmp_nextmtu = odp_cpu_to_be_16(mtu);
		}
	}
	icp->icmp_code = code;

	ip->ip_len = odp_cpu_to_be_16(icmp_len);
	ip->ip_v = OFP_IPVERSION;
	ip->ip_p = OFP_IPPROTO_ICMP;
	ip->ip_tos = 0;

	odp_packet_user_ptr_set(pkt, odp_packet_user_ptr(pkt_in));

	return icmp_reflect(pkt);
freeit:
	return OFP_PKT_DROP;
}

/*
 * Process a received ICMP message.
 */
enum ofp_return_code
ofp_icmp_input(odp_packet_t *pkt, int off)
{
	struct ofp_ip *ip = (struct ofp_ip *)odp_packet_l3_ptr(*pkt, NULL);
	struct ofp_icmp *icp = (struct ofp_icmp *)((uint8_t *)ip + off);
	const int icmplen = odp_be_to_cpu_16(ip->ip_len);

	if (ofp_cksum(*pkt, odp_packet_l3_offset(*pkt) + off, icmplen - (ip->ip_hl << 2)))
		return OFP_PKT_DROP;

	return _ofp_icmp_input(*pkt, ip, icp, icmp_reflect);
}

static enum ofp_return_code
icmp_deliver(struct ofp_icmp *icp, int icmplen, int code)
{
	struct ofp_sockaddr_in icmpsrc;
	pr_ctlinput_t *ctlfunc;

	bzero(&icmpsrc, sizeof(icmpsrc));
	icmpsrc.sin_len = sizeof(struct ofp_sockaddr_in);
	icmpsrc.sin_family = OFP_AF_INET;

	/*
	 * Problem with datagram; advise higher level routines.
	 */
	if (((unsigned int)icmplen) < OFP_ICMP_ADVLENMIN || icmplen < OFP_ICMP_ADVLEN(icp) ||
	    icp->ofp_icmp_ip.ip_hl < (sizeof(struct ofp_ip) >> 2)) {
		return OFP_PKT_DROP;
	}

	icp->ofp_icmp_ip.ip_len = odp_be_to_cpu_16(icp->ofp_icmp_ip.ip_len);

#ifdef ICMPPRINTFS
	if (icmpprintfs)
		OFP_DBG("deliver to protocol %d", icp->icmp_ip.ip_p);
#endif

	icmpsrc.sin_addr = icp->ofp_icmp_ip.ip_dst;
	/*
	 * XXX if the packet contains [IPv4 AH TCP], we can't make a
	 * notification to TCP layer.
	 */
	ctlfunc = ofp_inetsw[ofp_ip_protox[icp->ofp_icmp_ip.ip_p]].pr_ctlinput;

	if (ctlfunc)
		(*ctlfunc)(code, (struct ofp_sockaddr *)&icmpsrc,
			   (void *)&icp->ofp_icmp_ip);

	return OFP_PKT_DROP;
}

static enum ofp_return_code
icmp_destination_unreachable(struct ofp_icmp *icp, int icmplen)
{
	switch (icp->icmp_code) {
	case OFP_ICMP_UNREACH_NET:
	case OFP_ICMP_UNREACH_HOST:
	case OFP_ICMP_UNREACH_SRCFAIL:
	case OFP_ICMP_UNREACH_NET_UNKNOWN:
	case OFP_ICMP_UNREACH_HOST_UNKNOWN:
	case OFP_ICMP_UNREACH_ISOLATED:
	case OFP_ICMP_UNREACH_TOSNET:
	case OFP_ICMP_UNREACH_TOSHOST:
	case OFP_ICMP_UNREACH_HOST_PRECEDENCE:
	case OFP_ICMP_UNREACH_PRECEDENCE_CUTOFF:
		return icmp_deliver(icp, icmplen, OFP_PRC_UNREACH_NET);

	case OFP_ICMP_UNREACH_NEEDFRAG:
		return icmp_deliver(icp, icmplen, OFP_PRC_MSGSIZE);

	/*
	 * RFC 1122, Sections 3.2.2.1 and 4.2.3.9.
	 * Treat subcodes 2,3 as immediate RST
	 */
	case OFP_ICMP_UNREACH_PROTOCOL:
	case OFP_ICMP_UNREACH_PORT:
		return icmp_deliver(icp, icmplen, OFP_PRC_UNREACH_PORT);

	case OFP_ICMP_UNREACH_NET_PROHIB:
	case OFP_ICMP_UNREACH_HOST_PROHIB:
	case OFP_ICMP_UNREACH_FILTER_PROHIB:
		return icmp_deliver(icp, icmplen, OFP_PRC_UNREACH_ADMIN_PROHIB);

	default:
		break;
    }

    return OFP_PKT_DROP;
}

static enum ofp_return_code
icmp_time_exceeded(struct ofp_icmp *icp, int icmplen)
{
	if (icp->icmp_code > 1)
		return OFP_PKT_DROP;

	return icmp_deliver(icp, icmplen, icp->icmp_code + OFP_PRC_TIMXCEED_INTRANS);
}

static enum ofp_return_code
icmp_bad_ip_header(struct ofp_icmp *icp, int icmplen)
{
	if (icp->icmp_code > 1)
		return OFP_PKT_DROP;

	return icmp_deliver(icp, icmplen, OFP_PRC_PARAMPROB);
}

static enum ofp_return_code
icmp_packet_lost(struct ofp_icmp *icp, int icmplen)
{
	if (icp->icmp_code)
		return OFP_PKT_DROP;

	return icmp_deliver(icp, icmplen, OFP_PRC_QUENCH);
}

static enum ofp_return_code
icmp_echo(odp_packet_t pkt, struct ofp_icmp *icp,
	  enum ofp_return_code (*reflect)(odp_packet_t pkt))
{
	icp->icmp_type = OFP_ICMP_ECHOREPLY;
	return reflect(pkt);
}

static enum ofp_return_code
icmp_timestamp_request(odp_packet_t pkt, struct ofp_icmp *icp, int icmplen,
		       enum ofp_return_code (*reflect)(odp_packet_t pkt))
{
	if ((unsigned int)icmplen < OFP_ICMP_TSLEN)
		return OFP_PKT_DROP;

	icp->icmp_type = OFP_ICMP_TSTAMPREPLY;
	icp->ofp_icmp_rtime = iptime();
	icp->ofp_icmp_ttime = icp->ofp_icmp_rtime;      /* bogus, do later! */
	return reflect(pkt);
}

static enum ofp_return_code
icmp_address_mask_request(odp_packet_t pkt,
			  enum ofp_return_code (*reflect)(odp_packet_t pkt))
{
/*TODO  if (V_icmpmaskrepl == 0)*/
		return OFP_PKT_DROP;

	return reflect(pkt);
}

static enum ofp_return_code
icmp_shorter_route(struct ofp_ip *ip, struct ofp_icmp *icp)
{
	/*if (V_log_redirect)*/ {
#if defined(OFP_DEBUG)
		u_long src, dst, gw;

		src = odp_be_to_cpu_32(ip->ip_src.s_addr);
		dst = odp_be_to_cpu_32(icp->ofp_icmp_ip.ip_dst.s_addr);
		gw = odp_be_to_cpu_32(icp->ofp_icmp_gwaddr.s_addr);
		OFP_DBG("icmp redirect from %d.%d.%d.%d: "
		       "%d.%d.%d.%d => %d.%d.%d.%d",
		       (int)(src >> 24), (int)((src >> 16) & 0xff),
		       (int)((src >> 8) & 0xff), (int)(src & 0xff),
		       (int)(dst >> 24), (int)((dst >> 16) & 0xff),
		       (int)((dst >> 8) & 0xff), (int)(dst & 0xff),
		       (int)(gw >> 24), (int)((gw >> 16) & 0xff),
		       (int)((gw >> 8) & 0xff), (int)(gw & 0xff));
#else
		(void)ip;
		(void)icp;
#endif
	}
	/*
	 * RFC1812 says we must ignore ICMP redirects if we
	 * are acting as router.
	 */
/*TODO  if (V_drop_redirect || V_ipforwarding) */
		return OFP_PKT_DROP;
	/*
	 * Short circuit routing redirects to force
	 * immediate change in the kernel's routing
	 * tables.  The message is also handed to anyone
	 * listening on a raw socket (e.g. the routing
	 * daemon for use in updating its tables).
	 */
}

enum ofp_return_code
_ofp_icmp_input(odp_packet_t pkt, struct ofp_ip *ip, struct ofp_icmp *icp,
		enum ofp_return_code (*reflect)(odp_packet_t pkt))
{
	const int icmplen = odp_be_to_cpu_16(ip->ip_len);

#ifdef PROMISCUOUS_INET
	/* XXX ICMP plumbing is currently incomplete for promiscuous mode interfaces not in fib 0 */
	if ((m->m_pkthdr.rcvif->if_flags & IFF_PROMISCINET) &&
	    (M_GETFIB(m) > 0))
		return OFP_PKT_DROP;
#endif

	/*
	 * Locate icmp structure in mbuf, and check
	 * that not corrupted and of at least minimum length.
	 */
#ifdef ICMPPRINTFS
	if (icmpprintfs) {
		char buf[4 * sizeof "123"];
		strcpy(buf, inet_ntoa(ip->ip_src));
		OFP_DBG("icmp_input from %s to %s, len %d",
		       buf, inet_ntoa(ip->ip_dst), icmplen);
	}
#endif

	if (icmplen < OFP_ICMP_MINLEN)
		return OFP_PKT_DROP;

#ifdef ICMPPRINTFS
	if (icmpprintfs)
		OFP_DBG("icmp_input, type %d code %d", icp->icmp_type,
		    icp->icmp_code);
#endif
	/*
	 * Message type specific processing.
	 */
/*TODO ICMP stats
	ICMPSTAT_INC(icps_inhist[icp->icmp_type]);*/
	switch (icp->icmp_type) {

	case OFP_ICMP_UNREACH:
		return icmp_destination_unreachable(icp, icmplen);

	case OFP_ICMP_TIMXCEED:
		return icmp_time_exceeded(icp, icmplen);

	case OFP_ICMP_PARAMPROB:
		return icmp_bad_ip_header(icp, icmplen);

	case OFP_ICMP_SOURCEQUENCH:
		return icmp_packet_lost(icp, icmplen);

	case OFP_ICMP_ECHO:
		return icmp_echo(pkt, icp, reflect);

	case OFP_ICMP_TSTAMP:
		return icmp_timestamp_request(pkt, icp, icmplen, reflect);

	case OFP_ICMP_MASKREQ:
		return icmp_address_mask_request(pkt, reflect);

	case OFP_ICMP_REDIRECT:
		return icmp_shorter_route(ip, icp);

	default:
		break;
	}

	/*
	 * Anything we didn't process is forwarded to slow path.
	 */
	return OFP_PKT_CONTINUE;
}

/*
 * Reflect the ip packet back to the source
 */
static enum ofp_return_code
icmp_reflect(odp_packet_t pkt)
{
	struct ofp_ip *ip = (struct ofp_ip *)odp_packet_l3_ptr(pkt, NULL);
	struct ofp_in_addr t;
	struct ofp_nh_entry *nh = NULL;
	struct ofp_ifnet *dev_out, *ifp = odp_packet_user_ptr(pkt);
	int optlen = (ip->ip_hl << 2) - sizeof(*ip);

/*	if (IN_MULTICAST(odp_be_to_cpu_32(ip->ip_src.s_addr)) ||
	    IN_EXPERIMENTAL(odp_be_to_cpu_32(ip->ip_src.s_addr)) ||
	    IN_ZERONET(odp_be_to_cpu_32(ip->ip_src.s_addr)) ) {
		MPSTAT_INC(icps_badaddr);
		goto done;
* Ip_output() will check for broadcast
	}
*/
	if (ifp == NULL)
		goto drop;

	t = ip->ip_dst;
	ip->ip_dst = ip->ip_src;

	/*
	 * Source selection for ICMP replies:
	 *
	 * If the incoming packet was addressed directly to one of our
	 * own addresses, use dst as the src for the reply.
	 */
	if ((dev_out = ofp_get_ifnet_match(t.s_addr, ifp->vrf, ifp->vlan))) {
		goto match;
	}

	/*
	 * If the incoming packet was addressed to one of our broadcast
	 * addresses, use the first non-broadcast address which corresponds
	 * to the incoming interface.
	 */
/*	ifp = m->m_pkthdr.rcvif;
	if (ifp != NULL && ifp->if_flags & IFF_BROADCAST) {
		IF_ADDR_RLOCK(ifp);
		OFP_TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
			if (ifa->ifa_addr->sa_family != AF_INET)
				continue;
			ia = ifatoia(ifa);
			if (satosin(&ia->ia_broadaddr)->sin_addr.s_addr ==
			    t.s_addr) {
				t = IA_SIN(ia)->sin_addr;
				IF_ADDR_RUNLOCK(ifp);
				goto match;
			}
		}
		IF_ADDR_RUNLOCK(ifp);
	}
*/
	/*
	 * If the packet was transiting through us, use the address of
	 * the interface the packet came through in.  If that interface
	 * doesn't have a suitable IP address, the normal selection
	 * criteria apply.
	 */
	t.s_addr = 0;
	if (1 /*V_icmp_rfi*/)
		t.s_addr = ifp->ip_addr_info[0].ip_addr;
	/*
	 * If the packet was transiting through us, use the address of
	 * the interface that is the closest to the packet source.
	 * When we don't have a route back to the packet source, stop here
	 * and drop the packet.
	 */
	uint32_t flags;
	nh = ofp_get_next_hop(ifp->vrf, ip->ip_dst.s_addr, &flags);
	if (nh == NULL) {
/*		ICMPSTAT_INC(icps_noroute);*/
		if (t.s_addr)
			goto match;
		else
			goto drop;

	}
	dev_out = ofp_get_ifnet(nh->port, nh->vlan);
	t.s_addr = dev_out->ip_addr_info[0].ip_addr;
match:
#ifdef MAC
	mac_netinet_icmp_replyinplace(m);
#endif
	ip->ip_src = t;
	ip->ip_ttl = 64; /*default ttl, from RFC 1340*/

	if (optlen > 0) {
		/*TODO Uncomment and adapt this code once option processing has been implemented.
		register u_char *cp;
		int opt, cnt;
		u_int len;
		 * Retrieve any source routing from the incoming packet;
		 * add on any record-route or timestamp options.
		cp = (u_char *) (ip + 1);
		if ((opts = ip_srcroute(m)) == 0 &&
		    (opts = m_gethdr(M_DONTWAIT, MT_DATA))) {
			opts->m_len = sizeof(struct in_addr);
			mtod(opts, struct in_addr *)->s_addr = 0;
		}
		if (opts) {
#ifdef ICMPPRINTFS
		    if (icmpprintfs)
			    OFP_DBG("icmp_reflect optlen %d rt %d => ",
				optlen, opts->m_len);
#endif
		    for (cnt = optlen; cnt > 0; cnt -= len, cp += len) {
			    opt = cp[IPOPT_OPTVAL];
			    if (opt == IPOPT_EOL)
				    break;
			    if (opt == IPOPT_NOP)
				    len = 1;
			    else {
				    if (cnt < IPOPT_OLEN + sizeof(*cp))
					    break;
				    len = cp[IPOPT_OLEN];
				    if (len < IPOPT_OLEN + sizeof(*cp) ||
					len > cnt)
					    break;
			    }
			     * Should check for overflow, but it "can't happen"
			    if (opt == IPOPT_RR || opt == IPOPT_TS ||
				opt == IPOPT_SECURITY) {
				    bcopy((caddr_t)cp,
					mtod(opts, caddr_t) + opts->m_len, len);
				    opts->m_len += len;
			    }
		    }
		    * Terminate & pad, if necessary
		    cnt = opts->m_len % 4;
		    if (cnt) {
			    for (; cnt < 4; cnt++) {
				    *(mtod(opts, caddr_t) + opts->m_len) =
					IPOPT_EOL;
				    opts->m_len++;
			    }
		    }
#ifdef ICMPPRINTFS
		    if (icmpprintfs)
			    OFP_DBG("%d", opts->m_len);
#endif
		}
		 * Now strip out original options by copying rest of first
		 * mbuf's data back, and adjust the IP length.
		ip->ip_len -= optlen;
		ip->ip_v = IPVERSION;
		ip->ip_hl = 5;
		m->m_len -= optlen;
		if (m->m_flags & M_PKTHDR)
			m->m_pkthdr.len -= optlen;
		optlen += sizeof(struct ip);
		bcopy((caddr_t)ip + optlen, (caddr_t)(ip + 1),
			 (unsigned)(m->m_len - sizeof(struct ip)));
		*/

		/*
		 * Since we don't have IP option processing (yet),
		 * it's best to just remove all options.
		 */
		uint32_t optpos = odp_packet_l3_offset(pkt) + sizeof(struct ofp_ip);

		/* Move packet data back, overwriting IP options. */
		if (odp_packet_move_data(pkt, optpos, optpos + optlen,
					 odp_packet_len(pkt) - (optpos + optlen)))
			goto drop;
		if (!odp_packet_pull_tail(pkt, optlen))
			goto drop;

		ip->ip_v = OFP_IPVERSION;
		ip->ip_hl = 5;
		uint16_t ip_len = odp_be_to_cpu_16(ip->ip_len);
		ip_len -= optlen;
		ip->ip_len = odp_cpu_to_be_16(ip_len);
	}

	icmp_send(pkt, nh/*, opts*/);
	return OFP_PKT_PROCESSED;
drop:
	return OFP_PKT_DROP;
}

/*
 * Send an icmp packet back to the ip level,
 * after supplying a checksum.
 */
static void
icmp_send(odp_packet_t pkt, struct ofp_nh_entry *nh)
{
	register struct ofp_ip *ip = (struct ofp_ip *)odp_packet_l3_ptr(pkt, NULL);
	register uint16_t hlen = ip->ip_hl << 2;
	register struct ofp_icmp *icp = (struct ofp_icmp *)((uint8_t *)ip + hlen);

	icp->icmp_cksum = 0;
	icp->icmp_cksum = ofp_cksum(pkt, odp_packet_l3_offset(pkt) + hlen,
				      odp_be_to_cpu_16(ip->ip_len) - hlen);

#ifdef ICMPPRINTFS
	if (icmpprintfs) {
		char buf[4 * sizeof "123"];
		strcpy(buf, inet_ntoa(ip->ip_dst));
		OFP_DBG("icmp_send dst %s src %s",
		       buf, inet_ntoa(ip->ip_src));
	}
#endif
	(void) ofp_ip_output(pkt, nh);
}

