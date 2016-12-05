/*-
 * Copyright (c) 1982, 1986, 1988, 1990, 1993, 1995
 *	The Regents of the University of California.
 * Copyright (c) 2015 Nokia Solutions and Networks
 * Copyright (c) 2015 Enea Software AB
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
 *	@(#)tcp_subr.c	8.2 (Berkeley) 5/24/95
 */

#include <string.h>
#include <stddef.h>

#include "ofpi_pkt_processing.h"
#include "ofpi_errno.h"

#include "odp.h"

#include "ofpi_sysctl.h"
#include "ofpi_socketvar.h"
#include "ofpi_sockstate.h"
#include "ofpi_systm.h"
#include "ofpi_protosw.h"
#include "ofpi_in.h"
#include "ofpi_ip.h"
#include "ofpi_icmp.h"
#include "ofpi_tcp.h"
#include "ofpi_in_pcb.h"
#ifdef INET6
#include "ofpi_ip6.h"
#include "ofpi_ip6_var.h"
#include "ofpi_ip6protosw.h"
#include "ofpi_in6_pcb.h"
#endif

#include "ofpi_tcp_fsm.h"
#include "ofpi_tcp_seq.h"
#include "ofpi_tcp_timer.h"
#include "ofpi_tcp_var.h"
#include "ofpi_tcp_shm.h"
#ifdef INET6
#include "ofpi_tcp6_var.h"
#endif
#include "ofpi_tcp_syncache.h"
#include "ofpi_md5.h"

//#include "ofp_tcpip.h"
#ifdef TCPDEBUG
#include <netinet/tcp_debug.h>
#endif

#define	SYSCTL_VNET_INT OFP_SYSCTL_INT

unsigned int ofp_max_protohdr = 0;
int ofp_max_linkhdr = 64;

VNET_DEFINE(int, ofp_tcp_mssdflt) = OFP_TCP_MSS;
#ifdef INET6
VNET_DEFINE(int, ofp_tcp_v6mssdflt) = OFP_TCP6_MSS;
#endif

#if 0
static int
sysctl_net_inet_tcp_mss_check(OFP_SYSCTL_HANDLER_ARGS)
{
	int error, new;

	new = V_tcp_mssdflt;
	error = sysctl_handle_int(oidp, &new, 0, req);
	if (error == 0 && req->newptr) {
		if (new < OFP_TCP_MINMSS)
			error = OFP_EINVAL;
		else
			V_tcp_mssdflt = new;
	}
	return (error);
}
#endif

#ifdef _INET6
static int
sysctl_net_inet_tcp_mss_v6_check(OFP_SYSCTL_HANDLER_ARGS)
{
	int error, new;

	new = V_tcp_v6mssdflt;
	error = sysctl_handle_int(oidp, &new, 0, req);
	if (error == 0 && req->newptr) {
		if (new < OFP_TCP_MINMSS)
			error = OFP_EINVAL;
		else
			V_tcp_v6mssdflt = new;
	}
	return (error);
}

SYSCTL_VNET_PROC(_net_inet_tcp, TCPCTL_V6MSSDFLT, v6mssdflt,
    OFP_CTLTYPE_INT|OFP_CTLFLAG_RW, &VNET_NAME(tcp_v6mssdflt), 0,
    &sysctl_net_inet_tcp_mss_v6_check, "I",
   "Default TCP Maximum Segment Size for IPv6");
#endif /* INET6 */

/*
 * Minimum MSS we accept and use. This prevents DoS attacks where
 * we are forced to a ridiculous low MSS like 20 and send hundreds
 * of packets instead of one. The effect scales with the available
 * bandwidth and quickly saturates the CPU and network interface
 * with packet generation and sending. Set to zero to disable MINMSS
 * checking. This setting prevents us from sending too small packets.
 */
VNET_DEFINE(int, ofp_tcp_minmss) = OFP_TCP_MINMSS;
VNET_DEFINE(int, ofp_tcp_do_rfc1323) = 1;
SYSCTL_VNET_INT(_net_inet_tcp, TCPCTL_DO_RFC1323, rfc1323, OFP_CTLFLAG_RW,
    &VNET_NAME(ofp_tcp_do_rfc1323), 0,
    "Enable rfc1323 (high performance TCP) extensions");

static int	tcp_log_debug = 0;
OFP_SYSCTL_INT(_net_inet_tcp, OFP_OID_AUTO, log_debug, OFP_CTLFLAG_RW,
    &tcp_log_debug, 0, "Log errors caused by incoming TCP segments");

static int	tcp_tcbhashsize = 0;
OFP_SYSCTL_INT(_net_inet_tcp, OFP_OID_AUTO, tcbhashsize, OFP_CTLFLAG_RDTUN,
    &tcp_tcbhashsize, 0, "Size of TCP control-block hashtable");

static int	do_tcpdrain = 1;
OFP_SYSCTL_INT(_net_inet_tcp, OFP_OID_AUTO, do_tcpdrain, OFP_CTLFLAG_RW, &do_tcpdrain, 0,
    "Enable tcp_drain routine for extra help when low on mbufs");

static VNET_DEFINE(int, icmp_may_rst) = 1;
#define	V_icmp_may_rst			VNET(icmp_may_rst)
SYSCTL_VNET_INT(_net_inet_tcp, OFP_OID_AUTO, icmp_may_rst, OFP_CTLFLAG_RW,
    &VNET_NAME(icmp_may_rst), 0,
    "Certain ICMP unreachable messages may abort connections in SYN_SENT");

static VNET_DEFINE(int, tcp_isn_reseed_interval) = 0;
#define	V_tcp_isn_reseed_interval	VNET(tcp_isn_reseed_interval)
SYSCTL_VNET_INT(_net_inet_tcp, OFP_OID_AUTO, isn_reseed_interval, OFP_CTLFLAG_RW,
    &VNET_NAME(tcp_isn_reseed_interval), 0,
    "Seconds between reseeding of ISN secret");

static int	tcp_soreceive_stream = 0;
OFP_SYSCTL_INT(_net_inet_tcp, OFP_OID_AUTO, soreceive_stream, OFP_CTLFLAG_RDTUN,
    &tcp_soreceive_stream, 0, "Using soreceive_stream for TCP sockets");

#define OFP_SACK_HOLE_ZONE_NITEMS 65536  /* derived from ofp_tcp_sack_globalmaxholes */

VNET_DEFINE(struct hhook_head *, ofp_tcp_hhh[HHOOK_TCP_LAST+1]);

static struct inpcb *tcp_mtudisc_notify(struct inpcb *, int);
static char *	tcp_log_addr(struct in_conninfo *inc, struct ofp_tcphdr *th,
		    void *ip4hdr, const void *ip6hdr);

/*
 * Wrapper around transport structs that contain same-named congestion
 * control variables. Allows algos to be shared amongst multiple CC aware
 * transprots.
 */
struct cc_var {
	void		*cc_data; /* Per-connection private CC algorithm data. */
	int		bytes_this_ack; /* # bytes acked by the current ACK. */
	tcp_seq		curack; /* Most recent ACK. */
	uint32_t	flags; /* Flags for cc_var (see below) */
	int		type; /* Indicates which ptr is valid in ccvc. */
	union ccv_container {
		struct tcpcb		*tcp;
		struct sctp_nets	*sctp;
	} ccvc;
};

/*
 * Lock key:
 *   (c) container lock (e.g. jail's pr_mtx) and/or osd_object_lock
 *   (l) osd_list_lock
 */
struct osd {
	uint32_t	  osd_nslots;	/* (c) */
	void		**osd_slots;	/* (c) */
	OFP_LIST_ENTRY(osd)	  osd_next;	/* (l) */
};

/*
 * XXX
 * Callouts should be moved into struct tcp directly.  They are currently
 * separate because the tcpcb structure is exported to userland for sysctl
 * parsing purposes, which do not know about callouts.
 */
struct tcpcb_mem {
	struct	tcpcb		ofp_tcb;
	struct	tcp_timer	tt;
	struct	cc_var		ccv;
	struct	osd		osd;
};

static odp_spinlock_t isn_mtx;

#if 0
#define	ISN_LOCK_INIT()	mtx_init(&isn_mtx, "isn_mtx", NULL, MTX_DEF)
#define	ISN_LOCK()	mtx_lock(&isn_mtx)
#define	ISN_UNLOCK()	mtx_unlock(&isn_mtx)
#else
#define	ISN_LOCK_INIT()	do { \
		/*OFP_DBG("isn lock init");*/ \
		odp_spinlock_init(&isn_mtx); \
	} while (0)
#define	ISN_LOCK() do { \
		/*OFP_DBG("isn lock");*/ \
		odp_spinlock_lock(&isn_mtx); \
	} while (0)
#define	ISN_UNLOCK() do { \
		/*OFP_DBG("isn unlock");*/ \
		odp_spinlock_unlock(&isn_mtx); \
	} while (0)
#endif


static int
tcp_inpcb_init(void *mem, int size, int flags)
{
	struct inpcb *inp = mem;
	(void)size;
	(void)flags;

	INP_LOCK_INIT(inp, "inp", "tcpinp");
	return (0);
}

void
ofp_tcp_tcbinfo_hashstats(unsigned int *min, unsigned int *avg, unsigned int *max)
{
	ofp_in_pcbinfo_hashstats(&V_tcbinfo, min, avg, max);
}

void
ofp_tcp_init(void)
{
	int hashsize;

#if 0
	if (hhook_head_register(HHOOK_TYPE_TCP, HHOOK_TCP_EST_IN,
	    &V_tcp_hhh[HHOOK_TCP_EST_IN], HHOOK_NOWAIT|HHOOK_HEADISINVNET) != 0)
		OFP_WARN("unable to register helper hook");
	if (hhook_head_register(HHOOK_TYPE_TCP, HHOOK_TCP_EST_OUT,
	    &V_tcp_hhh[HHOOK_TCP_EST_OUT], HHOOK_NOWAIT|HHOOK_HEADISINVNET) != 0)
		OFP_WARN("unable to register helper hook");
#endif
	hashsize = TCBHASHSIZE;
#if 0 /* We trust size is power of 2. */
	TUNABLE_INT_FETCH("net.inet.tcp.tcbhashsize", &hashsize);
	if (!powerof2(hashsize)) {
		OFP_WARN("TCB hash size not a power of 2");
		hashsize = 512; /* safe default */
	}
#endif

#ifdef OFP_RSS
	ofp_tcp_rss_in_pcbinfo_init(hashsize, hashsize, tcp_inpcb_init, NULL, 0);
#else
	ofp_in_pcbinfo_init(&V_tcbinfo, "tcp", &V_tcb, hashsize, hashsize,
	    "tcp_inpcb", tcp_inpcb_init, NULL, 0);
#endif

	/*
	 * These have to be type stable for the benefit of the timers.
	 */
	V_tcpcb_zone = uma_zcreate(
		"tcpcb", OFP_NUM_PCB_TCP_MAX, sizeof(struct tcpcb_mem),
		NULL, NULL, NULL, NULL, UMA_ALIGN_PTR, UMA_ZONE_NOFREE);
	uma_zone_set_max(V_tcpcb_zone, maxsockets);

	ofp_tcp_tw_init();
	ofp_syncache_init();
	/* tcp_hc_init(); */
	ofp_tcp_reass_init();

	//TUNABLE_INT_FETCH("net.inet.tcp.sack.enable", &V_tcp_do_sack);

	V_sack_hole_zone = uma_zcreate(
		"sackhole", OFP_SACK_HOLE_ZONE_NITEMS, sizeof(struct sackhole),
		NULL, NULL, NULL, NULL, UMA_ALIGN_PTR, UMA_ZONE_NOFREE);

	/* XXX virtualize those bellow? */
	ofp_tcp_delacktime = TCPTV_DELACK;
	ofp_tcp_keepinit = TCPTV_KEEP_INIT;
	ofp_tcp_keepidle = TCPTV_KEEP_IDLE;
	ofp_tcp_keepintvl = TCPTV_KEEPINTVL;
	ofp_tcp_maxpersistidle = TCPTV_KEEP_IDLE;
	ofp_tcp_msl = TCPTV_MSL;
	ofp_tcp_rexmit_min = TCPTV_MIN;
	if (ofp_tcp_rexmit_min < 1)
		ofp_tcp_rexmit_min = 1;
	ofp_tcp_rexmit_slop = TCPTV_CPU_VAR;
#ifdef PASSIVE_INET
	tcp_reassdl = TCPTV_REASSDL;
#endif
	ofp_tcp_finwait2_timeout = TCPTV_FINWAIT2_TIMEOUT;
	tcp_tcbhashsize = hashsize;

#ifdef INET6
#define TCP_MINPROTOHDR (sizeof(struct ofp_ip6_hdr) + sizeof(struct ofp_tcphdr))
#else /* INET6 */
#define TCP_MINPROTOHDR (sizeof(struct tcpiphdr))
#endif /* INET6 */
	if (ofp_max_protohdr < TCP_MINPROTOHDR)
		ofp_max_protohdr = TCP_MINPROTOHDR;
	if (ofp_max_linkhdr + TCP_MINPROTOHDR > SHM_PKT_POOL_BUFFER_SIZE)
		panic("ofp_tcp_init");
#undef TCP_MINPROTOHDR

	ISN_LOCK_INIT();
#if 0
	EVENTHANDLER_REGISTER(shutdown_pre_sync, ofp_tcp_fini, NULL,
		SHUTDOWN_PRI_DEFAULT);
	EVENTHANDLER_REGISTER(maxsockets_change, tcp_zone_change, NULL,
		EVENTHANDLER_PRI_ANY);
#endif
#ifndef OFP_RSS
	shm_tcp->ofp_tcp_slow_timer = ofp_timer_start(500000, ofp_tcp_slowtimo, NULL, 0);
#else
	int32_t cpu_id = 0;
	for (; cpu_id < odp_cpu_count(); cpu_id++)
		shm_tcp->ofp_tcp_slow_timer[cpu_id] = ofp_timer_start_cpu_id(
				500000,	ofp_tcp_slowtimo, NULL, 0, cpu_id);
#endif
}

static void ofp_tcp_slow_timer_cancel(void)
{
#ifndef OFP_RSS
	ofp_timer_cancel(shm_tcp->ofp_tcp_slow_timer);
	shm_tcp->ofp_tcp_slow_timer = ODP_TIMER_INVALID;
#else
	int32_t cpu_id = 0;
	for (; cpu_id < odp_cpu_count(); cpu_id++) {
		ofp_timer_cancel(shm_tcp->ofp_tcp_slow_timer[cpu_id]);
		shm_tcp->ofp_tcp_slow_timer[cpu_id] = ODP_TIMER_INVALID;
	}
#endif
}


void
ofp_tcp_destroy(void)
{
	struct inpcb *inp, *inp_temp;
	struct tcptw *tw;
	struct tcpcb *tp;

	ofp_tcp_slow_timer_cancel();

	OFP_LIST_FOREACH_SAFE(inp, V_tcbinfo.ipi_listhead, inp_list, inp_temp) {

		if (inp->inp_flags & INP_TIMEWAIT) {
			tw = intotw(inp);
			if (tw)
				uma_zfree(V_tcptw_zone, tw);
		} else if (!(inp->inp_flags & INP_DROPPED)) {
			tp = intotcpcb(inp);
			if (tp)
				ofp_tcp_discardcb(tp);
		}
		if (inp->inp_socket) {
			ofp_sbdestroy(&inp->inp_socket->so_snd,
					inp->inp_socket);
			ofp_sbdestroy(&inp->inp_socket->so_rcv,
					inp->inp_socket);
		}

		uma_zfree(V_tcbinfo.ipi_zone, inp);
	}
	uma_zdestroy(V_sack_hole_zone);
	uma_zdestroy(V_tcp_reass_zone);
	uma_zdestroy(V_tcp_syncache_zone);
	uma_zdestroy(V_tcptw_zone);
	uma_zdestroy(V_tcpcb_zone);
	uma_zdestroy(V_tcbinfo.ipi_zone);
}

void
ofp_tcp_fini(void *xtp)
{
	(void)xtp;
}

/*
 * Fill in the IP and TCP headers for an outgoing packet, given the tcpcb.
 * tcp_template used to store this data in mbufs, but we now recopy it out
 * of the tcpcb each time to conserve mbufs.
 */
void
ofp_tcpip_fillheaders(struct inpcb *inp, void *ip_ptr, void *tcp_ptr)
{
	struct ofp_tcphdr *th = (struct ofp_tcphdr *)tcp_ptr;

	INP_WLOCK_ASSERT(inp);

#ifdef INET6
	if ((inp->inp_vflag & INP_IPV6) != 0) {
		struct ofp_ip6_hdr *ip6;

		ip6 = (struct ofp_ip6_hdr *)ip_ptr;
		ip6->ofp_ip6_flow = (ip6->ofp_ip6_flow & ~OFP_IPV6_FLOWINFO_MASK) |
			(inp->inp_flow & OFP_IPV6_FLOWINFO_MASK);
		ip6->ofp_ip6_vfc = (ip6->ofp_ip6_vfc & ~OFP_IPV6_VERSION_MASK) |
			(OFP_IPV6_VERSION & OFP_IPV6_VERSION_MASK);
		ip6->ofp_ip6_nxt = OFP_IPPROTO_TCP;
		ip6->ofp_ip6_plen = odp_cpu_to_be_16(sizeof(struct ofp_tcphdr));
		ip6->ip6_src = inp->in6p_laddr;
		ip6->ip6_dst = inp->in6p_faddr;
	}
	else
#endif
	{
		struct ofp_ip *ip;

		ip = (struct ofp_ip *)ip_ptr;
		ip->ip_v = OFP_IPVERSION;
		ip->ip_hl = 5;
		ip->ip_tos = inp->inp_ip_tos;
		ip->ip_len = 0;
		ip->ip_id = 0;
		ip->ip_off = 0;
		ip->ip_ttl = inp->inp_ip_ttl;
		ip->ip_sum = 0;
		ip->ip_p = OFP_IPPROTO_TCP;
		ip->ip_src = inp->inp_laddr;
		ip->ip_dst = inp->inp_faddr;
	}

	th->th_sport = inp->inp_lport;
	th->th_dport = inp->inp_fport;
	th->th_seq = 0;
	th->th_ack = 0;
	th->th_x2 = 0;
	th->th_off = 5;
	th->th_flags = 0;
	th->th_win = 0;
	th->th_urp = 0;
	th->th_sum = 0;		/* in_pseudo() is called later for ipv4 */
}

/*
 * Create template to be used to send tcp packets on a connection.
 * Allocates an mbuf and fills in a skeletal tcp/ip header.  The only
 * use for this function is in keepalives, which use ofp_tcp_respond.
 */
struct tcptemp *
ofp_tcpip_maketemplate(struct inpcb *inp)
{
	struct tcptemp *t;

	t = malloc(sizeof(*t));
	if (t == NULL)
		return (NULL);
	ofp_tcpip_fillheaders(inp, (void *)&t->tt_ipgen, (void *)&t->tt_t);
	return (t);
}

/*
 * Send a single message to the TCP at address specified by
 * the given TCP/IP header.  If m == NULL, then we make a copy
 * of the tcpiphdr at ti and send directly to the addressed host.
 * This is used to force keep alive messages out using the TCP
 * template for a connection.  If flags are given then we send
 * a message back to the TCP which originated the * segment ti,
 * and discard the mbuf containing it and any other attached mbufs.
 *
 * In any case the ack and sequence number of the transmitted
 * segment are as specified by the parameters.
 *
 * NOTE: If m != NULL, then ti must point to *inside* the mbuf.
 */
void
ofp_tcp_respond(struct tcpcb *tp, void *ipgen, struct ofp_tcphdr *th, odp_packet_t m,
	    tcp_seq ack, tcp_seq seq, int flags)
{
	int tlen;
	int win = 0;
	struct ofp_ip *ip;
	struct ofp_tcphdr *nth;
#ifdef INET6
	struct ofp_ip6_hdr *ip6;
	int isipv6;
#endif /* INET6 */
	int ipflags = 0;
	struct inpcb *inp;
	(void)ipflags;

	KASSERT(tp != NULL || m != ODP_PACKET_INVALID, ("ofp_tcp_respond: tp and m both NULL"));

#ifdef INET6
	isipv6 = ((struct ofp_ip *)ipgen)->ip_v == (OFP_IPV6_VERSION >> 4);
	ip6 = ipgen;
#endif /* INET6 */
	ip = ipgen;

	if (tp != NULL) {
		inp = tp->t_inpcb;
		KASSERT(inp != NULL, ("tcp control block w/o inpcb"));
		INP_WLOCK_ASSERT(inp);
	} else
		inp = NULL;

	if (tp != NULL) {
		if (!(flags & OFP_TH_RST)) {
			win = sbspace(&inp->inp_socket->so_rcv);

			if (win > (long)OFP_TCP_MAXWIN << tp->rcv_scale)
				win = (long)OFP_TCP_MAXWIN << tp->rcv_scale;
		}
	}

	int valid_m = m != ODP_PACKET_INVALID;

	if (!valid_m) {
#ifdef INET6
		if (isipv6) {
			m = ofp_packet_alloc(sizeof(struct ofp_ip6_hdr) +
				       sizeof(struct ofp_tcphdr));

			if (m == ODP_PACKET_INVALID)
				return;

			odp_packet_l3_offset_set(m, 0);
			odp_packet_l4_offset_set(m, sizeof(struct ofp_ip6_hdr));
		} else
#endif
		{
			m = ofp_packet_alloc(sizeof(struct ofp_ip) +
				       sizeof(struct ofp_tcphdr));

			if (m == ODP_PACKET_INVALID)
				return;

			odp_packet_l3_offset_set(m, 0);
			odp_packet_l4_offset_set(m, sizeof(struct ofp_ip));
		}
		flags = OFP_TH_ACK;
	}

	tlen = 0;

#ifdef INET6
	if (isipv6) {
		bcopy((char *)ip6, (char *)odp_packet_data(m),
		      sizeof(struct ofp_ip6_hdr));
		ip6 = (struct ofp_ip6_hdr *)odp_packet_data(m);
		nth = (struct ofp_tcphdr *)(ip6 + 1);
	} else
#endif /* INET6 */
	{
		bcopy((char *)ip, (char *)odp_packet_data(m),
		      sizeof(struct ofp_ip));
		ip = (struct ofp_ip *)odp_packet_data(m);
		nth = (struct ofp_tcphdr *)(ip + 1);
	}

	bcopy((char *)th, (char *)nth, sizeof(struct ofp_tcphdr));

	if (valid_m) {
#define xchg(a,b,type) { type t; t=a; a=b; b=t; }
#ifdef INET6
		if (isipv6) {
			xchg(ip6->ip6_dst, ip6->ip6_src, struct ofp_in6_addr);
		} else
#endif /* INET6 */
		{
			xchg(ip->ip_dst.s_addr, ip->ip_src.s_addr, uint32_t);
			xchg(nth->th_dport, nth->th_sport, uint16_t);
		}

#undef xchg
	} /* valid_m */

#ifdef INET6
	if (isipv6) {
		ip6->ofp_ip6_flow = 0;
		ip6->ofp_ip6_vfc = OFP_IPV6_VERSION;
		ip6->ofp_ip6_nxt = OFP_IPPROTO_TCP;
		ip6->ofp_ip6_plen = odp_cpu_to_be_16(sizeof(struct ofp_tcphdr));
		tlen += sizeof (struct ofp_ip6_hdr) + sizeof (struct ofp_tcphdr);
	}
#endif
#ifdef INET6
	else
#endif
	{
		tlen += sizeof (struct tcpiphdr);
		ip->ip_len = tlen;
		ip->ip_ttl = V_ip_defttl;
		if (V_path_mtu_discovery)
			ip->ip_off |= OFP_IP_DF;
	}

	odp_packet_user_ptr_set(m, NULL);
	nth->th_seq = odp_cpu_to_be_32(seq);
	nth->th_ack = odp_cpu_to_be_32(ack);
	nth->th_x2 = 0;
	nth->th_off = sizeof (struct ofp_tcphdr) >> 2;
	nth->th_flags = flags;
	if (tp != NULL)
		nth->th_win = odp_cpu_to_be_16((uint16_t) (win >> tp->rcv_scale));
	else
		nth->th_win = odp_cpu_to_be_16((uint16_t)win);
	nth->th_urp = 0;

	/* HJo FIX
	odp_packet_csum_data(m) = offsetof(struct ofp_tcphdr, th_sum);
	*/
#ifdef INET6
	if (isipv6) {
		odp_packet_set_csum_flags(m, CSUM_TCP_IPV6);
		nth->th_sum = 0;
		nth->th_sum = ofp_in6_cksum(m, OFP_IPPROTO_TCP,
			sizeof(struct ofp_ip6_hdr),
			tlen - sizeof(struct ofp_ip6_hdr));
		ip6->ofp_ip6_hlim = V_ip6_defhlim; /*in6_selecthlim(tp != NULL ? tp->t_inpcb :
		    NULL, NULL);*/
	}
#endif /* INET6 */
#ifdef INET6
	else
#endif
	{
		ip->ip_len = odp_cpu_to_be_16(ip->ip_len);
		ip->ip_off = odp_cpu_to_be_16(ip->ip_off);

		nth->th_sum = 0;
		nth->th_sum = ofp_in4_cksum(m);

		/* HJo FIX
		odp_packet_csum_flags(m) = CSUM_TCP;
		nth->th_sum = in_pseudo(ip->ip_src.s_addr, ip->ip_dst.s_addr,
		    odp_cpu_to_be_16((uint16_t)(tlen - sizeof(struct ofp_ip) + ip->ip_p)));
		*/
	}
#ifdef TCPDEBUG
	if (tp == NULL || (inp->inp_socket->so_options & OFP_SO_DEBUG))
		tcp_trace(TA_OUTPUT, 0, tp, (void *)odp_packet_data(m), th, 0);
#endif
#ifdef INET6
	if (isipv6)
		(void) ofp_ip6_output(m, NULL);
	else
#endif
		(void) ofp_ip_output(m, NULL);/* HJo, NULL, ipflags, NULL, inp*/
}

/*
 * Create a new TCP control block, making an
 * empty reassembly queue and hooking it to the argument
 * protocol control block.  The `inp' parameter must have
 * come from the zone allocator set up in ofp_tcp_init().
 */
struct tcpcb *
ofp_tcp_newtcpcb(struct inpcb *inp)
{
	struct tcpcb_mem *tm;
	struct tcpcb *tp;
#ifdef INET6
	int isipv6 = (inp->inp_vflag & INP_IPV6) != 0;
#endif /* INET6 */

	tm = uma_zalloc(V_tcpcb_zone, 0);
	if (tm == NULL)
		return (NULL);
	tp = &tm->ofp_tcb;

	/* Initialise cc_var struct for this tcpcb. */
	tp->ccv = &tm->ccv;
	tp->ccv->type = OFP_IPPROTO_TCP;
	tp->ccv->ccvc.tcp = tp;

#if 0 /* HJo FIX */
	/*
	 * Use the current system default CC algorithm.
	 */
	CC_LIST_RLOCK();
	KASSERT(!OFP_STAILQ_EMPTY(&cc_list), ("cc_list is empty!"));
	CC_ALGO(tp) = CC_DEFAULT();
	CC_LIST_RUNLOCK();

	if (CC_ALGO(tp)->cb_init != NULL)
		if (CC_ALGO(tp)->cb_init(tp->ccv) > 0) {
			uma_zfree(V_tcpcb_zone, tm);
			return (NULL);
		}

	tp->osd = &tm->osd;
	if (khelp_init_osd(HELPER_CLASS_TCP, tp->osd)) {
		uma_zfree(V_tcpcb_zone, tm);
		return (NULL);
	}
#endif

	tp->t_timers = &tm->tt;
	/*	OFP_LIST_INIT(&tp->t_segq); */	/* XXX covered by M_ZERO */
	tp->t_maxseg = tp->t_maxopd =
#ifdef INET6
		isipv6 ? V_tcp_v6mssdflt :
#endif /* INET6 */
		V_tcp_mssdflt;

	/* Set up our timeouts. */
	callout_init(&tp->t_timers->tt_rexmt, CALLOUT_MPSAFE);
	callout_init(&tp->t_timers->tt_persist, CALLOUT_MPSAFE);
	callout_init(&tp->t_timers->tt_keep, CALLOUT_MPSAFE);
	callout_init(&tp->t_timers->tt_2msl, CALLOUT_MPSAFE);
	callout_init(&tp->t_timers->tt_delack, CALLOUT_MPSAFE);

	if (V_tcp_do_rfc1323)
		tp->t_flags = (TF_REQ_SCALE|TF_REQ_TSTMP);
	if (V_tcp_do_sack)
		t_flags_or(tp->t_flags, TF_SACK_PERMIT);
	OFP_TAILQ_INIT(&tp->snd_holes);
	tp->t_inpcb = inp;	/* XXX */
	/*
	 * Init srtt to TCPTV_SRTTBASE (0), so we can tell that we have no
	 * rtt estimate.  Set rttvar so that srtt + 4 * rttvar gives
	 * reasonable initial retransmit time.
	 */
	tp->t_srtt = TCPTV_SRTTBASE;
	tp->t_rttvar = ((TCPTV_RTOBASE - TCPTV_SRTTBASE) << TCP_RTTVAR_SHIFT) / 4;
	tp->t_rttmin = ofp_tcp_rexmit_min;
	tp->t_rxtcur = TCPTV_RTOBASE;
	tp->snd_cwnd = OFP_TCP_MAXWIN << OFP_TCP_MAX_WINSHIFT;
	tp->snd_ssthresh = OFP_TCP_MAXWIN << OFP_TCP_MAX_WINSHIFT;
	tp->t_rcvtime = ofp_timer_ticks(0);
	/*
	 * IPv4 TTL initialization is necessary for an IPv6 socket as well,
	 * because the socket may be bound to an IPv6 wildcard address,
	 * which may match an IPv4-mapped IPv6 address.
	 */
	inp->inp_ip_ttl = V_ip_defttl;
	inp->inp_ppcb = tp;
	return (tp);		/* XXX */
}

#if 0 /* HJo */
/*
 * Switch the congestion control algorithm back to NewReno for any active
 * control blocks using an algorithm which is about to go away.
 * This ensures the CC framework can allow the unload to proceed without leaving
 * any dangling pointers which would trigger a panic.
 * Returning non-zero would inform the CC framework that something went wrong
 * and it would be unsafe to allow the unload to proceed. However, there is no
 * way for this to occur with this implementation so we always return zero.
 */
int
tcp_ccalgounload(struct cc_algo *unload_algo)
{
	struct cc_algo *tmpalgo;
	struct inpcb *inp;
	struct tcpcb *tp;
	VNET_ITERATOR_DECL(vnet_iter);

	/*
	 * Check all active control blocks across all network stacks and change
	 * any that are using "unload_algo" back to NewReno. If "unload_algo"
	 * requires cleanup code to be run, call it.
	 */
	VNET_LIST_RLOCK();
	VNET_FOREACH(vnet_iter) {
		CURVNET_SET(vnet_iter);
		INP_INFO_RLOCK(&V_tcbinfo);
		/*
		 * New connections already part way through being initialised
		 * with the CC algo we're removing will not race with this code
		 * because the INP_INFO_WLOCK is held during initialisation. We
		 * therefore don't enter the loop below until the connection
		 * list has stabilised.
		 */
		OFP_LIST_FOREACH(inp, &V_tcb, inp_list) {
			INP_WLOCK(inp);
			/* Important to skip tcptw structs. */
			if (!(inp->inp_flags & INP_TIMEWAIT) &&
			    (tp = intotcpcb(inp)) != NULL) {
				/*
				 * By holding INP_WLOCK here, we are assured
				 * that the connection is not currently
				 * executing inside the CC module's functions
				 * i.e. it is safe to make the switch back to
				 * NewReno.
				 */
				if (CC_ALGO(tp) == unload_algo) {
					tmpalgo = CC_ALGO(tp);
					/* NewReno does not require any init. */
					CC_ALGO(tp) = &newreno_cc_algo;
					if (tmpalgo->cb_destroy != NULL)
						tmpalgo->cb_destroy(tp->ccv);
				}
			}
			INP_WUNLOCK(inp);
		}
		INP_INFO_RUNLOCK(&V_tcbinfo);
		CURVNET_RESTORE();
	}
	VNET_LIST_RUNLOCK();

	return (0);
}
#endif

/*
 * Drop a TCP connection, reporting
 * the specified error.  If connection is synchronized,
 * then send a RST to peer.
 */
struct tcpcb *
ofp_tcp_drop(struct tcpcb *tp, int err)
{
	struct socket *so = tp->t_inpcb->inp_socket;

	INP_INFO_WLOCK_ASSERT(&V_tcbinfo);
	INP_WLOCK_ASSERT(tp->t_inpcb);

	if (TCPS_HAVERCVDSYN(tp->t_state)) {
		tp->t_state = TCPS_CLOSED;
		(void) ofp_tcp_output(tp);
		TCPSTAT_INC(tcps_drops);
	} else
		TCPSTAT_INC(tcps_conndrops);
	if (err == OFP_ETIMEDOUT && tp->t_softerror)
		err = tp->t_softerror;
	so->so_error = err;
	return (ofp_tcp_close(tp));
}

void
ofp_tcp_discardcb(struct tcpcb *tp)
{
	struct inpcb *inp = tp->t_inpcb;
	struct socket *so = inp->inp_socket;
#ifdef INET6
	int isipv6 = (inp->inp_vflag & INP_IPV6) != 0;
#endif /* INET6 */

	INP_WLOCK_ASSERT(inp);

	/*
	 * Make sure that all of our timers are stopped before we delete the
	 * PCB.
	 *
	 * XXXRW: Really, we would like to use callout_drain() here in order
	 * to avoid races experienced in tcp_timer.c where a timer is already
	 * executing at this point.  However, we can't, both because we're
	 * running in a context where we can't sleep, and also because we
	 * hold locks required by the timers.  What we instead need to do is
	 * test to see if callout_drain() is required, and if so, defer some
	 * portion of the remainder of ofp_tcp_discardcb() to an asynchronous
	 * context that can callout_drain() and then continue.  Some care
	 * will be required to ensure that no further processing takes place
	 * on the tcpcb, even though it hasn't been freed (a flag?).
	 */
	callout_stop(&tp->t_timers->tt_rexmt);
	callout_stop(&tp->t_timers->tt_persist);
	callout_stop(&tp->t_timers->tt_keep);
	callout_stop(&tp->t_timers->tt_2msl);
	callout_stop(&tp->t_timers->tt_delack);
#ifdef PASSIVE_INET
	callout_stop(&tp->t_timers->tt_reassdl);
#endif
	/*
	 * If we got enough samples through the srtt filter,
	 * save the rtt and rttvar in the routing entry.
	 * 'Enough' is arbitrarily defined as 4 rtt samples.
	 * 4 samples is enough for the srtt filter to converge
	 * to within enough % of the correct value; fewer samples
	 * and we could save a bogus rtt. The danger is not high
	 * as tcp quickly recovers from everything.
	 * XXX: Works very well but needs some more statistics!
	 */
	if (tp->t_rttupdated >= 4) {
		struct hc_metrics_lite metrics;
		uint64_t ssthresh;

		bzero(&metrics, sizeof(metrics));
		/*
		 * Update the ssthresh always when the conditions below
		 * are satisfied. This gives us better new start value
		 * for the congestion avoidance for new connections.
		 * ssthresh is only set if packet loss occured on a session.
		 *
		 * XXXRW: 'so' may be NULL here, and/or socket buffer may be
		 * being torn down.  Ideally this code would not use 'so'.
		 */
		ssthresh = tp->snd_ssthresh;
		if (ssthresh != 0 && ssthresh < so->so_snd.sb_hiwat / 2) {
			/*
			 * convert the limit from user data bytes to
			 * packets then to packet data bytes.
			 */
			ssthresh = (ssthresh + tp->t_maxseg / 2) / tp->t_maxseg;
			if (ssthresh < 2)
				ssthresh = 2;
			ssthresh *= (uint64_t)(tp->t_maxseg +
#ifdef INET6
				      (isipv6 ? sizeof (struct ofp_ip6_hdr) +
					       sizeof (struct ofp_tcphdr) :
#endif
				       sizeof (struct tcpiphdr)
#ifdef INET6
				       )
#endif
				      );
		} else
			ssthresh = 0;
		metrics.rmx_ssthresh = ssthresh;

		metrics.rmx_rtt = tp->t_srtt;
		metrics.rmx_rttvar = tp->t_rttvar;
		metrics.rmx_cwnd = tp->snd_cwnd;
		metrics.rmx_sendpipe = 0;
		metrics.rmx_recvpipe = 0;

		tcp_hc_update(&inp->inp_inc, &metrics);
	}

	/* free the reassembly queue, if any */
	ofp_tcp_reass_flush(tp);
#if 0 /* HJo */
	/* Disconnect offload device, if any. */
	tcp_offload_detach(tp);
#endif
	ofp_tcp_free_sackholes(tp);

#if 0 /* HJo */
	/* Allow the CC algorithm to clean up after itself. */
	if (CC_ALGO(tp)->cb_destroy != NULL)
		CC_ALGO(tp)->cb_destroy(tp->ccv);
	khelp_destroy_osd(tp->osd);

	CC_ALGO(tp) = NULL;
#endif
	inp->inp_ppcb = NULL;
	tp->t_inpcb = NULL;

	uma_zfree(V_tcpcb_zone, tp);
}

/*
 * Attempt to close a TCP control block, marking it as dropped, and freeing
 * the socket if we hold the only reference.
 */
struct tcpcb *
ofp_tcp_close(struct tcpcb *tp)
{
	struct inpcb *inp = tp->t_inpcb;
	struct socket *so;

	INP_INFO_WLOCK_ASSERT(&V_tcbinfo);
	INP_WLOCK_ASSERT(inp);

	/* Notify any offload devices of listener close */
	ofp_in_pcbdrop(inp);
	TCPSTAT_INC(tcps_closed);
	KASSERT(inp->inp_socket != NULL, ("ofp_tcp_close: inp_socket NULL"));
	so = inp->inp_socket;

	ofp_soisdisconnected(so);
	if (inp->inp_flags & INP_SOCKREF) {
		KASSERT(so->so_state & SS_PROTOREF,
		    ("ofp_tcp_close: !SS_PROTOREF"));
		inp->inp_flags &= ~INP_SOCKREF;
		INP_WUNLOCK(inp);
		ACCEPT_LOCK();
		OFP_SOCK_LOCK(so);
		so->so_state &= ~SS_PROTOREF;
		ofp_sofree(so);
		return (NULL);
	}
	return (tp);
}

void
ofp_tcp_drain(void)
{
	if (!do_tcpdrain)
		return;
}


/*
 * Notify a tcp user of an asynchronous error;
 * store error as soft error, but wake up user
 * (for now, won't do anything until can select for soft error).
 *
 * Do not wake up user since there currently is no mechanism for
 * reporting soft errors (yet - a kqueue filter may be added).
 */
static struct inpcb *
ofp_tcp_notify(struct inpcb *inp, int error)
{
	struct tcpcb *tp;

	INP_INFO_WLOCK_ASSERT(&V_tcbinfo);
	INP_WLOCK_ASSERT(inp);

	if ((inp->inp_flags & INP_TIMEWAIT) ||
	    (inp->inp_flags & INP_DROPPED))
		return (inp);

	tp = intotcpcb(inp);
	KASSERT(tp != NULL, ("tcp_notify: tp == NULL"));

	/*
	 * Ignore some errors if we are hooked up.
	 * If connection hasn't completed, has retransmitted several times,
	 * and receives a second error, give up now.  This is better
	 * than waiting a long time to establish a connection that
	 * can never complete.
	 */
	if (tp->t_state == TCPS_ESTABLISHED &&
	    (error == OFP_EHOSTUNREACH || error == OFP_ENETUNREACH ||
	     error == OFP_EHOSTDOWN)) {
		return (inp);
	} else if (tp->t_state < TCPS_ESTABLISHED && tp->t_rxtshift > 3 &&
	    tp->t_softerror) {
		tp = ofp_tcp_drop(tp, error);
		if (tp != NULL)
			return (inp);
		else
			return (NULL);
	} else {
		tp->t_softerror = error;
		return (inp);
	}

#if 0
	/* from freebsd*/
	wakeup( &so->so_timeo);
	sorwakeup(so);
	sowwakeup(so);
#endif
}

#if 0 /* HJo */
static int
tcp_pcblist(OFP_SYSCTL_HANDLER_ARGS)
{
	int error, i, m, n, pcb_count;
	struct inpcb *inp, **inp_list;
	inp_gen_t gencnt;
	struct xinpgen xig;

	/*
	 * The process of preparing the TCB list is too time-consuming and
	 * resource-intensive to repeat twice on every request.
	 */
	if (req->oldptr == NULL) {
		n = V_tcbinfo.ipi_count + ofp_syncache_pcbcount();
		n += imax(n / 8, 10);
		req->oldidx = 2 * (sizeof xig) + n * sizeof(struct xtcpcb);
		return (0);
	}

	if (req->newptr != NULL)
		return (OFP_EPERM);

	/*
	 * OK, now we're committed to doing something.
	 */
	INP_INFO_RLOCK(&V_tcbinfo);
	gencnt = V_tcbinfo.ipi_gencnt;
	n = V_tcbinfo.ipi_count;
	INP_INFO_RUNLOCK(&V_tcbinfo);

	m = ofp_syncache_pcbcount();

	error = sysctl_wire_old_buffer(req, 2 * (sizeof xig)
		+ (n + m) * sizeof(struct xtcpcb));
	if (error != 0)
		return (error);

	xig.xig_len = sizeof xig;
	xig.xig_count = n + m;
	xig.xig_gen = gencnt;
	xig.xig_sogen = so_gencnt;
	error = SYSCTL_OUT(req, &xig, sizeof xig);
	if (error)
		return (error);

	error = syncache_pcblist(req, m, &pcb_count);
	if (error)
		return (error);

	inp_list = malloc(n * sizeof *inp_list, M_TEMP, M_WAITOK);
	if (inp_list == NULL)
		return (OFP_ENOMEM);

	INP_INFO_RLOCK(&V_tcbinfo);
	for (inp = OFP_LIST_FIRST(V_tcbinfo.ipi_listhead), i = 0;
	    inp != NULL && i < n; inp = OFP_LIST_NEXT(inp, inp_list)) {
		INP_WLOCK(inp);
		if (inp->inp_gencnt <= gencnt) {
			/*
			 * XXX: This use of cr_cansee(), introduced with
			 * TCP state changes, is not quite right, but for
			 * now, better than nothing.
			 */
			if (inp->inp_flags & INP_TIMEWAIT) {
				if (intotw(inp) != NULL)
					error = cr_cansee(req->td->td_ucred,
					    intotw(inp)->tw_cred);
				else
					error = OFP_EINVAL;	/* Skip this inp. */
			} else
				error = cr_canseeinpcb(req->td->td_ucred, inp);
			if (error == 0) {
				ofp_in_pcbref(inp);
				inp_list[i++] = inp;
			}
		}
		INP_WUNLOCK(inp);
	}
	INP_INFO_RUNLOCK(&V_tcbinfo);
	n = i;

	error = 0;
	for (i = 0; i < n; i++) {
		inp = inp_list[i];
		INP_RLOCK(inp);
		if (inp->inp_gencnt <= gencnt) {
			struct xtcpcb xt;
			void *inp_ppcb;

			bzero(&xt, sizeof(xt));
			xt.xt_len = sizeof xt;
			/* XXX should avoid extra copy */
			bcopy(inp, &xt.xt_inp, sizeof *inp);
			inp_ppcb = inp->inp_ppcb;
			if (inp_ppcb == NULL)
				bzero((char *) &xt.xt_tp, sizeof xt.xt_tp);
			else if (inp->inp_flags & INP_TIMEWAIT) {
				bzero((char *) &xt.xt_tp, sizeof xt.xt_tp);
				xt.xt_tp.t_state = TCPS_TIME_WAIT;
			} else {
				bcopy(inp_ppcb, &xt.xt_tp, sizeof xt.xt_tp);
				if (xt.xt_tp.t_timers)
					tcp_timer_to_xtimer(&xt.xt_tp, xt.xt_tp.t_timers, &xt.xt_timer);
			}
			if (inp->inp_socket != NULL)
				sotoxsocket(inp->inp_socket, &xt.xt_socket);
			else {
				bzero(&xt.xt_socket, sizeof xt.xt_socket);
				xt.xt_socket.xso_protocol = OFP_IPPROTO_TCP;
			}
			xt.xt_inp.inp_gencnt = inp->inp_gencnt;
			INP_RUNLOCK(inp);
			error = SYSCTL_OUT(req, &xt, sizeof xt);
		} else
			INP_RUNLOCK(inp);
	}
	INP_INFO_WLOCK(&V_tcbinfo);
	for (i = 0; i < n; i++) {
		inp = inp_list[i];
		INP_RLOCK(inp);
		if (!ofp_in_pcbrele_rlocked(inp))
			INP_RUNLOCK(inp);
	}
	INP_INFO_WUNLOCK(&V_tcbinfo);

	if (!error) {
		/*
		 * Give the user an updated idea of our state.
		 * If the generation differs from what we told
		 * her before, she knows that something happened
		 * while we were processing this request, and it
		 * might be necessary to retry.
		 */
		INP_INFO_RLOCK(&V_tcbinfo);
		xig.xig_gen = V_tcbinfo.ipi_gencnt;
		xig.xig_sogen = so_gencnt;
		xig.xig_count = V_tcbinfo.ipi_count + pcb_count;
		INP_INFO_RUNLOCK(&V_tcbinfo);
		error = SYSCTL_OUT(req, &xig, sizeof xig);
	}
	free(inp_list, M_TEMP);
	return (error);
}

OFP_SYSCTL_PROC(_net_inet_tcp, TCPCTL_PCBLIST, pcblist,
    OFP_CTLTYPE_OPAQUE | OFP_CTLFLAG_RD, NULL, 0,
    tcp_pcblist, "S,xtcpcb", "List of active TCP connections");

static int
tcp_getcred(OFP_SYSCTL_HANDLER_ARGS)
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
	inp = ofp_in_pcblookup(&V_tcbinfo, addrs[1].sin_addr, addrs[1].sin_port,
	    addrs[0].sin_addr, addrs[0].sin_port, INPLOOKUP_RLOCKPCB, NULL);
	if (inp != NULL) {
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

#ifdef _INET6
static int
tcp6_getcred(OFP_SYSCTL_HANDLER_ARGS)
{
	struct xucred xuc;
	struct ofp_sockaddr_in6 addrs[2];
	struct inpcb *inp;
	int error;
#ifdef INET
	int mapped = 0;
#endif

	error = priv_check(req->td, PRIV_NETINET_GETCRED);
	if (error)
		return (error);
	error = SYSCTL_IN(req, addrs, sizeof(addrs));
	if (error)
		return (error);
	if ((error = sa6_embedscope(&addrs[0], V_ip6_use_defzone)) != 0 ||
	    (error = sa6_embedscope(&addrs[1], V_ip6_use_defzone)) != 0) {
		return (error);
	}
	if (IN6_IS_ADDR_V4MAPPED(&addrs[0].sin6_addr)) {
#ifdef INET
		if (IN6_IS_ADDR_V4MAPPED(&addrs[1].sin6_addr))
			mapped = 1;
		else
#endif
			return (OFP_EINVAL);
	}

#ifdef INET
	if (mapped == 1)
		inp = ofp_in_pcblookup(&V_tcbinfo,
			*(struct ofp_in_addr *)&addrs[1].sin6_addr.s6_addr[12],
			addrs[1].sin6_port,
			*(struct ofp_in_addr *)&addrs[0].sin6_addr.s6_addr[12],
			addrs[0].sin6_port, INPLOOKUP_RLOCKPCB, NULL);
	else
#endif
		inp = in6_pcblookup(&V_tcbinfo,
			&addrs[1].sin6_addr, addrs[1].sin6_port,
			&addrs[0].sin6_addr, addrs[0].sin6_port,
			INPLOOKUP_RLOCKPCB, NULL);
	if (inp != NULL) {
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

OFP_SYSCTL_PROC(_net_inet6_tcp6, OFP_OID_AUTO, getcred,
    OFP_CTLTYPE_OPAQUE|OFP_CTLFLAG_RW|OFP_CTLFLAG_PRISON, 0, 0,
    tcp6_getcred, "S,xucred", "Get the xucred of a TCP6 connection");
#endif /* INET6 */
#endif /* HJo */



/*
 * Return the next larger or smaller MTU plateau (table from RFC 1191)
 * given current value MTU.  If DIR is less than zero, a larger plateau
 * is returned; otherwise, a smaller value is returned.
 */
static int
ip_next_mtu(int mtu, int dir)
{
	static int mtutab[] = {
		65535, 32000, 17914, 8166, 4352, 2002, 1492, 1280, 1006, 508,
		296, 68, 0
	};
	int i, size;

	size = (sizeof mtutab) / (sizeof mtutab[0]);
	if (dir >= 0) {
		for (i = 0; i < size; i++)
			if (mtu > mtutab[i])
				return mtutab[i];
	} else {
		for (i = size - 1; i >= 0; i--)
			if (mtu < mtutab[i])
				return mtutab[i];
		if (mtu == mtutab[0])
			return mtutab[0];
	}
	return 0;
}

#ifdef INET
void
ofp_tcp_ctlinput(int cmd, struct ofp_sockaddr *sa, void *vip)
{
	struct ofp_ip *ip = vip;
	struct ofp_tcphdr *th;
	struct ofp_in_addr faddr;
	struct inpcb *inp;
	struct tcpcb *tp;
	struct inpcb *(*notify)(struct inpcb *, int) = ofp_tcp_notify;
	struct ofp_icmp *icp;
	struct in_conninfo inc;
	tcp_seq icmp_tcp_seq;
	int mtu;

	faddr = ((struct ofp_sockaddr_in *)sa)->sin_addr;
	if (sa->sa_family != OFP_AF_INET || faddr.s_addr == OFP_INADDR_ANY)
		return;

	if (cmd == OFP_PRC_MSGSIZE)
		notify = tcp_mtudisc_notify;
	else if (V_icmp_may_rst && (cmd == OFP_PRC_UNREACH_ADMIN_PROHIB ||
		cmd == OFP_PRC_UNREACH_PORT ||
		cmd == OFP_PRC_TIMXCEED_INTRANS) && ip)
		notify = ofp_tcp_drop_syn_sent;
	/*
	 * Redirects don't need to be handled up here.
	 */
	else if (OFP_PRC_IS_REDIRECT(cmd))
		return;
	/*
	 * Source quench is depreciated.
	 */
	else if (cmd == OFP_PRC_QUENCH)
		return;
	/*
	 * Hostdead is ugly because it goes linearly through all PCBs.
	 * XXX: We never get this from ICMP, otherwise it makes an
	 * excellent DoS attack on machines with many connections.
	 */
	else if (cmd == OFP_PRC_HOSTDEAD)
		ip = NULL;
	else if ((unsigned)cmd >= OFP_PRC_NCMDS || ofp_inetctlerrmap[cmd] == 0)
		return;

	if (ip != NULL) {
		icp = (struct ofp_icmp *)((char *)ip
				      - offsetof(struct ofp_icmp, ofp_icmp_ip));
		th = (struct ofp_tcphdr *)((char *)ip
				       + (ip->ip_hl << 2));
		INP_INFO_WLOCK(&V_tcbinfo);
		inp = ofp_in_pcblookup(&V_tcbinfo, faddr, th->th_dport,
		    ip->ip_src, th->th_sport, INPLOOKUP_WLOCKPCB, NULL);

		if (inp != NULL)  {
			if (!(inp->inp_flags & INP_TIMEWAIT) &&
			    !(inp->inp_flags & INP_DROPPED) &&
			    !(inp->inp_socket == NULL)) {
				icmp_tcp_seq = odp_cpu_to_be_32(th->th_seq);
				tp = intotcpcb(inp);

				if (SEQ_GEQ(icmp_tcp_seq, tp->snd_una) &&
				    SEQ_LT(icmp_tcp_seq, tp->snd_max)) {

					if (cmd == OFP_PRC_MSGSIZE) {
					    /*
					     * MTU discovery:
					     * If we got a needfrag set the MTU
					     * in the route to the suggested new
					     * value (if given) and then notify.
					     */
					    bzero(&inc, sizeof(inc));
					    inc.inc_faddr = faddr;
					    inc.inc_fibnum =
						inp->inp_inc.inc_fibnum;

					    mtu = odp_be_to_cpu_16(
					    	icp->ofp_icmp_nextmtu);

					    /*
					     * If no alternative MTU was
					     * proposed, try the next smaller
					     * one.  ip->ip_len has already
					     * been swapped in icmp_input().
					     */
					    if (!mtu)
						mtu = ip_next_mtu(ip->ip_len,
							1);

					    if (mtu < (int)(V_tcp_minmss
							    + sizeof(struct tcpiphdr)))
						mtu = V_tcp_minmss
						 + sizeof(struct tcpiphdr);
#if 0
					    /*
					     * Only cache the MTU if it
					     * is smaller than the interface
					     * or route MTU.  ofp_tcp_mtudisc()
					     * will do right thing by itself.
					     */
					    if (mtu <= (int)ofp_tcp_maxmtu(&inc, NULL))
						tcp_hc_updatemtu(&inc, mtu);
#endif /* 0 */
					    ofp_tcp_mtudisc(inp, mtu);
					} else
						inp = (*notify)(inp,
						    ofp_inetctlerrmap[cmd]);
				}
			}
			if (inp != NULL)
				INP_WUNLOCK(inp);
		} else {
			bzero(&inc, sizeof(inc));
			inc.inc_fport = th->th_dport;
			inc.inc_lport = th->th_sport;
			inc.inc_faddr = faddr;
			inc.inc_laddr = ip->ip_src;
			ofp_syncache_unreach(&inc, th);
		}
		INP_INFO_WUNLOCK(&V_tcbinfo);
	} else
		ofp_in_pcbnotifyall(&V_tcbinfo, faddr, ofp_inetctlerrmap[cmd], notify);
}
#endif /* INET */

#ifdef INET6
void
ofp_tcp6_ctlinput(int cmd, struct ofp_sockaddr *sa, void *d)
{
	struct ofp_tcphdr th;
	struct inpcb *(*notify)(struct inpcb *, int) = ofp_tcp_notify;
	struct ofp_ip6_hdr *ip6;
	odp_packet_t m;
	struct ofp_ip6ctlparam *ip6cp = NULL;
	const struct ofp_sockaddr_in6 *sa6_src = NULL;
	int off;
	struct tcp_portonly {
		uint16_t th_sport;
		uint16_t th_dport;
	} *thp;

	if (sa->sa_family != OFP_AF_INET6 ||
	    sa->sa_len != sizeof(struct ofp_sockaddr_in6))
		return;
	if (cmd == OFP_PRC_MSGSIZE)
		notify = tcp_mtudisc_notify;
	else if (!OFP_PRC_IS_REDIRECT(cmd) &&
		 ((unsigned)cmd >= OFP_PRC_NCMDS || ofp_inet6ctlerrmap[cmd] == 0))
		return;
	/* Source quench is depreciated. */
	else if (cmd == OFP_PRC_QUENCH)
		return;

	/* if the parameter is from icmp6, decode it. */
	if (d != NULL) {
		ip6cp = (struct ofp_ip6ctlparam *)d;
		m = ip6cp->ip6c_m;
		ip6 = ip6cp->ip6c_ip6;
		off = ip6cp->ip6c_off;
		sa6_src = ip6cp->ip6c_src;
	} else {
		m = NULL;
		ip6 = NULL;
		off = 0;	/* fool gcc */
		sa6_src = &ofp_sa6_any;
	}

	if (ip6 != NULL) {
		struct in_conninfo inc;
		/*
		 * XXX: We assume that when IPV6 is non NULL,
		 * M and OFF are valid.
		 */

#if 0
		/* check if we can safely examine src and dst ports */
		if (odp_packet_len(m) < off + sizeof(*thp))
			return;
#endif /* 0 */

		bzero(&th, sizeof(th));
		memcpy((uint8_t *)&th, (uint8_t *)odp_packet_l3_ptr(m, NULL) +
			off, sizeof(*thp));

		ofp_in6_pcbnotify(&V_tcbinfo, sa, th.th_dport,
		    (struct ofp_sockaddr *)ip6cp->ip6c_src,
		    th.th_sport, cmd, NULL, notify);

		bzero(&inc, sizeof(inc));
		inc.inc_fport = th.th_dport;
		inc.inc_lport = th.th_sport;
		inc.inc6_faddr = ((struct ofp_sockaddr_in6 *)sa)->sin6_addr;
		inc.inc6_laddr = ip6cp->ip6c_src->sin6_addr;
		inc.inc_flags |= INC_ISIPV6;
		INP_INFO_WLOCK(&V_tcbinfo);
#ifdef PROMISCUOUS_INET
		/* XXX need to pass mbuf here */
		ofp_syncache_unreach(&inc, &th, NULL);
#else
		ofp_syncache_unreach(&inc, &th);
#endif /* PROMISCUOUS_INET */
		INP_INFO_WUNLOCK(&V_tcbinfo);
	} else
		ofp_in6_pcbnotify(&V_tcbinfo, sa, 0,
			(const struct ofp_sockaddr *)sa6_src, 0, cmd,
			NULL, notify);

}
#endif /* INET6 */


/*
 * Following is where TCP initial sequence number generation occurs.
 *
 * There are two places where we must use initial sequence numbers:
 * 1.  In SYN-ACK packets.
 * 2.  In SYN packets.
 *
 * All ISNs for SYN-ACK packets are generated by the syncache.  See
 * tcp_syncache.c for details.
 *
 * The ISNs in SYN packets must be monotonic; TIME_WAIT recycling
 * depends on this property.  In addition, these ISNs should be
 * unguessable so as to prevent connection hijacking.  To satisfy
 * the requirements of this situation, the algorithm outlined in
 * RFC 1948 is used, with only small modifications.
 *
 * Implementation details:
 *
 * Time is based off the system timer, and is corrected so that it
 * increases by one megabyte per second.  This allows for proper
 * recycling on high speed LANs while still leaving over an hour
 * before rollover.
 *
 * As reading the *exact* system time is too expensive to be done
 * whenever setting up a TCP connection, we increment the time
 * offset in two ways.  First, a small random positive increment
 * is added to isn_offset for each connection that is set up.
 * Second, the function tcp_isn_tick fires once per clock tick
 * and increments isn_offset as necessary so that sequence numbers
 * are incremented at approximately ISN_BYTES_PER_SECOND.  The
 * random positive increments serve only to ensure that the same
 * exact sequence number is never sent out twice (as could otherwise
 * happen when a port is recycled in less than the system tick
 * interval.)
 *
 * net.inet.tcp.isn_reseed_interval controls the number of seconds
 * between seeding of isn_secret.  This is normally set to zero,
 * as reseeding should not be necessary.
 *
 * Locking of the global variables isn_secret, isn_last_reseed, isn_offset,
 * isn_offset_old, and isn_ctx is performed using the TCP pcbinfo lock.  In
 * general, this means holding an exclusive (write) lock.
 */

#define ISN_BYTES_PER_SECOND 1048576
#define ISN_STATIC_INCREMENT 4096
#define ISN_RANDOM_INCREMENT (4096 - 1)

static VNET_DEFINE(uint8_t, isn_secret[32]);
static VNET_DEFINE(int, isn_last);
static VNET_DEFINE(int, isn_last_reseed);
static VNET_DEFINE(uint32_t, isn_offset);
static VNET_DEFINE(uint32_t, isn_offset_old);

#define	V_isn_secret			VNET(isn_secret)
#define	V_isn_last			VNET(isn_last)
#define	V_isn_last_reseed		VNET(isn_last_reseed)
#define	V_isn_offset			VNET(isn_offset)
#define	V_isn_offset_old		VNET(isn_offset_old)

tcp_seq
ofp_tcp_new_isn(struct tcpcb *tp)
{
	MD5_CTX isn_ctx;
	uint32_t md5_buffer[4];
	tcp_seq new_isn;
	uint32_t projected_offset;
	uint64_t cpucycles;

	INP_WLOCK_ASSERT(tp->t_inpcb);

	ISN_LOCK();
	/* Seed if this is the first use, reseed if requested. */
	if ((V_isn_last_reseed == 0) || ((V_tcp_isn_reseed_interval > 0) &&
	     (((uint32_t)V_isn_last_reseed + (uint32_t)V_tcp_isn_reseed_interval*hz)
	      < (uint32_t)ofp_timer_ticks(0)))) {
		/* HJo: read_random(&V_isn_secret, sizeof(V_isn_secret));*/
		cpucycles = ofp_timer_ticks(0);
		bcopy(&cpucycles, V_isn_secret, sizeof(cpucycles));
		V_isn_last_reseed = ofp_timer_ticks(0);
	}

	/* Compute the md5 hash and return the ISN. */
	ofp_MD5Init(&isn_ctx);
	ofp_MD5Update(&isn_ctx, (uint8_t *) &tp->t_inpcb->inp_fport, sizeof(uint16_t));
	ofp_MD5Update(&isn_ctx, (uint8_t *) &tp->t_inpcb->inp_lport, sizeof(uint16_t));
#ifdef INET6
	if ((tp->t_inpcb->inp_vflag & INP_IPV6) != 0) {
		ofp_MD5Update(&isn_ctx, (uint8_t *) &tp->t_inpcb->in6p_faddr,
			  sizeof(struct ofp_in6_addr));
		ofp_MD5Update(&isn_ctx, (uint8_t *) &tp->t_inpcb->in6p_laddr,
			  sizeof(struct ofp_in6_addr));
	} else
#endif
	{
		ofp_MD5Update(&isn_ctx, (uint8_t *) &tp->t_inpcb->inp_faddr,
			  sizeof(struct ofp_in_addr));
		ofp_MD5Update(&isn_ctx, (uint8_t *) &tp->t_inpcb->inp_laddr,
			  sizeof(struct ofp_in_addr));
	}
	ofp_MD5Update(&isn_ctx, (uint8_t *) &V_isn_secret, sizeof(V_isn_secret));
	ofp_MD5Final((uint8_t *) &md5_buffer, &isn_ctx);
	new_isn = (tcp_seq) md5_buffer[0];
	V_isn_offset += ISN_STATIC_INCREMENT
		/* + (arc4random() & ISN_RANDOM_INCREMENT)*/;
	if (ofp_timer_ticks(0) != V_isn_last) {
		projected_offset = V_isn_offset_old +
		    ISN_BYTES_PER_SECOND / hz * (ofp_timer_ticks(0) - V_isn_last);
#define	SEQ_GT(a,b)	((int)((a)-(b)) > 0)
		if (SEQ_GT(projected_offset, V_isn_offset))
			V_isn_offset = projected_offset;
		V_isn_offset_old = V_isn_offset;
		V_isn_last = ofp_timer_ticks(0);
	}
	new_isn += V_isn_offset;
	ISN_UNLOCK();
	return (new_isn);
}

/*
 * When a specific ICMP unreachable message is received and the
 * connection state is SYN-SENT, drop the connection.  This behavior
 * is controlled by the icmp_may_rst sysctl.
 */
struct inpcb *
ofp_tcp_drop_syn_sent(struct inpcb *inp, int err)
{
	struct tcpcb *tp;

	INP_INFO_WLOCK_ASSERT(&V_tcbinfo);
	INP_WLOCK_ASSERT(inp);

	if ((inp->inp_flags & INP_TIMEWAIT) ||
	    (inp->inp_flags & INP_DROPPED))
		return (inp);

	tp = intotcpcb(inp);
	if (tp->t_state != TCPS_SYN_SENT)
		return (inp);

	tp = ofp_tcp_drop(tp, err);
	if (tp != NULL)
		return (inp);
	else
		return (NULL);
}


/*
 * When `need fragmentation' ICMP is received, update our idea of the MSS
 * based on the new value. Also nudge TCP to send something, since we
 * know the packet we just sent was dropped.
 * This duplicates some code in the ofp_tcp_mss() function in ofp_tcp_input.c.
 */
static struct inpcb *
tcp_mtudisc_notify(struct inpcb *inp, int err)
{
	(void)err;
	return (ofp_tcp_mtudisc(inp, -1));
}

struct inpcb *
ofp_tcp_mtudisc(struct inpcb *inp, int mtuoffer)
{
	struct tcpcb *tp;
	struct socket *so;

	INP_WLOCK_ASSERT(inp);
	if ((inp->inp_flags & INP_TIMEWAIT) ||
	    (inp->inp_flags & INP_DROPPED))
		return (inp);

	tp = intotcpcb(inp);
	KASSERT(tp != NULL, ("ofp_tcp_mtudisc: tp == NULL"));

	ofp_tcp_mss_update(tp, -1, mtuoffer, NULL, NULL);

	so = inp->inp_socket;
	SOCKBUF_LOCK(&so->so_snd);
	/* If the mss is larger than the socket buffer, decrease the mss. */
	if (so->so_snd.sb_hiwat < tp->t_maxseg)
		tp->t_maxseg = so->so_snd.sb_hiwat;
	SOCKBUF_UNLOCK(&so->so_snd);

	TCPSTAT_INC(tcps_mturesent);
	tp->t_rtttime = 0;
	tp->snd_nxt = tp->snd_una;
	ofp_tcp_free_sackholes(tp);
	tp->snd_recover = tp->snd_max;
	if (tp->t_flags & TF_SACK_PERMIT)
		EXIT_FASTRECOVERY(tp->t_flags);
	ofp_tcp_output(tp);
	return (inp);
}

#ifdef INET
/*
 * Look-up the routing entry to the peer of this inpcb.  If no route
 * is found and it cannot be allocated, then return 0.  This routine
 * is called by TCP routines that access the rmx structure and by
 * ofp_tcp_mss_update to get the peer/interface MTU.
 */
u_long
ofp_tcp_maxmtu(struct in_conninfo *inc, int *flags)
{
	(void)inc;
	(void)flags;
	return 1000;
#if 0 /* HJo: FIX */
	struct route sro;
	struct ofp_sockaddr_in *dst;
	struct ifnet *ifp = NULL;
	uint64_t maxmtu = 0;

	KASSERT(inc != NULL, ("ofp_tcp_maxmtu with NULL in_conninfo pointer"));

	bzero(&sro, sizeof(sro));
	if (inc->inc_faddr.s_addr != OFP_INADDR_ANY) {
	        dst = (struct ofp_sockaddr_in *)&sro.ro_dst;
		dst->sin_family = OFP_AF_INET;
		dst->sin_len = sizeof(*dst);
		dst->sin_addr = inc->inc_faddr;
		in_rtalloc_ign(&sro, 0, inc->inc_fibnum);
	}
	if (sro.ro_rt != NULL) {
		ifp = sro.ro_rt->rt_ifp;
		if (sro.ro_rt->rt_rmx.rmx_mtu == 0)
			maxmtu = ifp->if_mtu;
		else
			maxmtu = min(sro.ro_rt->rt_rmx.rmx_mtu, ifp->if_mtu);

		RTFREE(sro.ro_rt);
	}

	/* Report additional interface capabilities. */
	if (ifp && (flags != NULL)) {
		if (ifp->if_capenable & IFCAP_TSO4 &&
		    ifp->if_hwassist & CSUM_TSO)
			*flags |= CSUM_TSO;
	}


	return (maxmtu);
#endif
}
#endif /* INET */

#ifdef INET6
u_long
ofp_tcp_maxmtu6(struct in_conninfo *inc, int *flags)
{
#if 0
	struct route_in6 sro6;
	struct ifnet *ifp;
#endif
	uint64_t maxmtu = 1000;

	(void)inc;
	(void)flags;

	KASSERT(inc != NULL, ("tcp_maxmtu6 with NULL in_conninfo pointer"));
#if 0
	bzero(&sro6, sizeof(sro6));
	if (!IN6_IS_ADDR_UNSPECIFIED(&inc->inc6_faddr)) {
		sro6.ro_dst.sin6_family = OFP_AF_INET6;
		sro6.ro_dst.sin6_len = sizeof(struct ofp_sockaddr_in6);
		sro6.ro_dst.sin6_addr = inc->inc6_faddr;
		in6_rtalloc_ign(&sro6, 0, inc->inc_fibnum);
	}
	if (sro6.ro_rt != NULL) {
		ifp = sro6.ro_rt->rt_ifp;
		if (sro6.ro_rt->rt_rmx.rmx_mtu == 0)
			maxmtu = IN6_LINKMTU(sro6.ro_rt->rt_ifp);
		else
			maxmtu = min(sro6.ro_rt->rt_rmx.rmx_mtu,
				     IN6_LINKMTU(sro6.ro_rt->rt_ifp));

		/* Report additional interface capabilities. */
		if (flags != NULL) {
			if (ifp->if_capenable & IFCAP_TSO6 &&
			    ifp->if_hwassist & CSUM_TSO)
				*flags |= CSUM_TSO;
		}
		RTFREE(sro6.ro_rt);
	}
#endif
	return (maxmtu);
}
#endif /* INET6 */

#ifdef IPSEC
/* compute ESP/AH header size for TCP, including outer IP header. */
size_t
ipsec_hdrsiz_tcp(struct tcpcb *tp)
{
	struct inpcb *inp;
	odp_packet_t m;
	size_t hdrsiz;
	struct ofp_ip *ip;
#ifdef _INET6
	struct ip6_hdr *ip6;
#endif
	struct ofp_tcphdr *th;

	if ((tp == NULL) || ((inp = tp->t_inpcb) == NULL))
		return (0);
	MGETHDR(m, M_DONTWAIT, MT_DATA);
	if (!m)
		return (0);

#ifdef _INET6
	if ((inp->inp_vflag & INP_IPV6) != 0) {
		ip6 = (struct ip6_hdr *)odp_packet_data(m);
		th = (struct ofp_tcphdr *)(ip6 + 1);
		odp_packet_get_len(m) = odp_packet_get_len(m) =
			sizeof(struct ip6_hdr) + sizeof(struct ofp_tcphdr);
		ofp_tcpip_fillheaders(inp, ip6, th);
		hdrsiz = ipsec_hdrsiz(m, IPSEC_DIR_OUTBOUND, inp);
	} else
#endif /* INET6 */
	{
		ip = (struct ofp_ip *)odp_packet_data(m);
		th = (struct ofp_tcphdr *)(ip + 1);
		odp_packet_get_len(m) = odp_packet_get_len(m) = sizeof(struct tcpiphdr);
		ofp_tcpip_fillheaders(inp, ip, th);
		hdrsiz = ipsec_hdrsiz(m, IPSEC_DIR_OUTBOUND, inp);
	}

	m_free(m);
	return (hdrsiz);
}
#endif /* IPSEC */

#ifdef TCP_SIGNATURE
/*
 * Callback function invoked by m_apply() to digest TCP segment data
 * contained within an mbuf chain.
 */
static int
tcp_signature_apply(void *fstate, void *data, uint32_t len)
{

	ofp_MD5Update(fstate, (uint8_t *)data, len);
	return (0);
}

/*
 * Compute TCP-MD5 hash of a TCP segment. (RFC2385)
 *
 * Parameters:
 * m		pointer to head of mbuf chain
 * _unused
 * len		length of TCP segment data, excluding options
 * optlen	length of TCP segment options
 * buf		pointer to storage for computed MD5 digest
 * direction	direction of flow (IPSEC_DIR_INBOUND or OUTBOUND)
 *
 * We do this over ip, tcphdr, segment data, and the key in the SADB.
 * When called from ofp_tcp_input(), we can be sure that th_sum has been
 * zeroed out and verified already.
 *
 * Return 0 if successful, otherwise return -1.
 *
 * XXX The key is retrieved from the system's OFP_PF_KEY SADB, by keying a
 * search with the destination IP address, and a 'magic SPI' to be
 * determined by the application. This is hardcoded elsewhere to 1179
 * right now. Another branch of this code exists which uses the SPD to
 * specify per-application flows but it is unstable.
 */
int
tcp_signature_compute(odp_packet_t m, int _unused, int len, int optlen,
    uint8_t *buf, uint32_t direction)
{
	union sockaddr_union dst;
#ifdef INET
	struct ofp_ippseudo ippseudo;
#endif
	MD5_CTX ctx;
	int doff;
	struct ofp_ip *ip;
#ifdef INET
	struct ipovly *ipovly;
#endif
	struct secasvar *sav;
	struct ofp_tcphdr *th;
#ifdef INET6
	struct ofp_ip6_hdr *ip6;
	struct ofp_in6_addr in6;
	char ip6buf[INET6_ADDRSTRLEN];
	uint32_t plen;
	uint16_t nhdr;
#endif
	uint16_t savecsum;

	KASSERT(m != NULL, ("NULL mbuf chain"));
	KASSERT(buf != NULL, ("NULL signature pointer"));

	/* Extract the destination from the IP header in the mbuf. */
	bzero(&dst, sizeof(union sockaddr_union));
	ip = (struct ofp_ip *)odp_packet_data(m);
#ifdef INET6
	ip6 = NULL;	/* Make the compiler happy. */
#endif
	switch (ip->ip_v) {
#ifdef INET
	case IPVERSION:
		dst.sa.sa_len = sizeof(struct ofp_sockaddr_in);
		dst.sa.sa_family = OFP_AF_INET;
		dst.sin.sin_addr = (direction == IPSEC_DIR_INBOUND) ?
		    ip->ip_src : ip->ip_dst;
		break;
#endif
#ifdef INET6
	case (OFP_IPV6_VERSION >> 4):
		ip6 = (struct ofp_ip6_hdr *)odp_packet_data(m);
		dst.sa.sa_len = sizeof(struct ofp_sockaddr_in6);
		dst.sa.sa_family = OFP_AF_INET6;
		dst.sin6.sin6_addr = (direction == IPSEC_DIR_INBOUND) ?
		    ip6->ip6_src : ip6->ip6_dst;
		break;
#endif
	default:
		return (OFP_EINVAL);
		/* NOTREACHED */
		break;
	}

	/* Look up an SADB entry which matches the address of the peer. */
	sav = KEY_ALLOCSA(&dst, OFP_IPPROTO_TCP, odp_cpu_to_be_32(TCP_SIG_SPI));
	if (sav == NULL) {
		ipseclog((LOG_ERR, "%s: SADB lookup failed for %s\n", __func__,
		    (ip->ip_v == IPVERSION) ? ofp_inet_ntoa(dst.sin.sin_addr) :
#ifdef _INET6
			(ip->ip_v == (IPV6_VERSION >> 4)) ?
			    ip6_sprintf(ip6buf, &dst.sin6.sin6_addr) :
#endif
			"(unsupported)"));
		return (OFP_EINVAL);
	}

	ofp_MD5Init(&ctx);
	/*
	 * Step 1: Update MD5 hash with IP(v6) pseudo-header.
	 *
	 * XXX The ippseudo header MUST be digested in network byte order,
	 * or else we'll fail the regression test. Assume all fields we've
	 * been doing arithmetic on have been in host byte order.
	 * XXX One cannot depend on ipovly->ih_len here. When called from
	 * ofp_tcp_output(), the underlying ip_len member has not yet been set.
	 */
	switch (ip->ip_v) {
#ifdef INET
	case IPVERSION:
		ipovly = (struct ipovly *)ip;
		ippseudo.ippseudo_src = ipovly->ih_src;
		ippseudo.ippseudo_dst = ipovly->ih_dst;
		ippseudo.ippseudo_pad = 0;
		ippseudo.ippseudo_p = OFP_IPPROTO_TCP;
		ippseudo.ippseudo_len = odp_cpu_to_be_16(len + sizeof(struct ofp_tcphdr) +
		    optlen);
		ofp_MD5Update(&ctx, (char *)&ippseudo, sizeof(struct ofp_ippseudo));

		th = (struct ofp_tcphdr *)((uint8_t *)ip + sizeof(struct ofp_ip));
		doff = sizeof(struct ofp_ip) + sizeof(struct ofp_tcphdr) + optlen;
		break;
#endif
#ifdef _INET6
	/*
	 * RFC 2385, 2.0  Proposal
	 * For IPv6, the pseudo-header is as described in RFC 2460, namely the
	 * 128-bit source IPv6 address, 128-bit destination IPv6 address, zero-
	 * extended next header value (to form 32 bits), and 32-bit segment
	 * length.
	 * Note: Upper-Layer Packet Length comes before Next Header.
	 */
	case (IPV6_VERSION >> 4):
		in6 = ip6->ip6_src;
		in6_clearscope(&in6);
		ofp_MD5Update(&ctx, (char *)&in6, sizeof(struct ofp_in6_addr));
		in6 = ip6->ip6_dst;
		in6_clearscope(&in6);
		ofp_MD5Update(&ctx, (char *)&in6, sizeof(struct ofp_in6_addr));
		plen = odp_cpu_to_be_32(len + sizeof(struct ofp_tcphdr) + optlen);
		ofp_MD5Update(&ctx, (char *)&plen, sizeof(uint32_t));
		nhdr = 0;
		ofp_MD5Update(&ctx, (char *)&nhdr, sizeof(uint8_t));
		ofp_MD5Update(&ctx, (char *)&nhdr, sizeof(uint8_t));
		ofp_MD5Update(&ctx, (char *)&nhdr, sizeof(uint8_t));
		nhdr = OFP_IPPROTO_TCP;
		ofp_MD5Update(&ctx, (char *)&nhdr, sizeof(uint8_t));

		th = (struct ofp_tcphdr *)((uint8_t *)ip6 + sizeof(struct ip6_hdr));
		doff = sizeof(struct ip6_hdr) + sizeof(struct ofp_tcphdr) + optlen;
		break;
#endif
	default:
		return (OFP_EINVAL);
		/* NOTREACHED */
		break;
	}


	/*
	 * Step 2: Update MD5 hash with TCP header, excluding options.
	 * The TCP checksum must be set to zero.
	 */
	savecsum = th->th_sum;
	th->th_sum = 0;
	ofp_MD5Update(&ctx, (char *)th, sizeof(struct ofp_tcphdr));
	th->th_sum = savecsum;

	/*
	 * Step 3: Update MD5 hash with TCP segment data.
	 *         Use m_apply() to avoid an early odp_packet_ensure_contiguous().
	 */
	if (len > 0)
		m_apply(m, doff, len, tcp_signature_apply, &ctx);

	/*
	 * Step 4: Update MD5 hash with shared secret.
	 */
	ofp_MD5Update(&ctx, sav->key_auth->key_data, _KEYLEN(sav->key_auth));
	ofp_MD5Final(buf, &ctx);

	key_sa_recordxfer(sav, m);
	KEY_FREESAV(&sav);
	return (0);
}

/*
 * Verify the TCP-MD5 hash of a TCP segment. (RFC2385)
 *
 * Parameters:
 * m		pointer to head of mbuf chain
 * len		length of TCP segment data, excluding options
 * optlen	length of TCP segment options
 * buf		pointer to storage for computed MD5 digest
 * direction	direction of flow (IPSEC_DIR_INBOUND or OUTBOUND)
 *
 * Return 1 if successful, otherwise return 0.
 */
int
tcp_signature_verify(odp_packet_t m, int off0, int tlen, int optlen,
    struct tcpopt *to, struct ofp_tcphdr *th, uint32_t tcpbflag)
{
	char tmpdigest[TCP_SIGLEN];

	if (tcp_sig_checksigs == 0)
		return (1);
	if ((tcpbflag & TF_SIGNATURE) == 0) {
		if ((to->to_flags & TOF_SIGNATURE) != 0) {

			/*
			 * If this socket is not expecting signature but
			 * the segment contains signature just fail.
			 */
			TCPSTAT_INC(tcps_sig_err_sigopt);
			TCPSTAT_INC(tcps_sig_rcvbadsig);
			return (0);
		}

		/* Signature is not expected, and not present in segment. */
		return (1);
	}

	/*
	 * If this socket is expecting signature but the segment does not
	 * contain any just fail.
	 */
	if ((to->to_flags & TOF_SIGNATURE) == 0) {
		TCPSTAT_INC(tcps_sig_err_nosigopt);
		TCPSTAT_INC(tcps_sig_rcvbadsig);
		return (0);
	}
	if (tcp_signature_compute(m, off0, tlen, optlen, &tmpdigest[0],
	    IPSEC_DIR_INBOUND) == -1) {
		TCPSTAT_INC(tcps_sig_err_buildsig);
		TCPSTAT_INC(tcps_sig_rcvbadsig);
		return (0);
	}

	if (bcmp(to->to_signature, &tmpdigest[0], TCP_SIGLEN) != 0) {
		TCPSTAT_INC(tcps_sig_rcvbadsig);
		return (0);
	}
	TCPSTAT_INC(tcps_sig_rcvgoodsig);
	return (1);
}
#endif /* TCP_SIGNATURE */

#if 0 /* HJo */
static int
sysctl_drop(OFP_SYSCTL_HANDLER_ARGS)
{
	/* addrs[0] is a foreign socket, addrs[1] is a local one. */
	struct sockaddr_storage addrs[2];
	struct inpcb *inp;
	struct tcpcb *tp;
	struct tcptw *tw;
	struct ofp_sockaddr_in *fin, *lin;
#ifdef _INET6
	struct ofp_sockaddr_in6 *fin6, *lin6;
#endif
	int error;

	inp = NULL;
	fin = lin = NULL;
#ifdef _INET6
	fin6 = lin6 = NULL;
#endif
	error = 0;

	if (req->oldptr != NULL || req->oldlen != 0)
		return (OFP_EINVAL);
	if (req->newptr == NULL)
		return (OFP_EPERM);
	if (req->newlen < sizeof(addrs))
		return (OFP_ENOMEM);
	error = SYSCTL_IN(req, &addrs, sizeof(addrs));
	if (error)
		return (error);

	switch (addrs[0].ss_family) {
#ifdef _INET6
	case OFP_AF_INET6:
		fin6 = (struct ofp_sockaddr_in6 *)&addrs[0];
		lin6 = (struct ofp_sockaddr_in6 *)&addrs[1];
		if (fin6->sin6_len != sizeof(struct ofp_sockaddr_in6) ||
		    lin6->sin6_len != sizeof(struct ofp_sockaddr_in6))
			return (OFP_EINVAL);
		if (IN6_IS_ADDR_V4MAPPED(&fin6->sin6_addr)) {
			if (!IN6_IS_ADDR_V4MAPPED(&lin6->sin6_addr))
				return (OFP_EINVAL);
			in6_sin6_2_sin_in_sock((struct ofp_sockaddr *)&addrs[0]);
			in6_sin6_2_sin_in_sock((struct ofp_sockaddr *)&addrs[1]);
			fin = (struct ofp_sockaddr_in *)&addrs[0];
			lin = (struct ofp_sockaddr_in *)&addrs[1];
			break;
		}
		error = sa6_embedscope(fin6, V_ip6_use_defzone);
		if (error)
			return (error);
		error = sa6_embedscope(lin6, V_ip6_use_defzone);
		if (error)
			return (error);
		break;
#endif
#ifdef INET
	case OFP_AF_INET:
		fin = (struct ofp_sockaddr_in *)&addrs[0];
		lin = (struct ofp_sockaddr_in *)&addrs[1];
		if (fin->sin_len != sizeof(struct ofp_sockaddr_in) ||
		    lin->sin_len != sizeof(struct ofp_sockaddr_in))
			return (OFP_EINVAL);
		break;
#endif
	default:
		return (OFP_EINVAL);
	}
	INP_INFO_WLOCK(&V_tcbinfo);
	switch (addrs[0].ss_family) {
#ifdef _INET6
	case OFP_AF_INET6:
		inp = in6_pcblookup(&V_tcbinfo, &fin6->sin6_addr,
		    fin6->sin6_port, &lin6->sin6_addr, lin6->sin6_port,
		    INPLOOKUP_WLOCKPCB, NULL);
		break;
#endif
#ifdef INET
	case OFP_AF_INET:
		inp = ofp_in_pcblookup(&V_tcbinfo, fin->sin_addr, fin->sin_port,
		    lin->sin_addr, lin->sin_port, INPLOOKUP_WLOCKPCB, NULL);
		break;
#endif
	}
	if (inp != NULL) {
		if (inp->inp_flags & INP_TIMEWAIT) {
			/*
			 * XXXRW: There currently exists a state where an
			 * inpcb is present, but its timewait state has been
			 * discarded.  For now, don't allow dropping of this
			 * type of inpcb.
			 */
			tw = intotw(inp);
			if (tw != NULL)
				ofp_tcp_twclose(tw, 0);
			else
				INP_WUNLOCK(inp);
		} else if (!(inp->inp_flags & INP_DROPPED) &&
			   !(inp->inp_socket->so_options & OFP_SO_ACCEPTCONN)) {
			tp = intotcpcb(inp);
			tp = ofp_tcp_drop(tp, OFP_ECONNABORTED);
			if (tp != NULL)
				INP_WUNLOCK(inp);
		} else
			INP_WUNLOCK(inp);
	} else
		error = OFP_ESRCH;
	INP_INFO_WUNLOCK(&V_tcbinfo);
	return (error);
}

OFP_SYSCTL_PROC(_net_inet_tcp, TCPCTL_DROP, drop,
    OFP_CTLTYPE_STRUCT|OFP_CTLFLAG_WR|OFP_CTLFLAG_SKIP, NULL,
    0, sysctl_drop, "", "Drop TCP connection");
#endif /* HJo */

/*
 * Generate a standardized TCP log line for use throughout the
 * tcp subsystem.  Memory allocation is done with M_NOWAIT to
 * allow use in the interrupt context.
 *
 * NB: The caller MUST free(s, M_TCPLOG) the returned string.
 * NB: The function may return NULL if memory allocation failed.
 *
 * Due to header inclusion and ordering limitations the struct ip
 * and ip6_hdr pointers have to be passed as void pointers.
 */
char *
ofp_tcp_log_vain(struct in_conninfo *inc, struct ofp_tcphdr *th, void *ip4hdr,
    const void *ip6hdr)
{

	/* Is logging enabled? */
	if (ofp_tcp_log_in_vain == 0)
		return (NULL);

	return (tcp_log_addr(inc, th, ip4hdr, ip6hdr));
}

char *
ofp_tcp_log_addrs(struct in_conninfo *inc, struct ofp_tcphdr *th, void *ip4hdr,
    const void *ip6hdr)
{

	/* Is logging enabled? */
	if (tcp_log_debug == 0)
		return (NULL);

	return (tcp_log_addr(inc, th, ip4hdr, ip6hdr));
}

char *ofp_inet_ntoa(struct ofp_in_addr ina);
char *ofp_inet_ntoa_r(struct ofp_in_addr ina, char *buf);

char *
ofp_inet_ntoa(struct ofp_in_addr ina)
{
	static char buf[4*sizeof "123"];
	unsigned char *ucp = (unsigned char *)&ina;

	sprintf(buf, "%d.%d.%d.%d",
		ucp[0] & 0xff,
		ucp[1] & 0xff,
		ucp[2] & 0xff,
		ucp[3] & 0xff);
	return buf;
}

char *
ofp_inet_ntoa_r(struct ofp_in_addr ina, char *buf)
{
	unsigned char *ucp = (unsigned char *)&ina;

	sprintf(buf, "%d.%d.%d.%d",
		ucp[0] & 0xff,
		ucp[1] & 0xff,
		ucp[2] & 0xff,
		ucp[3] & 0xff);
	return buf;
}

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"
#pragma GCC diagnostic ignored "-Wcast-qual"
static char *
tcp_log_addr(struct in_conninfo *inc, struct ofp_tcphdr *th, void *ip4hdr,
    const void *ip6hdr)
{
	char *s, *sp;
	size_t size;
	struct ofp_ip *ip;
#ifdef INET6
	struct ofp_ip6_hdr *ip6;

	ip6 = (struct ofp_ip6_hdr *)ip6hdr;
#else
	(void)ip6hdr;
#endif /* INET6 */
	ip = (struct ofp_ip *)ip4hdr;
	(void)ip;

	/*
	 * The log line looks like this:
	 * "TCP: [1.2.3.4]:50332 to [1.2.3.4]:80 tcpflags 0x2<SYN>"
	 */
	size = sizeof("TCP: []:12345 to []:12345 tcpflags 0x2<>") +
	    sizeof(OFP_PRINT_TH_FLAGS) + 1 +
#ifdef INET6
	    2 * OFP_INET6_ADDRSTRLEN;
#else
	    2 * OFP_INET_ADDRSTRLEN;
#endif /* INET6 */

	s = malloc(size);
	if (s == NULL)
		return (NULL);

	strcat(s, "TCP: [");
	sp = s + strlen(s);

	if (inc && ((inc->inc_flags & INC_ISIPV6) == 0)) {
		ofp_inet_ntoa_r(inc->inc_faddr, sp);
		sp = s + strlen(s);
		sprintf(sp, "]:%i to [", odp_be_to_cpu_16(inc->inc_fport));
		sp = s + strlen(s);
		ofp_inet_ntoa_r(inc->inc_laddr, sp);
		sp = s + strlen(s);
		sprintf(sp, "]:%i", odp_be_to_cpu_16(inc->inc_lport));
#ifdef INET6
	} else if (inc) {
		sprintf(sp, "%s", ofp_print_ip6_addr((uint8_t *)&inc->inc6_faddr));
		sp = s + strlen(s);
		sprintf(sp, "]:%i to [", odp_be_to_cpu_16(inc->inc_fport));
		sp = s + strlen(s);
		sprintf(sp, "%s", ofp_print_ip6_addr((uint8_t *)&inc->inc6_laddr));
		sp = s + strlen(s);
		sprintf(sp, "]:%i", odp_be_to_cpu_16(inc->inc_lport));
	} else if (ip6 && th) {
		sprintf(sp, "%s", ofp_print_ip6_addr((uint8_t *)&ip6->ip6_src));
		sp = s + strlen(s);
		sprintf(sp, "]:%i to [", odp_be_to_cpu_16(th->th_sport));
		sp = s + strlen(s);
		sprintf(sp, "%s", ofp_print_ip6_addr((uint8_t *)&ip6->ip6_dst));
		sp = s + strlen(s);
		sprintf(sp, "]:%i", odp_be_to_cpu_16(th->th_dport));
#endif /* INET6 */
#ifdef INET
	} else if (ip && th) {
		ofp_inet_ntoa_r(ip->ip_src, sp);
		sp = s + strlen(s);
		sprintf(sp, "]:%i to [", odp_be_to_cpu_16(th->th_sport));
		sp = s + strlen(s);
		ofp_inet_ntoa_r(ip->ip_dst, sp);
		sp = s + strlen(s);
		sprintf(sp, "]:%i", odp_be_to_cpu_16(th->th_dport));
#endif /* INET */
	} else {
		free(s);
		return (NULL);
	}
	sp = s + strlen(s);
	if (th)
		sprintf(sp, " tcpflags 0x%b", th->th_flags, OFP_PRINT_TH_FLAGS);
	if (*(s + size - 1) != '\0')
		panic("string too long");
	return (s);
}
#pragma GCC diagnostic error "-Wformat"
#pragma GCC diagnostic error "-Wformat-extra-args"
#pragma GCC diagnostic warning "-Wcast-qual"
