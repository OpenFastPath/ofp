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

#include "odp.h"

#include "ofpi_pkt_processing.h"
#include "ofpi_errno.h"
#include "ofpi_sysctl.h"
#include "ofpi_socketvar.h"
#include "ofpi_sockstate.h"
#include "ofpi_protosw.h"
#include "ofpi_in.h"
#include "ofpi_in_pcb.h"
#include "ofpi_ip.h"
#include "ofpi_tcp.h"
#include "ofpi_tcp_fsm.h"
#include "ofpi_tcp_seq.h"
#include "ofpi_tcp_timer.h"
#include "ofpi_tcp_var.h"
#include "ofpi_tcp_shm.h"
#ifdef INET6
#include "ofpi_ip6.h"
#include "ofpi_ip6_var.h"
#include "ofpi_tcp6_var.h"
#endif /*INET6*/
#ifdef TCPDEBUG
#include <netinet/tcp_debug.h>
#endif
#include "ofpi_tcp_shm.h"

static int	maxtcptw;

/*
 * The timed wait queue contains references to each of the TCP sessions
 * currently in the TIME_WAIT state.  The queue pointers, including the
 * queue pointers in each tcptw structure, are protected using the global
 * ofp_tcbinfo lock, which must be held over queue iteration and modification.
 */

static void	tcp_tw_2msl_reset(struct tcptw *, int);
static void	tcp_tw_2msl_stop(struct tcptw *);

static int
tcptw_auto_size(void)
{
#ifdef OFP_TCP_MAX_CONNECTION_RATE
	return OFP_NUM_PCB_TCP_MAX;
#else
	int halfrange;

	/*
	 * Max out at half the ephemeral port range so that TIME_WAIT
	 * sockets don't tie up too many ephemeral ports.
	 */
	if (V_ipport_lastauto > V_ipport_firstauto)
		halfrange = (V_ipport_lastauto - V_ipport_firstauto) / 2;
	else
		halfrange = (V_ipport_firstauto - V_ipport_lastauto) / 2;
	/* Protect against goofy port ranges smaller than 32. */
	return (imin(imax(halfrange, 32), OFP_NUM_PCB_TCP_MAX / 5));
#endif /* OFP_TCP_MAX_CONNECTION_RATE*/
}

static int
sysctl_maxtcptw(OFP_SYSCTL_HANDLER_ARGS)
{
	int error, new;
	(void)arg1;
	(void)arg2;

	if (maxtcptw == 0)
		new = tcptw_auto_size();
	else
		new = maxtcptw;
	error = sysctl_handle_int(oidp, &new, 0, req);
	if (error == 0 && req->newptr)
		if (new >= 32) {
			maxtcptw = new;
			uma_zone_set_max(V_tcptw_zone, maxtcptw);
		}
	return (error);
}

OFP_SYSCTL_PROC(_net_inet_tcp, OFP_OID_AUTO, maxtcptw, OFP_CTLTYPE_INT|OFP_CTLFLAG_RW,
    &maxtcptw, 0, sysctl_maxtcptw, "IU",
    "Maximum number of compressed TCP TIME_WAIT entries");

VNET_DEFINE(int, ofp_nolocaltimewait) = 0;
#define	V_nolocaltimewait	VNET(ofp_nolocaltimewait)
OFP_SYSCTL_INT(_net_inet_tcp, OFP_OID_AUTO, nolocaltimewait, OFP_CTLFLAG_RW,
	   &ofp_nolocaltimewait, 0,
	   "Do not create compressed TCP TIME_WAIT entries for local connections");

void
ofp_tcp_tw_zone_change(void)
{
	/* HJo
	if (maxtcptw == 0)
		uma_zone_set_max(V_tcptw_zone, tcptw_auto_size());
	*/
}

void
ofp_tcp_tw_init(void)
{
	V_tcptw_zone = uma_zcreate(
		"tcptw", tcptw_auto_size(), sizeof(struct tcptw),
		NULL, NULL, NULL, NULL, UMA_ALIGN_PTR, UMA_ZONE_NOFREE);
	/* TUNABLE_INT_FETCH("net.inet.tcp.maxtcptw", &maxtcptw); */
	if (maxtcptw == 0) {
		uma_zone_set_max(V_tcptw_zone, tcptw_auto_size());
	} else {
		uma_zone_set_max(V_tcptw_zone, maxtcptw);
	}

#ifdef OFP_RSS
	int32_t cpu_id = 0;
	for (; cpu_id < odp_cpu_count() ; cpu_id++)
		OFP_TAILQ_INIT(&shm_tcp->twq_2msl[cpu_id]);
#else
	OFP_TAILQ_INIT(&V_twq_2msl);
#endif
}


/*
 * Move a TCP connection into TIME_WAIT state.
 *    ofp_tcbinfo is locked.
 *    inp is locked, and is unlocked before returning.
 */
void
ofp_tcp_twstart(struct tcpcb *tp)
{
	struct tcptw *tw;
	struct inpcb *inp = tp->t_inpcb;
	int acknow;
	struct socket *so;
#ifdef INET6
	int isipv6 = inp->inp_inc.inc_flags & INC_ISIPV6;
#endif

	INP_INFO_WLOCK_ASSERT(&V_tcbinfo);	/* tcp_tw_2msl_reset(). */
	INP_WLOCK_ASSERT(inp);

	if (V_nolocaltimewait) {
		int error = 0;
#ifdef INET6
		if (isipv6)
			error = 0 /*in6_localaddr(&inp->in6p_faddr)*/;
		else
#endif
			error = 0 /* HJo: FIX in_localip(inp->inp_faddr)*/;

		if (error) {
			tp = ofp_tcp_close(tp);
			if (tp != NULL)
				INP_WUNLOCK(inp);
			return;
		}
	}

	tw = uma_zalloc(V_tcptw_zone, M_NOWAIT);
	if (tw == NULL) {
		tw = ofp_tcp_tw_2msl_scan(1);
		if (tw == NULL) {
			tp = ofp_tcp_close(tp);
			if (tp != NULL)
				INP_WUNLOCK(inp);
			return;
		}
	}
	tw->tw_inpcb = inp;

	/*
	 * Recover last window size sent.
	 */
	if (SEQ_GT(tp->rcv_adv, tp->rcv_nxt))
		tw->last_win = (tp->rcv_adv - tp->rcv_nxt) >> tp->rcv_scale;
	else
		tw->last_win = 0;

	/*
	 * Set t_recent if timestamps are used on the connection.
	 */
	if ((tp->t_flags & (TF_REQ_TSTMP|TF_RCVD_TSTMP|TF_NOOPT)) ==
	    (TF_REQ_TSTMP|TF_RCVD_TSTMP)) {
		tw->t_recent = tp->ts_recent;
		tw->ts_offset = tp->ts_offset;
	} else {
		tw->t_recent = 0;
		tw->ts_offset = 0;
	}

	tw->snd_nxt = tp->snd_nxt;
	tw->rcv_nxt = tp->rcv_nxt;
	tw->iss     = tp->iss;
	tw->irs     = tp->irs;
	tw->t_starttime = tp->t_starttime;
	tw->tw_time = 0;

/* XXX
 * If this code will
 * be used for fin-wait-2 state also, then we may need
 * a ts_recent from the last segment.
 */
	acknow = tp->t_flags & TF_ACKNOW;

	/*
	 * First, discard tcpcb state, which includes stopping its timers and
	 * freeing it.  ofp_tcp_discardcb() used to also release the inpcb, but
	 * that work is now done in the caller.
	 *
	 * Note: ofp_soisdisconnected() call used to be made in ofp_tcp_discardcb(),
	 * and might not be needed here any longer.
	 */
	ofp_tcp_discardcb(tp);
	so = inp->inp_socket;
	ofp_soisdisconnected(so);
	/* HJo tw->tw_cred = crhold(so->so_cred);*/
	OFP_SOCK_LOCK(so);
	tw->tw_so_options = so->so_options;
	OFP_SOCK_UNLOCK(so);
	if (acknow)
		ofp_tcp_twrespond(tw, OFP_TH_ACK);
	inp->inp_ppcb = tw;
	inp->inp_flags |= INP_TIMEWAIT;
	tcp_tw_2msl_reset(tw, 0);

	/*
	 * If the inpcb owns the sole reference to the socket, then we can
	 * detach and free the socket as it is not needed in time wait.
	 */
	if (inp->inp_flags & INP_SOCKREF) {
		KASSERT(so->so_state & SS_PROTOREF,
		    ("ofp_tcp_twstart: !SS_PROTOREF"));
		inp->inp_flags &= ~INP_SOCKREF;
		INP_WUNLOCK(inp);
		ACCEPT_LOCK();
		OFP_SOCK_LOCK(so);
		so->so_state &= ~SS_PROTOREF;
		ofp_sofree(so);
	} else
		INP_WUNLOCK(inp);
}


/*
 * Returns 1 if the TIME_WAIT state was killed and we should start over,
 * looking for a pcb in the listen state.  Returns 0 otherwise.
 */
int
ofp_tcp_twcheck(struct inpcb *inp, struct tcpopt *to, struct ofp_tcphdr *th,
    odp_packet_t m, int tlen)
{
	struct tcptw *tw;
	int thflags;
	tcp_seq seq;
	(void)to;

	/* ofp_tcbinfo lock required for ofp_tcp_twclose(), tcp_tw_2msl_reset(). */
	INP_INFO_WLOCK_ASSERT(&V_tcbinfo);
	INP_WLOCK_ASSERT(inp);

	/*
	 * XXXRW: Time wait state for inpcb has been recycled, but inpcb is
	 * still present.  This is undesirable, but temporarily necessary
	 * until we work out how to handle inpcb's who's timewait state has
	 * been removed.
	 */
	tw = intotw(inp);
	if (tw == NULL)
		goto drop;

	thflags = th->th_flags;

	/*
	 * NOTE: for FIN_WAIT_2 (to be added later),
	 * must validate sequence number before accepting RST
	 */

	/*
	 * If the segment contains RST:
	 *	Drop the segment - see Stevens, vol. 2, p. 964 and
	 *      RFC 1337.
	 */
	if (thflags & OFP_TH_RST)
		goto drop;

	/*
	 * If a new connection request is received
	 * while in TIME_WAIT, drop the old connection
	 * and start over if the sequence numbers
	 * are above the previous ones.
	 */
	if ((thflags & OFP_TH_SYN) && SEQ_GT(th->th_seq, tw->rcv_nxt)) {
		ofp_tcp_twclose(tw, 0);
		return (1);
	}

	/*
	 * Drop the segment if it does not contain an ACK.
	 */
	if ((thflags & OFP_TH_ACK) == 0)
		goto drop;

	/*
	 * Reset the 2MSL timer if this is a duplicate FIN.
	 */
	if (thflags & OFP_TH_FIN) {
		seq = th->th_seq + tlen + (thflags & OFP_TH_SYN ? 1 : 0);
		if (seq + 1 == tw->rcv_nxt)
			tcp_tw_2msl_reset(tw, 1);
	}

	/*
	 * Acknowledge segments with control flags and no data.
	 */
	if (thflags != OFP_TH_ACK || tlen == 0 ||
	    th->th_seq != tw->rcv_nxt || th->th_ack != tw->snd_nxt)
		ofp_tcp_twrespond(tw, OFP_TH_ACK);
drop:
	INP_WUNLOCK(inp);
	odp_packet_free(m);
	return (0);
}

void
ofp_tcp_twclose(struct tcptw *tw, int reuse)
{
	struct socket *so;
	struct inpcb *inp;

	/*
	 * At this point, we are in one of two situations:
	 *
	 * (1) We have no socket, just an inpcb<->twtcp pair.  We can free
	 *     all state.
	 *
	 * (2) We have a socket -- if we own a reference, release it and
	 *     notify the socket layer.
	 */
	inp = tw->tw_inpcb;
	KASSERT((inp->inp_flags & INP_TIMEWAIT), ("ofp_tcp_twclose: !timewait"));
	KASSERT(intotw(inp) == tw, ("ofp_tcp_twclose: inp_ppcb != tw"));
	INP_INFO_WLOCK_ASSERT(&V_tcbinfo);	/* tcp_tw_2msl_stop(). */
	INP_WLOCK_ASSERT(inp);

	tw->tw_inpcb = NULL;
	tcp_tw_2msl_stop(tw);
	inp->inp_ppcb = NULL;
	ofp_in_pcbdrop(inp);

	so = inp->inp_socket;
	if (so != NULL) {
		/*
		 * If there's a socket, handle two cases: first, we own a
		 * strong reference, which we will now release, or we don't
		 * in which case another reference exists (XXXRW: think
		 * about this more), and we don't need to take action.
		 */
		if (inp->inp_flags & INP_SOCKREF) {
			inp->inp_flags &= ~INP_SOCKREF;
			INP_WUNLOCK(inp);
			ACCEPT_LOCK();
			OFP_SOCK_LOCK(so);
			KASSERT(so->so_state & SS_PROTOREF,
			    ("ofp_tcp_twclose: INP_SOCKREF && !SS_PROTOREF"));
			so->so_state &= ~SS_PROTOREF;
			ofp_sofree(so);
		} else {
			/*
			 * If we don't own the only reference, the socket and
			 * inpcb need to be left around to be handled by
			 * tcp_usr_detach() later.
			 */
			INP_WUNLOCK(inp);
		}
	} else
		ofp_in_pcbfree(inp);
	TCPSTAT_INC(tcps_closed);
	/* crfree(tw->tw_cred);*/
	tw->tw_cred = NULL;
	if (reuse)
		return;
	uma_zfree(V_tcptw_zone, tw);
}

int
ofp_tcp_twrespond(struct tcptw *tw, int flags)
{
	struct inpcb *inp = tw->tw_inpcb;
	struct ofp_tcphdr *th = NULL;

	odp_packet_t m;
	struct ofp_ip *ip = NULL;
	uint32_t hdrlen, optlen;
	int error = 0;			/* Keep compiler happy */
	struct tcpopt to;
#ifdef INET6
	struct ofp_ip6_hdr *ip6 = NULL;
	int isipv6 = inp->inp_inc.inc_flags & INC_ISIPV6;
#endif

	INP_WLOCK_ASSERT(inp);

#ifdef INET6
	if (isipv6) {
		hdrlen = sizeof(struct ofp_ip6_hdr) + sizeof(struct ofp_tcphdr);

		m = ofp_packet_alloc(hdrlen);

		if (m == ODP_PACKET_INVALID)
			return (OFP_ENOBUFS);

		odp_packet_l3_offset_set(m, 0);
		odp_packet_l4_offset_set(m, sizeof(struct ofp_ip6_hdr));

		ip6 = (struct ofp_ip6_hdr *)odp_packet_data(m);
		th = (struct ofp_tcphdr *)(ip6 + 1);
		ofp_tcpip_fillheaders(inp, ip6, th);
	}
	else
#endif
	{
		hdrlen = sizeof(struct tcpiphdr);

		m = ofp_packet_alloc(hdrlen);

		if (m == ODP_PACKET_INVALID)
			return (OFP_ENOBUFS);

		odp_packet_l3_offset_set(m, 0);
		odp_packet_l4_offset_set(m, sizeof(struct ofp_ip));

		ip = (struct ofp_ip *)odp_packet_data(m);
		th = (struct ofp_tcphdr *)(ip + 1);
		ofp_tcpip_fillheaders(inp, ip, th);
	}

	to.to_flags = 0;

	/*
	 * Send a timestamp and echo-reply if both our side and our peer
	 * have sent timestamps in our SYN's and this is not a RST.
	 */
	if (tw->t_recent && flags == OFP_TH_ACK) {
		to.to_flags |= TOF_TS;
		to.to_tsval = tcp_ts_getticks() + tw->ts_offset;
		to.to_tsecr = tw->t_recent;
	}
	optlen = ofp_tcp_addoptions(&to, (uint8_t *)(th + 1));
	/* This is done in wrong order. */
	odp_packet_push_tail(m, optlen);

	th->th_seq = odp_cpu_to_be_32(tw->snd_nxt);
	th->th_ack = odp_cpu_to_be_32(tw->rcv_nxt);
	th->th_off = (sizeof(struct ofp_tcphdr) + optlen) >> 2;
	th->th_flags = flags;
	th->th_win = odp_cpu_to_be_16(tw->last_win);

#ifdef INET6
	if (isipv6) {
		odp_packet_set_csum_flags(m, CSUM_TCP_IPV6);
		th->th_sum = 0;
		th->th_sum = ofp_in6_cksum(m, OFP_IPPROTO_TCP,
			sizeof(struct ofp_ip6_hdr),
			sizeof(struct ofp_tcphdr) + optlen);
		ip6->ofp_ip6_hlim = V_ip6_defhlim;/*in6_selecthlim(inp, NULL);*/
		ip6->ofp_ip6_plen = odp_cpu_to_be_16(odp_packet_len(m) -
			sizeof (struct ofp_ip6_hdr));

		error = ofp_ip6_output(m, NULL);
	}
	else
#endif
	{
		// HJo odp_packet_csum_flags(m) = CSUM_TCP;
		ip->ip_len = odp_cpu_to_be_16(odp_packet_len(m));
		if (V_path_mtu_discovery)
			ip->ip_off |= OFP_IP_DF;

		ip->ip_off = odp_cpu_to_be_16(ip->ip_off);
		ip->ip_sum = 0;
		th->th_sum = 0;
		th->th_sum = ofp_in4_cksum(m);

		error = ofp_ip_output(m, NULL);
	}

	if (flags & OFP_TH_ACK)
		TCPSTAT_INC(tcps_sndacks);
	else
		TCPSTAT_INC(tcps_sndctrl);
	TCPSTAT_INC(tcps_sndtotal);
	return (error);
}

static void
tcp_tw_2msl_reset(struct tcptw *tw, int rearm)
{

	INP_INFO_WLOCK_ASSERT(&V_tcbinfo);
	INP_WLOCK_ASSERT(tw->tw_inpcb);
	if (rearm)
		OFP_TAILQ_REMOVE(&V_twq_2msl, tw, tw_2msl);
	tw->tw_time = ticks + 2 * ofp_tcp_msl;
	OFP_TAILQ_INSERT_TAIL(&V_twq_2msl, tw, tw_2msl);
}

static void
tcp_tw_2msl_stop(struct tcptw *tw)
{

	INP_INFO_WLOCK_ASSERT(&V_tcbinfo);
	OFP_TAILQ_REMOVE(&V_twq_2msl, tw, tw_2msl);
}

struct tcptw *
ofp_tcp_tw_2msl_scan(int reuse)
{
	struct tcptw *tw;

	INP_INFO_WLOCK_ASSERT(&V_tcbinfo);
	for (;;) {
		tw = OFP_TAILQ_FIRST(&V_twq_2msl);
		if (tw == NULL || (!reuse && (tw->tw_time - ticks) > 0))
			break;
		INP_WLOCK(tw->tw_inpcb);
		ofp_tcp_twclose(tw, reuse);
		if (reuse)
			return (tw);
	}
	return (NULL);
}
