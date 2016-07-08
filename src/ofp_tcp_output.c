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
 *	@(#)ofp_tcp_output.c	8.4 (Berkeley) 5/24/95
 */
#include <string.h>
#include <stddef.h>

#include "ofpi_errno.h"
#include "ofpi_protosw.h"
#include "ofpi_sysctl.h"
#include "ofpi_socketvar.h"

#include "ofpi_in.h"
#include "ofpi_ip.h"
#ifdef INET6
#include "ofpi_ip6.h"
#include "ofpi_ip6_var.h"
#endif /* INET6 */
#define	OFP_TCPOUTFLAGS

#include "ofpi_util.h"
#include "ofpi_pkt_processing.h"
#include "ofpi_systm.h"
#include "ofpi_timer.h"
#include "ofpi_tcp.h"
#include "ofpi_tcp_fsm.h"
#include "ofpi_tcp_seq.h"
#include "ofpi_tcp_timer.h"
#include "ofpi_tcp_var.h"
//#include "ofp_tcpip.h"


#ifdef TCPDEBUG
#include <netinet/tcp_debug.h>
#endif

//#include <machine/in_cksum.h>

extern int ofp_max_linkhdr;

VNET_DEFINE(int, ofp_path_mtu_discovery) = 1;
OFP_SYSCTL_INT(_net_inet_tcp, OFP_OID_AUTO, path_mtu_discovery, OFP_CTLFLAG_RW,
	   &ofp_path_mtu_discovery, 1,
	   "Enable Path MTU Discovery");

VNET_DEFINE(int, ofp_ss_fltsz) = 1;
OFP_SYSCTL_INT(_net_inet_tcp, OFP_OID_AUTO, slowstart_flightsize, OFP_CTLFLAG_RW,
	   &ofp_ss_fltsz, 1,
	   "Slow start flight size");

VNET_DEFINE(int, ofp_ss_fltsz_local) = 4;
OFP_SYSCTL_INT(_net_inet_tcp, OFP_OID_AUTO, local_slowstart_flightsize,
	   OFP_CTLFLAG_RW, &ofp_ss_fltsz_local, 1,
	   "Slow start flight size for local networks");

VNET_DEFINE(int, ofp_tcp_do_tso) = 1;
#define	V_tcp_do_tso		VNET(ofp_tcp_do_tso)
OFP_SYSCTL_INT(_net_inet_tcp, OFP_OID_AUTO, tso, OFP_CTLFLAG_RW,
	   &ofp_tcp_do_tso, 0,
	   "Enable TCP Segmentation Offload");

VNET_DEFINE(int, ofp_tcp_do_autosndbuf) = 1;
#define	V_tcp_do_autosndbuf	VNET(ofp_tcp_do_autosndbuf)
OFP_SYSCTL_INT(_net_inet_tcp, OFP_OID_AUTO, sendbuf_auto, OFP_CTLFLAG_RW,
	   &ofp_tcp_do_autosndbuf, 0,
	   "Enable automatic send buffer sizing");

VNET_DEFINE(int, ofp_tcp_autosndbuf_inc) = 8*1024;
#define	V_tcp_autosndbuf_inc	VNET(ofp_tcp_autosndbuf_inc)
OFP_SYSCTL_INT(_net_inet_tcp, OFP_OID_AUTO, sendbuf_inc, OFP_CTLFLAG_RW,
	   &ofp_tcp_autosndbuf_inc, 0,
	   "Incrementor step size of automatic send buffer");

VNET_DEFINE(int, ofp_tcp_autosndbuf_max) = 2*1024*1024;
#define	V_tcp_autosndbuf_max	VNET(ofp_tcp_autosndbuf_max)
OFP_SYSCTL_INT(_net_inet_tcp, OFP_OID_AUTO, sendbuf_max, OFP_CTLFLAG_RW,
	   &ofp_tcp_autosndbuf_max, 0,
	   "Max size of automatic send buffer");

/*
static inline void	hhook_run_tcp_est_out(struct tcpcb *tp,
			    struct ofp_tcphdr *th, struct tcpopt *to,
			    long len, int tso);
*/
static inline void	cc_after_idle(struct tcpcb *tp);

/*
 * Wrapper for the TCP established ouput helper hook.
 */
#if 0
static void inline
hhook_run_tcp_est_out(struct tcpcb *tp, struct ofp_tcphdr *th,
    struct tcpopt *to, long len, int tso)
{
	struct tcp_hhook_data hhook_data;

	if (V_tcp_hhh[HHOOK_TCP_EST_OUT]->hhh_nhooks > 0) {
		hhook_data.tp = tp;
		hhook_data.th = th;
		hhook_data.to = to;
		hhook_data.len = len;
		hhook_data.tso = tso;

		hhook_run_hooks(V_tcp_hhh[HHOOK_TCP_EST_OUT], &hhook_data,
		    tp->osd);
	}
}
#endif
/*
 * CC wrapper hook functions
 */
static inline void
cc_after_idle(struct tcpcb *tp)
{
	(void)tp;
#if 0
	INP_WLOCK_ASSERT(tp->t_inpcb);

	if (CC_ALGO(tp)->after_idle != NULL)
		CC_ALGO(tp)->after_idle(tp->ccv);
#endif
}

/*
 * Tcp output routine: figure out what should be sent and send it.
 */
int
ofp_tcp_output(struct tcpcb *tp)
{
	struct socket *so = tp->t_inpcb->inp_socket;
	long len, recwin, sendwin;
	int off, flags, error = 0;	/* Keep compiler happy */
	odp_packet_t m;
	struct ofp_ip *ip = NULL;
	struct ipovly *ipov = NULL;
	struct ofp_tcphdr *th;
	uint8_t opt[OFP_TCP_MAXOLEN];
	unsigned ipoptlen, optlen, hdrlen;
	int idle, sendalot;
	int sack_rxmit, sack_bytes_rxmt;
	struct sackhole *p;
	int tso;
	struct tcpopt to;

	ipov = ipov;
#if 0
	int maxburst = OFP_TCP_MAXBURST;
#endif
#ifdef INET6
	struct ofp_ip6_hdr *ip6 = NULL;
	int isipv6;

	(void)ipov;

	isipv6 = (tp->t_inpcb->inp_vflag & INP_IPV6) != 0;
#endif
	INP_WLOCK_ASSERT(tp->t_inpcb);

	SOCKBUF_LOCK(&so->so_snd);

	/*
	 * Determine length of data that should be transmitted,
	 * and flags that will be used.
	 * If there is some data or critical controls (SYN, RST)
	 * to send, then transmit; otherwise, investigate further.
	 */
	idle = (tp->t_flags & TF_LASTIDLE) || (tp->snd_max == tp->snd_una);
	if (idle && (int)(ofp_timer_ticks(0) - tp->t_rcvtime) >= tp->t_rxtcur)
		cc_after_idle(tp);
	t_flags_and(tp->t_flags, ~TF_LASTIDLE);
	if (idle) {/* OK */
		if (tp->t_flags & TF_MORETOCOME) {
			t_flags_or(tp->t_flags, TF_LASTIDLE);
			idle = 0;
		}
	}
again:
	/*
	 * If we've recently taken a timeout, snd_max will be greater than
	 * snd_nxt.  There may be SACK information that allows us to avoid
	 * resending already delivered data.  Adjust snd_nxt accordingly.
	 */
	if ((tp->t_flags & TF_SACK_PERMIT) &&
	    SEQ_LT(tp->snd_nxt, tp->snd_max))
		ofp_tcp_sack_adjust(tp);
	sendalot = 0;
	tso = 0;
	off = tp->snd_nxt - tp->snd_una;
#ifndef min
#define min(a, b) ((int64_t)a > (int64_t)b ? (int64_t)b : (int64_t)a)
#endif
	sendwin = min(tp->snd_wnd, tp->snd_cwnd);

	flags = tcp_outflags[tp->t_state];
	/*
	 * Send any SACK-generated retransmissions.  If we're explicitly trying
	 * to send out new data (when sendalot is 1), bypass this function.
	 * If we retransmit in fast recovery mode, decrement snd_cwnd, since
	 * we're replacing a (future) new transmission with a retransmission
	 * now, and we previously incremented snd_cwnd in ofp_tcp_input().
	 */
	/*
	 * Still in sack recovery , reset rxmit flag to zero.
	 */
	sack_rxmit = 0;
	sack_bytes_rxmt = 0;
	len = 0;
	p = NULL;
	if ((tp->t_flags & TF_SACK_PERMIT) && IN_FASTRECOVERY(tp->t_flags) &&
	    (p = ofp_tcp_sack_output(tp, &sack_bytes_rxmt))) {
		long cwin;

		cwin = min(tp->snd_wnd, tp->snd_cwnd) - sack_bytes_rxmt;
		if (cwin < 0)
			cwin = 0;
		/* Do not retransmit SACK segments beyond snd_recover */
		if (SEQ_GT(p->end, tp->snd_recover)) {
			/*
			 * (At least) part of sack hole extends beyond
			 * snd_recover. Check to see if we can rexmit data
			 * for this hole.
			 */
			if (SEQ_GEQ(p->rxmit, tp->snd_recover)) {
				/*
				 * Can't rexmit any more data for this hole.
				 * That data will be rexmitted in the next
				 * sack recovery episode, when snd_recover
				 * moves past p->rxmit.
				 */
				p = NULL;
				goto after_sack_rexmit;
			} else {
				/* Can rexmit part of the current hole */
				len = ((long)ulmin(cwin,
						   tp->snd_recover - p->rxmit));
			}
		} else {
			len = ((long)ulmin(cwin, p->end - p->rxmit));
		}
		off = p->rxmit - tp->snd_una;
		KASSERT(off >= 0,("%s: sack block to the left of una : %d",
		    __func__, off));
		if (len > 0) {
			sack_rxmit = 1;
			sendalot = 1;
			TCPSTAT_INC(tcps_sack_rexmits);
			TCPSTAT_ADD(tcps_sack_rexmit_bytes,
			    min(len, tp->t_maxseg));
		}
	}
after_sack_rexmit:

	/*
	 * Get standard flags, and add SYN or FIN if requested by 'hidden'
	 * state flags.
	 */
	if (tp->t_flags & TF_NEEDFIN)
		flags |= OFP_TH_FIN;
	if (tp->t_flags & TF_NEEDSYN)
		flags |= OFP_TH_SYN;

	/*
	 * If in persist timeout with window of 0, send 1 byte.
	 * Otherwise, if window is small but nonzero
	 * and timer expired, we will send what we can
	 * and go to transmit state.
	 */
	if (tp->t_flags & TF_FORCEDATA) {
		if (sendwin == 0) {
			/*
			 * If we still have some data to send, then
			 * clear the FIN bit.  Usually this would
			 * happen below when it realizes that we
			 * aren't sending all the data.  However,
			 * if we have exactly 1 byte of unsent data,
			 * then it won't clear the FIN bit below,
			 * and if we are in persist state, we wind
			 * up sending the packet without recording
			 * that we sent the FIN bit.
			 *
			 * We can't just blindly clear the FIN bit,
			 * because if we don't have any more data
			 * to send then the probe will be the FIN
			 * itself.
			 */
			if (off < (int)so->so_snd.sb_cc)
				flags &= ~OFP_TH_FIN;
			sendwin = 1;
		} else {
			ofp_tcp_timer_activate(tp, TT_PERSIST, 0);
			tp->t_rxtshift = 0;
		}
	}

	/*
	 * If snd_nxt == snd_max and we have transmitted a FIN, the
	 * offset will be > 0 even if so_snd.sb_cc is 0, resulting in
	 * a negative length.  This can also occur when TCP opens up
	 * its congestion window while receiving additional duplicate
	 * acks after fast-retransmit because TCP will reset snd_nxt
	 * to snd_max after the fast-retransmit.
	 *
	 * In the normal retransmit-FIN-only case, however, snd_nxt will
	 * be set to snd_una, the offset will be 0, and the length may
	 * wind up 0.
	 *
	 * If sack_rxmit is true we are retransmitting from the scoreboard
	 * in which case len is already set.
	 */

	if (sack_rxmit == 0) {/* OK */
		if (sack_bytes_rxmt == 0) {/* OK */
			len = ((long)ulmin(so->so_snd.sb_cc, sendwin) - off);
		} else {
			long cwin;

                        /*
			 * We are inside of a SACK recovery episode and are
			 * sending new data, having retransmitted all the
			 * data possible in the scoreboard.
			 */
			len = ((long)ulmin(so->so_snd.sb_cc, tp->snd_wnd)
			       - off);
			/*
			 * Don't remove this (len > 0) check !
			 * We explicitly check for len > 0 here (although it
			 * isn't really necessary), to work around a gcc
			 * optimization issue - to force gcc to compute
			 * len above. Without this check, the computation
			 * of len is bungled by the optimizer.
			 */
			if (len > 0) {
				cwin = tp->snd_cwnd -
					(tp->snd_nxt - tp->sack_newdata) -
					sack_bytes_rxmt;
				if (cwin < 0)
					cwin = 0;
				len = lmin(len, cwin);
			}
		}
	}

	/*
	 * Lop off SYN bit if it has already been sent.  However, if this
	 * is SYN-SENT state and if segment contains data and if we don't
	 * know that foreign host supports TAO, suppress sending segment.
	 */
	if ((flags & OFP_TH_SYN) && SEQ_GT(tp->snd_nxt, tp->snd_una)) {
		if (tp->t_state != TCPS_SYN_RECEIVED)
			flags &= ~OFP_TH_SYN;
		off--, len++;
	}

	/*
	 * Be careful not to send data and/or FIN on SYN segments.
	 * This measure is needed to prevent interoperability problems
	 * with not fully conformant TCP implementations.
	 */
	if ((flags & OFP_TH_SYN) && (tp->t_flags & TF_NOOPT)) {
		len = 0;
		flags &= ~OFP_TH_FIN;
	}

	if (len < 0) {
		/*
		 * If FIN has been sent but not acked,
		 * but we haven't been called to retransmit,
		 * len will be < 0.  Otherwise, window shrank
		 * after we sent into it.  If window shrank to 0,
		 * cancel pending retransmit, pull snd_nxt back
		 * to (closed) window, and set the persist timer
		 * if it isn't already going.  If the window didn't
		 * close completely, just wait for an ACK.
		 */
		len = 0;
		if (sendwin == 0) {
			ofp_tcp_timer_activate(tp, TT_REXMT, 0);
			tp->t_rxtshift = 0;
			tp->snd_nxt = tp->snd_una;
			if (!ofp_tcp_timer_active(tp, TT_PERSIST))
				ofp_tcp_setpersist(tp);
		}
	}

	/* len will be >= 0 after this point. */
	KASSERT(len >= 0, ("[%s:%d]: len < 0", __func__, __LINE__));

	/*
	 * Automatic sizing of send socket buffer.  Often the send buffer
	 * size is not optimally adjusted to the actual network conditions
	 * at hand (delay bandwidth product).  Setting the buffer size too
	 * small limits throughput on links with high bandwidth and high
	 * delay (eg. trans-continental/oceanic links).  Setting the
	 * buffer size too big consumes too much real kernel memory,
	 * especially with many connections on busy servers.
	 *
	 * The criteria to step up the send buffer one notch are:
	 *  1. receive window of remote host is larger than send buffer
	 *     (with a fudge factor of 5/4th);
	 *  2. send buffer is filled to 7/8th with data (so we actually
	 *     have data to make use of it);
	 *  3. send buffer fill has not hit maximal automatic size;
	 *  4. our send window (slow start and cogestion controlled) is
	 *     larger than sent but unacknowledged data in send buffer.
	 *
	 * The remote host receive window scaling factor may limit the
	 * growing of the send buffer before it reaches its allowed
	 * maximum.
	 *
	 * It scales directly with slow start or congestion window
	 * and does at most one step per received ACK.  This fast
	 * scaling has the drawback of growing the send buffer beyond
	 * what is strictly necessary to make full use of a given
	 * delay*bandwith product.  However testing has shown this not
	 * to be much of an problem.  At worst we are trading wasting
	 * of available bandwith (the non-use of it) for wasting some
	 * socket buffer memory.
	 *
	 * TODO: Shrink send buffer during idle periods together
	 * with congestion window.  Requires another timer.  Has to
	 * wait for upcoming tcp timer rewrite.
	 */
#if 0 /* HJo: FIX */
	if (V_tcp_do_autosndbuf && so->so_snd.sb_flags & SB_AUTOSIZE) {
		if ((tp->snd_wnd / 4 * 5) >= so->so_snd.sb_hiwat &&
		    so->so_snd.sb_cc >= (so->so_snd.sb_hiwat / 8 * 7) &&
		    so->so_snd.sb_cc < V_tcp_autosndbuf_max &&
		    sendwin >= (so->so_snd.sb_cc - (tp->snd_nxt - tp->snd_una))) {
			if (!ofp_sbreserve_locked(&so->so_snd,
			    min(so->so_snd.sb_hiwat + V_tcp_autosndbuf_inc,
			     V_tcp_autosndbuf_max), so, curthread))
				so->so_snd.sb_flags &= ~SB_AUTOSIZE;
		}
	}
#endif
	/*
	 * Decide if we can use TCP Segmentation Offloading (if supported by
	 * hardware).
	 *
	 * TSO may only be used if we are in a pure bulk sending state.  The
	 * presence of TCP-MD5, SACK retransmits, SACK advertizements and
	 * IP options prevent using TSO.  With TSO the TCP header is the same
	 * (except for the sequence number) for all generated packets.  This
	 * makes it impossible to transmit any options which vary per generated
	 * segment or packet.
	 */
	if ((tp->t_flags & TF_TSO) && V_tcp_do_tso && len > tp->t_maxseg &&
	    ((tp->t_flags & TF_SIGNATURE) == 0) &&
	    tp->rcv_numsacks == 0 && sack_rxmit == 0 &&
	    tp->t_inpcb->inp_options == ODP_PACKET_INVALID &&
	    tp->t_inpcb->in6p_options == ODP_PACKET_INVALID)
		tso = 1;

	if (sack_rxmit) {
		if (SEQ_LT(p->rxmit + len, tp->snd_una + so->so_snd.sb_cc))
			flags &= ~OFP_TH_FIN;
	} else {/* OK */
		if (SEQ_LT(tp->snd_nxt + len, tp->snd_una + so->so_snd.sb_cc))
			flags &= ~OFP_TH_FIN;
	}

	recwin = sbspace(&so->so_rcv);

	/*
	 * Sender silly window avoidance.   We transmit under the following
	 * conditions when len is non-zero:
	 *
	 *	- We have a full segment (or more with TSO)
	 *	- This is the last buffer in a write()/send() and we are
	 *	  either idle or running NODELAY
	 *	- we've timed out (e.g. persist timer)
	 *	- we have more then 1/2 the maximum send window's worth of
	 *	  data (receiver may be limited the window size)
	 *	- we need to retransmit
	 */
	if (len) {/* OK */
		if (len >= tp->t_maxseg)
			goto send;
		/*
		 * NOTE! on localhost connections an 'ack' from the remote
		 * end may occur synchronously with the output and cause
		 * us to flush a buffer queued with moretocome.  XXX
		 *
		 * note: the len + off check is almost certainly unnecessary.
		 */
		if (!(tp->t_flags & TF_MORETOCOME) &&	/* normal case */
		    (idle || (tp->t_flags & TF_NODELAY)) &&
		    len + off >= so->so_snd.sb_cc &&
		    (tp->t_flags & TF_NOPUSH) == 0) {
			goto send;
		}
		if (tp->t_flags & TF_FORCEDATA)		/* typ. timeout case */
			goto send;
		if (len >= (int)(tp->max_sndwnd / 2) && tp->max_sndwnd > 0)
			goto send;
		if (SEQ_LT(tp->snd_nxt, tp->snd_max))	/* retransmit case */
			goto send;
		if (sack_rxmit)
			goto send;

	}

	/*
	 * Compare available window to amount of window
	 * known to peer (as advertised window less
	 * next expected input).  If the difference is at least two
	 * max size segments, or at least 50% of the maximum possible
	 * window, then want to send a window update to peer.
	 * Skip this if the connection is in T/TCP half-open state.
	 * Don't send pure window updates when the peer has closed
	 * the connection and won't ever send more data.
	 */
	if (recwin > 0 && !(tp->t_flags & TF_NEEDSYN) &&
	    !TCPS_HAVERCVDFIN(tp->t_state)) {
		/*
		 * "adv" is the amount we can increase the window,
		 * taking into account that we are limited by
		 * OFP_TCP_MAXWIN << tp->rcv_scale.
		 */
		long adv;
		int oldwin;

		adv = min(recwin, (long)OFP_TCP_MAXWIN << tp->rcv_scale);
		if (SEQ_GT(tp->rcv_adv, tp->rcv_nxt)) {
			oldwin = (tp->rcv_adv - tp->rcv_nxt);
			adv -= oldwin;
		} else
			oldwin = 0;

		/*
		 * If the new window size ends up being the same as the old
		 * size when it is scaled, then don't force a window update.
		 */
		if (oldwin >> tp->rcv_scale == (adv + oldwin) >> tp->rcv_scale)
			goto dontupdate;
		if (adv >= (long) (2 * tp->t_maxseg))
			goto send;
		if (2 * adv >= (long) so->so_rcv.sb_hiwat)
			goto send;
	}
dontupdate:
	/*
	 * Send if we owe the peer an ACK, RST, SYN, or urgent data.  ACKNOW
	 * is also a catch-all for the retransmit timer timeout case.
	 */
	if (tp->t_flags & TF_ACKNOW)
		goto send;
	if ((flags & OFP_TH_RST) ||
	    ((flags & OFP_TH_SYN) && (tp->t_flags & TF_NEEDSYN) == 0))
		goto send;
	if (SEQ_GT(tp->snd_up, tp->snd_una))
		goto send;

	/*
	 * If our state indicates that FIN should be sent
	 * and we have not yet done so, then we need to send.
	 */
	if (flags & OFP_TH_FIN &&
	    ((tp->t_flags & TF_SENTFIN) == 0 || tp->snd_nxt == tp->snd_una))
		goto send;

	/*
	 * In SACK, it is possible for ofp_tcp_output to fail to send a segment
	 * after the retransmission timer has been turned off.  Make sure
	 * that the retransmission timer is set.
	 */
	if ((tp->t_flags & TF_SACK_PERMIT) &&
	    SEQ_GT(tp->snd_max, tp->snd_una) &&
	    !ofp_tcp_timer_active(tp, TT_REXMT) &&
	    !ofp_tcp_timer_active(tp, TT_PERSIST)) {
		ofp_tcp_timer_activate(tp, TT_REXMT, tp->t_rxtcur);
		goto just_return;
	}

	/*
	 * TCP window updates are not reliable, rather a polling protocol
	 * using ``persist'' packets is used to insure receipt of window
	 * updates.  The three ``states'' for the output side are:
	 *	idle			not doing retransmits or persists
	 *	persisting		to move a small or zero window
	 *	(re)transmitting	and thereby not persisting
	 *
	 * ofp_tcp_timer_active(tp, TT_PERSIST)
	 *	is true when we are in persist state.
	 * (tp->t_flags & TF_FORCEDATA)
	 *	is set when we are called to send a persist packet.
	 * ofp_tcp_timer_active(tp, TT_REXMT)
	 *	is set when we are retransmitting
	 * The output side is idle when both timers are zero.
	 *
	 * If send window is too small, there is data to transmit, and no
	 * retransmit or persist is pending, then go to persist state.
	 * If nothing happens soon, send when timer expires:
	 * if window is nonzero, transmit what we can,
	 * otherwise force out a byte.
	 */
	if (so->so_snd.sb_cc && !ofp_tcp_timer_active(tp, TT_REXMT) &&
	    !ofp_tcp_timer_active(tp, TT_PERSIST)) {
		tp->t_rxtshift = 0;
		ofp_tcp_setpersist(tp);
	}

	/*
	 * No reason to send a segment, just return.
	 */
just_return:
	SOCKBUF_UNLOCK(&so->so_snd);
	return (0);

send:
	SOCKBUF_LOCK_ASSERT(&so->so_snd);
	/*
	 * Before ESTABLISHED, force sending of initial options
	 * unless TCP set not to do any options.
	 * NOTE: we assume that the IP/TCP header plus TCP options
	 * always fit in a single mbuf, leaving room for a maximum
	 * link header, i.e.
	 *	ofp_max_linkhdr + sizeof (struct tcpiphdr) + optlen <= MCLBYTES
	 */
	optlen = 0;
#ifdef INET6
	if (isipv6)
		hdrlen = sizeof (struct ofp_ip6_hdr) + sizeof (struct ofp_tcphdr);
	else
#endif
		hdrlen = sizeof (struct tcpiphdr);
	/*
	 * Compute options for segment.
	 * We only have to care about SYN and established connection
	 * segments.  Options for SYN-ACK segments are handled in TCP
	 * syncache.
	 */

	if ((tp->t_flags & TF_NOOPT) == 0) {/* OK */
		to.to_flags = 0;
		/* Maximum segment size. */
		if (flags & OFP_TH_SYN) {
			tp->snd_nxt = tp->iss;
			to.to_mss = ofp_tcp_mssopt(&tp->t_inpcb->inp_inc);
			to.to_flags |= TOF_MSS;
		}
		/* Window scaling. */
		if ((flags & OFP_TH_SYN) && (tp->t_flags & TF_REQ_SCALE)) {
			to.to_wscale = tp->request_r_scale;
			to.to_flags |= TOF_SCALE;
		}
		/* Timestamps. */
		if ((tp->t_flags & TF_RCVD_TSTMP) ||
		    ((flags & OFP_TH_SYN) && (tp->t_flags & TF_REQ_TSTMP))) {/* OK */
			to.to_tsval = tcp_ts_getticks() + tp->ts_offset;
			to.to_tsecr = tp->ts_recent;
			to.to_flags |= TOF_TS;
			/* Set receive buffer autosizing timestamp. */
			if (tp->rfbuf_ts == 0 &&
			    (so->so_rcv.sb_flags & SB_AUTOSIZE))
				tp->rfbuf_ts = tcp_ts_getticks();
		}
		/* Selective ACK's. */
		if (tp->t_flags & TF_SACK_PERMIT) {/* OK */
			if (flags & OFP_TH_SYN)
				to.to_flags |= TOF_SACKPERM;
			else if (TCPS_HAVEESTABLISHED(tp->t_state) &&
			    (tp->t_flags & TF_SACK_PERMIT) &&
			    tp->rcv_numsacks > 0) {
				to.to_flags |= TOF_SACK;
				to.to_nsacks = tp->rcv_numsacks;
				to.to_sacks = (uint8_t *)tp->sackblks;
			}
		}
#ifdef TCP_SIGNATURE
		/* TCP-MD5 (RFC2385). */
		if (tp->t_flags & TF_SIGNATURE)
			to.to_flags |= TOF_SIGNATURE;
#endif /* TCP_SIGNATURE */

		/* Processing the options. */
		hdrlen += optlen = ofp_tcp_addoptions(&to, opt);
	}

#ifdef INET6
	if (isipv6) /*Bogdan: no options*/
		ipoptlen = 0;/*ip6_optlen(tp->t_inpcb); */
	else
#endif
	if (tp->t_inpcb->inp_options != ODP_PACKET_INVALID)
		ipoptlen = odp_packet_len(tp->t_inpcb->inp_options) -
			offsetof(struct ofp_ipoption, ipopt_list);
	else
		ipoptlen = 0;
#ifdef IPSEC
	ipoptlen += ipsec_optlen;
#endif

	/*
	 * Adjust data length if insertion of options will
	 * bump the packet length beyond the t_maxopd length.
	 * Clear the FIN bit because we cut off the tail of
	 * the segment.
	 */
	if (len + optlen + ipoptlen > tp->t_maxopd) {/* OK */
		flags &= ~OFP_TH_FIN;

		if (tso) {
			KASSERT(ipoptlen == 0,
			    ("%s: TSO can't do IP options", __func__));

			/*
			 * Limit a burst to OFP_IP_MAXPACKET minus IP,
			 * TCP and options length to keep ip->ip_len
			 * from overflowing.
			 */
			if (len > OFP_IP_MAXPACKET - hdrlen) {
				len = OFP_IP_MAXPACKET - hdrlen;
				sendalot = 1;
			}

			/*
			 * Prevent the last segment from being
			 * fractional unless the send sockbuf can
			 * be emptied.
			 */
			if (sendalot && off + len < so->so_snd.sb_cc) {
				len -= len % (tp->t_maxopd - optlen);
				sendalot = 1;
			}

			/*
			 * Send the FIN in a separate segment
			 * after the bulk sending is done.
			 * We don't trust the TSO implementations
			 * to clear the FIN flag on all but the
			 * last segment.
			 */
			if (tp->t_flags & TF_NEEDFIN)
				sendalot = 1;

		} else {/* OK */
			len = tp->t_maxopd - optlen - ipoptlen;
			sendalot = 1;
		}
	} else
		tso = 0;

	KASSERT(len + hdrlen + ipoptlen <= OFP_IP_MAXPACKET,
	    ("%s: len > OFP_IP_MAXPACKET", __func__));

/*#ifdef DIAGNOSTIC*/
#if 0
#ifdef INET6
	if (ofp_max_linkhdr + hdrlen > MCLBYTES)
#else
	if (ofp_max_linkhdr + hdrlen > MHLEN)
#endif
		panic("tcphdr too big");
#endif
/*#endif*/

	/*
	 * This KASSERT is here to catch edge cases at a well defined place.
	 * Before, those had triggered (random) panic conditions further down.
	 */
	KASSERT(len >= 0, ("[%s:%d]: len < 0", __func__, __LINE__));

	/*
	 * Grab a header mbuf, attaching a copy of data to
	 * be transmitted, and initialize the header from
	 * the template for sends on this connection.
	 */

	if (len) {/* OK */
		if ((tp->t_flags & TF_FORCEDATA) && len == 1)
			TCPSTAT_INC(tcps_sndprobe);
		else if (SEQ_LT(tp->snd_nxt, tp->snd_max) || sack_rxmit) {
			tp->t_sndrexmitpack++;
			TCPSTAT_INC(tcps_sndrexmitpack);
			TCPSTAT_ADD(tcps_sndrexmitbyte, len);
		} else {/* OK */
			TCPSTAT_INC(tcps_sndpack);
			TCPSTAT_ADD(tcps_sndbyte, len);
		}

		m = ofp_packet_alloc(hdrlen + len);

		if (m == ODP_PACKET_INVALID) {
			SOCKBUF_UNLOCK(&so->so_snd);
			error = OFP_ENOBUFS;
			goto out;
		}

#if 0
		if (MHLEN < hdrlen + ofp_max_linkhdr) {
			MCLGET(m, M_DONTWAIT);
			if ((odp_packet_flags(m) & M_EXT) == 0) {
				SOCKBUF_UNLOCK(&so->so_snd);
				odp_packet_free(m);
				error = OFP_ENOBUFS;
				goto out;
			}
		}
#endif

		odp_packet_l3_offset_set(m, 0);
		odp_packet_l4_offset_set(m,
#ifdef INET6
			isipv6? sizeof(struct ofp_ip6_hdr) + ipoptlen :
#endif /*INET6*/
			sizeof(struct ofp_ip));

		ofp_sockbuf_copy_out(&so->so_snd, off, len,
				       (char *)odp_packet_data(m) + hdrlen);
		/*
		odp_packet_t src = so->so_snd.sb_mb[so->so_snd.sb_get];
		memcpy((uint8_t *)odp_packet_data(m) + hdrlen,
		       odp_packet_data(src), len);
		*/
		/*
		 * If we're sending everything we've got, set PUSH.
		 * (This will keep happy those implementations which only
		 * give data to the user when a buffer fills or
		 * a PUSH comes in.)
		 */
		if (off + len == so->so_snd.sb_cc)
			flags |= OFP_TH_PUSH;
	} else {
		if (tp->t_flags & TF_ACKNOW)
			TCPSTAT_INC(tcps_sndacks);
		else if (flags & (OFP_TH_SYN|OFP_TH_FIN|OFP_TH_RST))
			TCPSTAT_INC(tcps_sndctrl);
		else if (SEQ_GT(tp->snd_up, tp->snd_una))
			TCPSTAT_INC(tcps_sndurg);
		else
			TCPSTAT_INC(tcps_sndwinup);

		m = ofp_packet_alloc(hdrlen);

		if (m == ODP_PACKET_INVALID) {
			SOCKBUF_UNLOCK(&so->so_snd);
			error = OFP_ENOBUFS;
			goto out;
		}

#if 0
		if (isipv6 && (MHLEN < hdrlen + ofp_max_linkhdr) &&
		    MHLEN >= hdrlen) {
			MH_ALIGN(m, hdrlen);
		} else
#endif
		odp_packet_l3_offset_set(m, 0);
		odp_packet_l4_offset_set(m,
#ifdef INET6
			isipv6? sizeof(struct ofp_ip6_hdr) + ipoptlen :
#endif /*INET6*/
			sizeof(struct ofp_ip));
	}
	odp_packet_user_ptr_set(m, NULL);

#ifdef MAC
	mac_inpcb_create_mbuf(tp->t_inpcb, m);
#endif
#ifdef INET6
	if (isipv6) {
		ip6 = (struct ofp_ip6_hdr *)odp_packet_data(m);
		th = (struct ofp_tcphdr *)odp_packet_l4_ptr(m, NULL);
		ofp_tcpip_fillheaders(tp->t_inpcb, ip6, th);
	} else
#endif /* INET6 */
	{/* OK */
		ip = (struct ofp_ip *)(odp_packet_data(m));
		ipov = (struct ipovly *)ip;
		th = (struct ofp_tcphdr *)(ip + 1);
		ofp_tcpip_fillheaders(tp->t_inpcb, ip, th);
	}

	/*
	 * Fill in fields, remembering maximum advertised
	 * window for use in delaying messages about window sizes.
	 * If resending a FIN, be sure not to use a new sequence number.
	 */
	if (flags & OFP_TH_FIN && tp->t_flags & TF_SENTFIN &&
	    tp->snd_nxt == tp->snd_max)
		tp->snd_nxt--;
	/*
	 * If we are starting a connection, send ECN setup
	 * SYN packet. If we are on a retransmit, we may
	 * resend those bits a number of times as per
	 * RFC 3168.
	 */

	if (tp->t_state == TCPS_SYN_SENT && V_tcp_do_ecn) {
		if (tp->t_rxtshift >= 1) {
			if (tp->t_rxtshift <= V_tcp_ecn_maxretries)
				flags |= OFP_TH_ECE|OFP_TH_CWR;
		} else
			flags |= OFP_TH_ECE|OFP_TH_CWR;
	}

	if (tp->t_state == TCPS_ESTABLISHED &&
	    (tp->t_flags & TF_ECN_PERMIT)) {
		/*
		 * If the peer has ECN, mark data packets with
		 * ECN capable transmission (ECT).
		 * Ignore pure ack packets, retransmissions and window probes.
		 */
		if (len > 0 && SEQ_GEQ(tp->snd_nxt, tp->snd_max) &&
		    !((tp->t_flags & TF_FORCEDATA) && len == 1)) {
#ifdef INET6
			if (isipv6)
				ip6->ofp_ip6_flow |= odp_cpu_to_be_32(OFP_IPTOS_ECN_ECT0 << 20);
			else
#endif
				ip->ip_tos |= OFP_IPTOS_ECN_ECT0;
			TCPSTAT_INC(tcps_ecn_ect0);
		}

		/*
		 * Reply with proper ECN notifications.
		 */
		if (tp->t_flags & TF_ECN_SND_CWR) {
			flags |= OFP_TH_CWR;
			t_flags_and(tp->t_flags, ~TF_ECN_SND_CWR);
		}
		if (tp->t_flags & TF_ECN_SND_ECE)
			flags |= OFP_TH_ECE;
	}

	/*
	 * If we are doing retransmissions, then snd_nxt will
	 * not reflect the first unsent octet.  For ACK only
	 * packets, we do not want the sequence number of the
	 * retransmitted packet, we want the sequence number
	 * of the next unsent octet.  So, if there is no data
	 * (and no SYN or FIN), use snd_max instead of snd_nxt
	 * when filling in ti_seq.  But if we are in persist
	 * state, snd_max might reflect one byte beyond the
	 * right edge of the window, so use snd_nxt in that
	 * case, since we know we aren't doing a retransmission.
	 * (retransmit and persist are mutually exclusive...)
	 */

	if (sack_rxmit == 0) {/* OK */
		if (len || (flags & (OFP_TH_SYN|OFP_TH_FIN)) ||
		    ofp_tcp_timer_active(tp, TT_PERSIST))
			th->th_seq = odp_cpu_to_be_32(tp->snd_nxt);
		else
			th->th_seq = odp_cpu_to_be_32(tp->snd_max);
	} else {
		th->th_seq = odp_cpu_to_be_32(p->rxmit);
		p->rxmit += len;
		tp->sackhint.sack_bytes_rexmit += len;
	}
	th->th_ack = odp_cpu_to_be_32(tp->rcv_nxt);
	if (optlen) {/* OK */
		bcopy(opt, th + 1, optlen);
		th->th_off = (sizeof (struct ofp_tcphdr) + optlen) >> 2;
	}
	th->th_flags = flags;
	/*
	 * Calculate receive window.  Don't shrink window,
	 * but avoid silly window syndrome.
	 */
	if (recwin < (long)(so->so_rcv.sb_hiwat / 4) &&
	    recwin < (long)tp->t_maxseg)
		recwin = 0;
	if (SEQ_GT(tp->rcv_adv, tp->rcv_nxt) &&
	    recwin < (long)(tp->rcv_adv - tp->rcv_nxt))
		recwin = (long)(tp->rcv_adv - tp->rcv_nxt);
	if (recwin > (long)OFP_TCP_MAXWIN << tp->rcv_scale)
		recwin = (long)OFP_TCP_MAXWIN << tp->rcv_scale;

	/*
	 * According to RFC1323 the window field in a SYN (i.e., a <SYN>
	 * or <SYN,ACK>) segment itself is never scaled.  The <SYN,ACK>
	 * case is handled in syncache.
	 */
	if (flags & OFP_TH_SYN)
		th->th_win = odp_cpu_to_be_16((uint16_t)
				(min(sbspace(&so->so_rcv), OFP_TCP_MAXWIN)));
	else
		th->th_win = odp_cpu_to_be_16((uint16_t)(recwin >> tp->rcv_scale));
	/*
	 * Adjust the RXWIN0SENT flag - indicate that we have advertised
	 * a 0 window.  This may cause the remote transmitter to stall.  This
	 * flag tells ofp_soreceive() to disable delayed acknowledgements when
	 * draining the buffer.  This can occur if the receiver is attempting
	 * to read more data than can be buffered prior to transmitting on
	 * the connection.
	 */
	if (th->th_win == 0) {
		tp->t_sndzerowin++;
		t_flags_or(tp->t_flags, TF_RXWIN0SENT);
	} else
		t_flags_and(tp->t_flags, ~TF_RXWIN0SENT);
	if (SEQ_GT(tp->snd_up, tp->snd_nxt)) {
		th->th_urp = odp_cpu_to_be_16((uint16_t)(tp->snd_up - tp->snd_nxt));
		th->th_flags |= OFP_TH_URG;
	} else
		/*
		 * If no urgent pointer to send, then we pull
		 * the urgent pointer to the left edge of the send window
		 * so that it doesn't drift into the send window on sequence
		 * number wraparound.
		 */
		tp->snd_up = tp->snd_una;		/* drag it along */

#ifdef TCP_SIGNATURE
	if (tp->t_flags & TF_SIGNATURE) {
		int sigoff = to.to_signature - opt;
		tcp_signature_compute(m, 0, len, optlen,
		    (uint8_t *)(th + 1) + sigoff, IPSEC_DIR_OUTBOUND);
	}
#endif

	/*
	 * Put TCP length in extended header, and then
	 * checksum extended header and data.
	 */

	odp_packet_set_csum_data(m, offsetof(struct ofp_tcphdr, th_sum));
#ifdef INET6
	if (isipv6) {
		/*
		 * ip6_plen is not need to be filled now, and will be filled
		 * in ip6_output.
		 */
		odp_packet_set_csum_flags(m, CSUM_TCP_IPV6);
		th->th_sum = 0;
		th->th_sum = ofp_in6_cksum(m, OFP_IPPROTO_TCP,
			odp_packet_l4_offset(m),
			sizeof(struct ofp_tcphdr) + optlen + len);
	}
	else
#endif
	{/* OK */
		//odp_packet_set_csum_flags(m, CSUM_TCP);

		/* HJo: FIX:
		th->th_sum = in_pseudo(ip->ip_src.s_addr, ip->ip_dst.s_addr,
		    odp_cpu_to_be_16(sizeof(struct ofp_tcphdr) + OFP_IPPROTO_TCP + len + optlen));
		*/

		/* IP version must be set here for ipv4/ipv6 checking later */
		KASSERT(ip->ip_v == OFP_IPVERSION,
		    ("%s: IP version incorrect: %d", __func__, ip->ip_v));
	}

	/*
	 * Enable TSO and specify the size of the segments.
	 * The TCP pseudo header checksum is always provided.
	 * XXX: Fixme: This is currently not the case for IPv6.
	 */
	if (tso) {
		KASSERT(len > tp->t_maxopd - optlen,
		    ("%s: len <= tso_segsz", __func__));
		odp_packet_set_csum_flags(m, odp_packet_csum_flags(m) |
					  CSUM_TSO);
		/* HJo: FIX:
		m->m_pkthdr.tso_segsz = tp->t_maxopd - optlen;
		*/
	}

	KASSERT(len + hdrlen + ipoptlen == (int)odp_packet_len(m),
	    ("%s: mbuf chain shorter than expected: %ld + %u + %d != %d",
	    __func__, len, hdrlen, ipoptlen, odp_packet_len(m)));

	/*
	 * In transmit state, time the transmission and arrange for
	 * the retransmit.  In persist state, just set snd_max.
	 */

	if ((tp->t_flags & TF_FORCEDATA) == 0 ||
	    !ofp_tcp_timer_active(tp, TT_PERSIST)) {/* OK */
		tcp_seq startseq = tp->snd_nxt;

		/*
		 * Advance snd_nxt over sequence space of this segment.
		 */
		if (flags & (OFP_TH_SYN|OFP_TH_FIN)) {
			if (flags & OFP_TH_SYN)
				tp->snd_nxt++;
			if (flags & OFP_TH_FIN) {
				tp->snd_nxt++;
				t_flags_or(tp->t_flags, TF_SENTFIN);
			}
		}
		if (sack_rxmit)
			goto timer;
		tp->snd_nxt += len;
		if (SEQ_GT(tp->snd_nxt, tp->snd_max)) {/* OK */
			tp->snd_max = tp->snd_nxt;
			/*
			 * Time this transmission if not a retransmission and
			 * not currently timing anything.
			 */
			if (tp->t_rtttime == 0) {/* OK */
				tp->t_rtttime = ticks;
				tp->t_rtseq = startseq;
				TCPSTAT_INC(tcps_segstimed);
			}
		}

		/*
		 * Set retransmit timer if not currently set,
		 * and not doing a pure ack or a keep-alive probe.
		 * Initial value for retransmit timer is smoothed
		 * round-trip time + 2 * round-trip time variance.
		 * Initialize shift counter which is used for backoff
		 * of retransmit time.
		 */
timer:
		if (!ofp_tcp_timer_active(tp, TT_REXMT) &&
		    ((sack_rxmit && tp->snd_nxt != tp->snd_max) ||
		     (tp->snd_nxt != tp->snd_una))) {/* OK */
			if (ofp_tcp_timer_active(tp, TT_PERSIST)) {
				ofp_tcp_timer_activate(tp, TT_PERSIST, 0);
				tp->t_rxtshift = 0;
			}
			ofp_tcp_timer_activate(tp, TT_REXMT, tp->t_rxtcur);
		}
	} else {
		/*
		 * Persist case, update snd_max but since we are in
		 * persist mode (no window) we do not update snd_nxt.
		 */
		int xlen = len;
		if (flags & OFP_TH_SYN)
			++xlen;
		if (flags & OFP_TH_FIN) {
			++xlen;
			t_flags_or(tp->t_flags, TF_SENTFIN);
		}
		if (SEQ_GT(tp->snd_nxt + xlen, tp->snd_max))
			tp->snd_max = tp->snd_nxt + len;
	}

	/* Run HHOOK_TCP_ESTABLISHED_OUT helper hooks. */
	/* HJo: FIX
	hhook_run_tcp_est_out(tp, th, &to, len, tso);
	*/

#ifdef TCPDEBUG
	/*
	 * Trace.
	 */
	if (so->so_options & OFP_SO_DEBUG) {
		uint16_t save = 0;
#ifdef INET6
		if (!isipv6)
#endif
		{
			save = ipov->ih_len;
			ipov->ih_len = odp_cpu_to_be_16(odp_packet_get_len(m) /* - hdrlen + (th->th_off << 2) */);
		}
		tcp_trace(TA_OUTPUT, tp->t_state, tp, (void *)odp_packet_data(m), th, 0);
#ifdef INET6
		if (!isipv6)
#endif
		ipov->ih_len = save;
	}
#endif /* TCPDEBUG */
	SOCKBUF_UNLOCK(&so->so_snd);

	/*
	 * Fill in IP length and desired time to live and
	 * send to IP level.  There should be a better way
	 * to handle ttl and tos; we could keep them in
	 * the template, but need a way to checksum without them.
	 */
	/*
	 * odp_packet_get_len(m) should have been set before cksum calcuration,
	 * because in6_cksum() need it.
	 */
#ifdef INET6
	if (isipv6) {
		ip6->ofp_ip6_plen = odp_cpu_to_be_16(odp_packet_len(m) -
			sizeof (struct ofp_ip6_hdr));
		/*
		 * we separately set hoplimit for every segment, since the
		 * user might want to change the value via setsockopt.
		 * Also, desired default hop limit might be changed via
		 * Neighbor Discovery.
		 */
		ip6->ofp_ip6_hlim = V_ip6_defhlim;/* in6_selecthlim(tp->t_inpcb, NULL);*/

		/* TODO: IPv6 IP6TOS_ECT bit on */
#if 0
		error = ip6_output(m,
			    tp->t_inpcb->in6p_outputopts, NULL,
			    ((so->so_options & OFP_SO_DONTROUTE) ?
			    IP_ROUTETOIF : 0), NULL, NULL, tp->t_inpcb);
#else
		error = ofp_ip6_output(m, NULL);
#endif
	}
	else
#endif

    {/* OK */
	    ip->ip_len = odp_cpu_to_be_16(odp_packet_len(m));
#ifdef INET6
	if (tp->t_inpcb->inp_vflag & INP_IPV6PROTO)
		ip->ip_ttl = V_ip6_defhlim;/*in6_selecthlim(tp->t_inpcb, NULL);*/
#endif /* INET6 */
	/*
	 * If we do path MTU discovery, then we set DF on every packet.
	 * This might not be the best thing to do according to RFC3390
	 * Section 2. However the tcp hostcache migitates the problem
	 * so it affects only the first tcp connection with a host.
	 *
	 * NB: Don't set DF on small MTU/MSS to have a safe fallback.
	 */
	if (V_path_mtu_discovery && (int)tp->t_maxopd > V_tcp_minmss)
		ip->ip_off |= OFP_IP_DF;

	ip->ip_off = odp_cpu_to_be_16(ip->ip_off);
	ip->ip_sum = 0;
	th->th_sum = 0;
	th->th_sum = ofp_in4_cksum(m);

	error = ofp_ip_output(m, NULL);
    }

	if (error != OFP_PKT_PROCESSED) {
		/*
		 * We know that the packet was lost, so back out the
		 * sequence number advance, if any.
		 *
		 * If the error is OFP_EPERM the packet got blocked by the
		 * local firewall.  Normally we should terminate the
		 * connection but the blocking may have been spurious
		 * due to a firewall reconfiguration cycle.  So we treat
		 * it like a packet loss and let the retransmit timer and
		 * timeouts do their work over time.
		 * XXX: It is a POLA question whether calling ofp_tcp_drop right
		 * away would be the really correct behavior instead.
		 */
		if (((tp->t_flags & TF_FORCEDATA) == 0 ||
		    !ofp_tcp_timer_active(tp, TT_PERSIST)) &&
		    ((flags & OFP_TH_SYN) == 0) &&
		    (error != OFP_EPERM)) {
			if (sack_rxmit) {
				p->rxmit -= len;
				tp->sackhint.sack_bytes_rexmit -= len;
				KASSERT(tp->sackhint.sack_bytes_rexmit >= 0,
				    ("sackhint bytes rtx >= 0"));
			} else
				tp->snd_nxt -= len;
		}
out:
		SOCKBUF_UNLOCK_ASSERT(&so->so_snd);	/* Check gotos. */
#if 0
		switch (error) {
		case OFP_EPERM:
			tp->t_softerror = error;
			return (error);
		case OFP_ENOBUFS:
	                if (!ofp_tcp_timer_active(tp, TT_REXMT) &&
			    !ofp_tcp_timer_active(tp, TT_PERSIST))
	                        ofp_tcp_timer_activate(tp, TT_REXMT, tp->t_rxtcur);
			tp->snd_cwnd = tp->t_maxseg;
			return (0);
		case OFP_EMSGSIZE:
			/*
			 * For some reason the interface we used initially
			 * to send segments changed to another or lowered
			 * its MTU.
			 *
			 * ofp_tcp_mtudisc() will find out the new MTU and as
			 * its last action, initiate retransmission, so it
			 * is important to not do so here.
			 *
			 * If TSO was active we either got an interface
			 * without TSO capabilits or TSO was turned off.
			 * Disable it for this connection as too and
			 * immediatly retry with MSS sized segments generated
			 * by this function.
			 */
			if (tso)
				t_flags_and(tp->t_flags, ~TF_TSO);
			ofp_tcp_mtudisc(tp->t_inpcb, -1);
			return (0);
		case OFP_EHOSTDOWN:
		case OFP_EHOSTUNREACH:
		case OFP_ENETDOWN:
		case OFP_ENETUNREACH:
			if (TCPS_HAVERCVDSYN(tp->t_state)) {
				tp->t_softerror = error;
				return (0);
			}
			/* FALLTHROUGH */
		default:
			return (error);
		}
#endif
	}
	TCPSTAT_INC(tcps_sndtotal);

	/*
	 * Data sent (as far as we can tell).
	 * If this advertises a larger window than any other segment,
	 * then remember the size of the advertised window.
	 * Any pending ACK has now been sent.
	 */
	if (recwin >= 0 && SEQ_GT(tp->rcv_nxt + recwin, tp->rcv_adv))
		tp->rcv_adv = tp->rcv_nxt + recwin;
	tp->last_ack_sent = tp->rcv_nxt;
	t_flags_and(tp->t_flags, ~(TF_ACKNOW | TF_DELACK));
	if (ofp_tcp_timer_active(tp, TT_DELACK))
		ofp_tcp_timer_activate(tp, TT_DELACK, 0);
#if 0
	/*
	 * This completely breaks TCP if newreno is turned on.  What happens
	 * is that if delayed-acks are turned on on the receiver, this code
	 * on the transmitter effectively destroys the TCP window, forcing
	 * it to four packets (1.5Kx4 = 6K window).
	 */
	if (sendalot && --maxburst)
		goto again;
#endif
	if (sendalot) {
		SOCKBUF_LOCK(&so->so_snd);
		goto again;
	}

	return (0);
}

void
ofp_tcp_setpersist(struct tcpcb *tp)
{
	int t = ((tp->t_srtt >> 2) + tp->t_rttvar) >> 1;
	int tt;

	t_flags_and(tp->t_flags, ~TF_PREVVALID);
	if (ofp_tcp_timer_active(tp, TT_REXMT))
		panic("ofp_tcp_setpersist: retransmit pending");
	/*
	 * Start/restart persistance timer.
	 */
	TCPT_RANGESET(tt, t * ofp_tcp_backoff[tp->t_rxtshift],
		      TCPTV_PERSMIN, TCPTV_PERSMAX);
	ofp_tcp_timer_activate(tp, TT_PERSIST, tt);
	if (tp->t_rxtshift < TCP_MAXRXTSHIFT)
		tp->t_rxtshift++;
}

/*
 * Insert TCP options according to the supplied parameters to the place
 * optp in a consistent way.  Can handle unaligned destinations.
 *
 * The order of the option processing is crucial for optimal packing and
 * alignment for the scarce option space.
 *
 * The optimal order for a SYN/SYN-ACK segment is:
 *   MSS (4) + NOP (1) + Window scale (3) + SACK permitted (2) +
 *   Timestamp (10) + Signature (18) = 38 bytes out of a maximum of 40.
 *
 * The SACK options should be last.  SACK blocks consume 8*n+2 bytes.
 * So a full size SACK blocks option is 34 bytes (with 4 SACK blocks).
 * At minimum we need 10 bytes (to generate 1 SACK block).  If both
 * TCP Timestamps (12 bytes) and TCP Signatures (18 bytes) are present,
 * we only have 10 bytes for SACK options (40 - (12 + 18)).
 */
int
ofp_tcp_addoptions(struct tcpopt *to, uint8_t *optp)
{
	uint32_t mask, optlen = 0;

	for (mask = 1; mask < TOF_MAXOPT; mask <<= 1) {
		if ((to->to_flags & mask) != mask)
			continue;
		if (optlen == OFP_TCP_MAXOLEN)
			break;
		switch (to->to_flags & mask) {
		case TOF_MSS:
			while (optlen % 4) {
				optlen += OFP_TCPOLEN_NOP;
				*optp++ = OFP_TCPOPT_NOP;
			}
			if (OFP_TCP_MAXOLEN - optlen < OFP_TCPOLEN_MAXSEG)
				continue;
			optlen += OFP_TCPOLEN_MAXSEG;
			*optp++ = OFP_TCPOPT_MAXSEG;
			*optp++ = OFP_TCPOLEN_MAXSEG;
			to->to_mss = odp_cpu_to_be_16(to->to_mss);
			bcopy((uint8_t *)&to->to_mss, optp, sizeof(to->to_mss));
			optp += sizeof(to->to_mss);
			break;
		case TOF_SCALE:
			while (!optlen || optlen % 2 != 1) {
				optlen += OFP_TCPOLEN_NOP;
				*optp++ = OFP_TCPOPT_NOP;
			}
			if (OFP_TCP_MAXOLEN - optlen < OFP_TCPOLEN_WINDOW)
				continue;
			optlen += OFP_TCPOLEN_WINDOW;
			*optp++ = OFP_TCPOPT_WINDOW;
			*optp++ = OFP_TCPOLEN_WINDOW;
			*optp++ = to->to_wscale;
			break;
		case TOF_SACKPERM:
			while (optlen % 2) {
				optlen += OFP_TCPOLEN_NOP;
				*optp++ = OFP_TCPOPT_NOP;
			}
			if (OFP_TCP_MAXOLEN - optlen < OFP_TCPOLEN_SACK_PERMITTED)
				continue;
			optlen += OFP_TCPOLEN_SACK_PERMITTED;
			*optp++ = OFP_TCPOPT_SACK_PERMITTED;
			*optp++ = OFP_TCPOLEN_SACK_PERMITTED;
			break;
		case TOF_TS:
			while (!optlen || optlen % 4 != 2) {
				optlen += OFP_TCPOLEN_NOP;
				*optp++ = OFP_TCPOPT_NOP;
			}
			if (OFP_TCP_MAXOLEN - optlen < OFP_TCPOLEN_TIMESTAMP)
				continue;
			optlen += OFP_TCPOLEN_TIMESTAMP;
			*optp++ = OFP_TCPOPT_TIMESTAMP;
			*optp++ = OFP_TCPOLEN_TIMESTAMP;
			to->to_tsval = odp_cpu_to_be_32(to->to_tsval);
			to->to_tsecr = odp_cpu_to_be_32(to->to_tsecr);
			bcopy((uint8_t *)&to->to_tsval, optp, sizeof(to->to_tsval));
			optp += sizeof(to->to_tsval);
			bcopy((uint8_t *)&to->to_tsecr, optp, sizeof(to->to_tsecr));
			optp += sizeof(to->to_tsecr);
			break;
		case TOF_SIGNATURE:
			{
			int siglen = OFP_TCPOLEN_SIGNATURE - 2;

			while (!optlen || optlen % 4 != 2) {
				optlen += OFP_TCPOLEN_NOP;
				*optp++ = OFP_TCPOPT_NOP;
			}
			if (OFP_TCP_MAXOLEN - optlen < OFP_TCPOLEN_SIGNATURE)
				continue;
			optlen += OFP_TCPOLEN_SIGNATURE;
			*optp++ = OFP_TCPOPT_SIGNATURE;
			*optp++ = OFP_TCPOLEN_SIGNATURE;
			to->to_signature = optp;
			while (siglen--)
				 *optp++ = 0;
			break;
			}
		case TOF_SACK:
			{
			int sackblks = 0;
			struct sackblk *sack = (struct sackblk *)to->to_sacks;
			tcp_seq sack_seq;

			while (!optlen || optlen % 4 != 2) {
				optlen += OFP_TCPOLEN_NOP;
				*optp++ = OFP_TCPOPT_NOP;
			}
			if (OFP_TCP_MAXOLEN - optlen < OFP_TCPOLEN_SACKHDR + OFP_TCPOLEN_SACK)
				continue;
			optlen += OFP_TCPOLEN_SACKHDR;
			*optp++ = OFP_TCPOPT_SACK;
			sackblks = min(to->to_nsacks,
					(OFP_TCP_MAXOLEN - optlen) / OFP_TCPOLEN_SACK);
			*optp++ = OFP_TCPOLEN_SACKHDR + sackblks * OFP_TCPOLEN_SACK;
			while (sackblks--) {
				sack_seq = odp_cpu_to_be_32(sack->start);
				bcopy((uint8_t *)&sack_seq, optp, sizeof(sack_seq));
				optp += sizeof(sack_seq);
				sack_seq = odp_cpu_to_be_32(sack->end);
				bcopy((uint8_t *)&sack_seq, optp, sizeof(sack_seq));
				optp += sizeof(sack_seq);
				optlen += OFP_TCPOLEN_SACK;
				sack++;
			}
			TCPSTAT_INC(tcps_sack_send_blocks);
			break;
			}
		default:
			panic("unknown TCP option type");
			break;
		}
	}

	/* Terminate and pad TCP options to a 4 byte boundary. */
	if (optlen % 4) {
		optlen += OFP_TCPOLEN_EOL;
		*optp++ = OFP_TCPOPT_EOL;
	}
	/*
	 * According to RFC 793 (STD0007):
	 *   "The content of the header beyond the End-of-Option option
	 *    must be header padding (i.e., zero)."
	 *   and later: "The padding is composed of zeros."
	 */
	while (optlen % 4) {
		optlen += OFP_TCPOLEN_PAD;
		*optp++ = OFP_TCPOPT_PAD;
	}

	KASSERT(optlen <= OFP_TCP_MAXOLEN, ("%s: TCP options too long", __func__));
	return (optlen);
}
