/*-
 * Copyright (c) 1982, 1986, 1993, 1994, 1995
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
 *	@(#)tcp_var.h	8.4 (Berkeley) 5/24/95
 * $FreeBSD: release/9.1.0/sys/netinet/tcp_var.h 235051 2012-05-05 07:55:50Z glebius $
 */

#ifndef _NETINET_TCP_VAR_H_
#define _NETINET_TCP_VAR_H_

#include "ofpi_tcp.h"
#include "ofpi_vnet.h"

/*
 * Kernel variables for tcp.
 */

VNET_DECLARE(int, ofp_tcp_do_rfc1323);
#define	V_tcp_do_rfc1323	VNET(ofp_tcp_do_rfc1323)

/* TCP segment queue entry */
struct tseg_qent {
	OFP_LIST_ENTRY(tseg_qent) tqe_q;
	int	tqe_len;		/* TCP segment data length */
	struct ofp_tcphdr *tqe_th;		/* a pointer to tcp header */
	odp_packet_t tqe_m;		/* mbuf contains packet */
#ifdef PASSIVE_INET
	OFP_TAILQ_ENTRY(tseg_qent) tqe_ageq;
	int tqe_ticks;			/* ticks when queued */
#endif
};
OFP_LIST_HEAD(tsegqe_head, tseg_qent);

struct sackblk {
	tcp_seq start;		/* start seq no. of sack block */
	tcp_seq end;		/* end seq no. */
};

struct sackhole {
	tcp_seq start;		/* start seq no. of hole */
	tcp_seq end;		/* end seq no. */
	tcp_seq rxmit;		/* next seq. no in hole to be retransmitted */
	OFP_TAILQ_ENTRY(sackhole) scblink;	/* scoreboard linkage */
};

struct sackhint {
	struct sackhole	*nexthole;
	int		sack_bytes_rexmit;
	tcp_seq		last_sack_ack;	/* Most recent/largest sacked ack */

	int		ispare;		/* explicit pad for 64bit alignment */
	uint64_t	_pad[2];	/* 1 sacked_bytes, 1 TBD */
};

struct tcptemp {
	uint8_t	tt_ipgen[40]; /* the size must be of max ip header, now IPv6 */
	struct ofp_tcphdr tt_t;
};

#define tcp6cb		tcpcb  /* for KAME src sync over BSD*'s */

/* Neighbor Discovery, Neighbor Unreachability Detection Upper layer hint. */
#ifdef INET6
# if 1
#define ND6_HINT(tp)
# else
#define ND6_HINT(tp)						\
do {								\
	if ((tp) && (tp)->t_inpcb &&				\
	    ((tp)->t_inpcb->inp_vflag & INP_IPV6) != 0)		\
		nd6_nud_hint(NULL, NULL, 0);			\
} while (0)
# endif /*1*/
#else
#define ND6_HINT(tp)
#endif

/*
 * Tcp control block, one per tcp; fields:
 * Organized for 16 byte cacheline efficiency.
 */
struct tcpcb {
	struct	tsegqe_head t_segq;	/* segment reassembly queue */
	void	*t_pspare[2];		/* new reassembly queue */
	int	t_segqlen;		/* segment reassembly queue length */
	int	t_dupacks;		/* consecutive dup acks recd */

	struct tcp_timer *t_timers;	/* All the TCP timers in one struct */

	struct	inpcb *t_inpcb;		/* back pointer to internet pcb */
	int	t_state;		/* state of this connection */
	uint32_t	t_flags;

	struct	vnet *t_vnet;		/* back pointer to parent vnet */

	tcp_seq	snd_una;		/* send unacknowledged */
	tcp_seq	snd_max;		/* highest sequence number sent;
					 * used to recognize retransmits
					 */
	tcp_seq	snd_nxt;		/* send next */
	tcp_seq	snd_up;			/* send urgent pointer */

	tcp_seq	snd_wl1;		/* window update seg seq number */
	tcp_seq	snd_wl2;		/* window update seg ack number */
	tcp_seq	iss;			/* initial send sequence number */
	tcp_seq	irs;			/* initial receive sequence number */

	tcp_seq	rcv_nxt;		/* receive next */
	tcp_seq	rcv_adv;		/* advertised window */
	uint64_t	rcv_wnd;		/* receive window */
	tcp_seq	rcv_up;			/* receive urgent pointer */

	uint64_t	snd_wnd;		/* send window */
	uint64_t	snd_cwnd;		/* congestion-controlled window */
	uint64_t	snd_spare1;		/* unused */
	uint64_t	snd_ssthresh;		/* snd_cwnd size threshold for
					 * for slow start exponential to
					 * linear switch
					 */
	uint64_t	snd_spare2;		/* unused */
	tcp_seq	snd_recover;		/* for use in NewReno Fast Recovery */

	uint32_t	t_maxopd;		/* mss plus options */

	uint32_t	t_rcvtime;		/* inactivity time */
	uint32_t	t_starttime;		/* time connection was established */
	uint32_t	t_rtttime;		/* RTT measurement start time */
	tcp_seq	t_rtseq;		/* sequence number being timed */

	uint32_t	t_bw_spare1;		/* unused */
	tcp_seq	t_bw_spare2;		/* unused */

	int	t_rxtcur;		/* current retransmit value (ticks) */
	uint32_t	t_maxseg;		/* maximum segment size */
	int	t_srtt;			/* smoothed round-trip time */
	int	t_rttvar;		/* variance in round-trip time */

	int	t_rxtshift;		/* log(2) of rexmt exp. backoff */
	uint32_t	t_rttmin;		/* minimum rtt allowed */
	uint32_t	t_rttbest;		/* best rtt we've seen */
	uint64_t	t_rttupdated;		/* number of times rtt sampled */
	uint64_t	max_sndwnd;		/* largest window peer has offered */

	int	t_softerror;		/* possible error not yet reported */
/* out-of-band data */
	char	t_oobflags;		/* have some */
	char	t_iobc;			/* input character */
/* RFC 1323 variables */
	uint8_t	snd_scale;		/* window scaling for send window */
	uint8_t	rcv_scale;		/* window scaling for recv window */
	uint8_t	request_r_scale;	/* pending window scaling */
	uint32_t  ts_recent;		/* timestamp echo data */
	uint32_t	ts_recent_age;		/* when last updated */
	uint32_t  ts_offset;		/* our timestamp offset */

	tcp_seq	last_ack_sent;
/* experimental */
	uint64_t	snd_cwnd_prev;		/* cwnd prior to retransmit */
	uint64_t	snd_ssthresh_prev;	/* ssthresh prior to retransmit */
	tcp_seq	snd_recover_prev;	/* snd_recover prior to retransmit */
	int	t_sndzerowin;		/* zero-window updates sent */
	uint32_t	t_badrxtwin;		/* window for retransmit recovery */
	uint8_t	snd_limited;		/* segments limited transmitted */
/* SACK related state */
	int	snd_numholes;		/* number of holes seen by sender */
	OFP_TAILQ_HEAD(sackhole_head, sackhole) snd_holes;
					/* SACK scoreboard (sorted) */
	tcp_seq	snd_fack;		/* last seq number(+1) sack'd by rcv'r*/
	int	rcv_numsacks;		/* # distinct sack blks present */
	struct sackblk sackblks[OFP_MAX_SACK_BLKS]; /* seq nos. of sack blocks */
	tcp_seq sack_newdata;		/* New data xmitted in this recovery
					   episode starts at this seq number */
	struct sackhint	sackhint;	/* SACK scoreboard hint */
	int	t_rttlow;		/* smallest observerved RTT */
	uint32_t	rfbuf_ts;	/* recv buffer autoscaling timestamp */
	int	rfbuf_cnt;		/* recv buffer autoscaling byte count */
	struct toe_usrreqs *t_tu;	/* offload operations vector */
	int	t_sndrexmitpack;	/* retransmit packets sent */
	int	t_rcvoopack;		/* out-of-order packets received */
	void	*t_toe;			/* TOE pcb pointer */
	int	t_bytes_acked;		/* # bytes acked during current RTT */
	struct cc_algo	*cc_algo;	/* congestion control algorithm */
	struct cc_var	*ccv;		/* congestion control specific vars */
	struct osd	*osd;		/* storage for Khelp module data */

	uint32_t	t_keepinit;		/* time to establish connection */
	uint32_t	t_keepidle;		/* time before keepalive probes begin */
	uint32_t	t_keepintvl;		/* interval between keepalives */
	uint32_t	t_keepcnt;		/* number of keepalives before close */

	uint32_t t_ispare[8];		/* 5 UTO, 3 TBD */
	void	*t_pspare2[4];		/* 4 TBD */
	uint64_t _pad[6];		/* 6 TBD (1-2 CC/RTT?) */
};

/*
 * Flags and utility macros for the t_flags field.
 */
#define	TF_ACKNOW	0x000001	/* ack peer immediately */
#define	TF_DELACK	0x000002	/* ack, but try to delay it */
#define	TF_NODELAY	0x000004	/* don't delay packets to coalesce */
#define	TF_NOOPT	0x000008	/* don't use tcp options */
#define	TF_SENTFIN	0x000010	/* have sent FIN */
#define	TF_REQ_SCALE	0x000020	/* have/will request window scaling */
#define	TF_RCVD_SCALE	0x000040	/* other side has requested scaling */
#define	TF_REQ_TSTMP	0x000080	/* have/will request timestamps */
#define	TF_RCVD_TSTMP	0x000100	/* a timestamp was received in SYN */
#define	TF_SACK_PERMIT	0x000200	/* other side said I could SACK */
#define	TF_NEEDSYN	0x000400	/* send SYN (implicit state) */
#define	TF_NEEDFIN	0x000800	/* send FIN (implicit state) */
#define	TF_NOPUSH	0x001000	/* don't push */
#define	TF_PREVVALID	0x002000	/* saved values for bad rxmit valid */
#define	TF_MORETOCOME	0x010000	/* More data to be appended to sock */
#define	TF_LQ_OVERFLOW	0x020000	/* listen queue overflow */
#define	TF_LASTIDLE	0x040000	/* connection was previously idle */
#define	TF_RXWIN0SENT	0x080000	/* sent a receiver win 0 in response */
#define	TF_FASTRECOVERY	0x100000	/* in NewReno Fast Recovery */
#define	TF_WASFRECOVERY	0x200000	/* was in NewReno Fast Recovery */
#define	TF_SIGNATURE	0x400000	/* require MD5 digests (RFC2385) */
#define	TF_FORCEDATA	0x800000	/* force out a byte */
#define	TF_TSO		0x1000000	/* TSO enabled on this connection */
#define	TF_TOE		0x2000000	/* this connection is offloaded */
#define	TF_ECN_PERMIT	0x4000000	/* connection ECN-ready */
#define	TF_ECN_SND_CWR	0x8000000	/* ECN CWR in queue */
#define	TF_ECN_SND_ECE	0x10000000	/* ECN ECE in queue */
#define	TF_CONGRECOVERY	0x20000000	/* congestion recovery mode */
#define	TF_WASCRECOVERY	0x40000000	/* was in congestion recovery */

#define	IN_FASTRECOVERY(t_flags)	(t_flags & TF_FASTRECOVERY)
#define	ENTER_FASTRECOVERY(t_flags)	t_flags |= TF_FASTRECOVERY
#define	EXIT_FASTRECOVERY(t_flags)	t_flags &= ~TF_FASTRECOVERY

#define	IN_CONGRECOVERY(t_flags)	(t_flags & TF_CONGRECOVERY)
#define	ENTER_CONGRECOVERY(t_flags)	t_flags |= TF_CONGRECOVERY
#define	EXIT_CONGRECOVERY(t_flags)	t_flags &= ~TF_CONGRECOVERY

#define	IN_RECOVERY(t_flags) (t_flags & (TF_CONGRECOVERY | TF_FASTRECOVERY))
#define	ENTER_RECOVERY(t_flags) t_flags |= (TF_CONGRECOVERY | TF_FASTRECOVERY)
#define	EXIT_RECOVERY(t_flags) t_flags &= ~(TF_CONGRECOVERY | TF_FASTRECOVERY)

#define	BYTES_THIS_ACK(tp, th)	(th->th_ack - tp->snd_una)

/*
 * Flags for the t_oobflags field.
 */
#define	OFP_TCPOOB_HAVEDATA	0x01
#define	OFP_TCPOOB_HADDATA	0x02

/*
 * Structure to hold TCP options that are only used during segment
 * processing (in ofp_tcp_input), but not held in the tcpcb.
 * It's basically used to reduce the number of parameters
 * to tcp_dooptions and ofp_tcp_addoptions.
 * The binary order of the to_flags is relevant for packing of the
 * options in ofp_tcp_addoptions.
 */
struct tcpopt {
	uint64_t	to_flags;	/* which options are present */
#define	TOF_MSS		0x0001		/* maximum segment size */
#define	TOF_SCALE	0x0002		/* window scaling */
#define	TOF_SACKPERM	0x0004		/* SACK permitted */
#define	TOF_TS		0x0010		/* timestamp */
#define	TOF_SIGNATURE	0x0040		/* TCP-MD5 signature option (RFC2385) */
#define	TOF_SACK	0x0080		/* Peer sent SACK option */
#define	TOF_MAXOPT	0x0100
	uint32_t	to_tsval;	/* new timestamp */
	uint32_t	to_tsecr;	/* reflected timestamp */
	uint8_t		*to_sacks;	/* pointer to the first SACK blocks */
	uint8_t		*to_signature;	/* pointer to the TCP-MD5 signature */
	uint16_t	to_mss;		/* maximum segment size */
	uint8_t	to_wscale;	/* window scaling */
	uint8_t	to_nsacks;	/* number of SACK blocks */
	uint32_t	to_spare;	/* UTO */
};

/*
 * Flags for tcp_dooptions.
 */
#define	TO_SYN		0x01		/* parse SYN-only options */

struct hc_metrics_lite {	/* must stay in sync with hc_metrics */
	uint64_t	rmx_mtu;	/* MTU for this path */
	uint64_t	rmx_ssthresh;	/* outbound gateway buffer limit */
	uint64_t	rmx_rtt;	/* estimated round trip time */
	uint64_t	rmx_rttvar;	/* estimated rtt variance */
	uint64_t	rmx_bandwidth;	/* estimated bandwidth */
	uint64_t	rmx_cwnd;	/* congestion window */
	uint64_t	rmx_sendpipe;   /* outbound delay-bandwidth product */
	uint64_t	rmx_recvpipe;   /* inbound delay-bandwidth product */
};

#ifndef _NETINET_IN_PCB_H_
struct in_conninfo;
#endif /* _NETINET_IN_PCB_H_ */

struct tcptw {
	struct inpcb	*tw_inpcb;	/* XXX back pointer to internet pcb */
	tcp_seq		snd_nxt;
	tcp_seq		rcv_nxt;
	tcp_seq		iss;
	tcp_seq		irs;
	uint16_t		last_win;	/* cached window value */
	uint16_t		tw_so_options;	/* copy of so_options */
	struct ofp_ucred	*tw_cred;	/* user credentials */
	uint32_t	t_recent;
	uint32_t	ts_offset;	/* our timestamp offset */
	uint32_t		t_starttime;
	int		tw_time;
	OFP_TAILQ_ENTRY(tcptw) tw_2msl;
};

#define	intotcpcb(ip)	((struct tcpcb *)(ip)->inp_ppcb)
#define	intotw(ip)	((struct tcptw *)(ip)->inp_ppcb)
#define	sototcpcb(so)	(intotcpcb(sotoinpcb(so)))

/*
 * The smoothed round-trip time and estimated variance
 * are stored as fixed point numbers scaled by the values below.
 * For convenience, these scales are also used in smoothing the average
 * (smoothed = (1/scale)sample + ((scale-1)/scale)smoothed).
 * With these scales, srtt has 3 bits to the right of the binary point,
 * and thus an "ALPHA" of 0.875.  rttvar has 2 bits to the right of the
 * binary point, and is smoothed with an ALPHA of 0.75.
 */
#define	TCP_RTT_SCALE		32	/* multiplier for srtt; 3 bits frac. */
#define	TCP_RTT_SHIFT		5	/* shift for srtt; 3 bits frac. */
#define	TCP_RTTVAR_SCALE	16	/* multiplier for rttvar; 2 bits */
#define	TCP_RTTVAR_SHIFT	4	/* shift for rttvar; 2 bits */
#define	TCP_DELTA_SHIFT		2	/* see ofp_tcp_input.c */

/*
 * The initial retransmission should happen at rtt + 4 * rttvar.
 * Because of the way we do the smoothing, srtt and rttvar
 * will each average +1/2 tick of bias.  When we compute
 * the retransmit timer, we want 1/2 tick of rounding and
 * 1 extra tick because of +-1/2 tick uncertainty in the
 * firing of the timer.  The bias will give us exactly the
 * 1.5 tick we need.  But, because the bias is
 * statistical, we have to test that we don't drop below
 * the minimum feasible timer (which is 2 ticks).
 * This version of the macro adapted from a paper by Lawrence
 * Brakmo and Larry Peterson which outlines a problem caused
 * by insufficient precision in the original implementation,
 * which results in inappropriately large RTO values for very
 * fast networks.
 */
#define	TCP_REXMTVAL(tp) \
	max((tp)->t_rttmin, (((tp)->t_srtt >> (TCP_RTT_SHIFT - TCP_DELTA_SHIFT))  \
	  + (tp)->t_rttvar) >> TCP_DELTA_SHIFT)

/*
 * TCP statistics.
 * Many of these should be kept per connection,
 * but that's inconvenient at the moment.
 */
struct	ofp_tcpstat {
	uint64_t	tcps_connattempt;	/* connections initiated */
	uint64_t	tcps_accepts;		/* connections accepted */
	uint64_t	tcps_connects;		/* connections established */
	uint64_t	tcps_drops;		/* connections dropped */
	uint64_t	tcps_conndrops;		/* embryonic connections dropped */
	uint64_t	tcps_minmssdrops;	/* average minmss too low drops */
	uint64_t	tcps_closed;		/* conn. closed (includes drops) */
	uint64_t	tcps_segstimed;		/* segs where we tried to get rtt */
	uint64_t	tcps_rttupdated;	/* times we succeeded */
	uint64_t	tcps_delack;		/* delayed acks sent */
	uint64_t	tcps_timeoutdrop;	/* conn. dropped in rxmt timeout */
	uint64_t	tcps_rexmttimeo;	/* retransmit timeouts */
	uint64_t	tcps_persisttimeo;	/* persist timeouts */
	uint64_t	tcps_keeptimeo;		/* keepalive timeouts */
	uint64_t	tcps_keepprobe;		/* keepalive probes sent */
	uint64_t	tcps_keepdrops;		/* connections dropped in keepalive */

	uint64_t	tcps_sndtotal;		/* total packets sent */
	uint64_t	tcps_sndpack;		/* data packets sent */
	uint64_t	tcps_sndbyte;		/* data bytes sent */
	uint64_t	tcps_sndrexmitpack;	/* data packets retransmitted */
	uint64_t	tcps_sndrexmitbyte;	/* data bytes retransmitted */
	uint64_t	tcps_sndrexmitbad;	/* unnecessary packet retransmissions */
	uint64_t	tcps_sndacks;		/* ack-only packets sent */
	uint64_t	tcps_sndprobe;		/* window probes sent */
	uint64_t	tcps_sndurg;		/* packets sent with URG only */
	uint64_t	tcps_sndwinup;		/* window update-only packets sent */
	uint64_t	tcps_sndctrl;		/* control (SYN|FIN|RST) packets sent */

	uint64_t	tcps_rcvtotal;		/* total packets received */
	uint64_t	tcps_rcvpack;		/* packets received in sequence */
	uint64_t	tcps_rcvbyte;		/* bytes received in sequence */
	uint64_t	tcps_rcvbadsum;		/* packets received with ccksum errs */
	uint64_t	tcps_rcvbadoff;		/* packets received with bad offset */
	uint64_t	tcps_rcvmemdrop;	/* packets dropped for lack of memory */
	uint64_t	tcps_rcvshort;		/* packets received too short */
	uint64_t	tcps_rcvduppack;	/* duplicate-only packets received */
	uint64_t	tcps_rcvdupbyte;	/* duplicate-only bytes received */
	uint64_t	tcps_rcvpartduppack;	/* packets with some duplicate data */
	uint64_t	tcps_rcvpartdupbyte;	/* dup. bytes in part-dup. packets */
	uint64_t	tcps_rcvoopack;		/* out-of-order packets received */
	uint64_t	tcps_rcvoobyte;		/* out-of-order bytes received */
	uint64_t	tcps_rcvpackafterwin;	/* packets with data after window */
	uint64_t	tcps_rcvbyteafterwin;	/* bytes rcvd after window */
	uint64_t	tcps_rcvafterclose;	/* packets rcvd after "close" */
	uint64_t	tcps_rcvwinprobe;	/* rcvd window probe packets */
	uint64_t	tcps_rcvdupack;		/* rcvd duplicate acks */
	uint64_t	tcps_rcvacktoomuch;	/* rcvd acks for unsent data */
	uint64_t	tcps_rcvackpack;	/* rcvd ack packets */
	uint64_t	tcps_rcvackbyte;	/* bytes acked by rcvd acks */
	uint64_t	tcps_rcvwinupd;		/* rcvd window update packets */
	uint64_t	tcps_pawsdrop;		/* segments dropped due to PAWS */
	uint64_t	tcps_predack;		/* times hdr predict ok for acks */
	uint64_t	tcps_preddat;		/* times hdr predict ok for data pkts */
	uint64_t	tcps_pcbcachemiss;
	uint64_t	tcps_cachedrtt;		/* times cached RTT in route updated */
	uint64_t	tcps_cachedrttvar;	/* times cached rttvar updated */
	uint64_t	tcps_cachedssthresh;	/* times cached ssthresh updated */
	uint64_t	tcps_usedrtt;		/* times RTT initialized from route */
	uint64_t	tcps_usedrttvar;	/* times RTTVAR initialized from rt */
	uint64_t	tcps_usedssthresh;	/* times ssthresh initialized from rt*/
	uint64_t	tcps_persistdrop;	/* timeout in persist state */
	uint64_t	tcps_badsyn;		/* bogus SYN, e.g. premature ACK */
	uint64_t	tcps_mturesent;		/* resends due to MTU discovery */
	uint64_t	tcps_listendrop;	/* listen queue overflows */
	uint64_t	tcps_badrst;		/* ignored RSTs in the window */

	uint64_t	tcps_sc_added;		/* entry added to syncache */
	uint64_t	tcps_sc_retransmitted;	/* syncache entry was retransmitted */
	uint64_t	tcps_sc_dupsyn;		/* duplicate SYN packet */
	uint64_t	tcps_sc_dropped;	/* could not reply to packet */
	uint64_t	tcps_sc_completed;	/* successful extraction of entry */
	uint64_t	tcps_sc_bucketoverflow;	/* syncache per-bucket limit hit */
	uint64_t	tcps_sc_cacheoverflow;	/* syncache cache limit hit */
	uint64_t	tcps_sc_reset;		/* RST removed entry from syncache */
	uint64_t	tcps_sc_stale;		/* timed out or listen socket gone */
	uint64_t	tcps_sc_aborted;	/* syncache entry aborted */
	uint64_t	tcps_sc_badack;		/* removed due to bad ACK */
	uint64_t	tcps_sc_unreach;	/* ICMP unreachable received */
	uint64_t	tcps_sc_zonefail;	/* zalloc() failed */
	uint64_t	tcps_sc_sendcookie;	/* SYN cookie sent */
	uint64_t	tcps_sc_recvcookie;	/* SYN cookie received */

	uint64_t	tcps_hc_added;		/* entry added to hostcache */
	uint64_t	tcps_hc_bucketoverflow;	/* hostcache per bucket limit hit */

	uint64_t  tcps_finwait2_drops;    /* Drop FIN_WAIT_2 connection after time limit */

	/* SACK related stats */
	uint64_t	tcps_sack_recovery_episode; /* SACK recovery episodes */
	uint64_t  tcps_sack_rexmits;	    /* SACK rexmit segments   */
	uint64_t  tcps_sack_rexmit_bytes;	    /* SACK rexmit bytes      */
	uint64_t  tcps_sack_rcv_blocks;	    /* SACK blocks (options) received */
	uint64_t  tcps_sack_send_blocks;	    /* SACK blocks (options) sent     */
	uint64_t  tcps_sack_sboverflow;	    /* times scoreboard overflowed */

	/* ECN related stats */
	uint64_t	tcps_ecn_ce;		/* ECN Congestion Experienced */
	uint64_t	tcps_ecn_ect0;		/* ECN Capable Transport */
	uint64_t	tcps_ecn_ect1;		/* ECN Capable Transport */
	uint64_t	tcps_ecn_shs;		/* ECN successful handshakes */
	uint64_t	tcps_ecn_rcwnd;		/* # times ECN reduced the cwnd */

	/* TCP_SIGNATURE related stats */
	uint64_t	tcps_sig_rcvgoodsig;	/* Total matching signature received */
	uint64_t	tcps_sig_rcvbadsig;	/* Total bad signature received */
	uint64_t	tcps_sig_err_buildsig;	/* Mismatching signature received */
	uint64_t	tcps_sig_err_sigopt;	/* No signature expected by socket */
	uint64_t	tcps_sig_err_nosigopt;	/* No signature provided by segment */

	uint64_t	_pad[12];		/* 6 UTO, 6 TBD */
};

/*
 * In-kernel consumers can use these accessor macros directly to update
 * stats.
 */
#define	TCPSTAT_ADD(name, val)	V_tcpstat.name += (val)
#define	TCPSTAT_INC(name)	TCPSTAT_ADD(name, 1)

/*
 * Kernel module consumers must use this accessor macro.
 */
void	ofp_kmod_tcpstat_inc(int statnum);
#define	KMOD_TCPSTAT_INC(name)						\
	ofp_kmod_tcpstat_inc(offsetof(struct ofp_tcpstat, name) / sizeof(uint64_t))

/*
 * TCP specific helper hook point identifiers.
 */
#define	HHOOK_TCP_EST_IN		0
#define	HHOOK_TCP_EST_OUT		1
#define	HHOOK_TCP_LAST			HHOOK_TCP_EST_OUT

struct tcp_hhook_data {
	struct tcpcb	*tp;
	struct ofp_tcphdr	*th;
	struct tcpopt	*to;
	long		len;
	int		tso;
	tcp_seq		curack;
};

/*
 * TCB structure exported to user-land via sysctl(3).
 * Evil hack: declare only if in_pcb.h and sys/socketvar.h have been
 * included.  Not all of our clients do.
 */
#if defined(_NETINET_IN_PCB_H_) && defined(_SYS_SOCKETVAR_H_)
struct xtcp_timer {
	int tt_rexmt;	/* retransmit timer */
	int tt_persist;	/* retransmit persistence */
	int tt_keep;	/* keepalive */
	int tt_2msl;	/* 2*msl TIME_WAIT timer */
	int tt_delack;	/* delayed ACK timer */
	int t_rcvtime;	/* Time since last packet received */
};
struct	xtcpcb {
	size_t	xt_len;
	struct	inpcb	xt_inp;
	struct	tcpcb	xt_tp;
	struct	xsocket	xt_socket;
	struct	xtcp_timer xt_timer;
	uint64_t	xt_alignment_hack;
};
#endif

/*
 * Names for TCP sysctl objects
 */
#define	TCPCTL_DO_RFC1323	1	/* use RFC-1323 extensions */
#define	TCPCTL_MSSDFLT		3	/* MSS default */
#define TCPCTL_STATS		4	/* statistics (read-only) */
#define	TCPCTL_RTTDFLT		5	/* default RTT estimate */
#define	TCPCTL_KEEPIDLE		6	/* keepalive idle timer */
#define	TCPCTL_KEEPINTVL	7	/* interval to send keepalives */
#define	TCPCTL_SENDSPACE	8	/* send buffer space */
#define	TCPCTL_RECVSPACE	9	/* receive buffer space */
#define	TCPCTL_KEEPINIT		10	/* timeout for establishing syn */
#define	TCPCTL_PCBLIST		11	/* list of all outstanding PCBs */
#define	TCPCTL_DELACKTIME	12	/* time before sending delayed ACK */
#define	TCPCTL_V6MSSDFLT	13	/* MSS default for IPv6 */
#define	TCPCTL_SACK		14	/* Selective Acknowledgement,rfc 2018 */
#define	TCPCTL_DROP		15	/* drop tcp connection */
#define	TCPCTL_MAXID		16
#define TCPCTL_FINWAIT2_TIMEOUT	17

#define TCPCTL_NAMES { \
	{ 0, 0 }, \
	{ "rfc1323", OFP_CTLTYPE_INT }, \
	{ "mssdflt", OFP_CTLTYPE_INT }, \
	{ "stats", OFP_CTLTYPE_STRUCT }, \
	{ "rttdflt", OFP_CTLTYPE_INT }, \
	{ "keepidle", OFP_CTLTYPE_INT }, \
	{ "keepintvl", OFP_CTLTYPE_INT }, \
	{ "sendspace", OFP_CTLTYPE_INT }, \
	{ "recvspace", OFP_CTLTYPE_INT }, \
	{ "keepinit", OFP_CTLTYPE_INT }, \
	{ "pcblist", OFP_CTLTYPE_STRUCT }, \
	{ "delacktime", OFP_CTLTYPE_INT }, \
	{ "v6mssdflt", OFP_CTLTYPE_INT }, \
	{ "maxid", OFP_CTLTYPE_INT }, \
}

SYSCTL_DECL(_net_inet_tcp);
SYSCTL_DECL(_net_inet_tcp_sack);

VNET_DECLARE(struct ofp_tcpstat, ofp_tcpstat);		/* tcp statistics */
extern	int ofp_tcp_log_in_vain;
VNET_DECLARE(int, ofp_tcp_mssdflt);	/* XXX */
VNET_DECLARE(int, ofp_tcp_minmss);
VNET_DECLARE(int, ofp_tcp_delack_enabled);
VNET_DECLARE(int, ofp_tcp_do_rfc3390);
VNET_DECLARE(int, ofp_path_mtu_discovery);
VNET_DECLARE(int, ofp_ss_fltsz);
VNET_DECLARE(int, ofp_ss_fltsz_local);
VNET_DECLARE(int, ofp_tcp_do_rfc3465);
VNET_DECLARE(int, ofp_tcp_abc_l_var);
#define	V_tcpstat		VNET(ofp_tcpstat)
#define	V_tcp_mssdflt		VNET(ofp_tcp_mssdflt)
#define	V_tcp_minmss		VNET(ofp_tcp_minmss)
#define	V_tcp_delack_enabled	VNET(ofp_tcp_delack_enabled)
#define	V_tcp_do_rfc3390	VNET(ofp_tcp_do_rfc3390)
#define	V_path_mtu_discovery	VNET(ofp_path_mtu_discovery)
#define	V_ss_fltsz		VNET(ofp_ss_fltsz)
#define	V_ss_fltsz_local	VNET(ofp_ss_fltsz_local)
#define	V_tcp_do_rfc3465	VNET(ofp_tcp_do_rfc3465)
#define	V_tcp_abc_l_var		VNET(ofp_tcp_abc_l_var)

VNET_DECLARE(int, ofp_tcp_do_sack);			/* SACK enabled/disabled */
VNET_DECLARE(int, ofp_tcp_sc_rst_sock_fail);	/* RST on sock alloc failure */
#define	V_tcp_do_sack		VNET(ofp_tcp_do_sack)
#define	V_tcp_sc_rst_sock_fail	VNET(ofp_tcp_sc_rst_sock_fail)

VNET_DECLARE(int, ofp_tcp_do_ecn);			/* TCP ECN enabled/disabled */
VNET_DECLARE(int, ofp_tcp_ecn_maxretries);
#define	V_tcp_do_ecn		VNET(ofp_tcp_do_ecn)
#define	V_tcp_ecn_maxretries	VNET(ofp_tcp_ecn_maxretries)

VNET_DECLARE(struct hhook_head *, ofp_tcp_hhh[HHOOK_TCP_LAST + 1]);
#define	V_tcp_hhh		VNET(ofp_tcp_hhh)

int	 ofp_tcp_addoptions(struct tcpopt *, uint8_t *);
int	 tcp_ccalgounload(struct cc_algo *unload_algo);
struct tcpcb *
	 ofp_tcp_close(struct tcpcb *);
void	 ofp_tcp_discardcb(struct tcpcb *);
void	 ofp_tcp_twstart(struct tcpcb *);
#if 0
int	 tcp_twrecycleable(struct tcptw *tw);
#endif
void	 ofp_tcp_twclose(struct tcptw *_tw, int _reuse);
void	 ofp_tcp_ctlinput(int, struct ofp_sockaddr *, void *);
int	 ofp_tcp_ctloutput(struct socket *, struct sockopt *);
struct tcpcb *
	 ofp_tcp_drop(struct tcpcb *, int);
void	 ofp_tcp_drain(void);
void	 ofp_tcp_tcbinfo_hashstats(unsigned int *min, unsigned int *avg, unsigned int *max);
void	 ofp_tcp_init(void);
void	 ofp_tcp_destroy(void);
void	 ofp_tcp_fini(void *);
char	*ofp_tcp_log_addrs(struct in_conninfo *, struct ofp_tcphdr *, void *,
	    const void *);
char	*ofp_tcp_log_vain(struct in_conninfo *, struct ofp_tcphdr *, void *,
	    const void *);
int	 ofp_tcp_reass(struct tcpcb *, struct ofp_tcphdr *, int *, odp_packet_t );
void	 ofp_tcp_reass_init(void);
void	 ofp_tcp_reass_flush(struct tcpcb *);

enum ofp_return_code ofp_tcp_input(odp_packet_t , int);
#define	TI_UNLOCKED	1
#define	TI_WLOCKED	2
void	 ofp_tcp_do_segment(odp_packet_t m, struct ofp_tcphdr *th, struct socket *so,
	     struct tcpcb *tp, int drop_hdrlen, int tlen, uint8_t iptos,
	     int ti_locked, int no_unlock);
u_long	 ofp_tcp_maxmtu(struct in_conninfo *, int *);
u_long	 ofp_tcp_maxmtu6(struct in_conninfo *, int *);
void	 ofp_tcp_mss_update(struct tcpcb *, int, int, struct hc_metrics_lite *,
	    int *);
void	 ofp_tcp_mss(struct tcpcb *, int);
int	 ofp_tcp_mssopt(struct in_conninfo *);
struct inpcb *
	 ofp_tcp_drop_syn_sent(struct inpcb *, int);
struct inpcb *
	 ofp_tcp_mtudisc(struct inpcb *, int);
struct tcpcb *
	 ofp_tcp_newtcpcb(struct inpcb *);
int	 ofp_tcp_output(struct tcpcb *);
void	 ofp_tcp_respond(struct tcpcb *, void *,
	    struct ofp_tcphdr *, odp_packet_t , tcp_seq, tcp_seq, int);
void	 ofp_tcp_tw_init(void);
void	 ofp_tcp_tw_zone_change(void);
int	 ofp_tcp_twcheck(struct inpcb *, struct tcpopt *, struct ofp_tcphdr *,
	    odp_packet_t , int);
int	 ofp_tcp_twrespond(struct tcptw *, int);
void	 ofp_tcp_setpersist(struct tcpcb *);
void	 ofp_tcp_slowtimo(void *);
struct tcptemp *
	 ofp_tcpip_maketemplate(struct inpcb *);
void	 ofp_tcpip_fillheaders(struct inpcb *, void *, void *);
void	 ofp_tcp_timer_activate(struct tcpcb *, int, uint32_t);
int	 ofp_tcp_timer_active(struct tcpcb *, int);
void	 tcp_trace(short, short, struct tcpcb *, void *, struct ofp_tcphdr *, int);
/*
 * All tcp_hc_* functions are IPv4 and IPv6 (via in_conninfo)
 */
void	 tcp_hc_init(void);
void	 tcp_hc_get(struct in_conninfo *, struct hc_metrics_lite *);
u_long	 tcp_hc_getmtu(struct in_conninfo *);
void	 tcp_hc_updatemtu(struct in_conninfo *, uint64_t);
//void	 tcp_hc_update(struct in_conninfo *, struct hc_metrics_lite *);

extern	struct pr_usrreqs ofp_tcp_usrreqs;
extern	uint64_t ofp_tcp_sendspace;
extern	uint64_t ofp_tcp_recvspace;
tcp_seq ofp_tcp_new_isn(struct tcpcb *);

void	 ofp_tcp_sack_doack(struct tcpcb *, struct tcpopt *, tcp_seq);
void	 ofp_tcp_update_sack_list(struct tcpcb *tp, tcp_seq rcv_laststart, tcp_seq rcv_lastend);
void	 ofp_tcp_clean_sackreport(struct tcpcb *tp);
void	 ofp_tcp_sack_adjust(struct tcpcb *tp);
struct sackhole *ofp_tcp_sack_output(struct tcpcb *tp, int *sack_bytes_rexmt);
void	 ofp_tcp_sack_partialack(struct tcpcb *, struct ofp_tcphdr *);
void	 ofp_tcp_free_sackholes(struct tcpcb *tp);
int	 tcp_newreno(struct tcpcb *, struct ofp_tcphdr *);
u_long	 tcp_seq_subtract(uint64_t, uint64_t );

void	ofp_cc_cong_signal(struct tcpcb *tp, struct ofp_tcphdr *th, uint32_t type);

int ofp_tcp_var_lookup_shared_memory(void);
int ofp_tcp_var_init_global(void);
int ofp_tcp_var_term_global(void);
#endif /* _NETINET_TCP_VAR_H_ */
