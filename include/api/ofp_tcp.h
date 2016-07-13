/* Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/*-
 * Copyright (c) 1982, 1986, 1993
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
 *	@(#)tcp.h	8.1 (Berkeley) 6/10/93
 * $FreeBSD: release/9.1.0/sys/netinet/tcp.h 232945 2012-03-13 20:37:57Z glebius $
 */

#ifndef _OFP_TCP_H_
#define _OFP_TCP_H_

#include <odp.h>
#include "ofp_ip_var.h"

#if __GNUC__ >= 4
#pragma GCC visibility push(default)
#endif

typedef	uint32_t tcp_seq;

#define ofp_tcp6_seq	tcp_seq	/* for KAME src sync over BSD*'s */
#define ofp_tcp6hdr	tcphdr	/* for KAME src sync over BSD*'s */

/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
struct ofp_tcphdr {
	uint16_t	th_sport;		/* source port */
	uint16_t	th_dport;		/* destination port */
	tcp_seq		th_seq;			/* sequence number */
	tcp_seq		th_ack;			/* acknowledgement number */
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	uint8_t		th_x2:4,		/* (unused) */
			th_off:4;		/* data offset */
#endif
#if ODP_BYTE_ORDER == ODP_BIG_ENDIAN
	uint8_t		th_off:4,		/* data offset */
			th_x2:4;		/* (unused) */
#endif
	uint8_t		th_flags;
#define OFP_TH_FIN	0x01
#define OFP_TH_SYN	0x02
#define OFP_TH_RST	0x04
#define OFP_TH_PUSH	0x08
#define OFP_TH_ACK	0x10
#define OFP_TH_URG	0x20
#define OFP_TH_ECE	0x40
#define OFP_TH_CWR	0x80
#define OFP_TH_FLAGS	(TH_FIN|TH_SYN|TH_RST|TH_PUSH|TH_ACK|TH_URG|TH_ECE|TH_CWR)
#define OFP_PRINT_TH_FLAGS	"\20\1FIN\2SYN\3RST\4PUSH\5ACK\6URG\7ECE\10CWR"

	uint16_t	th_win;			/* window */
	uint16_t	th_sum;			/* checksum */
	uint16_t	th_urp;			/* urgent pointer */
};

#define OFP_TCPOPT_EOL		0
#define OFP_TCPOLEN_EOL		1
#define OFP_TCPOPT_PAD		0		/* padding after EOL */
#define OFP_TCPOLEN_PAD		1
#define OFP_TCPOPT_NOP		1
#define OFP_TCPOLEN_NOP		1
#define OFP_TCPOPT_MAXSEG		2
#define OFP_TCPOLEN_MAXSEG		4
#define OFP_TCPOPT_WINDOW		3
#define OFP_TCPOLEN_WINDOW		3
#define OFP_TCPOPT_SACK_PERMITTED	4
#define OFP_TCPOLEN_SACK_PERMITTED	2
#define OFP_TCPOPT_SACK		5
#define OFP_TCPOLEN_SACKHDR		2
#define OFP_TCPOLEN_SACK		8	/* 2*sizeof(tcp_seq) */
#define OFP_TCPOPT_TIMESTAMP		8
#define OFP_TCPOLEN_TIMESTAMP		10
#define OFP_TCPOLEN_TSTAMP_APPA	(OFP_TCPOLEN_TIMESTAMP+2) /* appendix A */
#define OFP_TCPOPT_SIGNATURE		19	/* Keyed MD5: RFC 2385 */
#define OFP_TCPOLEN_SIGNATURE		18

/* Miscellaneous constants */
#define OFP_MAX_SACK_BLKS		6	/* Max # SACK blocks stored at receiver side */
#define OFP_TCP_MAX_SACK		4	/* MAX # SACKs sent in any segment */


/*
 * The default maximum segment size (MSS) to be used for new TCP connections
 * when path MTU discovery is not enabled.
 *
 * RFC879 derives the default MSS from the largest datagram size hosts are
 * minimally required to handle directly or through IP reassembly minus the
 * size of the IP and TCP header.  With IPv6 the minimum MTU is specified
 * in RFC2460.
 *
 * For IPv4 the MSS is 576 - sizeof(struct tcpiphdr)
 * For IPv6 the MSS is IPV6_MMTU - sizeof(struct ip6_hdr) - sizeof(struct ofp_tcphdr)
 *
 * We use explicit numerical definition here to avoid header pollution.
 */
#define OFP_TCP_MSS	536
#define OFP_TCP6_MSS	1220

/*
 * Limit the lowest MSS we accept for path MTU discovery and the TCP SYN MSS
 * option.  Allowing low values of MSS can consume significant resources and
 * be used to mount a resource exhaustion attack.
 * Connections requesting lower MSS values will be rounded up to this value
 * and the OFP_IP_DF flag will be cleared to allow fragmentation along the path.
 *
 * See tcp_subr.c ofp_tcp_minmss SYSCTL declaration for more comments.  Setting
 * it to "0" disables the minmss check.
 *
 * The default value is fine for TCP across the Internet's smallest official
 * link MTU (256 bytes for AX.25 packet radio).  However, a connection is very
 * unlikely to come across such low MTU interfaces these days (anno domini 2003).
 */
#define OFP_TCP_MINMSS		216

#define OFP_TCP_MAXWIN		65535	/* largest value for (unscaled) window */
#define OFP_TTCP_CLIENT_SND_WND	4096	/* dflt send window for T/TCP client */

#define OFP_TCP_MAX_WINSHIFT		14	/* maximum window shift */

#define OFP_TCP_MAXBURST		4	/* maximum segments in a burst */

#define OFP_TCP_MAXHLEN		(0xf<<2)/* max length of header in bytes */
#define OFP_TCP_MAXOLEN		(OFP_TCP_MAXHLEN - sizeof(struct ofp_tcphdr))
						/* max space left for options */

/*
 * User-settable options (used with setsockopt).
 */
#define OFP_TCP_NODELAY	0x01	/* don't delay send to coalesce packets */
#define OFP_TCP_MAXSEG	0x02	/* set maximum segment size */
#define OFP_TCP_NOPUSH	0x04	/* don't push last block of write */
#define OFP_TCP_NOOPT	0x08	/* don't use TCP options */
#define OFP_TCP_MD5SIG	0x10	/* use MD5 digests (RFC2385) */
#define OFP_TCP_INFO	0x20	/* retrieve tcp_info structure */
#define OFP_TCP_CONGESTION	0x40	/* get/set congestion control algorithm */
#define OFP_TCP_KEEPINIT	0x80	/* N, time to establish connection */
#define OFP_TCP_KEEPIDLE	0x100	/* L,N,X start keepalives after this period */
#define OFP_TCP_KEEPINTVL	0x200	/* L,N interval between keepalives */
#define OFP_TCP_KEEPCNT	0x400	/* L,N number of keepalives before close */
#define OFP_TCP_REASSDL	0x800	/* wait this long for missing segments */

#define	OFP_TCP_CA_NAME_MAX	16	/* max congestion control name length */

#define	OFP_TCPI_OPT_TIMESTAMPS	0x01
#define	OFP_TCPI_OPT_SACK		0x02
#define	OFP_TCPI_OPT_WSCALE		0x04
#define	OFP_TCPI_OPT_ECN		0x08
#define	OFP_TCPI_OPT_TOE		0x10

/*
 * The TCP_INFO socket option comes from the Linux 2.6 TCP API, and permits
 * the caller to query certain information about the state of a TCP
 * connection.  We provide an overlapping set of fields with the Linux
 * implementation, but since this is a fixed size structure, room has been
 * left for growth.  In order to maximize potential future compatibility with
 * the Linux API, the same variable names and order have been adopted, and
 * padding left to make room for omitted fields in case they are added later.
 *
 * XXX: This is currently an unstable ABI/API, in that it is expected to
 * change.
 */
struct ofp_tcp_info {
	uint8_t	tcpi_state;		/* TCP FSM state. */
	uint8_t	__tcpi_ca_state;
	uint8_t	__tcpi_retransmits;
	uint8_t	__tcpi_probes;
	uint8_t	__tcpi_backoff;
	uint8_t	tcpi_options;		/* Options enabled on conn. */
	uint8_t	tcpi_snd_wscale:4,	/* RFC1323 send shift value. */
			tcpi_rcv_wscale:4;	/* RFC1323 recv shift value. */

	uint32_t	tcpi_rto;		/* Retransmission timeout (usec). */
	uint32_t	__tcpi_ato;
	uint32_t	tcpi_snd_mss;		/* Max segment size for send. */
	uint32_t	tcpi_rcv_mss;		/* Max segment size for receive. */

	uint32_t	__tcpi_unacked;
	uint32_t	__tcpi_sacked;
	uint32_t	__tcpi_lost;
	uint32_t	__tcpi_retrans;
	uint32_t	__tcpi_fackets;

	/* Times; measurements in usecs. */
	uint32_t	__tcpi_last_data_sent;
	uint32_t	__tcpi_last_ack_sent;	/* Also unimpl. on Linux? */
	uint32_t	tcpi_last_data_recv;	/* Time since last recv data. */
	uint32_t	__tcpi_last_ack_recv;

	/* Metrics; variable units. */
	uint32_t	__tcpi_pmtu;
	uint32_t	__tcpi_rcv_ssthresh;
	uint32_t	tcpi_rtt;		/* Smoothed RTT in usecs. */
	uint32_t	tcpi_rttvar;		/* RTT variance in usecs. */
	uint32_t	tcpi_snd_ssthresh;	/* Slow start threshold. */
	uint32_t	tcpi_snd_cwnd;		/* Send congestion window. */
	uint32_t	__tcpi_advmss;
	uint32_t	__tcpi_reordering;

	uint32_t	__tcpi_rcv_rtt;
	uint32_t	tcpi_rcv_space;		/* Advertised recv window. */

	/* FreeBSD extensions to tcp_info. */
	uint32_t	tcpi_snd_wnd;		/* Advertised send window. */
	uint32_t	tcpi_snd_bwnd;		/* No longer used. */
	uint32_t	tcpi_snd_nxt;		/* Next egress seqno */
	uint32_t	tcpi_rcv_nxt;		/* Next ingress seqno */
	uint32_t	tcpi_toe_tid;		/* HWTID for TOE endpoints */
	uint32_t	tcpi_snd_rexmitpack;	/* Retransmitted packets */
	uint32_t	tcpi_rcv_ooopack;	/* Out-of-order packets */
	uint32_t	tcpi_snd_zerowin;	/* Zero-sized windows sent */

	/* Padding to grow without breaking ABI. */
	uint32_t	__tcpi_pad[26];		/* Padding. */
};

/*
 * Tcp+ip header, after ip options removed.
 */
struct tcpiphdr {
	struct	ipovly ti_i;		/* overlaid ip structure */
	struct	ofp_tcphdr ti_t;		/* tcp header */
};
#define	ti_x1		ti_i.ih_x1
#define	ti_pr		ti_i.ih_pr
#define	ti_len		ti_i.ih_len
#define	ti_src		ti_i.ih_src
#define	ti_dst		ti_i.ih_dst
#define	ti_sport	ti_t.th_sport
#define	ti_dport	ti_t.th_dport
#define	ti_seq		ti_t.th_seq
#define	ti_ack		ti_t.th_ack
#define	ti_x2		ti_t.th_x2
#define	ti_off		ti_t.th_off
#define	ti_flags	ti_t.th_flags
#define	ti_win		ti_t.th_win
#define	ti_sum		ti_t.th_sum
#define	ti_urp		ti_t.th_urp

#if __GNUC__ >= 4
#pragma GCC visibility pop
#endif

#endif /* !_OFP_TCP_H_ */
