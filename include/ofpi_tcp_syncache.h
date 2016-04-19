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
 * $FreeBSD: release/9.1.0/sys/netinet/tcp_syncache.h 224151 2011-07-17 21:15:20Z bz $
 */

#ifndef _NETINET_TCP_SYNCACHE_H_
#define _NETINET_TCP_SYNCACHE_H_

struct toeopt;

void	 ofp_syncache_init(void);
int	 ofp_syncache_expand(struct in_conninfo *, struct tcpopt *,
	     struct ofp_tcphdr *, struct socket **, odp_packet_t );
int	 tcp_offload_syncache_expand(struct in_conninfo *inc, struct toeopt *toeo,
             struct ofp_tcphdr *th, struct socket **lsop, odp_packet_t m);
void	 ofp_syncache_add(struct in_conninfo *, struct tcpopt *,
		      struct ofp_tcphdr *, struct inpcb *, struct socket **, odp_packet_t ,
		      int);
void	 tcp_offload_syncache_add(struct in_conninfo *, struct toeopt *,
             struct ofp_tcphdr *, struct inpcb *, struct socket **,
             struct toe_usrreqs *tu, void *toepcb);

void	 ofp_syncache_chkrst(struct in_conninfo *, struct ofp_tcphdr *);
void	 ofp_syncache_badack(struct in_conninfo *);
int	 ofp_syncache_pcbcount(void);
void     ofp_syncache_unreach(struct in_conninfo *inc, struct ofp_tcphdr *th);
//int	 syncache_pcblist(struct ofp_sysctl_req *req, int max_pcbs, int *pcbs_exported);

struct syncache {
	OFP_TAILQ_ENTRY(syncache)	sc_hash;
	struct		in_conninfo sc_inc;	/* addresses */
	int		sc_rxttime;		/* retransmit time */
	uint16_t	sc_rxmits;		/* retransmit counter */
	uint32_t	sc_tsreflect;		/* timestamp to reflect */
	uint32_t	sc_ts;			/* our timestamp to send */
	uint32_t	sc_tsoff;		/* ts offset w/ syncookies */
	uint32_t	sc_flowlabel;		/* IPv6 flowlabel */
	tcp_seq		sc_irs;			/* seq from peer */
	tcp_seq		sc_iss;			/* our ISS */
	odp_packet_t 	sc_ipopts;		/* source route */
	uint16_t	sc_peer_mss;		/* peer's MSS */
	uint16_t	sc_wnd;			/* advertised window */
	uint8_t		sc_ip_ttl;		/* IPv4 TTL */
	uint8_t		sc_ip_tos;		/* IPv4 TOS */
	uint8_t		sc_requested_s_scale:4,
			sc_requested_r_scale:4;
	uint16_t	sc_flags;
#ifndef TCP_OFFLOAD_DISABLE
	struct toe_usrreqs *sc_tu;		/* TOE operations */
	void		*sc_toepcb;		/* TOE protocol block */
#endif			
	struct label	*sc_label;		/* MAC label reference */
	struct ofp_ucred	*sc_cred;		/* cred cache for jail checks */
	uint32_t	sc_spare[2];		/* UTO */
};

/*
 * Flags for the sc_flags field.
 */
#define SCF_NOOPT		0x01			/* no TCP options */
#define SCF_WINSCALE		0x02			/* negotiated window scaling */
#define SCF_TIMESTAMP		0x04			/* negotiated timestamps */
							/* MSS is implicit */
#define SCF_UNREACH		0x10			/* icmp unreachable received */
#define SCF_SIGNATURE		0x20			/* send MD5 digests */
#define SCF_SACK		0x80			/* send SACK option */
#define SCF_ECN			0x100			/* send ECN setup packet */
#define SCF_PASSIVE		0x200			/* connection is in passive mode */
#define SCF_PASSIVE_SYNACK	0x400			/* SYN|ACK captured in passive mode */
#define SCF_NO_TIMEOUT_RESET	0x800			/* don't reset timeout on dup SYN */ 
#define SCF_CONVERT_ON_TIMEOUT	0x1000			/* convert from passive to active on timeout */

#define	SYNCOOKIE_SECRET_SIZE	8	/* dwords */
#define	SYNCOOKIE_LIFETIME	16	/* seconds */

struct syncache_head {
	struct vnet	*sch_vnet;
	odp_spinlock_t	sch_mtx;
	OFP_TAILQ_HEAD(sch_head, syncache)	sch_bucket;
	struct callout	sch_timer;
	int		sch_nextc;
	uint32_t		sch_length;
	uint32_t		sch_oddeven;
	uint32_t	sch_secbits_odd[SYNCOOKIE_SECRET_SIZE];
	uint32_t	sch_secbits_even[SYNCOOKIE_SECRET_SIZE];
	uint32_t		sch_reseed;		/* time_uptime, seconds */
};

struct tcp_syncache {
	struct	syncache_head *hashbase;
	uint32_t	hashsize;
	uint32_t	hashmask;
	uint32_t	bucket_limit;
	uint32_t	cache_count;		/* XXX: unprotected */
	uint32_t	cache_limit;
	uint32_t	rexmt_limit;
	uint32_t	hash_secret;
};

#endif /* !_NETINET_TCP_SYNCACHE_H_ */
