/* Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

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
 *	@(#)ip.h	8.1 (Berkeley) 6/10/93
 */

#ifndef _OFP_IP6_H_
#define _OFP_IP6_H_

#if __GNUC__ >= 4
#pragma GCC visibility push(default)
#endif

/*
 * Definition for internet protocol version 6.
 * RFC 2460
 */

struct ofp_ip6_hdr {
	union {
		struct ofp_ip6_hdrctl {
			uint32_t ip6_un1_flow;	/* 20 bits of flow-ID */
			uint16_t ip6_un1_plen;	/* payload length */
			uint8_t  ip6_un1_nxt;	/* next header */
			uint8_t  ip6_un1_hlim;	/* hop limit */
		} ip6_un1;
		uint8_t ip6_un2_vfc;	/* 4 bits version, top 4 bits class */
		struct {
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
			uint8_t ip6_un2_tclass1:4;
			uint8_t ip6_un2_v:4;
#elif ODP_BYTE_ORDER == ODP_BIG_ENDIAN
			uint8_t ip6_un2_v:4;
			uint8_t ip6_un2_tclass1:4;
#else /* ODP_BYTE_ORDER */
#error Unknown byte ordering.
#endif /* ODP_BYTE_ORDER */
		} __attribute__((packed)) ip6_s;
	} ip6_ctlun;
	struct ofp_in6_addr ip6_src;	/* source address */
	struct ofp_in6_addr ip6_dst;	/* destination address */
} __attribute__((packed));

#define ofp_ip6_vfc		ip6_ctlun.ip6_un2_vfc
#define ofp_ip6_flow	ip6_ctlun.ip6_un1.ip6_un1_flow
#define ofp_ip6_plen	ip6_ctlun.ip6_un1.ip6_un1_plen
#define ofp_ip6_nxt		ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ofp_ip6_hlim	ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ofp_ip6_hops	ip6_ctlun.ip6_un1.ip6_un1_hlim

#define OFP_IPV6_VERSION		0x60
#define OFP_IPV6_VERSION_MASK		0xf0

#if ODP_BYTE_ORDER == ODP_BIG_ENDIAN
#define OFP_IPV6_FLOWINFO_MASK	0x0fffffff	/* flow info (28 bits) */
#define OFP_IPV6_FLOWLABEL_MASK	0x000fffff	/* flow label (20 bits) */
#else
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
#define OFP_IPV6_FLOWINFO_MASK	0xffffff0f	/* flow info (28 bits) */
#define OFP_IPV6_FLOWLABEL_MASK	0xffff0f00	/* flow label (20 bits) */
#endif /* LITTLE_ENDIAN */
#endif

/* ECN bits proposed by Sally Floyd */
#define OFP_IP6TOS_CE			0x01	/* congestion experienced */
#define OFP_IP6TOS_ECT		0x02	/* ECN-capable transport */


/*
 * Extension Headers
 */

struct	ofp_ip6_ext {
	uint8_t ip6e_nxt;
	uint8_t ip6e_len;
} __attribute__((packed));

/* Hop-by-Hop options header */
/* XXX should we pad it to force alignment on an 8-byte boundary? */
struct ofp_ip6_hbh {
	uint8_t ip6h_nxt;	/* next header */
	uint8_t ip6h_len;	/* length in units of 8 octets */
	/* followed by options */
} __attribute__((packed));

/* Destination options header */
/* XXX should we pad it to force alignment on an 8-byte boundary? */
struct ofp_ip6_dest {
	uint8_t ip6d_nxt;	/* next header */
	uint8_t ip6d_len;	/* length in units of 8 octets */
	/* followed by options */
} __attribute__((packed));

/* Option types and related macros */
#define OFP_IP6OPT_PAD1		0x00	/* 00 0 00000 */
#define OFP_IP6OPT_PADN		0x01	/* 00 0 00001 */
#define OFP_IP6OPT_JUMBO		0xC2	/* 11 0 00010 = 194 */
#define OFP_IP6OPT_NSAP_ADDR		0xC3	/* 11 0 00011 */
#define OFP_IP6OPT_TUNNEL_LIMIT	0x04	/* 00 0 00100 */
#define OFP_IP6OPT_RTALERT		0x05	/* 00 0 00101 (KAME definition) */
#define OFP_IP6OPT_ROUTER_ALERT	0x05	/* 00 0 00101 (RFC3542, recommended) */

#define OFP_IP6OPT_RTALERT_LEN	4
#define OFP_IP6OPT_RTALERT_MLD	0	/* Datagram contains an MLD message */
#define OFP_IP6OPT_RTALERT_RSVP	1	/* Datagram contains an RSVP message */
#define OFP_IP6OPT_RTALERT_ACTNET	2	/* contains an Active Networks msg */
#define OFP_IP6OPT_MINLEN		2

#define OFP_IP6OPT_EID		0x8a	/* 10 0 01010 */

#define OFP_IP6OPT_TYPE(o)		((o) & 0xC0)
#define OFP_IP6OPT_TYPE_SKIP		0x00
#define OFP_IP6OPT_TYPE_DISCARD	0x40
#define OFP_IP6OPT_TYPE_FORCEICMP	0x80
#define OFP_IP6OPT_TYPE_ICMP		0xC0

#define OFP_IP6OPT_MUTABLE		0x20

/* IPv6 options: common part */
struct ofp_ip6_opt {
	uint8_t ip6o_type;
	uint8_t ip6o_len;
} __attribute__((packed));

/* Jumbo Payload Option */
struct ofp_ip6_opt_jumbo {
	uint8_t ip6oj_type;
	uint8_t ip6oj_len;
	uint8_t ip6oj_jumbo_len[4];
} __attribute__((packed));
#define OFP_IP6OPT_JUMBO_LEN	6

/* NSAP Address Option */
struct ofp_ip6_opt_nsap {
	uint8_t ip6on_type;
	uint8_t ip6on_len;
	uint8_t ip6on_src_nsap_len;
	uint8_t ip6on_dst_nsap_len;
	/* followed by source NSAP */
	/* followed by destination NSAP */
} __attribute__((packed));

/* Tunnel Limit Option */
struct ofp_ip6_opt_tunnel {
	uint8_t ip6ot_type;
	uint8_t ip6ot_len;
	uint8_t ip6ot_encap_limit;
} __attribute__((packed));

/* Router Alert Option */
struct ofp_ip6_opt_router {
	uint8_t ip6or_type;
	uint8_t ip6or_len;
	uint8_t ip6or_value[2];
} __attribute__((packed));
/* Router alert values (in network byte order) */
#if ODP_BYTE_ORDER == ODP_BIG_ENDIAN
#define OFP_IP6_ALERT_MLD	0x0000
#define OFP_IP6_ALERT_RSVP	0x0001
#define OFP_IP6_ALERT_AN	0x0002
#else
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
#define OFP_IP6_ALERT_MLD	0x0000
#define OFP_IP6_ALERT_RSVP	0x0100
#define OFP_IP6_ALERT_AN	0x0200
#endif /* LITTLE_ENDIAN */
#endif

/* Routing header */
struct ofp_ip6_rthdr {
	uint8_t  ip6r_nxt;	/* next header */
	uint8_t  ip6r_len;	/* length in units of 8 octets */
	uint8_t  ip6r_type;	/* routing type */
	uint8_t  ip6r_segleft;	/* segments left */
	/* followed by routing type specific data */
} __attribute__((packed));

/* Type 0 Routing header, deprecated by RFC 5095. */
struct ofp_ip6_rthdr0 {
	uint8_t  ip6r0_nxt;		/* next header */
	uint8_t  ip6r0_len;		/* length in units of 8 octets */
	uint8_t  ip6r0_type;		/* always zero */
	uint8_t  ip6r0_segleft;	/* segments left */
	uint32_t  ip6r0_reserved;	/* reserved field */
	/* followed by up to 127 struct ofp_in6_addr */
} __attribute__((packed));

/* Fragment header */
struct ofp_ip6_frag {
	uint8_t  ip6f_nxt;		/* next header */
	uint8_t  ip6f_reserved;	/* reserved field */
	uint16_t ip6f_offlg;		/* offset, reserved, and flag */
	uint32_t ip6f_ident;		/* identification */
} __attribute__((packed));

#if ODP_BYTE_ORDER == ODP_BIG_ENDIAN
#define OFP_IP6F_OFF_MASK		0xfff8	/* mask out offset from _offlg */
#define OFP_IP6F_RESERVED_MASK	0x0006	/* reserved bits in ip6f_offlg */
#define OFP_IP6F_MORE_FRAG		0x0001	/* more-fragments flag */
#else /* BYTE_ORDER == LITTLE_ENDIAN */
#define OFP_IP6F_OFF_MASK		0xf8ff	/* mask out offset from _offlg */
#define OFP_IP6F_RESERVED_MASK	0x0600	/* reserved bits in ip6f_offlg */
#define OFP_IP6F_MORE_FRAG		0x0100	/* more-fragments flag */
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

/*
 * Internet implementation parameters.
 */
#define OFP_IPV6_MAXHLIM	255	/* maximum hoplimit */
#define OFP_IPV6_DEFHLIM	64	/* default hlim */
#define OFP_IPV6_FRAGTTL	120	/* ttl for fragment packets, in slowtimo tick */
#define OFP_IPV6_HLIMDEC	1	/* subtracted when forwarding */

#define OFP_IPV6_MMTU		1280	/* minimal MTU and reassembly. 1024 + 256 */
#define OFP_IPV6_MAXPACKET	65535	/* ip6 max packet size without Jumbo payload*/
#define OFP_IPV6_MAXOPTHDR	2048	/* max option header size, 256 64-bit words */

/*
 * OFP_IP6_EXTHDR_CHECK ensures that region between the IP6 header and the
 * target header (including IPv6 itself, extension headers and
 * TCP/UDP/ICMP6 headers) are contiguous. KAME requires drivers
 * to store incoming data into one internal mbuf or one or more external
 * mbufs(never into two or more internal mbufs). Thus, the third case is
 * supposed to never be matched but is prepared just in case.
 */

#define OFP_IP6_EXTHDR_CHECK(pkt, off, hlen, ret)			\
do {									\
	if (odp_packet_seg_len((pkt)) < (uint32_t)((off) + (hlen))) {	\
		return ret;						\
	}								\
} while (/*CONSTCOND*/ 0)

#if __GNUC__ >= 4
#pragma GCC visibility pop
#endif

#endif /* not _OFP_IP6_H_ */
