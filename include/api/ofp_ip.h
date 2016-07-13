/* Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/*-
 * Copyright (c) 1982, 1986, 1993
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
 *	@(#)ip.h	8.2 (Berkeley) 6/1/94
 * $FreeBSD: release/9.1.0/sys/netinet/ip.h 235805 2012-05-22 19:53:25Z delphij $
 */

#ifndef _OFP_IP_H_
#define _OFP_IP_H_

#include <odp.h>

#if __GNUC__ >= 4
#pragma GCC visibility push(default)
#endif

/*
 * Definitions for internet protocol version 4.
 *
 * Per RFC 791, September 1981.
 */
#define OFP_IPVERSION	4

/*
 * Structure of an internet header, naked of options.
 */
struct ofp_ip {
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	uint8_t	ip_hl:4,		/* header length */
		ip_v:4;			/* version */
#endif
#if ODP_BYTE_ORDER == ODP_BIG_ENDIAN
	uint8_t	ip_v:4,			/* version */
		ip_hl:4;		/* header length */
#endif
	uint8_t	ip_tos;			/* type of service */
	uint16_t	ip_len;			/* total length */
	uint16_t	ip_id;			/* identification */
	uint16_t	ip_off;			/* fragment offset field */
#define OFP_IP_RF 0x8000			/* reserved fragment flag */
#define OFP_IP_DF 0x4000			/* dont fragment flag */
#define OFP_IP_MF 0x2000			/* more fragments flag */
#define OFP_IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	uint8_t	ip_ttl;			/* time to live */
	uint8_t	ip_p;			/* protocol */
	uint16_t	ip_sum;			/* checksum */
	struct	ofp_in_addr ip_src,ip_dst;	/* source and dest address */
} __attribute__((packed));

#define OFP_IP_MAXPACKET	65535		/* maximum packet size */

/*
 * Definitions for IP type of service (ip_tos).
 */
#define OFP_IPTOS_LOWDELAY	0x10
#define OFP_IPTOS_THROUGHPUT	0x08
#define OFP_IPTOS_RELIABILITY	0x04
#define OFP_IPTOS_MINCOST	0x02

/*
 * Definitions for IP precedence (also in ip_tos) (hopefully unused).
 */
#define OFP_IPTOS_PREC_NETCONTROL		0xe0
#define OFP_IPTOS_PREC_INTERNETCONTROL	0xc0
#define OFP_IPTOS_PREC_CRITIC_ECP		0xa0
#define OFP_IPTOS_PREC_FLASHOVERRIDE		0x80
#define OFP_IPTOS_PREC_FLASH			0x60
#define OFP_IPTOS_PREC_IMMEDIATE		0x40
#define OFP_IPTOS_PREC_PRIORITY		0x20
#define OFP_IPTOS_PREC_ROUTINE		0x00

/*
 * Definitions for DiffServ Codepoints as per RFC2474
 */
#define OFP_IPTOS_DSCP_CS0		0x00
#define OFP_IPTOS_DSCP_CS1		0x20
#define OFP_IPTOS_DSCP_AF11		0x28
#define OFP_IPTOS_DSCP_AF12		0x30
#define OFP_IPTOS_DSCP_AF13		0x38
#define OFP_IPTOS_DSCP_CS2		0x40
#define OFP_IPTOS_DSCP_AF21		0x48
#define OFP_IPTOS_DSCP_AF22		0x50
#define OFP_IPTOS_DSCP_AF23		0x58
#define OFP_IPTOS_DSCP_CS3		0x60
#define OFP_IPTOS_DSCP_AF31		0x68
#define OFP_IPTOS_DSCP_AF32		0x70
#define OFP_IPTOS_DSCP_AF33		0x78
#define OFP_IPTOS_DSCP_CS4		0x80
#define OFP_IPTOS_DSCP_AF41		0x88
#define OFP_IPTOS_DSCP_AF42		0x90
#define OFP_IPTOS_DSCP_AF43		0x98
#define OFP_IPTOS_DSCP_CS5		0xa0
#define OFP_IPTOS_DSCP_EF		0xb8
#define OFP_IPTOS_DSCP_CS6		0xc0
#define OFP_IPTOS_DSCP_CS7		0xe0

/*
 * ECN (Explicit Congestion Notification) codepoints in RFC3168 mapped to the
 * lower 2 bits of the TOS field.
 */
#define OFP_IPTOS_ECN_NOTECT		0x00	/* not-ECT */
#define OFP_IPTOS_ECN_ECT1		0x01	/* ECN-capable transport (1) */
#define OFP_IPTOS_ECN_ECT0		0x02	/* ECN-capable transport (0) */
#define OFP_IPTOS_ECN_CE		0x03	/* congestion experienced */
#define OFP_IPTOS_ECN_MASK		0x03	/* ECN field mask */

/*
 * Definitions for options.
 */
#define OFP_IPOPT_COPIED(o)		((o)&0x80)
#define OFP_IPOPT_CLASS(o)		((o)&0x60)
#define OFP_IPOPT_NUMBER(o)		((o)&0x1f)

#define OFP_IPOPT_CONTROL		0x00
#define OFP_IPOPT_RESERVED1		0x20
#define OFP_IPOPT_DEBMEAS		0x40
#define OFP_IPOPT_RESERVED2		0x60

#define OFP_IPOPT_EOL			0		/* end of option list */
#define OFP_IPOPT_NOP			1		/* no operation */

#define OFP_IPOPT_RR			7		/* record packet route */
#define OFP_IPOPT_TS			68		/* timestamp */
#define OFP_IPOPT_SECURITY		130		/* provide s,c,h,tcc */
#define OFP_IPOPT_LSRR		131		/* loose source route */
#define OFP_IPOPT_ESO			133		/* extended security */
#define OFP_IPOPT_CIPSO		134		/* commerical security */
#define OFP_IPOPT_SATID		136		/* satnet id */
#define OFP_IPOPT_SSRR		137		/* strict source route */
#define OFP_IPOPT_RA			148		/* router alert */

/*
 * Offsets to fields in options other than EOL and NOP.
 */
#define OFP_IPOPT_OPTVAL		0		/* option ID */
#define OFP_IPOPT_OLEN		1		/* option length */
#define OFP_IPOPT_OFFSET		2		/* offset within option */
#define OFP_IPOPT_MINOFF		4		/* min value of above */

/*
 * Time stamp option structure.
 */
struct	ofp_ip_timestamp {
	uint8_t	ipt_code;		/* IPOPT_TS */
	uint8_t	ipt_len;		/* size of structure (variable) */
	uint8_t	ipt_ptr;		/* index of current entry */
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	uint8_t	ipt_flg:4,		/* flags, see below */
		ipt_oflw:4;		/* overflow counter */
#endif
#if ODP_BYTE_ORDER == ODP_BIG_ENDIAN
	uint8_t	ipt_oflw:4,		/* overflow counter */
		ipt_flg:4;		/* flags, see below */
#endif
	union ipt_timestamp {
		uint32_t ipt_time[1];	/* network format */
		struct	ofp_ipt_ta {
			struct ofp_in_addr ipt_addr;
			uint32_t ipt_time;	/* network format */
		} ipt_ta[1];
	} ipt_timestamp;
};

/* Flag bits for ipt_flg. */
#define OFP_IPOPT_TS_TSONLY		0		/* timestamps only */
#define OFP_IPOPT_TS_TSANDADDR	1		/* timestamps and addresses */
#define OFP_IPOPT_TS_PRESPEC		3		/* specified modules only */

/* Bits for security (not byte swapped). */
#define OFP_IPOPT_SECUR_UNCLASS	0x0000
#define OFP_IPOPT_SECUR_CONFID	0xf135
#define OFP_IPOPT_SECUR_EFTO		0x789a
#define OFP_IPOPT_SECUR_MMMM		0xbc4d
#define OFP_IPOPT_SECUR_RESTR		0xaf13
#define OFP_IPOPT_SECUR_SECRET	0xd788
#define OFP_IPOPT_SECUR_TOPSECRET	0x6bc5

/*
 * Internet implementation parameters.
 */
#define OFP_MAXTTL		255		/* maximum time to live (seconds) */
#define OFP_IPDEFTTL		64		/* default ttl, from RFC 1340 */
#define OFP_IPFRAGTTL		60		/* time to live for frags, slowhz */
#define OFP_IPTTLDEC		1		/* subtracted when forwarding */
#define OFP_IP_MSS		576		/* default maximum segment size */

/*
 * This is the real IPv4 pseudo header, used for computing the TCP and UDP
 * checksums. For the Internet checksum, struct ipovly can be used instead.
 * For stronger checksums, the real thing must be used.
 */
struct ofp_ippseudo {
	struct	ofp_in_addr	ippseudo_src;	/* source internet address */
	struct	ofp_in_addr	ippseudo_dst;	/* destination internet address */
	uint8_t		ippseudo_pad;	/* pad, must be zero */
	uint8_t		ippseudo_p;	/* protocol */
	uint16_t		ippseudo_len;	/* protocol length */
};

#if __GNUC__ >= 4
#pragma GCC visibility pop
#endif

#endif
