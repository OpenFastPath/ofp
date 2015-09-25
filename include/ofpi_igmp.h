/*-
 * Copyright (c) 1988 Stephen Deering.
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Stephen Deering of Stanford University.
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
 *	@(#)igmp.h	8.1 (Berkeley) 6/10/93
 * $FreeBSD: release/9.1.0/sys/netinet/igmp.h 193938 2009-06-10 18:12:15Z imp $
 */

#ifndef _NETINET_IGMP_H_
#define _NETINET_IGMP_H_

/*
 * Internet Group Management Protocol (IGMP) definitions.
 *
 * Written by Steve Deering, Stanford, May 1988.
 *
 * MULTICAST Revision: 3.5.1.2
 */

/* Minimum length of any IGMP protocol message. */
#define IGMP_MINLEN			8

/*
 * IGMPv1/v2 query and host report format.
 */
struct igmp {
	uint8_t		igmp_type;	/* version & type of IGMP message  */
	uint8_t		igmp_code;	/* subtype for routing msgs        */
	uint16_t		igmp_cksum;	/* IP-style checksum               */
	struct ofp_in_addr	igmp_group;	/* group address being reported    */
};					/*  (zero for queries)             */

/*
 * IGMP v3 query format.
 */
struct igmpv3 {
	uint8_t		igmp_type;	/* version & type of IGMP message  */
	uint8_t		igmp_code;	/* subtype for routing msgs        */
	uint16_t		igmp_cksum;	/* IP-style checksum               */
	struct ofp_in_addr	igmp_group;	/* group address being reported    */
					/*  (zero for queries)             */
	uint8_t		igmp_misc;	/* reserved/suppress/robustness    */
	uint8_t		igmp_qqi;	/* querier's query interval        */
	uint16_t		igmp_numsrc;	/* number of sources               */
	/*struct ofp_in_addr	igmp_sources[1];*/ /* source addresses */
};
#define IGMP_V3_QUERY_MINLEN		12
#define IGMP_EXP(x)			(((x) >> 4) & 0x07)
#define IGMP_MANT(x)			((x) & 0x0f)
#define IGMP_QRESV(x)			(((x) >> 4) & 0x0f)
#define IGMP_SFLAG(x)			(((x) >> 3) & 0x01)
#define IGMP_QRV(x)			((x) & 0x07)

struct igmp_grouprec {
	uint8_t		ig_type;	/* record type */
	uint8_t		ig_datalen;	/* length of auxiliary data */
	uint16_t		ig_numsrc;	/* number of sources */
	struct ofp_in_addr	ig_group;	/* group address being reported */
	/*struct ofp_in_addr	ig_sources[1];*/ /* source addresses */
};
#define IGMP_GRPREC_HDRLEN		8

/*
 * IGMPv3 host membership report header.
 */
struct igmp_report {
	uint8_t		ir_type;	/* IGMP_v3_HOST_MEMBERSHIP_REPORT */
	uint8_t		ir_rsv1;	/* must be zero */
	uint16_t		ir_cksum;	/* checksum */
	uint16_t		ir_rsv2;	/* must be zero */
	uint16_t		ir_numgrps;	/* number of group records */
	/*struct	igmp_grouprec ir_groups[1];*/	/* group records */
};
#define IGMP_V3_REPORT_MINLEN		8
#define IGMP_V3_REPORT_MAXRECS		65535

/*
 * Message types, including version number.
 */
#define IGMP_HOST_MEMBERSHIP_QUERY	0x11	/* membership query         */
#define IGMP_v1_HOST_MEMBERSHIP_REPORT	0x12	/* Ver. 1 membership report */
#define IGMP_DVMRP			0x13	/* DVMRP routing message    */
#define IGMP_PIM			0x14	/* PIMv1 message (historic) */
#define IGMP_v2_HOST_MEMBERSHIP_REPORT	0x16	/* Ver. 2 membership report */
#define IGMP_HOST_LEAVE_MESSAGE		0x17	/* Leave-group message     */
#define IGMP_MTRACE_REPLY		0x1e	/* mtrace(8) reply */
#define IGMP_MTRACE_QUERY		0x1f	/* mtrace(8) probe */
#define IGMP_v3_HOST_MEMBERSHIP_REPORT	0x22	/* Ver. 3 membership report */

/*
 * IGMPv3 report modes.
 */
#define IGMP_DO_NOTHING			0	/* don't send a record */
#define IGMP_MODE_IS_INCLUDE		1	/* MODE_IN */
#define IGMP_MODE_IS_EXCLUDE		2	/* MODE_EX */
#define IGMP_CHANGE_TO_INCLUDE_MODE	3	/* TO_IN */
#define IGMP_CHANGE_TO_EXCLUDE_MODE	4	/* TO_EX */
#define IGMP_ALLOW_NEW_SOURCES		5	/* ALLOW_NEW */
#define IGMP_BLOCK_OLD_SOURCES		6	/* BLOCK_OLD */

/*
 * IGMPv3 query types.
 */
#define IGMP_V3_GENERAL_QUERY		1
#define IGMP_V3_GROUP_QUERY		2
#define IGMP_V3_GROUP_SOURCE_QUERY	3

/*
 * Maximum report interval for IGMP v1/v2 host membership reports [RFC 1112]
 */
#define IGMP_V1V2_MAX_RI		10
#define IGMP_MAX_HOST_REPORT_DELAY	IGMP_V1V2_MAX_RI

/*
 * IGMP_TIMER_SCALE denotes that the igmp code field specifies
 * time in tenths of a second.
 */
#define IGMP_TIMER_SCALE		10

struct socket;
struct sockopt;
int ofp_ip_ctloutput(struct socket *so, struct sockopt *sopt);

#endif /* _NETINET_IGMP_H_ */
