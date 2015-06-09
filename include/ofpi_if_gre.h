/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/*	$NetBSD: if_gre.h,v 1.13 2003/11/10 08:51:52 wiz Exp $ */
/*	 $FreeBSD: release/9.1.0/sys/net/if_gre.h 223223 2011-06-18 09:34:03Z bz $ */

/*-
 * Copyright (c) 1998 The NetBSD Foundation, Inc.
 * All rights reserved
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Heiko W.Rupp <hwr@pilhuhn.de>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _OFPI_IF_GRE_H
#define _OFPI_IF_GRE_H

struct ofp_gre_h {
	uint16_t flags;	/* GRE flags */
	uint16_t ptype;	/* protocol type of payload typically
				   Ether protocol type*/
	uint32_t options[0];	/* optional options */
/*
 *  from here on: fields are optional, presence indicated by flags
 *
	uint_16 checksum	checksum (one-complements of GRE header
				and payload
				Present if (ck_pres | rt_pres == 1).
				Valid if (ck_pres == 1).
	uint_16 offset		offset from start of routing filed to
				first octet of active SRE (see below).
				Present if (ck_pres | rt_pres == 1).
				Valid if (rt_pres == 1).
	uint_32 key		inserted by encapsulator e.g. for
				authentication
				Present if (key_pres ==1 ).
	uint_32 seq_num	Sequence number to allow for packet order
				Present if (seq_pres ==1 ).
	struct gre_sre[] routing Routing fileds (see below)
				Present if (rt_pres == 1)
 */
} __attribute__((packed));

struct ofp_greip {
	struct ofp_ip gi_i;
	struct ofp_gre_h  gi_g;
} __attribute__((packed));

#define gi_pr		gi_i.ip_p
#define gi_len		gi_i.ip_len
#define gi_src		gi_i.ip_src
#define gi_dst		gi_i.ip_dst
#define gi_ptype	gi_g.ptype
#define gi_flags	gi_g.flags
#define gi_options	gi_g.options

#define OFP_GRE_CP		0x8000  /* Checksum Present */
#define OFP_GRE_RP		0x4000  /* Routing Present */
#define OFP_GRE_KP		0x2000  /* Key Present */
#define OFP_GRE_SP		0x1000  /* Sequence Present */
#define OFP_GRE_SS		0x0800	/* Strict Source Route */

#define OFP_GREPROTO_IP	0x0800

/*
 * gre_sre defines a Source route Entry. These are needed if packets
 * should be routed over more than one tunnel hop by hop
 */
struct ofp_gre_sre {
	uint16_t sre_family;	/* address family */
	uint8_t sre_offset;	/* offset to first octet of active entry */
	uint8_t sre_length;	/* number of octets in the SRE.
				   sre_lengthl==0 -> last entry. */
	uint8_t *sre_rtinfo;	/* the routing information */
};
#endif
