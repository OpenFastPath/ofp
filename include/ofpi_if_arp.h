/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/*-
 * Copyright (c) 1986, 1993
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
 *	@(#)if_arp.h	8.1 (Berkeley) 6/10/93
 * $FreeBSD: release/9.1.0/sys/net/if_arp.h 219819 2011-03-21 09:40:01Z jeff $
 */

#ifndef _OFPI_IF_ARP_H_
#define	_OFPI_IF_ARP_H_

/*
 * Address Resolution Protocol.
 *
 * See RFC 826 for protocol description.  ARP packets are variable
 * in size; the arphdr structure defines the fixed-length portion.
 * Protocol type values are the same as those for 10 Mb/s Ethernet.
 * It is followed by the variable-sized fields ar_sha, arp_spa,
 * arp_tha and arp_tpa in that order, according to the lengths
 * specified.  Field names used correspond to RFC 826.
 */
struct	ofp_arphdr {
	uint16_t hrd;			/* format of hardware address */
#define OFP_ARPHDR_ETHER	1	/* ethernet hardware format */
#define OFP_ARPHDR_IEEE802	6	/* token-ring hardware format */
#define OFP_ARPHDR_ARCNET	7	/* arcnet hardware format */
#define OFP_ARPHDR_FRELAY	15	/* frame relay hardware format */
#define OFP_ARPHDR_IEEE1394	24	/* firewire hardware format */
#define OFP_ARPHDR_INFINIBAND 32	/* infiniband hardware format */
	uint16_t pro;			/* format of protocol address */
	uint8_t  hln;			/* length of hardware address */
	uint8_t  pln;			/* length of protocol address */
	uint16_t op;			/* one of: */
#define	OFP_ARPOP_REQUEST	1	/* request to resolve address */
#define	OFP_ARPOP_REPLY	2	/* response to previous request */
#define	OFP_ARPOP_REVREQUEST	3	/* request protocol address given hardware */
#define	OFP_ARPOP_REVREPLY	4	/* response giving protocol address */
#define OFP_ARPOP_INVREQUEST	8	/* request to identify peer */
#define OFP_ARPOP_INVREPLY	9	/* response identifying peer */
	uint8_t  eth_src[OFP_ETHER_ADDR_LEN];
	uint32_t ip_src;

	uint8_t  eth_dst[OFP_ETHER_ADDR_LEN];
	uint32_t ip_dst;
} __attribute__((packed));

#endif
