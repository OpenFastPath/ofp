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
 *	@(#)ip_icmp.h	8.1 (Berkeley) 6/10/93
 */

#ifndef _OFP_ICMP6_H_
#define _OFP_ICMP6_H_

#include <odp.h>

#if __GNUC__ >= 4
#pragma GCC visibility push(default)
#endif

#define OFP_ICMPV6_PLD_MAXLEN	1232	/* IPV6_MMTU - sizeof(struct ip6_hdr)
					   - sizeof(struct icmp6_hdr) */

struct ofp_icmp6_hdr {
	uint8_t	icmp6_type;	/* type field */
	uint8_t	icmp6_code;	/* code field */
	uint16_t	icmp6_cksum;	/* checksum field */
	union {
		uint32_t	icmp6_un_data32[1]; /* type-specific field */
		uint16_t	icmp6_un_data16[2]; /* type-specific field */
		uint8_t	icmp6_un_data8[4];  /* type-specific field */
	} icmp6_dataun;
} __attribute__((packed));

#define ofp_icmp6_data32	icmp6_dataun.icmp6_un_data32
#define ofp_icmp6_data16	icmp6_dataun.icmp6_un_data16
#define ofp_icmp6_data8	icmp6_dataun.icmp6_un_data8
#define ofp_icmp6_pptr		ofp_icmp6_data32[0]	/* parameter prob */
#define ofp_icmp6_mtu		icmp6_data32[0]		/* packet too big */
#define ofp_icmp6_id		icmp6_data16[0]		/* echo request/reply */
#define ofp_icmp6_seq		icmp6_data16[1]		/* echo request/reply */
#define ofp_icmp6_maxdelay	icmp6_data16[0]		/* mcast group membership */

#define OFP_ICMP6_DST_UNREACH			1	/* dest unreachable, codes: */
#define OFP_ICMP6_PACKET_TOO_BIG		2	/* packet too big */
#define OFP_ICMP6_TIME_EXCEEDED		3	/* time exceeded, code: */
#define OFP_ICMP6_PARAM_PROB			4	/* ip6 header bad */

#define OFP_ICMP6_ECHO_REQUEST		128	/* echo service */
#define OFP_ICMP6_ECHO_REPLY			129	/* echo reply */
#define OFP_MLD_LISTENER_QUERY		130	/* multicast listener query */
#define OFP_MLD_LISTENER_REPORT		131	/* multicast listener report */
#define OFP_MLD_LISTENER_DONE			132	/* multicast listener done */
#define OFP_MLD_LISTENER_REDUCTION MLD_LISTENER_DONE /* RFC3542 definition */

/* RFC2292 decls */
#define OFP_ICMP6_MEMBERSHIP_QUERY		130	/* group membership query */
#define OFP_ICMP6_MEMBERSHIP_REPORT		131	/* group membership report */
#define OFP_ICMP6_MEMBERSHIP_REDUCTION	132	/* group membership termination */

/* the followings are for backward compatibility to old KAME apps. */
#define OFP_MLD6_LISTENER_QUERY		MLD_LISTENER_QUERY
#define OFP_MLD6_LISTENER_REPORT		MLD_LISTENER_REPORT
#define OFP_MLD6_LISTENER_DONE		MLD_LISTENER_DONE

#define OFP_ND_ROUTER_SOLICIT			133	/* router solicitation */
#define OFP_ND_ROUTER_ADVERT			134	/* router advertisement */
#define OFP_ND_NEIGHBOR_SOLICIT		135	/* neighbor solicitation */
#define OFP_ND_NEIGHBOR_ADVERT		136	/* neighbor advertisement */
#define OFP_ND_REDIRECT			137	/* redirect */

#define OFP_ICMP6_ROUTER_RENUMBERING		138	/* router renumbering */

#define OFP_ICMP6_WRUREQUEST			139	/* who are you request */
#define OFP_ICMP6_WRUREPLY			140	/* who are you reply */
#define OFP_ICMP6_FQDN_QUERY			139	/* FQDN query */
#define OFP_ICMP6_FQDN_REPLY			140	/* FQDN reply */
#define OFP_ICMP6_NI_QUERY			139	/* node information request */
#define OFP_ICMP6_NI_REPLY			140	/* node information reply */
#define OFP_MLDV2_LISTENER_REPORT		143	/* RFC3810 listener report */

/* The definitions below are experimental. TBA */
#define OFP_MLD_MTRACE_RESP			200	/* mtrace resp (to sender) */
#define OFP_MLD_MTRACE			201	/* mtrace messages */

#define OFP_MLD6_MTRACE_RESP			MLD_MTRACE_RESP
#define OFP_MLD6_MTRACE			MLD_MTRACE

#define OFP_ICMP6_MAXTYPE			201

#define OFP_ICMP6_DST_UNREACH_NOROUTE		0	/* no route to destination */
#define OFP_ICMP6_DST_UNREACH_ADMIN		1	/* administratively prohibited */
#define OFP_ICMP6_DST_UNREACH_NOTNEIGHBOR	2	/* not a neighbor(obsolete) */
#define OFP_ICMP6_DST_UNREACH_BEYONDSCOPE	2	/* beyond scope of source address */
#define OFP_ICMP6_DST_UNREACH_ADDR		3	/* address unreachable */
#define OFP_ICMP6_DST_UNREACH_NOPORT		4	/* port unreachable */

#define OFP_ICMP6_TIME_EXCEED_TRANSIT	0	/* ttl==0 in transit */
#define OFP_ICMP6_TIME_EXCEED_REASSEMBLY	1	/* ttl==0 in reass */

#define OFP_ICMP6_PARAMPROB_HEADER		0	/* erroneous header field */
#define OFP_ICMP6_PARAMPROB_NEXTHEADER	1	/* unrecognized next header */
#define OFP_ICMP6_PARAMPROB_OPTION		2	/* unrecognized option */

#define OFP_ICMP6_INFOMSG_MASK		0x80	/* all informational messages */

#define OFP_ICMP6_NI_SUBJ_IPV6		0	/* Query Subject is an IPv6 address */
#define OFP_ICMP6_NI_SUBJ_FQDN		1	/* Query Subject is a Domain name */
#define OFP_ICMP6_NI_SUBJ_IPV4		2	/* Query Subject is an IPv4 address */

#define OFP_ICMP6_NI_SUCCESS			0	/* node information successful reply */
#define OFP_ICMP6_NI_REFUSED			1	/* node information request is refused */
#define OFP_ICMP6_NI_UNKNOWN			2	/* unknown Qtype */

#define OFP_ICMP6_ROUTER_RENUMBERING_COMMAND  0	/* rr command */
#define OFP_ICMP6_ROUTER_RENUMBERING_RESULT   1	/* rr result */
#define OFP_ICMP6_ROUTER_RENUMBERING_SEQNUM_RESET   255	/* rr seq num reset */

/* Used in kernel only */
#define OFP_ND_REDIRECT_ONLINK		0	/* redirect to an on-link node */
#define OFP_ND_REDIRECT_ROUTER		1	/* redirect to a better router */

/*
 * Multicast Listener Discovery
 */
struct ofp_mld_hdr {
	struct ofp_icmp6_hdr	mld_icmp6_hdr;
	struct ofp_in6_addr   mld_addr; /* multicast address */
} __attribute__((packed));

/* definitions to provide backward compatibility to old KAME applications */
#define ofp_mld6_hdr		mld_hdr
#define ofp_mld6_type		mld_type
#define ofp_mld6_code		mld_code
#define ofp_mld6_cksum	mld_cksum
#define ofp_mld6_maxdelay	mld_maxdelay
#define ofp_mld6_reserved	mld_reserved
#define ofp_mld6_addr		mld_addr

/* shortcut macro definitions */
#define ofp_mld_type		mld_icmp6_hdr.icmp6_type
#define ofp_mld_code		mld_icmp6_hdr.icmp6_code
#define ofp_mld_cksum		mld_icmp6_hdr.icmp6_cksum
#define ofp_mld_maxdelay	mld_icmp6_hdr.icmp6_data16[0]
#define ofp_mld_reserved	mld_icmp6_hdr.icmp6_data16[1]
#define ofp_mld_v2_reserved	mld_icmp6_hdr.icmp6_data16[0]
#define ofp_mld_v2_numrecs	mld_icmp6_hdr.icmp6_data16[1]

/*
 * Neighbor Discovery
 */

struct ofp_nd_router_solicit {	/* router solicitation */
	struct ofp_icmp6_hdr	nd_rs_hdr;
	/* could be followed by options */
} __attribute__((packed));

#define ofp_nd_rs_type	nd_rs_hdr.icmp6_type
#define ofp_nd_rs_code	nd_rs_hdr.icmp6_code
#define ofp_nd_rs_cksum	nd_rs_hdr.icmp6_cksum
#define ofp_nd_rs_reserved	nd_rs_hdr.icmp6_data32[0]

struct ofp_nd_router_advert {	/* router advertisement */
	struct ofp_icmp6_hdr	nd_ra_hdr;
	uint32_t		nd_ra_reachable;	/* reachable time */
	uint32_t		nd_ra_retransmit;	/* retransmit timer */
	/* could be followed by options */
} __attribute__((packed));

#define ofp_nd_ra_type		nd_ra_hdr.icmp6_type
#define ofp_nd_ra_code		nd_ra_hdr.icmp6_code
#define ofp_nd_ra_cksum		nd_ra_hdr.icmp6_cksum
#define ofp_nd_ra_curhoplimit	nd_ra_hdr.icmp6_data8[0]
#define ofp_nd_ra_flags_reserved	nd_ra_hdr.icmp6_data8[1]
#define OFP_ND_RA_FLAG_MANAGED	0x80
#define OFP_ND_RA_FLAG_OTHER	0x40
#define OFP_ND_RA_FLAG_HA		0x20

/*
 * Router preference values based on draft-draves-ipngwg-router-selection-01.
 * These are non-standard definitions.
 */
#define OFP_ND_RA_FLAG_RTPREF_MASK	0x18 /* 00011000 */

#define OFP_ND_RA_FLAG_RTPREF_HIGH	0x08 /* 00001000 */
#define OFP_ND_RA_FLAG_RTPREF_MEDIUM	0x00 /* 00000000 */
#define OFP_ND_RA_FLAG_RTPREF_LOW	0x18 /* 00011000 */
#define OFP_ND_RA_FLAG_RTPREF_RSV	0x10 /* 00010000 */

#define ofp_nd_ra_router_lifetime	nd_ra_hdr.icmp6_data16[1]

struct ofp_nd_neighbor_solicit {	/* neighbor solicitation */
	struct ofp_icmp6_hdr	nd_ns_hdr;
	struct ofp_in6_addr		nd_ns_target;	/*target address */
	/* could be followed by options */
} __attribute__((packed));

#define ofp_nd_ns_type		nd_ns_hdr.icmp6_type
#define ofp_nd_ns_code		nd_ns_hdr.icmp6_code
#define ofp_nd_ns_cksum		nd_ns_hdr.icmp6_cksum
#define ofp_nd_ns_reserved		nd_ns_hdr.icmp6_data32[0]

struct ofp_nd_neighbor_advert {	/* neighbor advertisement */
	struct ofp_icmp6_hdr	nd_na_hdr;
	struct ofp_in6_addr		nd_na_target;	/* target address */
	/* could be followed by options */
} __attribute__((packed));

#define ofp_nd_na_type		nd_na_hdr.icmp6_type
#define ofp_nd_na_code		nd_na_hdr.icmp6_code
#define ofp_nd_na_cksum		nd_na_hdr.icmp6_cksum
#define ofp_nd_na_flags_reserved	nd_na_hdr.icmp6_data32[0]
#if ODP_BYTE_ORDER == ODP_BIG_ENDIAN
#define OFP_ND_NA_FLAG_ROUTER		0x80000000
#define OFP_ND_NA_FLAG_SOLICITED		0x40000000
#define OFP_ND_NA_FLAG_OVERRIDE		0x20000000
#else
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
#define OFP_ND_NA_FLAG_ROUTER		0x80
#define OFP_ND_NA_FLAG_SOLICITED		0x40
#define OFP_ND_NA_FLAG_OVERRIDE		0x20
#endif
#endif

struct ofp_nd_redirect {		/* redirect */
	struct ofp_icmp6_hdr	nd_rd_hdr;
	struct ofp_in6_addr		nd_rd_target;	/* target address */
	struct ofp_in6_addr		nd_rd_dst;	/* destination address */
	/* could be followed by options */
} __attribute__((packed));

#define ofp_nd_rd_type		nd_rd_hdr.icmp6_type
#define ofp_nd_rd_code		nd_rd_hdr.icmp6_code
#define ofp_nd_rd_cksum		nd_rd_hdr.icmp6_cksum
#define ofp_nd_rd_reserved		nd_rd_hdr.icmp6_data32[0]

struct ofp_nd_opt_hdr {		/* Neighbor discovery option header */
	uint8_t	nd_opt_type;
	uint8_t	nd_opt_len;
	/* followed by option specific data*/
} __attribute__((packed));

#define OFP_ND_OPT_SOURCE_LINKADDR		1
#define OFP_ND_OPT_TARGET_LINKADDR		2
#define OFP_ND_OPT_PREFIX_INFORMATION	3
#define OFP_ND_OPT_REDIRECTED_HEADER	4
#define OFP_ND_OPT_MTU			5
#define OFP_ND_OPT_ROUTE_INFO		24	/* RFC 4191 */
#define OFP_ND_OPT_RDNSS			25	/* RFC 6106 */
#define OFP_ND_OPT_DNSSL			31	/* RFC 6106 */

struct ofp_nd_opt_prefix_info {	/* prefix information */
	uint8_t		nd_opt_pi_type;
	uint8_t		nd_opt_pi_len;
	uint8_t		nd_opt_pi_prefix_len;
	uint8_t		nd_opt_pi_flags_reserved;
	uint32_t	nd_opt_pi_valid_time;
	uint32_t	nd_opt_pi_preferred_time;
	uint32_t	nd_opt_pi_reserved2;
	struct ofp_in6_addr	nd_opt_pi_prefix;
} __attribute__((packed));

#define OFP_ND_OPT_PI_FLAG_ONLINK		0x80
#define OFP_ND_OPT_PI_FLAG_AUTO		0x40

struct ofp_nd_opt_rd_hdr {		/* redirected header */
	uint8_t		nd_opt_rh_type;
	uint8_t		nd_opt_rh_len;
	uint16_t	nd_opt_rh_reserved1;
	uint32_t	nd_opt_rh_reserved2;
	/* followed by IP header and data */
} __attribute__((packed));

struct ofp_nd_opt_mtu {		/* MTU option */
	uint8_t		nd_opt_mtu_type;
	uint8_t		nd_opt_mtu_len;
	uint16_t	nd_opt_mtu_reserved;
	uint32_t	nd_opt_mtu_mtu;
} __attribute__((packed));

struct ofp_nd_opt_route_info {	/* route info */
	uint8_t		nd_opt_rti_type;
	uint8_t		nd_opt_rti_len;
	uint8_t		nd_opt_rti_prefixlen;
	uint8_t		nd_opt_rti_flags;
	uint32_t	nd_opt_rti_lifetime;
	/* prefix follows */
} __attribute__((packed));

struct ofp_nd_opt_rdnss {		/* RDNSS option (RFC 6106) */
	uint8_t		nd_opt_rdnss_type;
	uint8_t		nd_opt_rdnss_len;
	uint16_t	nd_opt_rdnss_reserved;
	uint32_t	nd_opt_rdnss_lifetime;
	/* followed by list of recursive DNS servers */
} __attribute__((packed));

struct ofp_nd_opt_dnssl {		/* DNSSL option (RFC 6106) */
	uint8_t		nd_opt_dnssl_type;
	uint8_t		nd_opt_dnssl_len;
	uint16_t	nd_opt_dnssl_reserved;
	uint32_t	nd_opt_dnssl_lifetime;
	/* followed by list of DNS search domains */
} __attribute__((packed));

/*
 * icmp6 namelookup
 */

struct ofp_icmp6_namelookup {
	struct ofp_icmp6_hdr	icmp6_nl_hdr;
	uint8_t		icmp6_nl_nonce[8];
	int32_t		icmp6_nl_ttl;
#if 0
	uint8_t		icmp6_nl_len;
	uint8_t		icmp6_nl_name[3];
#endif
	/* could be followed by options */
} __attribute__((packed));

/*
 * icmp6 node information
 */
struct ofp_icmp6_nodeinfo {
	struct ofp_icmp6_hdr icmp6_ni_hdr;
	uint8_t icmp6_ni_nonce[8];
	/* could be followed by reply data */
} __attribute__((packed));

#define ofp_ni_type	icmp6_ni_hdr.icmp6_type
#define ofp_ni_code	icmp6_ni_hdr.icmp6_code
#define ofp_ni_cksum	icmp6_ni_hdr.icmp6_cksum
#define ofp_ni_qtype	icmp6_ni_hdr.icmp6_data16[0]
#define ofp_ni_flags	icmp6_ni_hdr.icmp6_data16[1]

#define OFP_NI_QTYPE_NOOP		0 /* NOOP  */
#define OFP_NI_QTYPE_SUPTYPES		1 /* Supported Qtypes */
#define OFP_NI_QTYPE_FQDN		2 /* FQDN (draft 04) */
#define OFP_NI_QTYPE_DNSNAME		2 /* DNS Name */
#define OFP_NI_QTYPE_NODEADDR		3 /* Node Addresses */
#define OFP_NI_QTYPE_IPV4ADDR		4 /* IPv4 Addresses */

#if ODP_BYTE_ORDER == ODP_BIG_ENDIAN
#define OFP_NI_SUPTYPE_FLAG_COMPRESS	0x1
#define OFP_NI_FQDN_FLAG_VALIDTTL	0x1
#elif ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
#define OFP_NI_SUPTYPE_FLAG_COMPRESS	0x0100
#define OFP_NI_FQDN_FLAG_VALIDTTL	0x0100
#endif

#ifdef NAME_LOOKUPS_04
#if ODP_BYTE_ORDER == ODP_BIG_ENDIAN
#define OFP_NI_NODEADDR_FLAG_LINKLOCAL	0x1
#define OFP_NI_NODEADDR_FLAG_SITELOCAL	0x2
#define OFP_NI_NODEADDR_FLAG_GLOBAL		0x4
#define OFP_NI_NODEADDR_FLAG_ALL		0x8
#define OFP_NI_NODEADDR_FLAG_TRUNCATE		0x10
#define OFP_NI_NODEADDR_FLAG_ANYCAST		0x20 /* just experimental. not in spec */
#elif ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
#define OFP_NI_NODEADDR_FLAG_LINKLOCAL	0x0100
#define OFP_NI_NODEADDR_FLAG_SITELOCAL	0x0200
#define OFP_NI_NODEADDR_FLAG_GLOBAL		0x0400
#define OFP_NI_NODEADDR_FLAG_ALL		0x0800
#define OFP_NI_NODEADDR_FLAG_TRUNCATE		0x1000
#define OFP_NI_NODEADDR_FLAG_ANYCAST		0x2000 /* just experimental. not in spec */
#endif
#else  /* draft-ietf-ipngwg-icmp-name-lookups-05 (and later?) */
#if ODP_BYTE_ORDER == ODP_BIG_ENDIAN
#define OFP_NI_NODEADDR_FLAG_TRUNCATE		0x1
#define OFP_NI_NODEADDR_FLAG_ALL		0x2
#define OFP_NI_NODEADDR_FLAG_COMPAT		0x4
#define OFP_NI_NODEADDR_FLAG_LINKLOCAL	0x8
#define OFP_NI_NODEADDR_FLAG_SITELOCAL	0x10
#define OFP_NI_NODEADDR_FLAG_GLOBAL		0x20
#define OFP_NI_NODEADDR_FLAG_ANYCAST		0x40 /* just experimental. not in spec */
#elif ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
#define OFP_NI_NODEADDR_FLAG_TRUNCATE		0x0100
#define OFP_NI_NODEADDR_FLAG_ALL		0x0200
#define OFP_NI_NODEADDR_FLAG_COMPAT		0x0400
#define OFP_NI_NODEADDR_FLAG_LINKLOCAL	0x0800
#define OFP_NI_NODEADDR_FLAG_SITELOCAL	0x1000
#define OFP_NI_NODEADDR_FLAG_GLOBAL		0x2000
#define OFP_NI_NODEADDR_FLAG_ANYCAST		0x4000 /* just experimental. not in spec */
#endif
#endif

struct ofp_ni_reply_fqdn {
	uint32_t ni_fqdn_ttl;	/* TTL */
	uint8_t ni_fqdn_namelen; /* length in octets of the FQDN */
	uint8_t ni_fqdn_name[3]; /* XXX: alignment */
} __attribute__((packed));

/*
 * Router Renumbering. as router-renum-08.txt
 */
struct ofp_icmp6_router_renum {	/* router renumbering header */
	struct ofp_icmp6_hdr	rr_hdr;
	uint8_t		rr_segnum;
	uint8_t		rr_flags;
	uint16_t	rr_maxdelay;
	uint32_t	rr_reserved;
} __attribute__((packed));

#define OFP_ICMP6_RR_FLAGS_TEST	0x80
#define OFP_ICMP6_RR_FLAGS_REQRESULT	0x40
#define OFP_ICMP6_RR_FLAGS_FORCEAPPLY	0x20
#define OFP_ICMP6_RR_FLAGS_SPECSITE	0x10
#define OFP_ICMP6_RR_FLAGS_PREVDONE	0x08

#define OFP_rr_type		rr_hdr.icmp6_type
#define OFP_rr_code		rr_hdr.icmp6_code
#define OFP_rr_cksum		rr_hdr.icmp6_cksum
#define OFP_rr_seqnum	rr_hdr.icmp6_data32[0]

struct ofp_rr_pco_match {		/* match prefix part */
	uint8_t	rpm_code;
	uint8_t	rpm_len;
	uint8_t	rpm_ordinal;
	uint8_t	rpm_matchlen;
	uint8_t	rpm_minlen;
	uint8_t	rpm_maxlen;
	uint16_t	rpm_reserved;
	struct	ofp_in6_addr	rpm_prefix;
} __attribute__((packed));

#define OFP_RPM_PCO_ADD	1
#define OFP_RPM_PCO_CHANGE	2
#define OFP_RPM_PCO_SETGLOBAL	3
#define OFP_RPM_PCO_MAX	4

struct ofp_rr_pco_use {		/* use prefix part */
	uint8_t		rpu_uselen;
	uint8_t		rpu_keeplen;
	uint8_t		rpu_ramask;
	uint8_t		rpu_raflags;
	uint32_t	rpu_vltime;
	uint32_t	rpu_pltime;
	uint32_t	rpu_flags;
	struct	ofp_in6_addr rpu_prefix;
} __attribute__((packed));
#define OFP_ICMP6_RR_PCOUSE_RAFLAGS_ONLINK	0x80
#define OFP_ICMP6_RR_PCOUSE_RAFLAGS_AUTO	0x40

#if ODP_BYTE_ORDER == ODP_BIG_ENDIAN
#define OFP_ICMP6_RR_PCOUSE_FLAGS_DECRVLTIME     0x80000000
#define OFP_ICMP6_RR_PCOUSE_FLAGS_DECRPLTIME     0x40000000
#elif ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
#define OFP_ICMP6_RR_PCOUSE_FLAGS_DECRVLTIME     0x80
#define OFP_ICMP6_RR_PCOUSE_FLAGS_DECRPLTIME     0x40
#endif

struct ofp_rr_result {		/* router renumbering result message */
	uint16_t	rrr_flags;
	uint8_t		rrr_ordinal;
	uint8_t		rrr_matchedlen;
	uint32_t	rrr_ifid;
	struct	ofp_in6_addr rrr_prefix;
} __attribute__((packed));
#if ODP_BYTE_ORDER == ODP_BIG_ENDIAN
#define OFP_ICMP6_RR_RESULT_FLAGS_OOB		0x0002
#define OFP_ICMP6_RR_RESULT_FLAGS_FORBIDDEN	0x0001
#elif ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
#define OFP_ICMP6_RR_RESULT_FLAGS_OOB		0x0200
#define OFP_ICMP6_RR_RESULT_FLAGS_FORBIDDEN	0x0100
#endif

#define OFP_ICMP6_NODEINFO_FQDNOK		0x1
#define OFP_ICMP6_NODEINFO_NODEADDROK	0x2
#define OFP_ICMP6_NODEINFO_TMPADDROK	0x4
#define OFP_ICMP6_NODEINFO_GLOBALOK		0x8

#if __GNUC__ >= 4
#pragma GCC visibility pop
#endif

#endif /* not _OFP_ICMP6_H_ */
