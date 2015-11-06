/*-
 * Copyright (c) 2015 ENEA Software AB
 * Copyright (c) 2015 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "ofpi.h"
#include "ofpi_log.h"
#include "ofpi_debug.h"
#include "ofpi_util.h"

/**
 * Helper function to print a work packet content.
 * Only IP and ARP packets are supported.
 *
 * @param work Work queue entry.
 */
#define ofp_printf(a, b...) do { \
		if (ofp_debug_flags & OFP_DEBUG_PRINT_CONSOLE) {\
			OFP_LOG_NO_CTX_NO_LEVEL(b); \
		} \
		fprintf(a, b); } \
	while (0)

static void print_arp(FILE *f, char *p)
{
	ofp_printf(f, "ARP %d  %s -> %s ",
		p[7],						/* opcode */
		ofp_print_ip_addr(*((uint32_t *)(p+14))),	/* sender IP */
		ofp_print_ip_addr(*((uint32_t *)(p+24))));	/* target IP */
}

static void print_ipv6(FILE *f, char *p)
{
	struct ofp_ip6_hdr *ip6hdr = (struct ofp_ip6_hdr *)p;
	struct ofp_icmp6_hdr *icmp;
	struct ofp_udphdr *uh;

	if (ip6hdr->ofp_ip6_nxt == OFP_IPPROTO_UDP) {
		uh = (struct ofp_udphdr *)(ip6hdr + 1);

		ofp_printf(f, "IPv6 UDP: len=%d  %s port %d -> %s port %d ",
			odp_be_to_cpu_16(uh->uh_ulen),
			ofp_print_ip6_addr(ip6hdr->ip6_src.ofp_s6_addr),
			odp_be_to_cpu_16(uh->uh_sport),
			ofp_print_ip6_addr(ip6hdr->ip6_dst.ofp_s6_addr),
			odp_be_to_cpu_16(uh->uh_dport));
	} else if (ip6hdr->ofp_ip6_nxt == OFP_IPPROTO_ICMPV6) {
		icmp = (struct ofp_icmp6_hdr *)(ip6hdr + 1);

		ofp_printf(f, "IPv6 ICMP: len=%d",
			odp_be_to_cpu_16(ip6hdr->ofp_ip6_plen));

		switch (icmp->icmp6_type) {
		case OFP_ND_ROUTER_SOLICIT:
			ofp_printf(f, " type=Router-Solicitation");
			break;
		case OFP_ND_ROUTER_ADVERT:
			ofp_printf(f, " type=Router-Advertisement %s%s",
				(icmp->ofp_icmp6_data8[1] & 0x80) ? "M" : "",
				(icmp->ofp_icmp6_data8[1] & 0x40) ? "O" : "");
			break;
		case OFP_ND_NEIGHBOR_SOLICIT:
			ofp_printf(f, " type=Neighbor-Solicitation target=%s",
				ofp_print_ip6_addr(icmp->ofp_icmp6_data8 +
						     4));
			break;
		case OFP_ND_NEIGHBOR_ADVERT:
			ofp_printf(f,
				" type=Neighbor-Advertisement %s%s%s target=%s",
				(icmp->ofp_icmp6_data8[0] & 0x80) ? "R" : "",
				(icmp->ofp_icmp6_data8[0] & 0x40) ? "S" : "",
				(icmp->ofp_icmp6_data8[0] & 0x20) ? "O" : "",
				ofp_print_ip6_addr(icmp->ofp_icmp6_data8 +
						     4));
			break;
		case OFP_ND_REDIRECT:
			ofp_printf(f, " type=Redirect target=%s destination=%s",
				ofp_print_ip6_addr(icmp->ofp_icmp6_data8 +
						     4),
				ofp_print_ip6_addr(icmp->ofp_icmp6_data8 +
						     20));
			break;
		default:
			ofp_printf(f, " type=%d", icmp->icmp6_type);
		}

		ofp_printf(f, " code=%d\n", icmp->icmp6_code);
		ofp_printf(f, "  %s -> %s ",
			ofp_print_ip6_addr(ip6hdr->ip6_src.ofp_s6_addr),
			ofp_print_ip6_addr(ip6hdr->ip6_dst.ofp_s6_addr));

	} else {
		ofp_printf(f, "IPv6 PKT: len=%d next=%d %s -> %s ",
			odp_be_to_cpu_16(ip6hdr->ofp_ip6_plen),
			ip6hdr->ofp_ip6_nxt,
			ofp_print_ip6_addr(ip6hdr->ip6_src.ofp_s6_addr),
			ofp_print_ip6_addr(ip6hdr->ip6_dst.ofp_s6_addr));
	}
}

static void print_ipv4(FILE *f, char *p)
{
	struct ofp_ip *iphdr = (struct ofp_ip *)p;
	struct ofp_icmp *icmp;
	struct ofp_udphdr *uh;
	struct ofp_tcphdr *th;

	if (iphdr->ip_p == OFP_IPPROTO_UDP) {
		uh = (struct ofp_udphdr *)(((uint8_t *)iphdr) +
					     (iphdr->ip_hl<<2));

		ofp_printf(f, "IP UDP PKT len=%d  %s:%d -> %s:%d ",
			odp_be_to_cpu_16(uh->uh_ulen),
			ofp_print_ip_addr(iphdr->ip_src.s_addr),
			odp_be_to_cpu_16(uh->uh_sport),
			ofp_print_ip_addr(iphdr->ip_dst.s_addr),
			odp_be_to_cpu_16(uh->uh_dport));

	} else if (iphdr->ip_p == OFP_IPPROTO_TCP) {
		th = (struct ofp_tcphdr *)(((uint8_t *)iphdr) +
					     (iphdr->ip_hl<<2));
		ofp_printf(f, "IP len=%d TCP %s:%d -> %s:%d\n"
			"   seq=0x%x ack=0x%x off=%d\n   flags=",
			odp_be_to_cpu_16(iphdr->ip_len),
			ofp_print_ip_addr(iphdr->ip_src.s_addr),
			odp_be_to_cpu_16(th->th_sport),
			ofp_print_ip_addr(iphdr->ip_dst.s_addr),
			odp_be_to_cpu_16(th->th_dport),
			odp_be_to_cpu_32(th->th_seq),
			odp_be_to_cpu_32(th->th_ack),
			th->th_off);
		if (th->th_flags & OFP_TH_FIN)
			ofp_printf(f, "F");
		if (th->th_flags & OFP_TH_SYN)
			ofp_printf(f, "S");
		if (th->th_flags & OFP_TH_RST)
			ofp_printf(f, "R");
		if (th->th_flags & OFP_TH_PUSH)
			ofp_printf(f, "P");
		if (th->th_flags & OFP_TH_ACK)
			ofp_printf(f, "A");
		if (th->th_flags & OFP_TH_URG)
			ofp_printf(f, "U");
		if (th->th_flags & OFP_TH_ECE)
			ofp_printf(f, "E");
		if (th->th_flags & OFP_TH_CWR)
			ofp_printf(f, "C");
		ofp_printf(f, " win=%u sum=0x%x urp=%u",
			odp_be_to_cpu_16(th->th_win),
			odp_be_to_cpu_16(th->th_sum),
			odp_be_to_cpu_16(th->th_urp));
		int i;
		int len = odp_be_to_cpu_16(iphdr->ip_len);
#if 0
		if (odp_be_to_cpu_16(th->th_win) == 0) {
			/* wrong value */
			ofp_printf(f, "\n---- th_win == 0, quit\n");
			fflush(NULL);
			int *a = 0;
			*a = 8;
		}
#endif
		if (len > 2000) {
			ofp_printf(f, "\nToo long data!\n");
			int *a = 0, b = 8, c = 9;
			*a = b + c;
		} else if (0) {
			for (i = 0; i < len; i++) {
				if ((i & 0xf) == 0)
					ofp_printf(f, "\n");
				ofp_printf(f, " %02x", (uint8_t)p[i]);
			}
		}
	} else if (iphdr->ip_p == OFP_IPPROTO_ICMP) {
		icmp = (struct ofp_icmp *)(((uint8_t *)iphdr) +
					     (iphdr->ip_hl<<2));

		switch (icmp->icmp_type) {
		case OFP_ICMP_ECHOREPLY:
			ofp_printf(f,
				"IP ICMP: echo reply  %s -> %s  id=%d seq=%d",
				ofp_print_ip_addr(iphdr->ip_src.s_addr),
				ofp_print_ip_addr(iphdr->ip_dst.s_addr),
				icmp->ofp_icmp_id, icmp->ofp_icmp_seq);
			break;
		case OFP_ICMP_UNREACH:
			ofp_printf(f, "IP ICMP: dest unreachable  %s -> %s ",
				ofp_print_ip_addr(iphdr->ip_src.s_addr),
				ofp_print_ip_addr(iphdr->ip_dst.s_addr));
			break;
		case OFP_ICMP_ECHO:
			ofp_printf(f, "IP ICMP: echo  %s -> %s  id=%d seq=%d",
				ofp_print_ip_addr(iphdr->ip_src.s_addr),
				ofp_print_ip_addr(iphdr->ip_dst.s_addr),
				icmp->ofp_icmp_id, icmp->ofp_icmp_seq);
			break;
		default:
			ofp_printf(f, "IP ICMP %d: code=%d  %s -> %s ",
				icmp->icmp_type, icmp->icmp_code,
				ofp_print_ip_addr(iphdr->ip_src.s_addr),
				ofp_print_ip_addr(iphdr->ip_dst.s_addr));
		}
	} else {
		ofp_printf(f, "IP PKT len=%d proto=%d  %s -> %s ",
			odp_be_to_cpu_16(iphdr->ip_len),
			iphdr->ip_p,
			ofp_print_ip_addr(iphdr->ip_src.s_addr),
			ofp_print_ip_addr(iphdr->ip_dst.s_addr));
	}
}

static int print_gre(FILE *f, char *p, uint16_t *proto)
{
	int len = 4;
	struct ofp_gre_h *gre = (struct ofp_gre_h *)p;

	p += 4;

	ofp_printf(f, "GRE proto=0x%04x ", odp_be_to_cpu_16(gre->ptype));
	*proto = odp_be_to_cpu_16(gre->ptype);

	if ((gre->flags & OFP_GRE_CP) ||
	    (gre->flags & OFP_GRE_RP)) {
		len += 4; p += 4;
	}

	if (gre->flags & OFP_GRE_KP) {
		ofp_printf(f, "key=0x%02x%02x%02x%02x ", p[0], p[1], p[2], p[3]);
		len += 4; p += 4;
	}

	if (gre->flags & OFP_GRE_SP) {
		ofp_printf(f, "seq=0x%02x%02x%02x%02x ", p[0], p[1], p[2], p[3]);
		len += 4; p += 4;
	}

	if (gre->flags & OFP_GRE_RP)
		ofp_printf(f, "routing ");

	return len;
}

#ifdef PRINT_PACKETS_BINARY
static void print_pkt_binary(odp_packet_t pkt)
{
	uint32_t i;
	uint8_t *pnt = odp_packet_data(pkt);

	OFP_LOG_NO_CTX_NO_LEVEL("PACKET:\n");
	for (i = 0; i < odp_packet_len(pkt); i++)
		OFP_LOG_NO_CTX_NO_LEVEL("%02hhx ", pnt[i]);
	OFP_LOG_NO_CTX_NO_LEVEL("\n");
}
#endif

/* for local debug */
void ofp_print_packet_buffer(const char *comment, uint8_t *p)
{
	static int first = 1;
	FILE *f;
	struct ofp_ip *ip;
	uint16_t proto;
	char *g;

/*
 * Filter "noise"
 */
#if 0
	if (p[12] == 0x00 && p[13] == 0x27)
		return;
	if (p[12] == 0x01 && p[13] == 0x98)
		return;
#endif
	if (first) {
		f = fopen(DEFAULT_DEBUG_TXT_FILE_NAME, "w");
		fclose(f);
		first = 0;
	}

	f = fopen(DEFAULT_DEBUG_TXT_FILE_NAME, "a");

	if (!f)
		return;

	static struct timeval tv0;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	if (tv0.tv_sec == 0)
		tv0 = tv;
	int ms = (tv.tv_sec*1000+tv.tv_usec/1000) -
		(tv0.tv_sec*1000+tv0.tv_usec/1000);

	ofp_printf(f, "\n*************\n");
	ofp_printf(f, "[%d] %s: %d.%03d\n", odp_cpu_id(), comment,
		       ms/1000, ms%1000);
	ofp_printf(f, "%s ->%s\n  ", ofp_print_mac(p+6), ofp_print_mac(p));

	if (p[12] == 0x81 && p[13] == 0x00) {
		ofp_printf(f, "VLAN %d ", (p[14]<<8)|p[15]);
		p += 4;
	}

	if (p[12] == 0x88 && p[13] == 0x47) {
		uint8_t *label = p+14;
		int i;

		ofp_printf(f, "MPLS ");
		while (1) {
			ofp_printf(f, "[label=%d ttl=%d] ",
				label[0]*16*256 + label[1]*16 + label[2]/16,
				label[3]);
			if (label[2] & 1)
				break;
			label += 4;
		}

		if ((label[4] & 0xf0) == 0x40) {
			label[2] = 0x08; /* ipv4 */
			label[3] = 0x00;
		} else {
			label[2] = 0x86; /* ipv6 */
			label[3] = 0xdd;
		}

		label++;
		for (i = 0; i < 12; i++)
			*label-- = p[11 - i];
		p = label+1;
	}

	if (p[12] == 0x08 && p[13] == 0x06) {
		print_arp(f, (char *)(p + L2_HEADER_NO_VLAN_SIZE));
	} else if (p[12] == 0x86 && p[13] == 0xdd) {
		print_ipv6(f, (char *)(p + L2_HEADER_NO_VLAN_SIZE));
	} else if (p[12] == 0x08 && p[13] == 0x00) {
		ip = (struct ofp_ip *)(p + L2_HEADER_NO_VLAN_SIZE);

		if (ip->ip_p == 47) { /* GRE */
			g = ((char *)ip) + (ip->ip_hl << 2);
			g += print_gre(f, g, &proto);
			if (proto == 0x0800)
				print_ipv4(f, g);
			else if (proto == 0x86dd)
				print_ipv6(f, g);
		} else
			print_ipv4(f, (char *)(p + L2_HEADER_NO_VLAN_SIZE));
	} else {
		ofp_printf(f, "UNKNOWN ETH PACKET TYPE 0x%02x%02x ",
			p[12], p[13]);
	}

	ofp_printf(f, "\n");
	fclose(f);
	fflush(stdout);
}

void ofp_print_packet(const char *comment, odp_packet_t pkt)
{
	uint8_t *p;
	uint32_t len;

	p = odp_packet_data(pkt);
	len = odp_packet_len(pkt);
	(void)len;

	ofp_print_packet_buffer(comment, p);

#ifdef PRINT_PACKETS_BINARY
	print_pkt_binary(pkt);
#endif
}
