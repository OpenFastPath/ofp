/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 *
 */

#include "odp.h"
#include "ofpi_in.h"
#include "ofpi_ip.h"
#include "ofpi_log.h"
#include "ofpi_util.h"

uint16_t ofp_cksum_buffer(register uint16_t *addr, register int len)
{
	register int nleft = len;
	register uint16_t *w = addr;
	register uint16_t answer;
	register int sum = 0;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1)
		sum += odp_cpu_to_be_16(*(u_char *)w << 8);

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
	sum += (sum >> 16);                 /* add carry */
	answer = ~sum;                      /* truncate to 16 bits */
	return answer;
}

#define ADDCARRY(x)  (x > 65535 ? x -= 65535 : x)
#define REDUCE do {						\
l_util.l = sum; sum = l_util.s[0] + l_util.s[1]; ADDCARRY(sum);	\
} while (0)

static int __ofp_cksum(const odp_packet_t pkt, unsigned int off,
			 unsigned int len)
{
	int sum = 0;
	uint16_t tmp = 0;
	odp_packet_seg_t seg;
	uint32_t seglen, cksum_len, done = 0;
	uint8_t *cksum_data;
	union {
		uint16_t s[2];
		uint32_t l;
	} l_util;

	seg = odp_packet_first_seg(pkt);
	while (seg != ODP_PACKET_SEG_INVALID) {
		seglen = odp_packet_seg_data_len(pkt, seg);

		if (off >= seglen) {
			off -= seglen;
			continue;
		}

		cksum_len = seglen - off;
		if (cksum_len > len)
			cksum_len = len;

		cksum_data = (uint8_t *)odp_packet_seg_data(pkt, seg) + off;
		tmp = ~ofp_cksum_buffer((uint16_t *)cksum_data, cksum_len);

		/* swap bytes on odd boundary */
		if (done % 2)
			tmp = ((tmp&0x00ff) << 8) | ((tmp&0xff00) >> 8);

		sum += tmp;
		off = 0;
		done += cksum_len;

		if (done == len)
			break;

		seg = odp_packet_next_seg(pkt, seg);
	}

	REDUCE;
	return sum;
}

int ofp_cksum(const odp_packet_t pkt, unsigned int off, unsigned int len)
{
	return (~__ofp_cksum(pkt, off, len)) & 0xffff;
}

int ofp_getsum(const odp_packet_t pkt, unsigned int off, unsigned int len)
{
	return __ofp_cksum(pkt, off, len);
}

struct ofp_ipovly {
	uint8_t  ih_x1[9];             /* (unused) */
	uint8_t  ih_pr;                /* protocol */
	uint16_t ih_len;               /* protocol length */
	struct   ofp_in_addr ih_src;       /* source internet address */
	struct   ofp_in_addr ih_dst;       /* destination internet address */
} __attribute__((__packed__));

static inline int __ofp_in4_cksum(const odp_packet_t pkt)
{
	struct ofp_ip *ip;
	int off, len, sum = 0;
	uint16_t *w, tmp;
	union {
		uint16_t s[2];
		uint32_t l;
	} l_util;
	union {
		struct ofp_ipovly ipov;
		uint16_t w[10];
	} u;

	ip = (struct ofp_ip *)odp_packet_l3_ptr(pkt, NULL);
	off = ip->ip_hl << 2;
	/* pseudo header used to compute UDP checksum */
	memset(&u.ipov, 0, sizeof(u.ipov));
	u.ipov.ih_len = odp_cpu_to_be_16(odp_be_to_cpu_16(ip->ip_len) - off);
	u.ipov.ih_pr = ip->ip_p;
	u.ipov.ih_src = ip->ip_src;
	u.ipov.ih_dst = ip->ip_dst;
	w = u.w;
	/* assumes sizeof(ipov) == 20 */
	sum += w[0]; sum += w[1]; sum += w[2]; sum += w[3]; sum += w[4];
	sum += w[5]; sum += w[6]; sum += w[7]; sum += w[8]; sum += w[9];

	len = odp_be_to_cpu_16(ip->ip_len) - off;
	tmp = ~ofp_cksum(pkt, odp_packet_l3_offset(pkt) + off, len);
	sum += tmp;
	REDUCE;
	return (~sum & 0xffff);
}

int ofp_in4_cksum(const odp_packet_t pkt)
{
	return __ofp_in4_cksum(pkt);
}

