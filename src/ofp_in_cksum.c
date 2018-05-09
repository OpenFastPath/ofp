/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 *
 */

#include <odp_api.h>
#include "ofpi_in.h"
#include "ofpi_ip.h"
#include "ofpi_log.h"
#include "ofpi_util.h"

static inline uint16_t ofp_cksum_fold(register uint64_t sum)
{
	sum = (sum >> 32) + (sum & 0xffffffff);
	sum = (sum >> 16) + (sum & 0xffff);
	return sum + (sum >> 16);
}

uint16_t ofp_cksum_iph(const void *addr, int ip_hl)
{
	register uint64_t sum = 0;
	const uint16_t *w = (const uint16_t *)addr;
	int odd_word = 0;

	if ((uint64_t)w & 2) {
		sum += *w++;
		ip_hl--;
		odd_word = 1;
	}

	register const uint32_t *d = (const uint32_t *)w;

	sum += *d++;
	sum += *d++;
	sum += *d++;
	sum += *d++;

	ip_hl -= 4;

	if (odp_unlikely(ip_hl)) {
		switch (ip_hl) {
		case 11: sum += *d++; /* FALLTHROUGH */
		case 10: sum += *d++; /* FALLTHROUGH */
		case 9: sum += *d++; /* FALLTHROUGH */
		case 8: sum += *d++; /* FALLTHROUGH */
		case 7: sum += *d++; /* FALLTHROUGH */
		case 6: sum += *d++; /* FALLTHROUGH */
		case 5: sum += *d++; /* FALLTHROUGH */
		case 4: sum += *d++; /* FALLTHROUGH */
		case 3: sum += *d++; /* FALLTHROUGH */
		case 2: sum += *d++; /* FALLTHROUGH */
		case 1: sum += *d++; /* FALLTHROUGH */
		default: break;
		}
	}

	if (odd_word)
		sum += *((const uint16_t *)d);

	return ~ofp_cksum_fold(sum);
}

uint16_t ofp_cksum_buffer(const void *addr, int len)
{
	register int nleft = len;
	register uint64_t sum = 0;

	const uint16_t *w = (const uint16_t *)addr;

	if ((uint64_t)w & 2 && nleft >= 2) {
		sum += *w++;
		nleft -= 2;
	}

	register const uint32_t *d = (const uint32_t *)w;

#ifdef __ARM_ARCH
	/*
	 * On ARM the main loop compiles into ldp (load pair)
	 * instructions, so we need to align to the size of a pair of
	 * dwords, or 8 bytes.
	 */
	if ((uint64_t)d & 4 && nleft >= 4) {
		sum += *d++;
		nleft -= 4;
	}
#endif

	while (nleft >= 32)  {
		sum += *d++;
		sum += *d++;
		sum += *d++;
		sum += *d++;

		sum += *d++;
		sum += *d++;
		sum += *d++;
		sum += *d++;

		nleft -= 32;
	}

	switch (nleft>>2) {
	case 7: sum += *d++; /* FALLTHROUGH */
	case 6: sum += *d++; /* FALLTHROUGH */
	case 5: sum += *d++; /* FALLTHROUGH */
	case 4: sum += *d++; /* FALLTHROUGH */
	case 3: sum += *d++; /* FALLTHROUGH */
	case 2: sum += *d++; /* FALLTHROUGH */
	case 1: sum += *d++; /* FALLTHROUGH */
	default: break;
	}

	nleft &= 3;

	w = (const uint16_t *)d;

	if (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
		sum += odp_cpu_to_be_16(*(const uint8_t *)w << 8);

	return ~ofp_cksum_fold(sum);
}

#define ADDCARRY(x)  (x > 65535 ? x -= 65535 : x)
#define REDUCE do {						\
l_util.l = sum; sum = l_util.s[0] + l_util.s[1]; ADDCARRY(sum);	\
} while (0)

uint16_t ofp_cksum(const odp_packet_t pkt, unsigned int off, unsigned int len)
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
		tmp = ~ofp_cksum_buffer(cksum_data, cksum_len);

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
	return ~sum;
}

struct ofp_ipovly {
	uint8_t  ih_x1[9];             /* (unused) */
	uint8_t  ih_pr;                /* protocol */
	uint16_t ih_len;               /* protocol length */
	struct   ofp_in_addr ih_src;       /* source internet address */
	struct   ofp_in_addr ih_dst;       /* destination internet address */
} __attribute__((__packed__));

uint16_t ofp_in4_cksum(const odp_packet_t pkt)
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
