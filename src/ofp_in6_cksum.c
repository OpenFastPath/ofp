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
 *
 *	$KAME: in6_cksum.c,v 1.10 2000/12/03 00:53:59 itojun Exp $
 */

/*-
 * Copyright (c) 1988, 1992, 1993
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
 *	@(#)in_cksum.c	8.1 (Berkeley) 6/10/93
 */


#include <odp_api.h>
#include "ofpi_in.h"
#include "ofpi_in6.h"
#include "ofpi_ip6.h"
#include "ofpi_util.h"

/*
 * Checksum routine for Internet Protocol family headers (Portable Version).
 *
 * This routine is very heavily used in the network
 * code and should be modified for each CPU to be as fast as possible.
 */

#define ADDCARRY(x)  (x > 65535 ? x -= 65535 : x)
#define REDUCE do { \
	l_util.l = sum; sum = l_util.s[0] + l_util.s[1]; (void)ADDCARRY(sum); \
} while (0)

static int
_ofp_in6_cksum_pseudo(struct ofp_ip6_hdr *ip6, uint32_t len,
		uint8_t nxt, uint16_t csum)
{
	int sum;
	uint16_t scope = 0, *w;

	union {
		uint16_t phs[4];
		struct __attribute__ ((__packed__)) {
			uint32_t	ph_len;
			uint8_t	ph_zero[3];
			uint8_t	ph_nxt;
		} ph;
	} uph;

	sum = csum;

	/*
	 * First create IP6 pseudo header and calculate a summary.
	 */
	uph.ph.ph_len = odp_cpu_to_be_32(len);
	uph.ph.ph_zero[0] = uph.ph.ph_zero[1] = uph.ph.ph_zero[2] = 0;
	uph.ph.ph_nxt = nxt;

	/* Payload length and upper layer identifier. */
	sum += uph.phs[0];  sum += uph.phs[1];
	sum += uph.phs[2];  sum += uph.phs[3];

	/* IPv6 source address. */
	scope = ofp_in6_getscope(&ip6->ip6_src);
	w = (uint16_t *)&ip6->ip6_src;
	sum += w[0]; sum += w[1]; sum += w[2]; sum += w[3];
	sum += w[4]; sum += w[5]; sum += w[6]; sum += w[7];
	if (scope != 0)
		sum -= scope;

	/* IPv6 destination address. */
	scope = ofp_in6_getscope(&ip6->ip6_dst);
	w = (uint16_t *)&ip6->ip6_dst;
	sum += w[0]; sum += w[1]; sum += w[2]; sum += w[3];
	sum += w[4]; sum += w[5]; sum += w[6]; sum += w[7];
	if (scope != 0)
		sum -= scope;

	return sum;
}

int ofp_in6_cksum_pseudo(struct ofp_ip6_hdr *ip6,
		uint32_t len, uint8_t nxt, uint16_t csum)
{
	int sum;
	union {
		uint16_t s[2];
		uint32_t l;
	} l_util;

	sum = _ofp_in6_cksum_pseudo(ip6, len, nxt, csum);
	REDUCE;
	return sum;
}
int ofp_in6_cksum(odp_packet_t m, uint8_t nxt, uint32_t off, uint32_t len)
{
	int sum;
	uint16_t tmp;
	union {
		uint16_t s[2];
		uint32_t l;
	} l_util;
	struct ofp_ip6_hdr *ip6 = odp_packet_l3_ptr(m, NULL);

/*Pseudo header*/
	sum  = _ofp_in6_cksum_pseudo(ip6, len, nxt, 0);

/* Payload*/
	tmp = ~ofp_cksum(m, odp_packet_l3_offset(m) +
			off, len);
	sum += tmp;

	REDUCE;
	return (~sum & 0xffff);
}
