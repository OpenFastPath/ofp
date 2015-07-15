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
 *	$KAME: ip6_input.c,v 1.259 2002/01/21 04:58:09 jinmei Exp $
 */

/*-
 * Copyright (c) 1982, 1986, 1988, 1993
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
 *	@(#)ip_input.c	8.2 (Berkeley) 1/4/94
 */

#include <odp.h>
#include "api/ofp_types.h"
#include "ofpi_in.h"
#include "ofpi_ip6_var.h"
#include "ofpi_protosw.h"
#include "ofpi_ip6protosw.h"
#include "ofpi_icmp6.h"
#include "ofpi_log.h"
#include "ofpi_util.h"

uint8_t ofp_ip6_protox[OFP_IPPROTO_MAX];

/*
 * IP6 initialization: fill in IP6 protocol switch table.
 * All protocols not implemented go to slow path.
 */
void	ofp_ip6_init(void)
{
	struct ip6protosw *pr;
	int i;

	for (i = 0; i < OFP_IPPROTO_MAX; i++)
		ofp_ip6_protox[i] = 0;

	for (pr = (struct ip6protosw *)ofp_inet6domain.dom_protosw;
	    pr < (struct ip6protosw *)ofp_inet6domain.dom_protoswNPROTOSW;
	    pr++) {
		ofp_ip6_protox[pr->pr_protocol] = pr -
			(struct ip6protosw *)ofp_inet6domain.dom_protosw;
	}
}

#ifdef VIMAGE
void	ofp_ip6_destroy(void)
{
}
#endif

int ofp_ip6_input(odp_packet_t pkt, int *offp, int *nxt)
{
	(void)pkt;
	(void)offp;

	*nxt = OFP_IPPROTO_SP;
	return OFP_PKT_CONTINUE;
}

int ofp_ip6_none_input(odp_packet_t pkt, int *offp, int *nxt)
{
	(void)pkt;
	(void)offp;

	*nxt = OFP_IPPROTO_DONE;
	return OFP_PKT_PROCESSED;
}

int ofp_ip6_unrecognized_hdr_input(odp_packet_t pkt, int *offp, int *nxt)
{
	(void)offp;

	ofp_icmp6_error(pkt, OFP_ICMP6_PARAM_PROB,
		OFP_ICMP6_PARAMPROB_NEXTHEADER, 0);

	*nxt = OFP_IPPROTO_DONE;
	return OFP_PKT_DROP;
}
