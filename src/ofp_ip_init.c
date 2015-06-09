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
#include "ofpi_ip_var.h"
#include "ofpi_protosw.h"


uint8_t ofp_ip_protox[OFP_IPPROTO_MAX];
uint8_t ofp_ip_protox_udp;
uint8_t ofp_ip_protox_tcp;
uint8_t ofp_ip_protox_gre;

/*
 * IP initialization: fill in IP protocol switch table.
 * All protocols not implemented go to slow path.
 */
void ofp_ip_init(void)
{
	struct protosw *pr;
	int i;

	for (i = 0; i < OFP_IPPROTO_MAX; i++)
		ofp_ip_protox[i] = 0;

	for (pr = ofp_inetdomain.dom_protosw;
	    pr < ofp_inetdomain.dom_protoswNPROTOSW; pr++)
		if (pr->pr_protocol < OFP_IPPROTO_MAX)
			ofp_ip_protox[pr->pr_protocol] = pr -
				ofp_inetdomain.dom_protosw;
	ofp_ip_protox_udp = ofp_ip_protox[OFP_IPPROTO_UDP];
	ofp_ip_protox_tcp = ofp_ip_protox[OFP_IPPROTO_TCP];
	ofp_ip_protox_gre = ofp_ip_protox[OFP_IPPROTO_GRE];
}

#ifdef VIMAGE
void	ofp_ip_destroy(void)
{
}
#endif

int ofp_ip_input(odp_packet_t pkt, int off)
{
	(void)pkt;
	(void)off;

	return OFP_PKT_CONTINUE;
}
