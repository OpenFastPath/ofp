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
 *	$KAME: in6_proto.c,v 1.91 2001/05/27 13:28:35 itojun Exp $
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
 *	@(#)in_proto.c	8.1 (Berkeley) 6/10/93
 */

#include "ofpi_in.h"
#include "ofpi_in_pcb.h"
#include "ofpi_protosw.h"
#include "ofpi_tcp_var.h"
#include "ofpi_ip6protosw.h"
#include "ofpi_udp6_var.h"
#include "ofpi_tcp6_var.h"
#include "ofpi_domain.h"
#include "ofpi_ip6.h"
#include "ofpi_ip6_var.h"
#include "ofpi_socket.h"
#include "ofpi_icmp6.h"

/*
 * TCP/IP protocol family: IP6, ICMP6, UDP, TCP.
 */

extern	struct pr_usrreqs nousrreqs;

#define PR_LISTEN	0
#define PR_ABRTACPTDIS	0

/* Spacer for loadable protocols. */
#define IP6PROTOSPACER				\
{						\
	.pr_domain =		&ofp_inet6domain,	\
	.pr_protocol =		PROTO_SPACER,	\
	.pr_usrreqs =		&nousrreqs	\
}

struct ip6protosw ofp_inet6sw[] = {
{
	.pr_type =		0,
	.pr_domain =		&ofp_inet6domain,
	.pr_protocol =		OFP_IPPROTO_IPV6,
	.pr_init =		ofp_ip6_init,
#ifdef VIMAGE
	.pr_destroy =		ofp_ip6_destroy,
#else
	.pr_destroy =		NULL,
#endif
	.pr_input =		ofp_ip6_input,
	.pr_ctlinput =		NULL,
	.pr_ctloutput =		NULL,
	.pr_usrreqs =		&nousrreqs
},
{
	.pr_type =		OFP_SOCK_DGRAM,
	.pr_domain =		&ofp_inet6domain,
	.pr_protocol =		OFP_IPPROTO_UDP,
	.pr_flags =		PR_ATOMIC|PR_ADDR,
	.pr_input =		ofp_udp6_input,
	.pr_ctlinput =		ofp_udp6_ctlinput,
	.pr_ctloutput =		NULL, /*ip6_ctloutput,*/
#ifndef INET	/* Do not call initialization twice. */
	.pr_init =		ofp_udp_init,
	.pr_destroy =		ofp_udp_destroy,
#else
	.pr_init =		NULL,
	.pr_destroy =		NULL,
#endif
	.pr_usrreqs =		&ofp_udp6_usrreqs,
},
{
	.pr_type =		OFP_SOCK_STREAM,
	.pr_domain =		&ofp_inet6domain,
	.pr_protocol =		OFP_IPPROTO_TCP,
	.pr_flags =		PR_CONNREQUIRED|PR_WANTRCVD|PR_LISTEN,
	.pr_input =		ofp_tcp6_input,
	.pr_ctlinput =		ofp_tcp6_ctlinput,
	.pr_ctloutput =		ofp_tcp_ctloutput,
#ifndef INET	/* don't call initialization and timeout routines twice */
	.pr_init =		ofp_tcp_init,
	.pr_slowtimo =		ofp_tcp_slowtimo,
	.pr_destroy =		ofp_tcp_destroy,
#else
	.pr_init =		NULL,
	.pr_slowtimo =		NULL,
	.pr_destroy =		NULL,
#endif
	.pr_drain =		ofp_tcp_drain,
	.pr_usrreqs =		&ofp_tcp6_usrreqs,
},
#ifdef SCTP
{
	.pr_type =		SOCK_SEQPACKET,
	.pr_domain =		&ofp_inet6domain,
	.pr_protocol =		IPPROTO_SCTP,
	.pr_flags =		PR_WANTRCVD,
	.pr_input =		sctp6_input,
	.pr_ctlinput =		sctp6_ctlinput,
	.pr_ctloutput =	sctp_ctloutput,
	.pr_drain =		sctp_drain,
#ifndef INET	/* Do not call initialization twice. */
	.pr_init =		sctp_init,
#else
	.pr_init =		NULL,
#endif
	.pr_usrreqs =		&sctp6_usrreqs
},
{
	.pr_type =		SOCK_STREAM,
	.pr_domain =		&ofp_inet6domain,
	.pr_protocol =		IPPROTO_SCTP,
	.pr_flags =		PR_WANTRCVD,
	.pr_input =		sctp6_input,
	.pr_ctlinput =	sctp6_ctlinput,
	.pr_ctloutput =		sctp_ctloutput,
	.pr_drain =		sctp_drain,
	.pr_usrreqs =		&sctp6_usrreqs
},
#endif /* SCTP */
#ifdef RAW
{
	.pr_type =		OFP_SOCK_RAW,
	.pr_domain =		&ofp_inet6domain,
	.pr_protocol =		OFP_IPPROTO_RAW,
	.pr_flags =		PR_ATOMIC|PR_ADDR,
	.pr_input =		rip6_input,
	.pr_output =		rip6_output,
	.pr_ctlinput =		rip6_ctlinput,
	.pr_ctloutput =		rip6_ctloutput,
#ifndef INET	/* Do not call initialization twice. */
	.pr_init =		rip_init,
#else
	.pr_init =		NULL,
#endif
	.pr_destroy =		NULL,
	.pr_usrreqs =		&rip6_usrreqs
},
#endif
{
	.pr_type =		OFP_SOCK_RAW,
	.pr_domain =		&ofp_inet6domain,
	.pr_protocol =		OFP_IPPROTO_ICMPV6,
	.pr_init =		NULL,
	.pr_destroy =		NULL,
	.pr_flags =		PR_ATOMIC|PR_ADDR|PR_LASTHDR,
	.pr_input =		ofp_icmp6_input,
	.pr_output =		NULL/*rip6_output*/,
	.pr_ctlinput =		NULL/*rip6_ctlinput*/,
	.pr_ctloutput =		NULL/*rip6_ctloutput*/,
	.pr_fasttimo =		NULL/*icmp6_fasttimo*/,
	.pr_slowtimo =		NULL/*icmp6_slowtimo*/,
	.pr_usrreqs =		&nousrreqs
},
{
	.pr_type =		OFP_SOCK_RAW,
	.pr_domain =		&ofp_inet6domain,
	.pr_protocol =		OFP_IPPROTO_DSTOPTS,
	.pr_init =		NULL,
	.pr_destroy =		NULL,
	.pr_flags =		PR_ATOMIC|PR_ADDR,
	.pr_input =		ofp_ip6_unrecognized_hdr_input,
	.pr_usrreqs =		&nousrreqs
},
{
	.pr_type =		OFP_SOCK_RAW,
	.pr_domain =		&ofp_inet6domain,
	.pr_protocol =		OFP_IPPROTO_ROUTING,
	.pr_init =		NULL,
	.pr_destroy =		NULL,
	.pr_flags =		PR_ATOMIC|PR_ADDR,
	.pr_input =		ofp_ip6_unrecognized_hdr_input,
	.pr_usrreqs =		&nousrreqs
},
{
	.pr_type =		OFP_SOCK_RAW,
	.pr_domain =		&ofp_inet6domain,
	.pr_protocol =		OFP_IPPROTO_FRAGMENT,
	.pr_init =		NULL,
	.pr_destroy =		NULL,
	.pr_flags =		PR_ATOMIC|PR_ADDR,
	.pr_input =		ofp_ip6_unrecognized_hdr_input,
	.pr_usrreqs =		&nousrreqs
},
{
	.pr_type =		OFP_SOCK_RAW,
	.pr_domain =		&ofp_inet6domain,
	.pr_protocol =		OFP_IPPROTO_HOPOPTS,
	.pr_init =		NULL,
	.pr_destroy =		NULL,
	.pr_flags =		PR_ATOMIC|PR_ADDR,
	.pr_input =		ofp_ip6_unrecognized_hdr_input,
	.pr_usrreqs =		&nousrreqs
},
{
	.pr_type =		OFP_SOCK_RAW,
	.pr_domain =		&ofp_inet6domain,
	.pr_protocol =		OFP_IPPROTO_NONE,
	.pr_init =		NULL,
	.pr_destroy =		NULL,
	.pr_input =		ofp_ip6_none_input,
	.pr_ctlinput =		NULL,
	.pr_ctloutput =		NULL,
	.pr_usrreqs =		&nousrreqs
},
};

struct domain ofp_inet6domain = {
	.dom_family =		OFP_AF_INET6,
	.dom_name =		"internet",
	.dom_init =		NULL,
	.dom_protosw =		(struct protosw *)ofp_inet6sw,
	.dom_protoswNPROTOSW =	(struct protosw *)
				&ofp_inet6sw[sizeof(ofp_inet6sw) /
					sizeof(ofp_inet6sw[0])],
};

VNET_DEFINE(int, ip6_v6only) = 1;
VNET_DEFINE(int, ip6_auto_flowlabel) = 1;
VNET_DEFINE(int, ip6_defhlim) = OFP_IPV6_DEFHLIM;

VNET_DEFINE(int, icmp6_rediraccept) = 1;/* accept and process redirects */
VNET_DEFINE(int, icmp6_redirtimeout) = 10 * 60;	/* 10 minutes */
