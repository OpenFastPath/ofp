/*-
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
 * Copyright (c) 2014, Nokia
 * Copyright (c) 2014, Enea Software AB
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
 *	@(#)in_proto.c	8.2 (Berkeley) 2/9/95
 */

#include <odp_api.h>
#include "ofpi_in.h"
#include "ofpi_sysctl.h"
#include "ofpi_icmp.h"
#include "ofpi_gre.h"
#include "ofpi_udp.h"
#include "ofpi_igmp_var.h"
#include "ofpi_in_pcb.h"
#include "ofpi_domain.h"
#include "ofpi_protosw.h"
#include "ofpi_udp_var.h"
#include "ofpi_tcp_var.h"
#include "ofpi_socket.h"
#include "ofpi_ipsec.h"

extern	struct pr_usrreqs nousrreqs;

/*
 * TCP/IP protocol family: IP, ICMP, UDP, TCP.
 */
struct protosw ofp_inetsw[] = {
	{
		.pr_type =		0,
		.pr_domain =		&ofp_inetdomain,
		.pr_protocol =		OFP_IPPROTO_IP,
		.pr_init =		ofp_ip_init,
#ifdef VIMAGE
		.pr_destroy =		ofp_ip_destroy,
#else
		.pr_destroy =		NULL,
#endif
		.pr_input =		ofp_ip_input,
		.pr_ctlinput =		NULL,
		.pr_ctloutput =		ofp_ip_ctloutput,
		.pr_usrreqs =		&nousrreqs
	},
	{
		.pr_type =		OFP_SOCK_DGRAM,
		.pr_domain =		&ofp_inetdomain,
		.pr_protocol =		OFP_IPPROTO_UDP,
		.pr_flags =		PR_ATOMIC|PR_ADDR,
		.pr_input =		ofp_udp_input,
		.pr_ctlinput =		ofp_udp_ctlinput,
		.pr_ctloutput =		ofp_udp_ctloutput,
		.pr_init =		ofp_udp_init,
		.pr_destroy =           ofp_udp_destroy,
		.pr_usrreqs =		&ofp_udp_usrreqs
	},
	{
		.pr_type =		OFP_SOCK_STREAM,
		.pr_domain =		&ofp_inetdomain,
		.pr_protocol =		OFP_IPPROTO_TCP,
		.pr_flags =		PR_CONNREQUIRED|PR_IMPLOPCL|PR_WANTRCVD,
		.pr_input =		ofp_tcp_input,
		.pr_ctlinput =		ofp_tcp_ctlinput,
		.pr_ctloutput =		ofp_tcp_ctloutput,
		.pr_init =		ofp_tcp_init,
		.pr_destroy =           ofp_tcp_destroy,
		.pr_slowtimo =		ofp_tcp_slowtimo,
		.pr_drain =		ofp_tcp_drain,
		.pr_usrreqs =		&ofp_tcp_usrreqs
	},
#ifdef SCTP
	{
		.pr_type =		OFP_SOCK_SEQPACKET,
		.pr_domain =		&ofp_inetdomain,
		.pr_protocol =		OFP_IPPROTO_SCTP,
		.pr_flags =		PR_WANTRCVD,
		.pr_input =		sctp_input,
		.pr_ctlinput =		sctp_ctlinput,
		.pr_ctloutput =		sctp_ctloutput,
		.pr_init =		sctp_init,
		.pr_drain =		sctp_drain,
		.pr_usrreqs =		&sctp_usrreqs
	},
	{
		.pr_type =		OFP_SOCK_STREAM,
		.pr_domain =		&ofp_inetdomain,
		.pr_protocol =		OFP_IPPROTO_SCTP,
		.pr_flags =		PR_WANTRCVD,
		.pr_input =		sctp_input,
		.pr_ctlinput =		sctp_ctlinput,
		.pr_ctloutput =		sctp_ctloutput,
		.pr_drain =		sctp_drain,
		.pr_usrreqs =		&sctp_usrreqs
	},
#endif /* SCTP */
#ifdef RAW
	/* raw wildcard */
	{
		.pr_type =		OFP_SOCK_RAW,
		.pr_domain =		&ofp_inetdomain,
		.pr_protocol =		OFP_IPPROTO_RAW,
		.pr_flags =		PR_ATOMIC|PR_ADDR,
		.pr_input =		rip_input,
		.pr_ctloutput =		rip_ctloutput,
		.pr_init =		rip_init,
		.pr_usrreqs =		&rip_usrreqs
	},
#endif
	{
		.pr_type =		OFP_SOCK_RAW,
		.pr_domain =		&ofp_inetdomain,
		.pr_protocol =		OFP_IPPROTO_GRE,
		.pr_flags =		PR_ATOMIC|PR_ADDR|PR_LASTHDR,
		.pr_input =		ofp_gre_input,
		.pr_init =		NULL,
		.pr_destroy =		NULL,
		.pr_ctlinput =		NULL,
		.pr_ctloutput =		NULL/*rip_ctloutput*/,
		.pr_usrreqs =		&nousrreqs
	},
	{
		.pr_type =		OFP_SOCK_RAW,
		.pr_domain =		&ofp_inetdomain,
		.pr_protocol =		OFP_IPPROTO_ICMP,
		.pr_flags =		PR_ATOMIC|PR_ADDR|PR_LASTHDR,
		.pr_input =		ofp_icmp_input,
		.pr_init =		NULL,
		.pr_destroy =		NULL,
		.pr_ctlinput =		NULL,
		.pr_ctloutput =		NULL/*rip_ctloutput*/,
		.pr_usrreqs =		&nousrreqs
	},
	{
		.pr_type =		OFP_SOCK_RAW,
		.pr_domain =		&ofp_inetdomain,
		.pr_protocol =		OFP_IPPROTO_IGMP,
		.pr_flags =		PR_ATOMIC|PR_ADDR|PR_LASTHDR,
		.pr_input =		ofp_igmp_input,
		.pr_init =		ofp_igmp_init,
		.pr_destroy =		NULL,
		.pr_ctloutput =		NULL /*rip_ctloutput*/,
		.pr_fasttimo =		NULL /*igmp_fasttimo*/,
		.pr_slowtimo =		NULL /*ofp_igmp_slowtimo*/,
		.pr_usrreqs =		&nousrreqs /*rip_usrreqs*/
	},
	{
		.pr_type =		OFP_SOCK_RAW,
		.pr_domain =		&ofp_inetdomain,
		.pr_protocol =		OFP_IPPROTO_AH,
		.pr_flags =		PR_ATOMIC|PR_ADDR,
		.pr_input =		ofp_ipsec_input,
		.pr_init =		NULL,
		.pr_destroy =		NULL,
		.pr_ctloutput =		NULL,
		.pr_fasttimo =		NULL,
		.pr_slowtimo =		NULL,
		.pr_usrreqs =		&nousrreqs
	},
	{
		.pr_type =		OFP_SOCK_RAW,
		.pr_domain =		&ofp_inetdomain,
		.pr_protocol =		OFP_IPPROTO_ESP,
		.pr_flags =		PR_ATOMIC|PR_ADDR,
		.pr_input =		ofp_ipsec_input,
		.pr_init =		NULL,
		.pr_destroy =		NULL,
		.pr_ctloutput =		NULL,
		.pr_fasttimo =		NULL,
		.pr_slowtimo =		NULL,
		.pr_usrreqs =		&nousrreqs
	}
};


struct domain ofp_inetdomain = {
	.dom_family =		OFP_AF_INET,
	.dom_name =		"internet",
	.dom_init =		NULL,
	.dom_protosw =		ofp_inetsw,
	.dom_protoswNPROTOSW =	&ofp_inetsw[sizeof(ofp_inetsw) /
			sizeof(ofp_inetsw[0])],
};

OFP_SYSCTL_NODE(_net,      OFP_PF_INET,		inet,	OFP_CTLFLAG_RW, 0,
	"Internet Family");

OFP_SYSCTL_NODE(_net_inet, OFP_IPPROTO_IP,	ip,	OFP_CTLFLAG_RW, 0,	"IP");
OFP_SYSCTL_NODE(_net_inet, OFP_IPPROTO_ICMP,	icmp,	OFP_CTLFLAG_RW, 0,	"ICMP");
OFP_SYSCTL_NODE(_net_inet, OFP_IPPROTO_UDP,	udp,	OFP_CTLFLAG_RW, 0,	"UDP");
OFP_SYSCTL_NODE(_net_inet, OFP_IPPROTO_TCP,	tcp,	OFP_CTLFLAG_RW, 0,	"TCP");
#ifdef SCTP
OFP_SYSCTL_NODE(_net_inet, OFP_IPPROTO_SCTP,	sctp,	OFP_CTLFLAG_RW, 0,	"SCTP");
#endif
OFP_SYSCTL_NODE(_net_inet, OFP_IPPROTO_IGMP,	igmp,	OFP_CTLFLAG_RW, 0,	"IGMP");
#ifdef IPSEC
/* XXX no protocol # to use, pick something "reserved" */
OFP_SYSCTL_NODE(_net_inet, 253,		ipsec,	OFP_CTLFLAG_RW, 0,	"IPSEC");
OFP_SYSCTL_NODE(_net_inet, OFP_IPPROTO_AH,	ah,	OFP_CTLFLAG_RW, 0,	"AH");
OFP_SYSCTL_NODE(_net_inet, OFP_IPPROTO_ESP,	esp,	OFP_CTLFLAG_RW, 0,	"ESP");
OFP_SYSCTL_NODE(_net_inet, OFP_IPPROTO_IPCOMP,	ipcomp,	OFP_CTLFLAG_RW, 0,	"IPCOMP");
OFP_SYSCTL_NODE(_net_inet, OFP_IPPROTO_IPIP,	ipip,	OFP_CTLFLAG_RW, 0,	"IPIP");
#endif /* IPSEC */
OFP_SYSCTL_NODE(_net_inet, OFP_IPPROTO_RAW,	raw,	OFP_CTLFLAG_RW, 0,	"RAW");
