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
 *	@(#)ip_var.h	8.2 (Berkeley) 1/9/95
 * $FreeBSD: release/9.1.0/sys/netinet/ip_var.h 223666 2011-06-29 10:06:58Z ae $
 */

#ifndef _OFPI_IP_VAR_H_
#define	_OFPI_IP_VAR_H_

#include "ofpi_queue.h"
#include "ofpi_socket.h"
#include "ofpi_vnet.h"

#include "api/ofp_ip_var.h"

/*
 * In-kernel consumers can use these accessor macros directly to update
 * stats.
 */
#define	IPSTAT_ADD(name, val)	V_ipstat.name += (val)
#define	IPSTAT_SUB(name, val)	V_ipstat.name -= (val)
#define	IPSTAT_INC(name)	IPSTAT_ADD(name, 1)
#define	IPSTAT_DEC(name)	IPSTAT_SUB(name, 1)

/*
 * Kernel module consumers must use this accessor macro.
 */
void	kmod_ipstat_inc(int statnum);
#define	KMOD_IPSTAT_INC(name)						\
	kmod_ipstat_inc(offsetof(struct ofp_ipstat, name) / sizeof(uint64_t))
void	kmod_ipstat_dec(int statnum);
#define	KMOD_IPSTAT_DEC(name)						\
	kmod_ipstat_dec(offsetof(struct ofp_ipstat, name) / sizeof(uint64_t))

/* flags passed to ip_output as last parameter */
#define	IP_FORWARDING		0x1		/* most of ip header exists */
#define	IP_RAWOUTPUT		0x2		/* raw ip header exists */
#define	IP_SENDONES		0x4		/* send all-ones broadcast */
#define	IP_SENDTOIF		0x8		/* send on specific ifnet */
#define IP_ROUTETOIF		OFP_SO_DONTROUTE	/* 0x10 bypass routing tables */
#define IP_ALLOWBROADCAST	OFP_SO_BROADCAST	/* 0x20 can send broadcast packets */

/*
 * mbuf flag used by ip_fastfwd
 */
#define	M_PROTO1	0x00000010 /* protocol-specific */
#define	M_PROTO2	0x00000020 /* protocol-specific */
#define	M_PROTO3	0x00000040 /* protocol-specific */
#define	M_PROTO4	0x00000080 /* protocol-specific */
#define	M_PROTO5	0x00000100 /* protocol-specific */
#define	M_PROTO6	0x00080000 /* protocol-specific */
#define	M_PROTO7	0x00100000 /* protocol-specific */
#define	M_PROTO8	0x00200000 /* protocol-specific */
#define	M_PROTOFLAGS \
    (M_PROTO1|M_PROTO2|M_PROTO3|M_PROTO4|M_PROTO5|M_PROTO6|M_PROTO7|M_PROTO8)
#define	M_FASTFWD_OURS		M_PROTO1	/* changed dst to local */

#ifdef __NO_STRICT_ALIGNMENT
#define IP_HDR_ALIGNED_P(ip)	1
#else
#define IP_HDR_ALIGNED_P(ip)	((((intptr_t) (ip)) & 3) == 0)
#endif

struct ofp_ip;
struct inpcb;
struct route;
struct sockopt;

VNET_DECLARE(struct ofp_ipstat, ofp_ipstat);
VNET_DECLARE(uint16_t, ofp_ip_id);			/* ip packet ctr, for ids */
VNET_DECLARE(int, ofp_ip_defttl);			/* default IP ttl */
VNET_DECLARE(int, ofp_ipforwarding);		/* ip forwarding */
#ifdef IPSTEALTH
VNET_DECLARE(int, ipstealth);			/* stealth forwarding */
#endif
extern uint8_t	ofp_ip_protox[];
extern uint8_t ofp_ip_protox_udp;
extern uint8_t ofp_ip_protox_tcp;
extern uint8_t ofp_ip_protox_gre;
VNET_DECLARE(struct socket *, ofp_ip_rsvpd);	/* reservation protocol daemon*/
VNET_DECLARE(struct socket *, ofp_ip_mrouter);	/* multicast routing daemon */
extern int	(*legal_vif_num)(int);
extern uint64_t	(*ip_mcast_src)(int);
VNET_DECLARE(int, ofp_rsvp_on);
extern struct	pr_usrreqs rip_usrreqs;

#define	V_ipstat		VNET(ofp_ipstat)
#define	V_ip_id			VNET(ofp_ip_id)
#define	V_ip_defttl		VNET(ofp_ip_defttl)
#define	V_ipforwarding		VNET(ofp_ipforwarding)
#ifdef IPSTEALTH
#define	V_ipstealth		VNET(ipstealth)
#endif
#define	V_ip_rsvpd		VNET(ofp_ip_rsvpd)
#define	V_ip_mrouter		VNET(ofp_ip_mrouter)
#define	V_rsvp_on		VNET(ofp_rsvp_on)

void	ofp_inp_freemoptions(struct ofp_ip_moptions *);
int	ofp_inp_getmoptions(struct inpcb *, struct sockopt *);
int	ofp_inp_setmoptions(struct inpcb *, struct sockopt *);

int	ofp_ip_ctloutput(struct socket *, struct sockopt *sopt);
void	ip_drain(void);
int	ip_fragment(struct ofp_ip *ip, odp_packet_t *m_frag, int mtu,
	    uint64_t if_hwassist_flags, int sw_csum);
void	ip_forward(odp_packet_t m, int srcrt);

void	ofp_ip_init(void);
#ifdef VIMAGE
void	ofp_ip_destroy(void);
#endif
enum ofp_return_code ofp_ip_input(odp_packet_t , int);

extern int
	(*ip_mforward)(struct ofp_ip *, struct ofp_ifnet *, odp_packet_t ,
	    struct ofp_ip_moptions *);
int	ip_output(odp_packet_t ,
	    odp_packet_t , struct route *, int, struct ofp_ip_moptions *,
	    struct inpcb *);
int	ipproto_register(short);
int	ipproto_unregister(short);
odp_packet_t
	ip_reass(odp_packet_t );
struct ofp_ifnet *
	ip_rtaddr(struct ofp_in_addr, uint32_t fibnum);
void	ip_savecontrol(struct inpcb *, odp_packet_t *, struct ofp_ip *,
	    odp_packet_t );
void	ip_slowtimo(void);
uint16_t	ip_randomid(void);
int	rip_ctloutput(struct socket *, struct sockopt *);
void	rip_ctlinput(int, struct ofp_sockaddr *, void *);
void	rip_init(void);
void	rip_input(odp_packet_t , int);
int	rip_output(odp_packet_t , struct socket *, uint64_t);
void	ipip_input(odp_packet_t , int);
void	rsvp_input(odp_packet_t , int);
int	ip_rsvp_init(struct socket *);
int	ip_rsvp_done(void);
extern int	(*ip_rsvp_vif)(struct socket *, struct sockopt *);
extern void	(*ip_rsvp_force_done)(struct socket *);
extern void	(*rsvp_input_p)(odp_packet_t m, int off);

#if 0
VNET_DECLARE(struct pfil_head, inet_pfil_hook);	/* packet filter hooks */
#define	V_inet_pfil_hook	VNET(inet_pfil_hook)
#endif

void	in_delayed_cksum(odp_packet_t m);

/* Hooks for ipfw, dummynet, divert etc. Most are declared in raw_ip.c */
/*
 * Reference to an ipfw or packet filter rule that can be carried
 * outside critical sections.
 * A rule is identified by rulenum:rule_id which is ordered.
 * In version chain_id the rule can be found in slot 'slot', so
 * we don't need a lookup if chain_id == chain->id.
 *
 * On exit from the firewall this structure refers to the rule after
 * the matching one (slot points to the new rule; rulenum:rule_id-1
 * is the matching rule), and additional info (e.g. info often contains
 * the insn argument or tablearg in the low 16 bits, in host format).
 * On entry, the structure is valid if slot>0, and refers to the starting
 * rules. 'info' contains the reason for reinject, e.g. divert port,
 * divert direction, and so on.
 */
struct ipfw_rule_ref {
	uint32_t	slot;		/* slot for matching rule	*/
	uint32_t	rulenum;	/* matching rule number		*/
	uint32_t	rule_id;	/* matching rule id		*/
	uint32_t	chain_id;	/* ruleset id			*/
	uint32_t	info;		/* see below			*/
};

enum {
	IPFW_INFO_MASK	= 0x0000ffff,
	IPFW_INFO_OUT	= 0x00000000,	/* outgoing, just for convenience */
	IPFW_INFO_IN	= 0x80000000,	/* incoming, overloads dir */
	IPFW_ONEPASS	= 0x40000000,	/* One-pass, do not reinject */
	IPFW_IS_MASK	= 0x30000000,	/* which source ? */
	IPFW_IS_DIVERT	= 0x20000000,
	IPFW_IS_DUMMYNET =0x10000000,
	IPFW_IS_PIPE	= 0x08000000,	/* pip1=1, queue = 0 */
};
#define MTAG_IPFW	1148380143	/* IPFW-tagged cookie */
#define MTAG_IPFW_RULE	1262273568	/* rule reference */
#define	MTAG_IPFW_CALL	1308397630	/* call stack */

struct ip_fw_args;
typedef int	(*ip_fw_chk_ptr_t)(struct ip_fw_args *args);
typedef int	(*ip_fw_ctl_ptr_t)(struct sockopt *);
VNET_DECLARE(ip_fw_chk_ptr_t, ofp_ip_fw_chk_ptr);
VNET_DECLARE(ip_fw_ctl_ptr_t, ofp_ip_fw_ctl_ptr);
#define	V_ip_fw_chk_ptr		VNET(ofp_ip_fw_chk_ptr)
#define	V_ip_fw_ctl_ptr		VNET(ofp_ip_fw_ctl_ptr)

/* Divert hooks. */
extern void	(*ip_divert_ptr)(odp_packet_t m, int incoming);
/* ng_ipfw hooks -- XXX make it the same as divert and dummynet */
extern int	(*ng_ipfw_input_p)(odp_packet_t *, int,
			struct ip_fw_args *, int);

extern int	(*ip_dn_ctl_ptr)(struct sockopt *);
extern int	(*ip_dn_io_ptr)(odp_packet_t *, int, struct ip_fw_args *);

VNET_DECLARE(int, ofp_ip_do_randomid);
#define	V_ip_do_randomid	VNET(ofp_ip_do_randomid)
#define	ip_newid()	((V_ip_do_randomid != 0) ? ip_randomid() : \
			    odp_cpu_to_be_16(V_ip_id++))

#endif /* !_OFPI_IP_VAR_H_ */
