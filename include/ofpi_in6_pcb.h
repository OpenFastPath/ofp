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
 *	$KAME: in6_pcb.h,v 1.13 2001/02/06 09:16:53 itojun Exp $
 */

/*-
 * Copyright (c) 1982, 1986, 1990, 1993
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
 *	@(#)in_pcb.h	8.1 (Berkeley) 6/10/93
 * $FreeBSD: release/9.1.0/sys/netinet6/in6_pcb.h 222748 2011-06-06
 *	12:55:02Z rwatson $
 */

#ifndef _NETINET6_IN6_PCB_H_
#define _NETINET6_IN6_PCB_H_

#if 0
#define	satosin6(sa)	((struct sockaddr_in6 *)(sa))
#define	sin6tosa(sin6)	((struct sockaddr *)(sin6))
#define	ifatoia6(ifa)	((struct in6_ifaddr *)(ifa))

struct	inpcbgroup *
	in6_pcbgroup_byhash(struct inpcbinfo *, u_int, uint32_t);
struct	inpcbgroup *
	in6_pcbgroup_byinpcb __P((struct inpcb *));
struct inpcbgroup *
	in6_pcbgroup_bymbuf(struct inpcbinfo *, struct mbuf *);
struct	inpcbgroup *
	in6_pcbgroup_bytuple __P((struct inpcbinfo *, const struct in6_addr *,
	    u_short, const struct in6_addr *, u_short));

void	in6_pcbpurgeif0 __P((struct inpcbinfo *, struct ifnet *));
void	in6_losing __P((struct inpcb *));
#endif
int	ofp_in6_pcbbind __P((struct inpcb *, struct ofp_sockaddr *,
			struct ofp_ucred *));
int	ofp_in6_pcbconnect __P((struct inpcb *, struct ofp_sockaddr *,
			struct ofp_ucred *));
int	ofp_in6_pcbconnect_mbuf __P((struct inpcb *, struct ofp_sockaddr *,
			struct ofp_ucred *, odp_packet_t));
void	ofp_in6_pcbdisconnect __P((struct inpcb *));
int	ofp_in6_pcbladdr(struct inpcb *, struct ofp_sockaddr *,
			struct ofp_in6_addr *);
struct	inpcb *
	ofp_in6_pcblookup_local __P((struct inpcbinfo *,
				 struct ofp_in6_addr *, u_short, int,
				 struct ofp_ucred *));

struct	inpcb *
	ofp_in6_pcblookup __P((struct inpcbinfo *, struct ofp_in6_addr *,
			   u_int, struct ofp_in6_addr *, u_int, int,
			   struct ofp_ifnet *));

struct	inpcb *
	ofp_in6_pcblookup_hash_locked __P((struct inpcbinfo *,
			struct ofp_in6_addr *,
			u_int, struct ofp_in6_addr *, u_int, int,
			struct ofp_ifnet *));
struct	inpcb *
	ofp_in6_pcblookup_mbuf __P((struct inpcbinfo *,
			struct ofp_in6_addr *,
			u_int, struct ofp_in6_addr *, u_int, int,
			struct ofp_ifnet *ifp, odp_packet_t m));
void	ofp_in6_pcbnotify __P((struct inpcbinfo *, struct ofp_sockaddr *,
			u_int, const struct ofp_sockaddr *, u_int, int, void *,
			struct inpcb *(*)(struct inpcb *, int)));
struct inpcb *
	ofp_in6_rtchange(struct inpcb *inp, int error_val);

struct ofp_sockaddr *
	ofp_in6_sockaddr __P((ofp_in_port_t port,
			struct ofp_in6_addr *addr_p));

struct ofp_sockaddr *
	ofp_in6_v4mapsin6_sockaddr __P((ofp_in_port_t port,
			struct ofp_in_addr *addr_p));
#if 0
int	in6_getpeeraddr __P((struct socket *so, struct sockaddr **nam));
int	in6_getsockaddr __P((struct socket *so, struct sockaddr **nam));
int	in6_mapped_sockaddr __P((struct socket *so, struct sockaddr **nam));
int	in6_mapped_peeraddr __P((struct socket *so, struct sockaddr **nam));
int	in6_selecthlim __P((struct in6pcb *, struct ifnet *));
#endif
int	ofp_in6_pcbsetport __P((struct ofp_in6_addr *, struct inpcb *,
			struct ofp_ucred *));
void	ofp_init_sin6 __P((struct ofp_sockaddr_in6 *sin6,
			odp_packet_t pkt));


#endif /* !_NETINET6_IN6_PCB_H_ */
