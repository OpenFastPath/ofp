/*-
 * Copyright (c) 1982, 1986, 1988, 1993
 *	The Regents of the University of California.
 * Copyright (c) 2006-2007 Robert N. M. Watson
 * Copyright (c) 2010-2011 Juniper Networks, Inc.
 * Copyright (c) 2015 Nokia Solutions and Networks
 * Copyright (c) 2015 Enea Software AB
 * All rights reserved.
 *
 * Portions of this software were developed by Robert N. M. Watson under
 * contract to Juniper Networks, Inc.
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
 *	From: @(#)tcp_usrreq.c	8.2 (Berkeley) 1/3/94
 */
#include <strings.h>
#include <string.h>

#include "odp.h"

#include "ofpi_errno.h"
#include "ofpi_in.h"
#include "ofpi_ip.h"
#include "ofpi_ip6.h"
#include "ofpi_ip6_var.h"
#include "ofpi_udp.h"
#include "ofpi_icmp.h"
#include "ofpi_sysctl.h"
#include "ofpi_socketvar.h"

#include "ofpi_in_pcb.h"
#include "ofpi_tcp.h"
#include "ofpi_tcp_var.h"
#include "ofpi_tcp_shm.h"
#include "ofpi_socketvar.h"
#include "ofpi_ip_var.h"
#include "ofpi_sockbuf.h"
#include "ofpi_socket.h"
#include "ofpi_sockstate.h"
#include "ofpi_protosw.h"
#include "ofpi_ethernet.h"
#include "ofpi_tcp_timer.h"
#include "ofpi_tcp_fsm.h"
#include "ofpi_tcp_offload.h"
#include "ofpi_ioctl.h"

#ifdef INET6
#include "ofpi_in6_pcb.h"
#endif

#include "ofpi_util.h"

#define tick (1000000/HZ)

/*
 * Macros to initialize tcp sequence numbers for
 * send and receive from initial send and receive
 * sequence numbers.
 */
#define	tcp_rcvseqinit(tp) \
	(tp)->rcv_adv = (tp)->rcv_nxt = (tp)->irs + 1

#define	tcp_sendseqinit(tp) \
	(tp)->snd_una = (tp)->snd_nxt = (tp)->snd_max = (tp)->snd_up = \
	    (tp)->snd_recover = (tp)->iss


/*
 * TCP protocol interface to socket abstraction.
 */
static int	tcp_attach(struct socket *);
#ifdef INET
static int	tcp_connect(struct tcpcb *, struct ofp_sockaddr *,
		    struct thread *td);
#endif /* INET */
#ifdef INET6
static int	tcp6_connect(struct tcpcb *, struct ofp_sockaddr *,
		    struct thread *td);
#endif /* INET6 */
static void	tcp_disconnect(struct tcpcb *);
static void	tcp_usrclosed(struct tcpcb *);
/*static void	tcp_fill_info(struct tcpcb *, struct tcp_info *);*/

#ifdef TCPDEBUG
#define	TCPDEBUG0	int ostate = 0
#define	TCPDEBUG1()	ostate = tp ? tp->t_state : 0
#define	TCPDEBUG2(req)	if (tp && (so->so_options & OFP_SO_DEBUG)) \
				tcp_trace(TA_USER, ostate, tp, 0, 0, req)
#else
#define	TCPDEBUG0
#define	TCPDEBUG1()
#define	TCPDEBUG2(req)
#endif

/*
 * TCP attaches to socket via pru_attach(), reserving space,
 * and an internet control block.
 */
static int
tcp_usr_attach(struct socket *so, int proto, struct thread *td)
{
	struct inpcb *inp;
	struct tcpcb *tp = NULL;
	int error;
	TCPDEBUG0;

	(void)tp;
	(void)proto;
	(void)td;

	inp = sotoinpcb(so);
	KASSERT(inp == NULL, ("tcp_usr_attach: inp != NULL"));
	TCPDEBUG1();

	error = tcp_attach(so);
	if (error)
		goto out;

	if ((so->so_options & OFP_SO_LINGER) && so->so_linger == 0)
		so->so_linger = TCP_LINGERTIME;

	inp = sotoinpcb(so);
	tp = intotcpcb(inp);
out:
	TCPDEBUG2(OFP_PRU_ATTACH);
	return error;
}

/*
 * tcp_detach is called when the socket layer loses its final reference
 * to the socket, be it a file descriptor reference, a reference from TCP,
 * etc.  At this point, there is only one case in which we will keep around
 * inpcb state: time wait.
 *
 * This function can probably be re-absorbed back into tcp_usr_detach() now
 * that there is a single detach path.
 */
static void
tcp_detach(struct socket *so, struct inpcb *inp)
{
	struct tcpcb *tp;

	INP_INFO_WLOCK_ASSERT(&V_tcbinfo);
	INP_WLOCK_ASSERT(inp);

	KASSERT(so->so_pcb == inp, ("tcp_detach: so_pcb != inp"));
	KASSERT(inp->inp_socket == so, ("tcp_detach: inp_socket != so"));

	tp = intotcpcb(inp);

	if (inp->inp_flags & INP_TIMEWAIT) {
		/*
		 * There are two cases to handle: one in which the time wait
		 * state is being discarded (INP_DROPPED), and one in which
		 * this connection will remain in timewait.  In the former,
		 * it is time to discard all state (except tcptw, which has
		 * already been discarded by the timewait close code, which
		 * should be further up the call stack somewhere).  In the
		 * latter case, we detach from the socket, but leave the pcb
		 * present until timewait ends.
		 *
		 * XXXRW: Would it be cleaner to free the tcptw here?
		 */
		if (inp->inp_flags & INP_DROPPED) {
			KASSERT(tp == NULL, ("tcp_detach: INP_TIMEWAIT && "
			    "INP_DROPPED && tp != NULL"));
			ofp_in_pcbdetach(inp);
			ofp_in_pcbfree(inp);
		} else {
			ofp_in_pcbdetach(inp);
			INP_WUNLOCK(inp);
		}
	} else {
		/*
		 * If the connection is not in timewait, we consider two
		 * two conditions: one in which no further processing is
		 * necessary (dropped || embryonic), and one in which TCP is
		 * not yet done, but no longer requires the socket, so the
		 * pcb will persist for the time being.
		 *
		 * XXXRW: Does the second case still occur?
		 */
		if ((inp->inp_flags & INP_DROPPED) ||
		    tp->t_state < TCPS_SYN_SENT) {
			ofp_tcp_discardcb(tp);
			ofp_in_pcbdetach(inp);
			ofp_in_pcbfree(inp);
		} else {
			ofp_in_pcbdetach(inp);
			INP_WUNLOCK(inp);
		}
	}
}

/*
 * pru_detach() detaches the TCP protocol from the socket.
 * If the protocol state is non-embryonic, then can't
 * do this directly: have to initiate a pru_disconnect(),
 * which may finish later; embryonic TCB's can just
 * be discarded here.
 */
static void
tcp_usr_detach(struct socket *so)
{
	struct inpcb *inp;

	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("tcp_usr_detach: inp == NULL"));
	INP_INFO_WLOCK(&V_tcbinfo);
	INP_WLOCK(inp);
	KASSERT(inp->inp_socket != NULL,
	    ("tcp_usr_detach: inp_socket == NULL"));
	tcp_detach(so, inp);
	INP_INFO_WUNLOCK(&V_tcbinfo);
}

#ifdef INET
/*
 * Give the socket an address.
 */
static int
tcp_usr_bind(struct socket *so, struct ofp_sockaddr *nam, struct thread *td)
{
	int error = 0;
	struct inpcb *inp;
	struct tcpcb *tp = NULL;
	struct ofp_sockaddr_in *sinp;
	(void)tp;

	sinp = (struct ofp_sockaddr_in *)nam;
	if (nam->sa_len != sizeof (*sinp))
		return (OFP_EINVAL);
	/*
	 * Must check for multicast addresses and disallow binding
	 * to them.
	 */
	if (sinp->sin_family == OFP_AF_INET &&
	    OFP_IN_MULTICAST(odp_be_to_cpu_32(sinp->sin_addr.s_addr)))
		return (OFP_EAFNOSUPPORT);

	TCPDEBUG0;
	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("tcp_usr_bind: inp == NULL"));
	INP_WLOCK(inp);
	if (inp->inp_flags & (INP_TIMEWAIT | INP_DROPPED)) {
		error = OFP_EINVAL;
		goto out;
	}
	tp = intotcpcb(inp);
	TCPDEBUG1();
	INP_HASH_WLOCK(&V_tcbinfo);
	error = ofp_in_pcbbind(inp, nam, td->td_ucred);
	INP_HASH_WUNLOCK(&V_tcbinfo);
out:
	TCPDEBUG2(OFP_PRU_BIND);
	INP_WUNLOCK(inp);

	return (error);
}
#endif /* INET */

#ifdef INET6
static int
tcp6_usr_bind(struct socket *so, struct ofp_sockaddr *nam, struct thread *td)
{
	int error = 0;
	struct inpcb *inp;
	struct tcpcb *tp = NULL;
	struct ofp_sockaddr_in6 *sin6p;

	sin6p = (struct ofp_sockaddr_in6 *)nam;
	if (nam->sa_len != sizeof (*sin6p))
		return (OFP_EINVAL);
	/*
	 * Must check for multicast addresses and disallow binding
	 * to them.
	 */
	if (sin6p->sin6_family == OFP_AF_INET6 &&
	    OFP_IN6_IS_ADDR_MULTICAST(&sin6p->sin6_addr))
		return (OFP_EAFNOSUPPORT);

	TCPDEBUG0;
	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("tcp6_usr_bind: inp == NULL"));
	INP_WLOCK(inp);
	if (inp->inp_flags & (INP_TIMEWAIT | INP_DROPPED)) {
		error = OFP_EINVAL;
		goto out;
	}

	tp = intotcpcb(inp);
	(void)tp;
	TCPDEBUG1();
	INP_HASH_WLOCK(&V_tcbinfo);
	inp->inp_vflag &= ~INP_IPV4;
	inp->inp_vflag |= INP_IPV6;

	if ((inp->inp_flags & IN6P_IPV6_V6ONLY) == 0) {
		if (OFP_IN6_IS_ADDR_UNSPECIFIED(&sin6p->sin6_addr))
			inp->inp_vflag |= INP_IPV4;
		else if (OFP_IN6_IS_ADDR_V4MAPPED(&sin6p->sin6_addr)) {
			struct ofp_sockaddr_in sin;

			ofp_in6_sin6_2_sin(&sin, sin6p);
			inp->inp_vflag |= INP_IPV4;
			inp->inp_vflag &= ~INP_IPV6;
			error = ofp_in_pcbbind(inp, (struct ofp_sockaddr *)&sin,
			    td->td_ucred);
			INP_HASH_WUNLOCK(&V_tcbinfo);
			goto out;
		}
	}
	error = ofp_in6_pcbbind(inp, nam, td->td_ucred);
	INP_HASH_WUNLOCK(&V_tcbinfo);
out:
	TCPDEBUG2(OFP_PRU_BIND);
	INP_WUNLOCK(inp);
	return (error);
}
#endif /* INET6 */

#ifdef INET
/*
 * Prepare to accept connections.
 */
static int
tcp_usr_listen(struct socket *so, int backlog, struct thread *td)
{
	int error = 0;
	struct inpcb *inp;
	struct tcpcb *tp = NULL;

	TCPDEBUG0;
	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("tcp_usr_listen: inp == NULL"));
	INP_WLOCK(inp);
	if (inp->inp_flags & (INP_TIMEWAIT | INP_DROPPED)) {
		error = OFP_EINVAL;
		goto out;
	}
	tp = intotcpcb(inp);
	TCPDEBUG1();
	OFP_SOCK_LOCK(so);
	error = ofp_solisten_proto_check(so);
	INP_HASH_WLOCK(&V_tcbinfo);
	if (error == 0 && inp->inp_lport == 0)
		error = ofp_in_pcbbind(inp, (struct ofp_sockaddr *)0, td->td_ucred);
	INP_HASH_WUNLOCK(&V_tcbinfo);
	if (error == 0) {
		tp->t_state = TCPS_LISTEN;
		ofp_solisten_proto(so, backlog);
		tcp_offload_listen_open(tp);
	}
	OFP_SOCK_UNLOCK(so);

out:
	TCPDEBUG2(OFP_PRU_LISTEN);
	INP_WUNLOCK(inp);
	return (error);
}
#endif /* INET */

#ifdef INET6
static int
tcp6_usr_listen(struct socket *so, int backlog, struct thread *td)
{
	int error = 0;
	struct inpcb *inp;
	struct tcpcb *tp = NULL;

	TCPDEBUG0;
	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("tcp6_usr_listen: inp == NULL"));
	INP_WLOCK(inp);

	if (inp->inp_flags & (INP_TIMEWAIT | INP_DROPPED)) {
		error = OFP_EINVAL;
		goto out;
	}

	tp = intotcpcb(inp);
	TCPDEBUG1();
	OFP_SOCK_LOCK(so);

	error = ofp_solisten_proto_check(so);

	INP_HASH_WLOCK(&V_tcbinfo);
	if (error == 0 && inp->inp_lport == 0) {
		inp->inp_vflag &= ~INP_IPV4;

		if ((inp->inp_flags & IN6P_IPV6_V6ONLY) == 0)
			inp->inp_vflag |= INP_IPV4;
		error = ofp_in6_pcbbind(inp, (struct ofp_sockaddr *)0, td->td_ucred);
	}
	INP_HASH_WUNLOCK(&V_tcbinfo);

	if (error == 0) {
		tp->t_state = TCPS_LISTEN;
		ofp_solisten_proto(so, backlog);
	}
	OFP_SOCK_UNLOCK(so);
out:
	TCPDEBUG2(OFP_PRU_LISTEN);
	INP_WUNLOCK(inp);
	return (error);
}
#endif /* INET6 */

#ifdef INET
/*
 * Initiate connection to peer.
 * Create a template for use in transmissions on this connection.
 * Enter SYN_SENT state, and mark socket as connecting.
 * Start keep-alive timer, and seed output sequence space.
 * Send initial segment on connection.
 */
static int
tcp_usr_connect(struct socket *so, struct ofp_sockaddr *nam, struct thread *td)
{
	int error = 0;
	struct inpcb *inp;
	struct tcpcb *tp = NULL;
	struct ofp_sockaddr_in *sinp;

	sinp = (struct ofp_sockaddr_in *)nam;
	if (nam->sa_len != sizeof (*sinp))
		return (OFP_EINVAL);
	/*
	 * Must disallow TCP ``connections'' to multicast addresses.
	 */
	if (sinp->sin_family == OFP_AF_INET
	    && OFP_IN_MULTICAST(odp_be_to_cpu_32(sinp->sin_addr.s_addr)))
		return (OFP_EAFNOSUPPORT);
#if 0
	if ((error = prison_remote_ip4(td->td_ucred, &sinp->sin_addr)) != 0)
		return (error);
#endif
	TCPDEBUG0;
	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("tcp_usr_connect: inp == NULL"));
	INP_WLOCK(inp);
	if (inp->inp_flags & (INP_TIMEWAIT | INP_DROPPED)) {
		error = OFP_EINVAL;
		goto out;
	}
	tp = intotcpcb(inp);
	TCPDEBUG1();
	if ((error = tcp_connect(tp, nam, td)) != 0)
		goto out;
	if ((error = tcp_output_connect(so, nam)) != 0)
		goto out;
	error = OFP_EINPROGRESS;
out:
	TCPDEBUG2(OFP_PRU_CONNECT);
	INP_WUNLOCK(inp);
	return (error);
}
#endif /* INET */

#ifdef INET6
static int
tcp6_usr_connect(struct socket *so, struct ofp_sockaddr *nam, struct thread *td)
{
	int error = 0;
	struct inpcb *inp;
	struct tcpcb *tp = NULL;
	struct ofp_sockaddr_in6 *sin6p;

	TCPDEBUG0;

	sin6p = (struct ofp_sockaddr_in6 *)nam;
	if (nam->sa_len != sizeof (*sin6p))
		return (OFP_EINVAL);
	/*
	 * Must disallow TCP ``connections'' to multicast addresses.
	 */
	if (sin6p->sin6_family == OFP_AF_INET6
	    && OFP_IN6_IS_ADDR_MULTICAST(&sin6p->sin6_addr))
		return (OFP_EAFNOSUPPORT);

	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("tcp6_usr_connect: inp == NULL"));
	INP_WLOCK(inp);

	if (inp->inp_flags & (INP_TIMEWAIT | INP_DROPPED)) {
		error = OFP_EINVAL;
		goto out;
	}
	tp = intotcpcb(inp);
	TCPDEBUG1();

#ifdef INET
	/*
	 * XXXRW: Some confusion: V4/V6 flags relate to binding, and
	 * therefore probably require the hash lock, which isn't held here.
	 * Is this a significant problem?
	 */
	if (OFP_IN6_IS_ADDR_V4MAPPED(&sin6p->sin6_addr)) {
		struct ofp_sockaddr_in sin;

		if ((inp->inp_flags & IN6P_IPV6_V6ONLY) != 0) {
			error = OFP_EINVAL;
			goto out;
		}

		ofp_in6_sin6_2_sin(&sin, sin6p);
		inp->inp_vflag |= INP_IPV4;
		inp->inp_vflag &= ~INP_IPV6;
#if 0
		if ((error = prison_remote_ip4(td->td_ucred,
		    &sin.sin_addr)) != 0)
			goto out;
#endif
		if ((error = tcp_connect(tp, (struct ofp_sockaddr *)&sin, td)) != 0)
			goto out;
		if ((error = tcp_output_connect(so, nam)) != 0)
			goto out;
		error = OFP_EINPROGRESS;
		goto out;
	}
#endif
	inp->inp_vflag &= ~INP_IPV4;
	inp->inp_vflag |= INP_IPV6;
	inp->inp_inc.inc_flags |= INC_ISIPV6;
#if 0
	if ((error = prison_remote_ip6(td->td_ucred, &sin6p->sin6_addr)) != 0)
		goto out;
#endif
	if ((error = tcp6_connect(tp, nam, td)) != 0)
		goto out;
	if ((error = tcp_output_connect(so, nam)) != 0)
		goto out;
	error = OFP_EINPROGRESS;
out:
	TCPDEBUG2(OFP_PRU_CONNECT);
	INP_WUNLOCK(inp);
	return (error);
}
#endif /* INET6 */

/*
 * Initiate disconnect from peer.
 * If connection never passed embryonic stage, just drop;
 * else if don't need to let data drain, then can just drop anyways,
 * else have to begin TCP shutdown process: mark socket disconnecting,
 * drain unread data, state switch to reflect user close, and
 * send segment (e.g. FIN) to peer.  Socket will be really disconnected
 * when peer sends FIN and acks ours.
 *
 * SHOULD IMPLEMENT LATER OFP_PRU_CONNECT VIA REALLOC TCPCB.
 */
static int
tcp_usr_disconnect(struct socket *so)
{
	struct inpcb *inp;
	struct tcpcb *tp = NULL;
	int error = 0;

	TCPDEBUG0;
	INP_INFO_WLOCK(&V_tcbinfo);
	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("tcp_usr_disconnect: inp == NULL"));
	INP_WLOCK(inp);
	if (inp->inp_flags & (INP_TIMEWAIT | INP_DROPPED)) {
		error = OFP_ECONNRESET;
		goto out;
	}
	tp = intotcpcb(inp);
	TCPDEBUG1();
	tcp_disconnect(tp);
out:
	TCPDEBUG2(OFP_PRU_DISCONNECT);
	INP_WUNLOCK(inp);
	INP_INFO_WUNLOCK(&V_tcbinfo);
	return (error);
}

#ifdef INET
/*
 * Accept a connection.  Essentially all the work is done at higher levels;
 * just return the address of the peer, storing through addr.
 *
 * The rationale for acquiring the ofp_tcbinfo lock here is somewhat complicated,
 * and is described in detail in the commit log entry for r175612.  Acquiring
 * it delays an accept(2) racing with ofp_sonewconn(), which inserts the socket
 * before the inpcb address/port fields are initialized.  A better fix would
 * prevent the socket from being placed in the listen queue until all fields
 * are fully initialized.
 */
static int
tcp_usr_accept(struct socket *so, struct ofp_sockaddr **nam)
{
	int error = 0;
	struct inpcb *inp = NULL;
	struct tcpcb *tp = NULL;
	struct ofp_in_addr addr;
	ofp_in_port_t port = 0;
	TCPDEBUG0;
	(void)tp;

	if (so->so_state & SS_ISDISCONNECTED)
		return (OFP_ECONNABORTED);

	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("tcp_usr_accept: inp == NULL"));
	if (!(so->so_state & SS_EVENT)) /* Already locked in event state. */
		INP_INFO_RLOCK(&V_tcbinfo);
	INP_WLOCK(inp);
	if (inp->inp_flags & (INP_TIMEWAIT | INP_DROPPED)) {
		error = OFP_ECONNABORTED;
		goto out;
	}
	tp = intotcpcb(inp);
	TCPDEBUG1();

	/*
	 * We inline ofp_in_getpeeraddr and COMMON_END here, so that we can
	 * copy the data of interest and defer the malloc until after we
	 * release the lock.
	 */
	port = inp->inp_fport;
	addr = inp->inp_faddr;

out:
	TCPDEBUG2(OFP_PRU_ACCEPT);
	INP_WUNLOCK(inp);
	INP_INFO_RUNLOCK(&V_tcbinfo);
	if (error == 0)
		*nam = ofp_in_sockaddr(port, &addr);
	return error;
}
#endif /* INET */

#ifdef INET6
static int
tcp6_usr_accept(struct socket *so, struct ofp_sockaddr **nam)
{
	struct inpcb *inp = NULL;
	int error = 0;
	struct tcpcb *tp = NULL;
	struct ofp_in_addr addr;
	struct ofp_in6_addr addr6;
	ofp_in_port_t port = 0;
	int v4 = 0;
	TCPDEBUG0;

	if (so->so_state & SS_ISDISCONNECTED)
		return (OFP_ECONNABORTED);

	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("tcp6_usr_accept: inp == NULL"));
	INP_INFO_RLOCK(&V_tcbinfo);
	INP_WLOCK(inp);

	if (inp->inp_flags & (INP_TIMEWAIT | INP_DROPPED)) {
		error = OFP_ECONNABORTED;
		goto out;
	}
	tp = intotcpcb(inp);
	(void)tp;
	TCPDEBUG1();

	/*
	 * We inline in6_mapped_peeraddr and COMMON_END here, so that we can
	 * copy the data of interest and defer the malloc until after we
	 * release the lock.
	 */
	if (inp->inp_vflag & INP_IPV4) {
		v4 = 1;
		port = inp->inp_fport;
		addr = inp->inp_faddr;
	} else {
		port = inp->inp_fport;
		addr6 = inp->in6p_faddr;
	}

out:
	TCPDEBUG2(OFP_PRU_ACCEPT);
	INP_WUNLOCK(inp);
	INP_INFO_RUNLOCK(&V_tcbinfo);

	if (error == 0) {
		if (v4)
			*nam = ofp_in6_v4mapsin6_sockaddr(port, &addr);
		else
			*nam = ofp_in6_sockaddr(port, &addr6);
	}
	return error;
}
#endif /* INET6 */

/*
 * Mark the connection as being incapable of further output.
 */
static int
tcp_usr_shutdown(struct socket *so)
{
	int error = 0;
	struct inpcb *inp;
	struct tcpcb *tp = NULL;

	TCPDEBUG0;
	INP_INFO_WLOCK(&V_tcbinfo);
	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("inp == NULL"));
	INP_WLOCK(inp);
	if (inp->inp_flags & (INP_TIMEWAIT | INP_DROPPED)) {
		error = OFP_ECONNRESET;
		goto out;
	}
	tp = intotcpcb(inp);
	TCPDEBUG1();
	ofp_socantsendmore(so);
	tcp_usrclosed(tp);
	if (!(inp->inp_flags & INP_DROPPED))
		error = tcp_output_disconnect(tp);

out:
	TCPDEBUG2(OFP_PRU_SHUTDOWN);
	INP_WUNLOCK(inp);
	INP_INFO_WUNLOCK(&V_tcbinfo);

	return (error);
}

/*
 * After a receive, possibly send window update to peer.
 */
static int
tcp_usr_rcvd(struct socket *so, int flags)
{
	struct inpcb *inp;
	struct tcpcb *tp = NULL;
	int error = 0;
	(void)flags;

	TCPDEBUG0;
	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("tcp_usr_rcvd: inp == NULL"));
	INP_WLOCK(inp);
	if (inp->inp_flags & (INP_TIMEWAIT | INP_DROPPED)) {
		error = OFP_ECONNRESET;
		goto out;
	}
	tp = intotcpcb(inp);
	TCPDEBUG1();
	tcp_output_rcvd(tp);

out:
	TCPDEBUG2(OFP_PRU_RCVD);
	INP_WUNLOCK(inp);
	return (error);
}

/*
 * Do a send by putting data in output queue and updating urgent
 * marker if URG set.  Possibly send more data.  Unlike the other
 * pru_*() routines, the mbuf chains are our responsibility.  We
 * must either enqueue them or free them.  The other pru_* routines
 * generally are caller-frees.
 */
static int
tcp_usr_send(struct socket *so, int flags, odp_packet_t m,
    struct ofp_sockaddr *nam, odp_packet_t control, struct thread *td)
{
	int error = 0;
	struct inpcb *inp;
	struct tcpcb *tp = NULL;
#ifdef INET6
	int isipv6;
#endif
	int info_locked = 0;
	TCPDEBUG0;
	(void)td;
	/*
	 * We require the pcbinfo lock if we will close the socket as part of
	 * this call.
	 */
	if (flags & PRUS_EOF) {
		INP_INFO_WLOCK(&V_tcbinfo);
		info_locked = 1;
	}
	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("tcp_usr_send: inp == NULL"));
	INP_WLOCK(inp);
	if (inp->inp_flags & (INP_TIMEWAIT | INP_DROPPED)) {
		if (control != ODP_PACKET_INVALID)
			odp_packet_free(control);
		if (m != ODP_PACKET_INVALID)
			odp_packet_free(m);
		error = OFP_ECONNRESET;
		goto out;
	}
#ifdef INET6
	isipv6 = nam && nam->sa_family == OFP_AF_INET6;
#endif /* INET6 */
	tp = intotcpcb(inp);
	TCPDEBUG1();
	if (control != ODP_PACKET_INVALID) {
		/* TCP doesn't do control messages (rights, creds, etc) */
		if (odp_packet_len(control)) {
			odp_packet_free(control);
			if (m != ODP_PACKET_INVALID)
				odp_packet_free(m);
			error = OFP_EINVAL;
			goto out;
		}
		odp_packet_free(control);	/* empty control, just free it */
	}
	if (!(flags & PRUS_OOB)) {
		ofp_sbappendstream(&so->so_snd, m);
		if (nam && tp->t_state < TCPS_SYN_SENT) {
			/*
			 * Do implied connect if not yet connected,
			 * initialize window to default value, and
			 * initialize maxseg/maxopd using peer's cached
			 * MSS.
			 */
#ifdef INET6
			if (isipv6)
				error = tcp6_connect(tp, nam, td);
			else
#endif
				error = tcp_connect(tp, nam, td);
			if (error)
				goto out;
			tp->snd_wnd = OFP_TTCP_CLIENT_SND_WND;
			ofp_tcp_mss(tp, -1);
		}
		if (flags & PRUS_EOF) {
			/*
			 * Close the send side of the connection after
			 * the data is sent.
			 */
			INP_INFO_WLOCK_ASSERT(&V_tcbinfo);
			ofp_socantsendmore(so);
			tcp_usrclosed(tp);
		}
		if (!(inp->inp_flags & INP_DROPPED)) {
			if (flags & PRUS_MORETOCOME)
				t_flags_or(tp->t_flags, TF_MORETOCOME);
			error = tcp_output_send(tp);
			if (flags & PRUS_MORETOCOME)
				t_flags_and(tp->t_flags, ~TF_MORETOCOME);
		}
	} else {
		/*
		 * XXXRW: PRUS_EOF not implemented with PRUS_OOB?
		 */
		SOCKBUF_LOCK(&so->so_snd);
		if (sbspace(&so->so_snd) < -512) {
			SOCKBUF_UNLOCK(&so->so_snd);
			odp_packet_free(m);
			error = OFP_ENOBUFS;
			goto out;
		}
		/*
		 * According to RFC961 (Assigned Protocols),
		 * the urgent pointer points to the last octet
		 * of urgent data.  We continue, however,
		 * to consider it to indicate the first octet
		 * of data past the urgent section.
		 * Otherwise, snd_up should be one lower.
		 */
		ofp_sbappendstream_locked(&so->so_snd, m);
		SOCKBUF_UNLOCK(&so->so_snd);
		if (nam && tp->t_state < TCPS_SYN_SENT) {
			/*
			 * Do implied connect if not yet connected,
			 * initialize window to default value, and
			 * initialize maxseg/maxopd using peer's cached
			 * MSS.
			 */
#ifdef INET6
			if (isipv6)
				error = tcp6_connect(tp, nam, td);
			else
#endif
				error = tcp_connect(tp, nam, td);
			if (error)
				goto out;
			tp->snd_wnd = OFP_TTCP_CLIENT_SND_WND;
			ofp_tcp_mss(tp, -1);
		}
		tp->snd_up = tp->snd_una + so->so_snd.sb_cc;
		t_flags_or(tp->t_flags, TF_FORCEDATA);
		error = tcp_output_send(tp);
		t_flags_and(tp->t_flags, ~TF_FORCEDATA);
	}
out:
	TCPDEBUG2((flags & PRUS_OOB) ? OFP_PRU_SENDOOB :
		  ((flags & PRUS_EOF) ? OFP_PRU_SEND_EOF : OFP_PRU_SEND));
#ifdef PASSIVE_INET
	if (inp->inp_flags2 & INP_PASSIVE)
		in_passive_release_locks(so);
	else
#endif
	INP_WUNLOCK(inp);
	if (info_locked)
		INP_INFO_WUNLOCK(&V_tcbinfo);
	return (error);
}

/*
 * Abort the TCP.  Drop the connection abruptly.
 */
static void
tcp_usr_abort(struct socket *so)
{
	struct inpcb *inp;
	struct tcpcb *tp = NULL;
	TCPDEBUG0;

	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("tcp_usr_abort: inp == NULL"));

	INP_INFO_WLOCK(&V_tcbinfo);
	INP_WLOCK(inp);
	KASSERT(inp->inp_socket != NULL,
	    ("tcp_usr_abort: inp_socket == NULL"));

	/*
	 * If we still have full TCP state, and we're not dropped, drop.
	 */
	if (!(inp->inp_flags & INP_TIMEWAIT) &&
	    !(inp->inp_flags & INP_DROPPED)) {
		tp = intotcpcb(inp);
		TCPDEBUG1();
		ofp_tcp_drop(tp, OFP_ECONNABORTED);
		TCPDEBUG2(OFP_PRU_ABORT);
	}
	if (!(inp->inp_flags & INP_DROPPED)) {
		OFP_SOCK_LOCK(so);
		so->so_state |= SS_PROTOREF;
		OFP_SOCK_UNLOCK(so);
		inp->inp_flags |= INP_SOCKREF;
	}
	INP_WUNLOCK(inp);
	INP_INFO_WUNLOCK(&V_tcbinfo);
}

/*
 * TCP socket is closed.  Start friendly disconnect.
 */
static void
tcp_usr_close(struct socket *so)
{
	struct inpcb *inp;
	struct tcpcb *tp = NULL;
	TCPDEBUG0;

	inp = sotoinpcb(so);

	KASSERT(inp != NULL, ("tcp_usr_close: inp == NULL so=%p", so));

	INP_INFO_WLOCK(&V_tcbinfo);
	INP_WLOCK(inp);

	KASSERT(inp->inp_socket != NULL,
		("tcp_usr_close: inp_socket == NULL, inp=%p", inp));

	/*
	 * If we still have full TCP state, and we're not dropped, initiate
	 * a disconnect.
	 */
	if (!(inp->inp_flags & INP_TIMEWAIT) &&
	    !(inp->inp_flags & INP_DROPPED)) {
		tp = intotcpcb(inp);
		TCPDEBUG1();
		tcp_disconnect(tp);
		TCPDEBUG2(OFP_PRU_CLOSE);
	}
	if (!(inp->inp_flags & INP_DROPPED)) {
		OFP_SOCK_LOCK(so);
		so->so_state |= SS_PROTOREF;
		OFP_SOCK_UNLOCK(so);
		inp->inp_flags |= INP_SOCKREF;
	}
	INP_WUNLOCK(inp);
	INP_INFO_WUNLOCK(&V_tcbinfo);
}

/*
 * Receive out-of-band data.
 */
static int
tcp_usr_rcvoob(struct socket *so, odp_packet_t m, int flags)
{
	int error = 0;
	struct inpcb *inp;
	struct tcpcb *tp = NULL;
	(void)m;
	(void)flags;

	TCPDEBUG0;
	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("tcp_usr_rcvoob: inp == NULL"));
	INP_WLOCK(inp);
	if (inp->inp_flags & (INP_TIMEWAIT | INP_DROPPED)) {
		error = OFP_ECONNRESET;
		goto out;
	}
	tp = intotcpcb(inp);
	TCPDEBUG1();
	if ((so->so_oobmark == 0 &&
	    (so->so_rcv.sb_state & SBS_RCVATMARK) == 0) ||
	    (so->so_options & OFP_SO_OOBINLINE) ||
	    (tp->t_oobflags & OFP_TCPOOB_HADDATA)) {
		error = OFP_EINVAL;
		goto out;
	}
	if ((tp->t_oobflags & OFP_TCPOOB_HAVEDATA) == 0) {
		error = OFP_EWOULDBLOCK;
		goto out;
	}
	/* HJo: FIX:
	odp_packet_len(m) = 1;
	*(char *)odp_packet_data(m) = tp->t_iobc;
	if ((flags & OFP_MSG_PEEK) == 0)
		tp->t_oobflags ^= (TCPOOB_HAVEDATA | TCPOOB_HADDATA);
	*/

out:
	TCPDEBUG2(OFP_PRU_RCVOOB);
	INP_WUNLOCK(inp);
	return (error);
}

struct pr_usrreqs ofp_tcp_usrreqs = {
	.pru_abort =		tcp_usr_abort,
	.pru_accept =		tcp_usr_accept,
	.pru_attach =		tcp_usr_attach,
	.pru_bind =		tcp_usr_bind,
	.pru_connect =		tcp_usr_connect,
	.pru_control =		ofp_in_control,
	.pru_detach =		tcp_usr_detach,
	.pru_disconnect =	tcp_usr_disconnect,
	.pru_listen =		tcp_usr_listen,
	.pru_peeraddr =		ofp_in_getpeeraddr,
	.pru_rcvd =		tcp_usr_rcvd,
	.pru_rcvoob =		tcp_usr_rcvoob,
	.pru_send =		tcp_usr_send,
	.pru_shutdown =		tcp_usr_shutdown,
	.pru_sockaddr =		ofp_in_getsockaddr,
	.pru_sosetlabel =	ofp_in_pcbsosetlabel,
	.pru_close =		tcp_usr_close,
	.pru_sosend =		ofp_sosend_generic,
	.pru_soreceive =	ofp_soreceive_generic,
};

#ifdef INET6
struct pr_usrreqs ofp_tcp6_usrreqs = {
	.pru_abort =		tcp_usr_abort,
	.pru_accept =		tcp6_usr_accept,
	.pru_attach =		tcp_usr_attach,
	.pru_bind =		tcp6_usr_bind,
	.pru_connect =		tcp6_usr_connect,
	.pru_control =		NULL/*in6_control*/,
	.pru_detach =		tcp_usr_detach,
	.pru_disconnect =	tcp_usr_disconnect,
	.pru_listen =		tcp6_usr_listen,
	.pru_peeraddr =		NULL/*in6_mapped_peeraddr*/,
	.pru_rcvd =		tcp_usr_rcvd,
	.pru_rcvoob =		tcp_usr_rcvoob,
	.pru_send =		tcp_usr_send,
	.pru_shutdown =		tcp_usr_shutdown,
	.pru_sockaddr =		NULL/*in6_mapped_sockaddr*/,
	.pru_sosetlabel =	ofp_in_pcbsosetlabel,
	.pru_close =		tcp_usr_close,
	.pru_sosend =		ofp_sosend_generic,
	.pru_soreceive =	ofp_soreceive_generic,
};
#endif /* INET6 */

#ifdef INET
/*
 * Common subroutine to open a TCP connection to remote host specified
 * by struct ofp_sockaddr_in in mbuf *nam.  Call ofp_in_pcbbind to assign a local
 * port number if needed.  Call ofp_in_pcbconnect_setup to do the routing and
 * to choose a local host address (interface).  If there is an existing
 * incarnation of the same connection in TIME-WAIT state and if the remote
 * host was sending CC options and if the connection duration was < MSL, then
 * truncate the previous TIME-WAIT state and proceed.
 * Initialize connection parameters and enter SYN-SENT state.
 */
static int
tcp_connect(struct tcpcb *tp, struct ofp_sockaddr *nam, struct thread *td)
{
	struct inpcb *inp = tp->t_inpcb, *oinp;
	struct socket *so = inp->inp_socket;
	struct ofp_in_addr laddr;
	uint16_t lport;
	int error;

	INP_WLOCK_ASSERT(inp);
	INP_HASH_WLOCK(&V_tcbinfo);

	if (inp->inp_lport == 0) {
		error = ofp_in_pcbbind(inp, (struct ofp_sockaddr *)0, td->td_ucred);
		if (error)
			goto out;
	}

	/*
	 * Cannot simply call ofp_in_pcbconnect, because there might be an
	 * earlier incarnation of this same connection still in
	 * TIME_WAIT state, creating an ADDRINUSE error.
	 */
	laddr = inp->inp_laddr;
	lport = inp->inp_lport;
	error = ofp_in_pcbconnect_setup(inp, nam, &laddr.s_addr, &lport,
	    &inp->inp_faddr.s_addr, &inp->inp_fport, &oinp, td->td_ucred);
	if (error && oinp == NULL)
		goto out;
	if (oinp) {
		error = OFP_EADDRINUSE;
		goto out;
	}
	inp->inp_laddr = laddr;
	ofp_in_pcbrehash(inp);
	INP_HASH_WUNLOCK(&V_tcbinfo);

	/*
	 * Compute window scaling to request:
	 * Scale to fit into sweet spot.  See tcp_syncache.c.
	 * XXX: This should move to ofp_tcp_output().
	 */
	while (tp->request_r_scale < OFP_TCP_MAX_WINSHIFT &&
	       ((uint64_t)OFP_TCP_MAXWIN << tp->request_r_scale) < ofp_sb_max)
		tp->request_r_scale++;

	ofp_soisconnecting(so);
	TCPSTAT_INC(tcps_connattempt);
	tp->t_state = TCPS_SYN_SENT;
	ofp_tcp_timer_activate(tp, TT_KEEP, TP_KEEPINIT(tp));
	tp->iss = ofp_tcp_new_isn(tp);
	tcp_sendseqinit(tp);

	return 0;

out:
	INP_HASH_WUNLOCK(&V_tcbinfo);
	return (error);
}
#endif /* INET */

#ifdef INET6
static int
tcp6_connect(struct tcpcb *tp, struct ofp_sockaddr *nam, struct thread *td)
{
	struct inpcb *inp = tp->t_inpcb, *oinp;
	struct socket *so = inp->inp_socket;
	struct ofp_sockaddr_in6 *sin6 = (struct ofp_sockaddr_in6 *)nam;
	struct ofp_in6_addr addr6;
	int error;

	INP_WLOCK_ASSERT(inp);
	INP_HASH_WLOCK(&V_tcbinfo);

	if (inp->inp_lport == 0) {
		error = ofp_in6_pcbbind(inp, (struct ofp_sockaddr *)0, td->td_ucred);
		if (error)
			goto out;
	}

	/*
	 * Cannot simply call ofp_in_pcbconnect, because there might be an
	 * earlier incarnation of this same connection still in
	 * TIME_WAIT state, creating an ADDRINUSE error.
	 * in6_pcbladdr() also handles scope zone IDs.
	 *
	 * XXXRW: We wouldn't need to expose in6_pcblookup_hash_locked()
	 * outside of in6_pcb.c if there were an in6_pcbconnect_setup().
	 */
	error = ofp_in6_pcbladdr(inp, nam, &addr6);
	if (error)
		goto out;
	oinp = ofp_in6_pcblookup_hash_locked(inp->inp_pcbinfo,
				  &sin6->sin6_addr, sin6->sin6_port,
				  OFP_IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr)
				  ? &addr6
				  : &inp->in6p_laddr,
				  inp->inp_lport,  0, NULL);
	if (oinp) {
		OFP_ERR("OFP_EADDRINUSE");
		error = OFP_EADDRINUSE;
		goto out;
	}

	if (OFP_IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr))
		inp->in6p_laddr = addr6;

	inp->in6p_faddr = sin6->sin6_addr;
	inp->inp_fport = sin6->sin6_port;
	/* update flowinfo - draft-itojun-ipv6-flowlabel-api-00 */
	inp->inp_flow &= ~OFP_IPV6_FLOWLABEL_MASK;
	if (inp->inp_flags & IN6P_AUTOFLOWLABEL)
		inp->inp_flow |=
		    (odp_cpu_to_be_32(ofp_ip6_randomflowlabel())
		    	& OFP_IPV6_FLOWLABEL_MASK);
	ofp_in_pcbrehash(inp);
	INP_HASH_WUNLOCK(&V_tcbinfo);

	/* Compute window scaling to request.  */
	while (tp->request_r_scale < OFP_TCP_MAX_WINSHIFT &&
	    (uint64_t)(OFP_TCP_MAXWIN << tp->request_r_scale) < ofp_sb_max)
		tp->request_r_scale++;

	ofp_soisconnecting(so);
	TCPSTAT_INC(tcps_connattempt);
	tp->t_state = TCPS_SYN_SENT;
	ofp_tcp_timer_activate(tp, TT_KEEP, TP_KEEPINIT(tp));
	tp->iss = ofp_tcp_new_isn(tp);
	tcp_sendseqinit(tp);

	return 0;

out:
	INP_HASH_WUNLOCK(&V_tcbinfo);
	return error;
}
#endif /* INET6 */

#if 0
/*
 * Export TCP internal state information via a struct tcp_info, based on the
 * Linux 2.6 API.  Not ABI compatible as our constants are mapped differently
 * (TCP state machine, etc).  We export all information using FreeBSD-native
 * constants -- for example, the numeric values for tcpi_state will differ
 * from Linux.
 */
static void
tcp_fill_info(struct tcpcb *tp, struct tcp_info *ti)
{

	INP_WLOCK_ASSERT(tp->t_inpcb);
	bzero(ti, sizeof(*ti));

	ti->tcpi_state = tp->t_state;
	if ((tp->t_flags & TF_REQ_TSTMP) && (tp->t_flags & TF_RCVD_TSTMP))
		ti->tcpi_options |= TCPI_OPT_TIMESTAMPS;
	if (tp->t_flags & TF_SACK_PERMIT)
		ti->tcpi_options |= TCPI_OPT_SACK;
	if ((tp->t_flags & TF_REQ_SCALE) && (tp->t_flags & TF_RCVD_SCALE)) {
		ti->tcpi_options |= TCPI_OPT_WSCALE;
		ti->tcpi_snd_wscale = tp->snd_scale;
		ti->tcpi_rcv_wscale = tp->rcv_scale;
	}

	ti->tcpi_rto = tp->t_rxtcur * tick;
	ti->tcpi_last_data_recv = (long)(ticks - (int)tp->t_rcvtime) * tick;
	ti->tcpi_rtt = ((uint64_t)tp->t_srtt * tick) >> TCP_RTT_SHIFT;
	ti->tcpi_rttvar = ((uint64_t)tp->t_rttvar * tick) >> TCP_RTTVAR_SHIFT;

	ti->tcpi_snd_ssthresh = tp->snd_ssthresh;
	ti->tcpi_snd_cwnd = tp->snd_cwnd;

	/*
	 * FreeBSD-specific extension fields for tcp_info.
	 */
	ti->tcpi_rcv_space = tp->rcv_wnd;
	ti->tcpi_rcv_nxt = tp->rcv_nxt;
	ti->tcpi_snd_wnd = tp->snd_wnd;
	ti->tcpi_snd_bwnd = 0;		/* Unused, kept for compat. */
	ti->tcpi_snd_nxt = tp->snd_nxt;
	ti->tcpi_snd_mss = tp->t_maxseg;
	ti->tcpi_rcv_mss = tp->t_maxseg;
	if (tp->t_flags & TF_TOE)
		ti->tcpi_options |= TCPI_OPT_TOE;
	ti->tcpi_snd_rexmitpack = tp->t_sndrexmitpack;
	ti->tcpi_rcv_ooopack = tp->t_rcvoopack;
	ti->tcpi_snd_zerowin = tp->t_sndzerowin;
}
#endif

/*
 * ofp_tcp_ctloutput() must drop the inpcb lock before performing copyin on
 * socket option arguments.  When it re-acquires the lock after the copy, it
 * has to revalidate that the connection is still valid for the socket
 * option.
 */
#define INP_WLOCK_RECHECK(inp) do {					\
	INP_WLOCK(inp);							\
	if (inp->inp_flags & (INP_TIMEWAIT | INP_DROPPED)) {		\
		INP_WUNLOCK(inp);					\
		return (OFP_ECONNRESET);					\
	}								\
	tp = intotcpcb(inp);						\
} while(0)

int
ofp_tcp_ctloutput(struct socket *so, struct sockopt *sopt)
{
#if 0
	int	error, opt, optval;
	uint32_t	ui;
	struct	inpcb *inp;
	struct	tcpcb *tp;
	struct	tcp_info ti;
	char buf[TCP_CA_NAME_MAX];
	struct cc_algo *algo;

	error = 0;
	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("ofp_tcp_ctloutput: inp == NULL"));
	INP_WLOCK(inp);
	if (sopt->sopt_level != OFP_IPPROTO_TCP) {
#ifdef INET6
		if (inp->inp_vflag & INP_IPV6PROTO) {
			INP_WUNLOCK(inp);
			error = ip6_ctloutput(so, sopt);
		}
#endif /* INET6 */
#if defined(INET6) && defined(INET)
		else
#endif
#ifdef INET
		{
			INP_WUNLOCK(inp);
			error = ofp_ip_ctloutput(so, sopt);
		}
#endif
		return (error);
	}
	if (inp->inp_flags & (INP_TIMEWAIT | INP_DROPPED)) {
		INP_WUNLOCK(inp);
		return (OFP_ECONNRESET);
	}

	switch (sopt->sopt_dir) {
	case SOPT_SET:
		switch (sopt->sopt_name) {
#ifdef TCP_SIGNATURE
		case TCP_MD5SIG:
			INP_WUNLOCK(inp);
			error = sooptcopyin(sopt, &optval, sizeof optval,
			    sizeof optval);
			if (error)
				return (error);

			INP_WLOCK_RECHECK(inp);
			if (optval > 0)
				t_flags_or(tp->t_flags, TF_SIGNATURE);
			else
				t_flags_and(tp->t_flags, ~TF_SIGNATURE);
			INP_WUNLOCK(inp);
			break;
#endif /* TCP_SIGNATURE */
		case TCP_NODELAY:
		case TCP_NOOPT:
			INP_WUNLOCK(inp);
			error = sooptcopyin(sopt, &optval, sizeof optval,
			    sizeof optval);
			if (error)
				return (error);

			INP_WLOCK_RECHECK(inp);
			switch (sopt->sopt_name) {
			case TCP_NODELAY:
				opt = TF_NODELAY;
				break;
			case TCP_NOOPT:
				opt = TF_NOOPT;
				break;
			default:
				opt = 0; /* dead code to fool gcc */
				break;
			}

			if (optval)
				t_flags_or(tp->t_flags, opt);
			else
				t_flags_and(tp->t_flags, ~opt);
			INP_WUNLOCK(inp);
			break;

		case TCP_NOPUSH:
			INP_WUNLOCK(inp);
			error = sooptcopyin(sopt, &optval, sizeof optval,
			    sizeof optval);
			if (error)
				return (error);

			INP_WLOCK_RECHECK(inp);
			if (optval)
				t_flags_or(tp->t_flags, TF_NOPUSH);
			else if (tp->t_flags & TF_NOPUSH) {
				t_flags_and(tp->t_flags, ~TF_NOPUSH);
				if (TCPS_HAVEESTABLISHED(tp->t_state))
					error = ofp_tcp_output(tp);
			}
			INP_WUNLOCK(inp);
			break;

		case TCP_MAXSEG:
			INP_WUNLOCK(inp);
			error = sooptcopyin(sopt, &optval, sizeof optval,
			    sizeof optval);
			if (error)
				return (error);

			INP_WLOCK_RECHECK(inp);
			if (optval > 0 && optval <= tp->t_maxseg &&
			    optval + 40 >= V_tcp_minmss)
				tp->t_maxseg = optval;
			else
				error = OFP_EINVAL;
			INP_WUNLOCK(inp);
			break;

		case TCP_INFO:
			INP_WUNLOCK(inp);
			error = OFP_EINVAL;
			break;

		case TCP_CONGESTION:
			INP_WUNLOCK(inp);
			bzero(buf, sizeof(buf));
			error = sooptcopyin(sopt, &buf, sizeof(buf), 1);
			if (error)
				break;
			INP_WLOCK_RECHECK(inp);
			/*
			 * Return OFP_EINVAL if we can't find the requested cc algo.
			 */
			error = OFP_EINVAL;
			CC_LIST_RLOCK();
			OFP_STAILQ_FOREACH(algo, &cc_list, entries) {
				if (strncmp(buf, algo->name, TCP_CA_NAME_MAX)
				    == 0) {
					/* We've found the requested algo. */
					error = 0;
					/*
					 * We hold a write lock over the ofp_tcb
					 * so it's safe to do these things
					 * without ordering concerns.
					 */
					if (CC_ALGO(tp)->cb_destroy != NULL)
						CC_ALGO(tp)->cb_destroy(tp->ccv);
					CC_ALGO(tp) = algo;
					/*
					 * If something goes pear shaped
					 * initialising the new algo,
					 * fall back to newreno (which
					 * does not require initialisation).
					 */
					if (algo->cb_init != NULL)
						if (algo->cb_init(tp->ccv) > 0) {
							CC_ALGO(tp) = &newreno_cc_algo;
							/*
							 * The only reason init
							 * should fail is
							 * because of malloc.
							 */
							error = OFP_ENOMEM;
						}
					break; /* Break the OFP_STAILQ_FOREACH. */
				}
			}
			CC_LIST_RUNLOCK();
			INP_WUNLOCK(inp);
			break;

		case TCP_KEEPIDLE:
		case TCP_KEEPINTVL:
		case TCP_KEEPINIT:
			INP_WUNLOCK(inp);
			error = sooptcopyin(sopt, &ui, sizeof(ui), sizeof(ui));
			if (error)
				return (error);

			if (ui > (UINT_MAX / hz)) {
				error = OFP_EINVAL;
				break;
			}
			ui *= hz;

			INP_WLOCK_RECHECK(inp);
			switch (sopt->sopt_name) {
			case TCP_KEEPIDLE:
				tp->t_keepidle = ui;
				/*
				 * XXX: better check current remaining
				 * timeout and "merge" it with new value.
				 */
				if ((tp->t_state > TCPS_LISTEN) &&
				    (tp->t_state <= TCPS_CLOSING))
					ofp_tcp_timer_activate(tp, TT_KEEP,
					    TP_KEEPIDLE(tp));
				break;
			case TCP_KEEPINTVL:
				tp->t_keepintvl = ui;
				if ((tp->t_state == TCPS_FIN_WAIT_2) &&
				    (TP_MAXIDLE(tp) > 0))
					ofp_tcp_timer_activate(tp, TT_2MSL,
					    TP_MAXIDLE(tp));
				break;
			case TCP_KEEPINIT:
				tp->t_keepinit = ui;
				if (tp->t_state == TCPS_SYN_RECEIVED ||
				    tp->t_state == TCPS_SYN_SENT)
					ofp_tcp_timer_activate(tp, TT_KEEP,
					    TP_KEEPINIT(tp));
				break;
			}
			INP_WUNLOCK(inp);
			break;

#ifdef PASSIVE_INET
		case TCP_REASSDL:
				INP_WUNLOCK(inp);
				error = sooptcopyin(sopt, &ui, sizeof(ui), sizeof(ui));
				if (error)
					return (error);

				if (ui > (UINT_MAX / hz)) {
					error = OFP_EINVAL;
					break;
				}
				ui *= hz;

				INP_WLOCK_RECHECK(inp);
				tp->t_reassdl = ui / 1000;
				if (tp->t_reassdl == 0 && ui != 0)
					tp->t_reassdl = 1;
				INP_WUNLOCK(inp);
			break;
#endif

		case TCP_KEEPCNT:
			INP_WUNLOCK(inp);
			error = sooptcopyin(sopt, &ui, sizeof(ui), sizeof(ui));
			if (error)
				return (error);

			INP_WLOCK_RECHECK(inp);
			tp->t_keepcnt = ui;
			if ((tp->t_state == TCPS_FIN_WAIT_2) &&
			    (TP_MAXIDLE(tp) > 0))
				ofp_tcp_timer_activate(tp, TT_2MSL,
				    TP_MAXIDLE(tp));
			INP_WUNLOCK(inp);
			break;

		default:
			INP_WUNLOCK(inp);
			error = OFP_ENOPROTOOPT;
			break;
		}
		break;

	case SOPT_GET:
		tp = intotcpcb(inp);
		switch (sopt->sopt_name) {
#ifdef TCP_SIGNATURE
		case TCP_MD5SIG:
			optval = (tp->t_flags & TF_SIGNATURE) ? 1 : 0;
			INP_WUNLOCK(inp);
			error = sooptcopyout(sopt, &optval, sizeof optval);
			break;
#endif

		case TCP_NODELAY:
			optval = tp->t_flags & TF_NODELAY;
			INP_WUNLOCK(inp);
			error = sooptcopyout(sopt, &optval, sizeof optval);
			break;
		case TCP_MAXSEG:
			optval = tp->t_maxseg;
			INP_WUNLOCK(inp);
			error = sooptcopyout(sopt, &optval, sizeof optval);
			break;
		case TCP_NOOPT:
			optval = tp->t_flags & TF_NOOPT;
			INP_WUNLOCK(inp);
			error = sooptcopyout(sopt, &optval, sizeof optval);
			break;
		case TCP_NOPUSH:
			optval = tp->t_flags & TF_NOPUSH;
			INP_WUNLOCK(inp);
			error = sooptcopyout(sopt, &optval, sizeof optval);
			break;
		case TCP_INFO:
			tcp_fill_info(tp, &ti);
			INP_WUNLOCK(inp);
			error = sooptcopyout(sopt, &ti, sizeof ti);
			break;
		case TCP_CONGESTION:
			bzero(buf, sizeof(buf));
			strlcpy(buf, CC_ALGO(tp)->name, TCP_CA_NAME_MAX);
			INP_WUNLOCK(inp);
			error = sooptcopyout(sopt, buf, TCP_CA_NAME_MAX);
			break;
		default:
			INP_WUNLOCK(inp);
			error = OFP_ENOPROTOOPT;
			break;
		}
		break;
	}
	return (error);
#else
	int error, optval;
	struct inpcb *inp = sotoinpcb(so);

	if (sopt->sopt_level != OFP_IPPROTO_TCP)
		return 0;

	switch (sopt->sopt_dir) {
	case SOPT_SET:
		switch (sopt->sopt_name) {
		case OFP_TCP_CORK:
			error = ofp_sooptcopyin(sopt, &optval, sizeof(optval), sizeof(optval));
			if (error) return error;

			if (!optval) {
				INP_WLOCK(inp);
				struct tcpcb *tp = intotcpcb(inp);
				if (TCPS_HAVEESTABLISHED(tp->t_state)) {
					t_flags_or(tp->t_flags, TF_FORCEDATA);
					ofp_tcp_output(tp);
					t_flags_and(tp->t_flags, ~TF_FORCEDATA);
				}
				INP_WUNLOCK(inp);
			}
		}
		break;
	default:
		break;
	}

	return 0;
#endif
}
#undef INP_WLOCK_RECHECK

/*
 * ofp_tcp_sendspace and ofp_tcp_recvspace are the default send and receive window
 * sizes, respectively.  These are obsolescent (this information should
 * be set by the route).
 */
uint64_t ofp_tcp_sendspace = 1024*32;
OFP_SYSCTL_ULONG(_net_inet_tcp, TCPCTL_SENDSPACE, sendspace, OFP_CTLFLAG_RW,
    &ofp_tcp_sendspace , 0, "Maximum outgoing TCP datagram size");
uint64_t ofp_tcp_recvspace = 1024*64;
OFP_SYSCTL_ULONG(_net_inet_tcp, TCPCTL_RECVSPACE, recvspace, OFP_CTLFLAG_RW,
    &ofp_tcp_recvspace , 0, "Maximum incoming TCP datagram size");

/*
 * Attach TCP protocol to socket, allocating
 * internet protocol control block, tcp control block,
 * bufer space, and entering LISTEN state if to accept connections.
 */
static int
tcp_attach(struct socket *so)
{
	struct tcpcb *tp;
	struct inpcb *inp;
	int error;

	if (so->so_snd.sb_hiwat == 0 || so->so_rcv.sb_hiwat == 0) {
		error = ofp_soreserve(so, ofp_tcp_sendspace, ofp_tcp_recvspace);
		if (error)
			return (error);
	}
	so->so_rcv.sb_flags |= SB_AUTOSIZE;
	so->so_snd.sb_flags |= SB_AUTOSIZE;
	INP_INFO_WLOCK(&V_tcbinfo);
	error = ofp_in_pcballoc(so, &V_tcbinfo);
	if (error) {
		INP_INFO_WUNLOCK(&V_tcbinfo);
		return (error);
	}
	inp = sotoinpcb(so);
#ifdef INET6
	if (inp->inp_vflag & INP_IPV6PROTO) {
		inp->inp_vflag |= INP_IPV6;
		inp->in6p_hops = V_ip6_defhlim;
	}
	else
#endif
	inp->inp_vflag |= INP_IPV4;
	tp = ofp_tcp_newtcpcb(inp);
	if (tp == NULL) {
		ofp_in_pcbdetach(inp);
		ofp_in_pcbfree(inp);
		INP_INFO_WUNLOCK(&V_tcbinfo);
		return (OFP_ENOBUFS);
	}
	tp->t_state = TCPS_CLOSED;
	INP_WUNLOCK(inp);
	INP_INFO_WUNLOCK(&V_tcbinfo);
	return (0);
}

/*
 * Initiate (or continue) disconnect.
 * If embryonic state, just send reset (once).
 * If in ``let data drain'' option and linger null, just drop.
 * Otherwise (hard), mark socket disconnecting and drop
 * current input data; switch states based on user close, and
 * send segment to peer (with FIN).
 */
static void
tcp_disconnect(struct tcpcb *tp)
{
	struct inpcb *inp = tp->t_inpcb;
	struct socket *so = inp->inp_socket;

	INP_INFO_WLOCK_ASSERT(&V_tcbinfo);
	INP_WLOCK_ASSERT(inp);

	/*
	 * Neither ofp_tcp_close() nor ofp_tcp_drop() should return NULL, as the
	 * socket is still open.
	 */
	if (tp->t_state < TCPS_ESTABLISHED) {
		tp = ofp_tcp_close(tp);
		KASSERT(tp != NULL,
		    ("tcp_disconnect: ofp_tcp_close() returned NULL"));
	} else if ((so->so_options & OFP_SO_LINGER) && so->so_linger == 0) {
		tp = ofp_tcp_drop(tp, 0);
		KASSERT(tp != NULL,
		    ("tcp_disconnect: ofp_tcp_drop() returned NULL"));
	} else {
		ofp_soisdisconnecting(so);
		ofp_sbflush(&so->so_rcv);
		tcp_usrclosed(tp);
		if (!(inp->inp_flags & INP_DROPPED))
			tcp_output_disconnect(tp);
	}
}

/*
 * User issued close, and wish to trail through shutdown states:
 * if never received SYN, just forget it.  If got a SYN from peer,
 * but haven't sent FIN, then go to FIN_WAIT_1 state to send peer a FIN.
 * If already got a FIN from peer, then almost done; go to LAST_ACK
 * state.  In all other cases, have already sent FIN to peer (e.g.
 * after OFP_PRU_SHUTDOWN), and just have to play tedious game waiting
 * for peer to send FIN or not respond to keep-alives, etc.
 * We can let the user exit from the close as soon as the FIN is acked.
 */
static void
tcp_usrclosed(struct tcpcb *tp)
{

	INP_INFO_WLOCK_ASSERT(&V_tcbinfo);
	INP_WLOCK_ASSERT(tp->t_inpcb);
#ifdef PASSIVE_INET
again:
#endif
	switch (tp->t_state) {
	case TCPS_LISTEN:
		tcp_offload_listen_close(tp);
		/* FALLTHROUGH */
	case TCPS_CLOSED:
		tp->t_state = TCPS_CLOSED;
		tp = ofp_tcp_close(tp);
		/*
		 * ofp_tcp_close() should never return NULL here as the socket is
		 * still open.
		 */
		KASSERT(tp != NULL,
		    ("tcp_usrclosed: ofp_tcp_close() returned NULL"));
		break;

	case TCPS_SYN_SENT:
	case TCPS_SYN_RECEIVED:
		t_flags_or(tp->t_flags, TF_NEEDFIN);
		break;

	case TCPS_ESTABLISHED:
		tp->t_state = TCPS_FIN_WAIT_1;
		break;

	case TCPS_CLOSE_WAIT:
#ifdef PASSIVE_INET
		/* Passive sockets don't wait for an ack. */
		if (tp->t_inpcb->inp_flags2 & INP_PASSIVE) {
			tp->t_state = TCPS_CLOSED;
			goto again;
		}
#endif
		tp->t_state = TCPS_LAST_ACK;
		break;
	}
	if (tp->t_state >= TCPS_FIN_WAIT_2) {
		ofp_soisdisconnected(tp->t_inpcb->inp_socket);
		/* Prevent the connection hanging in FIN_WAIT_2 forever. */
		if (tp->t_state == TCPS_FIN_WAIT_2) {
			int timeout;

			timeout = (ofp_tcp_fast_finwait2_recycle) ?
			    ofp_tcp_finwait2_timeout : TP_MAXIDLE(tp);
			ofp_tcp_timer_activate(tp, TT_2MSL, timeout);
		}
	}
}

#ifdef DDB
static void
db_print_indent(int indent)
{
	int i;

	for (i = 0; i < indent; i++)
		db_printf(" ");
}

static void
db_print_tstate(int t_state)
{

	switch (t_state) {
	case TCPS_CLOSED:
		db_printf("TCPS_CLOSED");
		return;

	case TCPS_LISTEN:
		db_printf("TCPS_LISTEN");
		return;

	case TCPS_SYN_SENT:
		db_printf("TCPS_SYN_SENT");
		return;

	case TCPS_SYN_RECEIVED:
		db_printf("TCPS_SYN_RECEIVED");
		return;

	case TCPS_ESTABLISHED:
		db_printf("TCPS_ESTABLISHED");
		return;

	case TCPS_CLOSE_WAIT:
		db_printf("TCPS_CLOSE_WAIT");
		return;

	case TCPS_FIN_WAIT_1:
		db_printf("TCPS_FIN_WAIT_1");
		return;

	case TCPS_CLOSING:
		db_printf("TCPS_CLOSING");
		return;

	case TCPS_LAST_ACK:
		db_printf("TCPS_LAST_ACK");
		return;

	case TCPS_FIN_WAIT_2:
		db_printf("TCPS_FIN_WAIT_2");
		return;

	case TCPS_TIME_WAIT:
		db_printf("TCPS_TIME_WAIT");
		return;

	default:
		db_printf("unknown");
		return;
	}
}

static void
db_print_tflags(uint32_t t_flags)
{
	int comma;

	comma = 0;
	if (t_flags & TF_ACKNOW) {
		db_printf("%sTF_ACKNOW", comma ? ", " : "");
		comma = 1;
	}
	if (t_flags & TF_DELACK) {
		db_printf("%sTF_DELACK", comma ? ", " : "");
		comma = 1;
	}
	if (t_flags & TF_NODELAY) {
		db_printf("%sTF_NODELAY", comma ? ", " : "");
		comma = 1;
	}
	if (t_flags & TF_NOOPT) {
		db_printf("%sTF_NOOPT", comma ? ", " : "");
		comma = 1;
	}
	if (t_flags & TF_SENTFIN) {
		db_printf("%sTF_SENTFIN", comma ? ", " : "");
		comma = 1;
	}
	if (t_flags & TF_REQ_SCALE) {
		db_printf("%sTF_REQ_SCALE", comma ? ", " : "");
		comma = 1;
	}
	if (t_flags & TF_RCVD_SCALE) {
		db_printf("%sTF_RECVD_SCALE", comma ? ", " : "");
		comma = 1;
	}
	if (t_flags & TF_REQ_TSTMP) {
		db_printf("%sTF_REQ_TSTMP", comma ? ", " : "");
		comma = 1;
	}
	if (t_flags & TF_RCVD_TSTMP) {
		db_printf("%sTF_RCVD_TSTMP", comma ? ", " : "");
		comma = 1;
	}
	if (t_flags & TF_SACK_PERMIT) {
		db_printf("%sTF_SACK_PERMIT", comma ? ", " : "");
		comma = 1;
	}
	if (t_flags & TF_NEEDSYN) {
		db_printf("%sTF_NEEDSYN", comma ? ", " : "");
		comma = 1;
	}
	if (t_flags & TF_NEEDFIN) {
		db_printf("%sTF_NEEDFIN", comma ? ", " : "");
		comma = 1;
	}
	if (t_flags & TF_NOPUSH) {
		db_printf("%sTF_NOPUSH", comma ? ", " : "");
		comma = 1;
	}
	if (t_flags & TF_MORETOCOME) {
		db_printf("%sTF_MORETOCOME", comma ? ", " : "");
		comma = 1;
	}
	if (t_flags & TF_LQ_OVERFLOW) {
		db_printf("%sTF_LQ_OVERFLOW", comma ? ", " : "");
		comma = 1;
	}
	if (t_flags & TF_LASTIDLE) {
		db_printf("%sTF_LASTIDLE", comma ? ", " : "");
		comma = 1;
	}
	if (t_flags & TF_RXWIN0SENT) {
		db_printf("%sTF_RXWIN0SENT", comma ? ", " : "");
		comma = 1;
	}
	if (t_flags & TF_FASTRECOVERY) {
		db_printf("%sTF_FASTRECOVERY", comma ? ", " : "");
		comma = 1;
	}
	if (t_flags & TF_CONGRECOVERY) {
		db_printf("%sTF_CONGRECOVERY", comma ? ", " : "");
		comma = 1;
	}
	if (t_flags & TF_WASFRECOVERY) {
		db_printf("%sTF_WASFRECOVERY", comma ? ", " : "");
		comma = 1;
	}
	if (t_flags & TF_SIGNATURE) {
		db_printf("%sTF_SIGNATURE", comma ? ", " : "");
		comma = 1;
	}
	if (t_flags & TF_FORCEDATA) {
		db_printf("%sTF_FORCEDATA", comma ? ", " : "");
		comma = 1;
	}
	if (t_flags & TF_TSO) {
		db_printf("%sTF_TSO", comma ? ", " : "");
		comma = 1;
	}
	if (t_flags & TF_ECN_PERMIT) {
		db_printf("%sTF_ECN_PERMIT", comma ? ", " : "");
		comma = 1;
	}
}

static void
db_print_toobflags(char t_oobflags)
{
	int comma;

	comma = 0;
	if (t_oobflags & TCPOOB_HAVEDATA) {
		db_printf("%sTCPOOB_HAVEDATA", comma ? ", " : "");
		comma = 1;
	}
	if (t_oobflags & TCPOOB_HADDATA) {
		db_printf("%sTCPOOB_HADDATA", comma ? ", " : "");
		comma = 1;
	}
}

static void
db_print_tcpcb(struct tcpcb *tp, const char *name, int indent)
{

	db_print_indent(indent);
	db_printf("%s at %p\n", name, tp);

	indent += 2;

	db_print_indent(indent);
	db_printf("t_segq first: %p   t_segqlen: %d   t_dupacks: %d\n",
	   OFP_LIST_FIRST(&tp->t_segq), tp->t_segqlen, tp->t_dupacks);

	db_print_indent(indent);
	db_printf("tt_rexmt: %p   tt_persist: %p   tt_keep: %p\n",
	    &tp->t_timers->tt_rexmt, &tp->t_timers->tt_persist, &tp->t_timers->tt_keep);

	db_print_indent(indent);
	db_printf("tt_2msl: %p   tt_delack: %p   t_inpcb: %p\n", &tp->t_timers->tt_2msl,
	    &tp->t_timers->tt_delack, tp->t_inpcb);

	db_print_indent(indent);
	db_printf("t_state: %d (", tp->t_state);
	db_print_tstate(tp->t_state);
	db_printf(")\n");

	db_print_indent(indent);
	db_printf("t_flags: 0x%x (", tp->t_flags);
	db_print_tflags(tp->t_flags);
	db_printf(")\n");

	db_print_indent(indent);
	db_printf("snd_una: 0x%08x   snd_max: 0x%08x   snd_nxt: x0%08x\n",
	    tp->snd_una, tp->snd_max, tp->snd_nxt);

	db_print_indent(indent);
	db_printf("snd_up: 0x%08x   snd_wl1: 0x%08x   snd_wl2: 0x%08x\n",
	   tp->snd_up, tp->snd_wl1, tp->snd_wl2);

	db_print_indent(indent);
	db_printf("iss: 0x%08x   irs: 0x%08x   rcv_nxt: 0x%08x\n",
	    tp->iss, tp->irs, tp->rcv_nxt);

	db_print_indent(indent);
	db_printf("rcv_adv: 0x%08x   rcv_wnd: %lu   rcv_up: 0x%08x\n",
	    tp->rcv_adv, tp->rcv_wnd, tp->rcv_up);

	db_print_indent(indent);
	db_printf("snd_wnd: %lu   snd_cwnd: %lu\n",
	   tp->snd_wnd, tp->snd_cwnd);

	db_print_indent(indent);
	db_printf("snd_ssthresh: %lu   snd_recover: "
	    "0x%08x\n", tp->snd_ssthresh, tp->snd_recover);

	db_print_indent(indent);
	db_printf("t_maxopd: %u   t_rcvtime: %u   t_startime: %u\n",
	    tp->t_maxopd, tp->t_rcvtime, tp->t_starttime);

	db_print_indent(indent);
	db_printf("t_rttime: %u   t_rtsq: 0x%08x\n",
	    tp->t_rtttime, tp->t_rtseq);

	db_print_indent(indent);
	db_printf("t_rxtcur: %d   t_maxseg: %u   t_srtt: %d\n",
	    tp->t_rxtcur, tp->t_maxseg, tp->t_srtt);

	db_print_indent(indent);
	db_printf("t_rttvar: %d   t_rxtshift: %d   t_rttmin: %u   "
	    "t_rttbest: %u\n", tp->t_rttvar, tp->t_rxtshift, tp->t_rttmin,
	    tp->t_rttbest);

	db_print_indent(indent);
	db_printf("t_rttupdated: %lu   max_sndwnd: %lu   t_softerror: %d\n",
	    tp->t_rttupdated, tp->max_sndwnd, tp->t_softerror);

	db_print_indent(indent);
	db_printf("t_oobflags: 0x%x (", tp->t_oobflags);
	db_print_toobflags(tp->t_oobflags);
	db_printf(")   t_iobc: 0x%02x\n", tp->t_iobc);

	db_print_indent(indent);
	db_printf("snd_scale: %u   rcv_scale: %u   request_r_scale: %u\n",
	    tp->snd_scale, tp->rcv_scale, tp->request_r_scale);

	db_print_indent(indent);
	db_printf("ts_recent: %u   ts_recent_age: %u\n",
	    tp->ts_recent, tp->ts_recent_age);

	db_print_indent(indent);
	db_printf("ts_offset: %u   last_ack_sent: 0x%08x   snd_cwnd_prev: "
	    "%lu\n", tp->ts_offset, tp->last_ack_sent, tp->snd_cwnd_prev);

	db_print_indent(indent);
	db_printf("snd_ssthresh_prev: %lu   snd_recover_prev: 0x%08x   "
	    "t_badrxtwin: %u\n", tp->snd_ssthresh_prev,
	    tp->snd_recover_prev, tp->t_badrxtwin);

	db_print_indent(indent);
	db_printf("snd_numholes: %d  snd_holes first: %p\n",
	    tp->snd_numholes, OFP_TAILQ_FIRST(&tp->snd_holes));

	db_print_indent(indent);
	db_printf("snd_fack: 0x%08x   rcv_numsacks: %d   sack_newdata: "
	    "0x%08x\n", tp->snd_fack, tp->rcv_numsacks, tp->sack_newdata);

	/* Skip sackblks, sackhint. */

	db_print_indent(indent);
	db_printf("t_rttlow: %d   rfbuf_ts: %u   rfbuf_cnt: %d\n",
	    tp->t_rttlow, tp->rfbuf_ts, tp->rfbuf_cnt);
}

DB_SHOW_COMMAND(tcpcb, db_show_tcpcb)
{
	struct tcpcb *tp;

	if (!have_addr) {
		db_printf("usage: show tcpcb <addr>\n");
		return;
	}
	tp = (struct tcpcb *)addr;

	db_print_tcpcb(tp, "tcpcb", 0);
}
#endif
