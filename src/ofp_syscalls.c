/*
 * Copyright (c) 2014, Nokia
 * Copyright (c) 2014, Enea Software AB
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <strings.h>
#include <string.h>
#include <stdarg.h>

#include "odp.h"

#include "ofpi_errno.h"
#include "ofpi_log.h"
#include "ofpi_util.h"
#include "ofpi_in.h"
#include "ofpi_ip.h"
#include "ofpi_ip6.h"
#include "ofpi_udp.h"
#include "ofpi_icmp.h"

#include "ofpi_socketvar.h"
#include "ofpi_sockbuf.h"
#include "ofpi_socket.h"
#include "ofpi_sockstate.h"
#include "ofpi_in_pcb.h"
#include "ofpi_udp_var.h"
#include "ofpi_protosw.h"
#include "ofpi_ioctl.h"
#include "ofpi_route.h"
#include "api/ofp_types.h"
#include "ofpi_syscalls.h"

int
ofp_socket(int domain, int type, int protocol)
{
	return ofp_socket_vrf(domain, type, protocol, 0);
}

int
ofp_socket_vrf(int domain, int type, int protocol, int vrf)
{
	struct socket  *so;
	int		error;
	struct thread   td;

	td.td_proc.p_fibnum = vrf;
	td.td_ucred = NULL;
	error = ofp_socreate(domain, &so, type, protocol, &td);
	if (error) {
		ofp_errno = error;
		return -1;
	}
	return so->so_number;
}

int
ofp_close(int sockfd)
{
	struct socket  *so = ofp_get_sock_by_fd(sockfd);
	if (!so) {
		ofp_errno = OFP_EBADF;
		return -1;
	}
	ofp_errno = ofp_soclose(so);
	return ofp_errno ? -1 : 0;
}

int
ofp_shutdown(int sockfd, int how)
{
	struct socket  *so = ofp_get_sock_by_fd(sockfd);
	if (!so) {
		ofp_errno = OFP_EBADF;
		return -1;
	}
	ofp_errno = ofp_soshutdown(so, how);
	return ofp_errno ? -1 : 0;
}

int
ofp_bind(int sockfd, const struct ofp_sockaddr *addr, ofp_socklen_t addrlen)
{
	struct thread   td;
	union ofp_sockaddr_store nonconstaddr;
	struct socket  *so = ofp_get_sock_by_fd(sockfd);

	if (!so) {
		ofp_errno = OFP_EBADF;
		return -1;
	}

	memcpy(&nonconstaddr, addr, addrlen);

	td.td_proc.p_fibnum = so->so_fibnum;
	td.td_ucred = NULL;
	ofp_errno = ofp_sobind(so, (struct ofp_sockaddr *)&nonconstaddr,
		&td);
	return ofp_errno ? -1 : 0;
}

int
ofp_connect(int sockfd, const struct ofp_sockaddr *addr, ofp_socklen_t addrlen)
{
	struct thread   td;
	union ofp_sockaddr_store nonconstaddr;
	struct socket  *so = ofp_get_sock_by_fd(sockfd);

	if (!so) {
		ofp_errno = OFP_EBADF;
		return -1;
	}

	if (!addr || !addrlen) {
		ofp_errno = OFP_EINVAL;
		return -1;
	}

	memcpy(&nonconstaddr, addr, addrlen);

	td.td_proc.p_fibnum = so->so_fibnum;
	td.td_ucred = NULL;
	ofp_errno = ofp_soconnect(so, (struct ofp_sockaddr *)&nonconstaddr, &td);
	return ofp_errno ? -1 : 0;
}

ofp_ssize_t
ofp_sendto(int sockfd, const void *buf, size_t len, int flags,
	     const struct ofp_sockaddr *dest_addr, ofp_socklen_t addrlen)
{
	struct ofp_iovec iovec;
	struct uio uio;
	struct thread   td;
	union ofp_sockaddr_store nonconstaddr;
	struct socket  *so = ofp_get_sock_by_fd(sockfd);

	if (!so) {
		ofp_errno = OFP_EBADF;
		return -1;
	}

	if (dest_addr && addrlen)
		memcpy(&nonconstaddr, dest_addr, addrlen);

	uio.uio_iov = &iovec;
	uio.uio_iovcnt = 1;
	uio.uio_resid = len;
	uio.uio_offset = 0;
	iovec.iov_base = (void *)(uintptr_t)buf;
	iovec.iov_len = len;

	td.td_proc.p_fibnum = so->so_fibnum;
	td.td_ucred = NULL;

	ofp_errno = ofp_sosend(so,
	 (dest_addr && addrlen)? (struct ofp_sockaddr *)&nonconstaddr : NULL,
	 &uio, ODP_PACKET_INVALID, ODP_PACKET_INVALID, flags, &td);

	if (ofp_errno)
		return -1;

	return len - uio.uio_resid;
}

ofp_ssize_t
ofp_send(int sockfd, const void *buf, size_t len, int flags)
{
	return ofp_sendto(sockfd, buf, len, flags, NULL, 0);
}

ofp_ssize_t
ofp_recvfrom(int sockfd, void *buf, size_t len, int flags,
	       struct ofp_sockaddr *src_addr, ofp_socklen_t *addrlen)
{
	struct ofp_iovec iovec;
	struct uio uio;
	struct socket  *so = ofp_get_sock_by_fd(sockfd);
	if (!so) {
		ofp_errno = OFP_EBADF;
		return -1;
	}

	uio.uio_iov = &iovec;
	uio.uio_iovcnt = 1;
	uio.uio_resid = len;
	iovec.iov_base = buf;
	iovec.iov_len = len;

	ofp_errno = ofp_soreceive(so, &src_addr, &uio, NULL, NULL, &flags);
	if (ofp_errno)
		return -1;
	if (src_addr && addrlen)
		*addrlen = src_addr->sa_len;
	return (len - uio.uio_resid);
}

ofp_ssize_t
ofp_recv(int sockfd, void *buf, size_t len, int flags)
{
	return ofp_recvfrom(sockfd, buf, len, flags, NULL, 0);
}

int
ofp_listen(int sockfd, int backlog)
{
	struct thread   td;
	struct socket  *so = ofp_get_sock_by_fd(sockfd);

	if (!so) {
		ofp_errno = OFP_EBADF;
		return -1;
	}

	td.td_proc.p_fibnum = so->so_fibnum;
	td.td_ucred = NULL;

	ofp_errno = ofp_solisten(so, backlog, &td);
	if (ofp_errno)
		return -1;
	return 0;
}

int
ofp_accept(int sockfd, struct ofp_sockaddr *addr, ofp_socklen_t *addrlen)
{
	struct ofp_sockaddr *sa = NULL;
	struct socket *so, *head = ofp_get_sock_by_fd(sockfd);
	if (!head) {
		ofp_errno = OFP_EBADF;
		return -1;
	}

	if ((head->so_options & OFP_SO_ACCEPTCONN) == 0) {
		ofp_errno = OFP_EINVAL;
		return -1;
	}

	ACCEPT_LOCK();
	if ((head->so_state & SS_NBIO) && OFP_TAILQ_EMPTY(&head->so_comp)) {
		ACCEPT_UNLOCK();
		ofp_errno = OFP_EWOULDBLOCK;
		return -1;
	}

	while (OFP_TAILQ_EMPTY(&head->so_comp) && head->so_error == 0) {
		if (head->so_rcv.sb_state & SBS_CANTRCVMORE) {
			head->so_error = OFP_ECONNABORTED;
			break;
		}
		if (ofp_msleep(&head->so_timeo, ofp_accept_mtx(), 0,
				 "accept", 0)) {
			ACCEPT_UNLOCK();
			return -1;
		}
	}

	if (head->so_error) {
		ofp_errno = head->so_error;
		head->so_error = 0;
		ACCEPT_UNLOCK();
		return -1;
	}
	so = OFP_TAILQ_FIRST(&head->so_comp);
	KASSERT(!(so->so_qstate & SQ_INCOMP), ("accept1: so SQ_INCOMP"));
	KASSERT(so->so_qstate & SQ_COMP, ("accept1: so not SQ_COMP"));

	/*
	 * Before changing the flags on the socket, we have to bump the
	 * reference count.  Otherwise, if the protocol calls ofp_sofree(),
	 * the socket will be released due to a zero refcount.
	 */
	OFP_SOCK_LOCK(so);			/* soref() and so_state update */
	soref(so);			/* file descriptor reference */

	OFP_TAILQ_REMOVE(&head->so_comp, so, so_list);
	head->so_qlen--;
	so->so_state |= (head->so_state & SS_NBIO);
	so->so_qstate &= ~SQ_COMP;
	so->so_head = NULL;

	OFP_SOCK_UNLOCK(so);
	ACCEPT_UNLOCK();

	/* connection has been removed from the listen queue */
	/*KNOTE_UNLOCKED(&head->so_rcv.sb_sel.si_note, 0);*/

	sa = 0;
	ofp_errno = ofp_soaccept(so, &sa);
	if (ofp_errno) {
		/*
		 * return a namelen of zero for older code which might
		 * ignore the return value from accept.
		 */
		if (addr)
			*addrlen = 0;
		return -1;
	}

	if (sa == NULL) {
		if (addr)
			*addrlen = 0;
		return so->so_number;
	}

	if (addr) {
		/* check sa_len before it is destroyed */
		if (*addrlen > sa->sa_len)
			*addrlen = sa->sa_len;
		memcpy(addr, sa, *addrlen);
	}

	free(sa);
	return so->so_number;
}

int
ofp_select(int nfds, ofp_fd_set *readfds, ofp_fd_set *writefds,
	   ofp_fd_set *exceptfds, struct ofp_timeval *timeout)
{
	return _ofp_select(nfds, readfds, writefds, exceptfds, timeout, ofp_msleep);
}

static inline uint32_t
to_usec(struct ofp_timeval *timeout)
{
	return timeout ? timeout->tv_sec * US_PER_SEC + timeout->tv_usec : 0;
}

static inline int
is_accepting_socket(struct socket *so)
{
	return (so->so_options & OFP_SO_ACCEPTCONN);
}

static inline int
is_accepting_socket_readable(struct socket *so)
{
	return !(OFP_TAILQ_EMPTY(&so->so_comp));
}

static inline int
is_listening_socket_readable(struct socket *so)
{
	return (so->so_rcv.sb_cc > 0);
}

static int
is_readable(int fd)
{
	struct socket *so = ofp_get_sock_by_fd(fd);

	if (is_accepting_socket(so))
		return is_accepting_socket_readable(so);

	return is_listening_socket_readable(so);
}

static int
set_ready_fd(int fd, ofp_fd_set *fd_set, int(*is_ready)(int fd))
{
	if (OFP_FD_ISSET(fd, fd_set) && is_ready(fd))
		return 1;

	OFP_FD_CLR(fd, fd_set);
	return 0;
}

static int
set_ready_fds(int nfds, ofp_fd_set *fd_set, int (*is_ready)(int fd))
{
	int fd;
	int ready = 0;

	for (fd = OFP_SOCK_NUM_OFFSET; fd < nfds && fd_set; ++fd)
		ready += set_ready_fd(fd, fd_set, is_ready);

	return ready;
}

static int
none_of_ready(int nfds, ofp_fd_set *fd_set, int (*is_ready)(int fd))
{
	int fd;

	for (fd = OFP_SOCK_NUM_OFFSET; fd < nfds && fd_set; ++fd)
		if (OFP_FD_ISSET(fd, fd_set) && is_ready(fd))
			return 0;

	return 1;
}

static inline int
is_blocking(struct ofp_timeval *timeout)
{
	return (timeout == NULL || to_usec(timeout) > 0);
}

int
_ofp_select(int nfds, ofp_fd_set *readfds, ofp_fd_set *writefds,
	    ofp_fd_set *exceptfds, struct ofp_timeval *timeout,
	    int (*sleeper)(void *channel, odp_rwlock_t *mtx, int priority,
			   const char *wmesg, uint32_t timeout))
{
	(void)writefds;
	(void)exceptfds;

	if (is_blocking(timeout) && none_of_ready(nfds, readfds, is_readable))
		sleeper(NULL, NULL, 0, "select", to_usec(timeout));

	return set_ready_fds(nfds, readfds, is_readable);
}

static inline int
to_bit_index(int fd)
{
	return ((fd - OFP_SOCK_NUM_OFFSET) / 8);
}

static inline uint8_t
to_bit(int fd)
{
	return (1 << (fd - OFP_SOCK_NUM_OFFSET) % 8);
}

void
OFP_FD_CLR(int fd, ofp_fd_set *set)
{
	if (set)
		set->fd_set_buf[to_bit_index(fd)] &= ~to_bit(fd);
}

int
OFP_FD_ISSET(int fd, ofp_fd_set *set)
{
	return set ? set->fd_set_buf[to_bit_index(fd)] & to_bit(fd) : 0;
}

void
OFP_FD_SET(int fd, ofp_fd_set *set)
{
	if (set)
		set->fd_set_buf[to_bit_index(fd)] |= to_bit(fd);
}

void
OFP_FD_ZERO(ofp_fd_set *set)
{
	if (set)
		memset(set->fd_set_buf, 0, sizeof(set->fd_set_buf));
}

void *ofp_udp_packet_parse(odp_packet_t pkt, int *length,
			       struct ofp_sockaddr *addr,
			       ofp_socklen_t *addrlen)
{
	struct ofp_sockaddr *src_addr = NULL;
	ofp_socklen_t src_len = 0;
	struct ofp_udphdr *uh =
		(struct ofp_udphdr *)odp_packet_l4_ptr(pkt, NULL);
	int udplen = odp_be_to_cpu_16(uh->uh_ulen) - sizeof(*uh);
	uint8_t *data = (uint8_t *)(uh + 1);
	uint8_t *start = odp_packet_data(pkt);

	if (addr && addrlen) {
		src_addr = (struct ofp_sockaddr *)odp_packet_l2_ptr(pkt,
				NULL);
		if (src_addr->sa_family == OFP_AF_INET)
			src_len = sizeof(struct ofp_sockaddr_in);
		else if (src_addr->sa_family == OFP_AF_INET6)
			src_len = sizeof(struct ofp_sockaddr_in6);
		else
			return NULL;

		memcpy(addr, src_addr, min(*addrlen, src_len));
		*addrlen = src_len;
	}
	if (data > start)
		odp_packet_pull_head(pkt, (uint32_t)(data - start));
	int pktlen = odp_packet_len(pkt);
	if (pktlen > udplen)
		odp_packet_pull_tail(pkt, (uint32_t)(pktlen - udplen));
	if (length)
		*length = udplen;

	return data;
}

ofp_ssize_t
ofp_udp_pkt_sendto(int sockfd, odp_packet_t pkt,
		     const struct ofp_sockaddr *dest_addr, ofp_socklen_t addrlen)
{
	struct ofp_sockaddr *addr =
		(struct ofp_sockaddr *)(uintptr_t)dest_addr;
	struct socket *so = ofp_get_sock_by_fd(sockfd);
	struct thread   td;

	(void)addrlen;

	if (!so) {
		ofp_errno = OFP_EBADF;
		return -1;
	}

	td.td_proc.p_fibnum = so->so_fibnum;
	td.td_ucred = NULL;

	ofp_errno = (*so->so_proto->pr_usrreqs->pru_send)
		(so, 0, pkt, addr, ODP_PACKET_INVALID, &td);

	if (ofp_errno)
		return -1;

	return 0;
}

int ofp_socket_sigevent(struct ofp_sigevent *ev)
{
	struct ofp_sock_sigval *ss = ev->ofp_sigev_value.sival_ptr;
	struct socket *so = ofp_get_sock_by_fd(ss->sockfd);

	if (!so) {
		ofp_errno = OFP_EBADF;
		return -1;
	}

	switch (ev->ofp_sigev_notify) {
	case OFP_SIGEV_NONE:
		return 0;
	case OFP_SIGEV_HOOK:
		break;
	default:
		ofp_errno = OFP_EINVAL;
		return -1;
	};

	so->so_sigevent = *ev;
	so->so_rcv.sb_socket = so;
	so->so_snd.sb_socket = so;

	return 0;
}

int ofp_getsockopt(int sockfd, int level, int optname,
		     void *optval, ofp_socklen_t *optlen)
{
	struct sockopt sopt;
	struct socket  *so = ofp_get_sock_by_fd(sockfd);
	if (!so) {
		ofp_errno = OFP_EBADF;
		return -1;
	}

	sopt.sopt_dir = SOPT_GET;
	sopt.sopt_level = level;
	sopt.sopt_name = optname;
	sopt.sopt_val = (void *)(uintptr_t)optval;
	sopt.sopt_valsize = *optlen;

	ofp_errno = ofp_sogetopt(so, &sopt);

	*optlen = sopt.sopt_valsize;

	if (ofp_errno)
		return -1;

	return 0;
}

int ofp_setsockopt(int sockfd, int level, int optname,
		     const void *optval, ofp_socklen_t optlen)
{
	struct sockopt sopt;
	struct socket  *so = ofp_get_sock_by_fd(sockfd);
	if (!so) {
		ofp_errno = OFP_EBADF;
		return -1;
	}

	sopt.sopt_dir = SOPT_SET;
	sopt.sopt_level = level;
	sopt.sopt_name = optname;
	sopt.sopt_val = (void *)(uintptr_t)optval;
	sopt.sopt_valsize = optlen;

	ofp_errno = ofp_sosetopt(so, &sopt);
	if (ofp_errno)
		return -1;

	return 0;
}

static int get_port_vlan_by_name(const char *name, int *port, int *vlan)
{
	if (strncmp(name, OFP_IFNAME_PREFIX,
		    strlen(OFP_IFNAME_PREFIX)) == 0) {
		int i;
		const char *p = NULL;
		for (i = 0; i < OFP_IFNAMSIZ && name[i]; i++)
			if (name[i] == '.') {
				p = &name[i];
				break;
			}
		if (p)
			*vlan = atoi(p+1);
		else
			*vlan = 0;

		*port = atoi(name + strlen(OFP_IFNAME_PREFIX));
		return 0;
	} else if (strncmp(name, OFP_GRE_IFNAME_PREFIX,
			   strlen(OFP_GRE_IFNAME_PREFIX)) == 0) {
		*port = GRE_PORTS;
		*vlan = atoi(name + strlen(OFP_GRE_IFNAME_PREFIX));
		return 0;
	}
	return -1;
}

int ofp_ioctl(int sockfd, int request, ...)
{
	va_list ap;
	void *data;
	struct ofp_ifnet *iface = NULL;
	struct socket  *so = ofp_get_sock_by_fd(sockfd);
	if (!so) {
		ofp_errno = OFP_EBADF;
		return -1;
	}

	va_start(ap, request);
	data = va_arg(ap, void *);
	va_end(ap);

	if (request == (int)(OFP_SIOCGIFCONF)) {
		ofp_errno = ((*so->so_proto->pr_usrreqs->pru_control)
			       (so, request, data, NULL, NULL));
	} else if (OFP_IOCGROUP(request) == 'i') {
		/* All the interface requests start with interface name */
		int port, vlan = 0;
		char *name = data;

		if (get_port_vlan_by_name(name, &port, &vlan) < 0) {
			ofp_errno = OFP_EBADF;
			return -1;
		}

		if (request == (int)(OFP_SIOCSIFTUN)) {
			struct ofp_in_tunreq *treq = data;
			const char *retstr =
				ofp_config_interface_up_tun
				(port, vlan, treq->iftun_vrf,
				 treq->iftun_local_addr.sin_addr.s_addr,
				 treq->iftun_remote_addr.sin_addr.s_addr,
				 treq->iftun_p2p_addr.sin_addr.s_addr,
				 treq->iftun_addr.sin_addr.s_addr, 30);
			if (!retstr)
				ofp_errno = 0;
			else
				ofp_errno = OFP_EBADMSG;
		} else {
			iface = ofp_get_ifnet(port, vlan);

			if (so->so_proto->pr_usrreqs->pru_control)
				ofp_errno = ((*so->so_proto->pr_usrreqs->pru_control)
					       (so, request, data, iface, NULL));
			else
				ofp_errno = OFP_EOPNOTSUPP;
		}
	} else if (OFP_IOCGROUP(request) == 'r') {
		int port = 0, vlan = 0;
		struct ofp_rtentry *rt = data;
		uint32_t dst  = ((struct ofp_sockaddr_in *)&rt->rt_dst)->sin_addr.s_addr;
		uint32_t mask = ((struct ofp_sockaddr_in *)&rt->rt_genmask)->sin_addr.s_addr;
		uint32_t gw   = ((struct ofp_sockaddr_in *)&rt->rt_gateway)->sin_addr.s_addr;
		uint32_t maskcpu = odp_be_to_cpu_32(mask);
		uint32_t mlen = 0;

		if (request != (int)OFP_SIOCADDRT &&
		    request != (int)OFP_SIOCDELRT) {
			ofp_errno = OFP_EBADF;
			return -1;
		}

		if (request == (int)OFP_SIOCADDRT) {
			if (rt->rt_dev) {
				if (get_port_vlan_by_name(rt->rt_dev, &port, &vlan) < 0) {
					ofp_errno = OFP_EBADF;
					return -1;
				}
			} else {
				uint32_t flags;
				struct ofp_nh_entry *nh =
					ofp_get_next_hop(rt->rt_vrf, gw, &flags);
				if (!nh) {
					ofp_errno = OFP_EBADF;
					return -1;
				}
				port = nh->port;
				vlan = nh->vlan;
			}
		}

		while (maskcpu) {
			mlen++;
			maskcpu <<= 1;
		}

		ofp_set_route_params((request == (int) OFP_SIOCADDRT) ? OFP_ROUTE_ADD : OFP_ROUTE_DEL,
				     rt->rt_vrf, vlan, port,
				     dst, mlen, gw,
				     (request == (int) OFP_SIOCADDRT) ?
				     (gw ? OFP_RTF_GATEWAY : OFP_RTF_NET) : 0);
	} else {
		ofp_errno = ofp_soo_ioctl(so, request, data, NULL, NULL);
	}

	if (ofp_errno)
		return -1;

	return 0;
}
