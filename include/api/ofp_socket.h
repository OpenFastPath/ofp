/*-
 * Copyright (c) 1982, 1985, 1986, 1988, 1993, 1994
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
 *	@(#)socket.h	8.4 (Berkeley) 2/21/94
 * $FreeBSD: release/9.1.0/sys/sys/socket.h 232805 2012-03-11 00:48:54Z kib $
 */

#ifndef __OFP_SOCKET_H__
#define __OFP_SOCKET_H__

#include <odp.h>
#include "ofp_socket_types.h"
#include "ofp_config.h"

#if __GNUC__ >= 4
#pragma GCC visibility push(default)
#endif

/*
 * Definitions related to sockets: types, address families, options.
 */

/*
 * Data types.
 */
#ifndef OFP__GID_T_DECLARED
typedef	__ofp_gid_t		ofp_gid_t;
#define	OFP__GID_T_DECLARED
#endif /* OFP__GID_T_DECLARED */

#ifndef OFP__OFF_T_DECLARED
typedef	__ofp_off_t		ofp_off_t;
#define	OFP__OFF_T_DECLARED
#endif /* OFP__OFF_T_DECLARED */

#ifndef OFP__PID_T_DECLARED
typedef	__ofp_pid_t		ofp_pid_t;
#define	OFP__PID_T_DECLARED
#endif /* OFP__PID_T_DECLARED */

#ifndef OFP__SA_FAMILY_T_DECLARED
typedef	__ofp_sa_family_t	ofp_sa_family_t;
#define	OFP__SA_FAMILY_T_DECLARED
#endif /* OFP__SA_FAMILY_T_DECLARED */

#ifndef OFP__SOCKLEN_T_DECLARED
typedef	__ofp_socklen_t	ofp_socklen_t;
#define OFP__SOCKLEN_T_DECLARED
#endif /* OFP__SOCKLEN_T_DECLARED */

#ifndef OFP__SSIZE_T_DECLARED
typedef	__ofp_ssize_t		ofp_ssize_t;
#define	OFP__SSIZE_T_DECLARED
#endif /* OFP__SSIZE_T_DECLARED */

#ifndef OFP__UID_T_DECLARED
typedef	__ofp_uid_t		ofp_uid_t;
#define	OFP__UID_T_DECLARED
#endif /*OFP__UID_T_DECLARED*/

/*
 * Types
 */
#define	OFP_SOCK_STREAM	1		/* stream socket */
#define	OFP_SOCK_DGRAM	2		/* datagram socket */
#define	OFP_SOCK_RAW		3		/* raw-protocol interface */
#define	OFP_SOCK_RDM		4		/* reliably-delivered message */
#define	OFP_SOCK_SEQPACKET	5		/* sequenced packet stream */
#define OFP_SOCK_EPOLL          6       /* epoll socket */

/*
 * Option flags per-socket, kept in so_options.
 */
#define	OFP_SO_DEBUG		0x00000001	/* turn on debugging info recording */
#define	OFP_SO_ACCEPTCONN	0x00000002	/* socket has had listen() */
#define	OFP_SO_REUSEADDR	0x00000004	/* allow local address reuse */
#define	OFP_SO_KEEPALIVE	0x00000008	/* keep connections alive */
#define	OFP_SO_DONTROUTE	0x00000010	/* just use interface addresses */
#define	OFP_SO_BROADCAST	0x00000020	/* permit sending of broadcast msgs */
#define	OFP_SO_USELOOPBACK	0x00000040	/* bypass hardware when possible */
#define	OFP_SO_LINGER		0x00000080	/* linger on close if data present */
#define	OFP_SO_OOBINLINE	0x00000100	/* leave received OOB data in line */
#define	OFP_SO_REUSEPORT	0x00000200	/* allow local address & port reuse */
#define	OFP_SO_TIMESTAMP	0x00000400	/* timestamp received dgram traffic */
#define	OFP_SO_NOSIGPIPE	0x00000800	/* no SIGPIPE from OFP_EPIPE */
#define	OFP_SO_ACCEPTFILTER	0x00001000	/* there is an accept filter */
#define	OFP_SO_BINTIME	0x00002000	/* timestamp received dgram traffic */
#define	OFP_SO_NO_OFFLOAD	0x00004000	/* socket cannot be offloaded */
#define	OFP_SO_NO_DDP		0x00008000	/* disable direct data placement */
#define	OFP_SO_PROMISC	0x00010000	/* socket will be used for promiscuous listen */
#define	OFP_SO_PASSIVE	0x00020000	/* socket will be used for passive reassembly */
#define	OFP_SO_PASSIVECLNT	0x00040000	/* client socket in the passive pair */
#define	OFP_SO_ALTFIB		0x00080000	/* alternate FIB is set */

/*
 * Additional options, not kept in so_options.
 */
#define	OFP_SO_SNDBUF		0x1001		/* send buffer size */
#define	OFP_SO_RCVBUF		0x1002		/* receive buffer size */
#define	OFP_SO_SNDLOWAT	0x1003		/* send low-water mark */
#define	OFP_SO_RCVLOWAT	0x1004		/* receive low-water mark */
#define	OFP_SO_SNDTIMEO	0x1005		/* send timeout */
#define	OFP_SO_RCVTIMEO	0x1006		/* receive timeout */
#define	OFP_SO_ERROR		0x1007		/* get error status and clear */
#define	OFP_SO_TYPE		0x1008		/* get socket type */
#define	OFP_SO_LABEL		0x1009		/* socket's MAC label */
#define	OFP_SO_PEERLABEL	0x1010		/* socket's peer's MAC label */
#define	OFP_SO_LISTENQLIMIT	0x1011		/* socket's backlog limit */
#define	OFP_SO_LISTENQLEN	0x1012		/* socket's complete queue length */
#define	OFP_SO_LISTENINCQLEN	0x1013		/* socket's incomplete queue length */
#define	OFP_SO_SETFIB		0x1014		/* use this FIB to route */
#define	OFP_SO_USER_COOKIE	0x1015		/* user cookie (dummynet etc.) */
#define	OFP_SO_PROTOCOL	0x1016		/* get socket protocol (Linux name) */
#define	OFP_SO_PROTOTYPE	OFP_SO_PROTOCOL	/* alias for OFP_SO_PROTOCOL (SunOS name) */
#define OFP_SO_L2INFO		0x1017		/* PROMISCUOUS_INET MAC addrs and tags */

/*
 * Structure used for manipulating linger option.
 */
struct ofp_linger {
	int	l_onoff;		/* option on/off */
	int	l_linger;		/* linger time */
};

struct accept_filter_arg {
	char	af_name[16];
	char	af_arg[256-16];
};

/*
 * Level number for (get/set)sockopt() to apply to socket itself.
 */
#define	OFP_SOL_SOCKET	0xffff		/* options for socket level */

/*
 * Address families.
 */
#define	OFP_AF_UNSPEC	0		/* unspecified */
#define	OFP_AF_UNIX	1		/* standardized name for OFP_AF_LOCAL */
#define	OFP_AF_INET	2		/* internetwork: UDP, TCP, etc. */
#define	OFP_AF_INET6	3		/* IPv6 */
#define	OFP_AF_LINK	4		/* Link layer interface */
#define	OFP_AF_MAX	5

/*
 * Structure used by kernel to store most
 * addresses.
 */
struct ofp_sockaddr {
	unsigned char		sa_len;		/* total length */
	ofp_sa_family_t	sa_family;	/* address family */
	char			sa_data[14];	/* actually longer; address value */
};

#define	OFP_SOCK_MAXADDRLEN	255		/* longest possible addresses */

/*
 * Structure used by kernel to pass protocol
 * information in raw sockets.
 */
struct sockproto {
	unsigned short	sp_family;		/* address family */
	unsigned short	sp_protocol;		/* protocol */
};

/*
 * Protocol families, same as address families for now.
 */
#define	OFP_PF_UNSPEC	OFP_AF_UNSPEC
#define	OFP_PF_UNIX	OFP_PF_LOCAL	/* backward compatibility */
#define	OFP_PF_INET	OFP_AF_INET
#define	OFP_PF_INET6	OFP_AF_INET6
#define	OFP_PF_MAX	OFP_AF_MAX

/*
 * OFP_PF_ROUTE - Routing table
 *
 * Three additional levels are defined:
 *	Fourth: address family, 0 is wildcard
 *	Fifth: type of info, defined below
 *	Sixth: flag(s) to mask with for NET_RT_FLAGS
 */
#define NET_RT_DUMP	1		/* dump; may limit to a.f. */
#define NET_RT_FLAGS	2		/* by flags, e.g. RESOLVING */
#define NET_RT_IFLIST	3		/* survey interface list */
#define	NET_RT_IFMALIST	4		/* return multicast address list */
#define	NET_RT_IFLISTL	5		/* Survey interface list, using 'l'en
					 * versions of msghdr structs. */
#define	NET_RT_MAXID	6


/*
 * Maximum queue length specifiable by listen.
 */
#define	SOMAXCONN	128

/*
 * Message header for recvmsg and sendmsg calls.
 * Used value-result for recvmsg, value only for sendmsg.
 */
struct ofp_msghdr {
	void		*msg_name;		/* optional address */
	ofp_socklen_t	 msg_namelen;		/* size of address */
	struct ofp_iovec	*msg_iov;		/* scatter/gather array */
	int		 msg_iovlen;		/* # elements in msg_iov */
	void		*msg_control;		/* ancillary data, see below */
	ofp_socklen_t	 msg_controllen;	/* ancillary data buffer len */
	int		 msg_flags;		/* flags on received message */
};

#define	OFP_MSG_OOB		0x1		/* process out-of-band data */
#define	OFP_MSG_PEEK		0x2		/* peek at incoming message */
#define	OFP_MSG_DONTROUTE	0x4		/* send without using routing tables */
#define	OFP_MSG_EOR		0x8		/* data completes record */
#define	OFP_MSG_TRUNC		0x10		/* data discarded before delivery */
#define	OFP_MSG_CTRUNC	0x20		/* control data lost before delivery */
#define	OFP_MSG_WAITALL	0x40		/* wait for full request or error */
#define OFP_MSG_NOTIFICATION	0x2000         /* SCTP notification */
#define	OFP_MSG_DONTWAIT	0x80		/* this message should be nonblocking */
#define	OFP_MSG_EOF		0x100		/* data completes connection */
#define	OFP_MSG_NBIO		0x4000		/* FIONBIO mode, used by fifofs */
#define	OFP_MSG_COMPAT	0x8000		/* used in sendit() */
#define	OFP_MSG_SOCALLBCK	0x10000		/* for use by socket callbacks - ofp_soreceive (TCP) */
#define	OFP_MSG_NOSIGNAL	0x20000		/* do not generate SIGPIPE on EOF */
#define	OFP_MSG_HOLE_BREAK	0x40000		/* stop at and indicate hole boundary */

/*
 * Header for ancillary data objects in msg_control buffer.
 * Used for additional information with/about a datagram
 * not expressible by flags.  The format is a sequence
 * of message elements headed by cmsghdr structures.
 */
struct ofp_cmsghdr {
	ofp_socklen_t	cmsg_len;		/* data byte count, including hdr */
	int		cmsg_level;		/* originating protocol */
	int		cmsg_type;		/* protocol-specific type */
/* followed by	uint8_t  cmsg_data[]; */
};

/*
 * While we may have more groups than this, the cmsgcred struct must
 * be able to fit in an mbuf and we have historically supported a
 * maximum of 16 groups.
*/
#define CMGROUP_MAX 16

/*
 * Credentials structure, used to verify the identity of a peer
 * process that has sent us a message. This is allocated by the
 * peer process but filled in by the kernel. This prevents the
 * peer from lying about its identity. (Note that cmcred_groups[0]
 * is the effective GID.)
 */
struct ofp_cmsgcred {
	ofp_pid_t	cmcred_pid;		/* PID of sending process */
	ofp_uid_t	cmcred_uid;		/* real UID of sending process */
	ofp_uid_t	cmcred_euid;		/* effective UID of sending process */
	ofp_gid_t	cmcred_gid;		/* real GID of sending process */
	short	cmcred_ngroups;		/* number or groups */
	ofp_gid_t	cmcred_groups[CMGROUP_MAX];	/* groups */
};

/*
 * Socket credentials.
 */
struct ofp_sockcred {
	ofp_uid_t	sc_uid;			/* real user id */
	ofp_uid_t	sc_euid;		/* effective user id */
	ofp_gid_t	sc_gid;			/* real group id */
	ofp_gid_t	sc_egid;		/* effective group id */
	int	sc_ngroups;		/* number of supplemental groups */
	ofp_gid_t	sc_groups[1];		/* variable length */
};

/*
 * Compute size of a sockcred structure with groups.
 */
#define	OFP_SOCKCREDSIZE(ngrps) \
	(sizeof(struct ofp_sockcred) + (sizeof(ofp_gid_t) * ((ngrps) - 1)))

/* given pointer to struct ofp_cmsghdr, return pointer to data */
#define	OFP_CMSG_DATA(cmsg)		((unsigned char *)(cmsg) + \
				 _ALIGN(sizeof(struct ofp_cmsghdr)))

/* given pointer to struct ofp_cmsghdr, return pointer to next cmsghdr */
#define	OFP_CMSG_NXTHDR(mhdr, cmsg)	\
	((char *)(cmsg) == NULL ? OFP_CMSG_FIRSTHDR(mhdr) : \
	    ((char *)(cmsg) + _ALIGN(((struct ofp_cmsghdr *)(cmsg))->cmsg_len) + \
	  _ALIGN(sizeof(struct ofp_cmsghdr)) > \
	    (char *)(mhdr)->msg_control + (mhdr)->msg_controllen) ? \
	    (struct ofp_cmsghdr *)0 : \
	    (struct ofp_cmsghdr *)(void *)((char *)(cmsg) + \
	    _ALIGN(((struct ofp_cmsghdr *)(cmsg))->cmsg_len)))

/*
 * RFC 2292 requires to check msg_controllen, in case that the kernel returns
 * an empty list for some reasons.
 */
#define	OFP_CMSG_FIRSTHDR(mhdr) \
	((mhdr)->msg_controllen >= sizeof(struct ofp_cmsghdr) ? \
	 (struct ofp_cmsghdr *)(mhdr)->msg_control : \
	 (struct ofp_cmsghdr *)NULL)

/* HJo: NOTE! Architecture specific! */
#define	_ALIGNBYTES	(sizeof(register_t) - 1)
#define	_ALIGN(p)	(((uintptr_t)(p) + _ALIGNBYTES) & ~_ALIGNBYTES)

/* RFC 2292 additions */
#define	OFP_CMSG_SPACE(l)		(_ALIGN(sizeof(struct ofp_cmsghdr)) + _ALIGN(l))
#define	OFP_CMSG_LEN(l)		(_ALIGN(sizeof(struct ofp_cmsghdr)) + (l))

#define	OFP_CMSG_ALIGN(n)	_ALIGN(n)

/* "Socket"-level control message types: */
#define	OFP_SCM_RIGHTS	0x01		/* access rights (array of int) */
#define	OFP_SCM_TIMESTAMP	0x02		/* timestamp (struct timeval) */
#define	OFP_SCM_CREDS	0x03		/* process creds (struct cmsgcred) */
#define	OFP_SCM_BINTIME	0x04		/* timestamp (struct bintime) */

/*
 * 4.3 compat sockaddr, move to compat file later
 */
struct ofp_osockaddr {
	unsigned short sa_family;	/* address family */
	char	sa_data[14];		/* up to 14 bytes of direct address */
};

/*
 * 4.3-compat message header (move to compat file later).
 */
struct ofp_omsghdr {
	char	*msg_name;		/* optional address */
	int	msg_namelen;		/* size of address */
	struct	ofp_iovec *msg_iov;		/* scatter/gather array */
	int	msg_iovlen;		/* # elements in msg_iov */
	char	*msg_accrights;		/* access rights sent/received */
	int	msg_accrightslen;
};

/*
 * howto arguments for shutdown(2), specified by Posix.1g.
 */
#define	OFP_SHUT_RD		0		/* shut down the reading side */
#define	OFP_SHUT_WR		1		/* shut down the writing side */
#define	OFP_SHUT_RDWR	2		/* shut down both sides */

/* we cheat and use the OFP_SHUT_XX defines for these */
#define OFP_PRU_FLUSH_RD     OFP_SHUT_RD
#define OFP_PRU_FLUSH_WR     OFP_SHUT_WR
#define OFP_PRU_FLUSH_RDWR   OFP_SHUT_RDWR


/*
 * sendfile(2) header/trailer struct
 */
struct ofp_sf_hdtr {
	struct ofp_iovec *headers;	/* pointer to an array of header struct iovec's */
	int hdr_cnt;		/* number of header ofp_iovec's */
	struct ofp_iovec *trailers;	/* pointer to an array of trailer struct iovec's */
	int trl_cnt;		/* number of trailer ofp_iovec's */
};

/*
 * Sendfile-specific flag(s)
 */
#define	OFP_SF_NODISKIO     0x00000001
#define	OFP_SF_MNOWAIT	0x00000002
#define	OFP_SF_SYNC		0x00000004

/* Events */
#define OFP_EVENT_INVALID	0
#define OFP_EVENT_ACCEPT	1
#define OFP_EVENT_RECV	2

struct ofp_sock_sigval {
	int		sockfd;
	int		sockfd2;
	int		event;
	odp_packet_t	pkt;
};

union ofp_sigval {          /* Data passed with notification */
	int     sival_int;         /* Integer value */
	void   *sival_ptr;         /* Pointer value */
};

#define OFP_SIGEV_NONE 0
#define OFP_SIGEV_HOOK 1
#define OFP_SIGEV_SIGNAL 2
#define OFP_SIGEV_THREAD 3

struct ofp_sigevent {
	int          ofp_sigev_notify; /* Notification method */
	int          ofp_sigev_signo;  /* Notification signal */
	union ofp_sigval ofp_sigev_value;  /* Data passed with
					    notification */
	void       (*ofp_sigev_notify_function) (union ofp_sigval);
	/* Function used for thread
	   notification (SIGEV_THREAD) */
	void        *ofp_sigev_notify_attr;
	/* Attributes for notification thread
	   (SIGEV_THREAD) */
	ofp_pid_t        ofp_sigev_notify_thread_id;
	/* ID of thread to signal (SIGEV_THREAD_ID) */
};

struct ofp_timeval {
	uint32_t tv_sec;     /* seconds */
	uint32_t tv_usec;    /* microseconds */
};

typedef struct {
	uint8_t fd_set_buf[OFP_NUM_SOCKETS_MAX / 8 + 1];
} ofp_fd_set;

void OFP_FD_CLR(int fd, ofp_fd_set *set);
int  OFP_FD_ISSET(int fd, ofp_fd_set *set);
void OFP_FD_SET(int fd, ofp_fd_set *set);
void OFP_FD_ZERO(ofp_fd_set *set);

int	ofp_select(int nfds, ofp_fd_set *readfds, ofp_fd_set *writefds,
		ofp_fd_set *exceptfds, struct ofp_timeval *timeout);

int	ofp_socket(int, int, int);
int	ofp_socket_vrf(int, int, int, int);
int	ofp_accept(int, struct ofp_sockaddr *, ofp_socklen_t *);
int	ofp_bind(int, const struct ofp_sockaddr *, ofp_socklen_t);
int	ofp_connect(int, const struct ofp_sockaddr *, ofp_socklen_t);
int	ofp_listen(int, int);
int	ofp_shutdown(int, int);
int	ofp_close(int);

ofp_ssize_t	ofp_recv(int, void *, size_t, int);
ofp_ssize_t	ofp_recvfrom(int, void *, size_t, int,
		struct ofp_sockaddr * __restrict, ofp_socklen_t * __restrict);

ofp_ssize_t	ofp_send(int, const void *, size_t, int);
ofp_ssize_t	ofp_sendto(int, const void *,
		size_t, int, const struct ofp_sockaddr *, ofp_socklen_t);

int	ofp_setsockopt(int, int, int, const void *, ofp_socklen_t);
int	ofp_getsockopt(int, int, int, void *, ofp_socklen_t *);

int	ofp_ioctl(int, int, ...);

int	ofp_socket_sigevent(struct ofp_sigevent *);
void	*ofp_udp_packet_parse(odp_packet_t, int *,
				struct ofp_sockaddr *,
				ofp_socklen_t *);
ofp_ssize_t ofp_udp_pkt_sendto(int, odp_packet_t,
				   const struct ofp_sockaddr *, ofp_socklen_t);

#if 0 /* Not implemented */
int	ofp_getpeername(int, struct ofp_sockaddr * __restrict, ofp_socklen_t * __restrict);
int	ofp_getsockname(int, struct ofp_sockaddr * __restrict, ofp_socklen_t * __restrict);

ofp_ssize_t	ofp_recvmsg(int, struct ofp_msghdr *, int);
ofp_ssize_t	ofp_sendmsg(int, const struct ofp_msghdr *, int);
int	ofp_sendfile(int, int, ofp_off_t, size_t, struct ofp_sf_hdtr *,
		ofp_off_t *, int);

int	ofp_setfib(int);
int	ofp_sockatmark(int);
int	ofp_socketpair(int, int, int, int *);
#endif

struct ofp_socket;

#if __GNUC__ >= 4
#pragma GCC visibility pop
#endif

#endif /* __OFP_SOCKET_H__ */
