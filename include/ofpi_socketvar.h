/*-
 * Copyright (c) 1982, 1986, 1990, 1993
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
 *	@(#)socketvar.h	8.3 (Berkeley) 2/19/95
 *
 * $FreeBSD: release/9.1.0/sys/sys/socketvar.h 215178 2010-11-12 13:02:26Z luigi $
 */

#ifndef _SYS_SOCKETVAR_H_
#define _SYS_SOCKETVAR_H_

#include "ofpi_queue.h"			/* for TAILQ macros */
#include "ofpi_sockbuf.h"
#include "ofpi_in_pcb.h"
#include "ofpi_uma.h"

struct vnet;
struct in_l2info;

/*
 * Kernel structure per socket.
 * Contains send and receive buffer queues,
 * handle on protocol and pointer to protocol
 * private data and error information.
 */
typedef	uint64_t so_gen_t;

/*-
 * Locking key to struct socket:
 * (a) constant after allocation, no locking required.
 * (b) locked by OFP_SOCK_LOCK(so).
 * (c) locked by SOCKBUF_LOCK(&so->so_rcv).
 * (d) locked by SOCKBUF_LOCK(&so->so_snd).
 * (e) locked by ACCEPT_LOCK().
 * (f) not locked since integer reads/writes are atomic.
 * (g) used only as a sleep/wakeup address, no value.
 * (h) locked by global mutex so_global_mtx.
 */
struct socket {
	struct  socket *next;           /* next in free list */
	int	so_number;		/* file descriptor */
	int	so_count;		/* (b) reference count */
	short	so_type;		/* (a) generic type, see socket.h */
	int	so_options;		/* from socket call, see socket.h */
	short	so_linger;		/* time to linger while closing */
	short	so_state;		/* (b) internal state flags SS_* */
	int	so_qstate;		/* (e) internal state flags SQ_* */
	void	*so_pcb;		/* protocol control block */
	struct	vnet *so_vnet;		/* network stack instance */
	struct	protosw *so_proto;	/* (a) protocol handle */
/*
 * Variables for connection queuing.
 * Socket where accepts occur is so_head in all subsidiary sockets.
 * If so_head is 0, socket is not related to an accept.
 * For head socket so_incomp queues partially completed connections,
 * while so_comp is a queue of connections ready to be accepted.
 * If a connection is aborted and it has so_head set, then
 * it has to be pulled out of either so_incomp or so_comp.
 * We allow connections to queue up based on current queue lengths
 * and limit on number of queued connections for this socket.
 */
	struct	socket *so_head;	/* (e) back pointer to listen socket */
	OFP_TAILQ_HEAD(, socket) so_incomp;	/* (e) queue of partial unaccepted connections */
	OFP_TAILQ_HEAD(, socket) so_comp;	/* (e) queue of complete unaccepted connections */
	OFP_TAILQ_ENTRY(socket) so_list;	/* (e) list of unaccepted connections */
	uint16_t	so_qlen;		/* (e) number of unaccepted connections */
	uint16_t	so_incqlen;		/* (e) number of unaccepted incomplete
					   connections */
	uint16_t	so_qlimit;		/* (e) max number queued connections */
	short	so_timeo;		/* (g) connection timeout */
	uint16_t	so_error;		/* (f) error affecting connection */
	struct	sigio *so_sigio;	/* [sg] information for async I/O or
					   out of band data (SIGURG) */
	uint64_t	so_oobmark;		/* (c) chars to oob mark */
#if 0
	OFP_TAILQ_HEAD(, aiocblist) so_aiojobq; /* AIO ops waiting on socket */
#endif
	struct sockbuf so_rcv, so_snd;

	struct	ofp_ucred *so_cred;		/* (a) user credentials */
	struct	ofp_ucred  so_cred_space;
	struct	label *so_label;	/* (b) MAC label for socket */
	struct	label *so_peerlabel;	/* (b) cached MAC label for peer */
	/* NB: generation count must not be first. */
	so_gen_t so_gencnt;		/* (h) generation count */
	void	*so_emuldata;		/* (b) private data for emulators */
	struct so_accf {
		struct	accept_filter *so_accept_filter;
		void	*so_accept_filter_arg;	/* saved filter args */
		char	*so_accept_filter_str;	/* saved user args */
	} *so_accf;
	/*
	 * so_fibnum, so_user_cookie and friends can be used to attach
	 * some user-specified metadata to a socket, which then can be
	 * used by the kernel for various actions.
	 * so_user_cookie is used by ipfw/dummynet.
	 */
	int so_fibnum;		/* routing domain for this socket */
	int so_altfibnum;
	uint32_t so_user_cookie;

	struct so_upcallprep {
		void (*soup_accept)(struct socket *so, void *arg);
		void *soup_accept_arg;
		void (*soup_receive)(struct socket *so, void *arg, int64_t, int64_t);
		void *soup_receive_arg;
		void (*soup_send)(struct socket *so, void *arg, int64_t);
		void *soup_send_arg;
	} so_upcallprep;		/* (a) initialized once immediately after socket creation */

	struct in_l2info *so_l2info;	/* (b) PROMISCUOUS_INET L2 info */
	unsigned int so_user_ctx_count; /* (b) number of user contexts in use, lock needed to increment */
#define SOMAXUSERCTX 1
	void *so_user_ctx[SOMAXUSERCTX]; /* (a) each pointer managed by user */
	struct socket *so_passive_peer;	/* (a) peer socket when performing passive reassembly */
	union {
		struct inpcb dummy;
	} pcb_space;
	struct ofp_sigevent so_sigevent;
};


/*
 * Global accept mutex to serialize access to accept queues and
 * fields associated with multiple sockets.  This allows us to
 * avoid defining a lock order between listen and accept sockets
 * until such time as it proves to be a good idea.
 */
#define	ACCEPT_LOCK_ASSERT()		//mtx_assert(&accept_mtx, MA_OWNED)
#define	ACCEPT_UNLOCK_ASSERT()		//mtx_assert(&accept_mtx, MA_NOTOWNED)
#define	ACCEPT_LOCK()			ofp_accept_lock()
#define	ACCEPT_UNLOCK()			ofp_accept_unlock()

/*
 * Per-socket mutex: we reuse the receive socket buffer mutex for space
 * efficiency.  This decision should probably be revisited as we optimize
 * locking for the socket code.
 */
#define	OFP_SOCK_MTX(_so)			SOCKBUF_MTX(&(_so)->so_rcv)
#define	OFP_SOCK_LOCK(_so)			SOCKBUF_LOCK(&(_so)->so_rcv)
#define	OFP_SOCK_OWNED(_so)			SOCKBUF_OWNED(&(_so)->so_rcv)
#define	OFP_SOCK_UNLOCK(_so)			SOCKBUF_UNLOCK(&(_so)->so_rcv)
#define	OFP_SOCK_LOCK_ASSERT(_so)		SOCKBUF_LOCK_ASSERT(&(_so)->so_rcv)


/*
 * Socket state bits stored in so_qstate.
 */
#define	SQ_INCOMP		0x0800	/* unaccepted, incomplete connection */
#define	SQ_COMP			0x1000	/* unaccepted, complete connection */

/*
 * Externalized form of struct socket used by the sysctl(3) interface.
 */
struct xsocket {
	size_t	xso_len;	/* length of this structure */
	struct	socket *xso_so;	/* makes a convenient handle sometimes */
	short	so_type;
	int	so_options;
	short	so_linger;
	short	so_state;
	char *	so_pcb;		/* another convenient handle */
	int	xso_protocol;
	int	xso_family;
	uint16_t	so_qlen;
	uint16_t	so_incqlen;
	uint16_t	so_qlimit;
	short	so_timeo;
	uint16_t	so_error;
	ofp_pid_t	so_pgid;
	uint64_t	so_oobmark;
	struct xsockbuf so_rcv, so_snd;
	ofp_uid_t	so_uid;		/* XXX */
};

/*
 * Macros for sockets and socket buffering.
 */

/*
 * Flags to ofp_sblock().
 */
#define	SBL_WAIT	0x00000001	/* Wait if not immediately available. */
#define	SBL_NOINTR	0x00000002	/* Force non-interruptible sleep. */
#define	SBL_VALID	(SBL_WAIT | SBL_NOINTR)

/*
 * Do we need to notify the other side when I/O is possible?
 */
#define	sb_notify(sb)	(((sb)->sb_flags & (SB_WAIT | SB_SEL | SB_ASYNC | \
    SB_UPCALL | SB_AIO | SB_KNOTE)) != 0)

/* do we have to send all at once on a socket? */
#define	sosendallatonce(so) \
    ((so)->so_proto->pr_flags & PR_ATOMIC)

/* can we read something from so? */
#define	soreadabledata(so) \
    ((so)->so_rcv.sb_cc >= (so)->so_rcv.sb_lowat || \
	!OFP_TAILQ_EMPTY(&(so)->so_comp) || (so)->so_error)
#define	soreadable(so) \
	(soreadabledata(so) || ((so)->so_rcv.sb_state & SBS_CANTRCVMORE))

/* can we write something to so? */
#define	sowriteable(so) \
    ((sbspace(&(so)->so_snd) >= (so)->so_snd.sb_lowat && \
	(((so)->so_state&SS_ISCONNECTED) || \
	  ((so)->so_proto->pr_flags&PR_CONNREQUIRED)==0)) || \
     ((so)->so_snd.sb_state & SBS_CANTSENDMORE) || \
     (so)->so_error)

/*
 * soref()/sorele() ref-count the socket structure.  Note that you must
 * still explicitly close the socket, but the last ref count will free
 * the structure.
 */
#define	soref(so) do {							\
	OFP_SOCK_LOCK_ASSERT(so);						\
	++(so)->so_count;						\
} while (0)

#define	sorele(so) do {							\
	ACCEPT_LOCK_ASSERT();						\
	OFP_SOCK_LOCK_ASSERT(so);						\
	if ((so)->so_count <= 0)					\
		panic("sorele");					\
	if (--(so)->so_count == 0)					\
		ofp_sofree(so);						\
	else {								\
		OFP_SOCK_UNLOCK(so);					\
		ACCEPT_UNLOCK();					\
	}								\
} while (0)


/*
 * In sorwakeup() and sowwakeup(), acquire the socket buffer lock to
 * avoid a non-atomic test-and-wakeup.  However, ofp_sowakeup is
 * responsible for releasing the lock if it is called.  We unlock only
 * if we don't call into ofp_sowakeup.  If any code is introduced that
 * directly invokes the underlying ofp_sowakeup() primitives, it must
 * maintain the same semantics.
 */
#define	sorwakeup_locked(so) do {					\
	SOCKBUF_LOCK_ASSERT(&(so)->so_rcv);				\
	if (sb_notify(&(so)->so_rcv)) {					\
		ofp_sowakeup((so), &(so)->so_rcv);				\
	} else {							\
		SOCKBUF_UNLOCK(&(so)->so_rcv);				\
	}								\
} while (0)

#define	sorwakeup(so) do {						\
	SOCKBUF_LOCK(&(so)->so_rcv);					\
	sorwakeup_locked(so);						\
} while (0)

#define	sowwakeup_locked(so) do {					\
	SOCKBUF_LOCK_ASSERT(&(so)->so_snd);				\
	if (sb_notify(&(so)->so_snd))					\
		ofp_sowakeup((so), &(so)->so_snd);				\
	else								\
		SOCKBUF_UNLOCK(&(so)->so_snd);				\
} while (0)

#define	sowwakeup(so) do {						\
	SOCKBUF_LOCK(&(so)->so_snd);					\
	sowwakeup_locked(so);						\
} while (0)

struct accept_filter {
	char	accf_name[16];
	int	(*accf_callback)
		(struct socket *so, void *arg, int waitflag);
	void *	(*accf_create)
		(struct socket *so, char *arg);
	void	(*accf_destroy)
		(struct socket *so);
	OFP_SLIST_ENTRY(accept_filter) accf_next;
};

#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_ACCF);
MALLOC_DECLARE(M_PCB);
MALLOC_DECLARE(M_SONAME);
#endif

extern uint64_t	ofp_sb_max;
extern struct uma_zone *socket_zone;
extern so_gen_t so_gencnt;

struct mbuf;
struct ofp_sockaddr;
struct ofp_ucred;
struct uio;

/* 'which' values for socket upcalls. */
#define	OFP_SO_RCV		1
#define	OFP_SO_SND		2

/* Return values for socket upcalls. */
#define	SU_OK		0
#define	SU_ISCONNECTED	1

/*
 * From uipc_socket and friends
 */
struct socket *ofp_get_sock_by_fd(int fd);

int	sockargs(odp_packet_t *mp, char * buf, int buflen, int type);
int	getsockaddr(struct ofp_sockaddr **namp, char * uaddr, size_t len);
void	ofp_soabort(struct socket *so);
int	ofp_soaccept(struct socket *so, struct ofp_sockaddr **nam);
int	socheckuid(struct socket *so, ofp_uid_t uid);
int	ofp_sobind(struct socket *so, struct ofp_sockaddr *nam, struct thread *td);
int	ofp_soclose(struct socket *so);
int	ofp_soconnect(struct socket *so, struct ofp_sockaddr *nam, struct thread *td);
int	soconnect2(struct socket *so1, struct socket *so2);
int	socow_setup(odp_packet_t m0, struct uio *uio);
int	ofp_socreate(int dom, struct socket **aso, int type, int proto, struct thread *td);
int	ofp_sodisconnect(struct socket *so);
struct ofp_sockaddr *sodupsockaddr(const struct ofp_sockaddr *sa, int mflags);
void	ofp_sofree(struct socket *so);
void	ofp_sohasoutofband(struct socket *so);
int	ofp_solisten(struct socket *so, int backlog, struct thread *td);
void	ofp_solisten_proto(struct socket *so, int backlog);
int	ofp_solisten_proto_check(struct socket *so);
struct socket *
	ofp_sonewconn(struct socket *head, int connstatus);
struct socket *
	sonewconn_passive_client(struct socket *head, int connstatus);

int	sopoll(struct socket *so, int events, struct ofp_ucred *active_cred,
	    struct thread *td);
int	sopoll_generic(struct socket *so, int events,
	    struct ofp_ucred *active_cred, struct thread *td);
int	ofp_soreceive(struct socket *so, struct ofp_sockaddr **paddr, struct uio *uio,
	    odp_packet_t *mp0, odp_packet_t *controlp, int *flagsp);
int	soreceive_stream(struct socket *so, struct ofp_sockaddr **paddr,
	    struct uio *uio, odp_packet_t *mp0, odp_packet_t *controlp,
	    int *flagsp);
int	ofp_soreceive_dgram(struct socket *so, struct ofp_sockaddr **paddr,
	    struct uio *uio, odp_packet_t *mp0, odp_packet_t *controlp,
	    int *flagsp);
int	ofp_soreceive_generic(struct socket *so, struct ofp_sockaddr **paddr,
	    struct uio *uio, odp_packet_t *mp0, odp_packet_t *controlp,
	    int *flagsp);
int	ofp_soreserve(struct socket *so, uint64_t sndcc, uint64_t rcvcc);
void	sorflush(struct socket *so);
#if 0
int	ofp_sosend(struct socket *so, struct ofp_sockaddr *addr, struct uio *uio,
	       odp_packet_t top, odp_packet_t control, int flags,
	       struct thread *td);
#endif
int	ofp_sosend(struct socket *so, struct ofp_sockaddr *addr, struct uio *uio,
	       odp_packet_t top, odp_packet_t control, int flags, struct thread *td);

int	ofp_sosend_dgram(struct socket *so, struct ofp_sockaddr *addr,
		     struct uio *uio, odp_packet_t top, odp_packet_t control,
		     int flags, struct thread *td);

int	ofp_sosend_generic(struct socket *so, struct ofp_sockaddr *addr,
		       struct uio *uio, odp_packet_t top, odp_packet_t control,
		       int flags, struct thread *td);
int	ofp_soshutdown(struct socket *so, int how);
void	sotoxsocket(struct socket *so, struct xsocket *xso);
void	ofp_soupcall_clear(struct socket *so, int which);
void	ofp_soupcall_set(struct socket *so, int which,
	    int (*func)(struct socket *, void *, int), void *arg);
int	souserctx_alloc(struct socket *so);
void	ofp_sowakeup(struct socket *so, struct sockbuf *sb);
int	selsocket(struct socket *so, int events, struct timeval *tv,
	    struct thread *td);

/*
 * Accept filter functions (duh).
 */
int	accept_filt_add(struct accept_filter *filt);
int	accept_filt_del(char *name);
struct	accept_filter *accept_filt_get(char *name);
#ifdef ACCEPT_FILTER_MOD
#ifdef SYSCTL_DECL
SYSCTL_DECL(_net_inet_accf);
#endif
int	accept_filt_generic_mod_event(module_t mod, int event, void *data);
#endif

odp_packet_t ofp_packet_alloc(uint32_t len);
odp_rwlock_t *ofp_accept_mtx(void);
void ofp_accept_lock(void);
void ofp_accept_unlock(void);

/* Emulation for BSD wakeup mechanism */
int ofp_msleep(void *channel, odp_rwlock_t *mtx, int priority, const char *wmesg,
		 uint32_t timeout);
int ofp_wakeup(void *channel);
int ofp_wakeup_one(void *channel);
int ofp_send_sock_event(struct socket *head, struct socket *so, int event);

#endif /* !_SYS_SOCKETVAR_H_ */
