/*-
 * Copyright (c) 1982, 1986, 1988, 1990, 1993
 *	The Regents of the University of California.
 * Copyright (c) 2004 The FreeBSD Foundation
 * Copyright (c) 2004-2008 Robert N. M. Watson
 * Copyright (c) 2014, Nokia
 * Copyright (c) 2014, Enea Software AB
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
 *	@(#)uipc_socket.c	8.3 (Berkeley) 4/15/94
 */

/*
 * Comments on the socket life cycle:
 *
 * soalloc() sets of socket layer state for a socket, called only by
 * ofp_socreate() and ofp_sonewconn().  Socket layer private.
 *
 * sodealloc() tears down socket layer state for a socket, called only by
 * ofp_sofree() and ofp_sonewconn().  Socket layer private.
 *
 * pru_attach() associates protocol layer state with an allocated socket;
 * called only once, may fail, aborting socket allocation.  This is called
 * from ofp_socreate() and ofp_sonewconn().  Socket layer private.
 *
 * pru_detach() disassociates protocol layer state from an attached socket,
 * and will be called exactly once for sockets in which pru_attach() has
 * been successfully called.  If pru_attach() returned an error,
 * pru_detach() will not be called.  Socket layer private.
 *
 * pru_abort() and pru_close() notify the protocol layer that the last
 * consumer of a socket is starting to tear down the socket, and that the
 * protocol should terminate the connection.  Historically, pru_abort() also
 * detached protocol state from the socket state, but this is no longer the
 * case.
 *
 * ofp_socreate() creates a socket and attaches protocol state.  This is a public
 * interface that may be used by socket layer consumers to create new
 * sockets.
 *
 * ofp_sonewconn() creates a socket and attaches protocol state.  This is a
 * public interface  that may be used by protocols to create new sockets when
 * a new connection is received and will be available for accept() on a
 * listen socket.
 *
 * ofp_soclose() destroys a socket after possibly waiting for it to disconnect.
 * This is a public interface that socket consumers should use to close and
 * release a socket when done with it.
 *
 * ofp_soabort() destroys a socket without waiting for it to disconnect (used
 * only for incoming connections that are already partially or fully
 * connected).  This is used internally by the socket layer when clearing
 * listen socket queues (due to overflow or close on the listen socket), but
 * is also a public interface protocols may use to abort connections in
 * their incomplete listen queues should they no longer be required.  Sockets
 * placed in completed connection listen queues should not be aborted for
 * reasons described in the comment above the ofp_soclose() implementation.  This
 * is not a general purpose close routine, and except in the specific
 * circumstances described here, should not be used.
 *
 * ofp_sofree() will free a socket and its protocol state if all references on
 * the socket have been released, and is the public interface to attempt to
 * free a socket when a reference is removed.  This is a socket layer private
 * interface.
 *
 * NOTE: In addition to ofp_socreate() and ofp_soclose(), which provide a single
 * socket reference to the consumer to be managed as required, there are two
 * calls to explicitly manage socket references, soref(), and sorele().
 * Currently, these are generally required only when transitioning a socket
 * from a listen queue to a file descriptor, in order to prevent garbage
 * collection of the socket at an untimely moment.  For a number of reasons,
 * these interfaces are not preferred, and should be avoided.
 *
 * NOTE: With regard to VNETs the general rule is that callers do not set
 * curvnet. Exceptions to this rule include ofp_soabort(), ofp_sodisconnect(),
 * ofp_sofree() (and with that sorele(), sotryfree()), as well as ofp_sonewconn()
 * and sorflush(), which are usually called from a pre-set VNET context.
 * sopoll() currently does not need a VNET context to be set.
 */

#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include <limits.h>

#include "odp.h"

#include "ofpi_errno.h"
#include "ofpi_timer.h"
#include "ofpi_inet.h"
#include "ofpi_in.h"
#include "ofpi_ip.h"
#include "ofpi_ip6.h"
#include "ofpi_udp.h"
#include "ofpi_icmp.h"

#include "ofpi_util.h"

#include "ofpi_socketvar.h"
#include "ofpi_socket.h"
#include "ofpi_in_pcb.h"
#include "ofpi_domain.h"
#include "ofpi_protosw.h"
#include "ofpi_ip6protosw.h"
#include "ofpi_sockstate.h"
#include "ofpi_tcp_var.h"
#include "ofpi_tcp_shm.h"
#include "ofpi_tcp_timer.h"
#include "ofpi_callout.h"
#include "ofpi_log.h"

#define SHM_NAME_SOCKET "OfpSocketShMem"

#define OFP_NUM_SOCKET_POOLS 32

/*
 * Shared data
 */
struct ofp_socket_mem {
	struct socket socket_list[OFP_NUM_SOCKETS_MAX];
	struct socket *free_sockets;
	int sockets_allocated, max_sockets_allocated;
	int socket_zone;

	odp_rwlock_t so_global_mtx;
	odp_rwlock_t ofp_accept_mtx;
	int somaxconn;
	odp_pool_t pool;

	struct sleeper {
		struct sleeper *next;
		void *channel;
		const char *wmesg;
		int   go;
		odp_timer_t tmo;
		int woke_by_timer;
	} *sleep_list;
	struct sleeper sleeper_list[OFP_NUM_SOCKETS_MAX];
	struct sleeper *free_sleepers;
	odp_spinlock_t sleep_lock;
};

/*
 * Data per core
 */
//static __thread struct ofp_socket_mem *shm;
static struct ofp_socket_mem *shm;

#if 0
/* For debugging */
void print_open_conns(void);
void ofp_print_long_counters(void);
void ofp_print_sockets(void)
{
	int i;
	for (i = 0; i < OFP_NUM_SOCKETS_MAX; i++) {
		struct socket *so = &shm->socket_list[i];
		if (!so->so_proto)
			continue;
		OFP_INFO("Socket %d: rcv.put=%d rcv.get=%d snd.put=%d snd.get=%d",
			  so->so_number, so->so_rcv.sb_put, so->so_rcv.sb_get,
			  so->so_snd.sb_put, so->so_snd.sb_get);
	}

	struct sleeper *s = shm->sleep_list;
	while (s) {
		OFP_INFO("Sleeper %s, tmo=%x go=%d timer=%d",
			  s->wmesg, s->tmo, s->go, s->woke_by_timer);
		s = s->next;
	}
	print_open_conns();
}

struct cli_conn;
void f_sockets(struct cli_conn *conn, const char *s)
{
	ofp_print_sockets();
}
#endif


odp_packet_t ofp_packet_alloc(uint32_t len)
{
	return odp_packet_alloc(shm->pool, len);
}

odp_rwlock_t *ofp_accept_mtx(void)
{
	return &shm->ofp_accept_mtx;
}

void ofp_accept_lock(void)
{
	odp_rwlock_write_lock(&shm->ofp_accept_mtx);
}

void ofp_accept_unlock(void)
{
	odp_rwlock_write_unlock(&shm->ofp_accept_mtx);
}

static int ofp_socket_alloc_shared_memory(void)
{
	shm = ofp_shared_memory_alloc(SHM_NAME_SOCKET, sizeof(*shm));
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}
	return 0;
}

static int ofp_socket_free_shared_memory(void)
{
	int rc = 0;

	if (ofp_shared_memory_free(SHM_NAME_SOCKET) == -1) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}
	shm = NULL;
	return rc;
}


int ofp_socket_lookup_shared_memory(void)
{
	shm = ofp_shared_memory_lookup(SHM_NAME_SOCKET);
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}
	return 0;
}

int ofp_socket_init_global(odp_pool_t pool)
{
	uint32_t i;

	HANDLE_ERROR(ofp_socket_alloc_shared_memory());

	memset(shm, 0, sizeof(*shm));
	shm->pool = ODP_POOL_INVALID;

	for (i = 0; i < OFP_NUM_SOCKETS_MAX; i++) {
		shm->socket_list[i].next = (i == OFP_NUM_SOCKETS_MAX - 1) ?
			NULL : &(shm->socket_list[i+1]);
		shm->socket_list[i].so_number = i + OFP_SOCK_NUM_OFFSET;
	}
	shm->free_sockets = &(shm->socket_list[0]);

	for (i = 0; i < OFP_NUM_SOCKETS_MAX; i++) {
		shm->sleeper_list[i].next = (i == OFP_NUM_SOCKETS_MAX - 1) ?
			NULL : &(shm->sleeper_list[i+1]);
	}
	shm->free_sleepers = &(shm->sleeper_list[0]);

	shm->somaxconn = SOMAXCONN;
	shm->pool = pool;
	odp_rwlock_init(&shm->so_global_mtx);
	odp_rwlock_init(&shm->ofp_accept_mtx);
	odp_spinlock_init(&shm->sleep_lock);

	return 0;
}

int ofp_socket_term_global(void)
{
	struct sleeper *p, *next;
	int rc = 0;

	p = shm->sleep_list;
	while (p) {
		next = p->next;
		if (p->tmo != ODP_TIMER_INVALID) {
			CHECK_ERROR(ofp_timer_cancel(p->tmo), rc);
			p->tmo = ODP_TIMER_INVALID;
		}
		p->go = 1;
		p = next;

	}

	ofp_inet_term();

	CHECK_ERROR(ofp_socket_free_shared_memory(), rc);

	return rc;
}

struct socket *ofp_get_sock_by_fd(int fd)
{
	return &shm->socket_list[fd - OFP_SOCK_NUM_OFFSET];
}

/*
 * Get a socket structure from our zone, and initialize it.
 * Allocate socket and PCB at the same time.
 *
 * soalloc() returns a socket with a ref count of 0.
 */
static struct socket *soalloc(void)
{
#if 1
	odp_rwlock_write_lock(&shm->so_global_mtx);
	struct socket *so = shm->free_sockets;
	if (shm->free_sockets) {
		shm->free_sockets = shm->free_sockets->next;
		shm->sockets_allocated++;
		if (shm->sockets_allocated > shm->max_sockets_allocated)
			shm->max_sockets_allocated = shm->sockets_allocated;
	}
	odp_rwlock_write_unlock(&shm->so_global_mtx);
#else
	struct socket *so = ofp_socket_pool_alloc(shm->socket_zone);
#endif

	if (so == NULL) {
		OFP_ERR("Cannot allocate socket!");
		return (NULL);
	}

	/* clean socket memory */
	int	number = so->so_number;
	memset(so, 0, sizeof(*so));
	so->so_number = number;

	SOCKBUF_LOCK_INIT(&so->so_snd, "so_snd");
	SOCKBUF_LOCK_INIT(&so->so_rcv, "so_rcv");
	odp_spinlock_init(&so->so_snd.sb_sx);
	odp_spinlock_init(&so->so_rcv.sb_sx);

	return (so);
}


/*
 * Free the storage associated with a socket at the socket layer, tear down
 * locks, labels, etc.  All protocol state is assumed already to have been
 * torn down (and possibly never set up) by the caller.
 */
static void
sodealloc(struct socket *so)
{
	KASSERT(so->so_count == 0, ("sodealloc(): so_count %d", so->so_count));
	KASSERT(so->so_pcb == NULL, ("sodealloc(): so_pcb != NULL"));

	so->so_proto = 0;
	odp_rwlock_write_lock(&shm->so_global_mtx);
	so->next = shm->free_sockets;
	shm->free_sockets = so;
	shm->sockets_allocated--;
	odp_rwlock_write_unlock(&shm->so_global_mtx);
}

/*
 * ofp_socreate returns a socket with a ref count of 1.  The socket should be
 * closed with ofp_soclose().
 */
int
ofp_socreate(int dom, struct socket **aso, int type, int proto, struct thread *td)
{
	struct protosw *prp;
	struct socket *so;
	int error;

	prp = ofp_pffindproto(dom, proto, type);

	if (prp == NULL || prp->pr_usrreqs->pru_attach == NULL ||
	    prp->pr_usrreqs->pru_attach == ofp_pru_attach_notsupp)
		return (OFP_EPROTONOSUPPORT);

	if (prp->pr_type == 0)
		return (OFP_EPROTONOSUPPORT);

	if (prp->pr_type != type)
		return (OFP_EPROTOTYPE);

	so = soalloc();

	if (so == NULL)
		return (OFP_ENOBUFS);

	OFP_TAILQ_INIT(&so->so_incomp);
	OFP_TAILQ_INIT(&so->so_comp);
	so->so_type = type;
	// HJo: FIX: so->so_cred = crhold(cred);
	so->so_cred = &so->so_cred_space;

	so->so_fibnum = td->td_proc.p_fibnum;
	so->so_proto = prp;
#if 0
	knlist_init_mtx(&so->so_rcv.sb_sel.si_note, SOCKBUF_MTX(&so->so_rcv));
	knlist_init_mtx(&so->so_snd.sb_sel.si_note, SOCKBUF_MTX(&so->so_snd));
#endif
	so->so_count = 1;

	error = (*prp->pr_usrreqs->pru_attach)(so, proto, td);
	if (error) {
		KASSERT(so->so_count == 1, ("ofp_socreate: so_count %d",
					    so->so_count));
		so->so_count = 0;
		sodealloc(so);
		return (error);
	}

	*aso = so;
	return (0);
}

/*
 * When an attempt at a new connection is noted on a socket which accepts
 * connections, ofp_sonewconn is called.  If the connection is possible (subject
 * to space constraints, etc.) then we allocate a new structure, properly
 * linked into the data structure of the original socket, and return this.
 * Connstatus may be 0, or OFP_SO_ISCONFIRMING, or OFP_SO_ISCONNECTED.
 *
 * Note: the ref count on the socket is 0 on return.
 */
struct socket *
ofp_sonewconn(struct socket *head, int connstatus)
{
	struct socket *so;
	int over;

	ACCEPT_LOCK();
	over = (head->so_qlen > 3 * head->so_qlimit / 2);
	ACCEPT_UNLOCK();
	if (over)
		return (NULL);
	so = soalloc();
	if (so == NULL)
		return (NULL);
	if ((head->so_options & OFP_SO_ACCEPTFILTER) != 0)
		connstatus = 0;
	so->so_head = head;
	so->so_type = head->so_type;
	so->so_options = head->so_options &~ (OFP_SO_ACCEPTCONN|OFP_SO_PASSIVE);
	so->so_linger = head->so_linger;
	so->so_state = head->so_state | SS_NOFDREF;
	so->so_fibnum = head->so_fibnum;
	so->so_proto = head->so_proto;
	//HJo so->so_cred = crhold(head->so_cred);
	//knlist_init_mtx(&so->so_rcv.sb_sel.si_note, SOCKBUF_MTX(&so->so_rcv));
	//knlist_init_mtx(&so->so_snd.sb_sel.si_note, SOCKBUF_MTX(&so->so_snd));
	if (ofp_soreserve(so, head->so_snd.sb_hiwat, head->so_rcv.sb_hiwat) ||
	    (*so->so_proto->pr_usrreqs->pru_attach)(so, 0, NULL)) {
		sodealloc(so);
		return (NULL);
	}
	so->so_rcv.sb_lowat = head->so_rcv.sb_lowat;
	so->so_snd.sb_lowat = head->so_snd.sb_lowat;
	so->so_rcv.sb_timeo = head->so_rcv.sb_timeo;
	so->so_snd.sb_timeo = head->so_snd.sb_timeo;
	so->so_rcv.sb_flags |= head->so_rcv.sb_flags & SB_AUTOSIZE;
	so->so_snd.sb_flags |= head->so_snd.sb_flags & SB_AUTOSIZE;
	so->so_state |= connstatus;

	so->so_sigevent = head->so_sigevent;
	so->so_rcv.sb_socket = so;
	so->so_snd.sb_socket = NULL;

	ACCEPT_LOCK();
	if (connstatus) {
		OFP_TAILQ_INSERT_TAIL(&head->so_comp, so, so_list);
		so->so_qstate |= SQ_COMP;
		head->so_qlen++;
	} else {
		/*
		 * Keep removing sockets from the head until there's room for
		 * us to insert on the tail.  In pre-locking revisions, this
		 * was a simple if(), but as we could be racing with other
		 * threads and ofp_soabort() requires dropping locks, we must
		 * loop waiting for the condition to be true.
		 */
		while (head->so_incqlen > head->so_qlimit) {
			struct socket *sp;
			sp = OFP_TAILQ_FIRST(&head->so_incomp);
			OFP_TAILQ_REMOVE(&head->so_incomp, sp, so_list);
			head->so_incqlen--;
			sp->so_qstate &= ~SQ_INCOMP;
			sp->so_head = NULL;
			ACCEPT_UNLOCK();
			ofp_soabort(sp);
			ACCEPT_LOCK();
		}
		OFP_TAILQ_INSERT_TAIL(&head->so_incomp, so, so_list);
		so->so_qstate |= SQ_INCOMP;
		head->so_incqlen++;
	}
	ACCEPT_UNLOCK();
	if (connstatus) {
		sorwakeup(head);
		ofp_wakeup_one(&head->so_timeo);
	}
	return (so);
}

int
ofp_sobind(struct socket *so, struct ofp_sockaddr *nam, struct thread *td)
{
	int error;

	error = (*so->so_proto->pr_usrreqs->pru_bind)(so, nam, td);
	return error;
}

/*
 * ofp_solisten() transitions a socket from a non-listening state to a listening
 * state, but can also be used to update the listen queue depth on an
 * existing listen socket.  The protocol will call back into the sockets
 * layer using ofp_solisten_proto_check() and ofp_solisten_proto() to check and set
 * socket-layer listen state.  Call backs are used so that the protocol can
 * acquire both protocol and socket layer locks in whatever order is required
 * by the protocol.
 *
 * Protocol implementors are advised to hold the socket lock across the
 * socket-layer test and set to avoid races at the socket layer.
 */
int
ofp_solisten(struct socket *so, int backlog, struct thread *td)
{
	int error;

	error = (*so->so_proto->pr_usrreqs->pru_listen)(so, backlog, td);
	return error;
}

int
ofp_solisten_proto_check(struct socket *so)
{
	OFP_SOCK_LOCK_ASSERT(so);

	if (so->so_state & (SS_ISCONNECTED | SS_ISCONNECTING |
	    SS_ISDISCONNECTING))
		return (OFP_EINVAL);
	return (0);
}

void
ofp_solisten_proto(struct socket *so, int backlog)
{
	OFP_SOCK_LOCK_ASSERT(so);

	if (backlog < 0 || backlog > shm->somaxconn)
		backlog = shm->somaxconn;
	so->so_qlimit = backlog;
	so->so_options |= OFP_SO_ACCEPTCONN;
}


static void
sofree_dequeue(struct socket *so)
{
	struct socket *head;

	head = so->so_head;
	if (head != NULL) {
		KASSERT((so->so_qstate & SQ_COMP) != 0 ||
		    (so->so_qstate & SQ_INCOMP) != 0,
		    ("ofp_sofree: so_head != NULL, but neither SQ_COMP nor "
		    "SQ_INCOMP"));
		KASSERT((so->so_qstate & SQ_COMP) == 0 ||
		    (so->so_qstate & SQ_INCOMP) == 0,
		    ("ofp_sofree: so->so_qstate is SQ_COMP and also SQ_INCOMP"));
		OFP_TAILQ_REMOVE(&head->so_incomp, so, so_list);
		head->so_incqlen--;
		so->so_qstate &= ~SQ_INCOMP;
		so->so_head = NULL;
	}
	KASSERT((so->so_qstate & SQ_COMP) == 0 &&
	    (so->so_qstate & SQ_INCOMP) == 0,
	    ("ofp_sofree: so_head == NULL, but still SQ_COMP(%d) or SQ_INCOMP(%d)",
	    so->so_qstate & SQ_COMP, so->so_qstate & SQ_INCOMP));
	if (so->so_options & OFP_SO_ACCEPTCONN) {
		KASSERT((OFP_TAILQ_EMPTY(&so->so_comp)), ("ofp_sofree: so_comp populated"));
		KASSERT((OFP_TAILQ_EMPTY(&so->so_incomp)), ("ofp_sofree: so_comp populated"));
	}
}

static void
sofree_dispose(struct socket *so)
{
	struct protosw *pr = so->so_proto;
#if 0
	if (pr->pr_flags & PR_RIGHTS && pr->pr_domain->dom_dispose != NULL)
		(*pr->pr_domain->dom_dispose)(so->so_rcv.sb_mb);
#endif
	if (pr->pr_usrreqs->pru_detach != NULL)
		(*pr->pr_usrreqs->pru_detach)(so);

	/*
	 * From this point on, we assume that no other references to this
	 * socket exist anywhere else in the stack.  Therefore, no locks need
	 * to be acquired or held.
	 *
	 * We used to do a lot of socket buffer and socket locking here, as
	 * well as invoke sorflush() and perform wakeups.  The direct call to
	 * dom_dispose() and ofp_sbrelease_internal() are an inlining of what was
	 * necessary from sorflush().
	 *
	 * Notice that the socket buffer and kqueue state are torn down
	 * before calling pru_detach.  This means that protocols shold not
	 * assume they can perform socket wakeups, etc, in their detach code.
	 */

	ofp_sbdestroy(&so->so_snd, so);
	ofp_sbdestroy(&so->so_rcv, so);
#if 0
	seldrain(&so->so_snd.sb_sel);
	seldrain(&so->so_rcv.sb_sel);
	knlist_destroy(&so->so_rcv.sb_sel.si_note);
	knlist_destroy(&so->so_snd.sb_sel.si_note);
#endif
	sodealloc(so);
}

static int
sohasrefs(const struct socket *so)
{
	return ((so->so_state & SS_NOFDREF) == 0 || so->so_count != 0 ||
		(so->so_state & SS_PROTOREF) || (so->so_qstate & SQ_COMP));
}

/*
 * Evaluate the reference count and named references on a socket; if no
 * references remain, free it.  This should be called whenever a reference is
 * released, such as in sorele(), but also when named reference flags are
 * cleared in socket or protocol code.
 *
 * ofp_sofree() will free the socket if:
 *
 * - There are no outstanding file descriptor references or related consumers
 *   (so_count == 0).
 *
 * - The socket has been closed by user space, if ever open (SS_NOFDREF).
 *
 * - The protocol does not have an outstanding strong reference on the socket
 *   (SS_PROTOREF).
 *
 * - The socket is not in a completed connection queue, so a process has been
 *   notified that it is present.  If it is removed, the user process may
 *   block in accept() despite select() saying the socket was ready.
 */
void
ofp_sofree(struct socket *so)
{
	ACCEPT_LOCK_ASSERT();
	OFP_SOCK_LOCK_ASSERT(so);

	if (sohasrefs(so)) {
		OFP_SOCK_UNLOCK(so);
		ACCEPT_UNLOCK();
		return;
	}

	sofree_dequeue(so);

	OFP_SOCK_UNLOCK(so);
	ACCEPT_UNLOCK();

	sofree_dispose(so);
}

/*
 * Close a socket on last file table reference removal.  Initiate disconnect
 * if connected.  Free socket when disconnect complete.
 *
 * This function will sorele() the socket.  Note that ofp_soclose() may be called
 * prior to the ref count reaching zero.  The actual socket structure will
 * not be freed until the ref count reaches zero.
 */
int
ofp_soclose(struct socket *so)
{
	int error = 0;

	KASSERT(!(so->so_state & SS_NOFDREF), ("ofp_soclose: SS_NOFDREF on enter"));

	//funsetown(&so->so_sigio);
	if (so->so_state & SS_ISCONNECTED) {
		if ((so->so_state & SS_ISDISCONNECTING) == 0) {
			error = ofp_sodisconnect(so);
			if (error) {
				if (error == OFP_ENOTCONN)
					error = 0;
				goto drop;
			}
		}
		if (so->so_options & OFP_SO_LINGER) {
			if ((so->so_state & SS_ISDISCONNECTING) &&
			    (so->so_state & SS_NBIO))
				goto drop;

			while (so->so_state & SS_ISCONNECTED) {
				/* HJo: was tsleep */
				error = ofp_msleep(&so->so_timeo, NULL,
					       0, "soclos", so->so_linger*1000000);
				if (error)
					break;
			}
		}
	}

drop:
	if (so->so_proto->pr_usrreqs->pru_close != NULL)
		(*so->so_proto->pr_usrreqs->pru_close)(so);
	if (so->so_options & OFP_SO_ACCEPTCONN) {
		struct socket *sp;
		ACCEPT_LOCK();
		while ((sp = OFP_TAILQ_FIRST(&so->so_incomp)) != NULL) {
			OFP_TAILQ_REMOVE(&so->so_incomp, sp, so_list);
			so->so_incqlen--;
			sp->so_qstate &= ~SQ_INCOMP;
			sp->so_head = NULL;
			ACCEPT_UNLOCK();
			ofp_soabort(sp);
			ACCEPT_LOCK();
		}
		while ((sp = OFP_TAILQ_FIRST(&so->so_comp)) != NULL) {
			OFP_TAILQ_REMOVE(&so->so_comp, sp, so_list);
			so->so_qlen--;
			sp->so_qstate &= ~SQ_COMP;
			sp->so_head = NULL;
			ACCEPT_UNLOCK();
			ofp_soabort(sp);
			ACCEPT_LOCK();
		}
		ACCEPT_UNLOCK();
	}
	ACCEPT_LOCK();
	OFP_SOCK_LOCK(so);
	KASSERT((so->so_state & SS_NOFDREF) == 0, ("ofp_soclose: NOFDREF"));
	so->so_state |= SS_NOFDREF;
	sorele(so);
	return (error);
}

void
sorflush(struct socket *so)
{
	struct sockbuf *sb = &so->so_rcv;
	/*struct protosw *pr = so->so_proto;*/
	struct sockbuf asb;

	/*
	 * In order to avoid calling dom_dispose with the socket buffer mutex
	 * held, and in order to generally avoid holding the lock for a long
	 * time, we make a copy of the socket buffer and clear the original
	 * (except locks, state).  The new socket buffer copy won't have
	 * initialized locks so we can only call routines that won't use or
	 * assert those locks.
	 *
	 * Dislodge threads currently blocked in receive and wait to acquire
	 * a lock against other simultaneous readers before clearing the
	 * socket buffer.  Don't let our acquire be interrupted by a signal
	 * despite any existing socket disposition on interruptable waiting.
	 */
	ofp_socantrcvmore(so);
	(void) ofp_sblock(sb, SBL_WAIT | SBL_NOINTR);

	/*
	 * Invalidate/clear most of the sockbuf structure, but leave selinfo
	 * and mutex data unchanged.
	 */
	SOCKBUF_LOCK(sb);
	bzero(&asb, offsetof(struct sockbuf, sb_startzero));
	bcopy(&sb->sb_startzero, &asb.sb_startzero,
			sizeof(*sb) - offsetof(struct sockbuf, sb_startzero));
	bzero(&sb->sb_startzero,
			sizeof(*sb) - offsetof(struct sockbuf, sb_startzero));
	SOCKBUF_UNLOCK(sb);
	ofp_sbunlock(sb);

	/*
	 * Dispose of special rights and flush the socket buffer.  Don't call
	 * any unsafe routines (that rely on locks being initialized) on asb.
	 */
	/*if (pr->pr_flags & PR_RIGHTS && pr->pr_domain->dom_dispose != NULL)
		(*pr->pr_domain->dom_dispose)(asb.sb_mb);*/
	ofp_sbrelease_internal(&asb, so);
}

int
ofp_soshutdown(struct socket *so, int how)
{
	struct protosw *pr = so->so_proto;
	int error;

	if (!(how == OFP_SHUT_RD || how == OFP_SHUT_WR || how == OFP_SHUT_RDWR))
		return (OFP_EINVAL);

	if (pr->pr_usrreqs->pru_flush != NULL) {
		(*pr->pr_usrreqs->pru_flush)(so, how);
	}
	if (how != OFP_SHUT_WR)
		sorflush(so);
	if (how != OFP_SHUT_RD) {
		error = (*pr->pr_usrreqs->pru_shutdown)(so);
		return (error);
	}
	return (0);
}

/*
 * ofp_soabort() is used to abruptly tear down a connection, such as when a
 * resource limit is reached (listen queue depth exceeded), or if a listen
 * socket is closed while there are sockets waiting to be accepted.
 *
 * This interface is tricky, because it is called on an unreferenced socket,
 * and must be called only by a thread that has actually removed the socket
 * from the listen queue it was on, or races with other threads are risked.
 *
 * This interface will call into the protocol code, so must not be called
 * with any socket locks held.  Protocols do call it while holding their own
 * recursible protocol mutexes, but this is something that should be subject
 * to review in the future.
 */
void
ofp_soabort(struct socket *so)
{
	/*
	 * In as much as is possible, assert that no references to this
	 * socket are held.  This is not quite the same as asserting that the
	 * current thread is responsible for arranging for no references, but
	 * is as close as we can get for now.
	 */
	KASSERT(so->so_count == 0, ("ofp_soabort: so_count"));
	KASSERT((so->so_state & SS_PROTOREF) == 0, ("ofp_soabort: SS_PROTOREF"));
	KASSERT(so->so_state & SS_NOFDREF, ("ofp_soabort: !SS_NOFDREF"));
	KASSERT((so->so_state & SQ_COMP) == 0, ("ofp_soabort: SQ_COMP"));
	KASSERT((so->so_state & SQ_INCOMP) == 0, ("ofp_soabort: SQ_INCOMP"));

	if (so->so_proto->pr_usrreqs->pru_abort != NULL)
		(*so->so_proto->pr_usrreqs->pru_abort)(so);

	ACCEPT_LOCK();
	OFP_SOCK_LOCK(so);
	ofp_sofree(so);
}

int
ofp_soaccept(struct socket *so, struct ofp_sockaddr **nam)
{
	int error;

	OFP_SOCK_LOCK(so);
	KASSERT((so->so_state & SS_NOFDREF) != 0, ("ofp_soaccept: !NOFDREF"));
	so->so_state &= ~SS_NOFDREF;
	OFP_SOCK_UNLOCK(so);
	error = (*so->so_proto->pr_usrreqs->pru_accept)(so, nam);
	return (error);
}

int
ofp_soconnect(struct socket *so, struct ofp_sockaddr *nam, struct thread *td)
{
	int error;

	if (so->so_options & OFP_SO_ACCEPTCONN)
		return (OFP_EOPNOTSUPP);

	/*
	 * If protocol is connection-based, can only connect once.
	 * Otherwise, if connected, try to disconnect first.  This allows
	 * user to disconnect by connecting to, e.g., a null address.
	 */
	if (so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING) &&
	    ((so->so_proto->pr_flags & PR_CONNREQUIRED) ||
	    (error = ofp_sodisconnect(so)))) {
		error = OFP_EISCONN;
	} else {
		/*
		 * Prevent accumulated error from previous connection from
		 * biting us.
		 */
		so->so_error = 0;
		error = (*so->so_proto->pr_usrreqs->pru_connect)(so, nam, td);
	}

	return (error);
}

int
ofp_sodisconnect(struct socket *so)
{
	int error;

	if ((so->so_state & SS_ISCONNECTED) == 0)
		return (OFP_ENOTCONN);
	if (so->so_state & SS_ISDISCONNECTING)
		return (OFP_EALREADY);
	error = (*so->so_proto->pr_usrreqs->pru_disconnect)(so);
	return (error);
}

#define	SBLOCKWAIT(f)	(((f) & OFP_MSG_DONTWAIT) ? 0 : SBL_WAIT)

int
ofp_sosend_dgram(struct socket *so, struct ofp_sockaddr *addr, struct uio *uio,
	     odp_packet_t top, odp_packet_t control, int flags, struct thread *td)
{
	long space = 0;
	ofp_ssize_t resid;
	int clen = 0, error, dontroute;
	const uint8_t *data;
	//size_t len;

	KASSERT(so->so_type == OFP_SOCK_DGRAM, ("sodgram_send: !OFP_SOCK_DGRAM"));
	KASSERT(so->so_proto->pr_flags & PR_ATOMIC,
		("sodgram_send: !PR_ATOMIC"));


	if (uio != NULL) {
		data = uio->uio_iov->iov_base;
		resid = uio->uio_iov->iov_len;
	} else {
		data = odp_packet_data(top);
		resid = odp_packet_len(top);
	}

	dontroute =
	    (flags & OFP_MSG_DONTROUTE) && (so->so_options & OFP_SO_DONTROUTE) == 0;
	/* HJo
	if (td != NULL)
		td->td_ru.ru_msgsnd++;
	*/
	if (control != ODP_PACKET_INVALID)
		clen = odp_packet_len(control);

	SOCKBUF_LOCK(&so->so_snd);
	if (so->so_snd.sb_state & SBS_CANTSENDMORE) {
		SOCKBUF_UNLOCK(&so->so_snd);
		error = OFP_EPIPE;
		goto out;
	}
	if (so->so_error) {
		error = so->so_error;
		so->so_error = 0;
		SOCKBUF_UNLOCK(&so->so_snd);
		goto out;
	}
	if ((so->so_state & SS_ISCONNECTED) == 0) {
		/*
		 * `sendto' and `sendmsg' is allowed on a connection-based
		 * socket if it supports implied connect.  Return OFP_ENOTCONN if
		 * not connected and no address is supplied.
		 */
		if ((so->so_proto->pr_flags & PR_CONNREQUIRED) &&
		    (so->so_proto->pr_flags & PR_IMPLOPCL) == 0) {
			if ((so->so_state & SS_ISCONFIRMING) == 0 &&
			    !(resid == 0 && clen != 0)) {
				SOCKBUF_UNLOCK(&so->so_snd);
				error = OFP_ENOTCONN;
				goto out;
			}
		} else if (addr == NULL) {
			if (so->so_proto->pr_flags & PR_CONNREQUIRED)
				error = OFP_ENOTCONN;
			else
				error = OFP_EDESTADDRREQ;
			SOCKBUF_UNLOCK(&so->so_snd);
			goto out;
		}
	}

	SOCKBUF_UNLOCK(&so->so_snd);

	if (uio != NULL) {
		uint8_t *p;
		error = OFP_ENOBUFS;

		top = ofp_packet_alloc(resid);

		if (top == ODP_PACKET_INVALID)
			goto out;

		odp_packet_user_ptr_set(top, NULL);

		error = 0;

		p = odp_packet_data(top);

		memcpy(p, data, resid);
/*Bogdan: ToDo chain of buffers for multiple uio_iov*/
	}

	resid = 0;

	KASSERT(resid == 0, ("ofp_sosend_dgram: resid != 0"));
	/*
	 * XXXRW: Frobbing OFP_SO_DONTROUTE here is even worse without ofp_sblock
	 * than with.
	 */
	if (dontroute) {
		OFP_SOCK_LOCK(so);
		so->so_options |= OFP_SO_DONTROUTE;
		OFP_SOCK_UNLOCK(so);
	}
	/*
	 * XXX all the SBS_CANTSENDMORE checks previously done could be out
	 * of date.  We could have recieved a reset packet in an interrupt or
	 * maybe we slept while doing page faults in uiomove() etc.  We could
	 * probably recheck again inside the locking protection here, but
	 * there are probably other places that this also happens.  We must
	 * rethink this.
	 */
	error = (*so->so_proto->pr_usrreqs->pru_send)(so,
	    (flags & OFP_MSG_OOB) ? PRUS_OOB :
	/*
	 * If the user set OFP_MSG_EOF, the protocol understands this flag and
	 * nothing left to send then use OFP_PRU_SEND_EOF instead of OFP_PRU_SEND.
	 */
	    ((flags & OFP_MSG_EOF) &&
	     (so->so_proto->pr_flags & PR_IMPLOPCL) &&
	     (resid <= 0)) ?
		PRUS_EOF :
		/* If there is more to send set PRUS_MORETOCOME */
		(resid > 0 && space > 0) ? PRUS_MORETOCOME : 0,
		top, addr, control, td);
	if (dontroute) {
		OFP_SOCK_LOCK(so);
		so->so_options &= ~OFP_SO_DONTROUTE;
		OFP_SOCK_UNLOCK(so);
	}
	clen = 0;
	control = ODP_PACKET_INVALID;
	top = ODP_PACKET_INVALID;
out:
	if (top != ODP_PACKET_INVALID)
		odp_packet_free(top);
	if (control != ODP_PACKET_INVALID)
		odp_packet_free(control);
	return (error);
}

/*
 * Send on a socket.  If send must go all at once and message is larger than
 * send buffering, then hard error.  Lock against other senders.  If must go
 * all at once and not enough room now, then inform user that this would
 * block and do nothing.  Otherwise, if nonblocking, send as much as
 * possible.  The data to be sent is described by "uio" if nonzero, otherwise
 * by the mbuf chain "top" (which must be null if uio is not).  Data provided
 * in mbuf chain must be small enough to send all at once.
 *
 * Returns nonzero on error, timeout or signal; callers must check for short
 * counts if OFP_EINTR/OFP_ERESTART are returned.  Data and control buffers are freed
 * on return.
 */
int
ofp_sosend_generic(struct socket *so, struct ofp_sockaddr *addr, struct uio *uio,
	       odp_packet_t top, odp_packet_t control, int flags, struct thread *td)
{
	long space;
	ofp_ssize_t resid;
	int clen = 0, error, dontroute;
	int atomic = sosendallatonce(so) || top;

	if (uio != NULL)
		resid = uio->uio_resid;
	else
		resid = odp_packet_len(top);
	/*
	 * In theory resid should be unsigned.  However, space must be
	 * signed, as it might be less than 0 if we over-committed, and we
	 * must use a signed comparison of space and resid.  On the other
	 * hand, a negative resid causes us to loop sending 0-length
	 * segments to the protocol.
	 *
	 * Also check to make sure that OFP_MSG_EOR isn't used on OFP_SOCK_STREAM
	 * type sockets since that's an error.
	 */
	if (resid < 0 || (so->so_type == OFP_SOCK_STREAM && (flags & OFP_MSG_EOR))) {
		error = OFP_EINVAL;
		goto out;
	}

	dontroute =
	    (flags & OFP_MSG_DONTROUTE) && (so->so_options & OFP_SO_DONTROUTE) == 0 &&
	    (so->so_proto->pr_flags & PR_ATOMIC);
	/* HJo
	if (td != NULL)
		td->td_ru.ru_msgsnd++;
	*/
	if (control != ODP_PACKET_INVALID)
		clen = odp_packet_len(control);

	error = ofp_sblock(&so->so_snd, SBLOCKWAIT(flags));
	if (error)
		goto out;
restart:

	do {
		SOCKBUF_LOCK(&so->so_snd);
		if (so->so_snd.sb_state & SBS_CANTSENDMORE) {
			SOCKBUF_UNLOCK(&so->so_snd);
			error = OFP_EPIPE;

			goto release;
		}
		if (so->so_error) {
			error = so->so_error;
			so->so_error = 0;
			SOCKBUF_UNLOCK(&so->so_snd);

			goto release;
		}
		if ((so->so_state & SS_ISCONNECTED) == 0) {

			/*
			 * `sendto' and `sendmsg' is allowed on a connection-
			 * based socket if it supports implied connect.
			 * Return OFP_ENOTCONN if not connected and no address is
			 * supplied.
			 */
			if ((so->so_proto->pr_flags & PR_CONNREQUIRED) &&
			    (so->so_proto->pr_flags & PR_IMPLOPCL) == 0) {
				if ((so->so_state & SS_ISCONFIRMING) == 0 &&
				    !(resid == 0 && clen != 0)) {
					SOCKBUF_UNLOCK(&so->so_snd);
					error = OFP_ENOTCONN;
					goto release;
				}
			} else if (addr == NULL) {
				SOCKBUF_UNLOCK(&so->so_snd);
				if (so->so_proto->pr_flags & PR_CONNREQUIRED)
					error = OFP_ENOTCONN;
				else
					error = OFP_EDESTADDRREQ;
				goto release;
			}
		}

		space = sbspace(&so->so_snd);
		if (flags & OFP_MSG_OOB)
			space += 1024;
		if ((atomic && resid > so->so_snd.sb_hiwat) ||
		    clen > (int)so->so_snd.sb_hiwat) {
			SOCKBUF_UNLOCK(&so->so_snd);
			error = OFP_EMSGSIZE;

			goto release;
		}

		if (space < resid + clen &&
		    (atomic || space < so->so_snd.sb_lowat || space < clen)) {

			if ((so->so_state & SS_NBIO) || (flags & OFP_MSG_NBIO)) {
				if (so->so_upcallprep.soup_send) {
					so->so_upcallprep.soup_send(so,
						so->so_upcallprep.soup_send_arg,
						resid);
				}
				SOCKBUF_UNLOCK(&so->so_snd);
				error = OFP_EWOULDBLOCK;
				goto release;
			}

			error = ofp_sbwait(&so->so_snd);
			SOCKBUF_UNLOCK(&so->so_snd);
			if (error)
				goto release;
			goto restart;
		}

		SOCKBUF_UNLOCK(&so->so_snd);
		space -= clen;
		do {

			if (uio == NULL) {

				resid = 0;
				/* HJo: FIX
				if (flags & OFP_MSG_EOR)
					odp_packet_flags(top) |= M_EOR;
				*/
			} else {

				top = odp_packet_alloc(shm->pool, 1);
				error = OFP_ENOBUFS;

				if (top == ODP_PACKET_INVALID)
					goto release;

				int cancopy = resid;
				if (cancopy > SHM_PKT_POOL_BUFFER_SIZE)
					cancopy = SHM_PKT_POOL_BUFFER_SIZE;
				if (cancopy > space)
					cancopy = space;
				odp_packet_reset(top, cancopy);
				odp_packet_user_ptr_set(top, NULL);
				uint8_t *p = odp_packet_data(top);
				memcpy(p, uio->uio_iov->iov_base, cancopy);
				uio->uio_iov->iov_base = cancopy +
					(uint8_t *)uio->uio_iov->iov_base;
				uio->uio_resid -= cancopy;
				space -= resid - uio->uio_resid;
				resid = uio->uio_resid;
			}
			if (dontroute) {
				OFP_SOCK_LOCK(so);
				so->so_options |= OFP_SO_DONTROUTE;
				OFP_SOCK_UNLOCK(so);
			}
			/*
			 * XXX all the SBS_CANTSENDMORE checks previously
			 * done could be out of date.  We could have recieved
			 * a reset packet in an interrupt or maybe we slept
			 * while doing page faults in uiomove() etc.  We
			 * could probably recheck again inside the locking
			 * protection here, but there are probably other
			 * places that this also happens.  We must rethink
			 * this.
			 */
			error = (*so->so_proto->pr_usrreqs->pru_send)(so,
			    (flags & OFP_MSG_OOB) ? PRUS_OOB :
			/*
			 * If the user set OFP_MSG_EOF, the protocol understands
			 * this flag and nothing left to send then use
			 * OFP_PRU_SEND_EOF instead of OFP_PRU_SEND.
			 */
			    ((flags & OFP_MSG_EOF) &&
			     (so->so_proto->pr_flags & PR_IMPLOPCL) &&
			     (resid <= 0)) ?
				PRUS_EOF :
			/* If there is more to send set PRUS_MORETOCOME. */
			    (resid > 0 && space > 0) ? PRUS_MORETOCOME : 0,
			    top, addr, control, td);
			if (dontroute) {
				OFP_SOCK_LOCK(so);
				so->so_options &= ~OFP_SO_DONTROUTE;
				OFP_SOCK_UNLOCK(so);
			}
			clen = 0;
			control = ODP_PACKET_INVALID;
			top = ODP_PACKET_INVALID;

			if (error)
				goto release;
		} while (resid && space > 0);
	} while (resid);

release:
	ofp_sbunlock(&so->so_snd);
out:

	if (top != ODP_PACKET_INVALID)
		odp_packet_free(top);
	if (control != ODP_PACKET_INVALID)
		odp_packet_free(control);
	return (error);
}

int
ofp_sosend(struct socket *so, struct ofp_sockaddr *addr, struct uio *uio,
    odp_packet_t top, odp_packet_t control, int flags, struct thread *td)
{
	int error;

	if (so->so_proto->pr_flags & PR_CONNREQUIRED) {
		if (!(so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING))) {
			OFP_ERR("OFP_ENOTCONN: state = %x", so->so_state);
			return OFP_ENOTCONN;
		} else if (addr)
			return OFP_EISCONN;
	}

	error = so->so_proto->pr_usrreqs->pru_sosend(so, addr, uio, top,
						     control, flags, td);
	return (error);
}

/*
 * Implement receive operations on a socket.  We depend on the way that
 * records are added to the sockbuf by sbappend.  In particular, each record
 * (mbufs linked through m_next) must begin with an address if the protocol
 * so specifies, followed by an optional mbuf or mbufs containing ancillary
 * data, and then zero or more mbufs of data.  In order to allow parallelism
 * between network receive and copying to user space, as well as avoid
 * sleeping with a mutex held, we release the socket buffer mutex during the
 * user space copy.  Although the sockbuf is locked, new data may still be
 * appended, and thus we must maintain consistency of the sockbuf during that
 * time.
 *
 * The caller may receive the data as a single mbuf chain by supplying an
 * mbuf **mp0 for use in returning the chain.  The uio is then used only for
 * the count in uio_resid.
 */
int
ofp_soreceive_generic(struct socket *so, struct ofp_sockaddr **psa, struct uio *uio,
		  odp_packet_t *mp0, odp_packet_t *controlp, int *flagsp)
{
	odp_packet_t m, *mp;
	int flags, error, offset;
	ofp_ssize_t len;
	struct protosw *pr = so->so_proto;
	int moff, /* type = 0, last_m_flags,*/ hole_break = 0;
	ofp_ssize_t orig_resid = uio->uio_resid;
	uint32_t uio_off;

	mp = mp0;
	if (psa != NULL)
		*psa = NULL;
	if (controlp != NULL)
		*controlp = ODP_PACKET_INVALID;
	if (flagsp != NULL) {
		hole_break = *flagsp & OFP_MSG_HOLE_BREAK;
		*flagsp &= ~OFP_MSG_HOLE_BREAK;
		flags = *flagsp &~ OFP_MSG_EOR;
	} else
		flags = 0;

	hole_break = hole_break;

	/* HJo: FIX
	if (flags & OFP_MSG_OOB)
		return (soreceive_rcvoob(so, uio, flags));
	*/
	if (mp != NULL)
		*mp = ODP_PACKET_INVALID;
	if ((pr->pr_flags & PR_WANTRCVD) && (so->so_state & SS_ISCONFIRMING)
	    && uio->uio_resid) {
		(*pr->pr_usrreqs->pru_rcvd)(so, 0);
	}

	error = ofp_sblock(&so->so_rcv, SBLOCKWAIT(flags));
	if (error)
		return (error);
restart:
	SOCKBUF_LOCK(&so->so_rcv);
	m = ofp_sockbuf_get_first(&so->so_rcv);
	/*
	 * If we have less data than requested, block awaiting more (subject
	 * to any timeout) if:
	 *   1. the current count is less than the low water mark, or
	 *   2. OFP_MSG_WAITALL is set, and it is possible to do the entire
	 *	receive operation at once if we block (resid <= hiwat).
	 *   3. OFP_MSG_DONTWAIT is not set
	 * If OFP_MSG_WAITALL is set but resid is larger than the receive buffer,
	 * we have to do the receive in sections, and thus risk returning a
	 * short count if a timeout or signal occurs after we start.
	 */
	if (m == ODP_PACKET_INVALID ||
	    (((flags & OFP_MSG_DONTWAIT) == 0 &&
	      so->so_rcv.sb_cc < uio->uio_resid) &&
	     ((int)so->so_rcv.sb_cc < so->so_rcv.sb_lowat ||
	    ((flags & OFP_MSG_WAITALL) && uio->uio_resid <= so->so_rcv.sb_hiwat)) &&
	    (pr->pr_flags & PR_ATOMIC) == 0)) {
		KASSERT(m != ODP_PACKET_INVALID || !so->so_rcv.sb_cc,
		    ("receive: so->so_rcv.sb_cc == %u",
		    so->so_rcv.sb_cc));
		if (so->so_error) {
			if (m != ODP_PACKET_INVALID)
				goto dontblock;
			error = so->so_error;
			if ((flags & OFP_MSG_PEEK) == 0)
				so->so_error = 0;
			SOCKBUF_UNLOCK(&so->so_rcv);
			goto release;
		}
		SOCKBUF_LOCK_ASSERT(&so->so_rcv);
		if (so->so_rcv.sb_state & SBS_CANTRCVMORE) {
			if (m == ODP_PACKET_INVALID) {
				SOCKBUF_UNLOCK(&so->so_rcv);
				goto release;
			} else
				goto dontblock;
		}
		/* HJo: FIX:
		for (; m != NULL; m = m->m_next)
			if (m->m_type == MT_OOBDATA  || (odp_packet_flags(m) & M_EOR)) {
				m = so->so_rcv.sb_mb;
				goto dontblock;
			}
		*/
		if (m != ODP_PACKET_INVALID)
			goto dontblock;
		if ((so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING)) == 0 &&
		    (so->so_proto->pr_flags & PR_CONNREQUIRED)) {
			SOCKBUF_UNLOCK(&so->so_rcv);
			error = OFP_ENOTCONN;
			goto release;
		}
		if (uio->uio_resid == 0) {
			SOCKBUF_UNLOCK(&so->so_rcv);
			goto release;
		}
		if ((so->so_state & SS_NBIO) ||
		    (flags & (OFP_MSG_DONTWAIT|OFP_MSG_NBIO))) {
			if (so->so_upcallprep.soup_receive != NULL) {
				so->so_upcallprep.soup_receive(so,
					so->so_upcallprep.soup_receive_arg,
					orig_resid - uio->uio_resid, uio->uio_resid);
			}
			SOCKBUF_UNLOCK(&so->so_rcv);
			error = OFP_EWOULDBLOCK;
			goto release;
		}
		SBLASTRECORDCHK(&so->so_rcv);
		SBLASTMBUFCHK(&so->so_rcv);
		error = ofp_sbwait(&so->so_rcv);
		SOCKBUF_UNLOCK(&so->so_rcv);
		if (error)
			goto release;
		goto restart;
	}
dontblock:
	/*
	 * From this point onward, we maintain 'nextrecord' as a cache of the
	 * pointer to the next record in the socket buffer.  We must keep the
	 * various socket buffer pointers and local stack versions of the
	 * pointers in sync, pushing out modifications before dropping the
	 * socket buffer mutex, and re-reading them when picking it up.
	 *
	 * Otherwise, we will race with the network stack appending new data
	 * or records onto the socket buffer by using inconsistent/stale
	 * versions of the field, possibly resulting in socket buffer
	 * corruption.
	 *
	 * By holding the high-level ofp_sblock(), we prevent simultaneous
	 * readers from pulling off the front of the socket buffer.
	 */
	SOCKBUF_LOCK_ASSERT(&so->so_rcv);
	/* HJo
	if (uio->uio_td)
		uio->uio_td->td_ru.ru_msgrcv++;
	KASSERT(m == so->so_rcv.sb_mb, ("ofp_soreceive: m != so->so_rcv.sb_mb"));
	*/
	SBLASTRECORDCHK(&so->so_rcv);
	SBLASTMBUFCHK(&so->so_rcv);
	if (pr->pr_flags & PR_ADDR) {
		/* HJo
		KASSERT(m->m_type == MT_SONAME,
		    ("m->m_type == %d", m->m_type));
		*/
		orig_resid = 0;
		/* HJo: FIX
		if (psa != NULL)
			*psa = sodupsockaddr((struct ofp_sockaddr *)odp_packet_data(m),
			    M_NOWAIT);
		*/
		if (flags & OFP_MSG_PEEK) {
			/* HJo m = m->m_next; */
		} else {
			/* HJo
			sbfree(&so->so_rcv, m);
			odp_packet_free(m);
			m = ofp_sockbuf_remove_first(&so->so_rcv);
			*/
			/* sockbuf_pushsync(&so->so_rcv, nextrecord);*/
		}
	}

#if 0 /* HJo: FIX */
	/*
	 * Process one or more MT_CONTROL mbufs present before any data mbufs
	 * in the first mbuf chain on the socket buffer.  If OFP_MSG_PEEK, we
	 * just copy the data; if !OFP_MSG_PEEK, we call into the protocol to
	 * perform externalization (or freeing if controlp == NULL).
	 */
	if (m != NULL && m->m_type == MT_CONTROL) {
		odp_packet_t cm = NULL, *cmn;
		odp_packet_t *cme = &cm;

		do {
			if (flags & OFP_MSG_PEEK) {
				if (controlp != NULL) {
					*controlp = m_copy(m, 0, odp_packet_get_len(m));
					controlp = &(*controlp)->m_next;
				}
				m = m->m_next;
			} else {
				sbfree(&so->so_rcv, m);
				so->so_rcv.sb_mb = m->m_next;
				m->m_next = NULL;
				*cme = m;
				cme = &(*cme)->m_next;
				m = so->so_rcv.sb_mb;
			}
		} while (m != NULL && m->m_type == MT_CONTROL);
		/*
		if ((flags & OFP_MSG_PEEK) == 0)
			sockbuf_pushsync(&so->so_rcv, nextrecord);
		*/
		while (cm != NULL) {
			cmn = cm->m_next;
			cm->m_next = NULL;
			if (pr->pr_domain->dom_externalize != NULL) {
				SOCKBUF_UNLOCK(&so->so_rcv);
				VNET_SO_ASSERT(so);
				error = (*pr->pr_domain->dom_externalize)
				    (cm, controlp);
				SOCKBUF_LOCK(&so->so_rcv);
			} else if (controlp != NULL)
				*controlp = cm;
			else
				odp_packet_free(cm));
			if (controlp != NULL) {
				orig_resid = 0;
				while (*controlp != NULL)
					controlp = &(*controlp)->m_next;
			}
			cm = cmn;
		}
		/*
		if (m != NULL)
			nextrecord = so->so_rcv.sb_mb->m_nextpkt;
		else
			nextrecord = so->so_rcv.sb_mb;
		*/
		orig_resid = 0;
	}
	if (m != NULL) {
		if ((flags & OFP_MSG_PEEK) == 0) {
			/*
			KASSERT(m->m_nextpkt == nextrecord,
			    ("ofp_soreceive: post-control, nextrecord !sync"));
			if (nextrecord == NULL) {
				KASSERT(so->so_rcv.sb_mb == m,
				    ("ofp_soreceive: post-control, sb_mb!=m"));
				KASSERT(so->so_rcv.sb_lastrecord == m,
				    ("ofp_soreceive: post-control, lastrecord!=m"));
			}
			*/
		}
		type = m->m_type;
		if (type == MT_OOBDATA)
			flags |= OFP_MSG_OOB;
		last_m_flags = odp_packet_flags(m);
		if (hole_break && (odp_packet_flags(m) & M_HOLE))
			flags |= OFP_MSG_HOLE_BREAK;
	} else {
		if ((flags & OFP_MSG_PEEK) == 0) {
			/*
			KASSERT(so->so_rcv.sb_mb == nextrecord,
			    ("ofp_soreceive: sb_mb != nextrecord"));
			if (so->so_rcv.sb_mb == NULL) {
				KASSERT(so->so_rcv.sb_lastrecord == NULL,
				    ("ofp_soreceive: sb_lastercord != NULL"));
			}
			*/
		}
	}
#endif /* HJo */

	SOCKBUF_LOCK_ASSERT(&so->so_rcv);
	SBLASTRECORDCHK(&so->so_rcv);
	SBLASTMBUFCHK(&so->so_rcv);

	/*
	 * Now continue to read any data mbufs off of the head of the socket
	 * buffer until the read request is satisfied.  Note that 'type' is
	 * used to store the type of any mbuf reads that have happened so far
	 * such that ofp_soreceive() can stop reading if the type changes, which
	 * causes ofp_soreceive() to return only one of regular data and inline
	 * out-of-band data in a single socket receive operation.
	 */
	moff = 0;
	offset = 0;
	uio_off = 0;
	while (m != ODP_PACKET_INVALID && uio->uio_resid > 0 && error == 0) {
		/*
		 * If the type of mbuf has changed since the last mbuf
		 * examined ('type'), end the receive operation.
	 	 */
		SOCKBUF_LOCK_ASSERT(&so->so_rcv);
		/* HJo: FIX
		if (hole_break &&
		    ((odp_packet_flags(m) ^ last_m_flags) & M_HOLE))
			break;
		last_m_flags = odp_packet_flags(m);
		if (m->m_type == MT_OOBDATA) {
			if (type != MT_OOBDATA)
				break;
		} else if (type == MT_OOBDATA)
			break;
		else
		    KASSERT(m->m_type == MT_DATA,
			("m->m_type == %d", m->m_type));
		*/

		so->so_rcv.sb_state &= ~SBS_RCVATMARK;
		len = uio->uio_resid;
		if (so->so_oobmark && len > (int)(so->so_oobmark - offset))
			len = so->so_oobmark - offset;
		if (len > odp_packet_len(m) - moff)
			len = odp_packet_len(m) - moff;
		/*
		 * If mp is set, just pass back the mbufs.  Otherwise copy
		 * them out via the uio, then free.  Sockbuf must be
		 * consistent here (points to current mbuf, it points to next
		 * record) when we drop priority; we must note any additions
		 * to the sockbuf when we block interrupts again.
		 */
		if (mp == NULL) {
			SOCKBUF_LOCK_ASSERT(&so->so_rcv);
			SBLASTRECORDCHK(&so->so_rcv);
			SBLASTMBUFCHK(&so->so_rcv);
			SOCKBUF_UNLOCK(&so->so_rcv);

			if (!odp_packet_copy_to_mem(m, moff, len, (void*)
					((uintptr_t)uio->uio_iov->iov_base +
						 uio_off))) {
				uio_off += len;
				uio->uio_resid -= len;
			}

			SOCKBUF_LOCK(&so->so_rcv);
			if (error) {
				/*
				 * The MT_SONAME mbuf has already been removed
				 * from the record, so it is necessary to
				 * remove the data mbufs, if any, to preserve
				 * the invariant in the case of PR_ADDR that
				 * requires MT_SONAME mbufs at the head of
				 * each record.
				 */
				if (m != ODP_PACKET_INVALID &&
				    pr->pr_flags & PR_ATOMIC &&
				    ((flags & OFP_MSG_PEEK) == 0))
					(void)ofp_sbdroprecord_locked(&so->so_rcv);
				SOCKBUF_UNLOCK(&so->so_rcv);
				goto release;
			}
		} else
			uio->uio_resid -= len;

		SOCKBUF_LOCK_ASSERT(&so->so_rcv);
		if (len == odp_packet_len(m) - moff) {
			/* HJo
			if (odp_packet_flags(m) & M_EOR)
				flags |= OFP_MSG_EOR;
			*/
			if (flags & OFP_MSG_PEEK) {
				/* HJo m = m->m_next; */
				moff = 0;
			} else {
				/* HJo nextrecord = m->m_nextpkt; */
				sbfree(&so->so_rcv, m);
				if (mp != NULL) {
					*mp = m;
					/* HJo
					mp = &m->m_next;
					so->so_rcv.sb_mb = m = m->m_next;
					*mp = NULL;
					*/
				} else {
					ofp_sockbuf_remove_first(&so->so_rcv);
					ofp_sockbuf_packet_free(m);
					m = ofp_sockbuf_get_first(&so->so_rcv);
				}
				/*
				sockbuf_pushsync(&so->so_rcv, nextrecord);
				*/
				SBLASTRECORDCHK(&so->so_rcv);
				SBLASTMBUFCHK(&so->so_rcv);
			}
		} else {
			if (flags & OFP_MSG_PEEK)
				moff += len;
			else {
				if (mp != NULL) {
					int copy_flag;

#define M_WAIT     1
#define M_DONTWAIT 2
					if (flags & OFP_MSG_DONTWAIT)
						copy_flag = M_DONTWAIT;
					else
						copy_flag = M_WAIT;
					if (copy_flag == M_WAIT)
						SOCKBUF_UNLOCK(&so->so_rcv);
					*mp = odp_packet_copy(m, shm->pool);
					if (copy_flag == M_WAIT)
						SOCKBUF_LOCK(&so->so_rcv);
 					if (*mp == ODP_PACKET_INVALID) {
 						/*
 						 * m_copym() couldn't
						 * allocate an mbuf.  Adjust
						 * uio_resid back (it was
						 * adjusted down by len
						 * bytes, which we didn't end
						 * up "copying" over).
 						 */
 						uio->uio_resid += len;
 						break;
 					}
				}
				/* HJo
				if ((odp_packet_flags(m) & M_HOLE) == 0)
					m->m_data += len;
				odp_packet_get_len(m) -= len;
				*/
				odp_packet_pull_head(m, len);
				so->so_rcv.sb_cc -= len;
			}
		}
		SOCKBUF_LOCK_ASSERT(&so->so_rcv);
		if (so->so_oobmark) {
			if ((flags & OFP_MSG_PEEK) == 0) {
				so->so_oobmark -= len;
				if (so->so_oobmark == 0) {
					so->so_rcv.sb_state |= SBS_RCVATMARK;
					break;
				}
			} else {
				offset += len;
				if (offset == (int)so->so_oobmark)
					break;
			}
		}
		if (flags & OFP_MSG_EOR)
			break;
		/*
		 * If the OFP_MSG_WAITALL flag is set (for non-atomic socket), we
		 * must not quit until "uio->uio_resid == 0" or an error
		 * termination.  If a signal/timeout occurs, return with a
		 * short count but without error.  Keep sockbuf locked
		 * against other readers.
		 */
		while (flags & OFP_MSG_WAITALL && m == ODP_PACKET_INVALID &&
		       uio->uio_resid > 0 &&
		       !sosendallatonce(so) /* && nextrecord == NULL*/) {
			SOCKBUF_LOCK_ASSERT(&so->so_rcv);
			if (so->so_error || so->so_rcv.sb_state & SBS_CANTRCVMORE)
				break;
			/*
			 * Notify the protocol that some data has been
			 * drained before blocking.
			 */
			if (pr->pr_flags & PR_WANTRCVD) {
				SOCKBUF_UNLOCK(&so->so_rcv);
				(*pr->pr_usrreqs->pru_rcvd)(so, flags);
				SOCKBUF_LOCK(&so->so_rcv);
			}
			SBLASTRECORDCHK(&so->so_rcv);
			SBLASTMBUFCHK(&so->so_rcv);
			/*
			 * We could receive some data while was notifying
			 * the protocol. Skip blocking in this case.
			 */
			if (so->so_rcv.sb_mb == NULL) {
				error = ofp_sbwait(&so->so_rcv);
				if (error) {
					SOCKBUF_UNLOCK(&so->so_rcv);
					goto release;
				}
			}
			m = ofp_sockbuf_get_first(&so->so_rcv);
		}
	}

	SOCKBUF_LOCK_ASSERT(&so->so_rcv);
	if (m != ODP_PACKET_INVALID && pr->pr_flags & PR_ATOMIC) {
		flags |= OFP_MSG_TRUNC;
		if ((flags & OFP_MSG_PEEK) == 0)
			(void) ofp_sbdroprecord_locked(&so->so_rcv);
	}
	if ((flags & OFP_MSG_PEEK) == 0) {
		if (m == ODP_PACKET_INVALID) {
			/*
			 * First part is an inline SB_EMPTY_FIXUP().  Second
			 * part makes sure sb_lastrecord is up-to-date if
			 * there is still data in the socket buffer.
			 */
			if (uio->uio_resid > 0 && orig_resid != uio->uio_resid
			    && !sosendallatonce(so) /* && nextrecord == NULL */) {
				if (so->so_upcallprep.soup_receive != NULL) {
					so->so_upcallprep.soup_receive(so,
					       so->so_upcallprep.soup_receive_arg,
					       orig_resid - uio->uio_resid, uio->uio_resid);
				}
			}
		}
		SBLASTRECORDCHK(&so->so_rcv);
		SBLASTMBUFCHK(&so->so_rcv);
		/*
		 * If ofp_soreceive() is being done from the socket callback,
		 * then don't need to generate ACK to peer to update window,
		 * since ACK will be generated on return to TCP.
		 */
		if (!(flags & OFP_MSG_SOCALLBCK) &&
		    (pr->pr_flags & PR_WANTRCVD)) {
			SOCKBUF_UNLOCK(&so->so_rcv);
			(*pr->pr_usrreqs->pru_rcvd)(so, flags);
			SOCKBUF_LOCK(&so->so_rcv);
		}
	}
	SOCKBUF_LOCK_ASSERT(&so->so_rcv);
	if (orig_resid == uio->uio_resid && orig_resid &&
	    (flags & OFP_MSG_EOR) == 0 && (so->so_rcv.sb_state & SBS_CANTRCVMORE) == 0) {
		SOCKBUF_UNLOCK(&so->so_rcv);
		goto restart;
	}
	SOCKBUF_UNLOCK(&so->so_rcv);

	if (flagsp != NULL)
		*flagsp |= flags;
release:
	ofp_sbunlock(&so->so_rcv);
	return (error);
}

/*
 * Optimized version of ofp_soreceive() for simple datagram cases from userspace.
 * Unlike in the stream case, we're able to drop a datagram if copyout()
 * fails, and because we handle datagrams atomically, we don't need to use a
 * sleep lock to prevent I/O interlacing.
 */
int
ofp_soreceive_dgram(struct socket *so, struct ofp_sockaddr **psa, struct uio *uio,
		odp_packet_t *mp0, odp_packet_t *controlp, int *flagsp)
{
	int flags, error;
	size_t len;
	struct protosw *pr = so->so_proto;

	(void)mp0;

	/* HJo: Originally psa will be allocated. We want it set beforehand.
	if (psa != NULL)
		*psa = NULL;
		*/
	if (controlp != NULL)
		*controlp = ODP_PACKET_INVALID;
	if (flagsp != NULL)
		flags = *flagsp &~ OFP_MSG_EOR;
	else
		flags = 0;

	/*
	 * For any complicated cases, fall back to the full
	 * ofp_soreceive_generic().
	 */
#if 0
	if (mp0 != NULL || (flags & OFP_MSG_PEEK) || (flags & OFP_MSG_OOB))
		return (ofp_soreceive_generic(so, psa, uio, mp0, controlp,
		    flagsp));
#endif
	/*
	 * Enforce restrictions on use.
	 */
	KASSERT((pr->pr_flags & PR_WANTRCVD) == 0,
		("ofp_soreceive_dgram: wantrcvd"));
	KASSERT(pr->pr_flags & PR_ATOMIC, ("ofp_soreceive_dgram: !atomic"));
	KASSERT((so->so_rcv.sb_state & SBS_RCVATMARK) == 0,
		("ofp_soreceive_dgram: SBS_RCVATMARK"));
	KASSERT((so->so_proto->pr_flags & PR_CONNREQUIRED) == 0,
		("ofp_soreceive_dgram: P_CONNREQUIRED"));

	/*
	 * Loop blocking while waiting for a datagram.
	 */
	SOCKBUF_LOCK(&so->so_rcv);
	while (so->so_rcv.sb_put == so->so_rcv.sb_get) {
		KASSERT(so->so_rcv.sb_cc == 0,
			("ofp_soreceive_dgram: sb_mb NULL but sb_cc %u",
			 so->so_rcv.sb_cc));
		if (so->so_error) {
			error = so->so_error;
			so->so_error = 0;
			SOCKBUF_UNLOCK(&so->so_rcv);
			return (error);
		}
		if (so->so_rcv.sb_state & SBS_CANTRCVMORE ||
		    uio->uio_resid == 0) {
			SOCKBUF_UNLOCK(&so->so_rcv);
			return (0);
		}
		if ((so->so_state & SS_NBIO) ||
		    (flags & (OFP_MSG_DONTWAIT|OFP_MSG_NBIO))) {
			SOCKBUF_UNLOCK(&so->so_rcv);
			return (OFP_EWOULDBLOCK);
		}
		SBLASTRECORDCHK(&so->so_rcv);
		SBLASTMBUFCHK(&so->so_rcv);
		error = ofp_sbwait(&so->so_rcv);
		if (error) {
			SOCKBUF_UNLOCK(&so->so_rcv);
			return (error);
		}
	}
	SOCKBUF_LOCK_ASSERT(&so->so_rcv);

	odp_packet_t pkt = so->so_rcv.sb_mb[so->so_rcv.sb_get];
	sbfree(&so->so_rcv, pkt);
	if (++so->so_rcv.sb_get >= SOCKBUF_LEN)
		so->so_rcv.sb_get = 0;

	SOCKBUF_UNLOCK(&so->so_rcv);

	struct ofp_udphdr *uh = (struct ofp_udphdr *)odp_packet_l4_ptr(pkt, NULL);
	if (!uh) {
		OFP_ERR("UDP HDR == NULL!");
		return 0;
	}
	uint8_t *data = (uint8_t *)(uh + 1);
	len = odp_be_to_cpu_16(uh->uh_ulen) - sizeof(*uh);
	if (len > uio->uio_iov->iov_len) {
		len = uio->uio_iov->iov_len;
		flags |= OFP_MSG_TRUNC;
	}

	memcpy(uio->uio_iov->iov_base, data, len);

	if (psa && *psa) {
		 if (pr->pr_flags & PR_ADDR) {
			/* address is save on L2 & L3 */
			struct ofp_sockaddr *sa =
				(struct ofp_sockaddr *)odp_packet_l2_ptr(pkt, NULL);
			memcpy(*psa, sa, sa->sa_len);
		} else
			(*psa)->sa_len = 0;
	}

	odp_packet_free(pkt);
	uio->uio_resid -= len;

	if (flagsp != NULL)
		*flagsp |= flags;

	return (0);
}

int
ofp_soreceive(struct socket *so, struct ofp_sockaddr **psa, struct uio *uio,
	  odp_packet_t *mp0, odp_packet_t *controlp, int *flagsp)
{
	int error;

	if (so->so_proto->pr_flags & PR_CONNREQUIRED) {
		if (!(so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING)))
			return OFP_ENOTCONN;
	}

	error = (so->so_proto->pr_usrreqs->pru_soreceive(so, psa, uio, mp0,
							 controlp, flagsp));

	return (error);
}

int
ofp_sooptcopyin(struct sockopt *sopt, void *buf, size_t len, size_t minlen)
{
	size_t	valsize;

	/*
	 * If the user gives us more than we wanted, we ignore it, but if we
	 * don't get the minimum length the caller wants, we return OFP_EINVAL.
	 * On success, sopt->sopt_valsize is set to however much we actually
	 * retrieved.
	 */
	if ((valsize = sopt->sopt_valsize) < minlen)
		return OFP_EINVAL;
	if (valsize > len)
		sopt->sopt_valsize = valsize = len;

	bcopy(sopt->sopt_val, buf, valsize);
	return (0);
}

extern int ofp_ip_ctloutput(struct socket *so, struct sockopt *sopt);
int
ofp_sosetopt(struct socket *so, struct sockopt *sopt)
{
	int	error, optval = 0;
	struct ofp_linger l;
	struct ofp_timeval tv;
	uint64_t  val;
	uint32_t val32;

	error = 0;
	if (sopt->sopt_level != OFP_SOL_SOCKET) {
		if (so->so_proto->pr_ctloutput != NULL) {
			error = (*so->so_proto->pr_ctloutput)(so, sopt);
			return (error);
		}
		error = OFP_ENOPROTOOPT;
	} else {
		switch (sopt->sopt_name) {
		case OFP_SO_ACCEPTFILTER:
			error = OFP_EOPNOTSUPP;
			break;
		case OFP_SO_LINGER:
			error = ofp_sooptcopyin(sopt, &l, sizeof l, sizeof l);
			if (error)
				goto bad;

			OFP_SOCK_LOCK(so);
			so->so_linger = l.l_linger;
			if (l.l_onoff)
				so->so_options |= OFP_SO_LINGER;
			else
				so->so_options &= ~OFP_SO_LINGER;
			OFP_SOCK_UNLOCK(so);
			break;

		case OFP_SO_DEBUG:
		case OFP_SO_KEEPALIVE:
		case OFP_SO_DONTROUTE:
		case OFP_SO_USELOOPBACK:
		case OFP_SO_BROADCAST:
		case OFP_SO_REUSEADDR:
		case OFP_SO_REUSEPORT:
		case OFP_SO_OOBINLINE:
		case OFP_SO_TIMESTAMP:
		case OFP_SO_BINTIME:
		case OFP_SO_NOSIGPIPE:
		case OFP_SO_NO_DDP:
		case OFP_SO_NO_OFFLOAD:
			error = ofp_sooptcopyin(sopt, &optval, sizeof optval,
					    sizeof optval);
			if (error)
				goto bad;
			OFP_SOCK_LOCK(so);
			if (optval)
				so->so_options |= sopt->sopt_name;
			else
				so->so_options &= ~sopt->sopt_name;
			OFP_SOCK_UNLOCK(so);
			break;

		case OFP_SO_SETFIB:
			error = ofp_sooptcopyin(sopt, &optval, sizeof optval,
					    sizeof optval);
			if (optval < 0 || optval >= 4096 /* HJo rt_numfibs*/) {
				error = OFP_EINVAL;
				goto bad;
			}
			if (((so->so_proto->pr_domain->dom_family == OFP_PF_INET) ||
			     (so->so_proto->pr_domain->dom_family == OFP_PF_INET6))) {
				so->so_fibnum = optval;
				/* Note: ignore error */
				if (so->so_proto->pr_ctloutput)
					(*so->so_proto->pr_ctloutput)(so, sopt);
			} else {
				so->so_fibnum = 0;
			}
			break;

		case OFP_SO_ALTFIB:
			error = OFP_EOPNOTSUPP;
			break;

		case OFP_SO_USER_COOKIE:
			error = ofp_sooptcopyin(sopt, &val32, sizeof val32,
					    sizeof val32);
			if (error)
				goto bad;
			so->so_user_cookie = val32;
			break;

		case OFP_SO_L2INFO:
			error = OFP_EOPNOTSUPP;
			break;

		case OFP_SO_PASSIVE:
		case OFP_SO_PROMISC:
			error = OFP_EOPNOTSUPP;
			break;

		case OFP_SO_SNDBUF:
		case OFP_SO_RCVBUF:
		case OFP_SO_SNDLOWAT:
		case OFP_SO_RCVLOWAT:
			error = ofp_sooptcopyin(sopt, &optval, sizeof optval,
					    sizeof optval);
			if (error)
				goto bad;

			/*
			 * Values < 1 make no sense for any of these options,
			 * so disallow them.
			 */
			if (optval < 1) {
				error = OFP_EINVAL;
				goto bad;
			}

			switch (sopt->sopt_name) {
			case OFP_SO_SNDBUF:
			case OFP_SO_RCVBUF:
				if (ofp_sbreserve(sopt->sopt_name == OFP_SO_SNDBUF ?
				    &so->so_snd : &so->so_rcv, (uint64_t)optval,
				    so, NULL) == 0) {
					error = OFP_ENOBUFS;
					goto bad;
				}
				(sopt->sopt_name == OFP_SO_SNDBUF ? &so->so_snd :
				    &so->so_rcv)->sb_flags &= ~SB_AUTOSIZE;
				break;

			/*
			 * Make sure the low-water is never greater than the
			 * high-water.
			 */
			case OFP_SO_SNDLOWAT:
				SOCKBUF_LOCK(&so->so_snd);
				so->so_snd.sb_lowat =
					(optval > (int)so->so_snd.sb_hiwat) ?
					(int)so->so_snd.sb_hiwat : optval;
				SOCKBUF_UNLOCK(&so->so_snd);
				break;
			case OFP_SO_RCVLOWAT:
				SOCKBUF_LOCK(&so->so_rcv);
				so->so_rcv.sb_lowat =
					(optval > (int)so->so_rcv.sb_hiwat) ?
					(int)so->so_rcv.sb_hiwat : optval;
				SOCKBUF_UNLOCK(&so->so_rcv);
				break;
			}
			break;

		case OFP_SO_SNDTIMEO:
		case OFP_SO_RCVTIMEO:
			error = ofp_sooptcopyin(sopt, &tv, sizeof tv,
					    sizeof tv);
			if (error)
				goto bad;

			/* assert(hz > 0); */
			if (tv.tv_sec > (int32_t)(INT_MAX / hz) ||
			    tv.tv_usec >= 1000000) {
				error = OFP_EDOM;
				goto bad;
			}
			/* assert(tick > 0); */
			/* assert(ULONG_MAX - INT_MAX >= 1000000); */
#define tick (1000000/HZ)
			val = (uint64_t)(tv.tv_sec * hz) + tv.tv_usec / tick;
			if (val > INT_MAX) {
				error = OFP_EDOM;
				goto bad;
			}
			if (val == 0 && tv.tv_usec != 0)
				val = 1;

			switch (sopt->sopt_name) {
			case OFP_SO_SNDTIMEO:
				so->so_snd.sb_timeo = val;
				break;
			case OFP_SO_RCVTIMEO:
				so->so_rcv.sb_timeo = val;
				break;
			}
			break;

		case OFP_SO_LABEL:
			error = OFP_EOPNOTSUPP;
			break;

		default:
			error = OFP_ENOPROTOOPT;
			break;
		}
		if (error == 0 && so->so_proto->pr_ctloutput != NULL)
			(void)(*so->so_proto->pr_ctloutput)(so, sopt);
	}
bad:
	return (error);
}

int
ofp_sooptcopyout(struct sockopt *sopt, const void *buf, size_t len)
{
	int	error;
	size_t	valsize;

	error = 0;

	/*
	 * Documented get behavior is that we always return a value, possibly
	 * truncated to fit in the user's buffer.  Traditional behavior is
	 * that we always tell the user precisely how much we copied, rather
	 * than something useful like the total amount we had available for
	 * her.  Note that this interface is not idempotent; the entire
	 * answer must generated ahead of time.
	 */
	valsize = min(len, sopt->sopt_valsize);
	sopt->sopt_valsize = valsize;
	if (sopt->sopt_val != NULL) {
		bcopy(buf, sopt->sopt_val, valsize);
	}
	return (error);
}

int
ofp_sogetopt(struct socket *so, struct sockopt *sopt)
{
	int	error, optval;
	struct	ofp_linger l;
	struct	timeval tv;

	error = 0;
	if (sopt->sopt_level != OFP_SOL_SOCKET) {
		if (so->so_proto->pr_ctloutput != NULL)
			error = (*so->so_proto->pr_ctloutput)(so, sopt);
		else
			error = OFP_ENOPROTOOPT;
		return (error);
	} else {
		switch (sopt->sopt_name) {
		case OFP_SO_ACCEPTFILTER:
			error = OFP_EOPNOTSUPP;
			break;
		case OFP_SO_LINGER:
			OFP_SOCK_LOCK(so);
			l.l_onoff = so->so_options & OFP_SO_LINGER;
			l.l_linger = so->so_linger;
			OFP_SOCK_UNLOCK(so);
			error = ofp_sooptcopyout(sopt, &l, sizeof l);
			break;

		case OFP_SO_USELOOPBACK:
		case OFP_SO_DONTROUTE:
		case OFP_SO_DEBUG:
		case OFP_SO_KEEPALIVE:
		case OFP_SO_REUSEADDR:
		case OFP_SO_REUSEPORT:
		case OFP_SO_BROADCAST:
		case OFP_SO_OOBINLINE:
		case OFP_SO_ACCEPTCONN:
		case OFP_SO_TIMESTAMP:
		case OFP_SO_BINTIME:
		case OFP_SO_NOSIGPIPE:
			optval = so->so_options & sopt->sopt_name;
integer:
			error = ofp_sooptcopyout(sopt, &optval, sizeof optval);
			break;

		case OFP_SO_TYPE:
			optval = so->so_type;
			goto integer;

		case OFP_SO_PROTOCOL:
			optval = so->so_proto->pr_protocol;
			goto integer;

		case OFP_SO_ERROR:
			OFP_SOCK_LOCK(so);
			optval = so->so_error;
			so->so_error = 0;
			OFP_SOCK_UNLOCK(so);
			goto integer;

		case OFP_SO_L2INFO:
			error = OFP_EOPNOTSUPP;
			break;

		case OFP_SO_SNDBUF:
			optval = so->so_snd.sb_hiwat;
			goto integer;

		case OFP_SO_RCVBUF:
			optval = so->so_rcv.sb_hiwat;
			goto integer;

		case OFP_SO_SNDLOWAT:
			optval = so->so_snd.sb_lowat;
			goto integer;

		case OFP_SO_RCVLOWAT:
			optval = so->so_rcv.sb_lowat;
			goto integer;

		case OFP_SO_SNDTIMEO:
		case OFP_SO_RCVTIMEO:
			optval = (sopt->sopt_name == OFP_SO_SNDTIMEO ?
				  so->so_snd.sb_timeo : so->so_rcv.sb_timeo);

			tv.tv_sec = optval / hz;
			tv.tv_usec = (optval % hz) * tick;
			error = ofp_sooptcopyout(sopt, &tv, sizeof tv);
			break;

		case OFP_SO_LABEL:
			error = OFP_EOPNOTSUPP;
			break;

		case OFP_SO_PEERLABEL:
			error = OFP_EOPNOTSUPP;
			break;

		case OFP_SO_LISTENQLIMIT:
			optval = so->so_qlimit;
			goto integer;

		case OFP_SO_LISTENQLEN:
			optval = so->so_qlen;
			goto integer;

		case OFP_SO_LISTENINCQLEN:
			optval = so->so_incqlen;
			goto integer;

		default:
			error = OFP_ENOPROTOOPT;
			break;
		}
	}

	return (error);
}

/*
 * These functions are used by protocols to notify the socket layer (and its
 * consumers) of state changes in the sockets driven by protocol-side events.
 */

/*
 * Procedures to manipulate state flags of socket and do appropriate wakeups.
 *
 * Normal sequence from the active (originating) side is that
 * ofp_soisconnecting() is called during processing of connect() call, resulting
 * in an eventual call to ofp_soisconnected() if/when the connection is
 * established.  When the connection is torn down ofp_soisdisconnecting() is
 * called during processing of disconnect() call, and ofp_soisdisconnected() is
 * called when the connection to the peer is totally severed.  The semantics
 * of these routines are such that connectionless protocols can call
 * ofp_soisconnected() and ofp_soisdisconnected() only, bypassing the in-progress
 * calls when setting up a ``connection'' takes no time.
 *
 * From the passive side, a socket is created with two queues of sockets:
 * so_incomp for connections in progress and so_comp for connections already
 * made and awaiting user acceptance.  As a protocol is preparing incoming
 * connections, it creates a socket structure queued on so_incomp by calling
 * ofp_sonewconn().  When the connection is established, ofp_soisconnected() is
 * called, and transfers the socket structure to so_comp, making it available
 * to accept().
 *
 * If a socket is closed with sockets on either so_incomp or so_comp, these
 * sockets are dropped.
 *
 * If higher-level protocols are implemented in the kernel, the wakeups done
 * here will sometimes cause software-interrupt process scheduling.
 */
void
ofp_soisconnecting(struct socket *so)
{

	OFP_SOCK_LOCK(so);
	so->so_state &= ~(SS_ISCONNECTED|SS_ISDISCONNECTING);
	so->so_state |= SS_ISCONNECTING;
	OFP_SOCK_UNLOCK(so);
}

void
ofp_soisconnected(struct socket *so)
{
	struct socket *head;

	ACCEPT_LOCK();
	OFP_SOCK_LOCK(so);
	so->so_state &= ~(SS_ISCONNECTING|SS_ISDISCONNECTING|SS_ISCONFIRMING);
	so->so_state |= SS_ISCONNECTED;
	head = so->so_head;
	if (head != NULL && (so->so_qstate & SQ_INCOMP)) {
		if ((so->so_options & OFP_SO_ACCEPTFILTER) == 0) {
			OFP_SOCK_UNLOCK(so);
			OFP_TAILQ_REMOVE(&head->so_incomp, so, so_list);
			head->so_incqlen--;
			so->so_qstate &= ~SQ_INCOMP;
			OFP_TAILQ_INSERT_TAIL(&head->so_comp, so, so_list);
			head->so_qlen++;
			so->so_qstate |= SQ_COMP;
			ACCEPT_UNLOCK();
			ofp_send_sock_event(head, so, OFP_EVENT_ACCEPT);
			sorwakeup(head);
			ofp_wakeup_one(&head->so_timeo);
		} else {
			ACCEPT_UNLOCK();
			ofp_soupcall_set(so, OFP_SO_RCV,
			    head->so_accf->so_accept_filter->accf_callback,
			    head->so_accf->so_accept_filter_arg);
			so->so_options &= ~OFP_SO_ACCEPTFILTER;
			/* HJo: FIX
			ret = head->so_accf->so_accept_filter->accf_callback(so,
			    head->so_accf->so_accept_filter_arg, M_DONTWAIT);
			if (ret == SU_ISCONNECTED)
				ofp_soupcall_clear(so, OFP_SO_RCV);
			*/
			OFP_SOCK_UNLOCK(so);
			/* HJo
			if (ret == SU_ISCONNECTED)
				goto restart;
			*/
		}
		return;
	}
	OFP_SOCK_UNLOCK(so);
	ACCEPT_UNLOCK();
	ofp_wakeup(&so->so_timeo);
	sorwakeup(so);
	sowwakeup(so);
}

void
ofp_soisdisconnecting(struct socket *so)
{

	/*
	 * Note: This code assumes that OFP_SOCK_LOCK(so) and
	 * SOCKBUF_LOCK(&so->so_rcv) are the same.
	 */
	/* Socket handled by event and already locked? */
	if (!(so->so_state & SS_EVENT))
		SOCKBUF_LOCK(&so->so_rcv);
	so->so_state &= ~SS_ISCONNECTING;
	so->so_state |= SS_ISDISCONNECTING;
	so->so_rcv.sb_state |= SBS_CANTRCVMORE;
	sorwakeup_locked(so);
	SOCKBUF_LOCK(&so->so_snd);
	so->so_snd.sb_state |= SBS_CANTSENDMORE;
	sowwakeup_locked(so);
	ofp_wakeup(&so->so_timeo);
}

void
ofp_soisdisconnected(struct socket *so)
{

	/*
	 * Note: This code assumes that OFP_SOCK_LOCK(so) and
	 * SOCKBUF_LOCK(&so->so_rcv) are the same.
	 */
	SOCKBUF_LOCK(&so->so_rcv);
	so->so_state &= ~(SS_ISCONNECTING|SS_ISCONNECTED|SS_ISDISCONNECTING);
	so->so_state |= SS_ISDISCONNECTED;
	so->so_rcv.sb_state |= SBS_CANTRCVMORE;
	sorwakeup_locked(so);
	SOCKBUF_LOCK(&so->so_snd);
	so->so_snd.sb_state |= SBS_CANTSENDMORE;
	ofp_sbdrop_locked(&so->so_snd, so->so_snd.sb_cc);
	sowwakeup_locked(so);
	ofp_wakeup(&so->so_timeo);
}

/*
 * Register per-socket buffer upcalls.
 */
void
ofp_soupcall_set(struct socket *so, int which,
    int (*func)(struct socket *, void *, int), void *arg)
{
	struct sockbuf *sb = NULL;

	switch (which) {
	case OFP_SO_RCV:
		sb = &so->so_rcv;
		break;
	case OFP_SO_SND:
		sb = &so->so_snd;
		break;
	default:
		panic("ofp_soupcall_set: bad which");
	}
	SOCKBUF_LOCK_ASSERT(sb);
#if 0
	/* XXX: accf_http actually wants to do this on purpose. */
	KASSERT(sb->sb_upcall == NULL, ("ofp_soupcall_set: overwriting upcall"));
#endif
	sb->sb_upcall = func;
	sb->sb_upcallarg = arg;
	sb->sb_flags |= SB_UPCALL;
}

void
ofp_soupcall_clear(struct socket *so, int which)
{
	struct sockbuf *sb = NULL;

	switch (which) {
	case OFP_SO_RCV:
		sb = &so->so_rcv;
		break;
	case OFP_SO_SND:
		sb = &so->so_snd;
		break;
	default:
		panic("ofp_soupcall_clear: bad which");
	}
	SOCKBUF_LOCK_ASSERT(sb);
	KASSERT(sb->sb_upcall != NULL, ("ofp_soupcall_clear: no upcall to clear"));
	sb->sb_upcall = NULL;
	sb->sb_upcallarg = NULL;
	sb->sb_flags &= ~SB_UPCALL;
}

/*
 * ofp_sohasoutofband(): protocol notifies socket layer of the arrival of new
 * out-of-band data, which will then notify socket consumers.
 */
void
ofp_sohasoutofband(struct socket *so)
{
	(void)so;
	/* HJo: No sig
	if (so->so_sigio != NULL)
		pgsigio(&so->so_sigio, SIGURG, 0);
	*/
	/* HJo: FIX
	selwakeuppri(&so->so_rcv.sb_sel, PSOCK);
	*/
	ofp_wakeup(&so->so_rcv.sb_sel);
}

/* Emulation for BSD ofp_wakeup */

static int _ofp_wakeup(void *channel, int one, int tmo);

struct voidarg {
	void *p;
};

static void
sleep_timeout(void *arg)
{
	struct voidarg *arg1 = arg;
	_ofp_wakeup(arg1->p, 1, 1);
}

int
ofp_msleep(void *channel, odp_rwlock_t *mtx, int priority, const char *wmesg,
	     uint32_t timeout)
{
	struct sleeper *sleepy;
	struct voidarg arg;
	int ret;
	(void)mtx;
	(void)priority;

	odp_spinlock_lock(&shm->sleep_lock);
	if (!shm->free_sleepers) {
		odp_spinlock_unlock(&shm->sleep_lock);
		OFP_ERR("Out of sleepers");
		return OFP_ENOMEM;
	}
	sleepy = shm->free_sleepers;
	shm->free_sleepers = sleepy->next;

	sleepy->next = shm->sleep_list;
	sleepy->channel = channel;
	sleepy->wmesg = wmesg;
	sleepy->go = 0;
	sleepy->woke_by_timer = 0;
	sleepy->tmo = ODP_TIMER_INVALID;
	shm->sleep_list = sleepy;
	if (timeout) {
		arg.p = channel;
		sleepy->tmo = ofp_timer_start(timeout, sleep_timeout, &arg, sizeof(arg));
	}
	odp_spinlock_unlock(&shm->sleep_lock);

	while (sleepy->go == 0) {
		if (mtx) {
			odp_rwlock_write_unlock(mtx);
		}
		sched_yield();
		if (mtx) {
			odp_rwlock_write_lock(mtx);
		}
	}

	odp_spinlock_lock(&shm->sleep_lock);

	if (sleepy->tmo != ODP_TIMER_INVALID)
		ofp_timer_cancel(sleepy->tmo);

	ret = sleepy->woke_by_timer ? OFP_EWOULDBLOCK : 0;

	sleepy->next = shm->free_sleepers;
	shm->free_sleepers = sleepy;

	odp_spinlock_unlock(&shm->sleep_lock);

	return ret;
}

static int
_ofp_wakeup(void *channel, int one, int tmo)
{
	struct sleeper *p, *prev = NULL, *next;

	odp_spinlock_lock(&shm->sleep_lock);

	p = shm->sleep_list;
	while (p) {
		next = p->next;
		if (channel == p->channel) {
			if (prev)
				prev->next = p->next;
			else
				shm->sleep_list = p->next;
			if (tmo) {
				p->tmo = ODP_TIMER_INVALID;
				p->woke_by_timer = 1;
			}
			p->go = 1;
			if (one)
				break;
		} else
			prev = p;
		p = next;
	}

	odp_spinlock_unlock(&shm->sleep_lock);
	return -1;
}

int
ofp_wakeup_one(void *channel)
{
	/* wake up selects */
	if (channel)
		_ofp_wakeup(NULL, 0, 0);
	return _ofp_wakeup(channel, 1, 0);
}

int
ofp_wakeup(void *channel)
{
	/* wake up selects */
	if (channel)
		_ofp_wakeup(NULL, 0, 0);
	return _ofp_wakeup(channel, 0, 0);
}


int
ofp_pru_accept_notsupp(struct socket *so, struct ofp_sockaddr **nam)
{
	(void)so;
	(void)nam;
	return OFP_EOPNOTSUPP;
}

int
ofp_pru_attach_notsupp(struct socket *so, int proto, struct thread *td)
{
	(void)so;
	(void)proto;
	(void)td;
	return OFP_EOPNOTSUPP;
}

int
ofp_pru_bind_notsupp(struct socket *so, struct ofp_sockaddr *nam, struct thread *td)
{
	(void)so;
	(void)nam;
	(void)td;
	return OFP_EOPNOTSUPP;
}

int
ofp_pru_connect_notsupp(struct socket *so, struct ofp_sockaddr *nam, struct thread *td)
{
	(void)so;
	(void)nam;
	(void)td;
	return OFP_EOPNOTSUPP;
}

int
ofp_pru_connect2_notsupp(struct socket *so1, struct socket *so2)
{
	(void)so1;
	(void)so2;
	return OFP_EOPNOTSUPP;
}

int
ofp_pru_control_notsupp(struct socket *so, uint32_t cmd, char * data,
    struct ofp_ifnet *ifp, struct thread *td)
{
	(void)so;
	(void)cmd;
	(void)data;
	(void)ifp;
	(void)td;
	return OFP_EOPNOTSUPP;
}

int
ofp_pru_disconnect_notsupp(struct socket *so)
{
	(void)so;
	return OFP_EOPNOTSUPP;
}

int
ofp_pru_listen_notsupp(struct socket *so, int backlog, struct thread *td)
{
	(void)so;
	(void)backlog;
	(void)td;
	return OFP_EOPNOTSUPP;
}

int
ofp_pru_peeraddr_notsupp(struct socket *so, struct ofp_sockaddr **nam)
{
	(void)so;
	(void)nam;
	return OFP_EOPNOTSUPP;
}

int
ofp_pru_rcvd_notsupp(struct socket *so, int flags)
{
	(void)so;
	(void)flags;
	return OFP_EOPNOTSUPP;
}

int
ofp_pru_rcvoob_notsupp(struct socket *so, odp_packet_t m, int flags)
{
	(void)so;
	(void)m;
	(void)flags;
	return OFP_EOPNOTSUPP;
}

int
ofp_pru_send_notsupp(struct socket *so, int flags, odp_packet_t m,
    struct ofp_sockaddr *addr, odp_packet_t control, struct thread *td)
{
	(void)so;
	(void)m;
	(void)flags;
	(void)addr;
	(void)control;
	(void)td;
	return OFP_EOPNOTSUPP;
}

/*
 * This isn't really a ``null'' operation, but it's the default one and
 * doesn't do anything destructive.
 */
int
ofp_pru_sense_null(struct socket *so, struct stat *sb)
{

	/*sb->st_blksize = so->so_snd.sb_hiwat;*/
	(void)so;
	(void)sb;
	return 0;
}

int
ofp_pru_shutdown_notsupp(struct socket *so)
{
	(void)so;
	return OFP_EOPNOTSUPP;
}

int
ofp_pru_sockaddr_notsupp(struct socket *so, struct ofp_sockaddr **nam)
{
	(void)so;
	(void)nam;
	return OFP_EOPNOTSUPP;
}

int
ofp_pru_sosend_notsupp(struct socket *so, struct ofp_sockaddr *addr,
	struct uio *uio, odp_packet_t top, odp_packet_t control, int flags,
	struct thread *td)
{
	(void)so;
	(void)addr;
	(void)uio;
	(void)top;
	(void)control;
	(void)flags;
	(void)td;
	return OFP_EOPNOTSUPP;
}

int
ofp_pru_soreceive_notsupp(struct socket *so, struct ofp_sockaddr **paddr,
    struct uio *uio, odp_packet_t *mp0, odp_packet_t *controlp, int *flagsp)
{
	(void)so;
	(void)paddr;
	(void)uio;
	(void)mp0;
	(void)controlp;
	(void)flagsp;
	return OFP_EOPNOTSUPP;
}

int
ofp_pru_sopoll_notsupp(struct socket *so, int events, struct ofp_ucred *cred,
    struct thread *td)
{
	(void)so;
	(void)events;
	(void)cred;
	(void)td;
	return OFP_EOPNOTSUPP;
}

int
ofp_send_sock_event(struct socket *head, struct socket *so, int event)
{
	struct ofp_sigevent *ev = &head->so_sigevent;

	if (ev->ofp_sigev_notify) {
		struct ofp_sock_sigval *ss = ev->ofp_sigev_value.sival_ptr;
		ss->event = event;
		ss->sockfd = head->so_number;
		ss->sockfd2 = so->so_number;
		so->so_state |= SS_EVENT;
		head->so_state |= SS_EVENT;
		ev->ofp_sigev_notify_function(ev->ofp_sigev_value);
		so->so_state &= ~SS_EVENT;
		head->so_state &= ~SS_EVENT;
	}
	return 0;
}
