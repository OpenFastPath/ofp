/*-
 * Copyright (c) 1982, 1986, 1988, 1990, 1993
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
 *	@(#)uipc_socket2.c	8.1 (Berkeley) 6/10/93
 */

#include <string.h>

#include "ofpi_errno.h"
#include "ofpi_systm.h"
#include "ofpi_socketvar.h"
#include "ofpi_sockstate.h"
#include "ofpi_in_pcb.h"
#include "ofpi_in.h"
#include "ofpi_log.h"


/*
 * Primitive routines for operating on socket buffers
 */

/*
 * Constants related to network buffer management.
 * MCLBYTES must be no larger than PAGE_SIZE.
 */
#if 1
#ifndef	MSIZE
#define MSIZE		256		/* size of an mbuf */
#endif	/* MSIZE */

#ifndef	MCLSHIFT
#define MCLSHIFT	11		/* convert bytes to mbuf clusters */
#endif	/* MCLSHIFT */

//#define MCLBYTES	(1 << MCLSHIFT)	/* size of an mbuf cluster */
#endif

uint64_t ofp_sb_max = SB_MAX;

static uint64_t sb_efficiency = 8;	/* parameter for ofp_sbreserve() */

int packet_accepted_as_event(struct socket *so, odp_packet_t pkt)
{
	struct ofp_sigevent *ev;

	if (!so)
		return 0;

	ev = &so->so_sigevent;

	if (ev->ofp_sigev_notify) {
		union ofp_sigval sv;
		struct ofp_sock_sigval ss;

		sv.sival_ptr = (void *)&ss;

		ss.pkt = pkt;
		ss.event = OFP_EVENT_RECV;
		ss.sockfd = so->so_number;

		so->so_state |= SS_EVENT;
		ev->ofp_sigev_notify_function(sv);
		so->so_state &= ~SS_EVENT;

		if (ss.pkt == ODP_PACKET_INVALID)
			return 1; /* Callback function accepted the packet. */
	}
	return 0;
}

static int packet_accepted_as_event_locked(struct sockbuf *sb, odp_packet_t pkt)
{
	struct socket *so = sb->sb_socket;

	return packet_accepted_as_event(so, pkt);
}

int ofp_sockbuf_put_last(struct sockbuf *sb, odp_packet_t pkt)
{
	/* Offer to event function */
	if (packet_accepted_as_event_locked(sb, pkt))
		return 0;

	int next = sb->sb_put + 1;
	if (next >= SOCKBUF_LEN)
		next = 0;

	if (next == sb->sb_get) {
		ofp_sockbuf_packet_free(pkt);
		OFP_ERR("No more room, next=%d", next);
		return -1;
	}

	sb->sb_mb[sb->sb_put] = pkt;
	sb->sb_put = next;
	sballoc(sb, pkt);
	return 0;
}

odp_packet_t ofp_sockbuf_get_first(struct sockbuf *sb)
{
	if (sb->sb_get == sb->sb_put)
		return ODP_PACKET_INVALID;

	return sb->sb_mb[sb->sb_get];
}

odp_packet_t ofp_sockbuf_remove_first(struct sockbuf *sb)
{
	odp_packet_t pkt = ODP_PACKET_INVALID;

	if (sb->sb_get != sb->sb_put) {
		pkt = sb->sb_mb[sb->sb_get];
		if (++sb->sb_get >= SOCKBUF_LEN)
			sb->sb_get = 0;
	}
	return pkt;
}

void ofp_sockbuf_packet_free(odp_packet_t pkt)
{
	odp_packet_free(pkt);
}

void ofp_sockbuf_copy_out(struct sockbuf *sb, int off, int len, char *dst)
{
	int i = sb->sb_get, dstoff = 0;

	while (i != sb->sb_put) {
		int plen = odp_packet_len(sb->sb_mb[i]);
		if (off >= plen) {
			off -= plen;
			if (++i >= SOCKBUF_LEN)
				i = 0;
		} else
			break;
	}

	while (len && i != sb->sb_put) {
		int plen = odp_packet_len(sb->sb_mb[i]) - off;
		if (plen > len)
			plen = len;
		odp_packet_copy_to_mem(sb->sb_mb[i], off, plen, dst + dstoff);
		off = 0;
		len -= plen;
		dstoff += plen;

		if (++i >= SOCKBUF_LEN)
			i = 0;
	}
}

/*
 * Append address and data, and optionally, control (ancillary) data to the
 * receive queue of a socket.  If present, m0 must include a packet header
 * with total length.  Returns 0 if no space in sockbuf or insufficient
 * mbufs.
 */
int
ofp_sbappendaddr_locked(struct sockbuf *sb,
		    odp_packet_t pkt, odp_packet_t control)
{
	int next = sb->sb_put + 1;

	SOCKBUF_LOCK_ASSERT(sb);

	if (control != ODP_PACKET_INVALID)
		odp_packet_free(control);

	if (next >= SOCKBUF_LEN)
		next = 0;

	if (next == sb->sb_get) {
		OFP_ERR("Buffers full, sb_get=%d max_num=%d",
			  sb->sb_get, SOCKBUF_LEN);
		return 0;
	}

	sb->sb_mb[sb->sb_put] = pkt;
	sballoc(sb, pkt);
	sb->sb_put = next;
	return (1);
}

/*
 * Free all mbufs in a sockbuf.  Check that all resources are reclaimed.
 */
static void
sbflush_internal(struct sockbuf *sb)
{
	while (sb->sb_get != sb->sb_put) {
		odp_packet_free(sb->sb_mb[sb->sb_get]);
		if (++sb->sb_get >= SOCKBUF_LEN)
			sb->sb_get = 0;
	}
}

void
ofp_sbflush_locked(struct sockbuf *sb)
{
	SOCKBUF_LOCK_ASSERT(sb);
	sbflush_internal(sb);
}

void
ofp_sbflush(struct sockbuf *sb)
{
	SOCKBUF_LOCK(sb);
	ofp_sbflush_locked(sb);
	SOCKBUF_UNLOCK(sb);
}

/*
 * This version of sbappend() should only be used when the caller absolutely
 * knows that there will never be more than one record in the socket buffer,
 * that is, a stream protocol (such as TCP).
 */
void
ofp_sbappendstream_locked(struct sockbuf *sb, odp_packet_t m)
{
	SOCKBUF_LOCK_ASSERT(sb);

	SBLASTMBUFCHK(sb);

	sb->sb_lastrecord = sb->sb_put;
	ofp_sbcompress(sb, m, sb->sb_mbtail);

	SBLASTRECORDCHK(sb);
}

/*
 * This version of sbappend() should only be used when the caller absolutely
 * knows that there will never be more than one record in the socket buffer,
 * that is, a stream protocol (such as TCP).
 */
void
ofp_sbappendstream(struct sockbuf *sb, odp_packet_t m)
{
	SOCKBUF_LOCK(sb);
	ofp_sbappendstream_locked(sb, m);
	SOCKBUF_UNLOCK(sb);
 }

/*
 * Append the data in mbuf chain (m) into the socket buffer sb following mbuf
 * (n).  If (n) is NULL, the buffer is presumed empty.
 *
 * When the data is compressed, mbufs in the chain may be handled in one of
 * three ways:
 *
 * (1) The mbuf may simply be dropped, if it contributes nothing (no data, no
 *     record boundary, and no change in data type).
 *
 * (2) The mbuf may be coalesced -- i.e., data in the mbuf may be copied into
 *     an mbuf already in the socket buffer.  This can occur if an
 *     appropriate mbuf exists, there is room, and no merging of data types
 *     will occur.
 *
 * (3) The mbuf may be appended to the end of the existing mbuf chain.
 *
 * If any of the new mbufs is marked as M_EOR, mark the last mbuf appended as
 * end-of-record.
 */
void
ofp_sbcompress(struct sockbuf *sb, odp_packet_t pkt, int n)
{
	(void)n;
	SOCKBUF_LOCK_ASSERT(sb);
	ofp_sockbuf_put_last(sb, pkt);
}

/*
 * Drop data from (the front of) a sockbuf.
 */
static void
sbdrop_internal(struct sockbuf *sb, int len)
{
	odp_packet_t pkt;

	while (len > 0) {
		pkt = ofp_sockbuf_get_first(sb);
		if (pkt == ODP_PACKET_INVALID)
			return;

		int buflen = odp_packet_len(pkt);
		if (buflen > len) {
			odp_packet_pull_head(pkt, len);
			sb->sb_cc -= len;
			if (sb->sb_sndptroff != 0)
				sb->sb_sndptroff -= len;
			break;
		}
		len -= buflen;
		pkt = ofp_sockbuf_remove_first(sb);
		sbfree(sb, pkt);
		ofp_sockbuf_packet_free(pkt);
	}
}

/*
 * Drop data from (the front of) a sockbuf.
 */
void
ofp_sbdrop_locked(struct sockbuf *sb, int len)
{
	SOCKBUF_LOCK_ASSERT(sb);

	sbdrop_internal(sb, len);
}

void
ofp_sbdrop(struct sockbuf *sb, int len)
{
	SOCKBUF_LOCK(sb);
	ofp_sbdrop_locked(sb, len);
	SOCKBUF_UNLOCK(sb);
}

/*
 * Drop a record off the front of a sockbuf and move the next record to the
 * front.
 */
void
ofp_sbdroprecord_locked(struct sockbuf *sb)
{
	odp_packet_t pkt;

	SOCKBUF_LOCK_ASSERT(sb);

	pkt = ofp_sockbuf_remove_first(sb);
	if (pkt != ODP_PACKET_INVALID) {
		sbfree(sb, pkt);
		odp_packet_free(pkt);
	}
}

void
ofp_socantsendmore_locked(struct socket *so)
{
	SOCKBUF_LOCK_ASSERT(&so->so_snd);

	so->so_snd.sb_state |= SBS_CANTSENDMORE;
	sowwakeup_locked(so);
}

void
ofp_socantsendmore(struct socket *so)
{
	SOCKBUF_LOCK(&so->so_snd);
	ofp_socantsendmore_locked(so);
}

void
ofp_socantrcvmore_locked(struct socket *so)
{
	SOCKBUF_LOCK_ASSERT(&so->so_rcv);

	so->so_rcv.sb_state |= SBS_CANTRCVMORE;
	sorwakeup_locked(so);
}

void
ofp_socantrcvmore(struct socket *so)
{
	SOCKBUF_LOCK(&so->so_rcv);
	ofp_socantrcvmore_locked(so);
}

/*
 * Wait for data to arrive at/drain from a socket buffer.
 */

extern unsigned int sleep(unsigned int seconds);
int
ofp_sbwait(struct sockbuf *sb)
{
	SOCKBUF_LOCK_ASSERT(sb);

	sb->sb_flags |= SB_WAIT;
	return (ofp_msleep(&sb->sb_cc, &sb->sb_mtx,
			     0 /*HJo (sb->sb_flags & SB_NOINTR) ? PSOCK : PSOCK | PCATCH*/,
			     "sbwait",
			     1000000UL/HZ*sb->sb_timeo));
}

int
ofp_sblock(struct sockbuf *sb, int flags)
{
	KASSERT((flags & SBL_VALID) == flags,
	    ("ofp_sblock: flags invalid (0x%x)", flags));

	if (flags & SBL_WAIT) {
		if ((sb->sb_flags & SB_NOINTR) ||
		    (flags & SBL_NOINTR)) {
			odp_spinlock_lock(&sb->sb_sx);
			return (0);
		}
		//OFP_ERR("lock: dont know what to do");
		//odp_spinlock_lock(&sb->sb_sx);
		return 0;
		/* HJo: What is this?  (sx_xlock_sig(&sb->sb_sx));*/
	} else {
		if (!odp_spinlock_trylock(&sb->sb_sx))
			return (OFP_EWOULDBLOCK);
		return (0);
	}
}

void
ofp_sbunlock(struct sockbuf *sb)
{
	odp_spinlock_unlock(&sb->sb_sx);
}

void
ofp_sowakeup(struct socket *so, struct sockbuf *sb)
{
	(void)so;

	SOCKBUF_LOCK_ASSERT(sb);

	/*HJo selwakeuppri(&sb->sb_sel, PSOCK);*/
	ofp_wakeup(NULL);
#if 0
	if (!SEL_WAITING(&sb->sb_sel))
		sb->sb_flags &= ~SB_SEL;
#endif

	if (sb->sb_flags & SB_WAIT) {
		ofp_wakeup(&sb->sb_cc);
	}
#if 0
	KNOTE_LOCKED(&sb->sb_sel.si_note, 0);
	if (sb->sb_upcall != NULL) {
		ret = sb->sb_upcall(so, sb->sb_upcallarg, M_DONTWAIT);
		if (ret == SU_ISCONNECTED) {
			KASSERT(sb == &so->so_rcv,
			    ("OFP_SO_SND upcall returned SU_ISCONNECTED"));
			ofp_soupcall_clear(so, OFP_SO_RCV);
		}
	} else
		ret = SU_OK;
	if (sb->sb_flags & SB_AIO)
		aio_swake(so, sb);
#endif

	SOCKBUF_UNLOCK(sb);
#if 0
	if (ret == SU_ISCONNECTED)
		ofp_soisconnected(so);
	if ((so->so_state & SS_ASYNC) && so->so_sigio != NULL)
		pgsigio(&so->so_sigio, SIGIO, 0);
	mtx_assert(SOCKBUF_MTX(sb), MA_NOTOWNED);
#endif
}

/*
 * Allot mbufs to a sockbuf.  Attempt to scale mbmax so that mbcnt doesn't
 * become limiting if buffering efficiency is near the normal case.
 */
int
ofp_sbreserve_locked(struct sockbuf *sb, uint64_t cc, struct socket *so,
		 struct thread *td)
{
	(void)so;
	(void)td;
	SOCKBUF_LOCK_ASSERT(sb);
	long mclbytes = global_param->pkt_pool.buffer_size;
	/*
	 * When a thread is passed, we take into account the thread's socket
	 * buffer size limit.  The caller will generally pass curthread, but
	 * in the TCP input path, NULL will be passed to indicate that no
	 * appropriate thread resource limits are available.  In that case,
	 * we don't apply a process limit.
	 */

	uint64_t ofp_sb_max_adj =
		(int64_t)SB_MAX * global_param->pkt_pool.buffer_size / (MSIZE + mclbytes); /* adjusted ofp_sb_max */
	if (cc > ofp_sb_max_adj)
		return (0);
	sb->sb_hiwat = cc;
	sb->sb_mbmax = min(cc * sb_efficiency, ofp_sb_max);
	if (sb->sb_lowat > (int)sb->sb_hiwat)
		sb->sb_lowat = sb->sb_hiwat;
	return (1);
}

int
ofp_sbreserve(struct sockbuf *sb, uint64_t cc, struct socket *so,
    struct thread *td)
{
	int error;

	SOCKBUF_LOCK(sb);
	error = ofp_sbreserve_locked(sb, cc, so, td);
	SOCKBUF_UNLOCK(sb);
	return (error);
}

/*
 * Socket buffer (struct sockbuf) utility routines.
 *
 * Each socket contains two socket buffers: one for sending data and one for
 * receiving data.  Each buffer contains a queue of mbufs, information about
 * the number of mbufs and amount of data in the queue, and other fields
 * allowing select() statements and notification on data availability to be
 * implemented.
 *
 * Data stored in a socket buffer is maintained as a list of records.  Each
 * record is a list of mbufs chained together with the m_next field.  Records
 * are chained together with the m_nextpkt field. The upper level routine
 * ofp_soreceive() expects the following conventions to be observed when placing
 * information in the receive buffer:
 *
 * 1. If the protocol requires each message be preceded by the sender's name,
 *    then a record containing that name must be present before any
 *    associated data (mbuf's must be of type MT_SONAME).
 * 2. If the protocol supports the exchange of ``access rights'' (really just
 *    additional data associated with the message), and there are ``rights''
 *    to be received, then a record containing this data should be present
 *    (mbuf's must be of type MT_RIGHTS).
 * 3. If a name or rights record exists, then it must be followed by a data
 *    record, perhaps of zero length.
 *
 * Before using a new socket structure it is first necessary to reserve
 * buffer space to the socket, by calling ofp_sbreserve().  This should commit
 * some of the available buffer space in the system buffer pool for the
 * socket (currently, it does nothing but enforce limits).  The space should
 * be released by calling ofp_sbrelease() when the socket is destroyed.
 */
int
ofp_soreserve(struct socket *so, uint64_t sndcc, uint64_t rcvcc)
{
	struct thread *td = NULL /* HJo curthread*/;

	SOCKBUF_LOCK(&so->so_snd);
	SOCKBUF_LOCK(&so->so_rcv);
	if (ofp_sbreserve_locked(&so->so_snd, sndcc, so, td) == 0)
		goto bad;
	if (ofp_sbreserve_locked(&so->so_rcv, rcvcc, so, td) == 0)
		goto bad2;
	if (so->so_rcv.sb_lowat == 0)
		so->so_rcv.sb_lowat = 1;
	if (so->so_snd.sb_lowat == 0)
		so->so_snd.sb_lowat = global_param->pkt_pool.buffer_size;
	if (so->so_snd.sb_lowat > (int)so->so_snd.sb_hiwat)
		so->so_snd.sb_lowat = so->so_snd.sb_hiwat;
	SOCKBUF_UNLOCK(&so->so_rcv);
	SOCKBUF_UNLOCK(&so->so_snd);
	return (0);
bad2:
	ofp_sbrelease_locked(&so->so_snd, so);
bad:
	SOCKBUF_UNLOCK(&so->so_rcv);
	SOCKBUF_UNLOCK(&so->so_snd);
	return (OFP_ENOBUFS);
}

/*
 * Free mbufs held by a socket, and reserved mbuf space.
 */
void
ofp_sbrelease_internal(struct sockbuf *sb, struct socket *so)
{
	(void)so;

	sbflush_internal(sb);
#if 0 /* HJo */
	(void)chgsbsize(so->so_cred->cr_uidinfo, &sb->sb_hiwat, 0,
	    RLIM_INFINITY);
#else
	sb->sb_hiwat = 0;
#endif
	sb->sb_mbmax = 0;
}

void
ofp_sbrelease_locked(struct sockbuf *sb, struct socket *so)
{
	SOCKBUF_LOCK_ASSERT(sb);

	ofp_sbrelease_internal(sb, so);
}

void
ofp_sbrelease(struct sockbuf *sb, struct socket *so)
{
	SOCKBUF_LOCK(sb);
	ofp_sbrelease_locked(sb, so);
	SOCKBUF_UNLOCK(sb);
}

void
ofp_sbdestroy(struct sockbuf *sb, struct socket *so)
{
	ofp_sbrelease_internal(sb, so);
}
