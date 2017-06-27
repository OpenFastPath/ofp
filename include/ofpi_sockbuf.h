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
 * $FreeBSD: release/9.1.0/sys/sys/sockbuf.h 225169 2011-08-25 09:20:13Z bz $
 */
#ifndef _SYS_SOCKBUF_H_
#define _SYS_SOCKBUF_H_

#include "odp.h"
#include "ofpi_systm.h"
#include "ofpi_util.h"
#include "ofpi_config.h"

#define	SB_MAX		(2*1024*1024)	/* default for max chars in sockbuf */

/*
 * Constants for sb_flags field of struct sockbuf.
 */
#define	SB_WAIT		0x04		/* someone is waiting for data/space */
#define	SB_SEL		0x08		/* someone is selecting */
#define	SB_ASYNC	0x10		/* ASYNC I/O, need signals */
#define	SB_UPCALL	0x20		/* someone wants an upcall */
#define	SB_NOINTR	0x40		/* operations not interruptible */
#define	SB_AIO		0x80		/* AIO operations queued */
#define	SB_KNOTE	0x100		/* kernel note attached */
#define	SB_NOCOALESCE	0x200		/* don't coalesce new data into existing mbufs */
#define	SB_IN_TOE	0x400		/* socket buffer is in the middle of an operation */
#define	SB_AUTOSIZE	0x800		/* automatically size socket buffer */

struct ofp_sockaddr;
struct socket;
struct thread;

struct	xsockbuf {
	uint32_t	sb_cc;
	uint32_t	sb_hiwat;
	uint32_t	sb_mbcnt;
	uint32_t   sb_mcnt;
	uint32_t   sb_ccnt;
	uint32_t	sb_mbmax;
	int	sb_lowat;
	int	sb_timeo;
	short	sb_flags;
};

struct selinfo {
	OFP_LIST_ENTRY(selinfo)	si_list;
	void			*si_wakeup_channel;
	int			si_socket;
#if 0
	struct selfdlist	si_tdlist;	/* List of sleeping threads. */
	struct knlist		si_note;	/* kernel note list */
	struct mtx		*si_mtx;	/* Lock for tdlist. */
#endif
};

struct ofp_iovec {
	void   *iov_base;	/* Base address. */
	size_t	iov_len;	/* Length. */
};

struct uio {
	struct	ofp_iovec *uio_iov;		/* scatter/gather list */
	int	uio_iovcnt;		/* length of scatter/gather list */
	off_t	uio_offset;		/* offset in target object */
	ofp_ssize_t	uio_resid;		/* remaining bytes to process */
};

/*
 * Variables for socket buffering.
 */
struct	sockbuf {
	struct		selinfo sb_sel;	/* process selecting read/write */

	odp_rwlock_t 	sb_mtx;		/* sockbuf lock */
	odp_spinlock_t	sb_sx;		/* prevent I/O interlacing */

	short		sb_state;	/* (c/d) socket state on sockbuf */
#define	sb_startzero	sb_mb
#define SOCKBUF_LEN 64
	odp_packet_t	sb_mb[SOCKBUF_LEN];	/* (c/d) the pkt table */
	int		sb_put, sb_get;
	int		sb_mbtail;		/* (c/d) the last pkt in the table */
	int		sb_lastrecord;		/* (c/d) first mbuf of last
						 * record in socket buffer */
	int		sb_sndptr;	/* (c/d) next pkt to send */
	uint32_t	sb_sndptroff;	/* (c/d) byte offset of ptr into chain */
	uint32_t	sb_cc;		/* (c/d) actual chars in buffer */
	uint32_t	sb_hiwat;	/* (c/d) max actual char count */
	uint32_t	sb_mbcnt;	/* (c/d) chars of mbufs used */
	uint32_t	sb_mcnt;        /* (c/d) number of mbufs in buffer */
	uint32_t	sb_ccnt;        /* (c/d) number of clusters in buffer */
	uint32_t	sb_mbmax;	/* (c/d) max chars of mbufs to use */
	uint32_t	sb_ctl;		/* (c/d) non-data chars in buffer */
	int		sb_lowat;	/* (c/d) low water mark */
	int		sb_timeo;	/* (c/d) timeout for read/write */
	short		sb_flags;	/* (c/d) flags, see below */
	int		(*sb_upcall)(struct socket *, void *, int); /* (c/d) */
	void		*sb_upcallarg;	/* (c/d) */
	struct socket	*sb_socket;
	//const char      *lockedby_file;
	//int             lockedby_line;
};


/*
 * Per-socket buffer mutex used to protect most fields in the socket
 * buffer.
 */
#if (defined OFP_RSS) || (defined OFP_SOCKBUF_MTX_DISABLED)
/* The same core that puts data to sockbuf must also read the data.
 * This works with notify callback when the ofp_read/ofp_write is done
 * on the same core as the one that does udp/tcp_input() processing.
 */
# define SOCKBUF_MTX(_sb)		(void)_sb;

# define SOCKBUF_LOCK_INIT(_sb, _name)	(void)_sb; (void)_name;
# define SOCKBUF_LOCK(_sb)		(void)_sb;
# define SOCKBUF_UNLOCK(_sb)		(void)_sb;
# define SOCKBUF_RLOCK(_sb)		(void)_sb;
# define SOCKBUF_RUNLOCK(_sb)		(void)_sb;
#else
# define SOCKBUF_MTX(_sb)		(&(_sb)->sb_mtx)

# define SOCKBUF_LOCK_INIT(_sb, _name)	odp_rwlock_init(SOCKBUF_MTX(_sb))
# define SOCKBUF_LOCK(_sb)		odp_rwlock_write_lock(SOCKBUF_MTX(_sb))
# define SOCKBUF_UNLOCK(_sb)		odp_rwlock_write_unlock(SOCKBUF_MTX(_sb))
# define SOCKBUF_RLOCK(_sb)		odp_rwlock_read_lock(SOCKBUF_MTX(_sb))
# define SOCKBUF_RUNLOCK(_sb)		odp_rwlock_read_unlock(SOCKBUF_MTX(_sb))
#endif
#define SOCKBUF_LOCK_DESTROY(_sb)	/*mtx_destroy(SOCKBUF_MTX(_sb))*/
#define SOCKBUF_OWNED(_sb)		/*mtx_owned(SOCKBUF_MTX(_sb))*/
#define SOCKBUF_LOCK_ASSERT(_sb)	/*mtx_assert(SOCKBUF_MTX(_sb), MA_OWNED)*/
#define SOCKBUF_UNLOCK_ASSERT(_sb)	/*mtx_assert(SOCKBUF_MTX(_sb), MA_NOTOWNED)*/

/*#define SOCKBUF_LOCK_Y(_sb)		odp_rwlock_recursive_write_lock(SOCKBUF_MTX(_sb))*/
/*#define SOCKBUF_UNLOCK_Y(_sb)		odp_rwlock_recursive_write_unlock(SOCKBUF_MTX(_sb))*/

int	packet_accepted_as_event(struct socket *so, odp_packet_t pkt);
void	sbappend(struct sockbuf *sb, odp_packet_t m);
void	sbappend_locked(struct sockbuf *sb, odp_packet_t m);
void	ofp_sbappendstream(struct sockbuf *sb, odp_packet_t m);
void	ofp_sbappendstream_locked(struct sockbuf *sb, odp_packet_t m);
int	sbappendaddr(struct sockbuf *sb, const struct ofp_sockaddr *asa,
		odp_packet_t m0, odp_packet_t control);
int	ofp_sbappendaddr_locked(struct sockbuf *sb, odp_packet_t m0,
		odp_packet_t control);
int	sbappendcontrol(struct sockbuf *sb, odp_packet_t m0,
		odp_packet_t control);
int	sbappendcontrol_locked(struct sockbuf *sb, odp_packet_t m0,
		odp_packet_t control);
void	sbappendrecord(struct sockbuf *sb, odp_packet_t m0);
void	sbappendrecord_locked(struct sockbuf *sb, odp_packet_t m0);
void	sbcheck(struct sockbuf *sb);
void	ofp_sbcompress(struct sockbuf *sb, odp_packet_t m, int n);
odp_packet_t
	sbcreatecontrol(char * p, int size, int type, int level);
void	ofp_sbdestroy(struct sockbuf *sb, struct socket *so);
void	ofp_sbdrop(struct sockbuf *sb, int len);
void	ofp_sbdrop_locked(struct sockbuf *sb, int len);
void	sbdroprecord(struct sockbuf *sb);
void	ofp_sbdroprecord_locked(struct sockbuf *sb);
void	ofp_sbflush(struct sockbuf *sb);
void	ofp_sbflush_locked(struct sockbuf *sb);
void	ofp_sbrelease(struct sockbuf *sb, struct socket *so);
void	ofp_sbrelease_internal(struct sockbuf *sb, struct socket *so);
void	ofp_sbrelease_locked(struct sockbuf *sb, struct socket *so);
int	ofp_sbreserve(struct sockbuf *sb, uint64_t cc, struct socket *so,
		struct thread *td);
int	ofp_sbreserve_locked(struct sockbuf *sb, uint64_t cc, struct socket *so,
		struct thread *td);
odp_packet_t
	sbsndptr(struct sockbuf *sb, uint32_t off, uint32_t len, uint32_t *moff);
void	sbtoxsockbuf(struct sockbuf *sb, struct xsockbuf *xsb);
int	ofp_sbwait(struct sockbuf *sb);
int	ofp_sblock(struct sockbuf *sb, int flags);
void	ofp_sbunlock(struct sockbuf *sb);

/*
 * How much space is there in a socket buffer (so->so_snd or so->so_rcv)?
 * This is problematical if the fields are unsigned, as the space might
 * still be negative (cc > hiwat or mbcnt > mbmax).  Should detect
 * overflow and return 0.  Should use "lmin" but it doesn't exist now.
 */
#if 1
#define	sbspace(sb) \
	((long)(global_param->pkt_pool_buffer_size * \
		((sb)->sb_put >= (sb)->sb_get ?				\
		 (SOCKBUF_LEN - ((sb)->sb_put - (sb)->sb_get) - 1) :	\
		 ((sb)->sb_get - (sb)->sb_put - 1))))
#else
#define	sbspace(sb) \
    ((long) imin((int)((sb)->sb_hiwat - (sb)->sb_cc), \
	 (int)((sb)->sb_mbmax - (sb)->sb_mbcnt)))
#endif

/* adjust counters in sb reflecting allocation of m */
#define	sballoc(sb, m) { \
	(sb)->sb_cc += odp_packet_len(m); \
	(sb)->sb_mbcnt += odp_packet_buf_len(m);	\
	(sb)->sb_mcnt += 1; \
}

/* adjust counters in sb reflecting freeing of m */
#define	sbfree(sb, m) { \
	(sb)->sb_cc -= odp_packet_len(m); \
	(sb)->sb_mbcnt -= odp_packet_buf_len(m); \
	(sb)->sb_mcnt -= 1; \
	if ((sb)->sb_sndptr >= 0 && (sb)->sb_mb[(sb)->sb_sndptr] == (m)) { \
		(sb)->sb_sndptr = -1; \
		(sb)->sb_sndptroff = 0; \
	} \
	if ((sb)->sb_sndptroff != 0) \
		(sb)->sb_sndptroff -= odp_packet_len(m); \
}


#define SB_EMPTY_FIXUP(sb) do {						\
	if ((sb)->sb_mb == NULL) {					\
		(sb)->sb_mbtail = NULL;					\
		(sb)->sb_lastrecord = NULL;				\
	}								\
} while (/*CONSTCOND*/0)

#ifdef SOCKBUF_DEBUG
void	sblastrecordchk(struct sockbuf *, const char *, int);
#define	SBLASTRECORDCHK(sb)	sblastrecordchk((sb), __FILE__, __LINE__)

void	sblastmbufchk(struct sockbuf *, const char *, int);
#define	SBLASTMBUFCHK(sb)	sblastmbufchk((sb), __FILE__, __LINE__)
#else
#define	SBLASTRECORDCHK(sb)      /* nothing */
#define	SBLASTMBUFCHK(sb)        /* nothing */
#endif /* SOCKBUF_DEBUG */

void ofp_socantrcvmore_locked(struct socket *so);
void ofp_socantrcvmore(struct socket *so);

int ofp_sockbuf_put_last(struct sockbuf *sb, odp_packet_t pkt);
odp_packet_t ofp_sockbuf_get_first(struct sockbuf *);
odp_packet_t ofp_sockbuf_remove_first(struct sockbuf *);
odp_packet_t ofp_sockbuf_get_first_remove(struct sockbuf *);
void ofp_sockbuf_packet_free(odp_packet_t);
void ofp_sockbuf_copy_out(struct sockbuf *sb, int off, int len, char *dst);

#endif /* _SYS_SOCKBUF_H_ */
