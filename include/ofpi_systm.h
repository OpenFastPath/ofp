/*-
 * Copyright (c) 2014 ENEA Software AB
 * Copyright (c) 2014 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _OFPI_SYSTM_H_
#define _OFPI_SYSTM_H_

#include "odp/std_types.h"
#include "odp/packet.h"
#include "odp/spinlock.h"
#include "odp/rwlock.h"
#include "odp/thread.h"
#include "odp/cpu.h"
#include "ofpi_socket.h"

#define SHM_PKT_POOL_BUF_SIZE	1856
#define MCLBYTES SHM_PKT_POOL_BUF_SIZE
#define	RLIM_INFINITY	((uint64_t)(((uint64_t)1 << 63) - 1))

/*
 * Flags indicating hw checksum support and sw checksum requirements.  This
 * field can be directly tested against if_data.ifi_hwassist.
 */
#define	CSUM_IP			0x0001		/* will csum IP */
#define	CSUM_TCP		0x0002		/* will csum TCP */
#define	CSUM_UDP		0x0004		/* will csum UDP */
#define	CSUM_IP_FRAGS		0x0008		/* will csum IP fragments */
#define	CSUM_FRAGMENT		0x0010		/* will do IP fragmentation */
#define	CSUM_TSO		0x0020		/* will do TSO */
#define	CSUM_SCTP		0x0040		/* will csum SCTP */
#define CSUM_SCTP_IPV6		0x0080		/* will csum IPv6/SCTP */

#define	CSUM_IP_CHECKED		0x0100		/* did csum IP */
#define	CSUM_IP_VALID		0x0200		/*   ... the csum is valid */
#define	CSUM_DATA_VALID		0x0400		/* csum_data field is valid */
#define	CSUM_PSEUDO_HDR		0x0800		/* csum_data has pseudo hdr */
#define	CSUM_SCTP_VALID		0x1000		/* SCTP checksum is valid */
#define	CSUM_UDP_IPV6		0x2000		/* will csum IPv6/UDP */
#define	CSUM_TCP_IPV6		0x4000		/* will csum IPv6/TCP */

#ifndef OFP__UID_T_DECLARED
typedef	__ofp_uid_t		ofp_uid_t;
#define	OFP__UID_T_DECLARED
#endif /*OFP__UID_T_DECLARED*/

struct ofp_ucred {
	ofp_uid_t	cr_uid;			/* effective user id */
};

struct thread {
	struct proc {
		int p_fibnum;	/* in this routing domain XXX MRT */
	} td_proc;
	struct ofp_ucred	*td_ucred;	/* (k) Reference to credentials. */
};

static inline struct ofp_ifnet *ofp_packet_interface(odp_packet_t pkt) {
	struct ofp_ifnet *dev = odp_packet_user_ptr(pkt);
	return dev;
}


odp_packet_t odp_packet_ensure_contiguous(odp_packet_t pkt, int len);
int odp_packet_flags(odp_packet_t pkt);

typedef int (*uma_init)(void *mem, int size, int flags);
typedef void (*uma_fini)(void *mem, int size);

#define	HASH_NOWAIT	0x00000001
#define	HASH_WAITOK	0x00000002
void	*ofp_hashinit(int count, void *type, uint64_t *hashmask);
void    *ofp_hashinit_flags(int elements, void *type, uint64_t *hashmask, int flags);
void	*ofp_phashinit(int count, void *type, uint64_t *nentries);
void	ofp_hashdestroy(void *vhashtbl, void *type, uint64_t hashmask);

static __inline int imax(int a, int b) { return (a > b ? a : b); }
static __inline int imin(int a, int b) { return (a < b ? a : b); }
static __inline long lmax(long a, long b) { return (a > b ? a : b); }
static __inline long lmin(long a, long b) { return (a < b ? a : b); }
static __inline unsigned int max(unsigned int a, unsigned int b) { return (a > b ? a : b); }
static __inline unsigned int min(unsigned int a, unsigned int b) { return (a < b ? a : b); }
#if 0
static __inline quad_t qmax(quad_t a, quad_t b) { return (a > b ? a : b); }
static __inline quad_t qmin(quad_t a, quad_t b) { return (a < b ? a : b); }
#endif
static __inline unsigned long ulmax(unsigned long a, unsigned long b) { return (a > b ? a : b); }
static __inline unsigned long ulmin(unsigned long a, unsigned long b) { return (a < b ? a : b); }
#if 0
static __inline off_t omax(off_t a, off_t b) { return (a > b ? a : b); }
static __inline off_t omin(off_t a, off_t b) { return (a < b ? a : b); }
#endif

#if 0
static __inline int abs(int a) { return (a < 0 ? -a : a); }
static __inline long labs(long a) { return (a < 0 ? -a : a); }
static __inline quad_t qabs(quad_t a) { return (a < 0 ? -a : a); }
#endif

static inline void odp_packet_set_csum_data(odp_packet_t pkt, int val)
{
	(void)pkt; (void)val;
}

static inline int odp_packet_csum_data(odp_packet_t pkt)
{
	(void)pkt;
	return 0;
}

static inline void odp_packet_set_csum_flags(odp_packet_t pkt, int val)
{
	(void)pkt; (void)val;
}

static inline int odp_packet_csum_flags(odp_packet_t pkt)
{
	(void)pkt;
	return 0;
}

static inline int odp_packet_is_bcast(odp_packet_t pkt)
{
	(void)pkt;
	return 0;
}

static inline int odp_packet_is_mcast(odp_packet_t pkt)
{
	(void)pkt;
	return 0;
}

struct in_conninfo;
struct hc_metrics_lite;
static inline void tcp_hc_update(struct in_conninfo *c, struct hc_metrics_lite *a)
{
	(void)c; (void)a;
}


struct ofp_rec_rwlock {
	odp_rwlock_t	lock;
	odp_spinlock_t	splock;
	int		cnt;
	int		owner;
	const char	*file;
	int		line;
};

static inline void ofp_rec_init(struct ofp_rec_rwlock *lock,
				  const char *file, int line)
{
	(void)file;
	(void)line;
	odp_spinlock_init(&lock->splock);
	odp_rwlock_init(&lock->lock);
}

#define OFP_LOG_Z(a...) do {} while (0)

static inline void ofp_rec_wlock(struct ofp_rec_rwlock *lock,
				   const char *file, int line)
{
	odp_spinlock_lock(&lock->splock);

	if ((int32_t)(lock->lock.cnt.v) < 0) {
		OFP_LOG_Z("lock=%p is already locked by %s:%d cpu=%d cnt=%d\n",
			    lock, lock->file, lock->line, lock->owner, lock->cnt);
		if (odp_cpu_id() != lock->owner) {
			odp_spinlock_unlock(&lock->splock);
			odp_rwlock_write_lock(&lock->lock);
		} else {
			odp_spinlock_unlock(&lock->splock);
		}
	} else {
		odp_rwlock_write_lock(&lock->lock);
		odp_spinlock_unlock(&lock->splock);
	}

	lock->owner = odp_cpu_id();
	lock->cnt++;
	lock->file = file;
	lock->line = line;
}

static inline void ofp_rec_wunlock(struct ofp_rec_rwlock *lock,
				   const char *file, int line)
{
	(void)file;
	(void)line;

	if (--lock->cnt == 0) {
		lock->owner = -1;
		odp_rwlock_write_unlock(&lock->lock);
	} else
		OFP_LOG_Z("lock=%p still locked, cnt=%d\n",
			    lock, lock->cnt);
}

static inline void ofp_rec_rlock(struct ofp_rec_rwlock *lock,
				   const char *file, int line)
{
	(void)file;
	(void)line;
	odp_rwlock_read_lock(&lock->lock);
}

static inline void ofp_rec_runlock(struct ofp_rec_rwlock *lock,
				     const char *file, int line)
{
	(void)file;
	(void)line;
	odp_rwlock_read_unlock(&lock->lock);
}

static inline int ofp_rec_try_wlock(struct ofp_rec_rwlock *lock,
				      const char *file, int line)
{
	odp_spinlock_lock(&lock->splock);

	if ((int32_t)(lock->lock.cnt.v) < 0) {
		OFP_LOG_Z("try lock=%p is already locked by %s:%d cpu=%d cnt=%d\n",
			    lock, lock->file, lock->line, lock->owner, lock->cnt);
		if (odp_cpu_id() != lock->owner) {
			odp_spinlock_unlock(&lock->splock);
			return 0;
		}
		odp_spinlock_unlock(&lock->splock);
	} else {
		odp_rwlock_write_lock(&lock->lock);
		odp_spinlock_unlock(&lock->splock);
	}
	lock->owner = odp_cpu_id();
	lock->cnt++;
	lock->file = file;
	lock->line = line;
	return 1;
}


#endif
