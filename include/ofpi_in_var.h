/*-
 * Copyright (c) 1985, 1986, 1993
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
 *	@(#)in_var.h	8.2 (Berkeley) 1/9/95
 * $FreeBSD: release/9.1.0/sys/netinet/in_var.h 238713 2012-07-23 09:19:14Z glebius $
 */

#ifndef _NETINET_IN_VAR_H_
#define _NETINET_IN_VAR_H_

/*
 * Per-interface IGMP router version information.
 */
struct ofp_igmp_ifinfo {
	OFP_LIST_ENTRY(ofp_igmp_ifinfo) igi_link;
	struct ofp_ifnet *igi_ifp;	/* interface this instance belongs to */
	uint32_t igi_version;	/* IGMPv3 Host Compatibility Mode */
	uint32_t igi_v1_timer;	/* IGMPv1 Querier Present timer (s) */
	uint32_t igi_v2_timer;	/* IGMPv2 Querier Present timer (s) */
	uint32_t igi_v3_timer;	/* IGMPv3 General Query (interface) timer (s)*/
	uint32_t igi_flags;	/* IGMP per-interface flags */
	uint32_t igi_rv;	/* IGMPv3 Robustness Variable */
	uint32_t igi_qi;	/* IGMPv3 Query Interval (s) */
	uint32_t igi_qri;	/* IGMPv3 Query Response Interval (s) */
	uint32_t igi_uri;	/* IGMPv3 Unsolicited Report Interval (s) */
	OFP_SLIST_HEAD(,ofp_in_multi)	igi_relinmhead; /* released groups */
	struct ofp_ifqueue	 igi_gq;	/* queue of general query responses */
};

#define IGIF_SILENT	0x00000001	/* Do not use IGMP on this ifp */
#define IGIF_LOOPBACK	0x00000002	/* Send IGMP reports to loopback */

/*
 * IPv4 multicast IGMP-layer source entry.
 */
struct ofp_ip_msource {
	RB_ENTRY(ofp_ip_msource)	ims_link;	/* RB tree links */
	ofp_in_addr_t		ims_haddr;	/* host byte order */
	struct ims_st {
		uint16_t	ex;		/* # of exclusive members */
		uint16_t	in;		/* # of inclusive members */
	}			ims_st[2];	/* state at t0, t1 */
	uint8_t			ims_stp;	/* pending query */
};

/*
 * IPv4 multicast PCB-layer source entry.
 */
struct ofp_in_msource {
	RB_ENTRY(ofp_ip_msource)	ims_link;	/* RB tree links */
	ofp_in_addr_t		ims_haddr;	/* host byte order */
	uint8_t			imsl_st[2];	/* state before/at commit */
};

RB_HEAD(ip_msource_tree, ofp_ip_msource);	/* define struct ip_msource_tree */

static __inline int
ip_msource_cmp(const struct ofp_ip_msource *a, const struct ofp_ip_msource *b)
{

	if (a->ims_haddr < b->ims_haddr)
		return (-1);
	if (a->ims_haddr == b->ims_haddr)
		return (0);
	return (1);
}
RB_PROTOTYPE(ip_msource_tree, ofp_ip_msource, ims_link, ip_msource_cmp);

/*
 * IPv4 multicast PCB-layer group filter descriptor.
 */
struct ofp_in_mfilter {
	struct ip_msource_tree	imf_sources; /* source list for (S,G) */
	uint64_t			imf_nsrc;    /* # of source entries */
	uint8_t			imf_st[2];   /* state before/at commit */
};

/*
 * IPv4 group descriptor.
 *
 * For every entry on an ifnet's if_multiaddrs list which represents
 * an IP multicast group, there is one of these structures.
 *
 * If any source filters are present, then a node will exist in the RB-tree
 * to permit fast lookup by source whenever an operation takes place.
 * This permits pre-order traversal when we issue reports.
 * Source filter trees are kept separately from the socket layer to
 * greatly simplify locking.
 *
 * When IGMPv3 is active, inm_timer is the response to group query timer.
 * The state-change timer inm_sctimer is separate; whenever state changes
 * for the group the state change record is generated and transmitted,
 * and kept if retransmissions are necessary.
 *
 * FUTURE: inm_link is now only used when groups are being purged
 * on a detaching ifnet. It could be demoted to a SLIST_ENTRY, but
 * because it is at the very start of the struct, we can't do this
 * w/o breaking the ABI for ifmcstat.
 */
struct ofp_in_multi {
	OFP_LIST_ENTRY(ofp_in_multi) inm_link;	/* to-be-released by in_ifdetach */
	struct	ofp_in_addr inm_addr;	/* IP multicast address, convenience */
	struct	ofp_ifnet *inm_ifp;		/* back pointer to ifnet */
	struct ofp_ifmultiaddr *inm_ifma;	/* back pointer to ifmultiaddr */
	uint32_t	inm_timer;	/* IGMPv1/v2 group / v3 query timer */
	uint32_t	inm_state;	/* state of the membership */
	void	*inm_rti;		/* unused, legacy field */
	uint32_t	inm_refcount;	/* reference count */

	/* New fields for IGMPv3 follow. */
	struct ofp_igmp_ifinfo	*inm_igi;	/* IGMP info */
	OFP_SLIST_ENTRY(ofp_in_multi)	 inm_nrele;	/* to-be-released by IGMP */
	struct ip_msource_tree	 inm_srcs;	/* tree of sources */
	uint32_t		 inm_nsrc;	/* # of tree entries */

	struct ofp_ifqueue		 inm_scq;	/* queue of pending
						 * state-change packets */
	struct ofp_timeval		 inm_lastgsrtv;	/* Time of last G-S-R query */
	uint16_t		 inm_sctimer;	/* state-change timer */
	uint16_t		 inm_scrv;	/* state-change rexmit count */

	/*
	 * SSM state counters which track state at T0 (the time the last
	 * state-change report's RV timer went to zero) and T1
	 * (time of pending report, i.e. now).
	 * Used for computing IGMPv3 state-change reports. Several refcounts
	 * are maintained here to optimize for common use-cases.
	 */
	struct ofp_inm_st {
		uint16_t	iss_fmode;	/* IGMP filter mode */
		uint16_t	iss_asm;	/* # of ASM listeners */
		uint16_t	iss_ex;		/* # of exclusive members */
		uint16_t	iss_in;		/* # of inclusive members */
		uint16_t	iss_rec;	/* # of recorded sources */
	}			inm_st[2];	/* state at t0, t1 */
};

/*
 * Helper function to derive the filter mode on a source entry
 * from its internal counters. Predicates are:
 *  A source is only excluded if all listeners exclude it.
 *  A source is only included if no listeners exclude it,
 *  and at least one listener includes it.
 * May be used by ifmcstat(8).
 */
static __inline uint8_t
ims_get_mode(const struct ofp_in_multi *inm, const struct ofp_ip_msource *ims,
    uint8_t t)
{

	t = !!t;
	if (inm->inm_st[t].iss_ex > 0 &&
	    inm->inm_st[t].iss_ex == ims->ims_st[t].ex)
		return (OFP_MCAST_EXCLUDE);
	else if (ims->ims_st[t].in > 0 && ims->ims_st[t].ex == 0)
		return (OFP_MCAST_INCLUDE);
	return (OFP_MCAST_UNDEFINED);
}

SYSCTL_DECL(_net_inet);
SYSCTL_DECL(_net_inet_ip);
SYSCTL_DECL(_net_inet_raw);

/*
 * Lock macros for IPv4 layer multicast address lists.  IPv4 lock goes
 * before link layer multicast locks in the lock order.  In most cases,
 * consumers of IN_*_MULTI() macros should acquire the locks before
 * calling them; users of the in_{add,del}multi() functions should not.
 */
extern odp_rwlock_t ofp_in_multi_mtx;
#define	IN_MULTI_LOCK()		odp_rwlock_write_lock(&ofp_in_multi_mtx)
#define	IN_MULTI_UNLOCK()	odp_rwlock_write_unlock(&ofp_in_multi_mtx)
#define	IN_MULTI_LOCK_ASSERT()	do {} while (0) /*mtx_assert(&ofp_in_multi_mtx, MA_OWNED)*/
#define	IN_MULTI_UNLOCK_ASSERT() do {} while (0) /*mtx_assert(&ofp_in_multi_mtx, MA_NOTOWNED)*/

/*
 * Function for looking up an in_multi record for an IPv4 multicast address
 * on a given interface. ifp must be valid. If no record found, return NULL.
 * The IN_MULTI_LOCK and IF_ADDR_LOCK on ifp must be held.
 */
static __inline struct ofp_in_multi *
inm_lookup_locked(struct ofp_ifnet *ifp, const struct ofp_in_addr ina)
{
	struct ofp_ifmultiaddr *ifma;
	struct ofp_in_multi *inm;

	IN_MULTI_LOCK_ASSERT();
	IF_ADDR_LOCK_ASSERT(ifp);

	inm = NULL;
	OFP_TAILQ_FOREACH(ifma, &((ifp)->if_multiaddrs), ifma_link) {
		if (ifma->ifma_addr->sa_family == OFP_AF_INET) {
			inm = (struct ofp_in_multi *)ifma->ifma_protospec;
			if (inm->inm_addr.s_addr == ina.s_addr)
				break;
			inm = NULL;
		}
	}
	return (inm);
}

/*
 * Wrapper for inm_lookup_locked().
 * The IF_ADDR_LOCK will be taken on ifp and released on return.
 */
static __inline struct ofp_in_multi *
inm_lookup(struct ofp_ifnet *ifp, const struct ofp_in_addr ina)
{
	struct ofp_in_multi *inm;

	IN_MULTI_LOCK_ASSERT();
	IF_ADDR_RLOCK(ifp);
	inm = inm_lookup_locked(ifp, ina);
	IF_ADDR_RUNLOCK(ifp);

	return (inm);
}

/* Acquire an in_multi record. */
static __inline void
inm_acquire_locked(struct ofp_in_multi *inm)
{

	IN_MULTI_LOCK_ASSERT();
	++inm->inm_refcount;
}

/*
 * Return values for ofp_imo_multi_filter().
 */
#define OFP_MCAST_PASS		0	/* Pass */
#define OFP_MCAST_NOTGMEMBER	1	/* This host not a member of group */
#define OFP_MCAST_NOTSMEMBER	2	/* This host excluded source */
#define OFP_MCAST_MUTED		3	/* [deprecated] */

struct ofp_rtentry;
struct	route;
struct ofp_ip_moptions;

int	ofp_imo_multi_filter(const struct ofp_ip_moptions *, const struct ofp_ifnet *,
	    const struct ofp_sockaddr *, const struct ofp_sockaddr *);
void	ofp_inm_commit(struct ofp_in_multi *);
void	ofp_inm_clear_recorded(struct ofp_in_multi *);
void	ofp_inm_print(const struct ofp_in_multi *);
int	ofp_inm_record_source(struct ofp_in_multi *inm, const ofp_in_addr_t);
void	inm_release(struct ofp_in_multi *);
void	ofp_inm_release_locked(struct ofp_in_multi *);
struct ofp_in_multi *
	ofp_in_addmulti(struct ofp_in_addr *, struct ofp_ifnet *);
void	ofp_in_delmulti(struct ofp_in_multi *);
int	ofp_in_joingroup(struct ofp_ifnet *, const struct ofp_in_addr *,
	    /*const*/ struct ofp_in_mfilter *, struct ofp_in_multi **);
int	ofp_in_joingroup_locked(struct ofp_ifnet *, const struct ofp_in_addr *,
	    /*const*/ struct ofp_in_mfilter *, struct ofp_in_multi **);
int	ofp_in_leavegroup(struct ofp_in_multi *, /*const*/ struct ofp_in_mfilter *);
int	ofp_in_leavegroup_locked(struct ofp_in_multi *,
	    /*const*/ struct ofp_in_mfilter *);
int	in_control(struct ofp_socket *, uint64_t, char *, struct ofp_ifnet *,
		   void *);
void	in_rtqdrain(void);
void	ip_input(odp_packet_t );


#endif /* _NETINET_IN_VAR_H_ */
