/*-
 * Copyright (c) 2007-2009 Bruce Simpson.
 * Copyright (c) 2005 Robert N. M. Watson.
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
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * IPv4 multicast socket, group, and socket option processing module.
 */

//#define KTR

#include "ofpi_errno.h"
#include "ofpi.h"
#include "ofpi_tree.h"
#include "ofpi_util.h"
#include "ofpi_debug.h"
#include "ofpi_systm.h"
#include "ofpi_protosw.h"
#include "ofpi_sysctl.h"
#include "ofpi_portconf.h"
#include "ofpi_in_var.h"
#include "ofpi_in.h"
#include "ofpi_igmp.h"
#include "ofpi_igmp_var.h"
#include "ofpi_socketvar.h"
#include "ofpi_timer.h"
#include "ofpi_in_pcb.h"
#include "ofpi_ip.h"
#include "ofpi_ip6.h"
#include "ofpi_icmp6.h"
#include "ofpi_in6_pcb.h"
#include "ofpi_tcp_fsm.h"
#include "ofpi_tcp_seq.h"
#include "ofpi_tcp_timer.h"
#include "ofpi_tcp_var.h"
#include "ofpi_tcp6_var.h"
#include "ofpi_tcp.h"
#include "ofpi_tcp_syncache.h"
#include "ofpi_icmp.h"
#include "ofp_log.h"
#include "ofp_pkt_processing.h"


static struct ofp_ifmultiaddr *
if_allocmulti(struct ofp_ifnet *ifp, struct ofp_sockaddr *sa,
	      struct ofp_sockaddr *llsa, int mflags);

static void
if_freemulti(struct ofp_ifmultiaddr *ifma);

static int
if_delmulti_locked(struct ofp_ifnet *ifp,
		   struct ofp_ifmultiaddr *ifma, int detaching);

int	ofp_if_addmulti(struct ofp_ifnet *, struct ofp_sockaddr *, struct ofp_ifmultiaddr **);
int	ofp_if_delmulti(struct ofp_ifnet *, struct ofp_sockaddr *);
void	ofp_if_delmulti_ifma(struct ofp_ifmultiaddr *);
struct ofp_ifmultiaddr *
	ofp_if_findmulti(struct ofp_ifnet *, struct ofp_sockaddr *);

static uint32_t V_if_index = (4096 << 4) | 15;

#define OFP_INADDR_TO_IFP(_addr, _ifp) do {				\
		(_ifp) = ofp_get_ifnet_by_ip((_addr).s_addr, 0);	\
	} while (0)

#define malloc0(_s) calloc(_s, 1)

static char *inet_ntoa(struct ofp_in_addr a) {
	return ofp_print_ip_addr(a.s_addr);
}

static int if_index(struct ofp_ifnet *ifp)
{
	return (ifp->vlan << 4) | ifp->port;
}

static struct ofp_ifnet *ifnet_byindex(int ifindex)
{
	return ofp_get_ifnet(ifindex & 0xf, ifindex >> 4);
}

static int copyout(const void *src, void *dest, size_t n)
{
	bcopy(src, dest, n);
	return 0;
}

static int copyin(const void *src, void *dest, size_t n)
{
	bcopy(src, dest, n);
	return 0;
}

/*
 * Structure of a Link-Level sockaddr:
 */
struct ofp_sockaddr_dl {
	u_char	sdl_len;	/* Total length of sockaddr */
	u_char	sdl_family;	/* AF_LINK */
	u_short	sdl_index;	/* if != 0, system given index for interface */
	u_char	sdl_type;	/* interface type */
	u_char	sdl_nlen;	/* interface name length, no trailing 0 reqd. */
	u_char	sdl_alen;	/* link level address length */
	u_char	sdl_slen;	/* link layer selector length */
	char	sdl_data[46];	/* minimum work area, can be larger;
				   contains both if name and ll address */
};

#define LLADDR(s) ((caddr_t)((s)->sdl_data + (s)->sdl_nlen))

#ifdef KTR
#define CTR1(_l, _fmt, ...)  OFP_INFO(_fmt, ##__VA_ARGS__)
#else
#define CTR1(_l, _fmt, ...)  do { } while (0)
#endif
#define CTR2 CTR1
#define CTR3 CTR1
#define CTR4 CTR1
#define CTR5 CTR1

#ifndef KTR_IGMPV3
#define KTR_IGMPV3 KTR_INET
#endif

#ifndef __SOCKUNION_DECLARED
union sockunion {
	struct ofp_sockaddr_storage_2	ss;
	struct ofp_sockaddr		sa;
	struct ofp_sockaddr_dl	sdl;
	struct ofp_sockaddr_in	sin;
};
typedef union sockunion sockunion_t;
#define __SOCKUNION_DECLARED
#endif /* __SOCKUNION_DECLARED */

#if 0
static MALLOC_DEFINE(M_INMFILTER, "in_mfilter",
		     "IPv4 multicast PCB-layer source filter");
static MALLOC_DEFINE(M_IPMADDR, "in_multi", "IPv4 multicast group");
static MALLOC_DEFINE(M_IPMOPTS, "ip_moptions", "IPv4 multicast options");
static MALLOC_DEFINE(M_IPMSOURCE, "ip_msource",
    "IPv4 multicast IGMP-layer source filter");
#endif

/*
 * Locking:
 * - Lock order is: Giant, INP_WLOCK, IN_MULTI_LOCK, IGMP_LOCK, IF_ADDR_LOCK.
 * - The IF_ADDR_LOCK is implicitly taken by inm_lookup() earlier, however
 *   it can be taken by code in net/if.c also.
 * - ip_moptions and in_mfilter are covered by the INP_WLOCK.
 *
 * struct ofp_in_multi is covered by IN_MULTI_LOCK. There isn't strictly
 * any need for in_multi itself to be virtualized -- it is bound to an ifp
 * anyway no matter what happens.
 */
odp_rwlock_t ofp_in_multi_mtx;
//HJo MTX_SYSINIT(ofp_in_multi_mtx, &in_multi_mtx, "in_multi_mtx", MTX_DEF);

/*
 * Functions with non-static linkage defined in this file should be
 * declared in in_var.h:
 *  ofp_imo_multi_filter()
 *  ofp_in_addmulti()
 *  ofp_in_delmulti()
 *  ofp_in_joingroup()
 *  ofp_in_joingroup_locked()
 *  ofp_in_leavegroup()
 *  ofp_in_leavegroup_locked()
 * and ip_var.h:
 *  ofp_inp_freemoptions()
 *  ofp_inp_getmoptions()
 *  ofp_inp_setmoptions()
 *
 * XXX: Both carp and pf need to use the legacy (*,G) KPIs ofp_in_addmulti()
 * and ofp_in_delmulti().
 */
static void	imf_commit(struct ofp_in_mfilter *);
static int	imf_get_source(struct ofp_in_mfilter *imf,
		    const struct ofp_sockaddr_in *psin,
		    struct ofp_in_msource **);
static struct ofp_in_msource *
		imf_graft(struct ofp_in_mfilter *, const uint8_t,
		    const struct ofp_sockaddr_in *);
static void	imf_leave(struct ofp_in_mfilter *);
static int	imf_prune(struct ofp_in_mfilter *, const struct ofp_sockaddr_in *);
static void	imf_purge(struct ofp_in_mfilter *);
static void	imf_rollback(struct ofp_in_mfilter *);
static void	imf_reap(struct ofp_in_mfilter *);
static int	imo_grow(struct ofp_ip_moptions *);
static size_t	imo_match_group(const struct ofp_ip_moptions *,
		    const struct ofp_ifnet *, const struct ofp_sockaddr *);
static struct ofp_in_msource *
		imo_match_source(const struct ofp_ip_moptions *, const size_t,
		    const struct ofp_sockaddr *);
static void	ims_merge(struct ofp_ip_msource *ims,
		    const struct ofp_in_msource *lims, const int rollback);
static int	in_getmulti(struct ofp_ifnet *, const struct ofp_in_addr *,
		    struct ofp_in_multi **);
static int	inm_get_source(struct ofp_in_multi *inm, const ofp_in_addr_t haddr,
		    const int noalloc, struct ofp_ip_msource **pims);
#ifdef KTR
static int	inm_is_ifp_detached(const struct ofp_in_multi *);
#endif
static int	inm_merge(struct ofp_in_multi *, /*const*/ struct ofp_in_mfilter *);
static void	inm_purge(struct ofp_in_multi *);
static void	inm_reap(struct ofp_in_multi *);
static struct ofp_ip_moptions *
		inp_findmoptions(struct inpcb *);
static int	inp_get_source_filters(struct inpcb *, struct sockopt *);
static int	inp_join_group(struct inpcb *, struct sockopt *);
static int	inp_leave_group(struct inpcb *, struct sockopt *);
static struct ofp_ifnet *
		inp_lookup_mcast_ifp(const struct inpcb *,
		    const struct ofp_sockaddr_in *, const struct ofp_in_addr);
static int	inp_block_unblock_source(struct inpcb *, struct sockopt *);
static int	inp_set_multicast_if(struct inpcb *, struct sockopt *);
static int	inp_set_source_filters(struct inpcb *, struct sockopt *);
static int	sysctl_ip_mcast_filters(OFP_SYSCTL_HANDLER_ARGS);

OFP_SYSCTL_NODE(_net_inet_ip, OFP_OID_AUTO, mcast, OFP_CTLFLAG_RW, 0, "IPv4 multicast");

static uint64_t in_mcast_maxgrpsrc = OFP_IP_MAX_GROUP_SRC_FILTER;
OFP_SYSCTL_ULONG(_net_inet_ip_mcast, OFP_OID_AUTO, maxgrpsrc,
    OFP_CTLFLAG_RW | OFP_CTLFLAG_TUN, &in_mcast_maxgrpsrc, 0,
    "Max source filters per group");
//HJo TUNABLE_ULONG("net.inet.ip.mcast.maxgrpsrc", &in_mcast_maxgrpsrc);

static uint64_t in_mcast_maxsocksrc = OFP_IP_MAX_SOCK_SRC_FILTER;
OFP_SYSCTL_ULONG(_net_inet_ip_mcast, OFP_OID_AUTO, maxsocksrc,
    OFP_CTLFLAG_RW | OFP_CTLFLAG_TUN, &in_mcast_maxsocksrc, 0,
    "Max source filters per socket");
//HJo TUNABLE_ULONG("net.inet.ip.mcast.maxsocksrc", &in_mcast_maxsocksrc);

int ofp_in_mcast_loop = OFP_IP_DEFAULT_MULTICAST_LOOP;
OFP_SYSCTL_INT(_net_inet_ip_mcast, OFP_OID_AUTO, loop, OFP_CTLFLAG_RW | OFP_CTLFLAG_TUN,
    &ofp_in_mcast_loop, 0, "Loopback multicast datagrams by default");
//HJo TUNABLE_INT("net.inet.ip.mcast.loop", &ofp_in_mcast_loop);

OFP_SYSCTL_NODE(_net_inet_ip_mcast, OFP_OID_AUTO, filters,
    OFP_CTLFLAG_RD | OFP_CTLFLAG_MPSAFE, sysctl_ip_mcast_filters,
    "Per-interface stack-wide source filters");

#ifdef KTR
/*
 * Inline function which wraps assertions for a valid ifp.
 * The ifnet layer will set the ifma's ifp pointer to NULL if the ifp
 * is detached.
 */
static inline int
inm_is_ifp_detached(const struct ofp_in_multi *inm)
{
	struct ofp_ifnet *ifp;

	KASSERT(inm->inm_ifma != NULL, ("%s: no ifma", __func__));
	ifp = inm->inm_ifma->ifma_ifp;
	if (ifp != NULL) {
		/*
		 * Sanity check that netinet's notion of ifp is the
		 * same as net's.
		 */
		KASSERT(inm->inm_ifp == ifp, ("%s: bad ifp", __func__));
	}

	return (ifp == NULL);
}
#endif

/*
 * Initialize an in_mfilter structure to a known state at t0, t1
 * with an empty source filter list.
 */
static __inline void
imf_init(struct ofp_in_mfilter *imf, const int st0, const int st1)
{
	memset(imf, 0, sizeof(struct ofp_in_mfilter));
	RB_INIT(&imf->imf_sources);
	imf->imf_st[0] = st0;
	imf->imf_st[1] = st1;
}

/*
 * Resize the ip_moptions vector to the next power-of-two minus 1.
 * May be called with locks held; do not sleep.
 */
static int
imo_grow(struct ofp_ip_moptions *imo)
{
	struct ofp_in_multi	**nmships;
	struct ofp_in_multi	**omships;
	struct ofp_in_mfilter	 *nmfilters;
	struct ofp_in_mfilter	 *omfilters;
	size_t			  idx;
	size_t			  newmax;
	size_t			  oldmax;

	nmships = NULL;
	nmfilters = NULL;
	omships = imo->imo_membership;
	omfilters = imo->imo_mfilters;
	oldmax = imo->imo_max_memberships;
	newmax = ((oldmax + 1) * 2) - 1;

	if (newmax <= OFP_IP_MAX_MEMBERSHIPS) {
		nmships = (struct ofp_in_multi **)realloc(omships,
		    sizeof(struct ofp_in_multi *) * newmax);
		nmfilters = (struct ofp_in_mfilter *)realloc(omfilters,
		    sizeof(struct ofp_in_mfilter) * newmax);
		if (nmships != NULL && nmfilters != NULL) {
			/* Initialize newly allocated source filter heads. */
			for (idx = oldmax; idx < newmax; idx++) {
				imf_init(&nmfilters[idx], OFP_MCAST_UNDEFINED,
				    OFP_MCAST_EXCLUDE);
			}
			imo->imo_max_memberships = newmax;
			imo->imo_membership = nmships;
			imo->imo_mfilters = nmfilters;
		}
	}

	if (nmships == NULL || nmfilters == NULL) {
		if (nmships != NULL)
			free(nmships);
		if (nmfilters != NULL)
			free(nmfilters);
		return (OFP_ETOOMANYREFS);
	}

	return (0);
}

/*
 * Find an IPv4 multicast group entry for this ip_moptions instance
 * which matches the specified group, and optionally an interface.
 * Return its index into the array, or -1 if not found.
 */
static size_t
imo_match_group(const struct ofp_ip_moptions *imo, const struct ofp_ifnet *ifp,
    const struct ofp_sockaddr *group)
{
	const struct ofp_sockaddr_in *gsin;
	struct ofp_in_multi	**pinm;
	int		  idx;
	int		  nmships;

	gsin = (const struct ofp_sockaddr_in *)group;

	/* The imo_membership array may be lazy allocated. */
	if (imo->imo_membership == NULL || imo->imo_num_memberships == 0)
		return (-1);

	nmships = imo->imo_num_memberships;
	pinm = &imo->imo_membership[0];
	for (idx = 0; idx < nmships; idx++, pinm++) {
		if (*pinm == NULL)
			continue;
		if ((ifp == NULL || ((*pinm)->inm_ifp == ifp)) &&
		    ofp_in_hosteq((*pinm)->inm_addr, gsin->sin_addr)) {
			break;
		}
	}
	if (idx >= nmships)
		idx = -1;

	return (idx);
}

/*
 * Find an IPv4 multicast source entry for this imo which matches
 * the given group index for this socket, and source address.
 *
 * NOTE: This does not check if the entry is in-mode, merely if
 * it exists, which may not be the desired behaviour.
 */
static struct ofp_in_msource *
imo_match_source(const struct ofp_ip_moptions *imo, const size_t gidx,
    const struct ofp_sockaddr *src)
{
	struct ofp_ip_msource	 find;
	struct ofp_in_mfilter	*imf;
	struct ofp_ip_msource	*ims;
	const sockunion_t	*psa;

	KASSERT(src->sa_family == OFP_AF_INET, ("%s: !OFP_AF_INET", __func__));
	KASSERT((int)gidx != -1 && gidx < imo->imo_num_memberships,
	    ("%s: invalid index %d\n", __func__, (int)gidx));

	/* The imo_mfilters array may be lazy allocated. */
	if (imo->imo_mfilters == NULL)
		return (NULL);
	imf = &imo->imo_mfilters[gidx];

	/* Source trees are keyed in host byte order. */
	psa = (const sockunion_t *)src;
	find.ims_haddr = odp_be_to_cpu_32(psa->sin.sin_addr.s_addr);
	ims = RB_FIND(ip_msource_tree, &imf->imf_sources, &find);

	return ((struct ofp_in_msource *)ims);
}

/*
 * Perform filtering for multicast datagrams on a socket by group and source.
 *
 * Returns 0 if a datagram should be allowed through, or various error codes
 * if the socket was not a member of the group, or the source was muted, etc.
 */
int
ofp_imo_multi_filter(const struct ofp_ip_moptions *imo, const struct ofp_ifnet *ifp,
		 const struct ofp_sockaddr *group, const struct ofp_sockaddr *src)
{
	size_t gidx;
	struct ofp_in_msource *ims;
	int mode;

	KASSERT(ifp != NULL, ("%s: null ifp", __func__));

	gidx = imo_match_group(imo, ifp, group);
	if ((int)gidx == -1)
		return (OFP_MCAST_NOTGMEMBER);

	/*
	 * Check if the source was included in an (S,G) join.
	 * Allow reception on exclusive memberships by default,
	 * reject reception on inclusive memberships by default.
	 * Exclude source only if an in-mode exclude filter exists.
	 * Include source only if an in-mode include filter exists.
	 * NOTE: We are comparing group state here at IGMP t1 (now)
	 * with socket-layer t0 (since last downcall).
	 */
	mode = imo->imo_mfilters[gidx].imf_st[1];
	ims = imo_match_source(imo, gidx, src);

	if ((ims == NULL && mode == OFP_MCAST_INCLUDE) ||
	    (ims != NULL && ims->imsl_st[0] != mode))
		return (OFP_MCAST_NOTSMEMBER);

	return (OFP_MCAST_PASS);
}

/*
 * Find and return a reference to an in_multi record for (ifp, group),
 * and bump its reference count.
 * If one does not exist, try to allocate it, and update link-layer multicast
 * filters on ifp to listen for group.
 * Assumes the IN_MULTI lock is held across the call.
 * Return 0 if successful, otherwise return an appropriate error code.
 */
static int
in_getmulti(struct ofp_ifnet *ifp, const struct ofp_in_addr *group,
    struct ofp_in_multi **pinm)
{
	struct ofp_sockaddr_in	 gsin;
	struct ofp_ifmultiaddr	*ifma;
	struct ofp_in_ifinfo	*ii;
	struct ofp_in_multi		*inm;
	int error;

	IN_MULTI_LOCK_ASSERT();

	ii = (struct ofp_in_ifinfo *)ifp->if_afdata[OFP_AF_INET];

	inm = inm_lookup(ifp, *group);
	if (inm != NULL) {
		/*
		 * If we already joined this group, just bump the
		 * refcount and return it.
		 */
		KASSERT(inm->inm_refcount >= 1,
		    ("%s: bad refcount %d", __func__, inm->inm_refcount));
		++inm->inm_refcount;
		*pinm = inm;
		return (0);
	}

	memset(&gsin, 0, sizeof(gsin));
	gsin.sin_family = OFP_AF_INET;
	gsin.sin_len = sizeof(struct ofp_sockaddr_in);
	gsin.sin_addr = *group;

	/*
	 * Check if a link-layer group is already associated
	 * with this network-layer group on the given ifnet.
	 */
	error = ofp_if_addmulti(ifp, (struct ofp_sockaddr *)&gsin, &ifma);
	if (error != 0)
		return (error);

	/* XXX ifma_protospec must be covered by IF_ADDR_LOCK */
	IF_ADDR_WLOCK(ifp);

	/*
	 * If something other than netinet is occupying the link-layer
	 * group, print a meaningful error message and back out of
	 * the allocation.
	 * Otherwise, bump the refcount on the existing network-layer
	 * group association and return it.
	 */
	if (ifma->ifma_protospec != NULL) {
		inm = (struct ofp_in_multi *)ifma->ifma_protospec;
#ifdef INVARIANTS
		KASSERT(ifma->ifma_addr != NULL, ("%s: no ifma_addr",
		    __func__));
		KASSERT(ifma->ifma_addr->sa_family == OFP_AF_INET,
		    ("%s: ifma not OFP_AF_INET", __func__));
		KASSERT(inm != NULL, ("%s: no ifma_protospec", __func__));
		if (inm->inm_ifma != ifma || inm->inm_ifp != ifp ||
		    !in_hosteq(inm->inm_addr, *group))
			panic("%s: ifma %p is inconsistent with %p (%s)",
			    __func__, ifma, inm, inet_ntoa(*group));
#endif
		++inm->inm_refcount;
		*pinm = inm;
		IF_ADDR_WUNLOCK(ifp);
		return (0);
	}

	IF_ADDR_WLOCK_ASSERT(ifp);

	/*
	 * A new in_multi record is needed; allocate and initialize it.
	 * We DO NOT perform an IGMP join as the in_ layer may need to
	 * push an initial source list down to IGMP to support SSM.
	 *
	 * The initial source filter state is INCLUDE, {} as per the RFC.
	 */
	inm = malloc0(sizeof(*inm));
	if (inm == NULL) {
		ofp_if_delmulti_ifma(ifma);
		IF_ADDR_WUNLOCK(ifp);
		return (OFP_ENOMEM);
	}
	inm->inm_addr = *group;
	inm->inm_ifp = ifp;
	inm->inm_igi = ii->ii_igmp;
	inm->inm_ifma = ifma;
	inm->inm_refcount = 1;
	inm->inm_state = IGMP_NOT_MEMBER;

	/*
	 * Pending state-changes per group are subject to a bounds check.
	 */
	IFQ_SET_MAXLEN(&inm->inm_scq, IGMP_MAX_STATE_CHANGES);

	inm->inm_st[0].iss_fmode = OFP_MCAST_UNDEFINED;
	inm->inm_st[1].iss_fmode = OFP_MCAST_UNDEFINED;
	RB_INIT(&inm->inm_srcs);

	ifma->ifma_protospec = inm;

	*pinm = inm;

	IF_ADDR_WUNLOCK(ifp);
	return (0);
}

/*
 * Drop a reference to an in_multi record.
 *
 * If the refcount drops to 0, free the in_multi record and
 * delete the underlying link-layer membership.
 */
void
ofp_inm_release_locked(struct ofp_in_multi *inm)
{
	struct ofp_ifmultiaddr *ifma;

	IN_MULTI_LOCK_ASSERT();

	CTR2(KTR_IGMPV3, "%s: refcount is %d", __func__, inm->inm_refcount);

	if (--inm->inm_refcount > 0) {
		CTR2(KTR_IGMPV3, "%s: refcount is now %d", __func__,
		    inm->inm_refcount);
		return;
	}

	CTR2(KTR_IGMPV3, "%s: freeing inm %p", __func__, inm);

	ifma = inm->inm_ifma;

	/* XXX this access is not covered by IF_ADDR_LOCK */
	CTR2(KTR_IGMPV3, "%s: purging ifma %p", __func__, ifma);
	KASSERT(ifma->ifma_protospec == inm,
	    ("%s: ifma_protospec != inm", __func__));
	ifma->ifma_protospec = NULL;

	inm_purge(inm);

	free(inm);

	ofp_if_delmulti_ifma(ifma);
}

/*
 * Clear recorded source entries for a group.
 * Used by the IGMP code. Caller must hold the IN_MULTI lock.
 * FIXME: Should reap.
 */
void
ofp_inm_clear_recorded(struct ofp_in_multi *inm)
{
	struct ofp_ip_msource	*ims;

	IN_MULTI_LOCK_ASSERT();

	RB_FOREACH(ims, ip_msource_tree, &inm->inm_srcs) {
		if (ims->ims_stp) {
			ims->ims_stp = 0;
			--inm->inm_st[1].iss_rec;
		}
	}
	KASSERT(inm->inm_st[1].iss_rec == 0,
	    ("%s: iss_rec %d not 0", __func__, inm->inm_st[1].iss_rec));
}

/*
 * Record a source as pending for a Source-Group IGMPv3 query.
 * This lives here as it modifies the shared tree.
 *
 * inm is the group descriptor.
 * naddr is the address of the source to record in network-byte order.
 *
 * If the net.inet.igmp.sgalloc sysctl is non-zero, we will
 * lazy-allocate a source node in response to an SG query.
 * Otherwise, no allocation is performed. This saves some memory
 * with the trade-off that the source will not be reported to the
 * router if joined in the window between the query response and
 * the group actually being joined on the local host.
 *
 * VIMAGE: XXX: Currently the igmp_sgalloc feature has been removed.
 * This turns off the allocation of a recorded source entry if
 * the group has not been joined.
 *
 * Return 0 if the source didn't exist or was already marked as recorded.
 * Return 1 if the source was marked as recorded by this function.
 * Return <0 if any error occured (negated errno code).
 */
int
ofp_inm_record_source(struct ofp_in_multi *inm, const ofp_in_addr_t naddr)
{
	struct ofp_ip_msource	 find;
	struct ofp_ip_msource	*ims, *nims;

	IN_MULTI_LOCK_ASSERT();

	find.ims_haddr = odp_be_to_cpu_32(naddr);
	ims = RB_FIND(ip_msource_tree, &inm->inm_srcs, &find);
	if (ims && ims->ims_stp)
		return (0);
	if (ims == NULL) {
		if (inm->inm_nsrc == in_mcast_maxgrpsrc)
			return (-OFP_ENOSPC);
		nims = malloc0(sizeof(struct ofp_ip_msource));
		if (nims == NULL)
			return (-OFP_ENOMEM);
		nims->ims_haddr = find.ims_haddr;
		RB_INSERT(ip_msource_tree, &inm->inm_srcs, nims);
		++inm->inm_nsrc;
		ims = nims;
	}

	/*
	 * Mark the source as recorded and update the recorded
	 * source count.
	 */
	++ims->ims_stp;
	++inm->inm_st[1].iss_rec;

	return (1);
}

/*
 * Return a pointer to an in_msource owned by an in_mfilter,
 * given its source address.
 * Lazy-allocate if needed. If this is a new entry its filter state is
 * undefined at t0.
 *
 * imf is the filter set being modified.
 * haddr is the source address in *host* byte-order.
 *
 * SMPng: May be called with locks held; malloc must not block.
 */
static int
imf_get_source(struct ofp_in_mfilter *imf, const struct ofp_sockaddr_in *psin,
    struct ofp_in_msource **plims)
{
	struct ofp_ip_msource	 find;
	struct ofp_ip_msource	*ims, *nims;
	struct ofp_in_msource	*lims;
	int			 error;

	error = 0;
	ims = NULL;
	lims = NULL;

	/* key is host byte order */
	find.ims_haddr = odp_be_to_cpu_32(psin->sin_addr.s_addr);
	ims = RB_FIND(ip_msource_tree, &imf->imf_sources, &find);
	lims = (struct ofp_in_msource *)ims;
	if (lims == NULL) {
		if (imf->imf_nsrc == in_mcast_maxsocksrc)
			return (OFP_ENOSPC);
		nims = malloc0(sizeof(struct ofp_in_msource));
		if (nims == NULL)
			return (OFP_ENOMEM);
		lims = (struct ofp_in_msource *)nims;
		lims->ims_haddr = find.ims_haddr;
		lims->imsl_st[0] = OFP_MCAST_UNDEFINED;
		RB_INSERT(ip_msource_tree, &imf->imf_sources, nims);
		++imf->imf_nsrc;
	}

	*plims = lims;

	return (error);
}

/*
 * Graft a source entry into an existing socket-layer filter set,
 * maintaining any required invariants and checking allocations.
 *
 * The source is marked as being in the new filter mode at t1.
 *
 * Return the pointer to the new node, otherwise return NULL.
 */
static struct ofp_in_msource *
imf_graft(struct ofp_in_mfilter *imf, const uint8_t st1,
    const struct ofp_sockaddr_in *psin)
{
	struct ofp_ip_msource	*nims;
	struct ofp_in_msource	*lims;

	nims = malloc0(sizeof(struct ofp_in_msource));
	if (nims == NULL)
		return (NULL);
	lims = (struct ofp_in_msource *)nims;
	lims->ims_haddr = odp_be_to_cpu_32(psin->sin_addr.s_addr);
	lims->imsl_st[0] = OFP_MCAST_UNDEFINED;
	lims->imsl_st[1] = st1;
	RB_INSERT(ip_msource_tree, &imf->imf_sources, nims);
	++imf->imf_nsrc;

	return (lims);
}

/*
 * Prune a source entry from an existing socket-layer filter set,
 * maintaining any required invariants and checking allocations.
 *
 * The source is marked as being left at t1, it is not freed.
 *
 * Return 0 if no error occurred, otherwise return an errno value.
 */
static int
imf_prune(struct ofp_in_mfilter *imf, const struct ofp_sockaddr_in *psin)
{
	struct ofp_ip_msource	 find;
	struct ofp_ip_msource	*ims;
	struct ofp_in_msource	*lims;

	/* key is host byte order */
	find.ims_haddr = odp_be_to_cpu_32(psin->sin_addr.s_addr);
	ims = RB_FIND(ip_msource_tree, &imf->imf_sources, &find);
	if (ims == NULL)
		return (OFP_ENOENT);
	lims = (struct ofp_in_msource *)ims;
	lims->imsl_st[1] = OFP_MCAST_UNDEFINED;
	return (0);
}

/*
 * Revert socket-layer filter set deltas at t1 to t0 state.
 */
static void
imf_rollback(struct ofp_in_mfilter *imf)
{
	struct ofp_ip_msource	*ims, *tims;
	struct ofp_in_msource	*lims;

	RB_FOREACH_SAFE(ims, ip_msource_tree, &imf->imf_sources, tims) {
		lims = (struct ofp_in_msource *)ims;
		if (lims->imsl_st[0] == lims->imsl_st[1]) {
			/* no change at t1 */
			continue;
		} else if (lims->imsl_st[0] != OFP_MCAST_UNDEFINED) {
			/* revert change to existing source at t1 */
			lims->imsl_st[1] = lims->imsl_st[0];
		} else {
			/* revert source added t1 */
			CTR2(KTR_IGMPV3, "%s: free ims %p", __func__, ims);
			RB_REMOVE(ip_msource_tree, &imf->imf_sources, ims);
			free(ims);
			imf->imf_nsrc--;
		}
	}
	imf->imf_st[1] = imf->imf_st[0];
}

/*
 * Mark socket-layer filter set as INCLUDE {} at t1.
 */
static void
imf_leave(struct ofp_in_mfilter *imf)
{
	struct ofp_ip_msource	*ims;
	struct ofp_in_msource	*lims;

	RB_FOREACH(ims, ip_msource_tree, &imf->imf_sources) {
		lims = (struct ofp_in_msource *)ims;
		lims->imsl_st[1] = OFP_MCAST_UNDEFINED;
	}
	imf->imf_st[1] = OFP_MCAST_INCLUDE;
}

/*
 * Mark socket-layer filter set deltas as committed.
 */
static void
imf_commit(struct ofp_in_mfilter *imf)
{
	struct ofp_ip_msource	*ims;
	struct ofp_in_msource	*lims;

	RB_FOREACH(ims, ip_msource_tree, &imf->imf_sources) {
		lims = (struct ofp_in_msource *)ims;
		lims->imsl_st[0] = lims->imsl_st[1];
	}
	imf->imf_st[0] = imf->imf_st[1];
}

/*
 * Reap unreferenced sources from socket-layer filter set.
 */
static void
imf_reap(struct ofp_in_mfilter *imf)
{
	struct ofp_ip_msource	*ims, *tims;
	struct ofp_in_msource	*lims;

	RB_FOREACH_SAFE(ims, ip_msource_tree, &imf->imf_sources, tims) {
		lims = (struct ofp_in_msource *)ims;
		if ((lims->imsl_st[0] == OFP_MCAST_UNDEFINED) &&
		    (lims->imsl_st[1] == OFP_MCAST_UNDEFINED)) {
			CTR2(KTR_IGMPV3, "%s: free lims %p", __func__, ims);
			RB_REMOVE(ip_msource_tree, &imf->imf_sources, ims);
			free(ims);
			imf->imf_nsrc--;
		}
	}
}

/*
 * Purge socket-layer filter set.
 */
static void
imf_purge(struct ofp_in_mfilter *imf)
{
	struct ofp_ip_msource	*ims, *tims;

	RB_FOREACH_SAFE(ims, ip_msource_tree, &imf->imf_sources, tims) {
		CTR2(KTR_IGMPV3, "%s: free ims %p", __func__, ims);
		RB_REMOVE(ip_msource_tree, &imf->imf_sources, ims);
		free(ims);
		imf->imf_nsrc--;
	}
	imf->imf_st[0] = imf->imf_st[1] = OFP_MCAST_UNDEFINED;
	KASSERT(RB_EMPTY(&imf->imf_sources),
	    ("%s: imf_sources not empty", __func__));
}

/*
 * Look up a source filter entry for a multicast group.
 *
 * inm is the group descriptor to work with.
 * haddr is the host-byte-order IPv4 address to look up.
 * noalloc may be non-zero to suppress allocation of sources.
 * *pims will be set to the address of the retrieved or allocated source.
 *
 * SMPng: NOTE: may be called with locks held.
 * Return 0 if successful, otherwise return a non-zero error code.
 */
static int
inm_get_source(struct ofp_in_multi *inm, const ofp_in_addr_t haddr,
    const int noalloc, struct ofp_ip_msource **pims)
{
	struct ofp_ip_msource	 find;
	struct ofp_ip_msource	*ims, *nims;
#ifdef KTR
	struct ofp_in_addr ia;
#endif

	find.ims_haddr = haddr;
	ims = RB_FIND(ip_msource_tree, &inm->inm_srcs, &find);
	if (ims == NULL && !noalloc) {
		if (inm->inm_nsrc == in_mcast_maxgrpsrc)
			return (OFP_ENOSPC);
		nims = malloc0(sizeof(struct ofp_ip_msource));
		if (nims == NULL)
			return (OFP_ENOMEM);
		nims->ims_haddr = haddr;
		RB_INSERT(ip_msource_tree, &inm->inm_srcs, nims);
		++inm->inm_nsrc;
		ims = nims;
#ifdef KTR
		ia.s_addr = odp_cpu_to_be_32(haddr);
		CTR3(KTR_IGMPV3, "%s: allocated %s as %p", __func__,
		    inet_ntoa(ia), ims);
#endif
	}

	*pims = ims;
	return (0);
}

/*
 * Merge socket-layer source into IGMP-layer source.
 * If rollback is non-zero, perform the inverse of the merge.
 */
static void
ims_merge(struct ofp_ip_msource *ims, const struct ofp_in_msource *lims,
    const int rollback)
{
	int n = rollback ? -1 : 1;
#ifdef KTR
	struct ofp_in_addr ia;

	ia.s_addr = odp_cpu_to_be_32(ims->ims_haddr);
#endif

	if (lims->imsl_st[0] == OFP_MCAST_EXCLUDE) {
		CTR3(KTR_IGMPV3, "%s: t1 ex -= %d on %s",
		  __func__, n, inet_ntoa(ia));
		ims->ims_st[1].ex -= n;
	} else if (lims->imsl_st[0] == OFP_MCAST_INCLUDE) {
		CTR3(KTR_IGMPV3, "%s: t1 in -= %d on %s",
		  __func__, n, inet_ntoa(ia));
		ims->ims_st[1].in -= n;
	}

	if (lims->imsl_st[1] == OFP_MCAST_EXCLUDE) {
		CTR3(KTR_IGMPV3, "%s: t1 ex += %d on %s",
		  __func__, n, inet_ntoa(ia));
		ims->ims_st[1].ex += n;
	} else if (lims->imsl_st[1] == OFP_MCAST_INCLUDE) {
		CTR3(KTR_IGMPV3, "%s: t1 in += %d on %s",
		  __func__, n, inet_ntoa(ia));
		ims->ims_st[1].in += n;
	}
}

/*
 * Atomically update the global in_multi state, when a membership's
 * filter list is being updated in any way.
 *
 * imf is the per-inpcb-membership group filter pointer.
 * A fake imf may be passed for in-kernel consumers.
 *
 * XXX This is a candidate for a set-symmetric-difference style loop
 * which would eliminate the repeated lookup from root of ims nodes,
 * as they share the same key space.
 *
 * If any error occurred this function will back out of refcounts
 * and return a non-zero value.
 */
static int
inm_merge(struct ofp_in_multi *inm, /*const*/ struct ofp_in_mfilter *imf)
{
	struct ofp_ip_msource	*ims, *nims;
	struct ofp_in_msource	*lims;
	int			 schanged, error;
	int			 nsrc0, nsrc1;

	schanged = 0;
	error = 0;
	nsrc1 = nsrc0 = 0;

	/*
	 * Update the source filters first, as this may fail.
	 * Maintain count of in-mode filters at t0, t1. These are
	 * used to work out if we transition into ASM mode or not.
	 * Maintain a count of source filters whose state was
	 * actually modified by this operation.
	 */
	RB_FOREACH(ims, ip_msource_tree, &imf->imf_sources) {
		lims = (struct ofp_in_msource *)ims;
		if (lims->imsl_st[0] == imf->imf_st[0]) nsrc0++;
		if (lims->imsl_st[1] == imf->imf_st[1]) nsrc1++;
		if (lims->imsl_st[0] == lims->imsl_st[1]) continue;
		error = inm_get_source(inm, lims->ims_haddr, 0, &nims);
		++schanged;
		if (error)
			break;
		ims_merge(nims, lims, 0);
	}
	if (error) {
		struct ofp_ip_msource *bims;

		RB_FOREACH_REVERSE_FROM(ims, ip_msource_tree, nims) {
			lims = (struct ofp_in_msource *)ims;
			if (lims->imsl_st[0] == lims->imsl_st[1])
				continue;
			(void)inm_get_source(inm, lims->ims_haddr, 1, &bims);
			if (bims == NULL)
				continue;
			ims_merge(bims, lims, 1);
		}
		goto out_reap;
	}

	CTR3(KTR_IGMPV3, "%s: imf filters in-mode: %d at t0, %d at t1",
	    __func__, nsrc0, nsrc1);

	/* Handle transition between INCLUDE {n} and INCLUDE {} on socket. */
	if (imf->imf_st[0] == imf->imf_st[1] &&
	    imf->imf_st[1] == OFP_MCAST_INCLUDE) {
		if (nsrc1 == 0) {
			CTR1(KTR_IGMPV3, "%s: --in on inm at t1", __func__);
			--inm->inm_st[1].iss_in;
		}
	}

	/* Handle filter mode transition on socket. */
	if (imf->imf_st[0] != imf->imf_st[1]) {
		CTR3(KTR_IGMPV3, "%s: imf transition %d to %d",
		    __func__, imf->imf_st[0], imf->imf_st[1]);

		if (imf->imf_st[0] == OFP_MCAST_EXCLUDE) {
			CTR1(KTR_IGMPV3, "%s: --ex on inm at t1", __func__);
			--inm->inm_st[1].iss_ex;
		} else if (imf->imf_st[0] == OFP_MCAST_INCLUDE) {
			CTR1(KTR_IGMPV3, "%s: --in on inm at t1", __func__);
			--inm->inm_st[1].iss_in;
		}

		if (imf->imf_st[1] == OFP_MCAST_EXCLUDE) {
			CTR1(KTR_IGMPV3, "%s: ex++ on inm at t1", __func__);
			inm->inm_st[1].iss_ex++;
		} else if (imf->imf_st[1] == OFP_MCAST_INCLUDE && nsrc1 > 0) {
			CTR1(KTR_IGMPV3, "%s: in++ on inm at t1", __func__);
			inm->inm_st[1].iss_in++;
		}
	}

	/*
	 * Track inm filter state in terms of listener counts.
	 * If there are any exclusive listeners, stack-wide
	 * membership is exclusive.
	 * Otherwise, if only inclusive listeners, stack-wide is inclusive.
	 * If no listeners remain, state is undefined at t1,
	 * and the IGMP lifecycle for this group should finish.
	 */
	if (inm->inm_st[1].iss_ex > 0) {
		CTR1(KTR_IGMPV3, "%s: transition to EX", __func__);
		inm->inm_st[1].iss_fmode = OFP_MCAST_EXCLUDE;
	} else if (inm->inm_st[1].iss_in > 0) {
		CTR1(KTR_IGMPV3, "%s: transition to IN", __func__);
		inm->inm_st[1].iss_fmode = OFP_MCAST_INCLUDE;
	} else {
		CTR1(KTR_IGMPV3, "%s: transition to UNDEF", __func__);
		inm->inm_st[1].iss_fmode = OFP_MCAST_UNDEFINED;
	}

	/* Decrement ASM listener count on transition out of ASM mode. */
	if (imf->imf_st[0] == OFP_MCAST_EXCLUDE && nsrc0 == 0) {
		if ((imf->imf_st[1] != OFP_MCAST_EXCLUDE) ||
		    (imf->imf_st[1] == OFP_MCAST_EXCLUDE && nsrc1 > 0)) {
			CTR1(KTR_IGMPV3, "%s: --asm on inm at t1", __func__);
			--inm->inm_st[1].iss_asm;
		}
	}

	/* Increment ASM listener count on transition to ASM mode. */
	if (imf->imf_st[1] == OFP_MCAST_EXCLUDE && nsrc1 == 0) {
		CTR1(KTR_IGMPV3, "%s: asm++ on inm at t1", __func__);
		inm->inm_st[1].iss_asm++;
	}

	CTR3(KTR_IGMPV3, "%s: merged imf %p to inm %p", __func__, imf, inm);
	ofp_inm_print(inm);

out_reap:
	if (schanged > 0) {
		CTR1(KTR_IGMPV3, "%s: sources changed; reaping", __func__);
		inm_reap(inm);
	}
	return (error);
}

/*
 * Mark an in_multi's filter set deltas as committed.
 * Called by IGMP after a state change has been enqueued.
 */
void
ofp_inm_commit(struct ofp_in_multi *inm)
{
	struct ofp_ip_msource	*ims;

	CTR2(KTR_IGMPV3, "%s: commit inm %p", __func__, inm);
	CTR1(KTR_IGMPV3, "%s: pre commit:", __func__);
	ofp_inm_print(inm);

	RB_FOREACH(ims, ip_msource_tree, &inm->inm_srcs) {
		ims->ims_st[0] = ims->ims_st[1];
	}
	inm->inm_st[0] = inm->inm_st[1];
}

/*
 * Reap unreferenced nodes from an in_multi's filter set.
 */
static void
inm_reap(struct ofp_in_multi *inm)
{
	struct ofp_ip_msource	*ims, *tims;

	RB_FOREACH_SAFE(ims, ip_msource_tree, &inm->inm_srcs, tims) {
		if (ims->ims_st[0].ex > 0 || ims->ims_st[0].in > 0 ||
		    ims->ims_st[1].ex > 0 || ims->ims_st[1].in > 0 ||
		    ims->ims_stp != 0)
			continue;
		CTR2(KTR_IGMPV3, "%s: free ims %p", __func__, ims);
		RB_REMOVE(ip_msource_tree, &inm->inm_srcs, ims);
		free(ims);
		inm->inm_nsrc--;
	}
}

/*
 * Purge all source nodes from an in_multi's filter set.
 */
static void
inm_purge(struct ofp_in_multi *inm)
{
	struct ofp_ip_msource	*ims, *tims;

	RB_FOREACH_SAFE(ims, ip_msource_tree, &inm->inm_srcs, tims) {
		CTR2(KTR_IGMPV3, "%s: free ims %p", __func__, ims);
		RB_REMOVE(ip_msource_tree, &inm->inm_srcs, ims);
		free(ims);
		inm->inm_nsrc--;
	}
}

/*
 * Join a multicast group; unlocked entry point.
 *
 * SMPng: XXX: ofp_in_joingroup() is called from in_control() when Giant
 * is not held. Fortunately, ifp is unlikely to have been detached
 * at this point, so we assume it's OK to recurse.
 */
int
ofp_in_joingroup(struct ofp_ifnet *ifp, const struct ofp_in_addr *gina,
    /*const*/ struct ofp_in_mfilter *imf, struct ofp_in_multi **pinm)
{
	int error;

	IN_MULTI_LOCK();
	error = ofp_in_joingroup_locked(ifp, gina, imf, pinm);
	IN_MULTI_UNLOCK();

	return (error);
}

/*
 * Join a multicast group; real entry point.
 *
 * Only preserves atomicity at inm level.
 * NOTE: imf argument cannot be const due to sys/tree.h limitations.
 *
 * If the IGMP downcall fails, the group is not joined, and an error
 * code is returned.
 */
int
ofp_in_joingroup_locked(struct ofp_ifnet *ifp, const struct ofp_in_addr *gina,
    /*const*/ struct ofp_in_mfilter *imf, struct ofp_in_multi **pinm)
{
	struct ofp_in_mfilter	 timf;
	struct ofp_in_multi	*inm;
	int			 error;

	IN_MULTI_LOCK_ASSERT();

	CTR4(KTR_IGMPV3, "%s: join %s on %p(%s))", __func__,
	    inet_ntoa(*gina), ifp, ifp->if_name);

	error = 0;
	inm = NULL;

	/*
	 * If no imf was specified (i.e. kernel consumer),
	 * fake one up and assume it is an ASM join.
	 */
	if (imf == NULL) {
		imf_init(&timf, OFP_MCAST_UNDEFINED, OFP_MCAST_EXCLUDE);
		imf = &timf;
	}

	error = in_getmulti(ifp, gina, &inm);
	if (error) {
		CTR1(KTR_IGMPV3, "%s: in_getmulti() failure", __func__);
		return (error);
	}

	CTR1(KTR_IGMPV3, "%s: merge inm state", __func__);
	error = inm_merge(inm, imf);
	if (error) {
		CTR1(KTR_IGMPV3, "%s: failed to merge inm state", __func__);
		goto out_inm_release;
	}

	CTR1(KTR_IGMPV3, "%s: doing igmp downcall", __func__);
	error = ofp_igmp_change_state(inm);
	if (error) {
		CTR1(KTR_IGMPV3, "%s: failed to update source", __func__);
		goto out_inm_release;
	}

out_inm_release:
	if (error) {
		CTR2(KTR_IGMPV3, "%s: dropping ref on %p", __func__, inm);
		ofp_inm_release_locked(inm);
	} else {
		*pinm = inm;
	}

	return (error);
}

/*
 * Leave a multicast group; unlocked entry point.
 */
int
ofp_in_leavegroup(struct ofp_in_multi *inm, /*const*/ struct ofp_in_mfilter *imf)
{
	struct ofp_ifnet *ifp;
	int error;

	ifp = inm->inm_ifp;
	(void)ifp;

	IN_MULTI_LOCK();
	error = ofp_in_leavegroup_locked(inm, imf);
	IN_MULTI_UNLOCK();

	return (error);
}

/*
 * Leave a multicast group; real entry point.
 * All source filters will be expunged.
 *
 * Only preserves atomicity at inm level.
 *
 * Holding the write lock for the INP which contains imf
 * is highly advisable. We can't assert for it as imf does not
 * contain a back-pointer to the owning inp.
 *
 * Note: This is not the same as inm_release(*) as this function also
 * makes a state change downcall into IGMP.
 */
int
ofp_in_leavegroup_locked(struct ofp_in_multi *inm, /*const*/ struct ofp_in_mfilter *imf)
{
	struct ofp_in_mfilter	 timf;
	int			 error;

	error = 0;

	IN_MULTI_LOCK_ASSERT();

	CTR5(KTR_IGMPV3, "%s: leave inm %p, %s/%s, imf %p", __func__,
	    inm, inet_ntoa(inm->inm_addr),
	    (inm_is_ifp_detached(inm) ? "null" : inm->inm_ifp->if_name),
	    imf);

	/*
	 * If no imf was specified (i.e. kernel consumer),
	 * fake one up and assume it is an ASM join.
	 */
	if (imf == NULL) {
		imf_init(&timf, OFP_MCAST_EXCLUDE, OFP_MCAST_UNDEFINED);
		imf = &timf;
	}

	/*
	 * Begin state merge transaction at IGMP layer.
	 *
	 * As this particular invocation should not cause any memory
	 * to be allocated, and there is no opportunity to roll back
	 * the transaction, it MUST NOT fail.
	 */
	CTR1(KTR_IGMPV3, "%s: merge inm state", __func__);
	error = inm_merge(inm, imf);
	KASSERT(error == 0, ("%s: failed to merge inm state", __func__));

	CTR1(KTR_IGMPV3, "%s: doing igmp downcall", __func__);
	error = ofp_igmp_change_state(inm);
	if (error)
		CTR1(KTR_IGMPV3, "%s: failed igmp downcall", __func__);

	CTR2(KTR_IGMPV3, "%s: dropping ref on %p", __func__, inm);
	ofp_inm_release_locked(inm);

	return (error);
}

/*#ifndef BURN_BRIDGES*/
/*
 * Join an IPv4 multicast group in (*,G) exclusive mode.
 * The group must be a 224.0.0.0/24 link-scope group.
 * This KPI is for legacy kernel consumers only.
 */
struct ofp_in_multi *
ofp_in_addmulti(struct ofp_in_addr *ap, struct ofp_ifnet *ifp)
{
	struct ofp_in_multi *pinm;
	int error;

	KASSERT(OFP_IN_LOCAL_GROUP(odp_be_to_cpu_32(ap->s_addr)),
	    ("%s: %s not in 224.0.0.0/24", __func__, inet_ntoa(*ap)));

	error = ofp_in_joingroup(ifp, ap, NULL, &pinm);
	if (error != 0)
		pinm = NULL;

	return (pinm);
}

/*
 * Leave an IPv4 multicast group, assumed to be in exclusive (*,G) mode.
 * This KPI is for legacy kernel consumers only.
 */
void
ofp_in_delmulti(struct ofp_in_multi *inm)
{

	(void)ofp_in_leavegroup(inm, NULL);
}
/*#endif*/

/*
 * Block or unblock an ASM multicast source on an inpcb.
 * This implements the delta-based API described in RFC 3678.
 *
 * The delta-based API applies only to exclusive-mode memberships.
 * An IGMP downcall will be performed.
 *
 * SMPng: NOTE: Must take Giant as a join may create a new ifma.
 *
 * Return 0 if successful, otherwise return an appropriate error code.
 */
static int
inp_block_unblock_source(struct inpcb *inp, struct sockopt *sopt)
{
	struct ofp_group_source_req	 gsr;
	sockunion_t			*gsa, *ssa;
	struct ofp_ifnet		*ifp;
	struct ofp_in_mfilter		*imf;
	struct ofp_ip_moptions		*imo;
	struct ofp_in_msource		*ims;
	struct ofp_in_multi		*inm;
	size_t				 idx;
	uint16_t			 fmode;
	int				 error, doblock;

	ifp = NULL;
	error = 0;
	doblock = 0;

	memset(&gsr, 0, sizeof(struct ofp_group_source_req));
	gsa = (sockunion_t *)&gsr.gsr_group;
	ssa = (sockunion_t *)&gsr.gsr_source;

	switch (sopt->sopt_name) {
	case OFP_IP_BLOCK_SOURCE:
	case OFP_IP_UNBLOCK_SOURCE: {
		struct ofp_ip_mreq_source	 mreqs;

		error = ofp_sooptcopyin(sopt, &mreqs,
		    sizeof(struct ofp_ip_mreq_source),
		    sizeof(struct ofp_ip_mreq_source));
		if (error)
			return (error);

		gsa->sin.sin_family = OFP_AF_INET;
		gsa->sin.sin_len = sizeof(struct ofp_sockaddr_in);
		gsa->sin.sin_addr = mreqs.imr_multiaddr;

		ssa->sin.sin_family = OFP_AF_INET;
		ssa->sin.sin_len = sizeof(struct ofp_sockaddr_in);
		ssa->sin.sin_addr = mreqs.imr_sourceaddr;

		if (!ofp_in_nullhost(mreqs.imr_interface))
			OFP_INADDR_TO_IFP(mreqs.imr_interface, ifp);

		if (sopt->sopt_name == OFP_IP_BLOCK_SOURCE)
			doblock = 1;

		CTR3(KTR_IGMPV3, "%s: imr_interface = %s, ifp = %p",
		    __func__, inet_ntoa(mreqs.imr_interface), ifp);
		break;
	    }

	case OFP_MCAST_BLOCK_SOURCE:
	case OFP_MCAST_UNBLOCK_SOURCE:
		error = ofp_sooptcopyin(sopt, &gsr,
		    sizeof(struct ofp_group_source_req),
		    sizeof(struct ofp_group_source_req));
		if (error)
			return (error);

		if (gsa->sin.sin_family != OFP_AF_INET ||
		    gsa->sin.sin_len != sizeof(struct ofp_sockaddr_in))
			return (OFP_EINVAL);

		if (ssa->sin.sin_family != OFP_AF_INET ||
		    ssa->sin.sin_len != sizeof(struct ofp_sockaddr_in))
			return (OFP_EINVAL);

		if (gsr.gsr_interface == 0 || V_if_index < gsr.gsr_interface)
			return (OFP_EADDRNOTAVAIL);

		ifp = ifnet_byindex(gsr.gsr_interface);

		if (sopt->sopt_name == OFP_MCAST_BLOCK_SOURCE)
			doblock = 1;
		break;

	default:
		CTR2(KTR_IGMPV3, "%s: unknown sopt_name %d",
		    __func__, sopt->sopt_name);
		return (OFP_EOPNOTSUPP);
		break;
	}

	if (!OFP_IN_MULTICAST(odp_be_to_cpu_32(gsa->sin.sin_addr.s_addr)))
		return (OFP_EINVAL);

	/*
	 * Check if we are actually a member of this group.
	 */
	imo = inp_findmoptions(inp);
	idx = imo_match_group(imo, ifp, &gsa->sa);
	if ((int)idx == -1 || imo->imo_mfilters == NULL) {
		error = OFP_EADDRNOTAVAIL;
		goto out_inp_locked;
	}

	KASSERT(imo->imo_mfilters != NULL,
	    ("%s: imo_mfilters not allocated", __func__));
	imf = &imo->imo_mfilters[idx];
	inm = imo->imo_membership[idx];

	/*
	 * Attempting to use the delta-based API on an
	 * non exclusive-mode membership is an error.
	 */
	fmode = imf->imf_st[0];
	if (fmode != OFP_MCAST_EXCLUDE) {
		error = OFP_EINVAL;
		goto out_inp_locked;
	}

	/*
	 * Deal with error cases up-front:
	 *  Asked to block, but already blocked; or
	 *  Asked to unblock, but nothing to unblock.
	 * If adding a new block entry, allocate it.
	 */
	ims = imo_match_source(imo, idx, &ssa->sa);
	if ((ims != NULL && doblock) || (ims == NULL && !doblock)) {
		CTR3(KTR_IGMPV3, "%s: source %s %spresent", __func__,
		    inet_ntoa(ssa->sin.sin_addr), doblock ? "" : "not ");
		error = OFP_EADDRNOTAVAIL;
		goto out_inp_locked;
	}

	INP_WLOCK_ASSERT(inp);

	/*
	 * Begin state merge transaction at socket layer.
	 */
	if (doblock) {
		CTR2(KTR_IGMPV3, "%s: %s source", __func__, "block");
		ims = imf_graft(imf, fmode, &ssa->sin);
		if (ims == NULL)
			error = OFP_ENOMEM;
	} else {
		CTR2(KTR_IGMPV3, "%s: %s source", __func__, "allow");
		error = imf_prune(imf, &ssa->sin);
	}

	if (error) {
		CTR1(KTR_IGMPV3, "%s: merge imf state failed", __func__);
		goto out_imf_rollback;
	}

	/*
	 * Begin state merge transaction at IGMP layer.
	 */
	IN_MULTI_LOCK();

	CTR1(KTR_IGMPV3, "%s: merge inm state", __func__);
	error = inm_merge(inm, imf);
	if (error) {
		CTR1(KTR_IGMPV3, "%s: failed to merge inm state", __func__);
		goto out_imf_rollback;
	}

	CTR1(KTR_IGMPV3, "%s: doing igmp downcall", __func__);
	error = ofp_igmp_change_state(inm);
	if (error)
		CTR1(KTR_IGMPV3, "%s: failed igmp downcall", __func__);

	IN_MULTI_UNLOCK();

out_imf_rollback:
	if (error)
		imf_rollback(imf);
	else
		imf_commit(imf);

	imf_reap(imf);

out_inp_locked:
	INP_WUNLOCK(inp);
	return (error);
}

/*
 * Given an inpcb, return its multicast options structure pointer.  Accepts
 * an unlocked inpcb pointer, but will return it locked.  May sleep.
 *
 * SMPng: NOTE: Potentially calls malloc(M_WAITOK) with Giant held.
 * SMPng: NOTE: Returns with the INP write lock held.
 */
static struct ofp_ip_moptions *
inp_findmoptions(struct inpcb *inp)
{
	struct ofp_ip_moptions	 *imo;
	struct ofp_in_multi	**immp;
	struct ofp_in_mfilter	 *imfp;
	size_t			  idx;

	INP_WLOCK(inp);
	if (inp->inp_moptions != NULL)
		return (inp->inp_moptions);

	INP_WUNLOCK(inp);

	imo = malloc(sizeof(*imo));
	immp = malloc0(sizeof(*immp) * OFP_IP_MIN_MEMBERSHIPS);
	imfp = malloc(sizeof(struct ofp_in_mfilter) * OFP_IP_MIN_MEMBERSHIPS);

	imo->imo_multicast_ifp = NULL;
	imo->imo_multicast_addr.s_addr = OFP_INADDR_ANY;
	imo->imo_multicast_vif = -1;
	imo->imo_multicast_ttl = OFP_IP_DEFAULT_MULTICAST_TTL;
	imo->imo_multicast_loop = ofp_in_mcast_loop;
	imo->imo_num_memberships = 0;
	imo->imo_max_memberships = OFP_IP_MIN_MEMBERSHIPS;
	imo->imo_membership = immp;

	/* Initialize per-group source filters. */
	for (idx = 0; idx < OFP_IP_MIN_MEMBERSHIPS; idx++)
		imf_init(&imfp[idx], OFP_MCAST_UNDEFINED, OFP_MCAST_EXCLUDE);
	imo->imo_mfilters = imfp;

	INP_WLOCK(inp);
	if (inp->inp_moptions != NULL) {
		free(imfp);
		free(immp);
		free(imo);
		return (inp->inp_moptions);
	}
	inp->inp_moptions = imo;
	return (imo);
}

/*
 * Discard the IP multicast options (and source filters).
 *
 * SMPng: NOTE: assumes INP write lock is held.
 */
void
ofp_inp_freemoptions(struct ofp_ip_moptions *imo)
{
	struct ofp_in_mfilter	*imf;
	size_t			 idx, nmships;

	KASSERT(imo != NULL, ("%s: ip_moptions is NULL", __func__));

	nmships = imo->imo_num_memberships;
	for (idx = 0; idx < nmships; ++idx) {
		imf = imo->imo_mfilters ? &imo->imo_mfilters[idx] : NULL;
		if (imf)
			imf_leave(imf);
		(void)ofp_in_leavegroup(imo->imo_membership[idx], imf);
		if (imf)
			imf_purge(imf);
	}

	if (imo->imo_mfilters)
		free(imo->imo_mfilters);
	free(imo->imo_membership);
	free(imo);
}

/*
 * Atomically get source filters on a socket for an IPv4 multicast group.
 * Called with INP lock held; returns with lock released.
 */
static int
inp_get_source_filters(struct inpcb *inp, struct sockopt *sopt)
{
	struct __msfilterreq	 msfr;
	sockunion_t		*gsa;
	struct ofp_ifnet		*ifp;
	struct ofp_ip_moptions	*imo;
	struct ofp_in_mfilter	*imf;
	struct ofp_ip_msource	*ims;
	struct ofp_in_msource	*lims;
	struct ofp_sockaddr_in	*psin;
	struct ofp_sockaddr_storage_2	*ptss;
	struct ofp_sockaddr_storage_2	*tss;
	int			 error;
	size_t			 idx, nsrcs, ncsrcs;

	INP_WLOCK_ASSERT(inp);

	imo = inp->inp_moptions;
	KASSERT(imo != NULL, ("%s: null ip_moptions", __func__));

	INP_WUNLOCK(inp);

	error = ofp_sooptcopyin(sopt, &msfr, sizeof(struct __msfilterreq),
	    sizeof(struct __msfilterreq));
	if (error)
		return (error);

	if (msfr.msfr_ifindex == 0 || V_if_index < msfr.msfr_ifindex)
		return (OFP_EINVAL);

	ifp = ifnet_byindex(msfr.msfr_ifindex);
	if (ifp == NULL)
		return (OFP_EINVAL);

	INP_WLOCK(inp);

	/*
	 * Lookup group on the socket.
	 */
	gsa = (sockunion_t *)&msfr.msfr_group;
	idx = imo_match_group(imo, ifp, &gsa->sa);
	if ((int)idx == -1 || imo->imo_mfilters == NULL) {
		INP_WUNLOCK(inp);
		return (OFP_EADDRNOTAVAIL);
	}
	imf = &imo->imo_mfilters[idx];

	/*
	 * Ignore memberships which are in limbo.
	 */
	if (imf->imf_st[1] == OFP_MCAST_UNDEFINED) {
		INP_WUNLOCK(inp);
		return (OFP_EAGAIN);
	}
	msfr.msfr_fmode = imf->imf_st[1];

	/*
	 * If the user specified a buffer, copy out the source filter
	 * entries to userland gracefully.
	 * We only copy out the number of entries which userland
	 * has asked for, but we always tell userland how big the
	 * buffer really needs to be.
	 */
	tss = NULL;
	if (msfr.msfr_srcs != NULL && msfr.msfr_nsrcs > 0) {
		tss = malloc0(sizeof(struct ofp_sockaddr_storage_2) * msfr.msfr_nsrcs);
		if (tss == NULL) {
			INP_WUNLOCK(inp);
			return (OFP_ENOBUFS);
		}
	}

	/*
	 * Count number of sources in-mode at t0.
	 * If buffer space exists and remains, copy out source entries.
	 */
	nsrcs = msfr.msfr_nsrcs;
	ncsrcs = 0;
	ptss = tss;
	RB_FOREACH(ims, ip_msource_tree, &imf->imf_sources) {
		lims = (struct ofp_in_msource *)ims;
		if (lims->imsl_st[0] == OFP_MCAST_UNDEFINED ||
		    lims->imsl_st[0] != imf->imf_st[0])
			continue;
		++ncsrcs;
		if (tss != NULL && nsrcs > 0) {
			psin = (struct ofp_sockaddr_in *)ptss;
			psin->sin_family = OFP_AF_INET;
			psin->sin_len = sizeof(struct ofp_sockaddr_in);
			psin->sin_addr.s_addr = odp_cpu_to_be_32(lims->ims_haddr);
			psin->sin_port = 0;
			++ptss;
			--nsrcs;
		}
	}

	INP_WUNLOCK(inp);

	if (tss != NULL) {
		error = copyout(tss, msfr.msfr_srcs,
		    sizeof(struct ofp_sockaddr_storage_2) * msfr.msfr_nsrcs);
		free(tss);
		if (error)
			return (error);
	}

	msfr.msfr_nsrcs = ncsrcs;
	error = ofp_sooptcopyout(sopt, &msfr, sizeof(struct __msfilterreq));

	return (error);
}

/*
 * Return the IP multicast options in response to user getsockopt().
 */
int
ofp_inp_getmoptions(struct inpcb *inp, struct sockopt *sopt)
{
	struct ofp_ip_mreqn	 mreqn;
	struct ofp_ip_moptions	*imo;
	struct ofp_ifnet	*ifp;
	//struct in_ifaddr	*ia;
	int			 error, optval;
	uint8_t			 coptval;

	INP_WLOCK(inp);
	imo = inp->inp_moptions;
	/*
	 * If socket is neither of type OFP_SOCK_RAW or OFP_SOCK_DGRAM,
	 * or is a divert socket, reject it.
	 */
	if (inp->inp_socket->so_proto->pr_protocol == OFP_IPPROTO_DIVERT ||
	    (inp->inp_socket->so_proto->pr_type != OFP_SOCK_RAW &&
	    inp->inp_socket->so_proto->pr_type != OFP_SOCK_DGRAM)) {
		INP_WUNLOCK(inp);
		return (OFP_EOPNOTSUPP);
	}

	error = 0;
	switch (sopt->sopt_name) {
	case OFP_IP_MULTICAST_VIF:
		if (imo != NULL)
			optval = imo->imo_multicast_vif;
		else
			optval = -1;
		INP_WUNLOCK(inp);
		error = ofp_sooptcopyout(sopt, &optval, sizeof(int));
		break;

	case OFP_IP_MULTICAST_IF:
		memset(&mreqn, 0, sizeof(struct ofp_ip_mreqn));
		if (imo != NULL) {
			ifp = imo->imo_multicast_ifp;
			if (!ofp_in_nullhost(imo->imo_multicast_addr)) {
				mreqn.imr_address = imo->imo_multicast_addr;
			} else if (ifp != NULL) {
				mreqn.imr_ifindex = if_index(ifp);
				mreqn.imr_address.s_addr = ifp->ip_addr_info[0].ip_addr;
			}
		}
		INP_WUNLOCK(inp);
		if (sopt->sopt_valsize == sizeof(struct ofp_ip_mreqn)) {
			error = ofp_sooptcopyout(sopt, &mreqn,
			    sizeof(struct ofp_ip_mreqn));
		} else {
			error = ofp_sooptcopyout(sopt, &mreqn.imr_address,
			    sizeof(struct ofp_in_addr));
		}
		break;

	case OFP_IP_MULTICAST_TTL:
		if (imo == 0)
			optval = coptval = OFP_IP_DEFAULT_MULTICAST_TTL;
		else
			optval = coptval = imo->imo_multicast_ttl;
		INP_WUNLOCK(inp);
		if (sopt->sopt_valsize == sizeof(uint8_t))
			error = ofp_sooptcopyout(sopt, &coptval, sizeof(uint8_t));
		else
			error = ofp_sooptcopyout(sopt, &optval, sizeof(int));
		break;

	case OFP_IP_MULTICAST_LOOP:
		if (imo == 0)
			optval = coptval = OFP_IP_DEFAULT_MULTICAST_LOOP;
		else
			optval = coptval = imo->imo_multicast_loop;
		INP_WUNLOCK(inp);
		if (sopt->sopt_valsize == sizeof(uint8_t))
			error = ofp_sooptcopyout(sopt, &coptval, sizeof(uint8_t));
		else
			error = ofp_sooptcopyout(sopt, &optval, sizeof(int));
		break;

	case OFP_IP_MSFILTER:
		if (imo == NULL) {
			error = OFP_EADDRNOTAVAIL;
			INP_WUNLOCK(inp);
		} else {
			error = inp_get_source_filters(inp, sopt);
		}
		break;

	default:
		INP_WUNLOCK(inp);
		error = OFP_ENOPROTOOPT;
		break;
	}

	INP_UNLOCK_ASSERT(inp);

	return (error);
}

/*
 * Look up the ifnet to use for a multicast group membership,
 * given the IPv4 address of an interface, and the IPv4 group address.
 *
 * This routine exists to support legacy multicast applications
 * which do not understand that multicast memberships are scoped to
 * specific physical links in the networking stack, or which need
 * to join link-scope groups before IPv4 addresses are configured.
 *
 * If inp is non-NULL, use this socket's current FIB number for any
 * required FIB lookup.
 * If ina is OFP_INADDR_ANY, look up the group address in the unicast FIB,
 * and use its ifp; usually, this points to the default next-hop.
 *
 * If the FIB lookup fails, attempt to use the first non-loopback
 * interface with multicast capability in the system as a
 * last resort. The legacy IPv4 ASM API requires that we do
 * this in order to allow groups to be joined when the routing
 * table has not yet been populated during boot.
 *
 * Returns NULL if no ifp could be found.
 *
 * SMPng: TODO: Acquire the appropriate locks for INADDR_TO_IFP.
 * FUTURE: Implement IPv4 source-address selection.
 */
static struct ofp_ifnet *
inp_lookup_mcast_ifp(const struct inpcb *inp,
    const struct ofp_sockaddr_in *gsin, const struct ofp_in_addr ina)
{
	struct ofp_ifnet *ifp;

	KASSERT(gsin->sin_family == OFP_AF_INET, ("%s: not OFP_AF_INET", __func__));
	KASSERT(OFP_IN_MULTICAST(odp_be_to_cpu_32(gsin->sin_addr.s_addr)),
	    ("%s: not multicast", __func__));

	ifp = NULL;
	if (!ofp_in_nullhost(ina)) {
		OFP_INADDR_TO_IFP(ina, ifp);
	}
	(void)inp;
	(void)gsin;
#if 0 //HJo FIX
	else {
		struct route ro;

		ro.ro_rt = NULL;
		memcpy(&ro.ro_dst, gsin, sizeof(struct ofp_sockaddr_in));
		in_rtalloc_ign(&ro, 0, inp ? inp->inp_inc.inc_fibnum : 0);
		if (ro.ro_rt != NULL) {
			ifp = ro.ro_rt->rt_ifp;
			KASSERT(ifp != NULL, ("%s: null ifp", __func__));
			RTFREE(ro.ro_rt);
		} else {
			struct in_ifaddr *ia;
			struct ofp_ifnet *mifp;

			mifp = NULL;
			IN_IFADDR_RLOCK();
			TAILQ_FOREACH(ia, &V_in_ifaddrhead, ia_link) {
				mifp = ia->ia_ifp;
				if (!(mifp->if_flags & IFF_LOOPBACK) &&
				     (mifp->if_flags & IFF_MULTICAST)) {
					ifp = mifp;
					break;
				}
			}
			IN_IFADDR_RUNLOCK();
		}
	}
#endif
	return (ifp);
}

/*
 * Join an IPv4 multicast group, possibly with a source.
 */
static int
inp_join_group(struct inpcb *inp, struct sockopt *sopt)
{
	struct ofp_group_source_req	 gsr;
	sockunion_t			*gsa, *ssa;
	struct ofp_ifnet		*ifp;
	struct ofp_in_mfilter		*imf;
	struct ofp_ip_moptions		*imo;
	struct ofp_in_multi		*inm;
	struct ofp_in_msource		*lims;
	size_t				 idx;
	int				 error, is_new;

	ifp = NULL;
	imf = NULL;
	lims = NULL;
	error = 0;
	is_new = 0;

	memset(&gsr, 0, sizeof(struct ofp_group_source_req));
	gsa = (sockunion_t *)&gsr.gsr_group;
	gsa->ss.ss_family = OFP_AF_UNSPEC;
	ssa = (sockunion_t *)&gsr.gsr_source;
	ssa->ss.ss_family = OFP_AF_UNSPEC;

	switch (sopt->sopt_name) {
	case OFP_IP_ADD_MEMBERSHIP:
	case OFP_IP_ADD_SOURCE_MEMBERSHIP: {
		struct ofp_ip_mreq_source	 mreqs;
		memset(&mreqs, 0, sizeof(mreqs));

		if (sopt->sopt_name == OFP_IP_ADD_MEMBERSHIP) {
			error = ofp_sooptcopyin(sopt, &mreqs,
			    sizeof(struct ofp_ip_mreq),
			    sizeof(struct ofp_ip_mreq));
			/*
			 * Do argument switcharoo from ip_mreq into
			 * ip_mreq_source to avoid using two instances.
			 */
			mreqs.imr_interface = mreqs.imr_sourceaddr;
			mreqs.imr_sourceaddr.s_addr = OFP_INADDR_ANY;
		} else if (sopt->sopt_name == OFP_IP_ADD_SOURCE_MEMBERSHIP) {
			error = ofp_sooptcopyin(sopt, &mreqs,
			    sizeof(struct ofp_ip_mreq_source),
			    sizeof(struct ofp_ip_mreq_source));
		}
		if (error)
			return (error);

		gsa->sin.sin_family = OFP_AF_INET;
		gsa->sin.sin_len = sizeof(struct ofp_sockaddr_in);
		gsa->sin.sin_addr = mreqs.imr_multiaddr;

		if (sopt->sopt_name == OFP_IP_ADD_SOURCE_MEMBERSHIP) {
			ssa->sin.sin_family = OFP_AF_INET;
			ssa->sin.sin_len = sizeof(struct ofp_sockaddr_in);
			ssa->sin.sin_addr = mreqs.imr_sourceaddr;
		}

		if (!OFP_IN_MULTICAST(odp_be_to_cpu_32(gsa->sin.sin_addr.s_addr)))
			return (OFP_EINVAL);

		ifp = inp_lookup_mcast_ifp(inp, &gsa->sin,
		    mreqs.imr_interface);
		CTR3(KTR_IGMPV3, "%s: imr_interface = %s, ifp = %p",
		    __func__, inet_ntoa(mreqs.imr_interface), ifp);
		break;
	}

	case OFP_MCAST_JOIN_GROUP:
	case OFP_MCAST_JOIN_SOURCE_GROUP:
		if (sopt->sopt_name == OFP_MCAST_JOIN_GROUP) {
			error = ofp_sooptcopyin(sopt, &gsr,
			    sizeof(struct ofp_group_req),
			    sizeof(struct ofp_group_req));
		} else if (sopt->sopt_name == OFP_MCAST_JOIN_SOURCE_GROUP) {
			error = ofp_sooptcopyin(sopt, &gsr,
			    sizeof(struct ofp_group_source_req),
			    sizeof(struct ofp_group_source_req));
		}
		if (error)
			return (error);

		if (gsa->sin.sin_family != OFP_AF_INET ||
		    gsa->sin.sin_len != sizeof(struct ofp_sockaddr_in))
			return (OFP_EINVAL);

		/*
		 * Overwrite the port field if present, as the sockaddr
		 * being copied in may be matched with a binary comparison.
		 */
		gsa->sin.sin_port = 0;
		if (sopt->sopt_name == OFP_MCAST_JOIN_SOURCE_GROUP) {
			if (ssa->sin.sin_family != OFP_AF_INET ||
			    ssa->sin.sin_len != sizeof(struct ofp_sockaddr_in))
				return (OFP_EINVAL);
			ssa->sin.sin_port = 0;
		}

		if (!OFP_IN_MULTICAST(odp_be_to_cpu_32(gsa->sin.sin_addr.s_addr)))
			return (OFP_EINVAL);

		if (gsr.gsr_interface == 0 || V_if_index < gsr.gsr_interface)
			return (OFP_EADDRNOTAVAIL);
		ifp = ifnet_byindex(gsr.gsr_interface);
		break;

	default:
		CTR2(KTR_IGMPV3, "%s: unknown sopt_name %d",
		    __func__, sopt->sopt_name);
		return (OFP_EOPNOTSUPP);
		break;
	}

	if (ifp == NULL || (ifp->if_flags & OFP_IFF_MULTICAST) == 0)
		return (OFP_EADDRNOTAVAIL);

	imo = inp_findmoptions(inp);
	idx = imo_match_group(imo, ifp, &gsa->sa);
	if ((int)idx == -1) {
		is_new = 1;
	} else {
		inm = imo->imo_membership[idx];
		imf = &imo->imo_mfilters[idx];
		if (ssa->ss.ss_family != OFP_AF_UNSPEC) {
			/*
			 * OFP_MCAST_JOIN_SOURCE_GROUP on an exclusive membership
			 * is an error. On an existing inclusive membership,
			 * it just adds the source to the filter list.
			 */
			if (imf->imf_st[1] != OFP_MCAST_INCLUDE) {
				error = OFP_EINVAL;
				goto out_inp_locked;
			}
			/*
			 * Throw out duplicates.
			 *
			 * XXX FIXME: This makes a naive assumption that
			 * even if entries exist for *ssa in this imf,
			 * they will be rejected as dupes, even if they
			 * are not valid in the current mode (in-mode).
			 *
			 * in_msource is transactioned just as for anything
			 * else in SSM -- but note naive use of inm_graft()
			 * below for allocating new filter entries.
			 *
			 * This is only an issue if someone mixes the
			 * full-state SSM API with the delta-based API,
			 * which is discouraged in the relevant RFCs.
			 */
			lims = imo_match_source(imo, idx, &ssa->sa);
			if (lims != NULL /*&&
			    lims->imsl_st[1] == OFP_MCAST_INCLUDE*/) {
				error = OFP_EADDRNOTAVAIL;
				goto out_inp_locked;
			}
		} else {
			/*
			 * OFP_MCAST_JOIN_GROUP on an existing exclusive
			 * membership is an error; return EADDRINUSE
			 * to preserve 4.4BSD API idempotence, and
			 * avoid tedious detour to code below.
			 * NOTE: This is bending RFC 3678 a bit.
			 *
			 * On an existing inclusive membership, this is also
			 * an error; if you want to change filter mode,
			 * you must use the userland API setsourcefilter().
			 * XXX We don't reject this for imf in UNDEFINED
			 * state at t1, because allocation of a filter
			 * is atomic with allocation of a membership.
			 */
			error = OFP_EINVAL;
			if (imf->imf_st[1] == OFP_MCAST_EXCLUDE)
				error = OFP_EADDRINUSE;
			goto out_inp_locked;
		}
	}

	/*
	 * Begin state merge transaction at socket layer.
	 */
	INP_WLOCK_ASSERT(inp);

	if (is_new) {
		if (imo->imo_num_memberships == imo->imo_max_memberships) {
			error = imo_grow(imo);
			if (error)
				goto out_inp_locked;
		}
		/*
		 * Allocate the new slot upfront so we can deal with
		 * grafting the new source filter in same code path
		 * as for join-source on existing membership.
		 */
		idx = imo->imo_num_memberships;
		imo->imo_membership[idx] = NULL;
		imo->imo_num_memberships++;
		KASSERT(imo->imo_mfilters != NULL,
		    ("%s: imf_mfilters vector was not allocated", __func__));
		imf = &imo->imo_mfilters[idx];
		KASSERT(RB_EMPTY(&imf->imf_sources),
		    ("%s: imf_sources not empty", __func__));
	}

	/*
	 * Graft new source into filter list for this inpcb's
	 * membership of the group. The in_multi may not have
	 * been allocated yet if this is a new membership, however,
	 * the in_mfilter slot will be allocated and must be initialized.
	 *
	 * Note: Grafting of exclusive mode filters doesn't happen
	 * in this path.
	 * XXX: Should check for non-NULL lims (node exists but may
	 * not be in-mode) for interop with full-state API.
	 */
	if (ssa->ss.ss_family != OFP_AF_UNSPEC) {
		/* Membership starts in IN mode */
		if (is_new) {
			CTR1(KTR_IGMPV3, "%s: new join w/source", __func__);
			imf_init(imf, OFP_MCAST_UNDEFINED, OFP_MCAST_INCLUDE);
		} else {
			CTR2(KTR_IGMPV3, "%s: %s source", __func__, "allow");
		}
		lims = imf_graft(imf, OFP_MCAST_INCLUDE, &ssa->sin);
		if (lims == NULL) {
			CTR1(KTR_IGMPV3, "%s: merge imf state failed",
			    __func__);
			error = OFP_ENOMEM;
			goto out_imo_free;
		}
	} else {
		/* No address specified; Membership starts in EX mode */
		if (is_new) {
			CTR1(KTR_IGMPV3, "%s: new join w/o source", __func__);
			imf_init(imf, OFP_MCAST_UNDEFINED, OFP_MCAST_EXCLUDE);
		}
	}

	/*
	 * Begin state merge transaction at IGMP layer.
	 */
	IN_MULTI_LOCK();

	if (is_new) {
		error = ofp_in_joingroup_locked(ifp, &gsa->sin.sin_addr, imf,
		    &inm);
		if (error)
			goto out_imo_free;
		imo->imo_membership[idx] = inm;
	} else {
		CTR1(KTR_IGMPV3, "%s: merge inm state", __func__);
		error = inm_merge(inm, imf);
		if (error) {
			CTR1(KTR_IGMPV3, "%s: failed to merge inm state",
			    __func__);
			goto out_imf_rollback;
		}
		CTR1(KTR_IGMPV3, "%s: doing igmp downcall", __func__);
		error = ofp_igmp_change_state(inm);
		if (error) {
			CTR1(KTR_IGMPV3, "%s: failed igmp downcall",
			    __func__);
			goto out_imf_rollback;
		}
	}

	IN_MULTI_UNLOCK();

out_imf_rollback:
	INP_WLOCK_ASSERT(inp);
	if (error) {
		imf_rollback(imf);
		if (is_new)
			imf_purge(imf);
		else
			imf_reap(imf);
	} else {
		imf_commit(imf);
	}

out_imo_free:
	if (error && is_new) {
		imo->imo_membership[idx] = NULL;
		--imo->imo_num_memberships;
	}

out_inp_locked:
	INP_WUNLOCK(inp);
	return (error);
}

/*
 * Leave an IPv4 multicast group on an inpcb, possibly with a source.
 */
static int
inp_leave_group(struct inpcb *inp, struct sockopt *sopt)
{
	struct ofp_group_source_req		 gsr;
	struct ofp_ip_mreq_source		 mreqs;
	sockunion_t			*gsa, *ssa;
	struct ofp_ifnet			*ifp;
	struct ofp_in_mfilter		*imf;
	struct ofp_ip_moptions		*imo;
	struct ofp_in_msource		*ims;
	struct ofp_in_multi			*inm;
	size_t				 idx;
	int				 error, is_final;

	ifp = NULL;
	error = 0;
	is_final = 1;

	memset(&gsr, 0, sizeof(struct ofp_group_source_req));
	gsa = (sockunion_t *)&gsr.gsr_group;
	gsa->ss.ss_family = OFP_AF_UNSPEC;
	ssa = (sockunion_t *)&gsr.gsr_source;
	ssa->ss.ss_family = OFP_AF_UNSPEC;

	switch (sopt->sopt_name) {
	case OFP_IP_DROP_MEMBERSHIP:
	case OFP_IP_DROP_SOURCE_MEMBERSHIP:
		memset(&mreqs, 0, sizeof(mreqs));

		if (sopt->sopt_name == OFP_IP_DROP_MEMBERSHIP) {
			error = ofp_sooptcopyin(sopt, &mreqs,
			    sizeof(struct ofp_ip_mreq),
			    sizeof(struct ofp_ip_mreq));
			/*
			 * Swap interface and sourceaddr arguments,
			 * as ip_mreq and ip_mreq_source are laid
			 * out differently.
			 */
			mreqs.imr_interface = mreqs.imr_sourceaddr;
			mreqs.imr_sourceaddr.s_addr = OFP_INADDR_ANY;
		} else if (sopt->sopt_name == OFP_IP_DROP_SOURCE_MEMBERSHIP) {
			error = ofp_sooptcopyin(sopt, &mreqs,
			    sizeof(struct ofp_ip_mreq_source),
			    sizeof(struct ofp_ip_mreq_source));
		}
		if (error)
			return (error);

		gsa->sin.sin_family = OFP_AF_INET;
		gsa->sin.sin_len = sizeof(struct ofp_sockaddr_in);
		gsa->sin.sin_addr = mreqs.imr_multiaddr;

		if (sopt->sopt_name == OFP_IP_DROP_SOURCE_MEMBERSHIP) {
			ssa->sin.sin_family = OFP_AF_INET;
			ssa->sin.sin_len = sizeof(struct ofp_sockaddr_in);
			ssa->sin.sin_addr = mreqs.imr_sourceaddr;
		}

		/*
		 * Attempt to look up hinted ifp from interface address.
		 * Fallthrough with null ifp iff lookup fails, to
		 * preserve 4.4BSD mcast API idempotence.
		 * XXX NOTE WELL: The RFC 3678 API is preferred because
		 * using an IPv4 address as a key is racy.
		 */
		if (!ofp_in_nullhost(mreqs.imr_interface))
			OFP_INADDR_TO_IFP(mreqs.imr_interface, ifp);

		CTR3(KTR_IGMPV3, "%s: imr_interface = %s, ifp = %p",
		    __func__, inet_ntoa(mreqs.imr_interface), ifp);

		break;

	case OFP_MCAST_LEAVE_GROUP:
	case OFP_MCAST_LEAVE_SOURCE_GROUP:
		if (sopt->sopt_name == OFP_MCAST_LEAVE_GROUP) {
			error = ofp_sooptcopyin(sopt, &gsr,
			    sizeof(struct ofp_group_req),
			    sizeof(struct ofp_group_req));
		} else if (sopt->sopt_name == OFP_MCAST_LEAVE_SOURCE_GROUP) {
			error = ofp_sooptcopyin(sopt, &gsr,
			    sizeof(struct ofp_group_source_req),
			    sizeof(struct ofp_group_source_req));
		}
		if (error)
			return (error);

		if (gsa->sin.sin_family != OFP_AF_INET ||
		    gsa->sin.sin_len != sizeof(struct ofp_sockaddr_in))
			return (OFP_EINVAL);

		if (sopt->sopt_name == OFP_MCAST_LEAVE_SOURCE_GROUP) {
			if (ssa->sin.sin_family != OFP_AF_INET ||
			    ssa->sin.sin_len != sizeof(struct ofp_sockaddr_in))
				return (OFP_EINVAL);
		}

		if (gsr.gsr_interface == 0 || V_if_index < gsr.gsr_interface)
			return (OFP_EADDRNOTAVAIL);

		ifp = ifnet_byindex(gsr.gsr_interface);

		if (ifp == NULL)
			return (OFP_EADDRNOTAVAIL);
		break;

	default:
		CTR2(KTR_IGMPV3, "%s: unknown sopt_name %d",
		    __func__, sopt->sopt_name);
		return (OFP_EOPNOTSUPP);
		break;
	}

	if (!OFP_IN_MULTICAST(odp_be_to_cpu_32(gsa->sin.sin_addr.s_addr)))
		return (OFP_EINVAL);

	/*
	 * Find the membership in the membership array.
	 */
	imo = inp_findmoptions(inp);
	idx = imo_match_group(imo, ifp, &gsa->sa);
	if ((int)idx == -1) {
		error = OFP_EADDRNOTAVAIL;
		goto out_inp_locked;
	}
	inm = imo->imo_membership[idx];
	imf = &imo->imo_mfilters[idx];

	if (ssa->ss.ss_family != OFP_AF_UNSPEC)
		is_final = 0;

	/*
	 * Begin state merge transaction at socket layer.
	 */
	INP_WLOCK_ASSERT(inp);

	/*
	 * If we were instructed only to leave a given source, do so.
	 * OFP_MCAST_LEAVE_SOURCE_GROUP is only valid for inclusive memberships.
	 */
	if (is_final) {
		imf_leave(imf);
	} else {
		if (imf->imf_st[0] == OFP_MCAST_EXCLUDE) {
			error = OFP_EADDRNOTAVAIL;
			goto out_inp_locked;
		}
		ims = imo_match_source(imo, idx, &ssa->sa);
		if (ims == NULL) {
			CTR3(KTR_IGMPV3, "%s: source %s %spresent", __func__,
			    inet_ntoa(ssa->sin.sin_addr), "not ");
			error = OFP_EADDRNOTAVAIL;
			goto out_inp_locked;
		}
		CTR2(KTR_IGMPV3, "%s: %s source", __func__, "block");
		error = imf_prune(imf, &ssa->sin);
		if (error) {
			CTR1(KTR_IGMPV3, "%s: merge imf state failed",
			    __func__);
			goto out_inp_locked;
		}
	}

	/*
	 * Begin state merge transaction at IGMP layer.
	 */
	IN_MULTI_LOCK();

	if (is_final) {
		/*
		 * Give up the multicast address record to which
		 * the membership points.
		 */
		(void)ofp_in_leavegroup_locked(inm, imf);
	} else {
		CTR1(KTR_IGMPV3, "%s: merge inm state", __func__);
		error = inm_merge(inm, imf);
		if (error) {
			CTR1(KTR_IGMPV3, "%s: failed to merge inm state",
			    __func__);
			goto out_imf_rollback;
		}

		CTR1(KTR_IGMPV3, "%s: doing igmp downcall", __func__);
		error = ofp_igmp_change_state(inm);
		if (error) {
			CTR1(KTR_IGMPV3, "%s: failed igmp downcall",
			    __func__);
		}
	}

	IN_MULTI_UNLOCK();

out_imf_rollback:
	if (error)
		imf_rollback(imf);
	else
		imf_commit(imf);

	imf_reap(imf);

	if (is_final) {
		/* Remove the gap in the membership and filter array. */
		for (++idx; idx < imo->imo_num_memberships; ++idx) {
			imo->imo_membership[idx-1] = imo->imo_membership[idx];
			imo->imo_mfilters[idx-1] = imo->imo_mfilters[idx];
		}
		imo->imo_num_memberships--;
	}

out_inp_locked:
	INP_WUNLOCK(inp);
	return (error);
}

/*
 * Select the interface for transmitting IPv4 multicast datagrams.
 *
 * Either an instance of struct ofp_in_addr or an instance of struct ip_mreqn
 * may be passed to this socket option. An address of OFP_INADDR_ANY or an
 * interface index of 0 is used to remove a previous selection.
 * When no interface is selected, one is chosen for every send.
 */
static int
inp_set_multicast_if(struct inpcb *inp, struct sockopt *sopt)
{
	struct ofp_in_addr		 addr;
	struct ofp_ip_mreqn		 mreqn;
	struct ofp_ifnet		*ifp;
	struct ofp_ip_moptions	*imo;
	int			 error;

	if (sopt->sopt_valsize == sizeof(struct ofp_ip_mreqn)) {
		/*
		 * An interface index was specified using the
		 * Linux-derived ip_mreqn structure.
		 */
		error = ofp_sooptcopyin(sopt, &mreqn, sizeof(struct ofp_ip_mreqn),
		    sizeof(struct ofp_ip_mreqn));
		if (error)
			return (error);

		if (mreqn.imr_ifindex < 0 || (int)V_if_index < mreqn.imr_ifindex)
			return (OFP_EINVAL);

		if (mreqn.imr_ifindex == 0) {
			ifp = NULL;
		} else {
			ifp = ifnet_byindex(mreqn.imr_ifindex);
			if (ifp == NULL)
				return (OFP_EADDRNOTAVAIL);
		}
	} else {
		/*
		 * An interface was specified by IPv4 address.
		 * This is the traditional BSD usage.
		 */
		error = ofp_sooptcopyin(sopt, &addr, sizeof(struct ofp_in_addr),
		    sizeof(struct ofp_in_addr));
		if (error)
			return (error);
		if (ofp_in_nullhost(addr)) {
			ifp = NULL;
		} else {
			OFP_INADDR_TO_IFP(addr, ifp);
			if (ifp == NULL)
				return (OFP_EADDRNOTAVAIL);
		}
		CTR3(KTR_IGMPV3, "%s: ifp = %p, addr = %s", __func__, ifp,
		    inet_ntoa(addr));
	}

	/* Reject interfaces which do not support multicast. */
	if (ifp != NULL && (ifp->if_flags & OFP_IFF_MULTICAST) == 0)
		return (OFP_EOPNOTSUPP);

	imo = inp_findmoptions(inp);
	imo->imo_multicast_ifp = ifp;
	imo->imo_multicast_addr.s_addr = OFP_INADDR_ANY;
	INP_WUNLOCK(inp);

	return (0);
}

/*
 * Atomically set source filters on a socket for an IPv4 multicast group.
 *
 * SMPng: NOTE: Potentially calls malloc(M_WAITOK) with Giant held.
 */
static int
inp_set_source_filters(struct inpcb *inp, struct sockopt *sopt)
{
	struct __msfilterreq	 msfr;
	sockunion_t		*gsa;
	struct ofp_ifnet		*ifp;
	struct ofp_in_mfilter	*imf;
	struct ofp_ip_moptions	*imo;
	struct ofp_in_multi		*inm;
	size_t			 idx;
	int			 error;

	error = ofp_sooptcopyin(sopt, &msfr, sizeof(struct __msfilterreq),
	    sizeof(struct __msfilterreq));
	if (error)
		return (error);

	if (msfr.msfr_nsrcs > in_mcast_maxsocksrc)
		return (OFP_ENOBUFS);

	if ((msfr.msfr_fmode != OFP_MCAST_EXCLUDE &&
	     msfr.msfr_fmode != OFP_MCAST_INCLUDE))
		return (OFP_EINVAL);

	if (msfr.msfr_group.ss_family != OFP_AF_INET ||
	    msfr.msfr_group.ss_len != sizeof(struct ofp_sockaddr_in))
		return (OFP_EINVAL);

	gsa = (sockunion_t *)&msfr.msfr_group;
	if (!OFP_IN_MULTICAST(odp_be_to_cpu_32(gsa->sin.sin_addr.s_addr)))
		return (OFP_EINVAL);

	gsa->sin.sin_port = 0;	/* ignore port */

	if (msfr.msfr_ifindex == 0 || V_if_index < msfr.msfr_ifindex)
		return (OFP_EADDRNOTAVAIL);

	ifp = ifnet_byindex(msfr.msfr_ifindex);
	if (ifp == NULL)
		return (OFP_EADDRNOTAVAIL);

	/*
	 * Take the INP write lock.
	 * Check if this socket is a member of this group.
	 */
	imo = inp_findmoptions(inp);
	idx = imo_match_group(imo, ifp, &gsa->sa);
	if ((int)idx == -1 || imo->imo_mfilters == NULL) {
		error = OFP_EADDRNOTAVAIL;
		goto out_inp_locked;
	}
	inm = imo->imo_membership[idx];
	imf = &imo->imo_mfilters[idx];

	/*
	 * Begin state merge transaction at socket layer.
	 */
	INP_WLOCK_ASSERT(inp);

	imf->imf_st[1] = msfr.msfr_fmode;

	/*
	 * Apply any new source filters, if present.
	 * Make a copy of the user-space source vector so
	 * that we may copy them with a single copyin. This
	 * allows us to deal with page faults up-front.
	 */
	if (msfr.msfr_nsrcs > 0) {
		struct ofp_in_msource	*lims;
		struct ofp_sockaddr_in	*psin;
		struct ofp_sockaddr_storage_2	*kss, *pkss;
		int			 i;

		INP_WUNLOCK(inp);

		CTR2(KTR_IGMPV3, "%s: loading %lu source list entries",
		    __func__, (unsigned long)msfr.msfr_nsrcs);
		kss = malloc(sizeof(struct ofp_sockaddr_storage_2) * msfr.msfr_nsrcs);
		error = copyin(msfr.msfr_srcs, kss,
		    sizeof(struct ofp_sockaddr_storage_2) * msfr.msfr_nsrcs);
		if (error) {
			free(kss);
			return (error);
		}

		INP_WLOCK(inp);

		/*
		 * Mark all source filters as UNDEFINED at t1.
		 * Restore new group filter mode, as imf_leave()
		 * will set it to INCLUDE.
		 */
		imf_leave(imf);
		imf->imf_st[1] = msfr.msfr_fmode;

		/*
		 * Update socket layer filters at t1, lazy-allocating
		 * new entries. This saves a bunch of memory at the
		 * cost of one RB_FIND() per source entry; duplicate
		 * entries in the msfr_nsrcs vector are ignored.
		 * If we encounter an error, rollback transaction.
		 *
		 * XXX This too could be replaced with a set-symmetric
		 * difference like loop to avoid walking from root
		 * every time, as the key space is common.
		 */
		for (i = 0, pkss = kss; i < (int)msfr.msfr_nsrcs; i++, pkss++) {
			psin = (struct ofp_sockaddr_in *)pkss;
			if (psin->sin_family != OFP_AF_INET) {
				error = OFP_EAFNOSUPPORT;
				break;
			}
			if (psin->sin_len != sizeof(struct ofp_sockaddr_in)) {
				error = OFP_EINVAL;
				break;
			}
			error = imf_get_source(imf, psin, &lims);
			if (error)
				break;
			lims->imsl_st[1] = imf->imf_st[1];
		}
		free(kss);
	}

	if (error)
		goto out_imf_rollback;

	INP_WLOCK_ASSERT(inp);
	IN_MULTI_LOCK();

	/*
	 * Begin state merge transaction at IGMP layer.
	 */
	CTR1(KTR_IGMPV3, "%s: merge inm state", __func__);
	error = inm_merge(inm, imf);
	if (error) {
		CTR1(KTR_IGMPV3, "%s: failed to merge inm state", __func__);
		goto out_imf_rollback;
	}

	CTR1(KTR_IGMPV3, "%s: doing igmp downcall", __func__);
	error = ofp_igmp_change_state(inm);
	if (error)
		CTR1(KTR_IGMPV3, "%s: failed igmp downcall", __func__);

	IN_MULTI_UNLOCK();

out_imf_rollback:
	if (error)
		imf_rollback(imf);
	else
		imf_commit(imf);

	imf_reap(imf);

out_inp_locked:
	INP_WUNLOCK(inp);
	return (error);
}

/*
 * Set the IP multicast options in response to user setsockopt().
 *
 * Many of the socket options handled in this function duplicate the
 * functionality of socket options in the regular unicast API. However,
 * it is not possible to merge the duplicate code, because the idempotence
 * of the IPv4 multicast part of the BSD Sockets API must be preserved;
 * the effects of these options must be treated as separate and distinct.
 *
 * SMPng: XXX: Unlocked read of inp_socket believed OK.
 * FUTURE: The IP_MULTICAST_VIF option may be eliminated if MROUTING
 * is refactored to no longer use vifs.
 */
int
ofp_inp_setmoptions(struct inpcb *inp, struct sockopt *sopt)
{
	struct ofp_ip_moptions	*imo;
	int			 error;

	OFP_DBG("HERE\n");
	error = 0;

	/*
	 * If socket is neither of type OFP_SOCK_RAW or OFP_SOCK_DGRAM,
	 * or is a divert socket, reject it.
	 */
	if (inp->inp_socket->so_proto->pr_protocol == OFP_IPPROTO_DIVERT ||
	    (inp->inp_socket->so_proto->pr_type != OFP_SOCK_RAW &&
	     inp->inp_socket->so_proto->pr_type != OFP_SOCK_DGRAM))
		return (OFP_EOPNOTSUPP);

	switch (sopt->sopt_name) {
#if 0 //HJo
	case OFP_IP_MULTICAST_VIF: {
		int vifi;
		/*
		 * Select a multicast VIF for transmission.
		 * Only useful if multicast forwarding is active.
		 */
		if (legal_vif_num == NULL) {
			error = OFP_EOPNOTSUPP;
			break;
		}
		error = ofp_sooptcopyin(sopt, &vifi, sizeof(int), sizeof(int));
		if (error)
			break;
		if (!legal_vif_num(vifi) && (vifi != -1)) {
			error = OFP_EINVAL;
			break;
		}
		imo = inp_findmoptions(inp);
		imo->imo_multicast_vif = vifi;
		INP_WUNLOCK(inp);
		break;
	}
#endif

	case OFP_IP_MULTICAST_IF:
		error = inp_set_multicast_if(inp, sopt);
		break;

	case OFP_IP_MULTICAST_TTL: {
		uint8_t ttl;

		/*
		 * Set the IP time-to-live for outgoing multicast packets.
		 * The original multicast API required a char argument,
		 * which is inconsistent with the rest of the socket API.
		 * We allow either a char or an int.
		 */
		if (sopt->sopt_valsize == sizeof(uint8_t)) {
			error = ofp_sooptcopyin(sopt, &ttl, sizeof(uint8_t),
			    sizeof(uint8_t));
			if (error)
				break;
		} else {
			uint32_t ittl;

			error = ofp_sooptcopyin(sopt, &ittl, sizeof(uint32_t),
			    sizeof(uint32_t));
			if (error)
				break;
			if (ittl > 255) {
				error = OFP_EINVAL;
				break;
			}
			ttl = (uint8_t)ittl;
		}
		imo = inp_findmoptions(inp);
		imo->imo_multicast_ttl = ttl;
		INP_WUNLOCK(inp);
		break;
	}

	case OFP_IP_MULTICAST_LOOP: {
		uint8_t loop;

		/*
		 * Set the loopback flag for outgoing multicast packets.
		 * Must be zero or one.  The original multicast API required a
		 * char argument, which is inconsistent with the rest
		 * of the socket API.  We allow either a char or an int.
		 */
		if (sopt->sopt_valsize == sizeof(uint8_t)) {
			error = ofp_sooptcopyin(sopt, &loop, sizeof(uint8_t),
			    sizeof(uint8_t));
			if (error)
				break;
		} else {
			uint32_t iloop;

			error = ofp_sooptcopyin(sopt, &iloop, sizeof(uint32_t),
					    sizeof(uint32_t));
			if (error)
				break;
			loop = (uint8_t)iloop;
		}
		imo = inp_findmoptions(inp);
		imo->imo_multicast_loop = !!loop;
		INP_WUNLOCK(inp);
		break;
	}

	case OFP_IP_ADD_MEMBERSHIP:
	case OFP_IP_ADD_SOURCE_MEMBERSHIP:
	case OFP_MCAST_JOIN_GROUP:
	case OFP_MCAST_JOIN_SOURCE_GROUP:
		error = inp_join_group(inp, sopt);
		break;

	case OFP_IP_DROP_MEMBERSHIP:
	case OFP_IP_DROP_SOURCE_MEMBERSHIP:
	case OFP_MCAST_LEAVE_GROUP:
	case OFP_MCAST_LEAVE_SOURCE_GROUP:
		error = inp_leave_group(inp, sopt);
		break;

	case OFP_IP_BLOCK_SOURCE:
	case OFP_IP_UNBLOCK_SOURCE:
	case OFP_MCAST_BLOCK_SOURCE:
	case OFP_MCAST_UNBLOCK_SOURCE:
		error = inp_block_unblock_source(inp, sopt);
		break;

	case OFP_IP_MSFILTER:
		error = inp_set_source_filters(inp, sopt);
		break;

	default:
		error = OFP_EOPNOTSUPP;
		break;
	}

	INP_UNLOCK_ASSERT(inp);

	return (error);
}

/*
 * IP socket option processing.
 */
int
ofp_ip_ctloutput(struct socket *so, struct sockopt *sopt)
{
	struct	inpcb *inp = sotoinpcb(so);
	int	error, optval;

	OFP_DBG("HERE\n");
	error = optval = 0;
	if (sopt->sopt_level != OFP_IPPROTO_IP) {
		error = OFP_EINVAL;

		if (sopt->sopt_level == OFP_SOL_SOCKET &&
		    sopt->sopt_dir == SOPT_SET) {
			switch (sopt->sopt_name) {

			} /* switch (sopt->sopt_name) */
		} /* if (sopt->sopt_level == SOL_SOCKET */

		return (error);
	} /* sopt->sopt_level != IPPROTO_IP */

	switch (sopt->sopt_dir) {
	case SOPT_SET:
		switch (sopt->sopt_name) {
		/*
		 * Multicast socket options are processed by the in_mcast
		 * module.
		 */
		case OFP_IP_MULTICAST_IF:
		case OFP_IP_MULTICAST_VIF:
		case OFP_IP_MULTICAST_TTL:
		case OFP_IP_MULTICAST_LOOP:
		case OFP_IP_ADD_MEMBERSHIP:
		case OFP_IP_DROP_MEMBERSHIP:
		case OFP_IP_ADD_SOURCE_MEMBERSHIP:
		case OFP_IP_DROP_SOURCE_MEMBERSHIP:
		case OFP_IP_BLOCK_SOURCE:
		case OFP_IP_UNBLOCK_SOURCE:
		case OFP_IP_MSFILTER:
		case OFP_MCAST_JOIN_GROUP:
		case OFP_MCAST_LEAVE_GROUP:
		case OFP_MCAST_JOIN_SOURCE_GROUP:
		case OFP_MCAST_LEAVE_SOURCE_GROUP:
		case OFP_MCAST_BLOCK_SOURCE:
		case OFP_MCAST_UNBLOCK_SOURCE:
			error = ofp_inp_setmoptions(inp, sopt);
			break;
		} /* switch (sopt->sopt_name) */
		break;

	case SOPT_GET:
		switch (sopt->sopt_name) {
		} /* switch (sopt->sopt_name) */
		break;
	} /* switch (sopt->sopt_dir) */

	return error;
}

/*
 * Expose IGMP's multicast filter mode and source list(s) to userland,
 * keyed by (ifindex, group).
 * The filter mode is written out as a uint32_t, followed by
 * 0..n of struct ofp_in_addr.
 * For use by ifmcstat(8).
 * SMPng: NOTE: unlocked read of ifindex space.
 */
static int
sysctl_ip_mcast_filters(OFP_SYSCTL_HANDLER_ARGS)
{
	struct ofp_in_addr		 src, group;
	struct ofp_ifnet		*ifp;
	struct ofp_ifmultiaddr		*ifma;
	struct ofp_in_multi		*inm;
	struct ofp_ip_msource		*ims;
	int				*name;
	int				 retval = 0;
	uint32_t			 namelen;
	uint32_t			 fmode, ifindex;
	(void)oidp;

	name = (int *)arg1;
	namelen = arg2;

	if (req->newptr != NULL)
		return (OFP_EPERM);

	if (namelen != 2)
		return (OFP_EINVAL);

	ifindex = name[0];
	if (ifindex <= 0 || ifindex > V_if_index) {
		CTR2(KTR_IGMPV3, "%s: ifindex %u out of range",
		    __func__, ifindex);
		return (OFP_ENOENT);
	}

	group.s_addr = name[1];
	if (!OFP_IN_MULTICAST(odp_be_to_cpu_32(group.s_addr))) {
		CTR2(KTR_IGMPV3, "%s: group %s is not multicast",
		    __func__, inet_ntoa(group));
		return (OFP_EINVAL);
	}

	ifp = ifnet_byindex(ifindex);
	if (ifp == NULL) {
		CTR2(KTR_IGMPV3, "%s: no ifp for ifindex %u",
		    __func__, ifindex);
		return (OFP_ENOENT);
	}
#if 0 //HJo
	retval = sysctl_wire_old_buffer(req,
	    sizeof(uint32_t) + (in_mcast_maxgrpsrc * sizeof(struct ofp_in_addr)));
	if (retval)
		return (retval);
#endif
	IN_MULTI_LOCK();

	IF_ADDR_RLOCK(ifp);
	OFP_TAILQ_FOREACH(ifma, &ifp->if_multiaddrs, ifma_link) {
		if (ifma->ifma_addr->sa_family != OFP_AF_INET ||
		    ifma->ifma_protospec == NULL)
			continue;
		inm = (struct ofp_in_multi *)ifma->ifma_protospec;
		if (!ofp_in_hosteq(inm->inm_addr, group))
			continue;
		fmode = inm->inm_st[1].iss_fmode;
		retval = SYSCTL_OUT(req, &fmode, sizeof(uint32_t));
		if (retval != 0)
			break;
		RB_FOREACH(ims, ip_msource_tree, &inm->inm_srcs) {
#ifdef KTR
			struct ofp_in_addr ina;
			ina.s_addr = odp_cpu_to_be_32(ims->ims_haddr);
			CTR2(KTR_IGMPV3, "%s: visit node %s", __func__,
			    inet_ntoa(ina));
#endif
			/*
			 * Only copy-out sources which are in-mode.
			 */
			if (fmode != ims_get_mode(inm, ims, 1)) {
				CTR1(KTR_IGMPV3, "%s: skip non-in-mode",
				    __func__);
				continue;
			}
			src.s_addr = odp_cpu_to_be_32(ims->ims_haddr);
			retval = SYSCTL_OUT(req, &src, sizeof(struct ofp_in_addr));
			if (retval != 0)
				break;
		}
	}
	IF_ADDR_RUNLOCK(ifp);

	IN_MULTI_UNLOCK();

	return (retval);
}

#ifdef KTR

static const char *inm_modestrs[] = { "un", "in", "ex" };

static const char *
inm_mode_str(const int mode)
{

	if (mode >= OFP_MCAST_UNDEFINED && mode <= OFP_MCAST_EXCLUDE)
		return (inm_modestrs[mode]);
	return ("??");
}

static const char *inm_statestrs[] = {
	"not-member",
	"silent",
	"idle",
	"lazy",
	"sleeping",
	"awakening",
	"query-pending",
	"sg-query-pending",
	"leaving"
};

static const char *
inm_state_str(const int state)
{

	if (state >= IGMP_NOT_MEMBER && state <= IGMP_LEAVING_MEMBER)
		return (inm_statestrs[state]);
	return ("??");
}

/*
 * Dump an in_multi structure to the console.
 */
void
ofp_inm_print(const struct ofp_in_multi *inm)
{
	int t;

	(void)inm;
#if 0 //HJo
	if ((ktr_mask & KTR_IGMPV3) == 0)
		return;
#endif
	OFP_INFO("%s: --- begin inm %p ---", __func__, inm);
	OFP_INFO("addr %s ifp %p(%s) ifma %p",
	    inet_ntoa(inm->inm_addr),
	    inm->inm_ifp,
	    inm->inm_ifp->if_name,
	    inm->inm_ifma);
	OFP_INFO("timer %u state %s refcount %u scq.len %u",
	    inm->inm_timer,
	    inm_state_str(inm->inm_state),
	    inm->inm_refcount,
	    inm->inm_scq.ifq_len);
	OFP_INFO("igi %p nsrc %u sctimer %u scrv %u",
	    inm->inm_igi,
	    inm->inm_nsrc,
	    inm->inm_sctimer,
	    inm->inm_scrv);
	for (t = 0; t < 2; t++) {
		OFP_LOG_NO_CTX(OFP_LOG_INFO,
		    "t%d: fmode %s asm %u ex %u in %u rec %u\n", t,
		    inm_mode_str(inm->inm_st[t].iss_fmode),
		    inm->inm_st[t].iss_asm,
		    inm->inm_st[t].iss_ex,
		    inm->inm_st[t].iss_in,
		    inm->inm_st[t].iss_rec);
	}
	OFP_INFO("%s: --- end inm %p ---", __func__, inm);
}

#else /* !KTR */

void
ofp_inm_print(const struct ofp_in_multi *inm)
{
	(void)inm;
}

#endif /* KTR */

RB_GENERATE(ip_msource_tree, ofp_ip_msource, ims_link, ip_msource_cmp);

/*
 * if.c
 */

#define	sa_equal(a1, a2)	\
	(bcmp((a1), (a2), ((a1))->sa_len) == 0)

#define	sa_dl_equal(a1, a2)	\
	((((struct ofp_sockaddr_dl *)(a1))->sdl_len ==			\
	 ((struct ofp_sockaddr_dl *)(a2))->sdl_len) &&			\
	 (bcmp(LLADDR((struct ofp_sockaddr_dl *)(a1)),			\
	       LLADDR((struct ofp_sockaddr_dl *)(a2)),			\
	       ((struct ofp_sockaddr_dl *)(a1))->sdl_alen) == 0))

/*
 * Register an additional multicast address with a network interface.
 *
 * - If the address is already present, bump the reference count on the
 *   address and return.
 * - If the address is not link-layer, look up a link layer address.
 * - Allocate address structures for one or both addresses, and attach to the
 *   multicast address list on the interface.  If automatically adding a link
 *   layer address, the protocol address will own a reference to the link
 *   layer address, to be freed when it is freed.
 * - Notify the network device driver of an addition to the multicast address
 *   list.
 *
 * 'sa' points to caller-owned memory with the desired multicast address.
 *
 * 'retifma' will be used to return a pointer to the resulting multicast
 * address reference, if desired.
 */
int
ofp_if_addmulti(struct ofp_ifnet *ifp, struct ofp_sockaddr *sa,
		struct ofp_ifmultiaddr **retifma)
{
	struct ofp_ifmultiaddr *ifma, *ll_ifma;
	struct ofp_sockaddr *llsa;
	int error;

	/*
	 * If the address is already present, return a new reference to it;
	 * otherwise, allocate storage and set up a new address.
	 */
	IF_ADDR_WLOCK(ifp);
	ifma = ofp_if_findmulti(ifp, sa);
	if (ifma != NULL) {
		ifma->ifma_refcount++;
		if (retifma != NULL)
			*retifma = ifma;
		IF_ADDR_WUNLOCK(ifp);
		return (0);
	}

	/*
	 * The address isn't already present; resolve the protocol address
	 * into a link layer address, and then look that up, bump its
	 * refcount or allocate an ifma for that also.  If 'llsa' was
	 * returned, we will need to free it later.
	 */
	llsa = NULL;
	ll_ifma = NULL;
#if 0 // HJo
	if (ifp->if_resolvemulti != NULL) {
		error = ifp->if_resolvemulti(ifp, &llsa, sa);
		if (error)
			goto unlock_out;
	}
#endif
	/*
	 * Allocate the new address.  Don't hook it up yet, as we may also
	 * need to allocate a link layer multicast address.
	 */
	ifma = if_allocmulti(ifp, sa, llsa, 0);
	if (ifma == NULL) {
		error = OFP_ENOMEM;
		goto free_llsa_out;
	}

	/*
	 * If a link layer address is found, we'll need to see if it's
	 * already present in the address list, or allocate is as well.
	 * When this block finishes, the link layer address will be on the
	 * list.
	 */
	if (llsa != NULL) {
		ll_ifma = ofp_if_findmulti(ifp, llsa);
		if (ll_ifma == NULL) {
			ll_ifma = if_allocmulti(ifp, llsa, NULL, 0);
			if (ll_ifma == NULL) {
				--ifma->ifma_refcount;
				if_freemulti(ifma);
				error = OFP_ENOMEM;
				goto free_llsa_out;
			}
			OFP_TAILQ_INSERT_HEAD(&ifp->if_multiaddrs, ll_ifma,
			    ifma_link);
		} else
			ll_ifma->ifma_refcount++;
		ifma->ifma_llifma = ll_ifma;
	}

	/*
	 * We now have a new multicast address, ifma, and possibly a new or
	 * referenced link layer address.  Add the primary address to the
	 * ifnet address list.
	 */
	OFP_TAILQ_INSERT_HEAD(&ifp->if_multiaddrs, ifma, ifma_link);

	if (retifma != NULL)
		*retifma = ifma;

	/*
	 * Must generate the message while holding the lock so that 'ifma'
	 * pointer is still valid.
	 */
	//HJo FIX: rt_newmaddrmsg(RTM_NEWMADDR, ifma);
	IF_ADDR_WUNLOCK(ifp);

	/*
	 * We are certain we have added something, so call down to the
	 * interface to let them know about it.
	 */
#if 0 //HJo FIX
	if (ifp->if_ioctl != NULL) {
		(void) (*ifp->if_ioctl)(ifp, SIOCADDMULTI, 0);
	}
#endif
	if (llsa != NULL)
		free(llsa);

	return (0);

free_llsa_out:
	if (llsa != NULL)
		free(llsa);

// HJo unlock_out:
	IF_ADDR_WUNLOCK(ifp);
	return (error);
}

/*
 * Delete a multicast group membership by network-layer group address.
 *
 * Returns ENOENT if the entry could not be found. If ifp no longer
 * exists, results are undefined. This entry point should only be used
 * from subsystems which do appropriate locking to hold ifp for the
 * duration of the call.
 * Network-layer protocol domains must use ofp_if_delmulti_ifma().
 */
int
ofp_if_delmulti(struct ofp_ifnet *ifp, struct ofp_sockaddr *sa)
{
	struct ofp_ifmultiaddr *ifma;
	int lastref;
#ifdef INVARIANTS
	struct ofp_ifnet *oifp;

	IFNET_RLOCK_NOSLEEP();
	TAILQ_FOREACH(oifp, &V_ifnet, if_link)
		if (ifp == oifp)
			break;
	if (ifp != oifp)
		ifp = NULL;
	IFNET_RUNLOCK_NOSLEEP();

	KASSERT(ifp != NULL, ("%s: ifnet went away", __func__));
#endif
	if (ifp == NULL)
		return (OFP_ENOENT);

	IF_ADDR_WLOCK(ifp);
	lastref = 0;
	ifma = ofp_if_findmulti(ifp, sa);
	if (ifma != NULL)
		lastref = if_delmulti_locked(ifp, ifma, 0);
	IF_ADDR_WUNLOCK(ifp);

	if (ifma == NULL)
		return (OFP_ENOENT);

	(void)lastref;
#if 0 // HJo
	if (lastref && ifp->if_ioctl != NULL) {
		(void)(*ifp->if_ioctl)(ifp, SIOCDELMULTI, 0);
	}
#endif
	return (0);
}

struct ofp_ifmultiaddr *
ofp_if_findmulti(struct ofp_ifnet *ifp, struct ofp_sockaddr *sa)
{
	struct ofp_ifmultiaddr *ifma;

	IF_ADDR_LOCK_ASSERT(ifp);

	OFP_TAILQ_FOREACH(ifma, &ifp->if_multiaddrs, ifma_link) {
		if (sa->sa_family == OFP_AF_LINK) {
			if (sa_dl_equal(ifma->ifma_addr, sa))
				break;
		} else {
			if (sa_equal(ifma->ifma_addr, sa))
				break;
		}
	}

	return ifma;
}

/*
 * Allocate a new ifmultiaddr and initialize based on passed arguments.  We
 * make copies of passed sockaddrs.  The ifmultiaddr will not be added to
 * the ifnet multicast address list here, so the caller must do that and
 * other setup work (such as notifying the device driver).  The reference
 * count is initialized to 1.
 */
static struct ofp_ifmultiaddr *
if_allocmulti(struct ofp_ifnet *ifp, struct ofp_sockaddr *sa, struct ofp_sockaddr *llsa,
    int mflags)
{
	struct ofp_ifmultiaddr *ifma;
	struct ofp_sockaddr *dupsa;
	(void)mflags;

	ifma = malloc0(sizeof *ifma);
	if (ifma == NULL)
		return (NULL);

	dupsa = malloc(sa->sa_len);
	if (dupsa == NULL) {
		free(ifma);
		return (NULL);
	}
	bcopy(sa, dupsa, sa->sa_len);
	ifma->ifma_addr = dupsa;

	ifma->ifma_ifp = ifp;
	ifma->ifma_refcount = 1;
	ifma->ifma_protospec = NULL;

	if (llsa == NULL) {
		ifma->ifma_lladdr = NULL;
		return (ifma);
	}

	dupsa = malloc(llsa->sa_len);
	if (dupsa == NULL) {
		free(ifma->ifma_addr);
		free(ifma);
		return (NULL);
	}
	bcopy(llsa, dupsa, llsa->sa_len);
	ifma->ifma_lladdr = dupsa;

	return (ifma);
}

/*
 * if_freemulti: free ifmultiaddr structure and possibly attached related
 * addresses.  The caller is responsible for implementing reference
 * counting, notifying the driver, handling routing messages, and releasing
 * any dependent link layer state.
 */
static void
if_freemulti(struct ofp_ifmultiaddr *ifma)
{

	KASSERT(ifma->ifma_refcount == 0, ("if_freemulti: refcount %d",
	    ifma->ifma_refcount));
	KASSERT(ifma->ifma_protospec == NULL,
	    ("if_freemulti: protospec not NULL"));

	if (ifma->ifma_lladdr != NULL)
		free(ifma->ifma_lladdr);
	free(ifma->ifma_addr);
	free(ifma);
}

/*
 * Perform deletion of network-layer and/or link-layer multicast address.
 *
 * Return 0 if the reference count was decremented.
 * Return 1 if the final reference was released, indicating that the
 * hardware hash filter should be reprogrammed.
 */
static int
if_delmulti_locked(struct ofp_ifnet *ifp, struct ofp_ifmultiaddr *ifma, int detaching)
{
	struct ofp_ifmultiaddr *ll_ifma;

	if (ifp != NULL && ifma->ifma_ifp != NULL) {
		KASSERT(ifma->ifma_ifp == ifp,
		    ("%s: inconsistent ifp %p", __func__, ifp));
		IF_ADDR_WLOCK_ASSERT(ifp);
	}

	ifp = ifma->ifma_ifp;

	/*
	 * If the ifnet is detaching, null out references to ifnet,
	 * so that upper protocol layers will notice, and not attempt
	 * to obtain locks for an ifnet which no longer exists. The
	 * routing socket announcement must happen before the ifnet
	 * instance is detached from the system.
	 */
	if (detaching) {
#ifdef DIAGNOSTIC
		OFP_DBG("detaching ifnet instance %p", ifp);
#endif
		/*
		 * ifp may already be nulled out if we are being reentered
		 * to delete the ll_ifma.
		 */
		if (ifp != NULL) {
			//HJo FIX: rt_newmaddrmsg(RTM_DELMADDR, ifma);
			ifma->ifma_ifp = NULL;
		}
	}

	if (--ifma->ifma_refcount > 0)
		return 0;

	/*
	 * If this ifma is a network-layer ifma, a link-layer ifma may
	 * have been associated with it. Release it first if so.
	 */
	ll_ifma = ifma->ifma_llifma;
	if (ll_ifma != NULL) {
		KASSERT(ifma->ifma_lladdr != NULL,
		    ("%s: llifma w/o lladdr", __func__));
		if (detaching)
			ll_ifma->ifma_ifp = NULL;	/* XXX */
		if (--ll_ifma->ifma_refcount == 0) {
			if (ifp != NULL) {
				OFP_TAILQ_REMOVE(&ifp->if_multiaddrs, ll_ifma,
						 ifma_link);
			}
			if_freemulti(ll_ifma);
		}
	}

	if (ifp != NULL)
		OFP_TAILQ_REMOVE(&ifp->if_multiaddrs, ifma, ifma_link);

	if_freemulti(ifma);

	/*
	 * The last reference to this instance of struct ifmultiaddr
	 * was released; the hardware should be notified of this change.
	 */
	return 1;
}

/*
 * Delete a multicast group membership by group membership pointer.
 * Network-layer protocol domains must use this routine.
 *
 * It is safe to call this routine if the ifp disappeared.
 */
void
ofp_if_delmulti_ifma(struct ofp_ifmultiaddr *ifma)
{
	struct ofp_ifnet *ifp;
	int lastref;

	ifp = ifma->ifma_ifp;
#ifdef DIAGNOSTIC
	if (ifp == NULL) {
		OFP_DBG("ifma_ifp seems to be detached\n");
	} else {
		struct ifnet *oifp;

		IFNET_RLOCK_NOSLEEP();
		TAILQ_FOREACH(oifp, &V_ifnet, if_link)
			if (ifp == oifp)
				break;
		if (ifp != oifp) {
			OFP_DBG("ifnet %p disappeared\n", ifp);
			ifp = NULL;
		}
		IFNET_RUNLOCK_NOSLEEP();
	}
#endif
	/*
	 * If and only if the ifnet instance exists: Acquire the address lock.
	 */
	if (ifp != NULL)
		IF_ADDR_WLOCK(ifp);

	lastref = if_delmulti_locked(ifp, ifma, 0);

	if (ifp != NULL) {
		/*
		 * If and only if the ifnet instance exists:
		 *  Release the address lock.
		 *  If the group was left: update the hardware hash filter.
		 */
		IF_ADDR_WUNLOCK(ifp);
		(void)lastref;
#if 0 //HJo
		if (lastref && ifp->if_ioctl != NULL) {
			(void)(*ifp->if_ioctl)(ifp, SIOCDELMULTI, 0);
		}
#endif
	}
}
