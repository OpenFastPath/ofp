/*-
 * Copyright (c) 2007-2009 Bruce Simpson.
 * Copyright (c) 1988 Stephen Deering.
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Stephen Deering of Stanford University.
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
 *	@(#)igmp.c	8.1 (Berkeley) 7/19/93
 */

/*
 * Internet Group Management Protocol (IGMP) routines.
 * [RFC1112, RFC2236, RFC3376]
 *
 * Written by Steve Deering, Stanford, May 1988.
 * Modified by Rosen Sharma, Stanford, Aug 1994.
 * Modified by Bill Fenner, Xerox PARC, Feb 1995.
 * Modified to fully comply to IGMPv2 by Bill Fenner, Oct 1995.
 * Significantly rewritten for IGMPv3, VIMAGE, and SMP by Bruce Simpson.
 *
 * MULTICAST Revision: 3.5.1.4
 */

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
#include "ofpi_pkt_processing.h"

#ifndef KTR_IGMPV3
#define KTR_IGMPV3 0x00200000 /* KTR_INET */
#endif

static struct ofp_igmp_ifinfo *
		igi_alloc_locked(struct ofp_ifnet *);
static void	igi_delete_locked(const struct ofp_ifnet *);
static void	igmp_dispatch_queue(struct ofp_ifqueue *, int, const int);
static void	igmp_final_leave(struct ofp_in_multi *, struct ofp_igmp_ifinfo *);
static int	igmp_handle_state_change(struct ofp_in_multi *,
		    struct ofp_igmp_ifinfo *);
static int	igmp_initial_join(struct ofp_in_multi *, struct ofp_igmp_ifinfo *);
static int	igmp_input_v1_query(struct ofp_ifnet *, const struct ofp_ip *,
		    const struct igmp *);
static int	igmp_input_v2_query(struct ofp_ifnet *, const struct ofp_ip *,
		    const struct igmp *);
static int	igmp_input_v3_query(struct ofp_ifnet *, const struct ofp_ip *,
		    /*const*/ struct igmpv3 *);
static int	igmp_input_v3_group_query(struct ofp_in_multi *,
		    struct ofp_igmp_ifinfo *, int, /*const*/ struct igmpv3 *);
static int	igmp_input_v1_report(struct ofp_ifnet *, /*const*/ struct ofp_ip *,
		    /*const*/ struct igmp *);
static int	igmp_input_v2_report(struct ofp_ifnet *, /*const*/ struct ofp_ip *,
		    /*const*/ struct igmp *);
static void	igmp_intr(odp_packet_t );
static int	igmp_isgroupreported(const struct ofp_in_addr);
static odp_packet_t
		igmp_ra_alloc(void);
#ifdef IGMP_DEBUG
static const char *igmp_rec_type_to_str(const int);
#endif
static void	igmp_set_version(struct ofp_igmp_ifinfo *, const int);
static void	igmp_slowtimo_vnet(void);
static int	igmp_v1v2_queue_report(struct ofp_in_multi *, const int);
static void	igmp_v1v2_process_group_timer(struct ofp_in_multi *, const int);
static void	igmp_v1v2_process_querier_timers(struct ofp_igmp_ifinfo *);
static void	igmp_v2_update_group(struct ofp_in_multi *, const int);
static void	igmp_v3_cancel_link_timers(struct ofp_igmp_ifinfo *);
static void	igmp_v3_dispatch_general_query(struct ofp_igmp_ifinfo *);
static odp_packet_t
		igmp_v3_encap_report(struct ofp_ifnet *, odp_packet_t );
static int	igmp_v3_enqueue_group_record(struct ofp_ifqueue *,
		    struct ofp_in_multi *, const int, const int, const int);
static int	igmp_v3_enqueue_filter_change(struct ofp_ifqueue *,
		    struct ofp_in_multi *);
static void	igmp_v3_process_group_timers(struct ofp_igmp_ifinfo *,
		    struct ofp_ifqueue *, struct ofp_ifqueue *, struct ofp_in_multi *,
		    const int);
static int	igmp_v3_merge_state_changes(struct ofp_in_multi *,
		    struct ofp_ifqueue *);
static void	igmp_v3_suppress_group_record(struct ofp_in_multi *);
static int	sysctl_igmp_default_version(OFP_SYSCTL_HANDLER_ARGS);
static int	sysctl_igmp_gsr(OFP_SYSCTL_HANDLER_ARGS);
//HJo static int	sysctl_igmp_ifinfo(OFP_SYSCTL_HANDLER_ARGS);

#if 0 /* HJo: FIX */
static const struct netisr_handler igmp_nh = {
	.nh_name = "igmp",
	.nh_handler = igmp_intr,
	.nh_proto = NETISR_IGMP,
	.nh_policy = NETISR_POLICY_SOURCE,
};
#endif

#ifdef IGMP_DEBUG
#define CTR1(_l, _fmt, ...)  OFP_DBG(_fmt, ##__VA_ARGS__)
#else
#define CTR1(_l, _fmt, ...) do { } while (0)
#endif
#define CTR2 CTR1
#define CTR3 CTR1
#define CTR4 CTR1
#define CTR5 CTR1

#define PKT2HDR(_pkt) ((struct ifq_entry *)odp_packet_head(_pkt))
#define HDR2PKT(_hdr) (_hdr ? _hdr->pkt : ODP_PACKET_INVALID)

struct socket *ofp_ip_mrouter = NULL;	/* multicast routing daemon */
VNET_DEFINE(struct ofp_ipstat, ofp_ipstat);

#if 0
static void ofp_packet_set_flags(odp_packet_t pkt, int flags)
{
	struct ifq_entry *e = odp_packet_head(pkt);
	e->flags = flags;
}
#endif

static void ofp_packet_set_flag(odp_packet_t pkt, int flag)
{
	struct ifq_entry *e = odp_packet_head(pkt);
	e->flags |= flag;
}

static void ofp_packet_reset_flag(odp_packet_t pkt, int flag)
{
	struct ifq_entry *e = odp_packet_head(pkt);
	e->flags &= ~flag;
}

static int ofp_packet_flags(odp_packet_t pkt)
{
	struct ifq_entry *e = odp_packet_head(pkt);
	return e->flags;
}

static struct ofp_ifnet *ifnet_byindex(int ifindex)
{
	return ofp_get_ifnet(ifindex & 0xf, ifindex >> 4);
}

#define	NETISR_IGMP	2		/* IGMPv3 output queue */
static void netisr_dispatch(int x, odp_packet_t pkt)
{
	(void)x;
	igmp_intr(pkt);
}


/*
 * System-wide globals.
 *
 * Unlocked access to these is OK, except for the global IGMP output
 * queue. The IGMP subsystem lock ends up being system-wide for the moment,
 * because all VIMAGEs have to share a global output queue, as netisrs
 * themselves are not virtualized.
 *
 * Locking:
 *  * The permitted lock order is: IN_MULTI_LOCK, IGMP_LOCK, IF_ADDR_LOCK.
 *    Any may be taken independently; if any are held at the same
 *    time, the above lock order must be followed.
 *  * All output is delegated to the netisr.
 *    Now that Giant has been eliminated, the netisr may be inlined.
 *  * IN_MULTI_LOCK covers in_multi.
 *  * IGMP_LOCK covers igmp_ifinfo and any global variables in this file,
 *    including the output queue.
 *  * IF_ADDR_LOCK covers if_multiaddrs, which is used for a variety of
 *    per-link state iterators.
 *  * igmp_ifinfo is valid as long as OFP_PF_INET is attached to the interface,
 *    therefore it is not refcounted.
 *    We allow unlocked reads of igmp_ifinfo when accessed via in_multi.
 *
 * Reference counting
 *  * IGMP acquires its own reference every time an in_multi is passed to
 *    it and the group is being joined for the first time.
 *  * IGMP releases its reference(s) on in_multi in a deferred way,
 *    because the operations which process the release run as part of
 *    a loop whose control variables are directly affected by the release
 *    (that, and not recursing on the IF_ADDR_LOCK).
 *
 * VIMAGE: Each in_multi corresponds to an ifp, and each ifp corresponds
 * to a vnet in ifp->if_vnet.
 *
 * SMPng: XXX We may potentially race operations on ifma_protospec.
 * The problem is that we currently lack a clean way of taking the
 * IF_ADDR_LOCK() between the ifnet and in layers w/o recursing,
 * as anything which modifies ifma needs to be covered by that lock.
 * So check for ifma_protospec being NULL before proceeding.
 */
odp_rwlock_t ofp_igmp_mtx;

odp_packet_t ofp_m_raopt = ODP_PACKET_INVALID; /* Router Alert option */
//HJo MALLOC_DEFINE(M_IGMP, "igmp", "igmp state");

#define	VNET_DEFINE(t, n)	t n
#define	VNET(n)			(n)

#define	VNET_ASSERT(exp, msg)
#define	CURVNET_SET(arg)
#define	CURVNET_SET_QUIET(arg)
#define	CURVNET_RESTORE()

#define	VNET_LIST_RLOCK()
#define	VNET_LIST_TRY_RLOCK()		1
#define	VNET_LIST_RLOCK_NOSLEEP()
#define	VNET_LIST_TRY_RLOCK_NOSLEEP()	1
#define	VNET_LIST_RUNLOCK()
#define	VNET_LIST_RUNLOCK_NOSLEEP()
#define	VNET_ITERATOR_DECL(arg)
#define	VNET_FOREACH(arg)
#define	V_if_index	VNET(if_index)

#define	SYSCTL_VNET_INT(parent, nbr, name, access, ptr, val, descr)	\
	OFP_SYSCTL_INT(parent, nbr, name, access, ptr, val, descr)
#define	SYSCTL_VNET_PROC(parent, nbr, name, access, ptr, arg, handler,	\
	    fmt, descr)							\
	OFP_SYSCTL_PROC(parent, nbr, name, access, ptr, arg, handler, fmt,	\
	    descr)
#define	SYSCTL_VNET_OPAQUE(parent, nbr, name, access, ptr, len, fmt,    \
	    descr)							\
	OFP_SYSCTL_OPAQUE(parent, nbr, name, access, ptr, len, fmt, descr)
#define	SYSCTL_VNET_STRING(parent, nbr, name, access, arg, len, descr)	\
	OFP_SYSCTL_STRING(parent, nbr, name, access, arg, len, descr)
#define	SYSCTL_VNET_STRUCT(parent, nbr, name, access, ptr, type, descr)	\
	OFP_SYSCTL_STRUCT(parent, nbr, name, access, ptr, type, descr)
#define	SYSCTL_VNET_UINT(parent, nbr, name, access, ptr, val, descr)	\
	OFP_SYSCTL_UINT(parent, nbr, name, access, ptr, val, descr)
#define	VNET_SYSCTL_ARG(req, arg1)

/*
 * VIMAGE-wide globals.
 *
 * The IGMPv3 timers themselves need to run per-image, however,
 * protosw timers run globally (see tcp).
 * An ifnet can only be in one vimage at a time, and the loopback
 * ifnet, loif, is itself virtualized.
 * It would otherwise be possible to seriously hose IGMP state,
 * and create inconsistencies in upstream multicast routing, if you have
 * multiple VIMAGEs running on the same link joining different multicast
 * groups, UNLESS the "primary IP address" is different. This is because
 * IGMP for IPv4 does not force link-local addresses to be used for each
 * node, unlike MLD for IPv6.
 * Obviously the IGMPv3 per-interface state has per-vimage granularity
 * also as a result.
 *
 * FUTURE: Stop using IFP_TO_IA/OFP_INADDR_ANY, and use source address selection
 * policy to control the address used by IGMP on the link.
 */
static VNET_DEFINE(int, interface_timers_running);	/* IGMPv3 general
							 * query response */
static VNET_DEFINE(int, state_change_timers_running);	/* IGMPv3 state-change
							 * retransmit */
static VNET_DEFINE(int, current_state_timers_running);	/* IGMPv1/v2 host
							 * report; IGMPv3 g/sg
							 * query response */

#define	V_interface_timers_running	VNET(interface_timers_running)
#define	V_state_change_timers_running	VNET(state_change_timers_running)
#define	V_current_state_timers_running	VNET(current_state_timers_running)

static VNET_DEFINE(OFP_LIST_HEAD(, ofp_igmp_ifinfo), igi_head);
static VNET_DEFINE(struct igmpstat, igmpstat) = {
	.igps_version = IGPS_VERSION_3,
	.igps_len = sizeof(struct igmpstat),
};
static VNET_DEFINE(struct ofp_timeval, igmp_gsrdelay) = {10, 0};

#define	V_igi_head			VNET(igi_head)
#define	V_igmpstat			VNET(igmpstat)
#define	V_igmp_gsrdelay			VNET(igmp_gsrdelay)

static VNET_DEFINE(int, igmp_recvifkludge) = 1;
static VNET_DEFINE(int, igmp_sendra) = 1;
static VNET_DEFINE(int, igmp_sendlocal) = 1;
static VNET_DEFINE(int, igmp_v1enable) = 1;
static VNET_DEFINE(int, igmp_v2enable) = 1;
static VNET_DEFINE(int, igmp_legacysupp);
static VNET_DEFINE(int, igmp_default_version) = IGMP_VERSION_3;

#define	V_igmp_recvifkludge		VNET(igmp_recvifkludge)
#define	V_igmp_sendra			VNET(igmp_sendra)
#define	V_igmp_sendlocal		VNET(igmp_sendlocal)
#define	V_igmp_v1enable			VNET(igmp_v1enable)
#define	V_igmp_v2enable			VNET(igmp_v2enable)
#define	V_igmp_legacysupp		VNET(igmp_legacysupp)
#define	V_igmp_default_version		VNET(igmp_default_version)

VNET_DEFINE(int, if_index);

odp_timer_t ofp_igmp_fasttimo_timer = ODP_TIMER_INVALID;

/*
 * Virtualized sysctls.
 */
SYSCTL_VNET_STRUCT(_net_inet_igmp, IGMPCTL_STATS, stats, OFP_CTLFLAG_RW,
    &VNET_NAME(igmpstat), igmpstat, "");
SYSCTL_VNET_INT(_net_inet_igmp, OFP_OID_AUTO, recvifkludge, OFP_CTLFLAG_RW,
    &VNET_NAME(igmp_recvifkludge), 0,
    "Rewrite IGMPv1/v2 reports from 0.0.0.0 to contain subnet address");
SYSCTL_VNET_INT(_net_inet_igmp, OFP_OID_AUTO, sendra, OFP_CTLFLAG_RW,
    &VNET_NAME(igmp_sendra), 0,
    "Send IP Router Alert option in IGMPv2/v3 messages");
SYSCTL_VNET_INT(_net_inet_igmp, OFP_OID_AUTO, sendlocal, OFP_CTLFLAG_RW,
    &VNET_NAME(igmp_sendlocal), 0,
    "Send IGMP membership reports for 224.0.0.0/24 groups");
SYSCTL_VNET_INT(_net_inet_igmp, OFP_OID_AUTO, v1enable, OFP_CTLFLAG_RW,
    &VNET_NAME(igmp_v1enable), 0,
    "Enable backwards compatibility with IGMPv1");
SYSCTL_VNET_INT(_net_inet_igmp, OFP_OID_AUTO, v2enable, OFP_CTLFLAG_RW,
    &VNET_NAME(igmp_v2enable), 0,
    "Enable backwards compatibility with IGMPv2");
SYSCTL_VNET_INT(_net_inet_igmp, OFP_OID_AUTO, legacysupp, OFP_CTLFLAG_RW,
    &VNET_NAME(igmp_legacysupp), 0,
    "Allow v1/v2 reports to suppress v3 group responses");
SYSCTL_VNET_PROC(_net_inet_igmp, OFP_OID_AUTO, default_version,
    OFP_CTLTYPE_INT | OFP_CTLFLAG_RW | OFP_CTLFLAG_MPSAFE,
    &VNET_NAME(igmp_default_version), 0, sysctl_igmp_default_version, "I",
    "Default version of IGMP to run on each interface");
SYSCTL_VNET_PROC(_net_inet_igmp, OFP_OID_AUTO, gsrdelay,
    OFP_CTLTYPE_INT | OFP_CTLFLAG_RW | OFP_CTLFLAG_MPSAFE,
    &VNET_NAME(igmp_gsrdelay.tv_sec), 0, sysctl_igmp_gsr, "I",
    "Rate limit for IGMPv3 Group-and-Source queries in seconds");

/*
 * Non-virtualized sysctls.
 */
#if 0 //HJo
OFP_SYSCTL_NODE(_net_inet_igmp, OFP_OID_AUTO, ifinfo, OFP_CTLFLAG_RD | OFP_CTLFLAG_MPSAFE,
    sysctl_igmp_ifinfo, "Per-interface IGMPv3 state");
#endif

static __inline void
igmp_save_context(odp_packet_t m, struct ofp_ifnet *ifp)
{
	struct ifq_entry *e = odp_packet_head(m);
	e->flowid = ifp->port | (ifp->vlan << 4);
}

static __inline void
igmp_scrub_context(odp_packet_t m)
{
	struct ifq_entry *e = odp_packet_head(m);
	//m->m_pkthdr.header = NULL;
	e->flowid = 0;
}

#ifdef KTR
static __inline char *
inet_ntoa_haddr(ofp_in_addr_t haddr)
{
	struct ofp_in_addr ia;

	ia.s_addr = odp_cpu_to_be_32(haddr);
	return (inet_ntoa(ia));
}
#endif

/*
 * Restore context from a queued IGMP output chain.
 * Return saved ifindex.
 *
 * VIMAGE: The assertion is there to make sure that we
 * actually called CURVNET_SET() with what's in the mbuf chain.
 */
static __inline uint32_t
igmp_restore_context(odp_packet_t m)
{
	struct ifq_entry *e = odp_packet_head(m);
	return e->flowid;
}

/*
 * Retrieve or set default IGMP version.
 *
 * VIMAGE: Assume curvnet set by caller.
 * SMPng: NOTE: Serialized by IGMP lock.
 */
static int
sysctl_igmp_default_version(OFP_SYSCTL_HANDLER_ARGS)
{
	int	 error;
	int	 new;
	(void)arg1;
	(void)arg2;
#if 0 /* HJo: FIX */
	error = sysctl_wire_old_buffer(req, sizeof(int));
	if (error)
		return (error);
#endif
	IGMP_LOCK();

	new = V_igmp_default_version;

	error = sysctl_handle_int(oidp, &new, 0, req);
	if (error || !req->newptr)
		goto out_locked;

	if (new < IGMP_VERSION_1 || new > IGMP_VERSION_3) {
		error = OFP_EINVAL;
		goto out_locked;
	}
	CTR2(KTR_IGMPV3, "change igmp_default_version from %d to %d",
	     V_igmp_default_version, new);

	V_igmp_default_version = new;

out_locked:
	IGMP_UNLOCK();
	return (error);
}

/*
 * Retrieve or set threshold between group-source queries in seconds.
 *
 * VIMAGE: Assume curvnet set by caller.
 * SMPng: NOTE: Serialized by IGMP lock.
 */
static int
sysctl_igmp_gsr(OFP_SYSCTL_HANDLER_ARGS)
{
	int error;
	int i;
	(void)arg1;
	(void)arg2;
#if 0 /*HJo: FIX */
	error = sysctl_wire_old_buffer(req, sizeof(int));
	if (error)
		return (error);
#endif
	IGMP_LOCK();

	i = V_igmp_gsrdelay.tv_sec;

	error = sysctl_handle_int(oidp, &i, 0, req);
	if (error || !req->newptr)
		goto out_locked;

	if (i < -1 || i >= 60) {
		error = OFP_EINVAL;
		goto out_locked;
	}

	CTR2(KTR_IGMPV3, "change igmp_gsrdelay from %d to %d",
	     V_igmp_gsrdelay.tv_sec, i);
	V_igmp_gsrdelay.tv_sec = i;

out_locked:
	IGMP_UNLOCK();
	return (error);
}

/*
 * Expose struct ofp_igmp_ifinfo to userland, keyed by ifindex.
 * For use by ifmcstat(8).
 *
 * SMPng: NOTE: Does an unlocked ifindex space read.
 * VIMAGE: Assume curvnet set by caller. The node handler itself
 * is not directly virtualized.
 */
#if 0 /*HJo*/
static int
sysctl_igmp_ifinfo(OFP_SYSCTL_HANDLER_ARGS)
{
	int			*name;
	int			 error;
	uint32_t			 namelen;
	struct ofp_ifnet		*ifp;
	struct ofp_igmp_ifinfo	*igi;

	name = (int *)arg1;
	namelen = arg2;

	if (req->newptr != NULL)
		return (OFP_EPERM);

	if (namelen != 1)
		return (OFP_EINVAL);
#if 0 /*HJo:FIX*/
	error = sysctl_wire_old_buffer(req, sizeof(struct ofp_igmp_ifinfo));
	if (error)
		return (error);
#endif
	IN_MULTI_LOCK();
	IGMP_LOCK();

	if (name[0] <= 0 || name[0] > V_if_index) {
		error = OFP_ENOENT;
		goto out_locked;
	}

	error = OFP_ENOENT;

	ifp = ifnet_byindex(name[0]);
	if (ifp == NULL)
		goto out_locked;

	OFP_LIST_FOREACH(igi, &V_igi_head, igi_link) {
		if (ifp == igi->igi_ifp) {
			error = OFP_SYSCTL_OUT(req, igi,
			    sizeof(struct ofp_igmp_ifinfo));
			break;
		}
	}

out_locked:
	IGMP_UNLOCK();
	IN_MULTI_UNLOCK();
	return (error);
}
#endif
/*
 * Dispatch an entire queue of pending packet chains
 * using the netisr.
 * VIMAGE: Assumes the vnet pointer has been set.
 */
static void
igmp_dispatch_queue(struct ofp_ifqueue *ifq, int limit, const int loop)
{
	odp_packet_t m;

	for (;;) {
		_IF_DEQUEUE(ifq, m);
		if (m == ODP_PACKET_INVALID)
			break;
		CTR3(KTR_IGMPV3, "%s: dispatch %p from %p", __func__, ifq, m);
		if (loop)
			ofp_packet_set_flag(m, M_IGMP_LOOP);
		netisr_dispatch(NETISR_IGMP, m);
		if (--limit == 0)
			break;
	}
}

/*
 * Filter outgoing IGMP report state by group.
 *
 * Reports are ALWAYS suppressed for ALL-HOSTS (224.0.0.1).
 * If the net.inet.igmp.sendlocal sysctl is 0, then IGMP reports are
 * disabled for all groups in the 224.0.0.0/24 link-local scope. However,
 * this may break certain IGMP snooping switches which rely on the old
 * report behaviour.
 *
 * Return zero if the given group is one for which IGMP reports
 * should be suppressed, or non-zero if reports should be issued.
 */
static __inline int
igmp_isgroupreported(const struct ofp_in_addr addr)
{

	if (ofp_in_allhosts(addr) ||
	    ((!V_igmp_sendlocal && OFP_IN_LOCAL_GROUP(odp_be_to_cpu_32(addr.s_addr)))))
		return (0);

	return (1);
}

/*
 * Construct a Router Alert option to use in outgoing packets.
 */
static odp_packet_t
igmp_ra_alloc(void)
{
	odp_packet_t m;
	struct ofp_ipoption *p;

	m = ofp_packet_alloc(sizeof(p->ipopt_dst) + 0x04);
	if (m == ODP_PACKET_INVALID)
		return m;
	p = (struct ofp_ipoption *)odp_packet_data(m);
	p->ipopt_dst.s_addr = OFP_INADDR_ANY;
	p->ipopt_list[0] = OFP_IPOPT_RA;	/* Router Alert Option */
	p->ipopt_list[1] = 0x04;	/* 4 bytes long */
	p->ipopt_list[2] = OFP_IPOPT_EOL;	/* End of IP option list */
	p->ipopt_list[3] = 0x00;	/* pad byte */

	return (m);
}

/*
 * Attach IGMP when OFP_PF_INET is attached to an interface.
 */
struct ofp_igmp_ifinfo *
ofp_igmp_domifattach(struct ofp_ifnet *ifp)
{
	struct ofp_igmp_ifinfo *igi;

	CTR3(KTR_IGMPV3, "%s: called for ifp %p(%s)",
	    __func__, ifp, ifp->if_name);

	IGMP_LOCK();

	igi = igi_alloc_locked(ifp);
	if (!(ifp->if_flags & OFP_IFF_MULTICAST))
		igi->igi_flags |= IGIF_SILENT;

	IGMP_UNLOCK();

	return (igi);
}

/*
 * VIMAGE: assume curvnet set by caller.
 */
static struct ofp_igmp_ifinfo *
igi_alloc_locked(/*const*/ struct ofp_ifnet *ifp)
{
	struct ofp_igmp_ifinfo *igi;

	IGMP_LOCK_ASSERT();

	igi = calloc(1, sizeof(struct ofp_igmp_ifinfo));
	if (igi == NULL)
		goto out;

	igi->igi_ifp = ifp;
	igi->igi_version = V_igmp_default_version;
	igi->igi_flags = 0;
	igi->igi_rv = IGMP_RV_INIT;
	igi->igi_qi = IGMP_QI_INIT;
	igi->igi_qri = IGMP_QRI_INIT;
	igi->igi_uri = IGMP_URI_INIT;

	OFP_SLIST_INIT(&igi->igi_relinmhead);

	/*
	 * Responses to general queries are subject to bounds.
	 */
	IFQ_SET_MAXLEN(&igi->igi_gq, IGMP_MAX_RESPONSE_PACKETS);

	OFP_LIST_INSERT_HEAD(&V_igi_head, igi, igi_link);

	CTR2(KTR_IGMPV3, "allocate igmp_ifinfo for ifp %p(%s)",
	     ifp, ifp->if_name);

out:
	return (igi);
}

/*
 * Hook for ifdetach.
 *
 * NOTE: Some finalization tasks need to run before the protocol domain
 * is detached, but also before the link layer does its cleanup.
 *
 * SMPNG: ofp_igmp_ifdetach() needs to take IF_ADDR_LOCK().
 * XXX This is also bitten by unlocked ifma_protospec access.
 */
void
ofp_igmp_ifdetach(struct ofp_ifnet *ifp)
{
	struct ofp_igmp_ifinfo	*igi;
	struct ofp_ifmultiaddr	*ifma;
	struct ofp_in_multi	*inm, *tinm;

	CTR3(KTR_IGMPV3, "%s: called for ifp %p(%s)", __func__, ifp,
	    ifp->if_name);

	IGMP_LOCK();

	igi = ((struct ofp_in_ifinfo *)ifp->if_afdata[OFP_AF_INET])->ii_igmp;
	if (igi->igi_version == IGMP_VERSION_3) {
		IF_ADDR_RLOCK(ifp);
		OFP_TAILQ_FOREACH(ifma, &ifp->if_multiaddrs, ifma_link) {
			if (ifma->ifma_addr->sa_family != OFP_AF_INET ||
			    ifma->ifma_protospec == NULL)
				continue;
#if 0
			KASSERT(ifma->ifma_protospec != NULL,
			    ("%s: ifma_protospec is NULL", __func__));
#endif
			inm = (struct ofp_in_multi *)ifma->ifma_protospec;
			if (inm->inm_state == IGMP_LEAVING_MEMBER) {
				OFP_SLIST_INSERT_HEAD(&igi->igi_relinmhead,
				    inm, inm_nrele);
			}
			ofp_inm_clear_recorded(inm);
		}
		IF_ADDR_RUNLOCK(ifp);
		/*
		 * Free the in_multi reference(s) for this IGMP lifecycle.
		 */
		OFP_SLIST_FOREACH_SAFE(inm, &igi->igi_relinmhead, inm_nrele,
		    tinm) {
			OFP_SLIST_REMOVE_HEAD(&igi->igi_relinmhead, inm_nrele);
			ofp_inm_release_locked(inm);
		}
	}

	IGMP_UNLOCK();
}

/*
 * Hook for domifdetach.
 */
void
ofp_igmp_domifdetach(struct ofp_ifnet *ifp)
{
	struct ofp_igmp_ifinfo *igi;

	CTR3(KTR_IGMPV3, "%s: called for ifp %p(%s)",
	    __func__, ifp, ifp->if_name);

	IGMP_LOCK();

	igi = ((struct ofp_in_ifinfo *)ifp->if_afdata[OFP_AF_INET])->ii_igmp;
	(void)igi;
	igi_delete_locked(ifp);

	IGMP_UNLOCK();
}

static void
igi_delete_locked(const struct ofp_ifnet *ifp)
{
	struct ofp_igmp_ifinfo *igi, *tigi;

	CTR3(KTR_IGMPV3, "%s: freeing igmp_ifinfo for ifp %p(%s)",
	    __func__, ifp, ifp->if_name);

	IGMP_LOCK_ASSERT();

	OFP_LIST_FOREACH_SAFE(igi, &V_igi_head, igi_link, tigi) {
		if (igi->igi_ifp == ifp) {
			/*
			 * Free deferred General Query responses.
			 */
			_IF_DRAIN(&igi->igi_gq);

			OFP_LIST_REMOVE(igi, igi_link);

			KASSERT(OFP_SLIST_EMPTY(&igi->igi_relinmhead),
			    ("%s: there are dangling in_multi references",
			    __func__));

			free(igi);
			return;
		}
	}

#ifdef INVARIANTS
	panic("%s: igmp_ifinfo not found for ifp %p\n", __func__,  ifp);
#endif
}

/*
 * Process a received IGMPv1 query.
 * Return non-zero if the message should be dropped.
 *
 * VIMAGE: The curvnet pointer is derived from the input ifp.
 */
static int
igmp_input_v1_query(struct ofp_ifnet *ifp, const struct ofp_ip *ip,
    const struct igmp *igmp)
{
	struct ofp_ifmultiaddr	*ifma;
	struct ofp_igmp_ifinfo	*igi;
	struct ofp_in_multi		*inm;

	/*
	 * IGMPv1 Host Mmembership Queries SHOULD always be addressed to
	 * 224.0.0.1. They are always treated as General Queries.
	 * igmp_group is always ignored. Do not drop it as a userland
	 * daemon may wish to see it.
	 * XXX SMPng: unlocked increments in igmpstat assumed atomic.
	 */
	if (!ofp_in_allhosts(ip->ip_dst) || !ofp_in_nullhost(igmp->igmp_group)) {
		IGMPSTAT_INC(igps_rcv_badqueries);
		return (0);
	}
	IGMPSTAT_INC(igps_rcv_gen_queries);

	IN_MULTI_LOCK();
	IGMP_LOCK();

	igi = ((struct ofp_in_ifinfo *)ifp->if_afdata[OFP_AF_INET])->ii_igmp;
	KASSERT(igi != NULL, ("%s: no igmp_ifinfo for ifp %p", __func__, ifp));

	if (igi->igi_flags & IGIF_LOOPBACK) {
		CTR2(KTR_IGMPV3, "ignore v1 query on IGIF_LOOPBACK ifp %p(%s)",
		    ifp, ifp->if_name);
		goto out_locked;
	}

	/*
	 * Switch to IGMPv1 host compatibility mode.
	 */
	igmp_set_version(igi, IGMP_VERSION_1);

	CTR2(KTR_IGMPV3, "process v1 query on ifp %p(%s)", ifp, ifp->if_name);

	/*
	 * Start the timers in all of our group records
	 * for the interface on which the query arrived,
	 * except those which are already running.
	 */
	IF_ADDR_RLOCK(ifp);
	OFP_TAILQ_FOREACH(ifma, &ifp->if_multiaddrs, ifma_link) {
		if (ifma->ifma_addr->sa_family != OFP_AF_INET ||
		    ifma->ifma_protospec == NULL)
			continue;
		inm = (struct ofp_in_multi *)ifma->ifma_protospec;
		if (inm->inm_timer != 0)
			continue;
		switch (inm->inm_state) {
		case IGMP_NOT_MEMBER:
		case IGMP_SILENT_MEMBER:
			break;
		case IGMP_G_QUERY_PENDING_MEMBER:
		case IGMP_SG_QUERY_PENDING_MEMBER:
		case IGMP_REPORTING_MEMBER:
		case IGMP_IDLE_MEMBER:
		case IGMP_LAZY_MEMBER:
		case IGMP_SLEEPING_MEMBER:
		case IGMP_AWAKENING_MEMBER:
			inm->inm_state = IGMP_REPORTING_MEMBER;
			inm->inm_timer = IGMP_RANDOM_DELAY(
			    IGMP_V1V2_MAX_RI * PR_FASTHZ);
			V_current_state_timers_running = 1;
			break;
		case IGMP_LEAVING_MEMBER:
			break;
		}
	}
	IF_ADDR_RUNLOCK(ifp);

out_locked:
	IGMP_UNLOCK();
	IN_MULTI_UNLOCK();

	return (0);
}

/*
 * Process a received IGMPv2 general or group-specific query.
 */
static int
igmp_input_v2_query(struct ofp_ifnet *ifp, const struct ofp_ip *ip,
    const struct igmp *igmp)
{
	struct ofp_ifmultiaddr	*ifma;
	struct ofp_igmp_ifinfo	*igi;
	struct ofp_in_multi		*inm;
	int			 is_general_query;
	uint16_t		 timer;

	is_general_query = 0;

	/*
	 * Validate address fields upfront.
	 * XXX SMPng: unlocked increments in igmpstat assumed atomic.
	 */
	if (ofp_in_nullhost(igmp->igmp_group)) {
		/*
		 * IGMPv2 General Query.
		 * If this was not sent to the all-hosts group, ignore it.
		 */
		if (!ofp_in_allhosts(ip->ip_dst))
			return (0);
		IGMPSTAT_INC(igps_rcv_gen_queries);
		is_general_query = 1;
	} else {
		/* IGMPv2 Group-Specific Query. */
		IGMPSTAT_INC(igps_rcv_group_queries);
	}

	IN_MULTI_LOCK();
	IGMP_LOCK();

	igi = ((struct ofp_in_ifinfo *)ifp->if_afdata[OFP_AF_INET])->ii_igmp;
	KASSERT(igi != NULL, ("%s: no igmp_ifinfo for ifp %p", __func__, ifp));

	if (igi->igi_flags & IGIF_LOOPBACK) {
		CTR2(KTR_IGMPV3, "ignore v2 query on IGIF_LOOPBACK ifp %p(%s)",
		    ifp, ifp->if_name);
		goto out_locked;
	}

	/*
	 * Ignore v2 query if in v1 Compatibility Mode.
	 */
	if (igi->igi_version == IGMP_VERSION_1)
		goto out_locked;

	igmp_set_version(igi, IGMP_VERSION_2);

	timer = igmp->igmp_code * PR_FASTHZ / IGMP_TIMER_SCALE;
	if (timer == 0)
		timer = 1;

	if (is_general_query) {
		/*
		 * For each reporting group joined on this
		 * interface, kick the report timer.
		 */
		CTR2(KTR_IGMPV3, "process v2 general query on ifp %p(%s)",
		    ifp, ifp->if_name);
		IF_ADDR_RLOCK(ifp);
		OFP_TAILQ_FOREACH(ifma, &ifp->if_multiaddrs, ifma_link) {
			if (ifma->ifma_addr->sa_family != OFP_AF_INET ||
			    ifma->ifma_protospec == NULL)
				continue;
			inm = (struct ofp_in_multi *)ifma->ifma_protospec;
			igmp_v2_update_group(inm, timer);
		}
		IF_ADDR_RUNLOCK(ifp);
	} else {
		/*
		 * Group-specific IGMPv2 query, we need only
		 * look up the single group to process it.
		 */
		inm = inm_lookup(ifp, igmp->igmp_group);
		if (inm != NULL) {
			CTR3(KTR_IGMPV3, "process v2 query %s on ifp %p(%s)",
			    ofp_print_ip_addr(igmp->igmp_group.s_addr), ifp, ifp->if_name);
			igmp_v2_update_group(inm, timer);
		}
	}

out_locked:
	IGMP_UNLOCK();
	IN_MULTI_UNLOCK();

	return (0);
}

/*
 * Update the report timer on a group in response to an IGMPv2 query.
 *
 * If we are becoming the reporting member for this group, start the timer.
 * If we already are the reporting member for this group, and timer is
 * below the threshold, reset it.
 *
 * We may be updating the group for the first time since we switched
 * to IGMPv3. If we are, then we must clear any recorded source lists,
 * and transition to REPORTING state; the group timer is overloaded
 * for group and group-source query responses.
 *
 * Unlike IGMPv3, the delay per group should be jittered
 * to avoid bursts of IGMPv2 reports.
 */
static void
igmp_v2_update_group(struct ofp_in_multi *inm, const int timer)
{

	CTR4(KTR_IGMPV3, "%s: %s/%s timer=%d", __func__,
	    ofp_print_ip_addr(inm->inm_addr.s_addr), inm->inm_ifp->if_name, timer);

	IN_MULTI_LOCK_ASSERT();

	switch (inm->inm_state) {
	case IGMP_NOT_MEMBER:
	case IGMP_SILENT_MEMBER:
		break;
	case IGMP_REPORTING_MEMBER:
		if (inm->inm_timer != 0 &&
		    (int)inm->inm_timer <= timer) {
			CTR1(KTR_IGMPV3, "%s: REPORTING and timer running, "
			    "skipping.", __func__);
			break;
		}
		/* FALLTHROUGH */
	case IGMP_SG_QUERY_PENDING_MEMBER:
	case IGMP_G_QUERY_PENDING_MEMBER:
	case IGMP_IDLE_MEMBER:
	case IGMP_LAZY_MEMBER:
	case IGMP_AWAKENING_MEMBER:
		CTR1(KTR_IGMPV3, "%s: ->REPORTING", __func__);
		inm->inm_state = IGMP_REPORTING_MEMBER;
		inm->inm_timer = IGMP_RANDOM_DELAY(timer);
		V_current_state_timers_running = 1;
		break;
	case IGMP_SLEEPING_MEMBER:
		CTR1(KTR_IGMPV3, "%s: ->AWAKENING", __func__);
		inm->inm_state = IGMP_AWAKENING_MEMBER;
		break;
	case IGMP_LEAVING_MEMBER:
		break;
	}
}

/*
 * Process a received IGMPv3 general, group-specific or
 * group-and-source-specific query.
 * Assumes m has already been pulled up to the full IGMP message length.
 * Return 0 if successful, otherwise an appropriate error code is returned.
 */
static int
igmp_input_v3_query(struct ofp_ifnet *ifp, const struct ofp_ip *ip,
    /*const*/ struct igmpv3 *igmpv3)
{
	struct ofp_igmp_ifinfo	*igi;
	struct ofp_in_multi		*inm;
	int			 is_general_query;
	uint32_t		 maxresp, nsrc, qqi;
	uint16_t		 timer;
	uint8_t			 qrv;

	is_general_query = 0;

	CTR2(KTR_IGMPV3, "process v3 query on ifp %p(%s)", ifp, ifp->if_name);

	maxresp = igmpv3->igmp_code;	/* in 1/10ths of a second */
	if (maxresp >= 128) {
		maxresp = IGMP_MANT(igmpv3->igmp_code) <<
			  (IGMP_EXP(igmpv3->igmp_code) + 3);
	}

	/*
	 * Robustness must never be less than 2 for on-wire IGMPv3.
	 * FUTURE: Check if ifp has IGIF_LOOPBACK set, as we will make
	 * an exception for interfaces whose IGMPv3 state changes
	 * are redirected to loopback (e.g. MANET).
	 */
	qrv = IGMP_QRV(igmpv3->igmp_misc);
	if (qrv < 2) {
		CTR3(KTR_IGMPV3, "%s: clamping qrv %d to %d", __func__,
		    qrv, IGMP_RV_INIT);
		qrv = IGMP_RV_INIT;
	}

	qqi = igmpv3->igmp_qqi;
	if (qqi >= 128) {
		qqi = IGMP_MANT(igmpv3->igmp_qqi) <<
		     (IGMP_EXP(igmpv3->igmp_qqi) + 3);
	}

	timer = maxresp * PR_FASTHZ / IGMP_TIMER_SCALE;
	if (timer == 0)
		timer = 1;

	nsrc = odp_be_to_cpu_16(igmpv3->igmp_numsrc);

	/*
	 * Validate address fields and versions upfront before
	 * accepting v3 query.
	 * XXX SMPng: Unlocked access to igmpstat counters here.
	 */
	if (ofp_in_nullhost(igmpv3->igmp_group)) {
		/*
		 * IGMPv3 General Query.
		 *
		 * General Queries SHOULD be directed to 224.0.0.1.
		 * A general query with a source list has undefined
		 * behaviour; discard it.
		 */
		IGMPSTAT_INC(igps_rcv_gen_queries);
		if (!ofp_in_allhosts(ip->ip_dst) || nsrc > 0) {
			IGMPSTAT_INC(igps_rcv_badqueries);
			return (0);
		}
		is_general_query = 1;
	} else {
		/* Group or group-source specific query. */
		if (nsrc == 0)
			IGMPSTAT_INC(igps_rcv_group_queries);
		else
			IGMPSTAT_INC(igps_rcv_gsr_queries);
	}

	IN_MULTI_LOCK();
	IGMP_LOCK();

	igi = ((struct ofp_in_ifinfo *)ifp->if_afdata[OFP_AF_INET])->ii_igmp;
	KASSERT(igi != NULL, ("%s: no igmp_ifinfo for ifp %p", __func__, ifp));

	if (igi->igi_flags & IGIF_LOOPBACK) {
		CTR2(KTR_IGMPV3, "ignore v3 query on IGIF_LOOPBACK ifp %p(%s)",
		    ifp, ifp->if_name);
		goto out_locked;
	}

	/*
	 * Discard the v3 query if we're in Compatibility Mode.
	 * The RFC is not obviously worded that hosts need to stay in
	 * compatibility mode until the Old Version Querier Present
	 * timer expires.
	 */
	if (igi->igi_version != IGMP_VERSION_3) {
		CTR3(KTR_IGMPV3, "ignore v3 query in v%d mode on ifp %p(%s)",
		    igi->igi_version, ifp, ifp->if_name);
		goto out_locked;
	}

	igmp_set_version(igi, IGMP_VERSION_3);
	igi->igi_rv = qrv;
	igi->igi_qi = qqi;
	igi->igi_qri = maxresp;

	CTR4(KTR_IGMPV3, "%s: qrv %d qi %d qri %d", __func__, qrv, qqi,
	    maxresp);

	if (is_general_query) {
		/*
		 * Schedule a current-state report on this ifp for
		 * all groups, possibly containing source lists.
		 * If there is a pending General Query response
		 * scheduled earlier than the selected delay, do
		 * not schedule any other reports.
		 * Otherwise, reset the interface timer.
		 */
		CTR2(KTR_IGMPV3, "process v3 general query on ifp %p(%s)",
		    ifp, ifp->if_name);
		if (igi->igi_v3_timer == 0 || igi->igi_v3_timer >= timer) {
			igi->igi_v3_timer = IGMP_RANDOM_DELAY(timer);
			V_interface_timers_running = 1;
		}
	} else {
		/*
		 * Group-source-specific queries are throttled on
		 * a per-group basis to defeat denial-of-service attempts.
		 * Queries for groups we are not a member of on this
		 * link are simply ignored.
		 */
		inm = inm_lookup(ifp, igmpv3->igmp_group);
		if (inm == NULL)
			goto out_locked;
#if 0 /* HJo */
		if (nsrc > 0) {
			if (!ratecheck(&inm->inm_lastgsrtv,
				&V_igmp_gsrdelay)) {
				CTR1(KTR_IGMPV3, "%s: GS query throttled.",
				    __func__);
				IGMPSTAT_INC(igps_drop_gsr_queries);
				goto out_locked;
			}
		}
#endif
		CTR3(KTR_IGMPV3, "process v3 %s query on ifp %p(%s)",
		     ofp_print_ip_addr(igmpv3->igmp_group.s_addr), ifp, ifp->if_name);
		/*
		 * If there is a pending General Query response
		 * scheduled sooner than the selected delay, no
		 * further report need be scheduled.
		 * Otherwise, prepare to respond to the
		 * group-specific or group-and-source query.
		 */
		if (igi->igi_v3_timer == 0 || igi->igi_v3_timer >= timer)
			igmp_input_v3_group_query(inm, igi, timer, igmpv3);
	}

out_locked:
	IGMP_UNLOCK();
	IN_MULTI_UNLOCK();

	return (0);
}

/*
 * Process a recieved IGMPv3 group-specific or group-and-source-specific
 * query.
 * Return <0 if any error occured. Currently this is ignored.
 */
static int
igmp_input_v3_group_query(struct ofp_in_multi *inm, struct ofp_igmp_ifinfo *igi,
    int timer, /*const*/ struct igmpv3 *igmpv3)
{
	int			 retval;
	uint16_t		 nsrc;
	(void)igi;

	IN_MULTI_LOCK_ASSERT();
	IGMP_LOCK_ASSERT();

	retval = 0;

	switch (inm->inm_state) {
	case IGMP_NOT_MEMBER:
	case IGMP_SILENT_MEMBER:
	case IGMP_SLEEPING_MEMBER:
	case IGMP_LAZY_MEMBER:
	case IGMP_AWAKENING_MEMBER:
	case IGMP_IDLE_MEMBER:
	case IGMP_LEAVING_MEMBER:
		return (retval);
		break;
	case IGMP_REPORTING_MEMBER:
	case IGMP_G_QUERY_PENDING_MEMBER:
	case IGMP_SG_QUERY_PENDING_MEMBER:
		break;
	}

	nsrc = odp_be_to_cpu_16(igmpv3->igmp_numsrc);

	/*
	 * Deal with group-specific queries upfront.
	 * If any group query is already pending, purge any recorded
	 * source-list state if it exists, and schedule a query response
	 * for this group-specific query.
	 */
	if (nsrc == 0) {
		if (inm->inm_state == IGMP_G_QUERY_PENDING_MEMBER ||
		    inm->inm_state == IGMP_SG_QUERY_PENDING_MEMBER) {
			ofp_inm_clear_recorded(inm);
			timer = min(inm->inm_timer, timer);
		}
		inm->inm_state = IGMP_G_QUERY_PENDING_MEMBER;
		inm->inm_timer = IGMP_RANDOM_DELAY(timer);
		V_current_state_timers_running = 1;
		return (retval);
	}

	/*
	 * Deal with the case where a group-and-source-specific query has
	 * been received but a group-specific query is already pending.
	 */
	if (inm->inm_state == IGMP_G_QUERY_PENDING_MEMBER) {
		timer = min(inm->inm_timer, timer);
		inm->inm_timer = IGMP_RANDOM_DELAY(timer);
		V_current_state_timers_running = 1;
		return (retval);
	}

	/*
	 * Finally, deal with the case where a group-and-source-specific
	 * query has been received, where a response to a previous g-s-r
	 * query exists, or none exists.
	 * In this case, we need to parse the source-list which the Querier
	 * has provided us with and check if we have any source list filter
	 * entries at T1 for these sources. If we do not, there is no need
	 * schedule a report and the query may be dropped.
	 * If we do, we must record them and schedule a current-state
	 * report for those sources.
	 * FIXME: Handling source lists larger than 1 mbuf requires that
	 * we pass the mbuf chain pointer down to this function, and use
	 * m_getptr() to walk the chain.
	 */
	if (inm->inm_nsrc > 0) {
		const struct ofp_in_addr	*ap;
		int			 i, nrecorded;

		ap = (const struct ofp_in_addr *)(igmpv3 + 1);
		nrecorded = 0;
		for (i = 0; i < nsrc; i++, ap++) {
			retval = ofp_inm_record_source(inm, ap->s_addr);
			if (retval < 0)
				break;
			nrecorded += retval;
		}
		if (nrecorded > 0) {
			CTR1(KTR_IGMPV3,
			    "%s: schedule response to SG query", __func__);
			inm->inm_state = IGMP_SG_QUERY_PENDING_MEMBER;
			inm->inm_timer = IGMP_RANDOM_DELAY(timer);
			V_current_state_timers_running = 1;
		}
	}

	return (retval);
}

/*
 * Process a received IGMPv1 host membership report.
 *
 * NOTE: 0.0.0.0 workaround breaks const correctness.
 */
static int
igmp_input_v1_report(struct ofp_ifnet *ifp, /*const*/ struct ofp_ip *ip,
    /*const*/ struct igmp *igmp)
{
	struct ofp_in_multi *inm;

	IGMPSTAT_INC(igps_rcv_reports);

	if (ifp->if_flags & OFP_IFF_LOOPBACK)
		return (0);

	if (!OFP_IN_MULTICAST(odp_be_to_cpu_32(igmp->igmp_group.s_addr)) ||
	    !ofp_in_hosteq(igmp->igmp_group, ip->ip_dst)) {
		IGMPSTAT_INC(igps_rcv_badreports);
		return (OFP_EINVAL);
	}

	/*
	 * RFC 3376, Section 4.2.13, 9.2, 9.3:
	 * Booting clients may use the source address 0.0.0.0. Some
	 * IGMP daemons may not know how to use IP_RECVIF to determine
	 * the interface upon which this message was received.
	 * Replace 0.0.0.0 with the subnet address if told to do so.
	 */
	if (V_igmp_recvifkludge && ofp_in_nullhost(ip->ip_src)) {
		ip->ip_src.s_addr = ifp->ip_addr_info[0].ip_addr;
	}

	CTR3(KTR_IGMPV3, "process v1 report %s on ifp %p(%s)",
	     ofp_print_ip_addr(igmp->igmp_group.s_addr), ifp, ifp->if_name);

	/*
	 * IGMPv1 report suppression.
	 * If we are a member of this group, and our membership should be
	 * reported, stop our group timer and transition to the 'lazy' state.
	 */
	IN_MULTI_LOCK();
	inm = inm_lookup(ifp, igmp->igmp_group);
	if (inm != NULL) {
		struct ofp_igmp_ifinfo *igi;

		igi = inm->inm_igi;
		if (igi == NULL) {
			KASSERT(igi != NULL,
			    ("%s: no igi for ifp %p", __func__, ifp));
			goto out_locked;
		}

		IGMPSTAT_INC(igps_rcv_ourreports);

		/*
		 * If we are in IGMPv3 host mode, do not allow the
		 * other host's IGMPv1 report to suppress our reports
		 * unless explicitly configured to do so.
		 */
		if (igi->igi_version == IGMP_VERSION_3) {
			if (V_igmp_legacysupp)
				igmp_v3_suppress_group_record(inm);
			goto out_locked;
		}

		inm->inm_timer = 0;

		switch (inm->inm_state) {
		case IGMP_NOT_MEMBER:
		case IGMP_SILENT_MEMBER:
			break;
		case IGMP_IDLE_MEMBER:
		case IGMP_LAZY_MEMBER:
		case IGMP_AWAKENING_MEMBER:
			CTR3(KTR_IGMPV3,
			    "report suppressed for %s on ifp %p(%s)",
			    ofp_print_ip_addr(igmp->igmp_group.s_addr), ifp, ifp->if_name);
		case IGMP_SLEEPING_MEMBER:
			inm->inm_state = IGMP_SLEEPING_MEMBER;
			break;
		case IGMP_REPORTING_MEMBER:
			CTR3(KTR_IGMPV3,
			    "report suppressed for %s on ifp %p(%s)",
			    ofp_print_ip_addr(igmp->igmp_group.s_addr), ifp, ifp->if_name);
			if (igi->igi_version == IGMP_VERSION_1)
				inm->inm_state = IGMP_LAZY_MEMBER;
			else if (igi->igi_version == IGMP_VERSION_2)
				inm->inm_state = IGMP_SLEEPING_MEMBER;
			break;
		case IGMP_G_QUERY_PENDING_MEMBER:
		case IGMP_SG_QUERY_PENDING_MEMBER:
		case IGMP_LEAVING_MEMBER:
			break;
		}
	}

out_locked:
	IN_MULTI_UNLOCK();

	return (0);
}

/*
 * Process a received IGMPv2 host membership report.
 *
 * NOTE: 0.0.0.0 workaround breaks const correctness.
 */
static int
igmp_input_v2_report(struct ofp_ifnet *ifp, /*const*/ struct ofp_ip *ip,
    /*const*/ struct igmp *igmp)
{
	struct ofp_in_multi *inm;

	/*
	 * Make sure we don't hear our own membership report.  Fast
	 * leave requires knowing that we are the only member of a
	 * group.
	 */
	if (-1 != ofp_ifnet_ip_find(ifp, ip->ip_src.s_addr))
		return (0);


	IGMPSTAT_INC(igps_rcv_reports);

	if (ifp->if_flags & OFP_IFF_LOOPBACK) {
		return (0);
	}

	if (!OFP_IN_MULTICAST(odp_be_to_cpu_32(igmp->igmp_group.s_addr)) ||
	    !ofp_in_hosteq(igmp->igmp_group, ip->ip_dst)) {
		IGMPSTAT_INC(igps_rcv_badreports);
		return (OFP_EINVAL);
	}

	/*
	 * RFC 3376, Section 4.2.13, 9.2, 9.3:
	 * Booting clients may use the source address 0.0.0.0. Some
	 * IGMP daemons may not know how to use IP_RECVIF to determine
	 * the interface upon which this message was received.
	 * Replace 0.0.0.0 with the subnet address if told to do so.
	 */
	if (V_igmp_recvifkludge && ofp_in_nullhost(ip->ip_src)) {
		ip->ip_src.s_addr = ifp->ip_addr_info[0].ip_addr;
	}

	CTR3(KTR_IGMPV3, "process v2 report %s on ifp %p(%s)",
	     ofp_print_ip_addr(igmp->igmp_group.s_addr), ifp, ifp->if_name);

	/*
	 * IGMPv2 report suppression.
	 * If we are a member of this group, and our membership should be
	 * reported, and our group timer is pending or about to be reset,
	 * stop our group timer by transitioning to the 'lazy' state.
	 */
	IN_MULTI_LOCK();
	inm = inm_lookup(ifp, igmp->igmp_group);
	if (inm != NULL) {
		struct ofp_igmp_ifinfo *igi;

		igi = inm->inm_igi;
		KASSERT(igi != NULL, ("%s: no igi for ifp %p", __func__, ifp));

		IGMPSTAT_INC(igps_rcv_ourreports);

		/*
		 * If we are in IGMPv3 host mode, do not allow the
		 * other host's IGMPv1 report to suppress our reports
		 * unless explicitly configured to do so.
		 */
		if (igi->igi_version == IGMP_VERSION_3) {
			if (V_igmp_legacysupp)
				igmp_v3_suppress_group_record(inm);
			goto out_locked;
		}

		inm->inm_timer = 0;

		switch (inm->inm_state) {
		case IGMP_NOT_MEMBER:
		case IGMP_SILENT_MEMBER:
		case IGMP_SLEEPING_MEMBER:
			break;
		case IGMP_REPORTING_MEMBER:
		case IGMP_IDLE_MEMBER:
		case IGMP_AWAKENING_MEMBER:
			CTR3(KTR_IGMPV3,
			    "report suppressed for %s on ifp %p(%s)",
			    ofp_print_ip_addr(igmp->igmp_group.s_addr), ifp, ifp->if_name);
		case IGMP_LAZY_MEMBER:
			inm->inm_state = IGMP_LAZY_MEMBER;
			break;
		case IGMP_G_QUERY_PENDING_MEMBER:
		case IGMP_SG_QUERY_PENDING_MEMBER:
		case IGMP_LEAVING_MEMBER:
			break;
		}
	}

out_locked:
	IN_MULTI_UNLOCK();

	return (0);
}

enum ofp_return_code
ofp_igmp_input(odp_packet_t *m, int off)
{
	int iphlen;
	struct ofp_ifnet *ifp;
	struct igmp *igmp;
	struct ofp_ip *ip;
	int igmplen;
	int minlen;
	int queryver;
	(void)minlen;

	CTR3(KTR_IGMPV3, "%s: called w/mbuf (%p,%d)", __func__, m, off);

	ifp = odp_packet_user_ptr(*m);

	IGMPSTAT_INC(igps_rcv_total);

	ip = (struct ofp_ip *)odp_packet_l3_ptr(*m, NULL);
	iphlen = off;
	igmplen = odp_be_to_cpu_16(ip->ip_len);
	igmp = (struct igmp *)(((uint8_t *)ip) + iphlen);

	/*
	 * Validate lengths.
	 */
	if (igmplen < IGMP_MINLEN) {
		IGMPSTAT_INC(igps_rcv_tooshort);
		odp_packet_free(*m);
		return OFP_PKT_DROP;
	}

	/*
	 * Validate checksum.
	 */
	if (ofp_cksum_buffer(igmp, igmplen)) {
		IGMPSTAT_INC(igps_rcv_badsum);
		return OFP_PKT_DROP;
	}

	/*
	 * IGMP control traffic is link-scope, and must have a TTL of 1.
	 * DVMRP traffic (e.g. mrinfo, mtrace) is an exception;
	 * probe packets may come from beyond the LAN.
	 */
	if (igmp->igmp_type != IGMP_DVMRP && ip->ip_ttl != 1) {
		IGMPSTAT_INC(igps_rcv_badttl);
		return OFP_PKT_DROP;
	}

	switch (igmp->igmp_type) {
	case IGMP_HOST_MEMBERSHIP_QUERY:
		if (igmplen == IGMP_MINLEN) {
			if (igmp->igmp_code == 0)
				queryver = IGMP_VERSION_1;
			else
				queryver = IGMP_VERSION_2;
		} else if (igmplen >= IGMP_V3_QUERY_MINLEN) {
			queryver = IGMP_VERSION_3;
		} else {
			IGMPSTAT_INC(igps_rcv_tooshort);
			return OFP_PKT_DROP;
		}

		switch (queryver) {
		case IGMP_VERSION_1:
			IGMPSTAT_INC(igps_rcv_v1v2_queries);
			if (!V_igmp_v1enable)
				break;
			if (igmp_input_v1_query(ifp, ip, igmp) != 0) {
				return OFP_PKT_DROP;
			}
			break;

		case IGMP_VERSION_2:
			IGMPSTAT_INC(igps_rcv_v1v2_queries);
			if (!V_igmp_v2enable)
				break;
			if (igmp_input_v2_query(ifp, ip, igmp) != 0) {
				return OFP_PKT_DROP;
			}
			break;

		case IGMP_VERSION_3: {
				struct igmpv3 *igmpv3;
#if 0 /* HJo */
				uint16_t igmpv3len;
#endif
				uint16_t srclen;
				int nsrc;

				IGMPSTAT_INC(igps_rcv_v3_queries);
				igmpv3 = (struct igmpv3 *)igmp;
				/*
				 * Validate length based on source count.
				 */
				nsrc = odp_be_to_cpu_16(igmpv3->igmp_numsrc);
				srclen = sizeof(struct ofp_in_addr) * nsrc;
				if (nsrc * sizeof(ofp_in_addr_t) > srclen) {
					IGMPSTAT_INC(igps_rcv_tooshort);
					return OFP_PKT_PROCESSED;
				}
#if 0 /* HJo */
				/*
				 * odp_packet_ensure_contiguous() may modify m, so pullup in
				 * this scope.
				 */
				igmpv3len = iphlen + IGMP_V3_QUERY_MINLEN +
				    srclen;
				if ((ofp_packet_flags(m) & M_EXT ||
				     odp_packet_len(m) < igmpv3len) &&
				    (m = odp_packet_ensure_contiguous(m, igmpv3len)) == NULL) {
					IGMPSTAT_INC(igps_rcv_tooshort);
					return OFP_PKT_PROCESSED;
				}
#endif
				igmpv3 = (struct igmpv3 *)((uint8_t *)odp_packet_data(*m)
				    + iphlen);
				if (igmp_input_v3_query(ifp, ip, igmpv3) != 0) {
					return OFP_PKT_DROP;
				}
			}
			break;
		}
		break;

	case IGMP_v1_HOST_MEMBERSHIP_REPORT:
		if (!V_igmp_v1enable)
			break;
		if (igmp_input_v1_report(ifp, ip, igmp) != 0) {
			return OFP_PKT_DROP;
		}
		break;

	case IGMP_v2_HOST_MEMBERSHIP_REPORT:
		if (!V_igmp_v2enable)
			break;
#if 0 /*HJo*/
		if (!ip_checkrouteralert(m))
			IGMPSTAT_INC(igps_rcv_nora);
#endif
		if (igmp_input_v2_report(ifp, ip, igmp) != 0) {
			return OFP_PKT_DROP;
		}
		break;

	case IGMP_v3_HOST_MEMBERSHIP_REPORT:
		/*
		 * Hosts do not need to process IGMPv3 membership reports,
		 * as report suppression is no longer required.
		 */
#if 0 /*HJo*/
		if (!ip_checkrouteralert(m))
			IGMPSTAT_INC(igps_rcv_nora);
#endif
		break;

	default:
		break;
	}

	/*
	 * Pass all valid IGMP packets up to any process(es) listening on a
	 * raw IGMP socket.
	 */
	return OFP_PKT_CONTINUE;
}


/*
 * Fast timeout handler.
 */
static void
ofp_igmp_fasttimo(void *arg)
{
	struct ofp_ifqueue		 scq;	/* State-change packets */
	struct ofp_ifqueue		 qrq;	/* Query response packets */
	struct ofp_ifnet		*ifp;
	struct ofp_igmp_ifinfo	*igi;
	struct ofp_ifmultiaddr	*ifma;
	struct ofp_in_multi		*inm;
	int			 loop, uri_fasthz;
	(void)arg;

	loop = 0;
	uri_fasthz = 0;

	ofp_igmp_fasttimo_timer = ofp_timer_start(200000UL, ofp_igmp_fasttimo,
					NULL, 0);

	/*
	 * Quick check to see if any work needs to be done, in order to
	 * minimize the overhead of fasttimo processing.
	 * SMPng: XXX Unlocked reads.
	 */
	if (!V_current_state_timers_running &&
	    !V_interface_timers_running &&
	    !V_state_change_timers_running)
		return;

	IN_MULTI_LOCK();
	IGMP_LOCK();

	/*
	 * IGMPv3 General Query response timer processing.
	 */
	if (V_interface_timers_running) {
		CTR1(KTR_IGMPV3, "%s: interface timers running", __func__);

		V_interface_timers_running = 0;
		OFP_LIST_FOREACH(igi, &V_igi_head, igi_link) {
			if (igi->igi_v3_timer == 0) {
				/* Do nothing. */
			} else if (--igi->igi_v3_timer == 0) {
				igmp_v3_dispatch_general_query(igi);
			} else {
				V_interface_timers_running = 1;
			}
		}
	}

	if (!V_current_state_timers_running &&
	    !V_state_change_timers_running)
		goto out_locked;

	V_current_state_timers_running = 0;
	V_state_change_timers_running = 0;

	CTR1(KTR_IGMPV3, "%s: state change timers running", __func__);

	/*
	 * IGMPv1/v2/v3 host report and state-change timer processing.
	 * Note: Processing a v3 group timer may remove a node.
	 */
	OFP_LIST_FOREACH(igi, &V_igi_head, igi_link) {
		ifp = igi->igi_ifp;

		if (igi->igi_version == IGMP_VERSION_3) {
			loop = (igi->igi_flags & IGIF_LOOPBACK) ? 1 : 0;
			uri_fasthz = IGMP_RANDOM_DELAY(igi->igi_uri *
			    PR_FASTHZ);

			memset(&qrq, 0, sizeof(struct ofp_ifqueue));
			IFQ_SET_MAXLEN(&qrq, IGMP_MAX_G_GS_PACKETS);

			memset(&scq, 0, sizeof(struct ofp_ifqueue));
			IFQ_SET_MAXLEN(&scq, IGMP_MAX_STATE_CHANGE_PACKETS);
		}

		IF_ADDR_RLOCK(ifp);
		OFP_TAILQ_FOREACH(ifma, &ifp->if_multiaddrs, ifma_link) {
			if (ifma->ifma_addr->sa_family != OFP_AF_INET ||
			    ifma->ifma_protospec == NULL)
				continue;
			inm = (struct ofp_in_multi *)ifma->ifma_protospec;
			switch (igi->igi_version) {
			case IGMP_VERSION_1:
			case IGMP_VERSION_2:
				igmp_v1v2_process_group_timer(inm,
				    igi->igi_version);
				break;
			case IGMP_VERSION_3:
				igmp_v3_process_group_timers(igi, &qrq,
				    &scq, inm, uri_fasthz);
				break;
			}
		}
		IF_ADDR_RUNLOCK(ifp);

		if (igi->igi_version == IGMP_VERSION_3) {
			struct ofp_in_multi		*tinm;

			igmp_dispatch_queue(&qrq, 0, loop);
			igmp_dispatch_queue(&scq, 0, loop);

			/*
			 * Free the in_multi reference(s) for this
			 * IGMP lifecycle.
			 */
			OFP_SLIST_FOREACH_SAFE(inm, &igi->igi_relinmhead,
			    inm_nrele, tinm) {
				OFP_SLIST_REMOVE_HEAD(&igi->igi_relinmhead,
				    inm_nrele);
				ofp_inm_release_locked(inm);
			}
		}
	}

out_locked:
	IGMP_UNLOCK();
	IN_MULTI_UNLOCK();
}

/*
 * Update host report group timer for IGMPv1/v2.
 * Will update the global pending timer flags.
 */
static void
igmp_v1v2_process_group_timer(struct ofp_in_multi *inm, const int version)
{
	int report_timer_expired;

	IN_MULTI_LOCK_ASSERT();
	IGMP_LOCK_ASSERT();

	if (inm->inm_timer == 0) {
		report_timer_expired = 0;
	} else if (--inm->inm_timer == 0) {
		report_timer_expired = 1;
	} else {
		V_current_state_timers_running = 1;
		return;
	}

	switch (inm->inm_state) {
	case IGMP_NOT_MEMBER:
	case IGMP_SILENT_MEMBER:
	case IGMP_IDLE_MEMBER:
	case IGMP_LAZY_MEMBER:
	case IGMP_SLEEPING_MEMBER:
	case IGMP_AWAKENING_MEMBER:
		break;
	case IGMP_REPORTING_MEMBER:
		if (report_timer_expired) {
			inm->inm_state = IGMP_IDLE_MEMBER;
			(void)igmp_v1v2_queue_report(inm,
			    (version == IGMP_VERSION_2) ?
			     IGMP_v2_HOST_MEMBERSHIP_REPORT :
			     IGMP_v1_HOST_MEMBERSHIP_REPORT);
		}
		break;
	case IGMP_G_QUERY_PENDING_MEMBER:
	case IGMP_SG_QUERY_PENDING_MEMBER:
	case IGMP_LEAVING_MEMBER:
		break;
	}
}

/*
 * Update a group's timers for IGMPv3.
 * Will update the global pending timer flags.
 * Note: Unlocked read from igi.
 */
static void
igmp_v3_process_group_timers(struct ofp_igmp_ifinfo *igi,
    struct ofp_ifqueue *qrq, struct ofp_ifqueue *scq,
    struct ofp_in_multi *inm, const int uri_fasthz)
{
	int query_response_timer_expired;
	int state_change_retransmit_timer_expired;

	IN_MULTI_LOCK_ASSERT();
	IGMP_LOCK_ASSERT();

	query_response_timer_expired = 0;
	state_change_retransmit_timer_expired = 0;

	/*
	 * During a transition from v1/v2 compatibility mode back to v3,
	 * a group record in REPORTING state may still have its group
	 * timer active. This is a no-op in this function; it is easier
	 * to deal with it here than to complicate the slow-timeout path.
	 */
	if (inm->inm_timer == 0) {
		query_response_timer_expired = 0;
	} else if (--inm->inm_timer == 0) {
		query_response_timer_expired = 1;
	} else {
		V_current_state_timers_running = 1;
	}

	if (inm->inm_sctimer == 0) {
		state_change_retransmit_timer_expired = 0;
	} else if (--inm->inm_sctimer == 0) {
		state_change_retransmit_timer_expired = 1;
	} else {
		V_state_change_timers_running = 1;
	}

	/* We are in fasttimo, so be quick about it. */
	if (!state_change_retransmit_timer_expired &&
	    !query_response_timer_expired)
		return;

	switch (inm->inm_state) {
	case IGMP_NOT_MEMBER:
	case IGMP_SILENT_MEMBER:
	case IGMP_SLEEPING_MEMBER:
	case IGMP_LAZY_MEMBER:
	case IGMP_AWAKENING_MEMBER:
	case IGMP_IDLE_MEMBER:
		break;
	case IGMP_G_QUERY_PENDING_MEMBER:
	case IGMP_SG_QUERY_PENDING_MEMBER:
		/*
		 * Respond to a previously pending Group-Specific
		 * or Group-and-Source-Specific query by enqueueing
		 * the appropriate Current-State report for
		 * immediate transmission.
		 */
		if (query_response_timer_expired) {
			int retval;

			retval = igmp_v3_enqueue_group_record(qrq, inm, 0, 1,
			    (inm->inm_state == IGMP_SG_QUERY_PENDING_MEMBER));
			(void)retval;
			CTR2(KTR_IGMPV3, "%s: enqueue record = %d",
			    __func__, retval);
			inm->inm_state = IGMP_REPORTING_MEMBER;
			/* XXX Clear recorded sources for next time. */
			ofp_inm_clear_recorded(inm);
		}
		/* FALLTHROUGH */
	case IGMP_REPORTING_MEMBER:
	case IGMP_LEAVING_MEMBER:
		if (state_change_retransmit_timer_expired) {
			/*
			 * State-change retransmission timer fired.
			 * If there are any further pending retransmissions,
			 * set the global pending state-change flag, and
			 * reset the timer.
			 */
			if (--inm->inm_scrv > 0) {
				inm->inm_sctimer = uri_fasthz;
				V_state_change_timers_running = 1;
			}
			/*
			 * Retransmit the previously computed state-change
			 * report. If there are no further pending
			 * retransmissions, the mbuf queue will be consumed.
			 * Update T0 state to T1 as we have now sent
			 * a state-change.
			 */
			(void)igmp_v3_merge_state_changes(inm, scq);

			ofp_inm_commit(inm);
			CTR3(KTR_IGMPV3, "%s: T1 -> T0 for %s/%s", __func__,
			    ofp_print_ip_addr(inm->inm_addr.s_addr), inm->inm_ifp->if_name);

			/*
			 * If we are leaving the group for good, make sure
			 * we release IGMP's reference to it.
			 * This release must be deferred using a SLIST,
			 * as we are called from a loop which traverses
			 * the in_ifmultiaddr TAILQ.
			 */
			if (inm->inm_state == IGMP_LEAVING_MEMBER &&
			    inm->inm_scrv == 0) {
				inm->inm_state = IGMP_NOT_MEMBER;
				OFP_SLIST_INSERT_HEAD(&igi->igi_relinmhead,
				    inm, inm_nrele);
			}
		}
		break;
	}
}


/*
 * Suppress a group's pending response to a group or source/group query.
 *
 * Do NOT suppress state changes. This leads to IGMPv3 inconsistency.
 * Do NOT update ST1/ST0 as this operation merely suppresses
 * the currently pending group record.
 * Do NOT suppress the response to a general query. It is possible but
 * it would require adding another state or flag.
 */
static void
igmp_v3_suppress_group_record(struct ofp_in_multi *inm)
{

	IN_MULTI_LOCK_ASSERT();

	KASSERT(inm->inm_igi->igi_version == IGMP_VERSION_3,
		("%s: not IGMPv3 mode on link", __func__));

	if (inm->inm_state != IGMP_G_QUERY_PENDING_MEMBER ||
	    inm->inm_state != IGMP_SG_QUERY_PENDING_MEMBER)
		return;

	if (inm->inm_state == IGMP_SG_QUERY_PENDING_MEMBER)
		ofp_inm_clear_recorded(inm);

	inm->inm_timer = 0;
	inm->inm_state = IGMP_REPORTING_MEMBER;
}

/*
 * Switch to a different IGMP version on the given interface,
 * as per Section 7.2.1.
 */
static void
igmp_set_version(struct ofp_igmp_ifinfo *igi, const int version)
{
	int old_version_timer;

	IGMP_LOCK_ASSERT();

	CTR4(KTR_IGMPV3, "%s: switching to v%d on ifp %p(%s)", __func__,
	    version, igi->igi_ifp, igi->igi_ifp->if_name);

	if (version == IGMP_VERSION_1 || version == IGMP_VERSION_2) {
		/*
		 * Compute the "Older Version Querier Present" timer as per
		 * Section 8.12.
		 */
		old_version_timer = igi->igi_rv * igi->igi_qi + igi->igi_qri;
		old_version_timer *= PR_SLOWHZ;

		if (version == IGMP_VERSION_1) {
			igi->igi_v1_timer = old_version_timer;
			igi->igi_v2_timer = 0;
		} else if (version == IGMP_VERSION_2) {
			igi->igi_v1_timer = 0;
			igi->igi_v2_timer = old_version_timer;
		}
	}

	if (igi->igi_v1_timer == 0 && igi->igi_v2_timer > 0) {
		if (igi->igi_version != IGMP_VERSION_2) {
			igi->igi_version = IGMP_VERSION_2;
			igmp_v3_cancel_link_timers(igi);
		}
	} else if (igi->igi_v1_timer > 0) {
		if (igi->igi_version != IGMP_VERSION_1) {
			igi->igi_version = IGMP_VERSION_1;
			igmp_v3_cancel_link_timers(igi);
		}
	}
}

/*
 * Cancel pending IGMPv3 timers for the given link and all groups
 * joined on it; state-change, general-query, and group-query timers.
 *
 * Only ever called on a transition from v3 to Compatibility mode. Kill
 * the timers stone dead (this may be expensive for large N groups), they
 * will be restarted if Compatibility Mode deems that they must be due to
 * query processing.
 */
static void
igmp_v3_cancel_link_timers(struct ofp_igmp_ifinfo *igi)
{
	struct ofp_ifmultiaddr	*ifma;
	struct ofp_ifnet		*ifp;
	struct ofp_in_multi		*inm, *tinm;

	CTR3(KTR_IGMPV3, "%s: cancel v3 timers on ifp %p(%s)", __func__,
	    igi->igi_ifp, igi->igi_ifp->if_name);

	IN_MULTI_LOCK_ASSERT();
	IGMP_LOCK_ASSERT();

	/*
	 * Stop the v3 General Query Response on this link stone dead.
	 * If fasttimo is woken up due to V_interface_timers_running,
	 * the flag will be cleared if there are no pending link timers.
	 */
	igi->igi_v3_timer = 0;

	/*
	 * Now clear the current-state and state-change report timers
	 * for all memberships scoped to this link.
	 */
	ifp = igi->igi_ifp;
	IF_ADDR_RLOCK(ifp);
	OFP_TAILQ_FOREACH(ifma, &ifp->if_multiaddrs, ifma_link) {
		if (ifma->ifma_addr->sa_family != OFP_AF_INET ||
		    ifma->ifma_protospec == NULL)
			continue;
		inm = (struct ofp_in_multi *)ifma->ifma_protospec;
		switch (inm->inm_state) {
		case IGMP_NOT_MEMBER:
		case IGMP_SILENT_MEMBER:
		case IGMP_IDLE_MEMBER:
		case IGMP_LAZY_MEMBER:
		case IGMP_SLEEPING_MEMBER:
		case IGMP_AWAKENING_MEMBER:
			/*
			 * These states are either not relevant in v3 mode,
			 * or are unreported. Do nothing.
			 */
			break;
		case IGMP_LEAVING_MEMBER:
			/*
			 * If we are leaving the group and switching to
			 * compatibility mode, we need to release the final
			 * reference held for issuing the INCLUDE {}, and
			 * transition to REPORTING to ensure the host leave
			 * message is sent upstream to the old querier --
			 * transition to NOT would lose the leave and race.
			 */
			OFP_SLIST_INSERT_HEAD(&igi->igi_relinmhead, inm, inm_nrele);
			/* FALLTHROUGH */
		case IGMP_G_QUERY_PENDING_MEMBER:
		case IGMP_SG_QUERY_PENDING_MEMBER:
			ofp_inm_clear_recorded(inm);
			/* FALLTHROUGH */
		case IGMP_REPORTING_MEMBER:
			inm->inm_state = IGMP_REPORTING_MEMBER;
			break;
		}
		/*
		 * Always clear state-change and group report timers.
		 * Free any pending IGMPv3 state-change records.
		 */
		inm->inm_sctimer = 0;
		inm->inm_timer = 0;
		_IF_DRAIN(&inm->inm_scq);
	}
	IF_ADDR_RUNLOCK(ifp);
	OFP_SLIST_FOREACH_SAFE(inm, &igi->igi_relinmhead, inm_nrele, tinm) {
		OFP_SLIST_REMOVE_HEAD(&igi->igi_relinmhead, inm_nrele);
		ofp_inm_release_locked(inm);
	}
}

/*
 * Update the Older Version Querier Present timers for a link.
 * See Section 7.2.1 of RFC 3376.
 */
static void
igmp_v1v2_process_querier_timers(struct ofp_igmp_ifinfo *igi)
{

	IGMP_LOCK_ASSERT();

	if (igi->igi_v1_timer == 0 && igi->igi_v2_timer == 0) {
		/*
		 * IGMPv1 and IGMPv2 Querier Present timers expired.
		 *
		 * Revert to IGMPv3.
		 */
		if (igi->igi_version != IGMP_VERSION_3) {
			CTR5(KTR_IGMPV3,
			    "%s: transition from v%d -> v%d on %p(%s)",
			    __func__, igi->igi_version, IGMP_VERSION_3,
			    igi->igi_ifp, igi->igi_ifp->if_name);
			igi->igi_version = IGMP_VERSION_3;
		}
	} else if (igi->igi_v1_timer == 0 && igi->igi_v2_timer > 0) {
		/*
		 * IGMPv1 Querier Present timer expired,
		 * IGMPv2 Querier Present timer running.
		 * If IGMPv2 was disabled since last timeout,
		 * revert to IGMPv3.
		 * If IGMPv2 is enabled, revert to IGMPv2.
		 */
		if (!V_igmp_v2enable) {
			CTR5(KTR_IGMPV3,
			    "%s: transition from v%d -> v%d on %p(%s)",
			    __func__, igi->igi_version, IGMP_VERSION_3,
			    igi->igi_ifp, igi->igi_ifp->if_name);
			igi->igi_v2_timer = 0;
			igi->igi_version = IGMP_VERSION_3;
		} else {
			--igi->igi_v2_timer;
			if (igi->igi_version != IGMP_VERSION_2) {
				CTR5(KTR_IGMPV3,
				    "%s: transition from v%d -> v%d on %p(%s)",
				    __func__, igi->igi_version, IGMP_VERSION_2,
				    igi->igi_ifp, igi->igi_ifp->if_name);
				igi->igi_version = IGMP_VERSION_2;
			}
		}
	} else if (igi->igi_v1_timer > 0) {
		/*
		 * IGMPv1 Querier Present timer running.
		 * Stop IGMPv2 timer if running.
		 *
		 * If IGMPv1 was disabled since last timeout,
		 * revert to IGMPv3.
		 * If IGMPv1 is enabled, reset IGMPv2 timer if running.
		 */
		if (!V_igmp_v1enable) {
			CTR5(KTR_IGMPV3,
			    "%s: transition from v%d -> v%d on %p(%s)",
			    __func__, igi->igi_version, IGMP_VERSION_3,
			    igi->igi_ifp, igi->igi_ifp->if_name);
			igi->igi_v1_timer = 0;
			igi->igi_version = IGMP_VERSION_3;
		} else {
			--igi->igi_v1_timer;
		}
		if (igi->igi_v2_timer > 0) {
			CTR3(KTR_IGMPV3,
			    "%s: cancel v2 timer on %p(%s)",
			    __func__, igi->igi_ifp, igi->igi_ifp->if_name);
			igi->igi_v2_timer = 0;
		}
	}
}

/*
 * Global slowtimo handler.
 * VIMAGE: Timeout handlers are expected to service all vimages.
 */
void
ofp_igmp_slowtimo(void)
{
	VNET_ITERATOR_DECL(vnet_iter);

	VNET_LIST_RLOCK_NOSLEEP();
	VNET_FOREACH(vnet_iter) {
		CURVNET_SET(vnet_iter);
		igmp_slowtimo_vnet();
		CURVNET_RESTORE();
	}
	VNET_LIST_RUNLOCK_NOSLEEP();
}

/*
 * Per-vnet slowtimo handler.
 */
static void
igmp_slowtimo_vnet(void)
{
	struct ofp_igmp_ifinfo *igi;

	IGMP_LOCK();

	OFP_LIST_FOREACH(igi, &V_igi_head, igi_link) {
		igmp_v1v2_process_querier_timers(igi);
	}

	IGMP_UNLOCK();
}

/*
 * Dispatch an IGMPv1/v2 host report or leave message.
 * These are always small enough to fit inside a single mbuf.
 */
static int
igmp_v1v2_queue_report(struct ofp_in_multi *inm, const int type)
{
	struct ofp_ifnet	*ifp;
	struct igmp		*igmp;
	struct ofp_ip		*ip;
	odp_packet_t		m;

	IN_MULTI_LOCK_ASSERT();
	IGMP_LOCK_ASSERT();

	ifp = inm->inm_ifp;

	m = ofp_packet_alloc(sizeof(struct ofp_ip) + sizeof(struct igmp));
	if (m == ODP_PACKET_INVALID)
		return (OFP_ENOMEM);

	ip = (struct ofp_ip *)odp_packet_data(m);
	igmp = (struct igmp *)(ip + 1);

	igmp->igmp_type = type;
	igmp->igmp_code = 0;
	igmp->igmp_group = inm->inm_addr;
	igmp->igmp_cksum = 0;
	igmp->igmp_cksum = ofp_cksum_buffer(igmp, sizeof(struct igmp));

	ip->ip_tos = 0;
	ip->ip_len = sizeof(struct ofp_ip) + sizeof(struct igmp);
	ip->ip_off = 0;
	ip->ip_p = OFP_IPPROTO_IGMP;
	ip->ip_src.s_addr = OFP_INADDR_ANY;

	if (type == IGMP_HOST_LEAVE_MESSAGE)
		ip->ip_dst.s_addr = odp_cpu_to_be_32(OFP_INADDR_ALLRTRS_GROUP);
	else
		ip->ip_dst = inm->inm_addr;

	igmp_save_context(m, ifp);

	ofp_packet_set_flag(m, M_IGMPV2);
	if (inm->inm_igi->igi_flags & IGIF_LOOPBACK)
		ofp_packet_set_flag(m, M_IGMP_LOOP);

	CTR2(KTR_IGMPV3, "%s: netisr_dispatch(NETISR_IGMP, %p)", __func__, m);
	netisr_dispatch(NETISR_IGMP, m);

	return (0);
}

/*
 * Process a state change from the upper layer for the given IPv4 group.
 *
 * Each socket holds a reference on the in_multi in its own ip_moptions.
 * The socket layer will have made the necessary updates to.the group
 * state, it is now up to IGMP to issue a state change report if there
 * has been any change between T0 (when the last state-change was issued)
 * and T1 (now).
 *
 * We use the IGMPv3 state machine at group level. The IGMP module
 * however makes the decision as to which IGMP protocol version to speak.
 * A state change *from* INCLUDE {} always means an initial join.
 * A state change *to* INCLUDE {} always means a final leave.
 *
 * FUTURE: If IGIF_V3LITE is enabled for this interface, then we can
 * save ourselves a bunch of work; any exclusive mode groups need not
 * compute source filter lists.
 *
 * VIMAGE: curvnet should have been set by caller, as this routine
 * is called from the socket option handlers.
 */
int
ofp_igmp_change_state(struct ofp_in_multi *inm)
{
	struct ofp_igmp_ifinfo *igi;
	struct ofp_ifnet *ifp;
	int error;

	IN_MULTI_LOCK_ASSERT();

	error = 0;

	/*
	 * Try to detect if the upper layer just asked us to change state
	 * for an interface which has now gone away.
	 */
	KASSERT(inm->inm_ifma != NULL, ("%s: no ifma", __func__));
	ifp = inm->inm_ifma->ifma_ifp;
	if (ifp != NULL) {
		/*
		 * Sanity check that netinet's notion of ifp is the
		 * same as net's.
		 */
		KASSERT(inm->inm_ifp == ifp, ("%s: bad ifp", __func__));
	}

	IGMP_LOCK();

	igi = ((struct ofp_in_ifinfo *)ifp->if_afdata[OFP_AF_INET])->ii_igmp;
	KASSERT(igi != NULL, ("%s: no igmp_ifinfo for ifp %p", __func__, ifp));

	/*
	 * If we detect a state transition to or from OFP_MCAST_UNDEFINED
	 * for this group, then we are starting or finishing an IGMP
	 * life cycle for this group.
	 */
	if (inm->inm_st[1].iss_fmode != inm->inm_st[0].iss_fmode) {
		CTR3(KTR_IGMPV3, "%s: inm transition %d -> %d", __func__,
		    inm->inm_st[0].iss_fmode, inm->inm_st[1].iss_fmode);
		if (inm->inm_st[0].iss_fmode == OFP_MCAST_UNDEFINED) {
			CTR1(KTR_IGMPV3, "%s: initial join", __func__);
			error = igmp_initial_join(inm, igi);
			goto out_locked;
		} else if (inm->inm_st[1].iss_fmode == OFP_MCAST_UNDEFINED) {
			CTR1(KTR_IGMPV3, "%s: final leave", __func__);
			igmp_final_leave(inm, igi);
			goto out_locked;
		}
	} else {
		CTR1(KTR_IGMPV3, "%s: filter set change", __func__);
	}

	error = igmp_handle_state_change(inm, igi);

out_locked:
	IGMP_UNLOCK();
	return (error);
}

/*
 * Perform the initial join for an IGMP group.
 *
 * When joining a group:
 *  If the group should have its IGMP traffic suppressed, do nothing.
 *  IGMPv1 starts sending IGMPv1 host membership reports.
 *  IGMPv2 starts sending IGMPv2 host membership reports.
 *  IGMPv3 will schedule an IGMPv3 state-change report containing the
 *  initial state of the membership.
 */
static int
igmp_initial_join(struct ofp_in_multi *inm, struct ofp_igmp_ifinfo *igi)
{
	struct ofp_ifnet		*ifp;
	struct ofp_ifqueue		*ifq;
	int			 error, retval, syncstates;

	CTR4(KTR_IGMPV3, "%s: initial join %s on ifp %p(%s)",
	    __func__, ofp_print_ip_addr(inm->inm_addr.s_addr), inm->inm_ifp,
	    inm->inm_ifp->if_name);

	error = 0;
	syncstates = 1;

	ifp = inm->inm_ifp;

	IN_MULTI_LOCK_ASSERT();
	IGMP_LOCK_ASSERT();

	KASSERT(igi && igi->igi_ifp == ifp, ("%s: inconsistent ifp", __func__));

	/*
	 * Groups joined on loopback or marked as 'not reported',
	 * e.g. 224.0.0.1, enter the IGMP_SILENT_MEMBER state and
	 * are never reported in any IGMP protocol exchanges.
	 * All other groups enter the appropriate IGMP state machine
	 * for the version in use on this link.
	 * A link marked as IGIF_SILENT causes IGMP to be completely
	 * disabled for the link.
	 */
	if ((ifp->if_flags & OFP_IFF_LOOPBACK) ||
	    (igi->igi_flags & IGIF_SILENT) ||
	    !igmp_isgroupreported(inm->inm_addr)) {
		CTR1(KTR_IGMPV3,
"%s: not kicking state machine for silent group", __func__);
		inm->inm_state = IGMP_SILENT_MEMBER;
		inm->inm_timer = 0;
	} else {
		/*
		 * Deal with overlapping in_multi lifecycle.
		 * If this group was LEAVING, then make sure
		 * we drop the reference we picked up to keep the
		 * group around for the final INCLUDE {} enqueue.
		 */
		if (igi->igi_version == IGMP_VERSION_3 &&
		    inm->inm_state == IGMP_LEAVING_MEMBER)
			ofp_inm_release_locked(inm);

		inm->inm_state = IGMP_REPORTING_MEMBER;

		switch (igi->igi_version) {
		case IGMP_VERSION_1:
		case IGMP_VERSION_2:
			inm->inm_state = IGMP_IDLE_MEMBER;
			error = igmp_v1v2_queue_report(inm,
			    (igi->igi_version == IGMP_VERSION_2) ?
			     IGMP_v2_HOST_MEMBERSHIP_REPORT :
			     IGMP_v1_HOST_MEMBERSHIP_REPORT);
			if (error == 0) {
				inm->inm_timer = IGMP_RANDOM_DELAY(
				    IGMP_V1V2_MAX_RI * PR_FASTHZ);
				V_current_state_timers_running = 1;
			}
			break;

		case IGMP_VERSION_3:
			/*
			 * Defer update of T0 to T1, until the first copy
			 * of the state change has been transmitted.
			 */
			syncstates = 0;

			/*
			 * Immediately enqueue a State-Change Report for
			 * this interface, freeing any previous reports.
			 * Don't kick the timers if there is nothing to do,
			 * or if an error occurred.
			 */
			ifq = &inm->inm_scq;
			_IF_DRAIN(ifq);
			retval = igmp_v3_enqueue_group_record(ifq, inm, 1,
			    0, 0);
			CTR2(KTR_IGMPV3, "%s: enqueue record = %d",
			    __func__, retval);
			if (retval <= 0) {
				error = retval * -1;
				break;
			}

			/*
			 * Schedule transmission of pending state-change
			 * report up to RV times for this link. The timer
			 * will fire at the next igmp_fasttimo (~200ms),
			 * giving us an opportunity to merge the reports.
			 */
			if (igi->igi_flags & IGIF_LOOPBACK) {
				inm->inm_scrv = 1;
			} else {
				KASSERT(igi->igi_rv > 1,
				   ("%s: invalid robustness %d", __func__,
				    igi->igi_rv));
				inm->inm_scrv = igi->igi_rv;
			}
			inm->inm_sctimer = 1;
			V_state_change_timers_running = 1;

			error = 0;
			break;
		}
	}

	/*
	 * Only update the T0 state if state change is atomic,
	 * i.e. we don't need to wait for a timer to fire before we
	 * can consider the state change to have been communicated.
	 */
	if (syncstates) {
		ofp_inm_commit(inm);
		CTR3(KTR_IGMPV3, "%s: T1 -> T0 for %s/%s", __func__,
		    ofp_print_ip_addr(inm->inm_addr.s_addr), inm->inm_ifp->if_name);
	}

	return (error);
}

/*
 * Issue an intermediate state change during the IGMP life-cycle.
 */
static int
igmp_handle_state_change(struct ofp_in_multi *inm, struct ofp_igmp_ifinfo *igi)
{
	struct ofp_ifnet		*ifp;
	int			 retval;

	CTR4(KTR_IGMPV3, "%s: state change for %s on ifp %p(%s)",
	    __func__, ofp_print_ip_addr(inm->inm_addr.s_addr), inm->inm_ifp,
	    inm->inm_ifp->if_name);

	ifp = inm->inm_ifp;

	IN_MULTI_LOCK_ASSERT();
	IGMP_LOCK_ASSERT();

	KASSERT(igi && igi->igi_ifp == ifp, ("%s: inconsistent ifp", __func__));

	if ((ifp->if_flags & OFP_IFF_LOOPBACK) ||
	    (igi->igi_flags & IGIF_SILENT) ||
	    !igmp_isgroupreported(inm->inm_addr) ||
	    (igi->igi_version != IGMP_VERSION_3)) {
		if (!igmp_isgroupreported(inm->inm_addr)) {
			CTR1(KTR_IGMPV3,
"%s: not kicking state machine for silent group", __func__);
		}
		CTR1(KTR_IGMPV3, "%s: nothing to do", __func__);
		ofp_inm_commit(inm);
		CTR3(KTR_IGMPV3, "%s: T1 -> T0 for %s/%s", __func__,
		    ofp_print_ip_addr(inm->inm_addr.s_addr), inm->inm_ifp->if_name);
		return (0);
	}

	_IF_DRAIN(&inm->inm_scq);

	retval = igmp_v3_enqueue_group_record(&inm->inm_scq, inm, 1, 0, 0);
	CTR2(KTR_IGMPV3, "%s: enqueue record = %d", __func__, retval);
	if (retval <= 0)
		return (-retval);

	/*
	 * If record(s) were enqueued, start the state-change
	 * report timer for this group.
	 */
	inm->inm_scrv = ((igi->igi_flags & IGIF_LOOPBACK) ? 1 : igi->igi_rv);
	inm->inm_sctimer = 1;
	V_state_change_timers_running = 1;

	return (0);
}

/*
 * Perform the final leave for an IGMP group.
 *
 * When leaving a group:
 *  IGMPv1 does nothing.
 *  IGMPv2 sends a host leave message, if and only if we are the reporter.
 *  IGMPv3 enqueues a state-change report containing a transition
 *  to INCLUDE {} for immediate transmission.
 */
static void
igmp_final_leave(struct ofp_in_multi *inm, struct ofp_igmp_ifinfo *igi)
{
	int syncstates;

	syncstates = 1;

	CTR4(KTR_IGMPV3, "%s: final leave %s on ifp %p(%s)",
	    __func__, ofp_print_ip_addr(inm->inm_addr.s_addr), inm->inm_ifp,
	    inm->inm_ifp->if_name);

	IN_MULTI_LOCK_ASSERT();
	IGMP_LOCK_ASSERT();

	switch (inm->inm_state) {
	case IGMP_NOT_MEMBER:
	case IGMP_SILENT_MEMBER:
	case IGMP_LEAVING_MEMBER:
		/* Already leaving or left; do nothing. */
		CTR1(KTR_IGMPV3,
"%s: not kicking state machine for silent group", __func__);
		break;
	case IGMP_REPORTING_MEMBER:
	case IGMP_IDLE_MEMBER:
	case IGMP_G_QUERY_PENDING_MEMBER:
	case IGMP_SG_QUERY_PENDING_MEMBER:
		if (igi->igi_version == IGMP_VERSION_2) {
#ifdef INVARIANTS
			if (inm->inm_state == IGMP_G_QUERY_PENDING_MEMBER ||
			    inm->inm_state == IGMP_SG_QUERY_PENDING_MEMBER)
			panic("%s: IGMPv3 state reached, not IGMPv3 mode",
			     __func__);
#endif
			igmp_v1v2_queue_report(inm, IGMP_HOST_LEAVE_MESSAGE);
			inm->inm_state = IGMP_NOT_MEMBER;
		} else if (igi->igi_version == IGMP_VERSION_3) {
			/*
			 * Stop group timer and all pending reports.
			 * Immediately enqueue a state-change report
			 * TO_IN {} to be sent on the next fast timeout,
			 * giving us an opportunity to merge reports.
			 */
			_IF_DRAIN(&inm->inm_scq);
			inm->inm_timer = 0;
			if (igi->igi_flags & IGIF_LOOPBACK) {
				inm->inm_scrv = 1;
			} else {
				inm->inm_scrv = igi->igi_rv;
			}
			CTR4(KTR_IGMPV3, "%s: Leaving %s/%s with %d "
			    "pending retransmissions.", __func__,
			    ofp_print_ip_addr(inm->inm_addr.s_addr),
			    inm->inm_ifp->if_name, inm->inm_scrv);
			if (inm->inm_scrv == 0) {
				inm->inm_state = IGMP_NOT_MEMBER;
				inm->inm_sctimer = 0;
			} else {
				int retval;

				inm_acquire_locked(inm);

				retval = igmp_v3_enqueue_group_record(
				    &inm->inm_scq, inm, 1, 0, 0);
				KASSERT(retval != 0,
				    ("%s: enqueue record = %d", __func__,
				     retval));

				inm->inm_state = IGMP_LEAVING_MEMBER;
				inm->inm_sctimer = 1;
				V_state_change_timers_running = 1;
				syncstates = 0;
			}
			break;
		}
		break;
	case IGMP_LAZY_MEMBER:
	case IGMP_SLEEPING_MEMBER:
	case IGMP_AWAKENING_MEMBER:
		/* Our reports are suppressed; do nothing. */
		break;
	}

	if (syncstates) {
		ofp_inm_commit(inm);
		CTR3(KTR_IGMPV3, "%s: T1 -> T0 for %s/%s", __func__,
		    ofp_print_ip_addr(inm->inm_addr.s_addr), inm->inm_ifp->if_name);
		inm->inm_st[1].iss_fmode = OFP_MCAST_UNDEFINED;
		CTR3(KTR_IGMPV3, "%s: T1 now OFP_MCAST_UNDEFINED for %s/%s",
		    __func__, ofp_print_ip_addr(inm->inm_addr.s_addr), inm->inm_ifp->if_name);
	}
}

static int myappend(odp_packet_t *pkt, int size, void *src)
{
	/*
	 * TODO: Use odp_packet_add_data() instead, and handle the
	 * segmented packets that may result.
	 */
	uint8_t *p = odp_packet_push_tail(*pkt, size);
	if (!p)
		return 0;
	memcpy(p, src, size);
	return 1;
}

#define m_append(_m, _size, _src) myappend(&_m, _size, _src)


/*
 * Enqueue an IGMPv3 group record to the given output queue.
 *
 * XXX This function could do with having the allocation code
 * split out, and the multiple-tree-walks coalesced into a single
 * routine as has been done in igmp_v3_enqueue_filter_change().
 *
 * If is_state_change is zero, a current-state record is appended.
 * If is_state_change is non-zero, a state-change report is appended.
 *
 * If is_group_query is non-zero, an mbuf packet chain is allocated.
 * If is_group_query is zero, and if there is a packet with free space
 * at the tail of the queue, it will be appended to providing there
 * is enough free space.
 * Otherwise a new mbuf packet chain is allocated.
 *
 * If is_source_query is non-zero, each source is checked to see if
 * it was recorded for a Group-Source query, and will be omitted if
 * it is not both in-mode and recorded.
 *
 * The function will attempt to allocate leading space in the packet
 * for the IP/IGMP header to be prepended without fragmenting the chain.
 *
 * If successful the size of all data appended to the queue is returned,
 * otherwise an error code less than zero is returned, or zero if
 * no record(s) were appended.
 */
static int
igmp_v3_enqueue_group_record(struct ofp_ifqueue *ifq, struct ofp_in_multi *inm,
    const int is_state_change, const int is_group_query,
    const int is_source_query)
{
	struct igmp_grouprec	 ig;
	struct igmp_grouprec	*pig;
	struct ofp_ifnet	*ifp;
	struct ofp_ip_msource	*ims, *nims;
	odp_packet_t		 m0, m;
	int			 error, is_filter_list_change;
	int			 minrec0len, m0srcs, msrcs, nbytes;
	int			 record_has_sources;
	int			 now;
	int			 type;
	ofp_in_addr_t		 naddr;
	uint8_t			 mode;

	IN_MULTI_LOCK_ASSERT();

	error = 0;
	(void)error;
	ifp = inm->inm_ifp;
	is_filter_list_change = 0;
	m = ODP_PACKET_INVALID;
	m0 = ODP_PACKET_INVALID;
	m0srcs = 0;
	msrcs = 0;
	nbytes = 0;
	nims = NULL;
	record_has_sources = 1;
	pig = NULL;
	type = IGMP_DO_NOTHING;
	mode = inm->inm_st[1].iss_fmode;

	/*
	 * If we did not transition out of ASM mode during t0->t1,
	 * and there are no source nodes to process, we can skip
	 * the generation of source records.
	 */
	if (inm->inm_st[0].iss_asm > 0 && inm->inm_st[1].iss_asm > 0 &&
	    inm->inm_nsrc == 0)
		record_has_sources = 0;

	if (is_state_change) {
		/*
		 * Queue a state change record.
		 * If the mode did not change, and there are non-ASM
		 * listeners or source filters present,
		 * we potentially need to issue two records for the group.
		 * If we are transitioning to OFP_MCAST_UNDEFINED, we need
		 * not send any sources.
		 * If there are ASM listeners, and there was no filter
		 * mode transition of any kind, do nothing.
		 */
		if (mode != inm->inm_st[0].iss_fmode) {
			if (mode == OFP_MCAST_EXCLUDE) {
				CTR1(KTR_IGMPV3, "%s: change to EXCLUDE",
				    __func__);
				type = IGMP_CHANGE_TO_EXCLUDE_MODE;
			} else {
				CTR1(KTR_IGMPV3, "%s: change to INCLUDE",
				    __func__);
				type = IGMP_CHANGE_TO_INCLUDE_MODE;
				if (mode == OFP_MCAST_UNDEFINED)
					record_has_sources = 0;
			}
		} else {
			if (record_has_sources) {
				is_filter_list_change = 1;
			} else {
				type = IGMP_DO_NOTHING;
			}
		}
	} else {
		/*
		 * Queue a current state record.
		 */
		if (mode == OFP_MCAST_EXCLUDE) {
			type = IGMP_MODE_IS_EXCLUDE;
		} else if (mode == OFP_MCAST_INCLUDE) {
			type = IGMP_MODE_IS_INCLUDE;
			KASSERT(inm->inm_st[1].iss_asm == 0,
			    ("%s: inm %p is INCLUDE but ASM count is %d",
			     __func__, inm, inm->inm_st[1].iss_asm));
		}
	}

	/*
	 * Generate the filter list changes using a separate function.
	 */
	if (is_filter_list_change)
		return (igmp_v3_enqueue_filter_change(ifq, inm));

	if (type == IGMP_DO_NOTHING) {
		CTR3(KTR_IGMPV3, "%s: nothing to do for %s/%s",
		    __func__, ofp_print_ip_addr(inm->inm_addr.s_addr),
		    inm->inm_ifp->if_name);
		return (0);
	}

	/*
	 * If any sources are present, we must be able to fit at least
	 * one in the trailing space of the tail packet's mbuf,
	 * ideally more.
	 */
	minrec0len = sizeof(struct igmp_grouprec);
	if (record_has_sources)
		minrec0len += sizeof(ofp_in_addr_t);

	CTR4(KTR_IGMPV3, "%s: queueing %s for %s/%s", __func__,
	    igmp_rec_type_to_str(type), ofp_print_ip_addr(inm->inm_addr.s_addr),
	    inm->inm_ifp->if_name);

	/*
	 * Check if we have a packet in the tail of the queue for this
	 * group into which the first group record for this group will fit.
	 * Otherwise allocate a new packet.
	 * Always allocate leading space for IP+RA_OPT+IGMP+REPORT.
	 * Note: Group records for G/GSR query responses MUST be sent
	 * in their own packet.
	 */
	m0 = HDR2PKT(ifq->ifq_tail);
	if (!is_group_query &&
	    m0 != ODP_PACKET_INVALID &&
	    (PKT2HDR(m0)->vt_nrecs + 1 <= IGMP_V3_REPORT_MAXRECS) &&
	    (odp_packet_len(m0) + minrec0len) <
	     (ifp->if_mtu - IGMP_LEADINGSPACE)) {
		m0srcs = (ifp->if_mtu - odp_packet_len(m0) -
			    sizeof(struct igmp_grouprec)) / sizeof(ofp_in_addr_t);
		m = m0;
		CTR1(KTR_IGMPV3, "%s: use existing packet", __func__);
	} else {
		if (_IF_QFULL(ifq)) {
			CTR1(KTR_IGMPV3, "%s: outbound queue full", __func__);
			return (-OFP_ENOMEM);
		}
		m0srcs = (ifp->if_mtu - IGMP_LEADINGSPACE -
		    sizeof(struct igmp_grouprec)) / sizeof(ofp_in_addr_t);
		m = ofp_packet_alloc(0);
		if (m == ODP_PACKET_INVALID)
			return (-OFP_ENOMEM);

		igmp_save_context(m, ifp);

		CTR1(KTR_IGMPV3, "%s: allocated first packet", __func__);
	}

	/*
	 * Append group record.
	 * If we have sources, we don't know how many yet.
	 */
	ig.ig_type = type;
	ig.ig_datalen = 0;
	ig.ig_numsrc = 0;
	ig.ig_group = inm->inm_addr;
	if (!m_append(m, sizeof(struct igmp_grouprec), (void *)&ig)) {
		if (m != m0)
			odp_packet_free(m);
		CTR1(KTR_IGMPV3, "%s: m_append() failed.", __func__);
		return (-OFP_ENOMEM);
	}
	nbytes += sizeof(struct igmp_grouprec);

	/*
	 * Append as many sources as will fit in the first packet.
	 * If we are appending to a new packet, the chain allocation
	 * may potentially use clusters; use m_getptr() in this case.
	 * If we are appending to an existing packet, we need to obtain
	 * a pointer to the group record after m_append(), in case a new
	 * mbuf was allocated.
	 * Only append sources which are in-mode at t1. If we are
	 * transitioning to OFP_MCAST_UNDEFINED state on the group, do not
	 * include source entries.
	 * Only report recorded sources in our filter set when responding
	 * to a group-source query.
	 */
	if (record_has_sources) {
		pig = (struct igmp_grouprec *)((uint8_t *)odp_packet_data(m) +
					       odp_packet_len(m) - nbytes);
		msrcs = 0;
		RB_FOREACH_SAFE(ims, ip_msource_tree, &inm->inm_srcs, nims) {
			CTR2(KTR_IGMPV3, "%s: visit node %s", __func__,
			    ofp_print_ip_addr(ims->ims_haddr));
			now = ims_get_mode(inm, ims, 1);
			CTR2(KTR_IGMPV3, "%s: node is %d", __func__, now);
			if ((now != mode) ||
			    (now == mode && mode == OFP_MCAST_UNDEFINED)) {
				CTR1(KTR_IGMPV3, "%s: skip node", __func__);
				continue;
			}
			if (is_source_query && ims->ims_stp == 0) {
				CTR1(KTR_IGMPV3, "%s: skip unrecorded node",
				    __func__);
				continue;
			}
			CTR1(KTR_IGMPV3, "%s: append node", __func__);
			naddr = odp_cpu_to_be_32(ims->ims_haddr);
			if (!m_append(m, sizeof(ofp_in_addr_t), (void *)&naddr)) {
				if (m != m0)
					odp_packet_free(m);
				CTR1(KTR_IGMPV3, "%s: m_append() failed.",
				    __func__);
				return (-OFP_ENOMEM);
			}
			nbytes += sizeof(ofp_in_addr_t);
			++msrcs;
			if (msrcs == m0srcs)
				break;
		}
		CTR2(KTR_IGMPV3, "%s: msrcs is %d this packet", __func__,
		    msrcs);
		pig->ig_numsrc = odp_cpu_to_be_16(msrcs);
		nbytes += (msrcs * sizeof(ofp_in_addr_t));
	}

	if (is_source_query && msrcs == 0) {
		CTR1(KTR_IGMPV3, "%s: no recorded sources to report", __func__);
		if (m != m0)
			odp_packet_free(m);
		return (0);
	}

	/*
	 * We are good to go with first packet.
	 */
	if (m != m0) {
		CTR1(KTR_IGMPV3, "%s: enqueueing first packet", __func__);
		PKT2HDR(m)->vt_nrecs = 1;
		_IF_ENQUEUE(ifq, m);
	} else
 		PKT2HDR(m)->vt_nrecs++;

	/*
	 * No further work needed if no source list in packet(s).
	 */
	if (!record_has_sources)
		return (nbytes);

	/*
	 * Whilst sources remain to be announced, we need to allocate
	 * a new packet and fill out as many sources as will fit.
	 * Always try for a cluster first.
	 */
	while (nims != NULL) {
		if (_IF_QFULL(ifq)) {
			CTR1(KTR_IGMPV3, "%s: outbound queue full", __func__);
			return (-OFP_ENOMEM);
		}
		m = ofp_packet_alloc(0);
		// HJo: to do: alloc IGMP_LEADINGSPACE
		if (m == ODP_PACKET_INVALID)
			return (-OFP_ENOMEM);
		igmp_save_context(m, ifp);
		pig = (struct igmp_grouprec *)((uint8_t *)odp_packet_data(m));
		CTR1(KTR_IGMPV3, "%s: allocated next packet", __func__);

		if (!m_append(m, sizeof(struct igmp_grouprec), (void *)&ig)) {
			if (m != m0)
				odp_packet_free(m);
			CTR1(KTR_IGMPV3, "%s: m_append() failed.", __func__);
			return (-OFP_ENOMEM);
		}

		PKT2HDR(m)->vt_nrecs = 1;
		nbytes += sizeof(struct igmp_grouprec);

		m0srcs = (ifp->if_mtu - IGMP_LEADINGSPACE -
		    sizeof(struct igmp_grouprec)) / sizeof(ofp_in_addr_t);

		msrcs = 0;
		RB_FOREACH_FROM(ims, ip_msource_tree, nims) {
			CTR2(KTR_IGMPV3, "%s: visit node %s", __func__,
			    ofp_print_ip_addr(ims->ims_haddr));
			now = ims_get_mode(inm, ims, 1);
			if ((now != mode) ||
			    (now == mode && mode == OFP_MCAST_UNDEFINED)) {
				CTR1(KTR_IGMPV3, "%s: skip node", __func__);
				continue;
			}
			if (is_source_query && ims->ims_stp == 0) {
				CTR1(KTR_IGMPV3, "%s: skip unrecorded node",
				    __func__);
				continue;
			}
			CTR1(KTR_IGMPV3, "%s: append node", __func__);
			naddr = odp_cpu_to_be_32(ims->ims_haddr);
			if (!m_append(m, sizeof(ofp_in_addr_t), (void *)&naddr)) {
				if (m != m0)
					odp_packet_free(m);
				CTR1(KTR_IGMPV3, "%s: m_append() failed.",
				    __func__);
				return (-OFP_ENOMEM);
			}
			++msrcs;
			if (msrcs == m0srcs)
				break;
		}
		pig->ig_numsrc = odp_cpu_to_be_16(msrcs);
		nbytes += (msrcs * sizeof(ofp_in_addr_t));

		CTR1(KTR_IGMPV3, "%s: enqueueing next packet", __func__);
		_IF_ENQUEUE(ifq, m);
	}

	return (nbytes);
}

/*
 * Type used to mark record pass completion.
 * We exploit the fact we can cast to this easily from the
 * current filter modes on each ip_msource node.
 */
typedef enum {
	REC_NONE = 0x00,	/* OFP_MCAST_UNDEFINED */
	REC_ALLOW = 0x01,	/* OFP_MCAST_INCLUDE */
	REC_BLOCK = 0x02,	/* OFP_MCAST_EXCLUDE */
	REC_FULL = REC_ALLOW | REC_BLOCK
} rectype_t;

/*
 * Enqueue an IGMPv3 filter list change to the given output queue.
 *
 * Source list filter state is held in an RB-tree. When the filter list
 * for a group is changed without changing its mode, we need to compute
 * the deltas between T0 and T1 for each source in the filter set,
 * and enqueue the appropriate ALLOW_NEW/BLOCK_OLD records.
 *
 * As we may potentially queue two record types, and the entire R-B tree
 * needs to be walked at once, we break this out into its own function
 * so we can generate a tightly packed queue of packets.
 *
 * XXX This could be written to only use one tree walk, although that makes
 * serializing into the mbuf chains a bit harder. For now we do two walks
 * which makes things easier on us, and it may or may not be harder on
 * the L2 cache.
 *
 * If successful the size of all data appended to the queue is returned,
 * otherwise an error code less than zero is returned, or zero if
 * no record(s) were appended.
 */
static int
igmp_v3_enqueue_filter_change(struct ofp_ifqueue *ifq, struct ofp_in_multi *inm)
{
	static const int MINRECLEN =
	    sizeof(struct igmp_grouprec) + sizeof(ofp_in_addr_t);
	struct ofp_ifnet		*ifp;
	struct igmp_grouprec	 ig;
	struct igmp_grouprec	*pig;
	struct ofp_ip_msource	*ims, *nims;
	odp_packet_t		 m, m0;
	ofp_in_addr_t		 naddr;
	int			 m0srcs, nbytes, npbytes, rsrcs, schanged;
	int			 nallow, nblock;
	uint8_t			 mode, now, then;
	rectype_t		 crt, drt, nrt;

	IN_MULTI_LOCK_ASSERT();

	if (inm->inm_nsrc == 0 ||
	    (inm->inm_st[0].iss_asm > 0 && inm->inm_st[1].iss_asm > 0))
		return (0);

	ifp = inm->inm_ifp;			/* interface */
	mode = inm->inm_st[1].iss_fmode;	/* filter mode at t1 */
	crt = REC_NONE;	/* current group record type */
	drt = REC_NONE;	/* mask of completed group record types */
	nrt = REC_NONE;	/* record type for current node */
	m0srcs = 0;	/* # source which will fit in current mbuf chain */
	nbytes = 0;	/* # of bytes appended to group's state-change queue */
	npbytes = 0;	/* # of bytes appended this packet */
	rsrcs = 0;	/* # sources encoded in current record */
	schanged = 0;	/* # nodes encoded in overall filter change */
	nallow = 0;	/* # of source entries in ALLOW_NEW */
	nblock = 0;	/* # of source entries in BLOCK_OLD */
	nims = NULL;	/* next tree node pointer */

	/*
	 * For each possible filter record mode.
	 * The first kind of source we encounter tells us which
	 * is the first kind of record we start appending.
	 * If a node transitioned to UNDEFINED at t1, its mode is treated
	 * as the inverse of the group's filter mode.
	 */
	while (drt != REC_FULL) {
		do {
			m0 = HDR2PKT(ifq->ifq_tail);
			if (m0 != ODP_PACKET_INVALID &&
			    /* HJo (m0->m_pkthdr.PH_vt.vt_nrecs + 1 <=
			       IGMP_V3_REPORT_MAXRECS) &&*/
			    (odp_packet_len(m0) + MINRECLEN) <
			     (ifp->if_mtu - IGMP_LEADINGSPACE)) {
				m = m0;
				m0srcs = (ifp->if_mtu - odp_packet_len(m0) -
					    sizeof(struct igmp_grouprec)) /
				    sizeof(ofp_in_addr_t);
				CTR1(KTR_IGMPV3,
				    "%s: use previous packet", __func__);
			} else {
				m = ofp_packet_alloc(0);
				if (m == ODP_PACKET_INVALID) {
					CTR1(KTR_IGMPV3,
					    "%s: m_get*() failed", __func__);
					return (-OFP_ENOMEM);
				}
				igmp_save_context(m, ifp);
				m0srcs = (ifp->if_mtu - IGMP_LEADINGSPACE -
				    sizeof(struct igmp_grouprec)) /
				    sizeof(ofp_in_addr_t);
				npbytes = 0;
				CTR1(KTR_IGMPV3,
				    "%s: allocated new packet", __func__);
			}
			/*
			 * Append the IGMP group record header to the
			 * current packet's data area.
			 * Recalculate pointer to free space for next
			 * group record, in case m_append() allocated
			 * a new mbuf or cluster.
			 */
			memset(&ig, 0, sizeof(ig));
			ig.ig_group = inm->inm_addr;
			if (!m_append(m, sizeof(ig), (void *)&ig)) {
				if (m != m0)
					odp_packet_free(m);
				CTR1(KTR_IGMPV3,
				    "%s: m_append() failed", __func__);
				return (-OFP_ENOMEM);
			}
			npbytes += sizeof(struct igmp_grouprec);
			pig = (struct igmp_grouprec *)
				((uint8_t *)odp_packet_tail(m) -
				 sizeof(struct igmp_grouprec));
			/*
			 * Begin walking the tree for this record type
			 * pass, or continue from where we left off
			 * previously if we had to allocate a new packet.
			 * Only report deltas in-mode at t1.
			 * We need not report included sources as allowed
			 * if we are in inclusive mode on the group,
			 * however the converse is not true.
			 */
			rsrcs = 0;
			if (nims == NULL)
				nims = RB_MIN(ip_msource_tree, &inm->inm_srcs);
			RB_FOREACH_FROM(ims, ip_msource_tree, nims) {
				CTR2(KTR_IGMPV3, "%s: visit node %s",
				    __func__, ofp_print_ip_addr(ims->ims_haddr));
				now = ims_get_mode(inm, ims, 1);
				then = ims_get_mode(inm, ims, 0);
				CTR3(KTR_IGMPV3, "%s: mode: t0 %d, t1 %d",
				    __func__, then, now);
				if (now == then) {
					CTR1(KTR_IGMPV3,
					    "%s: skip unchanged", __func__);
					continue;
				}
				if (mode == OFP_MCAST_EXCLUDE &&
				    now == OFP_MCAST_INCLUDE) {
					CTR1(KTR_IGMPV3,
					    "%s: skip IN src on EX group",
					    __func__);
					continue;
				}
				nrt = (rectype_t)now;
				if (nrt == REC_NONE)
					nrt = (rectype_t)(~mode & REC_FULL);
				if (schanged++ == 0) {
					crt = nrt;
				} else if (crt != nrt)
					continue;
				naddr = odp_cpu_to_be_32(ims->ims_haddr);
				if (!m_append(m, sizeof(ofp_in_addr_t),
				    (void *)&naddr)) {
					if (m != m0)
						odp_packet_free(m);
					CTR1(KTR_IGMPV3,
					    "%s: m_append() failed", __func__);
					return (-OFP_ENOMEM);
				}
				nallow += !!(crt == REC_ALLOW);
				nblock += !!(crt == REC_BLOCK);
				if (++rsrcs == m0srcs)
					break;
			}
			/*
			 * If we did not append any tree nodes on this
			 * pass, back out of allocations.
			 */
			if (rsrcs == 0) {
				npbytes -= sizeof(struct igmp_grouprec);
				if (m != m0) {
					CTR1(KTR_IGMPV3,
					    "%s: m_free(m)", __func__);
					odp_packet_free(m);
				} else {
					CTR1(KTR_IGMPV3,
					    "%s: odp_packet_pull_head(m, -ig)", __func__);
					odp_packet_pull_head(m, ((int)sizeof(
					    struct igmp_grouprec)));
				}
				continue;
			}
			npbytes += (rsrcs * sizeof(ofp_in_addr_t));
			if (crt == REC_ALLOW)
				pig->ig_type = IGMP_ALLOW_NEW_SOURCES;
			else if (crt == REC_BLOCK)
				pig->ig_type = IGMP_BLOCK_OLD_SOURCES;
			pig->ig_numsrc = odp_cpu_to_be_16(rsrcs);
			/*
			 * Count the new group record, and enqueue this
			 * packet if it wasn't already queued.
			 */
			/* HJo m->m_pkthdr.PH_vt.vt_nrecs++;*/
			if (m != m0)
				_IF_ENQUEUE(ifq, m);
			nbytes += npbytes;
		} while (nims != NULL);
		drt |= crt;
		crt = (~crt & REC_FULL);
	}

	CTR3(KTR_IGMPV3, "%s: queued %d ALLOW_NEW, %d BLOCK_OLD", __func__,
	    nallow, nblock);

	return (nbytes);
}

static int
igmp_v3_merge_state_changes(struct ofp_in_multi *inm, struct ofp_ifqueue *ifscq)
{
	struct ofp_ifqueue	*gq;
	odp_packet_t m;		/* pending state-change */
	odp_packet_t m0;		/* copy of pending state-change */
	odp_packet_t mt;		/* last state-change in packet */
	int		 docopy, domerge;
	uint32_t		 recslen;

	docopy = 0;
	domerge = 0;
	recslen = 0;

	IN_MULTI_LOCK_ASSERT();
	IGMP_LOCK_ASSERT();

	/*
	 * If there are further pending retransmissions, make a writable
	 * copy of each queued state-change message before merging.
	 */
	if (inm->inm_scrv > 0)
		docopy = 1;

	gq = &inm->inm_scq;
#ifdef KTR
	if (gq->ifq_head == NULL) {
		CTR2(KTR_IGMPV3, "%s: WARNING: queue for inm %p is empty",
		    __func__, inm);
	}
#endif

	m = HDR2PKT(gq->ifq_head);
	while (m != ODP_PACKET_INVALID) {
		/*
		 * Only merge the report into the current packet if
		 * there is sufficient space to do so; an IGMPv3 report
		 * packet may only contain 65,535 group records.
		 * Always use a simple mbuf chain concatentation to do this,
		 * as large state changes for single groups may have
		 * allocated clusters.
		 */
		domerge = 0;
		mt = HDR2PKT(ifscq->ifq_tail);
		if (mt != ODP_PACKET_INVALID) {
			recslen = odp_packet_len(m);

			if ((PKT2HDR(mt)->vt_nrecs +
			     PKT2HDR(m)->vt_nrecs <=
			     IGMP_V3_REPORT_MAXRECS) &&
			    (odp_packet_len(mt) + recslen <=
			    (inm->inm_ifp->if_mtu - IGMP_LEADINGSPACE)))
				domerge = 1;
		}

		if (!domerge && _IF_QFULL(gq)) {
			CTR2(KTR_IGMPV3,
			    "%s: outbound queue full, skipping whole packet %p",
			    __func__, m);
			mt = HDR2PKT(PKT2HDR(m)->next);
			if (!docopy)
				odp_packet_free(m);
			m = mt;
			continue;
		}

		if (!docopy) {
			CTR2(KTR_IGMPV3, "%s: dequeueing %p", __func__, m);
			_IF_DEQUEUE(gq, m0);
			m = HDR2PKT(PKT2HDR(m0)->next);
		} else {
			CTR2(KTR_IGMPV3, "%s: copying %p", __func__, m);
			m0 = odp_packet_copy(m, ofp_packet_pool);
			if (m0 == ODP_PACKET_INVALID)
				return (OFP_ENOMEM);
			*PKT2HDR(m0) = *PKT2HDR(m);
			PKT2HDR(m0)->next = NULL;
			m = HDR2PKT(PKT2HDR(m)->next);
		}

		if (!domerge) {
			CTR3(KTR_IGMPV3, "%s: queueing %p to ifscq %p)",
			    __func__, m0, ifscq);
			_IF_ENQUEUE(ifscq, m0);
		} else {
			CTR3(KTR_IGMPV3, "%s: merging %p with ifscq tail %p)",
			    __func__, m0, mt);

			PKT2HDR(mt)->vt_nrecs +=
				PKT2HDR(m0)->vt_nrecs;

			m_append(mt, odp_packet_len(m0),
				 odp_packet_data(m0));
			odp_packet_free(m0);
		}
	}

	return (0);
}

/*
 * Respond to a pending IGMPv3 General Query.
 */
static void
igmp_v3_dispatch_general_query(struct ofp_igmp_ifinfo *igi)
{
	struct ofp_ifmultiaddr	*ifma;
	struct ofp_ifnet		*ifp;
	struct ofp_in_multi		*inm;
	int			 retval, loop;

	IN_MULTI_LOCK_ASSERT();
	IGMP_LOCK_ASSERT();

	KASSERT(igi->igi_version == IGMP_VERSION_3,
	    ("%s: called when version %d", __func__, igi->igi_version));

	ifp = igi->igi_ifp;

	IF_ADDR_RLOCK(ifp);
	OFP_TAILQ_FOREACH(ifma, &ifp->if_multiaddrs, ifma_link) {
		if (ifma->ifma_addr->sa_family != OFP_AF_INET ||
		    ifma->ifma_protospec == NULL)
			continue;

		inm = (struct ofp_in_multi *)ifma->ifma_protospec;
		KASSERT(ifp == inm->inm_ifp,
		    ("%s: inconsistent ifp", __func__));

		switch (inm->inm_state) {
		case IGMP_NOT_MEMBER:
		case IGMP_SILENT_MEMBER:
			break;
		case IGMP_REPORTING_MEMBER:
		case IGMP_IDLE_MEMBER:
		case IGMP_LAZY_MEMBER:
		case IGMP_SLEEPING_MEMBER:
		case IGMP_AWAKENING_MEMBER:
			inm->inm_state = IGMP_REPORTING_MEMBER;
			retval = igmp_v3_enqueue_group_record(&igi->igi_gq,
			    inm, 0, 0, 0);
			CTR2(KTR_IGMPV3, "%s: enqueue record = %d",
			    __func__, retval);
			(void)retval;
			break;
		case IGMP_G_QUERY_PENDING_MEMBER:
		case IGMP_SG_QUERY_PENDING_MEMBER:
		case IGMP_LEAVING_MEMBER:
			break;
		}
	}
	IF_ADDR_RUNLOCK(ifp);

	loop = (igi->igi_flags & IGIF_LOOPBACK) ? 1 : 0;
	igmp_dispatch_queue(&igi->igi_gq, IGMP_MAX_RESPONSE_BURST, loop);

	/*
	 * Slew transmission of bursts over 500ms intervals.
	 */
	if (igi->igi_gq.ifq_head != NULL) {
		igi->igi_v3_timer = 1 + IGMP_RANDOM_DELAY(
		    IGMP_RESPONSE_BURST_INTERVAL);
		V_interface_timers_running = 1;
	}
}

/*
 * Transmit the next pending IGMP message in the output queue.
 *
 * We get called from netisr_processqueue(). A mutex private to igmpoq
 * will be acquired and released around this routine.
 *
 * VIMAGE: Needs to store/restore vnet pointer on a per-mbuf-chain basis.
 * MRT: Nothing needs to be done, as IGMP traffic is always local to
 * a link and uses a link-scope multicast address.
 */
static void
igmp_intr(odp_packet_t m)
{
	struct ofp_ip_moptions	imo;
	struct ofp_ifnet	*ifp;
	odp_packet_t		ipopts, m0;
	int			error;
	uint32_t		ifindex;

	CTR2(KTR_IGMPV3, "%s: transmit %p", __func__, m);

	ifindex = igmp_restore_context(m);

	/*
	 * Check if the ifnet still exists. This limits the scope of
	 * any race in the absence of a global ifp lock for low cost
	 * (an array lookup).
	 */
	ifp = ifnet_byindex(ifindex);
	if (ifp == NULL) {
		CTR3(KTR_IGMPV3, "%s: dropped %p as ifindex %u went away.",
		    __func__, m, ifindex);
		odp_packet_free(m);
		IPSTAT_INC(ips_noroute);
		return;
	}

	ipopts = V_igmp_sendra ? ofp_m_raopt : ODP_PACKET_INVALID;

	imo.imo_multicast_ttl  = 1;
	imo.imo_multicast_vif  = -1;
	imo.imo_multicast_loop = (V_ip_mrouter != NULL);

	/*
	 * If the user requested that IGMP traffic be explicitly
	 * redirected to the loopback interface (e.g. they are running a
	 * MANET interface and the routing protocol needs to see the
	 * updates), handle this now.
	 */
#if 0 // HJO
	if (ofp_packet_flags(m) & M_IGMP_LOOP)
		imo.imo_multicast_ifp = V_loif;
	else
#endif
		imo.imo_multicast_ifp = ifp;

	if (ofp_packet_flags(m) & M_IGMPV2) {
		m0 = m;
	} else {
		m0 = igmp_v3_encap_report(ifp, m);
		if (m0 == ODP_PACKET_INVALID) {
			CTR2(KTR_IGMPV3, "%s: dropped %p", __func__, m);
			odp_packet_free(m);
			IPSTAT_INC(ips_odropped);
			return;
		}
	}

	igmp_scrub_context(m0);
	ofp_packet_reset_flag(m, M_PROTOFLAGS);
	// HJo odp_packet_interface(m0) = V_loif;
	error = ofp_ip_output_opt(m0, ipopts, NULL, 0, &imo, NULL);
	if (error !=  OFP_PKT_PROCESSED) {
		CTR3(KTR_IGMPV3, "%s: ip_output(%p) = %d", __func__, m0, error);
		return;
	}

	IGMPSTAT_INC(igps_snd_reports);
}

/*
 * Encapsulate an IGMPv3 report.
 *
 * The internal mbuf flag M_IGMPV3_HDR is used to indicate that the mbuf
 * chain has already had its IP/IGMPv3 header prepended. In this case
 * the function will not attempt to prepend; the lengths and checksums
 * will however be re-computed.
 *
 * Returns a pointer to the new mbuf chain head, or NULL if the
 * allocation failed.
 */
static odp_packet_t
igmp_v3_encap_report(struct ofp_ifnet *ifp, odp_packet_t m)
{
	struct igmp_report	*igmp;
	struct ofp_ip		*ip;
	int			 hdrlen, igmpreclen;
	(void)ifp;

	igmpreclen = odp_packet_len(m);
	hdrlen = sizeof(struct ofp_ip) + sizeof(struct igmp_report);

	if (ofp_packet_flags(m) & M_IGMPV3_HDR) {
		igmpreclen -= hdrlen;
	} else {
		odp_packet_push_head(m, hdrlen);
		/* HJo
		m = odp_packet_add_data(m, 0, hdrlen);
		if (m == ODP_PACKET_INVALID)
			return (NULL);
		*/
		ofp_packet_set_flag(m, M_IGMPV3_HDR);
	}

	CTR2(KTR_IGMPV3, "%s: igmpreclen is %d", __func__, igmpreclen);

	ip = (struct ofp_ip *)odp_packet_data(m);
	igmp = (struct igmp_report *)(ip + 1);

	igmp->ir_type = IGMP_v3_HOST_MEMBERSHIP_REPORT;
	igmp->ir_rsv1 = 0;
	igmp->ir_rsv2 = 0;
	igmp->ir_numgrps = odp_cpu_to_be_16(PKT2HDR(m)->vt_nrecs);
	igmp->ir_cksum = 0;
	igmp->ir_cksum = ofp_cksum_buffer(igmp,
			sizeof(struct igmp_report) + igmpreclen);
	PKT2HDR(m)->vt_nrecs = 0;

	ip->ip_tos = IPTOS_PREC_INTERNETCONTROL;
	ip->ip_len = hdrlen + igmpreclen;
	ip->ip_off = OFP_IP_DF;
	ip->ip_p = OFP_IPPROTO_IGMP;
	ip->ip_sum = 0;

	ip->ip_src.s_addr = OFP_INADDR_ANY;

#if 0 // HJo FIX
	if (ofp_packet_flags(m) & M_IGMP_LOOP) {
		struct in_ifaddr *ia;

		IFP_TO_IA(ifp, ia);
		if (ia != NULL) {
			ip->ip_src = ia->ia_addr.sin_addr;
			ifa_free(&ia->ia_ifa);
		}
	}
#endif
	ip->ip_dst.s_addr = odp_cpu_to_be_32(OFP_INADDR_ALLRPTS_GROUP);

	return (m);
}

#ifdef IGMP_DEBUG
static const char *
igmp_rec_type_to_str(const int type)
{

	switch (type) {
		case IGMP_CHANGE_TO_EXCLUDE_MODE:
			return "TO_EX";
			break;
		case IGMP_CHANGE_TO_INCLUDE_MODE:
			return "TO_IN";
			break;
		case IGMP_MODE_IS_EXCLUDE:
			return "MODE_EX";
			break;
		case IGMP_MODE_IS_INCLUDE:
			return "MODE_IN";
			break;
		case IGMP_ALLOW_NEW_SOURCES:
			return "ALLOW_NEW";
			break;
		case IGMP_BLOCK_OLD_SOURCES:
			return "BLOCK_OLD";
			break;
		default:
			break;
	}
	return "unknown";
}
#endif

void
ofp_igmp_init(void)
{
	CTR1(KTR_IGMPV3, "%s: initializing", __func__);

	IGMP_LOCK_INIT();

	ofp_m_raopt = igmp_ra_alloc();

	ofp_igmp_fasttimo_timer = ofp_timer_start(200000UL, ofp_igmp_fasttimo,
					NULL, 0);

	// HJo netisr_register(&igmp_nh);
}
//HJo SYSINIT(ofp_igmp_init, SI_SUB_PSEUDO, SI_ORDER_MIDDLE, igmp_init, NULL);


void
ofp_igmp_uninit(void *unused)
{
	(void)unused;

	CTR1(KTR_IGMPV3, "%s: tearing down", __func__);

	/* HJo netisr_unregister(&igmp_nh);*/

	if (ofp_igmp_fasttimo_timer != ODP_TIMER_INVALID) {
		ofp_timer_cancel(ofp_igmp_fasttimo_timer);
		ofp_igmp_fasttimo_timer = ODP_TIMER_INVALID;
	}

	if (ofp_m_raopt != ODP_PACKET_INVALID) {
		odp_packet_free(ofp_m_raopt);
		ofp_m_raopt = ODP_PACKET_INVALID;
	}

	IGMP_LOCK_DESTROY();
}
//HJo SYSUNINIT(igmp_uninit, SI_SUB_PSEUDO, SI_ORDER_MIDDLE, igmp_uninit, NULL);

#if 0 //HJo

static void
vnet_igmp_init(const void *unused)
{
	(void)unused;

	CTR1(KTR_IGMPV3, "%s: initializing", __func__);

	OFP_LIST_INIT(&V_igi_head);
}
//HJo VNET_SYSINIT(vnet_igmp_init, SI_SUB_PSEUDO, SI_ORDER_ANY, vnet_igmp_init, NULL);

static void
vnet_igmp_uninit(const void *unused)
{
	(void)unused;

	CTR1(KTR_IGMPV3, "%s: tearing down", __func__);

	KASSERT(OFP_LIST_EMPTY(&V_igi_head),
	    ("%s: igi list not empty; ifnets not detached?", __func__));
}
//HJo VNET_SYSUNINIT(vnet_igmp_uninit, SI_SUB_PSEUDO, SI_ORDER_ANY, vnet_igmp_uninit, NULL);

static int
igmp_modevent(module_t mod, int type, void *unused)
{
	(void)unused;

    switch (type) {
    case MOD_LOAD:
    case MOD_UNLOAD:
	break;
    default:
	return (EOPNOTSUPP);
    }
    return (0);
}

static moduledata_t igmp_mod = {
    "igmp",
    igmp_modevent,
    0
};
DECLARE_MODULE(igmp, igmp_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
#endif
