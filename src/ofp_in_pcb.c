/*-
 * Copyright (c) 1982, 1986, 1991, 1993, 1995
 *	The Regents of the University of California.
 * Copyright (c) 2007-2009 Robert N. M. Watson
 * Copyright (c) 2010-2011 Juniper Networks, Inc.
 * Copyright (c) 2014, Nokia
 * Copyright (c) 2014, Enea Software AB
 * All rights reserved.
 *
 * Portions of this software were developed by Robert N. M. Watson under
 * contract to Juniper Networks, Inc.
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
 */

#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

#include "ofpi_errno.h"
#include "ofpi_init.h"
#include "ofpi_in.h"
#include "ofpi_in_pcb.h"
#include "ofpi_protosw.h"
#include "ofpi_socketvar.h"
#include "ofpi_tcp_var.h"
#include "ofpi_tcp_shm.h"
#include "ofpi_systm.h"
#include "ofpi_route.h"
#include "ofpi_ip6_var.h"
#ifdef INET6
#include "ofpi_in6_pcb.h"
#endif /*INET6*/

#include "ofpi_pkt_processing.h"

#include "ofpi_log.h"
#include "ofpi_util.h"

#define	HASH_NOWAIT	0x00000001
#define	HASH_WAITOK	0x00000002
extern void *ofp_hashinit(int count, void *type, uint64_t *hashmask);
extern void  ofp_hashdestroy(void *vhashtbl, void *type, uint64_t hashmask);

extern struct inpcbinfo ofp_udbinfo;

static void in_pcbremlists(struct inpcb *inp);
static struct inpcb *
in_pcblookup_hash_locked(struct inpcbinfo *pcbinfo, struct ofp_in_addr faddr,
			 uint32_t fport_arg, struct ofp_in_addr laddr,
			 uint32_t lport_arg, int lookupflags,
			 struct ofp_ifnet *ifp);

static __inline void
refcount_init(odp_atomic_u32_t *count, uint32_t value)
{
	odp_atomic_store_u32(count, value);
}

static __inline void
refcount_acquire(odp_atomic_u32_t *count)
{
	odp_atomic_inc_u32(count);
}

static __inline int
refcount_release(odp_atomic_u32_t *count)
{
	uint32_t old;

	old = odp_atomic_fetch_sub_u32(count, 1);
	KASSERT(old > 0, ("negative refcount %p", count));
	return (old == 1);
}

#ifdef OFP_RSS
void ofp_tcp_rss_in_pcbinfo_init( int hash_nelements, int porthash_nelements,
    uma_init inpcbzone_init, uma_fini inpcbzone_fini, uint32_t inpcbzone_flags)
{
	int32_t cpu_id;

	/* make compiler happy */
	(void)inpcbzone_init;
	(void)inpcbzone_fini;
	(void)inpcbzone_flags;

	for (cpu_id = 0; cpu_id < odp_cpu_count(); cpu_id++) {
		struct inpcbinfo *pcbinfo = &shm_tcp->ofp_tcbinfo[cpu_id];
		struct inpcbhead *listhead = &shm_tcp->ofp_tcb[cpu_id];
		char name_cpu[16];

		sprintf (name_cpu, "tcp_%u", cpu_id);
		INP_INFO_LOCK_INIT(pcbinfo, name_cpu);

		sprintf (name_cpu, "pcbinfohash_%u", cpu_id);
		INP_HASH_LOCK_INIT(pcbinfo, name_cpu);
		pcbinfo->ipi_listhead = listhead;
		OFP_LIST_INIT(pcbinfo->ipi_listhead);
		pcbinfo->ipi_count = 0;

		pcbinfo->ipi_hashbase = shm_tcp->ofp_hashtbl;
		ofp_tcp_hashinit(hash_nelements, &pcbinfo->ipi_hashmask,
				pcbinfo->ipi_hashbase);

		pcbinfo->ipi_porthashbase = shm_tcp->ofp_porthashtbl;
		ofp_tcp_hashinit(porthash_nelements,
			&pcbinfo->ipi_hashmask,
			pcbinfo->ipi_porthashbase);

		sprintf (name_cpu, "tcp_inpcb_%u", cpu_id);
		pcbinfo->ipi_zone = uma_zcreate(name_cpu,
			global_param->pcb_tcp_max, sizeof(struct inpcb),
			NULL, NULL, inpcbzone_init, inpcbzone_fini,
			UMA_ALIGN_PTR, inpcbzone_flags);

		if (pcbinfo->ipi_zone == -1)
			OFP_ERR("ipi_zone for pcbinfo NOT allocated!");

		uma_zone_set_max(pcbinfo->ipi_zone, maxsockets);
	}

	return;
}
#endif

/*
 * Initialize an inpcbinfo -- we should be able to reduce the number of
 * arguments in time.
 */
void
ofp_in_pcbinfo_init(struct inpcbinfo *pcbinfo, const char *name,
    struct inpcbhead *listhead, int hash_nelements, int porthash_nelements,
    const char *inpcbzone_name, uma_init inpcbzone_init, uma_fini inpcbzone_fini,
    uint32_t inpcbzone_flags)
{
	int pcb_size = OFP_NUM_SOCKETS_MAX;

	/* make compiler happy */
	(void)inpcbzone_init;
	(void)inpcbzone_fini;
	(void)inpcbzone_flags;

	INP_INFO_LOCK_INIT(pcbinfo, name);
	INP_HASH_LOCK_INIT(pcbinfo, "pcbinfohash");	/* XXXRW: argument? */
	pcbinfo->ipi_listhead = listhead;
	OFP_LIST_INIT(pcbinfo->ipi_listhead);
	pcbinfo->ipi_count = 0;

	if (strcmp(name, "tcp") == 0) {
		pcbinfo->ipi_hashbase = shm_tcp->ofp_hashtbl;
		ofp_tcp_hashinit(hash_nelements, &pcbinfo->ipi_hashmask,
			pcbinfo->ipi_hashbase);

		pcbinfo->ipi_porthashbase = shm_tcp->ofp_porthashtbl;
		ofp_tcp_hashinit(porthash_nelements, &pcbinfo->ipi_hashmask,
                        pcbinfo->ipi_porthashbase);
		pcb_size = global_param->pcb_tcp_max;
	} else {
		pcbinfo->ipi_hashbase = ofp_hashinit(hash_nelements, 0,
		    &pcbinfo->ipi_hashmask);
		pcbinfo->ipi_porthashbase = ofp_hashinit(porthash_nelements, 0,
		    &pcbinfo->ipi_porthashmask);
	}

	pcbinfo->ipi_zone = uma_zcreate(
		inpcbzone_name, pcb_size, sizeof(struct inpcb),
		NULL, NULL, inpcbzone_init, inpcbzone_fini, UMA_ALIGN_PTR,
		inpcbzone_flags);
	uma_zone_set_max(pcbinfo->ipi_zone, maxsockets);
}

/*
 * Destroy an inpcbinfo.
 */
void
ofp_in_pcbinfo_destroy(struct inpcbinfo *pcbinfo)
{
	KASSERT(pcbinfo->ipi_count == 0,
		("%s: ipi_count = %u", __func__, pcbinfo->ipi_count));

	ofp_hashdestroy(pcbinfo->ipi_hashbase, 0, pcbinfo->ipi_hashmask);
	ofp_hashdestroy(pcbinfo->ipi_porthashbase, 0,
		    pcbinfo->ipi_porthashmask);
	/* INP_HASH_LOCK_DESTROY(pcbinfo);
	   INP_INFO_LOCK_DESTROY(pcbinfo);*/
}

void
ofp_in_pcbinfo_hashstats(struct inpcbinfo *pcbinfo, unsigned int *min,
		     unsigned int *avg, unsigned int *max)
{
	unsigned int bucket;
	unsigned int bucket_count;
	unsigned int occupied;
	unsigned int lmin, lsum, lmax;
	struct inpcb *inp;
	struct inpcbhead *head;

	INP_HASH_WLOCK(pcbinfo);

	lmin = (unsigned int)-1;
	lsum = 0;
	lmax = 0;
	occupied = 0;

	for (bucket = 0; bucket <= pcbinfo->ipi_hashmask; bucket++) {

		bucket_count = 0;

		head = &pcbinfo->ipi_hashbase[bucket];
		OFP_LIST_FOREACH(inp, head, inp_hash) {
			bucket_count++;
		}

		if (bucket_count < lmin) lmin = bucket_count;

		if (bucket_count > 0) {
			lsum += bucket_count;
			occupied++;
		}
		if (bucket_count > lmax) lmax = bucket_count;
	}

	*min = lmin;
	*avg = lsum / occupied;
	*max = lmax;

	INP_HASH_WUNLOCK(pcbinfo);
}

/*
 * Allocate a PCB and associate it with the socket.
 * On success return with the PCB locked.
 */
int
ofp_in_pcballoc(struct socket *so, struct inpcbinfo *pcbinfo)
{
	struct inpcb *inp;
	int error;

	INP_INFO_WLOCK_ASSERT(pcbinfo);
	error = 0;
	inp = uma_zalloc(pcbinfo->ipi_zone, OFP_M_NOWAIT);
	if (inp == NULL)
		return (OFP_ENOBUFS);
	bzero(inp, inp_zero_size);
	inp->inp_pcbinfo = pcbinfo;
	inp->inp_socket = so;
	inp->inp_cred = so->so_cred; // HJo: ref inc removed
	inp->inp_inc.inc_fibnum = so->so_fibnum;
	inp->inp_options = ODP_PACKET_INVALID;
#ifdef INET6
	if (INP_SOCKAF(so) == OFP_AF_INET6) {
		inp->inp_vflag |= INP_IPV6PROTO;
		if (V_ip6_v6only)
			inp->inp_flags |= IN6P_IPV6_V6ONLY;
	}
#endif
	OFP_LIST_INSERT_HEAD(pcbinfo->ipi_listhead, inp, inp_list);
	pcbinfo->ipi_count++;
	so->so_pcb = (char *)inp;
#ifdef INET6
	if (V_ip6_auto_flowlabel)
		inp->inp_flags |= IN6P_AUTOFLOWLABEL;
#endif
	INP_WLOCK(inp);
	inp->inp_gencnt = ++pcbinfo->ipi_gencnt;
	refcount_init(&inp->inp_refcount, 1);	/* Reference from inpcbinfo */
	return (error);
}

int
ofp_in_pcbbind(struct inpcb *inp, struct ofp_sockaddr *nam, struct ofp_ucred *cred)
{
	int anonport, error;

	INP_WLOCK_ASSERT(inp);
	INP_HASH_WLOCK_ASSERT(inp->inp_pcbinfo);

	if (inp->inp_lport != 0 || inp->inp_laddr.s_addr != OFP_INADDR_ANY)
		return (OFP_EINVAL);
	anonport = inp->inp_lport == 0 &&
		(nam == NULL ||
		 ((struct ofp_sockaddr_in *)nam)->sin_port == 0);
	error = ofp_in_pcbbind_setup(inp, nam, &inp->inp_laddr.s_addr,
				 &inp->inp_lport, cred);
	if (error)
		return (error);
	if (ofp_in_pcbinshash(inp) != 0) {
		inp->inp_laddr.s_addr = OFP_INADDR_ANY;
		inp->inp_lport = 0;
		return (OFP_EAGAIN);
	}
	if (anonport)
		inp->inp_flags |= INP_ANONPORT;
	return (0);
}

/* HJo: FIX: sysctl variables */
int ofp_ipport_hifirstauto = 1200;	/* sysctl */
int ofp_ipport_hilastauto = 40000;
int ofp_ipport_lowfirstauto = 1023;	/* 1023 */
int ofp_ipport_lowlastauto = 40000;	/* 600 */
int ofp_ipport_firstauto = 1023;	/* sysctl */
int ofp_ipport_lastauto = 40000;

/*
 * Reserved ports accessible only to root. There are significant
 * security considerations that must be accounted for when changing these,
 * but the security benefits can be great. Please be careful.
 */
VNET_DEFINE(int, ofp_ipport_reservedhigh) = OFP_IPPORT_RESERVED - 1;	/* 1023 */
VNET_DEFINE(int, ofp_ipport_reservedlow);

/* Variables dealing with random ephemeral port allocation. */
VNET_DEFINE(int, ofp_ipport_randomized) = 1;	/* user controlled via sysctl */
VNET_DEFINE(int, ofp_ipport_randomcps) = 10;	/* user controlled via sysctl */
VNET_DEFINE(int, ofp_ipport_randomtime) = 45;	/* user controlled via sysctl */
VNET_DEFINE(int, ofp_ipport_stoprandom);		/* toggled by ipport_tick */
VNET_DEFINE(int, ofp_ipport_tcpallocs);

#define	V_ipport_tcplastcount		VNET(ipport_tcplastcount)

#define RANGECHK(var, min, max) \
	if ((var) < (min)) { (var) = (min); } \
	else if ((var) > (max)) { (var) = (max); }

static int
sysctl_net_ipport_check(OFP_SYSCTL_HANDLER_ARGS)
{
	int error;

	error = sysctl_handle_int(oidp, arg1, arg2, req);

	if (error == 0) {
		RANGECHK(V_ipport_lowfirstauto, 1, OFP_IPPORT_RESERVED - 1);
		RANGECHK(V_ipport_lowlastauto, 1, OFP_IPPORT_RESERVED - 1);
		RANGECHK(V_ipport_firstauto, OFP_IPPORT_RESERVED, OFP_IPPORT_MAX);
		RANGECHK(V_ipport_lastauto, OFP_IPPORT_RESERVED, OFP_IPPORT_MAX);
		RANGECHK(V_ipport_hifirstauto, OFP_IPPORT_RESERVED, OFP_IPPORT_MAX);
		RANGECHK(V_ipport_hilastauto, OFP_IPPORT_RESERVED, OFP_IPPORT_MAX);
	}
	return (error);
}

#define SYSCTL_VNET_PROC OFP_SYSCTL_PROC
#define SYSCTL_VNET_INT OFP_SYSCTL_INT

SYSCTL_DECL(_net_inet_ip);
OFP_SYSCTL_NODE(_net_inet_ip, OFP_IPPROTO_IP, portrange, OFP_CTLFLAG_RW, 0, "IP Ports");

SYSCTL_VNET_PROC(_net_inet_ip_portrange, OFP_OID_AUTO, lowfirst,
	OFP_CTLTYPE_INT|OFP_CTLFLAG_RW, &VNET_NAME(ofp_ipport_lowfirstauto), 0,
	&sysctl_net_ipport_check, "I", "");
SYSCTL_VNET_PROC(_net_inet_ip_portrange, OFP_OID_AUTO, lowlast,
	OFP_CTLTYPE_INT|OFP_CTLFLAG_RW, &VNET_NAME(ofp_ipport_lowlastauto), 0,
	&sysctl_net_ipport_check, "I", "");
SYSCTL_VNET_PROC(_net_inet_ip_portrange, OFP_OID_AUTO, first,
	OFP_CTLTYPE_INT|OFP_CTLFLAG_RW, &VNET_NAME(ofp_ipport_firstauto), 0,
	&sysctl_net_ipport_check, "I", "");
SYSCTL_VNET_PROC(_net_inet_ip_portrange, OFP_OID_AUTO, last,
	OFP_CTLTYPE_INT|OFP_CTLFLAG_RW, &VNET_NAME(ofp_ipport_lastauto), 0,
	&sysctl_net_ipport_check, "I", "");
SYSCTL_VNET_PROC(_net_inet_ip_portrange, OFP_OID_AUTO, hifirst,
	OFP_CTLTYPE_INT|OFP_CTLFLAG_RW, &VNET_NAME(ofp_ipport_hifirstauto), 0,
	&sysctl_net_ipport_check, "I", "");
SYSCTL_VNET_PROC(_net_inet_ip_portrange, OFP_OID_AUTO, hilast,
	OFP_CTLTYPE_INT|OFP_CTLFLAG_RW, &VNET_NAME(ofp_ipport_hilastauto), 0,
	&sysctl_net_ipport_check, "I", "");
SYSCTL_VNET_INT(_net_inet_ip_portrange, OFP_OID_AUTO, reservedhigh,
	OFP_CTLFLAG_RW|OFP_CTLFLAG_SECURE, &VNET_NAME(ofp_ipport_reservedhigh), 0, "");
SYSCTL_VNET_INT(_net_inet_ip_portrange, OFP_OID_AUTO, reservedlow,
	OFP_CTLFLAG_RW|OFP_CTLFLAG_SECURE, &VNET_NAME(ofp_ipport_reservedlow), 0, "");
SYSCTL_VNET_INT(_net_inet_ip_portrange, OFP_OID_AUTO, randomized, OFP_CTLFLAG_RW,
	&VNET_NAME(ofp_ipport_randomized), 0, "Enable random port allocation");
SYSCTL_VNET_INT(_net_inet_ip_portrange, OFP_OID_AUTO, randomcps, OFP_CTLFLAG_RW,
	&VNET_NAME(ofp_ipport_randomcps), 0, "Maximum number of random port "
	"allocations before switching to a sequental one");
SYSCTL_VNET_INT(_net_inet_ip_portrange, OFP_OID_AUTO, randomtime, OFP_CTLFLAG_RW,
	&VNET_NAME(ofp_ipport_randomtime), 0,
	"Minimum time to keep sequental port "
	"allocation before switching to a random one");


int
ofp_in_pcb_lport(struct inpcb *inp, struct ofp_in_addr *laddrp, uint16_t *lportp,
	     struct ofp_ucred *cred, int lookupflags)
{
	struct inpcbinfo *pcbinfo;
	struct inpcb *tmpinp;
	unsigned short *lastport;
	int count, dorandom;
	uint16_t aux, first, last, lport;
	struct ofp_in_addr laddr;

	/* make compiler happy */
	(void)cred;
	(void)lookupflags;

	pcbinfo = inp->inp_pcbinfo;

	/*
	 * Because no actual state changes occur here, a global write lock on
	 * the pcbinfo isn't required.
	 */
	INP_LOCK_ASSERT(inp);
	INP_HASH_LOCK_ASSERT(pcbinfo);

	if (inp->inp_flags & INP_HIGHPORT) {
		first = ofp_ipport_hifirstauto;	/* sysctl */
		last  = ofp_ipport_hilastauto;
		lastport = &pcbinfo->ipi_lasthi;
	} else if (inp->inp_flags & INP_LOWPORT) {
		first = ofp_ipport_lowfirstauto;	/* 1023 */
		last  = ofp_ipport_lowlastauto;	/* 600 */
		lastport = &pcbinfo->ipi_lastlow;
	} else {
		first = ofp_ipport_firstauto;	/* sysctl */
		last  = ofp_ipport_lastauto;
		lastport = &pcbinfo->ipi_lastport;
	}
	/*
	 * For UDP, use random port allocation as long as the user
	 * allows it.  For TCP (and as of yet unknown) connections,
	 * use random port allocation only if the user allows it AND
	 * ipport_tick() allows it.
	 */

	if (ofp_ipport_randomized && pcbinfo == &ofp_udbinfo)
		dorandom = 1;
	else
		dorandom = 0;

	/*
	 * It makes no sense to do random port allocation if
	 * we have the only port available.
	 */
	if (first == last)
		dorandom = 0;

	/*
	 * Instead of having two loops further down counting up or down
	 * make sure that first is always <= last and go with only one
	 * code path implementing all logic.
	 */
	if (first > last) {
		aux = first;
		first = last;
		last = aux;
	}

	/* Make the compiler happy. */
	laddr.s_addr = 0;
	if ((inp->inp_vflag & (INP_IPV4|INP_IPV6)) == INP_IPV4) {
		KASSERT(laddrp != NULL, ("%s: laddrp NULL for v4 inp %p",
					 __func__, inp));
		laddr = *laddrp;
		(void)laddr; /* Compiler happy */
	}

	tmpinp = NULL;	/* Make compiler happy. */
	lport = *lportp;

	if (dorandom)
		*lastport = first + (random() % (last - first));

	count = last - first;

	do {
		if (count-- < 0)	/* completely used? */
			return (OFP_EADDRNOTAVAIL);
		++*lastport;
		if (*lastport < first || *lastport > last)
			*lastport = first;
		lport = odp_cpu_to_be_16(*lastport);

#ifdef INET6
		if ((inp->inp_vflag & INP_IPV6) != 0)
			tmpinp = ofp_in6_pcblookup_local(pcbinfo,
			    &inp->in6p_laddr, lport, lookupflags, cred);
		else
#endif
			tmpinp = ofp_in_pcblookup_local(pcbinfo, laddr,
			    lport, lookupflags, cred);
	} while (tmpinp != NULL);

	if ((inp->inp_vflag & (INP_IPV4|INP_IPV6)) == INP_IPV4)
		laddrp->s_addr = laddr.s_addr;

	*lportp = lport;

	return (0);
}

/*
 * Set up a bind operation on a PCB, performing port allocation
 * as required, but do not actually modify the PCB. Callers can
 * either complete the bind by setting inp_laddr/inp_lport and
 * calling ofp_in_pcbinshash(), or they can just use the resulting
 * port and address to authorise the sending of a once-off packet.
 *
 * On error, the values of *laddrp and *lportp are not changed.
 */
int
ofp_in_pcbbind_setup(struct inpcb *inp, struct ofp_sockaddr *nam,
		 ofp_in_addr_t *laddrp,
		 uint16_t *lportp, struct ofp_ucred *cred)
{
	struct socket *so = inp->inp_socket;
	struct ofp_sockaddr_in *sin;
	struct inpcbinfo *pcbinfo = inp->inp_pcbinfo;
	struct ofp_in_addr laddr;
	uint16_t lport = 0;
	int lookupflags = 0, reuseport = (so->so_options & OFP_SO_REUSEPORT);
	int error;

	/*
	 * No state changes, so read locks are sufficient here.
	 */
	INP_LOCK_ASSERT(inp);
	INP_HASH_LOCK_ASSERT(pcbinfo);

	if (OFP_TAILQ_EMPTY(ofp_get_ifaddrhead())) /* XXX broken! */
		return (OFP_EADDRNOTAVAIL);

	laddr.s_addr = *laddrp;
	if (nam != NULL && laddr.s_addr != OFP_INADDR_ANY)
		return (OFP_EINVAL);
	if ((so->so_options & (OFP_SO_REUSEADDR|OFP_SO_REUSEPORT)) == 0)
		lookupflags = INPLOOKUP_WILDCARD;
	if (nam) {
		sin = (struct ofp_sockaddr_in *)nam;
		if (nam->sa_len != sizeof (*sin))
			return (OFP_EINVAL);
#ifdef notdef
		/*
		 * We should check the family, but old programs
		 * incorrectly fail to initialize it.
		 */
		if (sin->sin_family != OFP_AF_INET)
			return (OFP_EAFNOSUPPORT);
#endif
		if (sin->sin_port != *lportp) {
			/* Don't allow the port to change. */
			if (*lportp != 0)
				return (OFP_EINVAL);
			lport = sin->sin_port;
		}
		/* NB: lport is left as 0 if the port isn't being changed. */
		if (OFP_IN_MULTICAST(odp_be_to_cpu_32(sin->sin_addr.s_addr))) {
			/*
			 * Treat OFP_SO_REUSEADDR as OFP_SO_REUSEPORT for multicast;
			 * allow complete duplication of binding if
			 * OFP_SO_REUSEPORT is set, or if OFP_SO_REUSEADDR is set
			 * and a multicast address is bound on both
			 * new and duplicated sockets.
			 */
			if (so->so_options & OFP_SO_REUSEADDR)
				reuseport = OFP_SO_REUSEADDR|OFP_SO_REUSEPORT;
		} else if (sin->sin_addr.s_addr != OFP_INADDR_ANY) {
			sin->sin_port = 0;		/* yech... */
			bzero(&sin->sin_zero, sizeof(sin->sin_zero));

			/*
			 * Is the address a local IP address?
			 * If INP_BINDANY is set, then the socket may be bound
			 * to any endpoint address, local or not.
			 */
			if ((inp->inp_flags & INP_BINDANY) == 0 &&
				ofp_ifaddr_elem_get(
				inp->inp_inc.inc_fibnum,
				(uint8_t *)&(sin->sin_addr.s_addr)) == NULL)
				return (OFP_EADDRNOTAVAIL);
		}
		laddr = sin->sin_addr;
		if (lport) {
			struct inpcb *t;
			struct tcptw *tw;

			if (!OFP_IN_MULTICAST(odp_be_to_cpu_32(sin->sin_addr.s_addr))) {
				t = ofp_in_pcblookup_local(pcbinfo, sin->sin_addr,
						       lport, INPLOOKUP_WILDCARD, cred);
				/*
				 * XXX
				 * This entire block sorely needs a rewrite.
				 * (HJo: this comment is from FreeBSD)
				 */
				if (t &&
				    ((t->inp_flags & INP_TIMEWAIT) == 0) &&
				    (so->so_type != OFP_SOCK_STREAM ||
				     odp_be_to_cpu_32(t->inp_faddr.s_addr) == OFP_INADDR_ANY) &&
				    (odp_be_to_cpu_32(sin->sin_addr.s_addr) != OFP_INADDR_ANY ||
				     odp_be_to_cpu_32(t->inp_laddr.s_addr) != OFP_INADDR_ANY ||
				     (t->inp_flags2 & INP_REUSEPORT) == 0) &&
				    (inp->inp_cred->cr_uid !=
				     t->inp_cred->cr_uid))
					return (OFP_EADDRINUSE);
			}
			t = ofp_in_pcblookup_local(pcbinfo, sin->sin_addr,
					       lport, lookupflags, cred);
			if (t && (t->inp_flags & INP_TIMEWAIT)) {
				/*
				 * XXXRW: If an incpb has had its timewait
				 * state recycled, we treat the address as
				 * being in use (for now).  This is better
				 * than a panic, but not desirable.
				 */
				tw = intotw(t);
				if (tw == NULL ||
				    (reuseport & tw->tw_so_options) == 0)
					return (OFP_EADDRINUSE);
			} else if (t && (reuseport == 0 ||
			    (t->inp_flags2 & INP_REUSEPORT) == 0)) {
#ifdef INET6
				if (odp_be_to_cpu_32(sin->sin_addr.s_addr) !=
				    OFP_INADDR_ANY ||
				    odp_be_to_cpu_32(t->inp_laddr.s_addr) !=
				    OFP_INADDR_ANY ||
				    (inp->inp_vflag & INP_IPV6PROTO) == 0 ||
				    (t->inp_vflag & INP_IPV6PROTO) == 0)
#endif
				return (OFP_EADDRINUSE);
			}
		}
	}
	if (*lportp != 0)
		lport = *lportp;

	if (lport == 0)
	{
		error = ofp_in_pcb_lport(inp, &laddr, &lport, cred, lookupflags);
		if (error != 0)
			return (error);
	}
	*laddrp = laddr.s_addr;
	*lportp = lport;
	return (0);
}

/*
 * Connect from a socket to a specified address.
 * Both address and port must be specified in argument sin.
 * If don't have a local address for this socket yet,
 * then pick one.
 */
int
ofp_in_pcbconnect_mbuf(struct inpcb *inp, struct ofp_sockaddr *nam,
		   struct ofp_ucred *cred, odp_packet_t m)
{
	u_short lport, fport;
	ofp_in_addr_t laddr, faddr;
	int anonport, error;

	INP_WLOCK_ASSERT(inp);
	INP_HASH_WLOCK_ASSERT(inp->inp_pcbinfo);

	lport = inp->inp_lport;
	laddr = inp->inp_laddr.s_addr;
	anonport = (lport == 0);
	error = ofp_in_pcbconnect_setup(inp, nam, &laddr, &lport, &faddr, &fport,
					  NULL, cred);
	if (error)
		return (error);

	/* Do the initial binding of the local address if required. */
	if (inp->inp_laddr.s_addr == OFP_INADDR_ANY && inp->inp_lport == 0) {
		inp->inp_lport = lport;
		inp->inp_laddr.s_addr = laddr;
		if (ofp_in_pcbinshash(inp) != 0) {
			inp->inp_laddr.s_addr = OFP_INADDR_ANY;
			inp->inp_lport = 0;
			return (OFP_EAGAIN);
		}
	}

	/* Commit the remaining changes. */
	inp->inp_lport = lport;
	inp->inp_laddr.s_addr = laddr;
	inp->inp_faddr.s_addr = faddr;
	inp->inp_fport = fport;
	ofp_in_pcbrehash_mbuf(inp, m);

	if (anonport)
		inp->inp_flags |= INP_ANONPORT;
	return (0);
}

/*
 * Connect from a socket to a specified address.
 * Both address and port must be specified in argument sin.
 * If don't have a local address for this socket yet,
 * then pick one.
 */
int
ofp_in_pcbconnect(struct inpcb *inp, struct ofp_sockaddr *nam, struct ofp_ucred *cred)
{
	uint16_t lport, fport;
	ofp_in_addr_t laddr, faddr;
	int anonport, error;

	INP_WLOCK_ASSERT(inp);
	INP_HASH_WLOCK_ASSERT(inp->inp_pcbinfo);

	lport = inp->inp_lport;
	laddr = inp->inp_laddr.s_addr;
	anonport = (lport == 0);
	error = ofp_in_pcbconnect_setup(inp, nam, &laddr, &lport, &faddr, &fport,
				    NULL, cred);
	if (error)
		return (error);

	/* Do the initial binding of the local address if required. */
	if (inp->inp_laddr.s_addr == OFP_INADDR_ANY && inp->inp_lport == 0) {
		inp->inp_lport = lport;
		inp->inp_laddr.s_addr = laddr;
		if (ofp_in_pcbinshash(inp) != 0) {
			inp->inp_laddr.s_addr = OFP_INADDR_ANY;
			inp->inp_lport = 0;
			return (OFP_EAGAIN);
		}
	}

	/* Commit the remaining changes. */
	inp->inp_lport = lport;
	inp->inp_laddr.s_addr = laddr;
	inp->inp_faddr.s_addr = faddr;
	inp->inp_fport = fport;
	ofp_in_pcbrehash(inp);

	if (anonport)
		inp->inp_flags |= INP_ANONPORT;
	return (0);
}

/*
 * Do proper source address selection on an unbound socket in case
 * of connect.
 */
static int
in_pcbladdr(struct inpcb *inp, struct ofp_in_addr *faddr,
	    struct ofp_in_addr *laddr, struct ofp_ucred *cred)
{
	struct ofp_nh_entry *nh;
	struct ofp_ifnet *dev_out;
	uint32_t flags;
	(void)inp;
	(void)faddr;
	(void)cred;

	KASSERT(laddr != NULL, ("%s: laddr NULL", __func__));

	nh = ofp_get_next_hop(0, faddr->s_addr, &flags);
	if (!nh)
		return OFP_ENETUNREACH;

	dev_out = ofp_get_ifnet(nh->port, nh->vlan);

	if (dev_out) {
		laddr->s_addr = dev_out->ip_addr_info[0].ip_addr;
		return 0;
	}

	return OFP_ENETUNREACH;
}

/*
 * Set up for a connect from a socket to the specified address.
 * On entry, *laddrp and *lportp should contain the current local
 * address and port for the PCB; these are updated to the values
 * that should be placed in inp_laddr and inp_lport to complete
 * the connect.
 *
 * On success, *faddrp and *fportp will be set to the remote address
 * and port. These are not updated in the error case.
 *
 * If the operation fails because the connection already exists,
 * *oinpp will be set to the PCB of that connection so that the
 * caller can decide to override it. In all other cases, *oinpp
 * is set to NULL.
 */
int
ofp_in_pcbconnect_setup(struct inpcb *inp, struct ofp_sockaddr *nam,
    ofp_in_addr_t *laddrp, uint16_t *lportp, ofp_in_addr_t *faddrp, uint16_t *fportp,
    struct inpcb **oinpp, struct ofp_ucred *cred)
{
	struct ofp_sockaddr_in *sin = (struct ofp_sockaddr_in *)nam;
	struct inpcb *oinp;
	struct ofp_in_addr laddr, faddr;
	uint16_t lport, fport;
	int error;

	/*
	 * Because a global state change doesn't actually occur here, a read
	 * lock is sufficient.
	 */
	INP_LOCK_ASSERT(inp);
	INP_HASH_LOCK_ASSERT(inp->inp_pcbinfo);

	if (oinpp != NULL)
		*oinpp = NULL;
	if (nam->sa_len != sizeof (*sin))
		return (OFP_EINVAL);
	if (sin->sin_family != OFP_AF_INET)
		return (OFP_EAFNOSUPPORT);
	if (sin->sin_port == 0)
		return (OFP_EADDRNOTAVAIL);
	laddr.s_addr = *laddrp;
	lport = *lportp;
	faddr = sin->sin_addr;
	fport = sin->sin_port;

	if (!OFP_TAILQ_EMPTY(ofp_get_ifaddrhead())) {
		/*
		 * If the destination address is OFP_INADDR_ANY,
		 * use the primary local address.
		 * If the supplied address is OFP_INADDR_BROADCAST,
		 * and the primary interface supports broadcast,
		 * choose the broadcast address for that interface.
		 */
		if (faddr.s_addr == OFP_INADDR_ANY) {
			IN_IFADDR_RLOCK();
			faddr.s_addr = OFP_TAILQ_FIRST(ofp_get_ifaddrhead())->ip_addr_info[0].ip_addr;
			IN_IFADDR_RUNLOCK();
		} else if (faddr.s_addr == (uint64_t)OFP_INADDR_BROADCAST) {
			/* HJo: FIX
			IN_IFADDR_RLOCK();
			if (OFP_TAILQ_FIRST(ofp_get_ifaddrhead())->ia_ifp->if_flags &
			    IFF_BROADCAST)
				faddr = ((struct ofp_sockaddr_in *)(&OFP_TAILQ_FIRST
								(ofp_get_ifaddrhead())->
								ia_broadaddr))->sin_addr;
			IN_IFADDR_RUNLOCK();
			*/
		}
	}
	if (laddr.s_addr == OFP_INADDR_ANY) {
		error = in_pcbladdr(inp, &faddr, &laddr, cred);
		/*
		 * If the destination address is multicast and an outgoing
		 * interface has been set as a multicast option, prefer the
		 * address of that interface as our source address.
		 */
		/* HJo: Multicast is not supported. */
		if (OFP_IN_MULTICAST(odp_be_to_cpu_32(faddr.s_addr)) &&
		    inp->inp_moptions != NULL) {
			struct ofp_ip_moptions *imo;
			struct ofp_ifnet *ifp;

			imo = inp->inp_moptions;
			if (imo->imo_multicast_ifp != NULL) {
				ifp = imo->imo_multicast_ifp;
				laddr.s_addr = ifp->ip_addr_info[0].ip_addr;
				error = 0;
			}
		}
		if (error)
			return (error);
	}
	oinp = in_pcblookup_hash_locked(inp->inp_pcbinfo, faddr, fport,
	    laddr, lport, 0, NULL);

	if (oinp != NULL) {
		if (oinpp != NULL)
			*oinpp = oinp;
		return (OFP_EADDRINUSE);
	}
	if (lport == 0) {
		error = ofp_in_pcbbind_setup(inp, NULL, &laddr.s_addr, &lport,
		    cred);
		if (error)
			return (error);
	}
	*laddrp = laddr.s_addr;
	*lportp = lport;
	*faddrp = faddr.s_addr;
	*fportp = fport;

	return (0);
}

void
ofp_in_pcbdisconnect(struct inpcb *inp)
{

	INP_WLOCK_ASSERT(inp);
	INP_HASH_WLOCK_ASSERT(inp->inp_pcbinfo);

	inp->inp_faddr.s_addr = OFP_INADDR_ANY;
	inp->inp_fport = 0;
	ofp_in_pcbrehash(inp);
}

/*
 * ofp_in_pcbdetach() is responsibe for disassociating a socket from an inpcb.
 * For most protocols, this will be invoked immediately prior to calling
 * ofp_in_pcbfree().  However, with TCP the inpcb may significantly outlive the
 * socket, in which case ofp_in_pcbfree() is deferred.
 */
void
ofp_in_pcbdetach(struct inpcb *inp)
{
	KASSERT(inp->inp_socket != NULL, ("%s: inp_socket == NULL", __func__));

	inp->inp_socket->so_pcb = NULL;
	inp->inp_socket = NULL;
}

/*
 * ofp_in_pcbref() bumps the reference count on an inpcb in order to maintain
 * stability of an inpcb pointer despite the inpcb lock being released.  This
 * is used in TCP when the inpcbinfo lock needs to be acquired or upgraded,
 * but where the inpcb lock may already held, or when acquiring a reference
 * via a pcbgroup.
 *
 * ofp_in_pcbref() should be used only to provide brief memory stability, and
 * must always be followed by a call to INP_WLOCK() and in_pcbrele() to
 * garbage collect the inpcb if it has been ofp_in_pcbfree()'d from another
 * context.  Until in_pcbrele() has returned that the inpcb is still valid,
 * lock and rele are the *only* safe operations that may be performed on the
 * inpcb.
 *
 * While the inpcb will not be freed, releasing the inpcb lock means that the
 * connection's state may change, so the caller should be careful to
 * revalidate any cached state on reacquiring the lock.  Drop the reference
 * using in_pcbrele().
 */
void
ofp_in_pcbref(struct inpcb *inp)
{

	KASSERT(inp->inp_refcount.v > 0, ("%s: refcount 0", __func__));

	refcount_acquire(&inp->inp_refcount);
}

/*
 * Drop a refcount on an inpcb elevated using ofp_in_pcbref(); because a call to
 * ofp_in_pcbfree() may have been made between ofp_in_pcbref() and in_pcbrele(), we
 * return a flag indicating whether or not the inpcb remains valid.  If it is
 * valid, we return with the inpcb lock held.
 *
 * Notice that, unlike ofp_in_pcbref(), the inpcb lock must be held to drop a
 * reference on an inpcb.  Historically more work was done here (actually, in
 * in_pcbfree_internal()) but has been moved to ofp_in_pcbfree() to avoid the
 * need for the pcbinfo lock in in_pcbrele().  Deferring the free is entirely
 * about memory stability (and continued use of the write lock).
 */
int
ofp_in_pcbrele_rlocked(struct inpcb *inp)
{
	KASSERT(inp->inp_refcount.v > 0, ("%s: refcount 0", __func__));

	INP_RLOCK_ASSERT(inp);

	if (refcount_release(&inp->inp_refcount) == 0)
		return (0);

	KASSERT(inp->inp_socket == NULL, ("%s: inp_socket != NULL", __func__));

	INP_RUNLOCK(inp);
	uma_zfree(inp->inp_pcbinfo->ipi_zone, inp);
	return (1);
}

int
ofp_in_pcbrele_wlocked(struct inpcb *inp)
{
	KASSERT(inp->inp_refcount.v > 0, ("%s: refcount 0", __func__));

	INP_WLOCK_ASSERT(inp);

	if (refcount_release(&inp->inp_refcount) == 0)
		return (0);

	KASSERT(inp->inp_socket == NULL, ("%s: inp_socket != NULL", __func__));

	INP_WUNLOCK(inp);
	uma_zfree(inp->inp_pcbinfo->ipi_zone, inp);
	return (1);
}

/*
 * Unconditionally schedule an inpcb to be freed by decrementing its
 * reference count, which should occur only after the inpcb has been detached
 * from its socket.  If another thread holds a temporary reference (acquired
 * using ofp_in_pcbref()) then the free is deferred until that reference is
 * released using in_pcbrele(), but the inpcb is still unlocked.  Almost all
 * work, including removal from global lists, is done in this context, where
 * the pcbinfo lock is held.
 */
void
ofp_in_pcbfree(struct inpcb *inp)
{
	struct inpcbinfo *pcbinfo = inp->inp_pcbinfo;

	KASSERT(inp->inp_socket == NULL, ("%s: inp_socket != NULL", __func__));

	INP_INFO_WLOCK_ASSERT(pcbinfo);
	INP_WLOCK_ASSERT(inp);

	inp->inp_gencnt = ++pcbinfo->ipi_gencnt;
	in_pcbremlists(inp);
#ifdef INET6
#if 0
	if (inp->inp_vflag & INP_IPV6PROTO) {
		ip6_freepcbopts(inp->in6p_outputopts);
		if (inp->in6p_moptions != NULL)
			ip6_freemoptions(inp->in6p_moptions);*/
	}
#endif /*0*/
#endif
	/* HJo: FIX
	if (inp->inp_options)
		(void)m_free(inp->inp_options);
	*/
	/* HJo: Multicast not supported
	if (inp->inp_moptions != NULL)
		ofp_inp_freemoptions(inp->inp_moptions);
	*/

	inp->inp_vflag = 0;
	/* HJo: cred structure not used
	crfree(inp->inp_cred);
	*/

	if (!ofp_in_pcbrele_wlocked(inp))
		INP_WUNLOCK(inp);
}

/*
 * ofp_in_pcbdrop() removes an inpcb from hashed lists, releasing its address and
 * port reservation, and preventing it from being returned by inpcb lookups.
 *
 * It is used by TCP to mark an inpcb as unused and avoid future packet
 * delivery or event notification when a socket remains open but TCP has
 * closed.  This might occur as a result of a shutdown()-initiated TCP close
 * or a RST on the wire, and allows the port binding to be reused while still
 * maintaining the invariant that so_pcb always points to a valid inpcb until
 * ofp_in_pcbdetach().
 *
 * XXXRW: Possibly ofp_in_pcbdrop() should also prevent future notifications by
 * in_pcbnotifyall() and in_pcbpurgeif0()?
 */
void
ofp_in_pcbdrop(struct inpcb *inp)
{
	INP_WLOCK_ASSERT(inp);

	/*
	 * XXXRW: Possibly we should protect the setting of INP_DROPPED with
	 * the hash lock...?
	 */
	inp->inp_flags |= INP_DROPPED;
	if (inp->inp_flags & INP_INHASHLIST) {
		struct inpcbport *phd = inp->inp_phd;

		INP_HASH_WLOCK(inp->inp_pcbinfo);
		OFP_LIST_REMOVE(inp, inp_hash);
		OFP_LIST_REMOVE(inp, inp_portlist);
		if (OFP_LIST_FIRST(&phd->phd_pcblist) == NULL) {
			OFP_LIST_REMOVE(phd, phd_hash);
			free(phd);
		}
		INP_HASH_WUNLOCK(inp->inp_pcbinfo);
		inp->inp_flags &= ~INP_INHASHLIST;
	}
}

/*
 * Common routines to return the socket addresses associated with inpcbs.
 */
struct ofp_sockaddr *
ofp_in_sockaddr(ofp_in_port_t port, struct ofp_in_addr *addr_p)
{
	struct ofp_sockaddr_in *sin;

	sin = malloc(sizeof *sin);
	sin->sin_family = OFP_AF_INET;
	sin->sin_len = sizeof(*sin);
	sin->sin_addr = *addr_p;
	sin->sin_port = port;

	return (struct ofp_sockaddr *)sin;
}

int
ofp_in_getsockaddr(struct socket *so, struct ofp_sockaddr **nam)
{
	struct inpcb *inp;
	struct ofp_in_addr addr;
	ofp_in_port_t port;

	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("ofp_in_getsockaddr: inp == NULL"));

	INP_RLOCK(inp);
	port = inp->inp_lport;
	addr = inp->inp_laddr;
	INP_RUNLOCK(inp);

	*nam = ofp_in_sockaddr(port, &addr);
	return 0;
}

int
ofp_in_getpeeraddr(struct socket *so, struct ofp_sockaddr **nam)
{
	struct inpcb *inp;
	struct ofp_in_addr addr;
	ofp_in_port_t port;

	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("ofp_in_getpeeraddr: inp == NULL"));

	INP_RLOCK(inp);
	port = inp->inp_fport;
	addr = inp->inp_faddr;
	INP_RUNLOCK(inp);

	*nam = ofp_in_sockaddr(port, &addr);
	return 0;
}

void ofp_in_pcbnotifyall(struct inpcbinfo *pcbinfo,
	struct ofp_in_addr faddr, int error_val,
	struct inpcb *(*notify)(struct inpcb *inpcb_, int int_val)) {
	struct inpcb *inp, *inp_temp;

	INP_INFO_WLOCK(pcbinfo);
	OFP_LIST_FOREACH_SAFE(inp, pcbinfo->ipi_listhead, inp_list, inp_temp) {
		INP_WLOCK(inp);
#ifdef INET6
		if ((inp->inp_vflag & INP_IPV4) == 0) {
			INP_WUNLOCK(inp);
			continue;
		}
#endif
		if (inp->inp_faddr.s_addr != faddr.s_addr ||
		    inp->inp_socket == NULL) {
			INP_WUNLOCK(inp);
			continue;
		}
		if ((*notify)(inp, error_val))
			INP_WUNLOCK(inp);
	}
	INP_INFO_WUNLOCK(pcbinfo);
}

/*
 * Lookup a PCB based on the local address and port.  Caller must hold the
 * hash lock.  No inpcb locks or references are acquired.
 */
#define INP_LOOKUP_MAPPED_PCB_COST	3
struct inpcb *
ofp_in_pcblookup_local(struct inpcbinfo *pcbinfo, struct ofp_in_addr laddr,
		   uint16_t lport, int lookupflags, struct ofp_ucred *cred)
{
	struct inpcb *inp;

	(void)cred;
#ifdef INET6
	int matchwild = 3 + INP_LOOKUP_MAPPED_PCB_COST;
#else
	int matchwild = 3;
#endif
	int wildcard;

	KASSERT((lookupflags & ~(INPLOOKUP_WILDCARD)) == 0,
		("%s: invalid lookup flags %d", __func__, lookupflags));

	INP_HASH_LOCK_ASSERT(pcbinfo);

	if ((lookupflags & INPLOOKUP_WILDCARD) == 0) {
		struct inpcbhead *head;
		/*
		 * Look for an unconnected (wildcard foreign addr) PCB that
		 * matches the local address and port we're looking for.
		 */
		head = &pcbinfo->ipi_hashbase[INP_PCBHASH(OFP_INADDR_ANY, lport,
		    0, pcbinfo->ipi_hashmask)];
		OFP_LIST_FOREACH(inp, head, inp_hash) {
#ifdef INET6
			/* XXX inp locking */
			if ((inp->inp_vflag & INP_IPV4) == 0)
				continue;
#endif
			if (inp->inp_faddr.s_addr == OFP_INADDR_ANY &&
			    inp->inp_laddr.s_addr == laddr.s_addr &&
			    inp->inp_lport == lport) {
				/*
				 * Found
				 */
				return (inp);
			}
		}
		/*
		 * Not found.
		 */
		return (NULL);
	} else {
		struct inpcbporthead *porthash;
		struct inpcbport *phd;
		struct inpcb *match = NULL;
		/*
		 * Best fit PCB lookup.
		 *
		 * First see if this local port is in use by looking on the
		 * port hash list.
		 */
		porthash = &pcbinfo->ipi_porthashbase[INP_PCBPORTHASH(lport,
		    pcbinfo->ipi_porthashmask)];
		OFP_LIST_FOREACH(phd, porthash, phd_hash) {
			if (phd->phd_port == lport)
				break;
		}
		if (phd != NULL) {
			/*
			 * Port is in use by one or more PCBs. Look for best
			 * fit.
			 */
			OFP_LIST_FOREACH(inp, &phd->phd_pcblist, inp_portlist) {
				wildcard = 0;
#ifdef INET6
				/* XXX inp locking */
				if ((inp->inp_vflag & INP_IPV4) == 0)
					continue;
				/*
				 * We never select the PCB that has
				 * INP_IPV6 flag and is bound to :: if
				 * we have another PCB which is bound
				 * to 0.0.0.0.  If a PCB has the
				 * INP_IPV6 flag, then we set its cost
				 * higher than IPv4 only PCBs.
				 *
				 * Note that the case only happens
				 * when a socket is bound to ::, under
				 * the condition that the use of the
				 * mapped address is allowed.
				 */
				if ((inp->inp_vflag & INP_IPV6) != 0)
					wildcard += INP_LOOKUP_MAPPED_PCB_COST;
#endif
				if (inp->inp_faddr.s_addr != OFP_INADDR_ANY)
					wildcard++;
				if (inp->inp_laddr.s_addr != OFP_INADDR_ANY) {
					if (laddr.s_addr == OFP_INADDR_ANY)
						wildcard++;
					else if (inp->inp_laddr.s_addr != laddr.s_addr)
						continue;
				} else {
					if (laddr.s_addr != OFP_INADDR_ANY)
						wildcard++;
				}
				if (wildcard < matchwild) {
					match = inp;
					matchwild = wildcard;
					if (matchwild == 0)
						break;
				}
			}
		}
		return (match);
	}
}

/*
 * Insert PCB onto various hash lists.
 */
static int
in_pcbinshash_internal(struct inpcb *inp, int do_pcbgroup_update)
{
	struct inpcbhead *pcbhash;
	struct inpcbporthead *pcbporthash;
	struct inpcbinfo *pcbinfo = inp->inp_pcbinfo;
	struct inpcbport *phd;
	uint32_t hashkey_faddr;
	uint32_t hashkey;

	(void)do_pcbgroup_update;

	INP_WLOCK_ASSERT(inp);
	INP_HASH_WLOCK_ASSERT(pcbinfo);

	KASSERT((inp->inp_flags & INP_INHASHLIST) == 0,
	    ("ofp_in_pcbinshash: INP_INHASHLIST"));

#ifdef INET6
	if (inp->inp_vflag & INP_IPV6)
		hashkey_faddr = inp->in6p_faddr.ofp_s6_addr32[3] /* XXX */;
	else
#endif /* INET6 */
	hashkey_faddr = inp->inp_faddr.s_addr;

	hashkey = INP_PCBHASH(hashkey_faddr,
		 inp->inp_lport, inp->inp_fport, pcbinfo->ipi_hashmask);

	pcbhash = &pcbinfo->ipi_hashbase[hashkey];

	hashkey = INP_PCBPORTHASH(inp->inp_lport, pcbinfo->ipi_porthashmask);

	pcbporthash = &pcbinfo->ipi_porthashbase[hashkey];
	/*
	 * Go through port list and look for a head for this lport.
	 */
	OFP_LIST_FOREACH(phd, pcbporthash, phd_hash) {
		if (phd->phd_port == inp->inp_lport)
			break;
	}
	/*
	 * If none exists, malloc one and tack it on.
	 */
	if (phd == NULL) {
		phd = malloc(sizeof(struct inpcbport));
		if (phd == NULL) {
			return (OFP_ENOBUFS); /* XXX */
		}
		phd->phd_port = inp->inp_lport;
		OFP_LIST_INIT(&phd->phd_pcblist);
		OFP_LIST_INSERT_HEAD(pcbporthash, phd, phd_hash);
	}
	inp->inp_phd = phd;
	OFP_LIST_INSERT_HEAD(&phd->phd_pcblist, inp, inp_portlist);
	OFP_LIST_INSERT_HEAD(pcbhash, inp, inp_hash);
	inp->inp_flags |= INP_INHASHLIST;

	return (0);
}

/*
 * For now, there are two public interfaces to insert an inpcb into the hash
 * lists -- one that does update pcbgroups, and one that doesn't.  The latter
 * is used only in the TCP syncache, where ofp_in_pcbinshash is called before the
 * full 4-tuple is set for the inpcb, and we don't want to install in the
 * pcbgroup until later.
 *
 * XXXRW: This seems like a misfeature.  ofp_in_pcbinshash should always update
 * connection groups, and partially initialised inpcbs should not be exposed
 * to either reservation hash tables or pcbgroups.
 */
int
ofp_in_pcbinshash(struct inpcb *inp)
{

	return (in_pcbinshash_internal(inp, 1));
}

int
ofp_in_pcbinshash_nopcbgroup(struct inpcb *inp)
{

	return (in_pcbinshash_internal(inp, 0));
}

/*
 * Lookup PCB in hash list, using pcbinfo tables.  This variation assumes
 * that the caller has locked the hash list, and will not perform any further
 * locking or reference operations on either the hash list or the connection.
 */
static struct inpcb *
in_pcblookup_hash_locked(struct inpcbinfo *pcbinfo, struct ofp_in_addr faddr,
			 uint32_t fport_arg, struct ofp_in_addr laddr,\
			 uint32_t lport_arg, int lookupflags,
			 struct ofp_ifnet *ifp)
{
	struct inpcbhead *head;
	struct inpcb *inp;
	uint16_t fport = fport_arg, lport = lport_arg;

	(void)ifp;

	KASSERT((lookupflags & ~(INPLOOKUP_WILDCARD)) == 0,
		("%s: invalid lookup flags %d", __func__, lookupflags));

	INP_HASH_LOCK_ASSERT(pcbinfo);

	/*
	 * First look for an exact match.
	 */
	head = &pcbinfo->ipi_hashbase[INP_PCBHASH(faddr.s_addr, lport, fport,
	    pcbinfo->ipi_hashmask)];
	OFP_LIST_FOREACH(inp, head, inp_hash) {
#ifdef INET6
		/* XXX inp locking */
		if (odp_unlikely((inp->inp_vflag & INP_IPV4) == 0))
			continue;
#endif
		if (inp->inp_faddr.s_addr == faddr.s_addr &&
		    inp->inp_laddr.s_addr == laddr.s_addr &&
		    inp->inp_fport == fport &&
		    inp->inp_lport == lport) {
			/*
			 * XXX We should be able to directly return
			 * the inp here, without any checks.
			 * Well unless both bound with OFP_SO_REUSEPORT?
			 */
			return (inp);
		}
	}

	/*
	 * Then look for a wildcard match, if requested.
	 */
	if ((lookupflags & INPLOOKUP_WILDCARD) != 0) {
		struct inpcb *local_wild = NULL, *local_exact = NULL;
#ifdef _INET6
		struct inpcb *local_wild_mapped = NULL;
#endif
		struct inpcb *jail_wild = NULL;
		int injail = 0;

		/*
		 * Order of socket selection - we always prefer jails.
		 *      1. jailed, non-wild.
		 *      2. jailed, wild.
		 *      3. non-jailed, non-wild.
		 *      4. non-jailed, wild.
		 */

		head = &pcbinfo->ipi_hashbase[INP_PCBHASH(OFP_INADDR_ANY, lport,
		    0, pcbinfo->ipi_hashmask)];
		OFP_LIST_FOREACH(inp, head, inp_hash) {
#ifdef _INET6
			/* XXX inp locking */
			if ((inp->inp_vflag & INP_IPV4) == 0)
				continue;
#endif
			if (inp->inp_faddr.s_addr != OFP_INADDR_ANY ||
			    inp->inp_lport != lport)
				continue;

#if 0
			/* XXX inp locking */
			if (ifp && ifp->if_type == IFT_FAITH &&
			    (inp->inp_flags & INP_FAITH) == 0)
				continue;

			injail = prison_flag(inp->inp_cred, PR_IP4);
#endif
			if (injail) {
#if 0
				if (prison_check_ip4(inp->inp_cred,
				    &laddr) != 0)
					continue;
#endif
			} else {
				if (local_exact != NULL)
					continue;
			}

			if (inp->inp_laddr.s_addr == laddr.s_addr) {
				if (injail)
					return (inp);
				else
					local_exact = inp;
			} else if (inp->inp_laddr.s_addr == OFP_INADDR_ANY) {
#ifdef _INET6
				/* XXX inp locking, NULL check */
				if (inp->inp_vflag & INP_IPV6PROTO)
					local_wild_mapped = inp;
				else
#endif /* INET6 */
					if (injail)
						jail_wild = inp;
					else
						local_wild = inp;
			}
		} /* OFP_LIST_FOREACH */
		if (jail_wild != NULL) {
			return (jail_wild);
		}
		if (local_exact != NULL) {
			return (local_exact);
		}
		if (local_wild != NULL) {
			return (local_wild);
		}
#ifdef _INET6
		if (local_wild_mapped != NULL) {
			return (local_wild_mapped);
		}
#endif /* defined(INET6) */
	} /* if ((lookupflags & INPLOOKUP_WILDCARD) != 0) */

	return (NULL);
}

static struct inpcb *
in_pcblookup_hash(struct inpcbinfo *pcbinfo, struct ofp_in_addr faddr,
		  uint32_t fport, struct ofp_in_addr laddr, uint32_t lport,
		  int lookupflags, struct ofp_ifnet *ifp)
{
	struct inpcb *inp;

	INP_HASH_RLOCK(pcbinfo);

	inp = in_pcblookup_hash_locked(pcbinfo, faddr, fport, laddr, lport,
				       (lookupflags & ~(INPLOOKUP_RLOCKPCB | INPLOOKUP_WLOCKPCB)), ifp);
	if (inp != NULL) {
		ofp_in_pcbref(inp);
		INP_HASH_RUNLOCK(pcbinfo);
		if (lookupflags & INPLOOKUP_WLOCKPCB) {
			INP_WLOCK(inp);
			if (ofp_in_pcbrele_wlocked(inp)) {
				return (NULL);
			}
		} else if (lookupflags & INPLOOKUP_RLOCKPCB) {
			INP_RLOCK(inp);
			if (ofp_in_pcbrele_rlocked(inp)) {
				return (NULL);
			}
		} else
			panic("locking bug");
	} else {
		INP_HASH_RUNLOCK(pcbinfo);
	}

	return (inp);
}

/*
 * Public inpcb lookup routines, accepting a 4-tuple, and optionally, an mbuf
 * from which a pre-calculated hash value may be extracted.
 *
 * Possibly more of this logic should be in in_pcbgroup.c.
 */
struct inpcb *
ofp_in_pcblookup(struct inpcbinfo *pcbinfo, struct ofp_in_addr faddr,
	     uint32_t fport, struct ofp_in_addr laddr, uint32_t lport,
	     int lookupflags, struct ofp_ifnet *ifp)
{
	KASSERT((lookupflags & ~INPLOOKUP_MASK) == 0,
	    ("%s: invalid lookup flags %d", __func__, lookupflags));
	KASSERT((lookupflags & (INPLOOKUP_RLOCKPCB | INPLOOKUP_WLOCKPCB)) != 0,
	    ("%s: LOCKPCB not set", __func__));

	return (in_pcblookup_hash(pcbinfo, faddr, fport, laddr, lport,
				  lookupflags, ifp));
}

struct inpcb *
ofp_in_pcblookup_mbuf(struct inpcbinfo *pcbinfo, struct ofp_in_addr faddr,
    uint32_t fport, struct ofp_in_addr laddr, uint32_t lport, int lookupflags,
    struct ofp_ifnet *ifp, odp_packet_t m)
{
	(void)m;
	KASSERT((lookupflags & ~INPLOOKUP_MASK) == 0,
	    ("%s: invalid lookup flags %d", __func__, lookupflags));
	KASSERT((lookupflags & (INPLOOKUP_RLOCKPCB | INPLOOKUP_WLOCKPCB)) != 0,
	    ("%s: LOCKPCB not set", __func__));

	return (in_pcblookup_hash(pcbinfo, faddr, fport, laddr, lport,
				  lookupflags, ifp));
}

/*
 * Move PCB to the proper hash bucket when { faddr, fport } have  been
 * changed. NOTE: This does not handle the case of the lport changing (the
 * hashed port list would have to be updated as well), so the lport must
 * not change after ofp_in_pcbinshash() has been called.
 */
void
ofp_in_pcbrehash_mbuf(struct inpcb *inp, odp_packet_t m)
{
	struct inpcbinfo *pcbinfo = inp->inp_pcbinfo;
	struct inpcbhead *head;
	uint32_t hashkey_faddr;
	uint32_t hashkey;
	(void)m;

	INP_WLOCK_ASSERT(inp);
	INP_HASH_WLOCK_ASSERT(pcbinfo);

	KASSERT(inp->inp_flags & INP_INHASHLIST,
	    ("ofp_in_pcbrehash: !INP_INHASHLIST"));

#ifdef INET6
	if (inp->inp_vflag & INP_IPV6)
		hashkey_faddr = inp->in6p_faddr.ofp_s6_addr32[3] /* XXX */;
	else
#endif /* INET6 */
	hashkey_faddr = inp->inp_faddr.s_addr;

	hashkey = INP_PCBHASH(hashkey_faddr,
			      inp->inp_lport, inp->inp_fport, pcbinfo->ipi_hashmask);

	head = &pcbinfo->ipi_hashbase[hashkey];

	OFP_LIST_REMOVE(inp, inp_hash);
	OFP_LIST_INSERT_HEAD(head, inp, inp_hash);

}

/*
 * Move PCB to the proper hash bucket when { faddr, fport } have  been
 * changed. NOTE: This does not handle the case of the lport changing (the
 * hashed port list would have to be updated as well), so the lport must
 * not change after ofp_in_pcbinshash() has been called.
 */
void
ofp_in_pcbrehash(struct inpcb *inp)
{
	struct inpcbinfo *pcbinfo = inp->inp_pcbinfo;
	struct inpcbhead *head;
	uint32_t hashkey_faddr;
	uint32_t hashkey;

	INP_WLOCK_ASSERT(inp);
	INP_HASH_WLOCK_ASSERT(pcbinfo);

	KASSERT(inp->inp_flags & INP_INHASHLIST,
		("ofp_in_pcbrehash: !INP_INHASHLIST"));

#ifdef INET6
	if (inp->inp_vflag & INP_IPV6)
		hashkey_faddr = inp->in6p_faddr.ofp_s6_addr32[3] /* XXX */;
	else
#endif /* INET6 */
	hashkey_faddr = inp->inp_faddr.s_addr;

	hashkey = INP_PCBHASH(hashkey_faddr,
			      inp->inp_lport, inp->inp_fport, pcbinfo->ipi_hashmask);

	head = &pcbinfo->ipi_hashbase[hashkey];

	OFP_LIST_REMOVE(inp, inp_hash);
	OFP_LIST_INSERT_HEAD(head, inp, inp_hash);
}

/*
 * Remove PCB from various lists.
 */
static void
in_pcbremlists(struct inpcb *inp)
{
	struct inpcbinfo *pcbinfo = inp->inp_pcbinfo;

	INP_INFO_WLOCK_ASSERT(pcbinfo);
	INP_WLOCK_ASSERT(inp);

	inp->inp_gencnt = ++pcbinfo->ipi_gencnt;
	if (inp->inp_flags & INP_INHASHLIST) {
		struct inpcbport *phd = inp->inp_phd;

		INP_HASH_WLOCK(pcbinfo);
		OFP_LIST_REMOVE(inp, inp_hash);
		OFP_LIST_REMOVE(inp, inp_portlist);
		if (OFP_LIST_FIRST(&phd->phd_pcblist) == NULL) {
			OFP_LIST_REMOVE(phd, phd_hash);
			free(phd);
		}
		INP_HASH_WUNLOCK(pcbinfo);
		inp->inp_flags &= ~INP_INHASHLIST;
	}
	OFP_LIST_REMOVE(inp, inp_list);
	pcbinfo->ipi_count--;
}

/*
 * A set label operation has occurred at the socket layer, propagate the
 * label change into the in_pcb for the socket.
 */
void
ofp_in_pcbsosetlabel(struct socket *so)
{
	(void)so;
}

/*
 * in_pcb.c: manage the Protocol Control Blocks.
 *
 * NOTE: It is assumed that most of these functions will be called with
 * the pcbinfo lock held, and often, the inpcb lock held, as these utility
 * functions often modify hash chains or addresses in pcbs.
 */

