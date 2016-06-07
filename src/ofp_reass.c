/*-
 * Copyright (c) 2015 Nokia Solutions and Networks
 * Copyright (c) 2015 ENEA Software AB
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ofpi.h"
#include "ofpi_pkt_processing.h"
#include "ofpi_portconf.h"
#include "ofpi_rt_lookup.h"
#include "ofpi_route.h"
#include "ofpi_util.h"
#include "ofpi_stat.h"
#include "ofpi_debug.h"
#include "ofpi_avl.h"
#include "ofpi_protosw.h"
#include "ofpi_ip6protosw.h"
#include "ofpi_arp.h"
#include "ofpi_hook.h"
#include "ofpi_log.h"
#include "ofpi_socketvar.h"
#include "ofpi_queue.h"
#include "ofpi_reass.h"

#define SHM_NAME_REASSEMBLY "OfpIpShMem"

#define	IPREASS_NHASH_LOG2	6
#define	IPREASS_NHASH		(1 << IPREASS_NHASH_LOG2)
#define	IPREASS_HMASK		(IPREASS_NHASH - 1)
#define	IPREASS_HASH(x,y) \
	(((((x) & 0xF) | ((((x) >> 8) & 0xF) << 4)) ^ (y)) & IPREASS_HMASK)

/*
 * Chain is an IP fragment queue. Chains are linked together via the first
 * packet. Packet headroom is used to save pointer information.
 */
#define NEXT_CHAIN(_f) ((_f)->next_chain)
#define NEXT_FRAG(_f) ((_f)->next_frag)
#define NEXT_TMO(_f) ((_f)->next_tmo)

#define SET_NEXT_CHAIN(_f, _v) (_f)->next_chain = _v
#define SET_NEXT_FRAG(_f, _v) (_f)->next_frag = _v
#define SET_NEXT_TMO(_f, _v) (_f)->next_tmo = _v

struct frag {
	struct frag 	*next_chain;
	struct frag 	*next_frag;
	struct frag	*next_tmo;
	odp_packet_t	pkt;
	uint16_t	off_hashix;
	uint8_t		nfrags;
	uint8_t         ipq_ttl;
};

struct ofp_reassembly_mem {
	int maxnipq, nipq;
	int maxfragsperpacket;
	struct frag *ipq[IPREASS_NHASH];
	odp_spinlock_t ipqlock;
	odp_timer_t timer;
};

static struct ofp_reassembly_mem *shm;

static void ip_freef(struct frag **head, struct frag *chain);
static void slow_tmo(void *arg);

static inline struct ofp_ip *FRAG_IP(struct frag *f)
{
	struct ofp_ip	*ip;
	/* Packet is pulled for frag struct */
	char *l3 = odp_packet_l3_ptr(f->pkt, NULL);
	ip = (struct ofp_ip	*)(l3 + sizeof(struct frag));
	return ip;
}

static int ofp_reassembly_alloc_shared_memory(void)
{
	shm = ofp_shared_memory_alloc(SHM_NAME_REASSEMBLY, sizeof(*shm));
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}

	return 0;
}

static int ofp_reassembly_free_shared_memory(void)
{
	int rc = 0;

	if (ofp_shared_memory_free(SHM_NAME_REASSEMBLY)) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}
	shm = NULL;
	return rc;
}

int ofp_reassembly_lookup_shared_memory(void)
{
	shm = ofp_shared_memory_lookup(SHM_NAME_REASSEMBLY);
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}
	return 0;
}

int ofp_reassembly_init_global(void)
{
	HANDLE_ERROR(ofp_reassembly_alloc_shared_memory());

	memset(shm, 0, sizeof(*shm));
	shm->maxnipq = 1024;
	shm->maxfragsperpacket = 16;
	shm->timer = ODP_TIMER_INVALID;
	odp_spinlock_init(&shm->ipqlock);

	return 0;
}

int ofp_reassembly_term_global(void)
{
	int i;
	struct frag *chain, *next;
	odp_packet_t pkt;
	int rc = 0;

	if (ofp_reassembly_lookup_shared_memory())
		return -1;

	if (shm->timer != ODP_TIMER_INVALID) {
		CHECK_ERROR(ofp_timer_cancel(shm->timer), rc);
		shm->timer = ODP_TIMER_INVALID;
	}

	for (i = 0; i < IPREASS_NHASH; i++) {
		chain = shm->ipq[i];
		while (chain) {
			next = NEXT_CHAIN(chain);

			while (chain) {
				pkt = chain->pkt;
				chain = NEXT_FRAG(chain);
				odp_packet_free(pkt);
			}

			chain = next;
		}
		shm->ipq[i] = NULL;
	}

	CHECK_ERROR(ofp_reassembly_free_shared_memory(), rc);

	return rc;
}

/* IP fragment reassembly functionality*/
odp_packet_t ofp_ip_reass(odp_packet_t pkt)
{
	struct ofp_ip *pkt_ip = (struct ofp_ip *)odp_packet_l3_ptr(pkt, NULL);
	struct ofp_ip *frag_ip, *chain_ip;
	int hlen = pkt_ip->ip_hl << 2;
        uint8_t ttl = pkt_ip->ip_ttl;
	uint16_t hash;
	odp_packet_t ret;
	struct frag **head, *chain = NULL, *frag, *pkt_p, *last,
		*c1 = NULL, *c2 = NULL;

	if (shm->timer == ODP_TIMER_INVALID)
		shm->timer = ofp_timer_start(1000000, slow_tmo, NULL, 0);

	if (shm->nipq > shm->maxnipq)
		goto dropfrag;

	/* To host byte order */
	pkt_ip->ip_len = odp_be_to_cpu_16(pkt_ip->ip_len);
	pkt_ip->ip_off = odp_be_to_cpu_16(pkt_ip->ip_off);
	hash = IPREASS_HASH(pkt_ip->ip_src.s_addr, pkt_ip->ip_id);
	head = &shm->ipq[hash];
	odp_spinlock_lock(&shm->ipqlock);

	/*
	 * Make space for frag header.
	 */
	pkt_p = odp_packet_push_head(pkt, sizeof(struct frag));
	if (!pkt_p)
		goto dropfrag;

	/*
	 * Save data to frag header.
	 */
	pkt_p->pkt = pkt;
	pkt_p->off_hashix = (pkt_ip->ip_off & ~OFP_IP_OFFMASK) | hash;
	SET_NEXT_CHAIN(pkt_p, NULL);
	SET_NEXT_FRAG(pkt_p, NULL);
	SET_NEXT_TMO(pkt_p, NULL);
	pkt_p->nfrags = 1;

	/*
	 * Look for queue of fragments
	 * of this datagram.
	 */
	chain = *head;
	while (chain) {
		chain_ip = FRAG_IP(chain);
		if (pkt_ip->ip_id == chain_ip->ip_id &&
		    pkt_ip->ip_src.s_addr == chain_ip->ip_src.s_addr &&
		    pkt_ip->ip_dst.s_addr == chain_ip->ip_dst.s_addr &&
		    pkt_ip->ip_p == chain_ip->ip_p)
			goto found;
		c1 = chain;
		chain = NEXT_CHAIN(chain);
	}

	chain = NULL;

	/*
	 * Attempt to trim the number of allocated fragment queues if it
	 * exceeds the administrative limit.
	 */
	if ((shm->nipq > shm->maxnipq) && (shm->maxnipq > 0)) {
	}

found:
	/*
	 * Adjust ip_len to not reflect header,
	 * convert offset of this to bytes.
	 */
	pkt_ip->ip_len -= hlen;
	if (pkt_ip->ip_off & OFP_IP_MF) {
		/*
		 * Make sure that fragments have a data length
		 * that's a non-zero multiple of 8 bytes.
		 */
		if (pkt_ip->ip_len == 0 || (pkt_ip->ip_len & 0x7) != 0) {
			goto dropfrag;
		}
	}
	pkt_ip->ip_off <<= 3;

	/*
	 * If first fragment to arrive, create a reassembly queue.
	 */
	if (chain == NULL) {
		shm->nipq++;
		pkt_p->ipq_ttl = ttl < 15 ? 15 : ttl;
		SET_NEXT_CHAIN(pkt_p, *head);
		*head = pkt_p;
		goto done;
	} else {
		chain->nfrags++;
		c2 = NEXT_CHAIN(chain);
		if (ttl > chain->ipq_ttl)
			chain->ipq_ttl = ttl;
	}

	/*
	 * Find a segment which begins after this one does.
	 */
	struct frag *prev = NULL;
	frag = last = chain;
	while (frag) {
		last = frag;
		frag_ip = FRAG_IP(frag);
		if (pkt_ip->ip_off <= frag_ip->ip_off)
			break;
		prev = frag;
		frag = NEXT_FRAG(frag);
	}

	/*
	 * If there is a preceding segment, it may provide some of
	 * our data already.  If so, drop the data from the incoming
	 * segment.  If it provides all of our data, drop us, otherwise
	 * stick new segment in the proper place.
	 *
	 * If some of the data is dropped from the preceding
	 * segment, then it's checksum is invalidated.
	 */
	if (frag) {
		if (prev) { // not first in list
			int over;
			struct ofp_ip *prev_ip = FRAG_IP(prev);
			over = prev_ip->ip_off + prev_ip->ip_len - pkt_ip->ip_off;
			if (over > 0) {
				if (over >= pkt_ip->ip_len)
					goto dropfrag;
				memmove((char *)pkt_ip + hlen,
					(char *)pkt_ip + hlen + over,
					pkt_ip->ip_len - over);
				pkt_ip->ip_off += over;
				pkt_ip->ip_len -= over;
			}
			SET_NEXT_FRAG(pkt_p, frag);
			SET_NEXT_FRAG(prev, pkt_p);
		} else { // new first in chain
			pkt_p->nfrags = frag->nfrags;
			SET_NEXT_FRAG(pkt_p, frag);
			SET_NEXT_CHAIN(pkt_p, NEXT_CHAIN(chain));
			if (c1) {
				SET_NEXT_CHAIN(c1, pkt_p);
			} else {
				*head = pkt_p;
			}
			chain = pkt_p;
		}
	} else { // append to chain
		SET_NEXT_FRAG(last, pkt_p);
	}

	/*
	 * While we overlap succeeding segments trim them or,
	 * if they are completely covered, dequeue them.
	 */
	prev = pkt_p;
	struct frag *fr = NEXT_FRAG(prev);
	while (fr) {
		struct ofp_ip *prev_ip = FRAG_IP(prev);
		struct ofp_ip *fr_ip = FRAG_IP(fr);
		int over = prev_ip->ip_off + prev_ip->ip_len - fr_ip->ip_off;
		if (over > 0) {
			if (over >= fr_ip->ip_len) {
				odp_packet_t tmp = fr->pkt;
				SET_NEXT_FRAG(prev, NEXT_FRAG(fr));
				fr = prev;
				chain->nfrags--;
				odp_packet_free(tmp);
			} else {
				int off = fr_ip->ip_hl << 2;
				memmove((char *)fr_ip + off,
					(char *)fr_ip + off + over,
					fr_ip->ip_len - over);
				fr_ip->ip_off += over;
				fr_ip->ip_len -= over;
			}
		}
		prev = fr;
		fr = NEXT_FRAG(fr);
	}

	/*
	 * Check for complete reassembly and perform frag per packet
	 * limiting.
	 *
	 * Frag limiting is performed here so that the nth frag has
	 * a chance to complete the packet before we drop the packet.
	 * As a result, n+1 frags are actually allowed per packet, but
	 * only n will ever be stored. (n = maxfragsperpacket.)
	 *
	 */
	uint16_t saved_off;
	int next = 0;
	frag = chain;
	while (frag) {
		saved_off = frag->off_hashix;
		frag_ip = FRAG_IP(frag);
		if (frag_ip->ip_off != next) {
			if (chain->nfrags > shm->maxfragsperpacket)
				ip_freef(head, chain);
			goto done;
		}
		next += frag_ip->ip_len;
		frag = NEXT_FRAG(frag);
	}

	/* Make sure the last packet didn't have the IP_MF flag */
	if (saved_off & OFP_IP_MF) {
		if (chain->nfrags > shm->maxfragsperpacket)
			ip_freef(head, chain);
		goto done;
	}

	/*
	 * Reassembly is complete.  Make sure the packet is a sane size.
	 */
	if (next + hlen > 65535) {
		ip_freef(head, chain);
		goto done;
	}

	/*
	 * Concatenate fragments.
	 */
	if (c1)
		SET_NEXT_CHAIN(c1, c2);
	else
		*head = c2;

	shm->nipq--;
	frag = NEXT_FRAG(chain);
	chain_ip = FRAG_IP(chain);
	ret = chain->pkt;
	odp_packet_pull_head(ret, sizeof(struct frag));
	int len = (chain_ip->ip_hl << 2) + chain_ip->ip_len;
	int nextoff = odp_packet_l3_offset(ret) + len;

	while (frag) {
		frag_ip = FRAG_IP(frag);
		int fraghlen = frag_ip->ip_hl<<2;
		int fraglen = frag_ip->ip_len;
		odp_packet_add_data(&ret, nextoff, fraglen);
		odp_packet_copy_from_mem(ret, nextoff, fraglen,
				       (char *)(frag_ip) + fraghlen);
		nextoff += fraglen;
		len += fraglen;
		odp_packet_t tmp = frag->pkt;
		frag = NEXT_FRAG(frag);
		odp_packet_free(tmp);
	}

	chain_ip = odp_packet_l3_ptr(ret, NULL);
	chain_ip->ip_sum = 0;
	chain_ip->ip_off = 0;
	chain_ip->ip_len = odp_cpu_to_be_16(len);
	chain_ip->ip_sum = ofp_cksum_buffer((uint16_t *)chain_ip,
					  chain_ip->ip_hl << 2);
	odp_spinlock_unlock(&shm->ipqlock);
	return ret;

dropfrag:
	if (chain)
		chain->nfrags--;
	odp_packet_free(pkt);
done:
	odp_spinlock_unlock(&shm->ipqlock);
	return ODP_PACKET_INVALID;
}

/*
 * Free a fragment reassembly header and all
 * associated datagrams.
 */
static void
ip_freef(struct frag **head, struct frag *chain)
{
	struct frag *c1, *c2;

	c1 = *head;
	c2 = NEXT_CHAIN(chain);

	if (chain == c1) {
		*head = c2;
	} else {
		while (c1 && NEXT_CHAIN(c1) != chain) {
			c1 = NEXT_CHAIN(c1);
		}
		if (c1)
			SET_NEXT_CHAIN(c1, c2);
		else {
			OFP_ERR("Chain not found");
		}
	}

	while (chain) {
		odp_packet_t tmp = chain->pkt;
		chain = NEXT_FRAG(chain);
		odp_packet_free(tmp);
	}
}

static void slow_tmo(void *arg)
{
	int i;
	struct frag *chain, *frag, *prev, *next;
	(void)arg;

	odp_spinlock_lock(&shm->ipqlock);

	for (i = 0; i < IPREASS_NHASH; i++) {
		prev = NULL;
		chain = shm->ipq[i];
		while (chain) {
			next = NEXT_CHAIN(chain);
			if (! --chain->ipq_ttl) {
				if (!prev)
					shm->ipq[i] = next;
				else
					SET_NEXT_CHAIN(prev, next);
				frag = chain;

				odp_packet_pull_head(frag->pkt, sizeof(struct frag));
				ofp_icmp_error(frag->pkt, OFP_ICMP_TIMXCEED, OFP_ICMP_TIMXCEED_REASS, 0 , 0);
				odp_packet_push_head(frag->pkt, sizeof(struct frag));

				while (frag) {
					odp_packet_t tmp = frag->pkt;
					frag = NEXT_FRAG(frag);
					odp_packet_free(tmp);
				}
			} else
				prev = chain;
			chain = next;
		}
	}

	odp_spinlock_unlock(&shm->ipqlock);
	shm->timer = ofp_timer_start(1000000, slow_tmo, NULL, 0);
}

#if 0
/* For debugging purposes */
void ofp_print_reass_queue(void)
{
	int i;
	struct frag *frag, *chain;
	struct ofp_ip *frag_ip, *chain_ip;

	OFP_LOG_NO_CTX_NO_LEVEL("\nREASS QUEUES:\n");
	for (i = 0; i < IPREASS_NHASH; i++) {
		chain = shm->ipq[i];
		while (chain) {
			chain_ip = FRAG_IP(chain);
			OFP_LOG_NO_CTX_NO_LEVEL(
			      "Chain i=%d chain=%p src=%x dst=%x p=%d id=%d:\n",
			       i, chain,
			       chain_ip->ip_src.s_addr,
			       chain_ip->ip_dst.s_addr,
			       chain_ip->ip_p,
			       chain_ip->ip_p);
			frag = chain;
			while (frag) {
				frag_ip = FRAG_IP(frag);
				OFP_LOG_NO_CTX_NO_LEVEL(
				       "  [frag=%p off=%d len=%d]\n",
				       frag,
				       frag_ip->ip_off,
				       frag_ip->ip_len);
				frag = NEXT_FRAG(frag);
			}
			OFP_LOG_NO_CTX_NO_LEVEL("\n");
			chain = NEXT_CHAIN(chain);
		}
	}
	OFP_LOG_NO_CTX_NO_LEVEL("\n");
}
#endif
