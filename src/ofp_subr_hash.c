/*-
 * Copyright (c) 1982, 1986, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * Copyright (c) 2014, Nokia
 * Copyright (c) 2014, Enea Software AB
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
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
 *	@(#)kern_subr.c	8.3 (Berkeley) 1/21/94
 */

#include "odp.h"
#include "ofpi_queue.h"
#include "ofpi_socket.h"
#include "ofpi_systm.h"
#include "ofpi_util.h"
#include "ofpi_tcp_shm.h"

/*
 * Initialize tcb hash tables.
 */
void
ofp_tcp_hashinit(long hashsize, uint64_t *hashmask,
	void *tcp_hashtbl)
{
	OFP_LIST_HEAD(generic, generic) *hashtbl = tcp_hashtbl;
	int i;

	if (hashtbl != NULL) {
		for (i = 0; i < hashsize; i++)
			OFP_LIST_INIT(&hashtbl[i]);
		*hashmask = hashsize - 1;
	}
	return;
}

/*
 * General routine to allocate a hash table with control of memory flags.
 */
void *
ofp_hashinit_flags(int elements, void *type, uint64_t *hashmask,
	       int flags)
{
	long hashsize;
	OFP_LIST_HEAD(generic, generic) *hashtbl;
	int i;

	(void)type;

	KASSERT(elements > 0, ("%s: bad elements", __func__));
	/* Exactly one of HASH_WAITOK and HASH_NOWAIT must be set. */
	KASSERT((flags & HASH_WAITOK) ^ (flags & HASH_NOWAIT),
	    ("Bad flags (0x%x) passed to ofp_hashinit_flags", flags));

	for (hashsize = 1; hashsize <= elements; hashsize <<= 1)
		continue;
	hashsize >>= 1;

	if (flags & HASH_NOWAIT)
		hashtbl = malloc((uint64_t)hashsize * sizeof(*hashtbl));
	else
		hashtbl = malloc((uint64_t)hashsize * sizeof(*hashtbl));

	if (hashtbl != NULL) {
		for (i = 0; i < hashsize; i++)
			OFP_LIST_INIT(&hashtbl[i]);
		*hashmask = hashsize - 1;
	}
	return (hashtbl);
}

/*
 * Allocate and initialize a hash table with default flag: may sleep.
 */
void *
ofp_hashinit(int elements, void *type, uint64_t *hashmask)
{

	return (ofp_hashinit_flags(elements, type, hashmask, HASH_WAITOK));
}

void
ofp_hashdestroy(void *vhashtbl, void *type, uint64_t hashmask)
{
	(void)type;

	OFP_LIST_HEAD(generic, generic) *hashtbl, *hp;

	hashtbl = vhashtbl;
	for (hp = hashtbl; hp <= &hashtbl[hashmask]; hp++)
		KASSERT(OFP_LIST_EMPTY(hp), ("%s: hash not empty", __func__));
	free(hashtbl);
}

static const int primes[] = { 1, 13, 31, 61, 127, 251, 509, 761, 1021, 1531,
			2039, 2557, 3067, 3583, 4093, 4603, 5119, 5623, 6143,
			6653, 7159, 7673, 8191, 12281, 16381, 24571, 32749 };
#define NPRIMES (sizeof(primes) / sizeof(primes[0]))

/*
 * General routine to allocate a prime number sized hash table.
 */
void *
ofp_phashinit(int elements, void *type, uint64_t *nentries)
{
	long hashsize;
	OFP_LIST_HEAD(generic, generic) *hashtbl;
	int i;

	(void)type;

	KASSERT(elements > 0, ("%s: bad elements", __func__));
	for (i = 1, hashsize = primes[1]; hashsize <= elements;) {
		i++;
		if (i == NPRIMES)
			break;
		hashsize = primes[i];
	}
	hashsize = primes[i - 1];
	hashtbl = malloc((uint64_t)hashsize * sizeof(*hashtbl));
	for (i = 0; i < hashsize; i++)
		OFP_LIST_INIT(&hashtbl[i]);
	*nentries = hashsize;
	return (hashtbl);
}
