/*-
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 * Copyright (c) 2015, Nokia Solutions and Networks
 * Copyright (c) 2015, ENEA Software AB
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Karels at Berkeley Software Design, Inc.
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
 */

#ifndef _SYS_SYSCTL_H_
#define	_SYS_SYSCTL_H_

#include "ofpi_queue.h"
#include "api/ofp_sysctl.h"

enum sysinit_sub_id {
	SI_SUB_DUMMY		= 0x0000000,	/* not executed; for linker*/
	SI_SUB_KMEM		= 0x1800000,	/* kernel memory*/
};

enum sysinit_elem_order {
	SI_ORDER_FIRST		= 0x0000000,	/* first*/
	SI_ORDER_SECOND		= 0x0000001,	/* second*/
	SI_ORDER_THIRD		= 0x0000002,	/* third*/
	SI_ORDER_FOURTH		= 0x0000003,	/* fourth*/
	SI_ORDER_MIDDLE		= 0x1000000,	/* somewhere in the middle */
	SI_ORDER_ANY		= 0xfffffff	/* last*/
};

typedef void (*sysinit_nfunc_t)(void *);
typedef void (*sysinit_cfunc_t)(const void *);

struct sysinit {
	enum sysinit_sub_id	subsystem;	/* subsystem identifier*/
	enum sysinit_elem_order	order;		/* init order within subsystem*/
	sysinit_cfunc_t func;			/* function		*/
	const void	*udata;			/* multiplexer/argument */
};

/* definitions for ofp_sysctl_req 'lock' member */
#define	REQ_UNWIRED	1
#define	REQ_WIRED	2

/* definitions for ofp_sysctl_req 'flags' member */
#if defined(__amd64__) || defined(__ia64__) || defined(__powerpc64__)
#define	SCTL_MASK32	1	/* 32 bit emulation */
#endif

/* Dynamic oid handling */
int	ofp_kernel_sysctl(struct thread *td, const int *name, unsigned int namelen, void *old,
			    size_t *oldlenp, const void *new, size_t newlen,
			    size_t *retval, int flags);
int	ofp_sysctl_find_oid(const int *name, unsigned int namelen, struct ofp_sysctl_oid **noid,
			      int *nindx, struct ofp_sysctl_req *req);
void	ofp_register_sysctls(void);
int	ofp_unregister_sysctls(void);
void	ofp_sysctl_write_tree(int fd);

#endif	/* !_SYS_SYSCTL_H_ */
