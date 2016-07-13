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

#ifndef _OFP_SYSCTL_H_
#define _OFP_SYSCTL_H_

#include "ofp_queue.h"

#if __GNUC__ >= 4
#pragma GCC visibility push(default)
#endif

/*
 * Top-level identifiers
 */
#define	OFP_CTL_UNSPEC	0		/* unused */
#define	OFP_CTL_NET		4		/* network, see socket.h */
#define	OFP_CTL_DEBUG		5		/* number of valid top-level ids */
#define	OFP_CTL_MAXID		6		/* number of valid top-level ids */

/*
 * Helper definitions
 */
#define	__CONCAT(x,y)	x ## y
#define SET_DECLARE(set, ptype)						\
	extern ptype *__CONCAT(__start_set_,set);			\
	extern ptype *__CONCAT(__stop_set_,set)
#define SET_BEGIN(set)							\
	(&__CONCAT(__start_set_,set))
#define SET_LIMIT(set)							\
	(&__CONCAT(__stop_set_,set))
#define SET_FOREACH(pvar, set)						\
	for (pvar = SET_BEGIN(set); pvar < SET_LIMIT(set); pvar++)
#define SET_ITEM(set, i)						\
	((SET_BEGIN(set))[i])
#define SET_COUNT(set)							\
	(SET_LIMIT(set) - SET_BEGIN(set))

#define	__GLOBL1(sym)	__asm__(".globl " #sym)
#define	__GLOBL(sym)	__GLOBL1(sym)
#define __MAKE_SET(set, sym)						\
	__GLOBL(__CONCAT(__start_set_,set));				\
	__GLOBL(__CONCAT(__stop_set_,set));				\
	static void const * const __set_##set##_sym_##sym 		\
	__attribute__ ((section ("set_" #set)))				\
	__attribute__ ((used)) = &sym


#define TEXT_SET(set, sym)	__MAKE_SET(set, sym)
#define DATA_SET(set, sym)	__MAKE_SET(set, sym)
#define BSS_SET(set, sym)	__MAKE_SET(set, sym)
#define ABS_SET(set, sym)	__MAKE_SET(set, sym)
#define SET_ENTRY(set, sym)	__MAKE_SET(set, sym)

#define	C_SYSINIT(uniquifier, subsystem, order, func, ident)	\
	static struct sysinit uniquifier ## _sys_init = {	\
		subsystem,					\
		order,						\
		func,						\
		(ident)						\
	};							\
	DATA_SET(sysinit_set,uniquifier ## _sys_init)
#define	SYSINIT(uniquifier, subsystem, order, func, ident)	\
	C_SYSINIT(uniquifier, subsystem, order,			\
	(sysinit_cfunc_t)(sysinit_nfunc_t)func, (void *)(ident))
/******/

struct thread;
/*
 * Definitions for sysctl call.  The sysctl call uses a hierarchical name
 * for objects that can be examined or modified.  The name is expressed as
 * a sequence of integers.  Like a file path name, the meaning of each
 * component depends on its place in the hierarchy.  The top-level and kern
 * identifiers are defined here, and other identifiers are defined in the
 * respective subsystem header files.
 */

#define OFP_CTL_MAXNAME	24	/* largest number of components supported */

/*
 * Each subsystem defined by sysctl defines a list of variables
 * for that subsystem. Each name is either a node with further
 * levels defined below it, or it is a leaf of some particular
 * type given below. Each sysctl level defines a set of name/type
 * pairs to be used by sysctl(8) in manipulating the subsystem.
 */
#define OFP_CTLTYPE		0xf	/* Mask for the type */
#define	OFP_CTLTYPE_NODE	1	/* name is a node */
#define	OFP_CTLTYPE_INT	2	/* name describes an integer */
#define	OFP_CTLTYPE_STRING	3	/* name describes a string */
#define	OFP_CTLTYPE_S64	4	/* name describes a signed 64-bit number */
#define	OFP_CTLTYPE_OPAQUE	5	/* name describes a structure */
#define	OFP_CTLTYPE_STRUCT	OFP_CTLTYPE_OPAQUE	/* name describes a structure */
#define	OFP_CTLTYPE_UINT	6	/* name describes an unsigned integer */
#define	OFP_CTLTYPE_LONG	7	/* name describes a long */
#define	OFP_CTLTYPE_ULONG	8	/* name describes an unsigned long */
#define	OFP_CTLTYPE_U64	9	/* name describes an unsigned 64-bit number */

#define OFP_CTLFLAG_RD	0x80000000	/* Allow reads of variable */
#define OFP_CTLFLAG_WR	0x40000000	/* Allow writes to the variable */
#define OFP_CTLFLAG_RW	(OFP_CTLFLAG_RD|OFP_CTLFLAG_WR)
#define OFP_CTLFLAG_ANYBODY	0x10000000	/* All users can set this var */
#define OFP_CTLFLAG_SECURE	0x08000000	/* Permit set only if securelevel<=0 */
#define OFP_CTLFLAG_PRISON	0x04000000	/* Prisoned roots can fiddle */
#define OFP_CTLFLAG_DYN	0x02000000	/* Dynamic oid - can be freed */
#define OFP_CTLFLAG_SKIP	0x01000000	/* Skip this sysctl when listing */
#define OFP_CTLMASK_SECURE	0x00F00000	/* Secure level */
#define OFP_CTLFLAG_TUN	0x00080000	/* Tunable variable */
#define OFP_CTLFLAG_MPSAFE	0x00040000	/* Handler is MP safe */
#define OFP_CTLFLAG_VNET	0x00020000	/* Prisons with vnet can fiddle */
#define OFP_CTLFLAG_RDTUN	(OFP_CTLFLAG_RD|OFP_CTLFLAG_TUN)
#define	OFP_CTLFLAG_DYING	0x00010000	/* oid is being removed */
#define OFP_CTLFLAG_CAPRD	0x00008000	/* Can be read in capability mode */
#define OFP_CTLFLAG_CAPWR	0x00004000	/* Can be written in capability mode */
#define OFP_CTLFLAG_CAPRW	(OFP_CTLFLAG_CAPRD|OFP_CTLFLAG_CAPWR)

/*
 * USE THIS instead of a hardwired number from the categories below
 * to get dynamically assigned sysctl entries using the linker-set
 * technology. This is the way nearly all new sysctl variables should
 * be implemented.
 * e.g. OFP_SYSCTL_INT(_parent, OFP_OID_AUTO, name, OFP_CTLFLAG_RW, &variable, 0, "");
 */
#define OFP_OID_AUTO	(-1)

/*
 * The starting number for dynamically-assigned entries.  WARNING!
 * ALL static sysctl entries should have numbers LESS than this!
 */
#define OFP_CTL_AUTO_START	0x100

#define OFP_SYSCTL_HANDLER_ARGS struct ofp_sysctl_oid *oidp, void *arg1,	\
	intptr_t arg2, struct ofp_sysctl_req *req

/*
 * This describes the access space for a sysctl request.  This is needed
 * so that we can use the interface from the kernel or from user-space.
 */
struct ofp_sysctl_req {
	struct thread	*td;		/* used for access checking */
	int		lock;		/* wiring state */
	void		*oldptr;
	size_t		oldlen;
	size_t		oldidx;
	int		(*oldfunc)(struct ofp_sysctl_req *, const void *, size_t);
	const void	*newptr;
	size_t		newlen;
	size_t		newidx;
	int		(*newfunc)(struct ofp_sysctl_req *, void *, size_t);
	size_t		validlen;
	int		flags;
};

OFP_SLIST_HEAD(ofp_sysctl_oid_list, ofp_sysctl_oid);

/*
 * This describes one "oid" in the MIB tree.  Potentially more nodes can
 * be hidden behind it, expanded by the handler.
 */
struct ofp_sysctl_oid {
	struct ofp_sysctl_oid_list *oid_parent;
	OFP_SLIST_ENTRY(ofp_sysctl_oid) oid_link;
	int		oid_number;
	unsigned int		oid_kind;
	void		*oid_arg1;
	intptr_t	oid_arg2;
	const char	*oid_name;
	int 		(*oid_handler)(OFP_SYSCTL_HANDLER_ARGS);
	const char	*oid_fmt;
	int		oid_refcnt;
	unsigned int		oid_running;
	const char	*oid_descr;
};

#define SYSCTL_IN(r, p, l) (r->newfunc)(r, p, l)
#define SYSCTL_OUT(r, p, l) (r->oldfunc)(r, p, l)

int sysctl_handle_int(OFP_SYSCTL_HANDLER_ARGS);
int sysctl_msec_to_ticks(OFP_SYSCTL_HANDLER_ARGS);
int sysctl_handle_long(OFP_SYSCTL_HANDLER_ARGS);
int sysctl_handle_64(OFP_SYSCTL_HANDLER_ARGS);
int sysctl_handle_string(OFP_SYSCTL_HANDLER_ARGS);
int sysctl_handle_opaque(OFP_SYSCTL_HANDLER_ARGS);

int sysctl_dpcpu_int(OFP_SYSCTL_HANDLER_ARGS);
int sysctl_dpcpu_long(OFP_SYSCTL_HANDLER_ARGS);
int sysctl_dpcpu_quad(OFP_SYSCTL_HANDLER_ARGS);

/*
 * These functions are used to add/remove an oid from the mib.
 */
//void sysctl_register_oid(struct ofp_sysctl_oid *oidp);
//void sysctl_unregister_oid(struct ofp_sysctl_oid *oidp);

/* Declare a static oid to allow child oids to be added to it. */
#define SYSCTL_DECL(name)					\
	extern struct ofp_sysctl_oid_list sysctl_##name##_children

/* Hide these in macros */
#define	SYSCTL_CHILDREN(oid_ptr) (struct ofp_sysctl_oid_list *) \
	(oid_ptr)->oid_arg1
#define	SYSCTL_CHILDREN_SET(oid_ptr, val) \
	(oid_ptr)->oid_arg1 = (val);
#define	SYSCTL_STATIC_CHILDREN(oid_name) \
	(&sysctl_##oid_name##_children)

/* === Structs and macros related to context handling === */

/* All dynamically created sysctls can be tracked in a context list. */
struct sysctl_ctx_entry {
	struct ofp_sysctl_oid *entry;
	OFP_TAILQ_ENTRY(sysctl_ctx_entry) link;
};

OFP_TAILQ_HEAD(sysctl_ctx_list, sysctl_ctx_entry);

#define SYSCTL_NODE_CHILDREN(parent, name) \
	sysctl_##parent##_##name##_children

/*
 * These macros provide type safety for sysctls.  SYSCTL_ALLOWED_TYPES()
 * defines a transparent union of the allowed types.  SYSCTL_ASSERT_TYPE()
 * and SYSCTL_ADD_ASSERT_TYPE() use the transparent union to assert that
 * the pointer matches the allowed types.
 *
 * The allow_0 member allows a literal 0 to be passed for ptr.
 */
#define	SYSCTL_ALLOWED_TYPES(type, decls)			\
	union sysctl_##type {					\
		long allow_0;					\
		decls						\
	} __attribute__((__transparent_union__));		\
								\
	static inline void *					\
	__sysctl_assert_##type(union sysctl_##type ptr)		\
	{							\
		return (ptr.a);					\
	}							\
	struct __hack

SYSCTL_ALLOWED_TYPES(INT, int *a; );
SYSCTL_ALLOWED_TYPES(UINT, unsigned int *a; );
SYSCTL_ALLOWED_TYPES(LONG, long *a; );
SYSCTL_ALLOWED_TYPES(ULONG, unsigned long *a; );
SYSCTL_ALLOWED_TYPES(INT64, int64_t *a; long long *b; );
SYSCTL_ALLOWED_TYPES(UINT64, uint64_t *a; unsigned long long *b; );

#define	CTASSERT(x)		_CTASSERT(x, __LINE__)
#define	_CTASSERT(x, y)		__CTASSERT(x, y)
#define	__CTASSERT(x, y)	typedef char __assert ## y[(x) ? 1 : -1]

#ifdef notyet
#define	SYSCTL_ADD_ASSERT_TYPE(type, ptr)	\
	__sysctl_assert_ ## type (ptr)
#define	SYSCTL_ASSERT_TYPE(type, ptr, parent, name)	\
	_SYSCTL_ASSERT_TYPE(type, ptr, __LINE__, parent##_##name)
#else
#define	SYSCTL_ADD_ASSERT_TYPE(type, ptr)	ptr
#define	SYSCTL_ASSERT_TYPE(type, ptr, parent, name)
#endif
#define	_SYSCTL_ASSERT_TYPE(t, p, l, id)		\
	__SYSCTL_ASSERT_TYPE(t, p, l, id)
#define	__SYSCTL_ASSERT_TYPE(type, ptr, line, id)			\
	static inline void						\
	sysctl_assert_##line##_##id(void)				\
	{								\
		(void)__sysctl_assert_##type(ptr);			\
	}								\
	struct __hack

#ifndef NO_SYSCTL_DESCR
#define __DESCR(d) d
#else
#define __DESCR(d) ""
#endif

/* This constructs a "raw" MIB oid. */
#define OFP_SYSCTL_OID(parent, nbr, name, kind, a1, a2, handler, fmt, descr) \
	static struct ofp_sysctl_oid sysctl__##parent##_##name = {		 \
		&sysctl_##parent##_children, { NULL }, nbr, kind,	 \
		a1, a2, #name, handler, fmt, 0, 0, __DESCR(descr) };	 \
	DATA_SET(sysctl_set, sysctl__##parent##_##name)

#define OFP_SYSCTL_ADD_OID(ctx, parent, nbr, name, kind, a1, a2, handler, fmt, descr) \
	ofp_sysctl_add_oid(ctx, parent, nbr, name, kind, a1, a2, handler, fmt, __DESCR(descr))

/* This constructs a node from which other oids can hang. */
#define OFP_SYSCTL_NODE(parent, nbr, name, access, handler, descr)		    \
	struct ofp_sysctl_oid_list SYSCTL_NODE_CHILDREN(parent, name);	    \
	OFP_SYSCTL_OID(parent, nbr, name, OFP_CTLTYPE_NODE|(access),		    \
	    (void*)&SYSCTL_NODE_CHILDREN(parent, name), 0, handler, "N", descr)

#define OFP_SYSCTL_ADD_NODE(ctx, parent, nbr, name, access, handler, descr)	    \
	ofp_sysctl_add_oid(ctx, parent, nbr, name, OFP_CTLTYPE_NODE|(access),	    \
	NULL, 0, handler, "N", __DESCR(descr))

/* Oid for a string.  len can be 0 to indicate '\0' termination. */
#define OFP_SYSCTL_STRING(parent, nbr, name, access, arg, len, descr) \
	OFP_SYSCTL_OID(parent, nbr, name, OFP_CTLTYPE_STRING|(access), \
		arg, len, sysctl_handle_string, "A", descr)

#define OFP_SYSCTL_ADD_STRING(ctx, parent, nbr, name, access, arg, len, descr)  \
	ofp_sysctl_add_oid(ctx, parent, nbr, name, OFP_CTLTYPE_STRING|(access),	    \
	arg, len, sysctl_handle_string, "A", __DESCR(descr))

/* Oid for an int.  If ptr is NULL, val is returned. */
#define	OFP_SYSCTL_INT(parent, nbr, name, access, ptr, val, descr)		\
	SYSCTL_ASSERT_TYPE(INT, ptr, parent, name);			\
	OFP_SYSCTL_OID(parent, nbr, name,					\
	    OFP_CTLTYPE_INT | OFP_CTLFLAG_MPSAFE | (access),			\
	    ptr, val, sysctl_handle_int, "I", descr)

#define	OFP_SYSCTL_ADD_INT(ctx, parent, nbr, name, access, ptr, val, descr)	\
	ofp_sysctl_add_oid(ctx, parent, nbr, name,				\
	    OFP_CTLTYPE_INT | OFP_CTLFLAG_MPSAFE | (access),			\
	    SYSCTL_ADD_ASSERT_TYPE(INT, ptr), val,			\
	    sysctl_handle_int, "I", __DESCR(descr))

/* Oid for an unsigned int.  If ptr is NULL, val is returned. */
#define	OFP_SYSCTL_UINT(parent, nbr, name, access, ptr, val, descr)		\
	SYSCTL_ASSERT_TYPE(UINT, ptr, parent, name);			\
	OFP_SYSCTL_OID(parent, nbr, name,					\
	    OFP_CTLTYPE_UINT | OFP_CTLFLAG_MPSAFE | (access),			\
	    ptr, val, sysctl_handle_int, "IU", descr)

#define	OFP_SYSCTL_ADD_UINT(ctx, parent, nbr, name, access, ptr, val, descr) \
	ofp_sysctl_add_oid(ctx, parent, nbr, name,				\
	    OFP_CTLTYPE_UINT | OFP_CTLFLAG_MPSAFE | (access),			\
	    SYSCTL_ADD_ASSERT_TYPE(UINT, ptr), val,			\
	    sysctl_handle_int, "IU", __DESCR(descr))

/* Oid for a long.  The pointer must be non NULL. */
#define	OFP_SYSCTL_LONG(parent, nbr, name, access, ptr, val, descr)		\
	SYSCTL_ASSERT_TYPE(LONG, ptr, parent, name);			\
	OFP_SYSCTL_OID(parent, nbr, name,					\
	    OFP_CTLTYPE_LONG | OFP_CTLFLAG_MPSAFE | (access),			\
	    ptr, val, sysctl_handle_long, "L", descr)

#define	OFP_SYSCTL_ADD_LONG(ctx, parent, nbr, name, access, ptr, descr)	\
	ofp_sysctl_add_oid(ctx, parent, nbr, name,				\
	    OFP_CTLTYPE_LONG | OFP_CTLFLAG_MPSAFE | (access),			\
	    SYSCTL_ADD_ASSERT_TYPE(LONG, ptr), 0,			\
	    sysctl_handle_long,	"L", __DESCR(descr))

/* Oid for an unsigned long.  The pointer must be non NULL. */
#define	OFP_SYSCTL_ULONG(parent, nbr, name, access, ptr, val, descr)	\
	SYSCTL_ASSERT_TYPE(ULONG, ptr, parent, name);			\
	OFP_SYSCTL_OID(parent, nbr, name,					\
	    OFP_CTLTYPE_ULONG | OFP_CTLFLAG_MPSAFE | (access),			\
	    ptr, val, sysctl_handle_long, "LU", descr)

#define	OFP_SYSCTL_ADD_ULONG(ctx, parent, nbr, name, access, ptr, descr)	\
	ofp_sysctl_add_oid(ctx, parent, nbr, name,				\
	    OFP_CTLTYPE_ULONG | OFP_CTLFLAG_MPSAFE | (access),			\
	    SYSCTL_ADD_ASSERT_TYPE(ULONG, ptr), 0,			\
	    sysctl_handle_long, "LU", __DESCR(descr))

/* Oid for a quad.  The pointer must be non NULL. */
#define	OFP_SYSCTL_QUAD(parent, nbr, name, access, ptr, val, descr)		\
	SYSCTL_ASSERT_TYPE(INT64, ptr, parent, name);			\
	OFP_SYSCTL_OID(parent, nbr, name,					\
	    OFP_CTLTYPE_S64 | OFP_CTLFLAG_MPSAFE | (access),			\
	    ptr, val, sysctl_handle_64, "Q", descr)

#define	OFP_SYSCTL_ADD_QUAD(ctx, parent, nbr, name, access, ptr, descr)	\
	ofp_sysctl_add_oid(ctx, parent, nbr, name,				\
	    OFP_CTLTYPE_S64 | OFP_CTLFLAG_MPSAFE | (access),			\
	    SYSCTL_ADD_ASSERT_TYPE(INT64, ptr), 0,			\
	    sysctl_handle_64, "Q", __DESCR(descr))

#define	OFP_SYSCTL_UQUAD(parent, nbr, name, access, ptr, val, descr)	\
	SYSCTL_ASSERT_TYPE(UINT64, ptr, parent, name);			\
	OFP_SYSCTL_OID(parent, nbr, name,					\
	    OFP_CTLTYPE_U64 | OFP_CTLFLAG_MPSAFE | (access),			\
	    ptr, val, sysctl_handle_64, "QU", descr)

#define	OFP_SYSCTL_ADD_UQUAD(ctx, parent, nbr, name, access, ptr, descr)	\
	ofp_sysctl_add_oid(ctx, parent, nbr, name,				\
	    OFP_CTLTYPE_U64 | OFP_CTLFLAG_MPSAFE | (access),			\
	    SYSCTL_ADD_ASSERT_TYPE(UINT64, ptr), 0,			\
	    sysctl_handle_64, "QU", __DESCR(descr))

/* Oid for an opaque object.  Specified by a pointer and a length. */
#define OFP_SYSCTL_OPAQUE(parent, nbr, name, access, ptr, len, fmt, descr) \
	OFP_SYSCTL_OID(parent, nbr, name, OFP_CTLTYPE_OPAQUE|(access), \
		ptr, len, sysctl_handle_opaque, fmt, descr)

#define OFP_SYSCTL_ADD_OPAQUE(ctx, parent, nbr, name, access, ptr, len, fmt, descr)\
	ofp_sysctl_add_oid(ctx, parent, nbr, name, OFP_CTLTYPE_OPAQUE|(access),	    \
	ptr, len, sysctl_handle_opaque, fmt, __DESCR(descr))

/* Oid for a struct.  Specified by a pointer and a type. */
#define OFP_SYSCTL_STRUCT(parent, nbr, name, access, ptr, type, descr) \
	OFP_SYSCTL_OID(parent, nbr, name, OFP_CTLTYPE_OPAQUE|(access), \
		ptr, sizeof(struct type), sysctl_handle_opaque, \
		"S," #type, descr)

#define OFP_SYSCTL_ADD_STRUCT(ctx, parent, nbr, name, access, ptr, type, descr) \
	ofp_sysctl_add_oid(ctx, parent, nbr, name, OFP_CTLTYPE_OPAQUE|(access),	    \
	ptr, sizeof(struct type), sysctl_handle_opaque, "S," #type, __DESCR(descr))

/* Oid for a procedure.  Specified by a pointer and an arg. */
#define OFP_SYSCTL_PROC(parent, nbr, name, access, ptr, arg, handler, fmt, descr) \
	CTASSERT(((access) & OFP_CTLTYPE) != 0);				\
	OFP_SYSCTL_OID(parent, nbr, name, (access), \
		ptr, arg, handler, fmt, descr)

#define OFP_SYSCTL_ADD_PROC(ctx, parent, nbr, name, access, ptr, arg, handler, fmt, descr) \
	ofp_sysctl_add_oid(ctx, parent, nbr, name, (access),			    \
	ptr, arg, handler, fmt, __DESCR(descr))

/*
 * Declare some common oids.
 */
extern struct ofp_sysctl_oid_list sysctl__children;
SYSCTL_DECL(_net);
SYSCTL_DECL(_debug);

/* Dynamic oid handling */
struct ofp_sysctl_oid *ofp_sysctl_add_oid(struct sysctl_ctx_list *clist,
		struct ofp_sysctl_oid_list *parent, int nbr, const char *name,
		int kind, void *arg1, intptr_t arg2,
		int (*handler) (OFP_SYSCTL_HANDLER_ARGS),
		const char *fmt, const char *descr);

int	ofp_sysctl(const char *name, void *old, size_t *oldlenp,
		     const void *newp, size_t newlen, size_t *retval);

#if __GNUC__ >= 4
#pragma GCC visibility pop
#endif

#endif
