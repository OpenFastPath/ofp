/*-
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 * Copyright (c) 2015, Nokia Solutions and Networks
 * Copyright (c) 2015, ENEA Software AB
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Karels at Berkeley Software Design, Inc.
 *
 * Quite extensively rewritten by Poul-Henning Kamp of the FreeBSD
 * project, to make these variables more userfriendly.
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
 *	@(#)kern_sysctl.c	8.4 (Berkeley) 4/14/94
 */

#include <stdlib.h>

#include "odp.h"
#include "ofpi.h"
#include "ofpi_log.h"
#include "ofpi_util.h"
#include "ofpi_errno.h"
#include "ofpi_sysctl.h"
#include "ofpi_socketvar.h"

#define SYSCTL_DEBUG 1

#define malloc(_a, _b, _c) malloc(_a)
#define free(_a, _b) free(_a)

//static MALLOC_DEFINE(M_SYSCTL, "sysctl", "sysctl internal magic");
//static MALLOC_DEFINE(M_SYSCTLOID, "sysctloid", "sysctl dynamic oids");
//static MALLOC_DEFINE(M_SYSCTLTMP, "sysctltmp", "sysctl temp output buffer");

/*
 * The sysctllock protects the MIB tree.  It also protects sysctl
 * contexts used with dynamic sysctls.  The sysctl_register_oid() and
 * sysctl_unregister_oid() routines require the sysctllock to already
 * be held, so the sysctl_lock() and sysctl_unlock() routines are
 * provided for the few places in the kernel which need to use that
 * API rather than using the dynamic API.  Use of the dynamic API is
 * strongly encouraged for most code.
 *
 * The sysctlmemlock is used to limit the amount of user memory wired for
 * sysctl requests.  This is implemented by serializing any userland
 * sysctl requests larger than a single page via an exclusive lock.
 */
static odp_spinlock_t sysctllock;
static odp_spinlock_t sysctlmemlock;

#define	SYSCTL_XLOCK()		odp_spinlock_lock(&sysctllock)
#define	SYSCTL_XUNLOCK()	odp_spinlock_unlock(&sysctllock)
#define	SYSCTL_ASSERT_XLOCKED()	//sx_assert(&sysctllock, SA_XLOCKED)
#define	SYSCTL_INIT()		odp_spinlock_init(&sysctllock)
#define	SYSCTL_SLEEP(ch, wmesg, timo) do {} while (0)
	//				sx_sleep(ch, &sysctllock, 0, wmesg, timo)

static int sysctl_root(OFP_SYSCTL_HANDLER_ARGS);

struct ofp_sysctl_oid_list sysctl__children; /* root list */

OFP_SYSCTL_NODE(, 0, sysctl, OFP_CTLFLAG_RW, 0,
	"Sysctl internal magic");
OFP_SYSCTL_NODE(, OFP_CTL_NET, net, OFP_CTLFLAG_RW, 0,
	"Network, (see socket.h)");

#if 0
static int	sysctl_remove_oid_locked(struct ofp_sysctl_oid *oidp, int del,
		    int recurse);
static int
copyout(const void *src, void *dst, size_t len)
{
	memcpy(dst, src, len);
	return 0;
}

static int
copyin(const void *src, void *dst, size_t len)
{
	memcpy(dst, src, len);
	return 0;
}
#endif

static struct ofp_sysctl_oid *
sysctl_find_oidname(const char *name, struct ofp_sysctl_oid_list *list)
{
	struct ofp_sysctl_oid *oidp;

	SYSCTL_ASSERT_XLOCKED();
	OFP_SLIST_FOREACH(oidp, list, oid_link) {
		if (strcmp(oidp->oid_name, name) == 0) {
			return (oidp);
		}
	}
	return (NULL);
}

/*
 * Initialization of the MIB tree.
 *
 * Order by number in each list.
 */

static void
sysctl_register_oid(struct ofp_sysctl_oid *oidp)
{
	struct ofp_sysctl_oid_list *parent = oidp->oid_parent;
	struct ofp_sysctl_oid *p;
	struct ofp_sysctl_oid *q;

	/*
	 * First check if another oid with the same name already
	 * exists in the parent's list.
	 */
	SYSCTL_ASSERT_XLOCKED();
	p = sysctl_find_oidname(oidp->oid_name, parent);
	if (p != NULL) {
		if ((p->oid_kind & OFP_CTLTYPE) == OFP_CTLTYPE_NODE) {
			p->oid_refcnt++;
			return;
		} else {
			OFP_ERR("Cannot re-use leaf '%s'", p->oid_name);
			return;
		}
	}
	/*
	 * If this oid has a number OFP_OID_AUTO, give it a number which
	 * is greater than any current oid.
	 * NOTE: DO NOT change the starting value here, change it in
	 * <sys/sysctl.h>, and make sure it is at least 256 to
	 * accomodate e.g. net.inet.raw as a static sysctl node.
	 */
	if (oidp->oid_number == OFP_OID_AUTO) {
		static int newoid = OFP_CTL_AUTO_START;

		oidp->oid_number = newoid++;
		if (newoid == 0x7fffffff)
			panic("out of oids");
	}
#if 0
	else if (oidp->oid_number >= OFP_CTL_AUTO_START) {
		/* do not panic; this happens when unregistering sysctl sets */
		OFP_ERR("Static sysctl oid too high: %d", oidp->oid_number);
	}
#endif

	/*
	 * Insert the oid into the parent's list in order.
	 */
	q = NULL;
	OFP_SLIST_FOREACH(p, parent, oid_link) {
		if (oidp->oid_number < p->oid_number)
			break;
		q = p;
	}
	if (q)
		OFP_SLIST_INSERT_AFTER(q, oidp, oid_link);
	else
		OFP_SLIST_INSERT_HEAD(parent, oidp, oid_link);
}


static int
sysctl_unregister_oid(struct ofp_sysctl_oid *oidp)
{
	struct ofp_sysctl_oid *p;
	int error = 0;

	SYSCTL_ASSERT_XLOCKED();
	error = OFP_ENOENT;
	if (oidp->oid_number == OFP_OID_AUTO) {
		error = OFP_EINVAL;
	} else {
		OFP_SLIST_FOREACH(p, oidp->oid_parent, oid_link) {
			if (p == oidp) {
				OFP_SLIST_REMOVE(oidp->oid_parent, oidp,
				    ofp_sysctl_oid, oid_link);
				error = 0;
				break;
			}
		}
	}

	/*
	 * This can happen when a module fails to register and is
	 * being unloaded afterwards.  It should not be a panic()
	 * for normal use.
	 */
	if (error)
		OFP_ERR("Failed to unregister sysctl");

	return error;
}

#if 0
/* Initialize a new context to keep track of dynamically added sysctls. */
static int
sysctl_ctx_init(struct sysctl_ctx_list *c)
{

	if (c == NULL) {
		return (OFP_EINVAL);
	}

	/*
	 * No locking here, the caller is responsible for not adding
	 * new nodes to a context until after this function has
	 * returned.
	 */
	OFP_TAILQ_INIT(c);
	return (0);
}

/* Free the context, and destroy all dynamic oids registered in this context */
static int
sysctl_ctx_free(struct sysctl_ctx_list *clist)
{
	struct sysctl_ctx_entry *e, *e1;
	int error;

	error = 0;
	/*
	 * First perform a "dry run" to check if it's ok to remove oids.
	 * XXX FIXME
	 * XXX This algorithm is a hack. But I don't know any
	 * XXX better solution for now...
	 */
	SYSCTL_XLOCK();
	OFP_TAILQ_FOREACH(e, clist, link) {
		error = sysctl_remove_oid_locked(e->entry, 0, 0);
		if (error)
			break;
	}
	/*
	 * Restore deregistered entries, either from the end,
	 * or from the place where error occured.
	 * e contains the entry that was not unregistered
	 */
	if (error)
		e1 = OFP_TAILQ_PREV(e, sysctl_ctx_list, link);
	else
		e1 = OFP_TAILQ_LAST(clist, sysctl_ctx_list);
	while (e1 != NULL) {
		sysctl_register_oid(e1->entry);
		e1 = OFP_TAILQ_PREV(e1, sysctl_ctx_list, link);
	}
	if (error) {
		SYSCTL_XUNLOCK();
		return(OFP_EBUSY);
	}
	/* Now really delete the entries */
	e = OFP_TAILQ_FIRST(clist);
	while (e != NULL) {
		e1 = OFP_TAILQ_NEXT(e, link);
		error = sysctl_remove_oid_locked(e->entry, 1, 0);
		if (error)
			panic("sysctl_remove_oid: corrupt tree\n");
		free(e, M_SYSCTLOID);
		e = e1;
	}
	SYSCTL_XUNLOCK();
	return (error);
}
#endif

/* Add an entry to the context */
static struct sysctl_ctx_entry *
sysctl_ctx_entry_add(struct sysctl_ctx_list *clist, struct ofp_sysctl_oid *oidp)
{
	struct sysctl_ctx_entry *e;

	SYSCTL_ASSERT_XLOCKED();
	if (clist == NULL || oidp == NULL)
		return(NULL);
	e = malloc(sizeof(struct sysctl_ctx_entry), M_SYSCTLOID, M_WAITOK);
	e->entry = oidp;
	OFP_TAILQ_INSERT_HEAD(clist, e, link);
	return (e);
}

#if 0
/* Find an entry in the context */
static struct sysctl_ctx_entry *
sysctl_ctx_entry_find(struct sysctl_ctx_list *clist, struct ofp_sysctl_oid *oidp)
{
	struct sysctl_ctx_entry *e;

	SYSCTL_ASSERT_XLOCKED();
	if (clist == NULL || oidp == NULL)
		return(NULL);
	OFP_TAILQ_FOREACH(e, clist, link) {
		if(e->entry == oidp)
			return(e);
	}
	return (e);
}

/*
 * Delete an entry from the context.
 * NOTE: this function doesn't free oidp! You have to remove it
 * with sysctl_remove_oid().
 */
static int
sysctl_ctx_entry_del(struct sysctl_ctx_list *clist, struct ofp_sysctl_oid *oidp)
{
	struct sysctl_ctx_entry *e;

	if (clist == NULL || oidp == NULL)
		return (OFP_EINVAL);
	SYSCTL_XLOCK();
	e = sysctl_ctx_entry_find(clist, oidp);
	if (e != NULL) {
		OFP_TAILQ_REMOVE(clist, e, link);
		SYSCTL_XUNLOCK();
		free(e, M_SYSCTLOID);
		return (0);
	} else {
		SYSCTL_XUNLOCK();
		return (OFP_ENOENT);
	}
}


/*
 * Remove dynamically created sysctl trees.
 * oidp - top of the tree to be removed
 * del - if 0 - just deregister, otherwise free up entries as well
 * recurse - if != 0 traverse the subtree to be deleted
 */
static int
sysctl_remove_oid(struct ofp_sysctl_oid *oidp, int del, int recurse)
{
	int error;

	SYSCTL_XLOCK();
	error = sysctl_remove_oid_locked(oidp, del, recurse);
	SYSCTL_XUNLOCK();
	return (error);
}

static int
sysctl_remove_name(struct ofp_sysctl_oid *parent, const char *name,
    int del, int recurse)
{
	struct ofp_sysctl_oid *p, *tmp;
	int error;

	error = OFP_ENOENT;
	SYSCTL_XLOCK();
	OFP_SLIST_FOREACH_SAFE(p, SYSCTL_CHILDREN(parent), oid_link, tmp) {
		if (strcmp(p->oid_name, name) == 0) {
			error = sysctl_remove_oid_locked(p, del, recurse);
			break;
		}
	}
	SYSCTL_XUNLOCK();

	return (error);
}


static int
sysctl_remove_oid_locked(struct ofp_sysctl_oid *oidp, int del, int recurse)
{
	struct ofp_sysctl_oid *p, *tmp;
	int error;

	SYSCTL_ASSERT_XLOCKED();
	if (oidp == NULL)
		return(OFP_EINVAL);
	if ((oidp->oid_kind & OFP_CTLFLAG_DYN) == 0) {
		OFP_ERR("Cannot remove non-dynamic nodes");
		return OFP_EINVAL;
	}
	/*
	 * WARNING: normal method to do this should be through
	 * sysctl_ctx_free(). Use recursing as the last resort
	 * method to purge your sysctl tree of leftovers...
	 * However, if some other code still references these nodes,
	 * it will panic.
	 */
	if ((oidp->oid_kind & OFP_CTLTYPE) == OFP_CTLTYPE_NODE) {
		if (oidp->oid_refcnt == 1) {
			OFP_SLIST_FOREACH_SAFE(p,
			    SYSCTL_CHILDREN(oidp), oid_link, tmp) {
				if (!recurse)
					return (OFP_ENOTEMPTY);
				error = sysctl_remove_oid_locked(p, del,
				    recurse);
				if (error)
					return (error);
			}
			if (del)
				free(SYSCTL_CHILDREN(oidp), M_SYSCTLOID);
		}
	}
	if (oidp->oid_refcnt > 1 ) {
		oidp->oid_refcnt--;
	} else {
		if (oidp->oid_refcnt == 0) {
			OFP_ERR("Bad oid_refcnt=%u '%s'",
				oidp->oid_refcnt, oidp->oid_name);
			return OFP_EINVAL;
		}
		sysctl_unregister_oid(oidp);
		if (del) {
			/*
			 * Wait for all threads running the handler to drain.
			 * This preserves the previous behavior when the
			 * sysctl lock was held across a handler invocation,
			 * and is necessary for module unload correctness.
			 */
			while (oidp->oid_running > 0) {
				oidp->oid_kind |= OFP_CTLFLAG_DYING;
				SYSCTL_SLEEP(&oidp->oid_running, "oidrm", 0);
			}
			if (oidp->oid_descr)
				free((void *)(uintptr_t)(const void *)oidp->oid_descr, M_SYSCTLOID);
			free((void *)(uintptr_t)(const void *)oidp->oid_name,
			     M_SYSCTLOID);
			free(oidp, M_SYSCTLOID);
		}
	}
	return 0;
}
#endif
/*
 * Create new sysctls at run time.
 * clist may point to a valid context initialized with sysctl_ctx_init().
 */
struct ofp_sysctl_oid *
ofp_sysctl_add_oid(struct sysctl_ctx_list *clist, struct ofp_sysctl_oid_list *parent,
	int number, const char *name, int kind, void *arg1, intptr_t arg2,
	int (*handler)(OFP_SYSCTL_HANDLER_ARGS), const char *fmt, const char *descr)
{
	struct ofp_sysctl_oid *oidp;
	ssize_t len;
	char *newname;

	/* You have to hook up somewhere.. */
	if (parent == NULL)
		return(NULL);
	/* Check if the node already exists, otherwise create it */
	SYSCTL_XLOCK();
	oidp = sysctl_find_oidname(name, parent);
	if (oidp != NULL) {
		if ((oidp->oid_kind & OFP_CTLTYPE) == OFP_CTLTYPE_NODE) {
			oidp->oid_refcnt++;
			/* Update the context */
			if (clist != NULL)
				sysctl_ctx_entry_add(clist, oidp);
			SYSCTL_XUNLOCK();
			return (oidp);
		} else {
			SYSCTL_XUNLOCK();
			OFP_ERR("Cannot re-use leaf '%s'", name);
			return NULL;
		}
	}
	oidp = malloc(sizeof(struct ofp_sysctl_oid), M_SYSCTLOID, M_WAITOK|M_ZERO);
	oidp->oid_parent = parent;
	OFP_SLIST_NEXT(oidp, oid_link) = NULL;
	oidp->oid_number = number;
	oidp->oid_refcnt = 1;
	len = strlen(name);
	newname = malloc(len + 1, M_SYSCTLOID, M_WAITOK);
	bcopy(name, newname, len + 1);
	newname[len] = '\0';
	oidp->oid_name = newname;
	oidp->oid_handler = handler;
	oidp->oid_kind = OFP_CTLFLAG_DYN | kind;
	if ((kind & OFP_CTLTYPE) == OFP_CTLTYPE_NODE) {
		/* Allocate space for children */
		SYSCTL_CHILDREN_SET(oidp, malloc(sizeof(struct ofp_sysctl_oid_list),
		    M_SYSCTLOID, M_WAITOK));
		OFP_SLIST_INIT(SYSCTL_CHILDREN(oidp));
		oidp->oid_arg2 = arg2;
	} else {
		oidp->oid_arg1 = arg1;
		oidp->oid_arg2 = arg2;
	}
	oidp->oid_fmt = fmt;
	if (descr) {
		int len = strlen(descr) + 1;
		oidp->oid_descr = malloc(len, M_SYSCTLOID, M_WAITOK);
		if (oidp->oid_descr)
			strcpy((char *)(uintptr_t)(const void *)oidp->oid_descr, descr);
	}
	/* Update the context, if used */
	if (clist != NULL)
		sysctl_ctx_entry_add(clist, oidp);
	/* Register this oid */
	sysctl_register_oid(oidp);
	SYSCTL_XUNLOCK();
	return (oidp);
}

#if 0
/*
 * Rename an existing oid.
 */
static void
sysctl_rename_oid(struct ofp_sysctl_oid *oidp, const char *name)
{
	ssize_t len;
	char *newname;
	void *oldname;

	len = strlen(name);
	newname = malloc(len + 1, M_SYSCTLOID, M_WAITOK);
	bcopy(name, newname, len + 1);
	newname[len] = '\0';
	SYSCTL_XLOCK();
	oldname = (void *)(uintptr_t)(const void *)oidp->oid_name;
	oidp->oid_name = newname;
	SYSCTL_XUNLOCK();
	free(oldname, M_SYSCTLOID);
}

/*
 * Reparent an existing oid.
 */
static int
sysctl_move_oid(struct ofp_sysctl_oid *oid, struct ofp_sysctl_oid_list *parent)
{
	struct ofp_sysctl_oid *oidp;

	SYSCTL_XLOCK();
	if (oid->oid_parent == parent) {
		SYSCTL_XUNLOCK();
		return (0);
	}
	oidp = sysctl_find_oidname(oid->oid_name, parent);
	if (oidp != NULL) {
		SYSCTL_XUNLOCK();
		return (OFP_EEXIST);
	}
	sysctl_unregister_oid(oid);
	oid->oid_parent = parent;
	oid->oid_number = OFP_OID_AUTO;
	sysctl_register_oid(oid);
	SYSCTL_XUNLOCK();
	return (0);
}
#endif

/*
 * Register the kernel's oids on startup.
 */
SET_DECLARE(sysctl_set, struct ofp_sysctl_oid);

static void
sysctl_register_all(void *arg)
{
	struct ofp_sysctl_oid **oidp;
	(void)arg;

	odp_spinlock_init(&sysctlmemlock);
	SYSCTL_INIT();
	SYSCTL_XLOCK();
	SET_FOREACH(oidp, sysctl_set)
		sysctl_register_oid(*oidp);
	SYSCTL_XUNLOCK();
}

static int
sysctl_unregister_all(void *arg)
{
	int ret = 0;
	struct ofp_sysctl_oid **oidp;
	(void)arg;

	SYSCTL_XLOCK();
	SET_FOREACH(oidp, sysctl_set)
		if (sysctl_unregister_oid(*oidp))
			ret = -1;
	SYSCTL_XUNLOCK();
	return ret;
}

SYSINIT(sysctl, SI_SUB_KMEM, SI_ORDER_ANY, sysctl_register_all, 0);

/*
 * "Staff-functions"
 *
 * These functions implement a presently undocumented interface
 * used by the sysctl program to walk the tree, and get the type
 * so it can print the value.
 * This interface is under work and consideration, and should probably
 * be killed with a big axe by the first person who can find the time.
 * (be aware though, that the proper interface isn't as obvious as it
 * may seem, there are various conflicting requirements.
 *
 * {0,0}	printf the entire MIB-tree.
 * {0,1,...}	return the name of the "..." OID.
 * {0,2,...}	return the next OID.
 * {0,3}	return the OID of the name in "new"
 * {0,4,...}	return the kind & format info for the "..." OID.
 * {0,5,...}	return the description the "..." OID.
 */

#ifdef SYSCTL_DEBUG
#include <stdio.h>

static void
sysctl_sysctl_debug_dump_node(int fd, struct ofp_sysctl_oid_list *l, int i)
{
	int k;
	struct ofp_sysctl_oid *oidp;

	SYSCTL_ASSERT_XLOCKED();
	OFP_SLIST_FOREACH(oidp, l, oid_link) {

		for (k=0; k<i; k++)
			ofp_sendf(fd, " ");

		ofp_sendf(fd, "%d %s ", oidp->oid_number, oidp->oid_name);

		ofp_sendf(fd, "%c%c",
			oidp->oid_kind & OFP_CTLFLAG_RD ? 'R':' ',
			oidp->oid_kind & OFP_CTLFLAG_WR ? 'W':' ');

		/*if (oidp->oid_handler)
		  ofp_sendf(fd, " *Handler");*/

		switch (oidp->oid_kind & OFP_CTLTYPE) {
			case OFP_CTLTYPE_NODE:
				ofp_sendf(fd, " Node  (%s)\r\n", oidp->oid_descr);
				if (!oidp->oid_handler) {
					sysctl_sysctl_debug_dump_node(fd,
						oidp->oid_arg1, i+2);
				}
				break;
			case OFP_CTLTYPE_INT:
				ofp_sendf(fd, " int  (%s)\r\n", oidp->oid_descr);
				break;
			case OFP_CTLTYPE_UINT:
				ofp_sendf(fd, " u_int  (%s)\r\n", oidp->oid_descr);
				break;
			case OFP_CTLTYPE_LONG:
				ofp_sendf(fd, " long  (%s)\r\n", oidp->oid_descr);
				break;
			case OFP_CTLTYPE_ULONG:
				ofp_sendf(fd, " u_long  (%s)\r\n", oidp->oid_descr);
				break;
			case OFP_CTLTYPE_STRING:
				ofp_sendf(fd, " string  (%s)\r\n", oidp->oid_descr);
				break;
			case OFP_CTLTYPE_U64:
				ofp_sendf(fd, " uint64_t  (%s)\r\n", oidp->oid_descr);
				break;
			case OFP_CTLTYPE_S64:
				ofp_sendf(fd, " int64_t  (%s)\r\n", oidp->oid_descr);
				break;
			case OFP_CTLTYPE_OPAQUE:
				ofp_sendf(fd, " opaque/struct  (%s)\r\n", oidp->oid_descr);
				break;
		}
	}
}

static int
sysctl_sysctl_debug(OFP_SYSCTL_HANDLER_ARGS)
{
	(void)oidp;
	(void)arg1;
	(void)arg2;
	(void)req;
#if 0 /* HJo */
	int error;
	error = priv_check(req->td, PRIV_SYSCTL_DEBUG);
	if (error)
		return (error);
#endif
	SYSCTL_XLOCK();
	sysctl_sysctl_debug_dump_node(1, &sysctl__children, 0);
	SYSCTL_XUNLOCK();
	return (OFP_ENOENT);
}

OFP_SYSCTL_PROC(_sysctl, 0, debug, OFP_CTLTYPE_STRING|OFP_CTLFLAG_RD,
	0, 0, sysctl_sysctl_debug, "-", "");

#endif
#if 0
static int
sysctl_sysctl_name(OFP_SYSCTL_HANDLER_ARGS)
{
	int *name = (int *) arg1;
	u_int namelen = arg2;
	int error = 0;
	struct ofp_sysctl_oid *oid;
	struct ofp_sysctl_oid_list *lsp = &sysctl__children, *lsp2;
	char buf[10];
	(void) oidp;

	SYSCTL_XLOCK();
	while (namelen) {
		if (!lsp) {
			snprintf(buf,sizeof(buf),"%d",*name);
			if (req->oldidx)
				error = SYSCTL_OUT(req, ".", 1);
			if (!error)
				error = SYSCTL_OUT(req, buf, strlen(buf));
			if (error)
				goto out;
			namelen--;
			name++;
			continue;
		}
		lsp2 = 0;
		OFP_SLIST_FOREACH(oid, lsp, oid_link) {
			if (oid->oid_number != *name)
				continue;

			if (req->oldidx)
				error = SYSCTL_OUT(req, ".", 1);
			if (!error)
				error = SYSCTL_OUT(req, oid->oid_name,
					strlen(oid->oid_name));
			if (error)
				goto out;

			namelen--;
			name++;

			if ((oid->oid_kind & OFP_CTLTYPE) != OFP_CTLTYPE_NODE)
				break;

			if (oid->oid_handler)
				break;

			lsp2 = SYSCTL_CHILDREN(oid);
			break;
		}
		lsp = lsp2;
	}
	error = SYSCTL_OUT(req, "", 1);
 out:
	SYSCTL_XUNLOCK();
	return (error);
}
#endif
/*
 * XXXRW/JA: Shouldn't return name data for nodes that we don't permit in
 * capability mode.
 */
/*
static OFP_SYSCTL_NODE(_sysctl, 1, name, OFP_CTLFLAG_RD | OFP_CTLFLAG_CAPRD,
    sysctl_sysctl_name, "");
*/

static int
sysctl_sysctl_next_ls(struct ofp_sysctl_oid_list *lsp, int *name, u_int namelen,
	int *next, int *len, int level, struct ofp_sysctl_oid **oidpp)
{
	struct ofp_sysctl_oid *oidp;

	SYSCTL_ASSERT_XLOCKED();
	*len = level;
	OFP_SLIST_FOREACH(oidp, lsp, oid_link) {
		*next = oidp->oid_number;
		*oidpp = oidp;

		if (oidp->oid_kind & OFP_CTLFLAG_SKIP)
			continue;

		if (!namelen) {
			if ((oidp->oid_kind & OFP_CTLTYPE) != OFP_CTLTYPE_NODE)
				return (0);
			if (oidp->oid_handler)
				/* We really should call the handler here...*/
				return (0);
			lsp = SYSCTL_CHILDREN(oidp);
			if (!sysctl_sysctl_next_ls(lsp, 0, 0, next+1,
				len, level+1, oidpp))
				return (0);
			goto emptynode;
		}

		if (oidp->oid_number < *name)
			continue;

		if (oidp->oid_number > *name) {
			if ((oidp->oid_kind & OFP_CTLTYPE) != OFP_CTLTYPE_NODE)
				return (0);
			if (oidp->oid_handler)
				return (0);
			lsp = SYSCTL_CHILDREN(oidp);
			if (!sysctl_sysctl_next_ls(lsp, name+1, namelen-1,
				next+1, len, level+1, oidpp))
				return (0);
			goto next;
		}
		if ((oidp->oid_kind & OFP_CTLTYPE) != OFP_CTLTYPE_NODE)
			continue;

		if (oidp->oid_handler)
			continue;

		lsp = SYSCTL_CHILDREN(oidp);
		if (!sysctl_sysctl_next_ls(lsp, name+1, namelen-1, next+1,
			len, level+1, oidpp))
			return (0);
	next:
		namelen = 1;
	emptynode:
		*len = level;
	}
	return (1);
}

static int
sysctl_sysctl_next(OFP_SYSCTL_HANDLER_ARGS)
{
	int *name = (int *) arg1;
	u_int namelen = arg2;
	int i, j, error;
	struct ofp_sysctl_oid *oid;
	struct ofp_sysctl_oid_list *lsp = &sysctl__children;
	int newoid[OFP_CTL_MAXNAME];
	(void) oidp;

	SYSCTL_XLOCK();
	i = sysctl_sysctl_next_ls(lsp, name, namelen, newoid, &j, 1, &oid);
	OFP_INFO("name=%p namelen=%d i=%d", name, namelen, i);
	SYSCTL_XUNLOCK();
	if (i)
		return (OFP_ENOENT);
	error = SYSCTL_OUT(req, newoid, j * sizeof (int));
	return (error);
}

/*
 * XXXRW/JA: Shouldn't return next data for nodes that we don't permit in
 * capability mode.
 */
static OFP_SYSCTL_NODE(_sysctl, 2, next, OFP_CTLFLAG_RD | OFP_CTLFLAG_CAPRD,
    sysctl_sysctl_next, "");

static int
name2oid(char *name, int *oid, int *len, struct ofp_sysctl_oid **oidpp)
{
	int i;
	struct ofp_sysctl_oid *oidp;
	struct ofp_sysctl_oid_list *lsp = &sysctl__children;
	char *p;

	SYSCTL_ASSERT_XLOCKED();

	if (!*name)
		return (OFP_ENOENT);

	p = name + strlen(name) - 1 ;
	if (*p == '.')
		*p = '\0';

	*len = 0;

	for (p = name; *p && *p != '.'; p++)
		;
	i = *p;
	if (i == '.')
		*p = '\0';

	oidp = OFP_SLIST_FIRST(lsp);

	while (oidp && *len < OFP_CTL_MAXNAME) {
		if (strcmp(name, oidp->oid_name)) {
			oidp = OFP_SLIST_NEXT(oidp, oid_link);
			continue;
		}
		*oid++ = oidp->oid_number;
		(*len)++;

		if (!i) {
			if (oidpp)
				*oidpp = oidp;
			return (0);
		}

		if ((oidp->oid_kind & OFP_CTLTYPE) != OFP_CTLTYPE_NODE)
			break;

		if (oidp->oid_handler)
			break;

		lsp = SYSCTL_CHILDREN(oidp);
		oidp = OFP_SLIST_FIRST(lsp);
		name = p+1;
		for (p = name; *p && *p != '.'; p++)
				;
		i = *p;
		if (i == '.')
			*p = '\0';
	}
	return (OFP_ENOENT);
}

#define	MAXPATHLEN	1024

static int
sysctl_sysctl_name2oid(OFP_SYSCTL_HANDLER_ARGS)
{
	char *p;
	int error, oid[OFP_CTL_MAXNAME], len = 0;
	struct ofp_sysctl_oid *op = 0;
	(void)arg1;
	(void)arg2;
	(void)oidp;

	if (!req->newlen)
		return (OFP_ENOENT);
	if (req->newlen >= MAXPATHLEN)	/* XXX arbitrary, undocumented */
		return (OFP_ENAMETOOLONG);

	p = malloc(req->newlen+1, M_SYSCTL, M_WAITOK);

	error = SYSCTL_IN(req, p, req->newlen);
	if (error) {
		free(p, M_SYSCTL);
		return (error);
	}

	p [req->newlen] = '\0';

	SYSCTL_XLOCK();
	error = name2oid(p, oid, &len, &op);
	SYSCTL_XUNLOCK();

	free(p, M_SYSCTL);

	if (error)
		return (error);

	error = SYSCTL_OUT(req, oid, len * sizeof *oid);
	return (error);
}

/*
 * XXXRW/JA: Shouldn't return name2oid data for nodes that we don't permit in
 * capability mode.
 */
OFP_SYSCTL_PROC(_sysctl, 3, name2oid,
    OFP_CTLTYPE_INT | OFP_CTLFLAG_RW | OFP_CTLFLAG_ANYBODY | OFP_CTLFLAG_MPSAFE
    | OFP_CTLFLAG_CAPRW, 0, 0, sysctl_sysctl_name2oid, "I", "");

static int
sysctl_sysctl_oidfmt(OFP_SYSCTL_HANDLER_ARGS)
{
	struct ofp_sysctl_oid *oid;
	int error;
	(void)oidp;

	SYSCTL_XLOCK();
	error = ofp_sysctl_find_oid(arg1, arg2, &oid, NULL, req);
	if (error)
		goto out;

	if (oid->oid_fmt == NULL) {
		error = OFP_ENOENT;
		goto out;
	}
	error = SYSCTL_OUT(req, &oid->oid_kind, sizeof(oid->oid_kind));
	if (error)
		goto out;
	error = SYSCTL_OUT(req, oid->oid_fmt, strlen(oid->oid_fmt) + 1);
 out:
	SYSCTL_XUNLOCK();
	return (error);
}


static OFP_SYSCTL_NODE(_sysctl, 4, oidfmt, OFP_CTLFLAG_RD|OFP_CTLFLAG_MPSAFE|OFP_CTLFLAG_CAPRD,
    sysctl_sysctl_oidfmt, "");

static int
sysctl_sysctl_oiddescr(OFP_SYSCTL_HANDLER_ARGS)
{
	struct ofp_sysctl_oid *oid;
	int error;
	(void)oidp;

	SYSCTL_XLOCK();
	error = ofp_sysctl_find_oid(arg1, arg2, &oid, NULL, req);
	if (error)
		goto out;

	if (oid->oid_descr == NULL) {
		error = OFP_ENOENT;
		goto out;
	}
	error = SYSCTL_OUT(req, oid->oid_descr, strlen(oid->oid_descr) + 1);
 out:
	SYSCTL_XUNLOCK();
	return (error);
}

static OFP_SYSCTL_NODE(_sysctl, 5, oiddescr, OFP_CTLFLAG_RD|OFP_CTLFLAG_CAPRD,
    sysctl_sysctl_oiddescr, "");

/*
 * Default "handler" functions.
 */

/*
 * Handle an int, signed or unsigned.
 * Two cases:
 *     a variable:  point arg1 at it.
 *     a constant:  pass it in arg2.
 */

int
sysctl_handle_int(OFP_SYSCTL_HANDLER_ARGS)
{
	int tmpout, error = 0;
	(void)oidp;

	/*
	 * Attempt to get a coherent snapshot by making a copy of the data.
	 */
	if (arg1)
		tmpout = *(int *)arg1;
	else
		tmpout = arg2;
	error = SYSCTL_OUT(req, &tmpout, sizeof(int));

	if (error || !req->newptr)
		return (error);

	if (!arg1)
		error = OFP_EPERM;
	else
		error = SYSCTL_IN(req, arg1, sizeof(int));
	return (error);
}

/*
 * Based on on sysctl_handle_int() convert milliseconds into ticks.
 * Note: this is used by TCP.
 */

int
sysctl_msec_to_ticks(OFP_SYSCTL_HANDLER_ARGS)
{
	int error, s, tt;
	(void)arg2;

	tt = *(int *)arg1;
	s = (int)((int64_t)tt * 1000 / hz);

	error = sysctl_handle_int(oidp, &s, 0, req);
	if (error || !req->newptr)
		return (error);

	tt = (int)((int64_t)s * hz / 1000);
	if (tt < 1)
		return (OFP_EINVAL);

	*(int *)arg1 = tt;
	return (0);
}


/*
 * Handle a long, signed or unsigned.  arg1 points to it.
 */

int
sysctl_handle_long(OFP_SYSCTL_HANDLER_ARGS)
{
	int error = 0;
	long tmplong;
#ifdef SCTL_MASK32
	int tmpint;
#endif
	(void)arg2;
	(void)oidp;
	/*
	 * Attempt to get a coherent snapshot by making a copy of the data.
	 */
	if (!arg1)
		return (OFP_EINVAL);
	tmplong = *(long *)arg1;
#ifdef SCTL_MASK32
	if (req->flags & SCTL_MASK32) {
		tmpint = tmplong;
		error = SYSCTL_OUT(req, &tmpint, sizeof(int));
	} else
#endif
		error = SYSCTL_OUT(req, &tmplong, sizeof(long));

	if (error || !req->newptr)
		return (error);

#ifdef SCTL_MASK32
	if (req->flags & SCTL_MASK32) {
		error = SYSCTL_IN(req, &tmpint, sizeof(int));
		*(long *)arg1 = (long)tmpint;
	} else
#endif
		error = SYSCTL_IN(req, arg1, sizeof(long));
	return (error);
}

/*
 * Handle a 64 bit int, signed or unsigned.  arg1 points to it.
 */
int
sysctl_handle_64(OFP_SYSCTL_HANDLER_ARGS)
{
	int error = 0;
	uint64_t tmpout;
	(void)oidp;
	(void)arg2;

	/*
	 * Attempt to get a coherent snapshot by making a copy of the data.
	 */
	if (!arg1)
		return (OFP_EINVAL);
	tmpout = *(uint64_t *)arg1;
	error = SYSCTL_OUT(req, &tmpout, sizeof(uint64_t));

	if (error || !req->newptr)
		return (error);

	error = SYSCTL_IN(req, arg1, sizeof(uint64_t));
	return (error);
}

static size_t strlcpy(char *dst, const char *src, size_t size)
{
	strncpy(dst, src, size);
	dst[size-1] = 0;
	return strlen(src);
}

/*
 * Handle our generic '\0' terminated 'C' string.
 * Two cases:
 * 	a variable string:  point arg1 at it, arg2 is max length.
 * 	a constant string:  point arg1 at it, arg2 is zero.
 */

int
sysctl_handle_string(OFP_SYSCTL_HANDLER_ARGS)
{
	int error=0;
	char *tmparg;
	size_t outlen;
	(void)oidp;

	/*
	 * Attempt to get a coherent snapshot by copying to a
	 * temporary kernel buffer.
	 */
retry:
	outlen = strlen((char *)arg1)+1;
	tmparg = malloc(outlen, M_SYSCTLTMP, M_WAITOK);

	if (strlcpy(tmparg, (char *)arg1, outlen) >= outlen) {
		free(tmparg, M_SYSCTLTMP);
		goto retry;
	}

	error = SYSCTL_OUT(req, tmparg, outlen);
	free(tmparg, M_SYSCTLTMP);

	if (error || !req->newptr)
		return (error);

	if ((int)(req->newlen - req->newidx) >= arg2) {
		error = OFP_EINVAL;
	} else {
		arg2 = (req->newlen - req->newidx);
		error = SYSCTL_IN(req, arg1, arg2);
		((char *)arg1)[arg2] = '\0';
	}

	return (error);
}

/*
 * Handle any kind of opaque data.
 * arg1 points to it, arg2 is the size.
 */

int
sysctl_handle_opaque(OFP_SYSCTL_HANDLER_ARGS)
{
	int error, tries;
	int generation;
	struct ofp_sysctl_req req2;
	(void)oidp;

	/*
	 * Attempt to get a coherent snapshot, by using the thread
	 * pre-emption counter updated from within mi_switch() to
	 * determine if we were pre-empted during a bcopy() or
	 * copyout(). Make 3 attempts at doing this before giving up.
	 * If we encounter an error, stop immediately.
	 */
	tries = 0;
	req2 = *req;
retry:
	generation = odp_cpu_id();
	error = SYSCTL_OUT(req, arg1, arg2);
	if (error)
		return (error);
	tries++;
	if (generation != odp_cpu_id() && tries < 3) {
		*req = req2;
		goto retry;
	}

	error = SYSCTL_IN(req, arg1, arg2);

	return (error);
}

/*
 * Transfer functions to/from kernel space.
 * XXX: rather untested at this point
 */
static int
sysctl_old_kernel(struct ofp_sysctl_req *req, const void *p, size_t l)
{
	size_t i = 0;

	if (req->oldptr) {
		i = l;
		if (req->oldlen <= req->oldidx)
			i = 0;
		else
			if (i > req->oldlen - req->oldidx)
				i = req->oldlen - req->oldidx;
		if (i > 0)
			bcopy(p, (char *)req->oldptr + req->oldidx, i);
	}
	req->oldidx += l;
	if (req->oldptr && i != l)
		return (OFP_ENOMEM);
	return (0);
}

static int
sysctl_new_kernel(struct ofp_sysctl_req *req, void *p, size_t l)
{
	if (!req->newptr)
		return (0);
	if (req->newlen - req->newidx < l)
		return (OFP_EINVAL);
	bcopy((const char *)req->newptr + req->newidx, p, l);
	req->newidx += l;
	return (0);
}

int
ofp_kernel_sysctl(struct thread *td, const int *name, u_int namelen, void *old,
    size_t *oldlenp, const void *new, size_t newlen, size_t *retval, int flags)
{
	int error = 0;
	struct ofp_sysctl_req req;

	bzero(&req, sizeof req);

	req.td = td;
	req.flags = flags;

	if (oldlenp) {
		req.oldlen = *oldlenp;
	}
	req.validlen = req.oldlen;

	if (old) {
		req.oldptr= old;
	}

	if (new != NULL) {
		req.newlen = newlen;
		req.newptr = new;
	}

	req.oldfunc = sysctl_old_kernel;
	req.newfunc = sysctl_new_kernel;
	req.lock = REQ_UNWIRED;

	SYSCTL_XLOCK();
	error = sysctl_root(0, (void *)(intptr_t)name, namelen, &req);
	SYSCTL_XUNLOCK();

#if 0	/* HJo: FIX */
	if (req.lock == REQ_WIRED && req.validlen > 0)
		vsunlock(req.oldptr, req.validlen);
#endif
	if (error && error != OFP_ENOMEM)
		return (error);

	if (retval) {
		if (req.oldptr && req.oldidx > req.validlen)
			*retval = req.validlen;
		else
			*retval = req.oldidx;
	}
	return (error);
}

static int
kernel_sysctlbyname(struct thread *td, const char *name, void *old, size_t *oldlenp,
    const void *new, size_t newlen, size_t *retval, int flags)
{
        int oid[OFP_CTL_MAXNAME];
        size_t oidlen, plen;
	int error;

	oid[0] = 0;		/* sysctl internal magic */
	oid[1] = 3;		/* name2oid */
	oidlen = sizeof(oid);

	error = ofp_kernel_sysctl(td, oid, 2, oid, &oidlen,
	    (const void *)name, strlen(name), &plen, flags);
	if (error)
		return (error);

	error = ofp_kernel_sysctl(td, oid, plen / sizeof(int), old, oldlenp,
	    new, newlen, retval, flags);
	return (error);
}

#if 0
/*
 * Transfer function to/from user space.
 */
static int
sysctl_old_user(struct ofp_sysctl_req *req, const void *p, size_t l)
{
	size_t i, len, origidx;
	int error;

	origidx = req->oldidx;
	req->oldidx += l;
	if (req->oldptr == NULL)
		return (0);
	i = l;
	len = req->validlen;
	if (len <= origidx)
		i = 0;
	else {
		if (i > len - origidx)
			i = len - origidx;
		error = copyout(p, (char *)req->oldptr + origidx, i);
		if (error != 0)
			return (error);
	}
	if (i < l)
		return (OFP_ENOMEM);
	return (0);
}

static int
sysctl_new_user(struct ofp_sysctl_req *req, void *p, size_t l)
{
	int error = 0;

	if (!req->newptr)
		return (0);
	if (req->newlen - req->newidx < l)
		return (OFP_EINVAL);
	/* HJo
	WITNESS_WARN(WARN_GIANTOK | WARN_SLEEPOK, NULL,
	    "sysctl_new_user()");
	*/
	error = copyin((const char *)req->newptr + req->newidx, p, l);
	req->newidx += l;
	return (error);
}

/*
 * Wire the user space destination buffer.  If set to a value greater than
 * zero, the len parameter limits the maximum amount of wired memory.
 */
static int
sysctl_wire_old_buffer(struct ofp_sysctl_req *req, size_t len)
{
	size_t wiredlen;

	wiredlen = (len > 0 && len < req->oldlen) ? len : req->oldlen;

	if (req->lock != REQ_WIRED && req->oldptr &&
	    req->oldfunc == sysctl_old_user) {
#if 0 /* HJo */
		if (wiredlen != 0) {
			int ret = 0;
			ret = vslock(req->oldptr, wiredlen);
			if (ret != 0) {
				if (ret != OFP_ENOMEM)
					return (ret);
				wiredlen = 0;
			}
		}
#endif
		req->lock = REQ_WIRED;
		req->validlen = wiredlen;
	}
	return (0);
}
#endif

int
ofp_sysctl_find_oid(const int *name, u_int namelen, struct ofp_sysctl_oid **noid,
		      int *nindx, struct ofp_sysctl_req *req)
{
	struct ofp_sysctl_oid_list *lsp;
	struct ofp_sysctl_oid *oid;
	int indx;
	(void)req;

	SYSCTL_ASSERT_XLOCKED();
	lsp = &sysctl__children;
	indx = 0;
	while (indx < OFP_CTL_MAXNAME) {
		OFP_SLIST_FOREACH(oid, lsp, oid_link) {
			if (oid->oid_number == name[indx])
				break;
		}
		if (oid == NULL)
			return (OFP_ENOENT);

		indx++;
		if ((oid->oid_kind & OFP_CTLTYPE) == OFP_CTLTYPE_NODE) {
			if (oid->oid_handler != NULL || indx == (int)namelen) {
				*noid = oid;
				if (nindx != NULL)
					*nindx = indx;
				KASSERT((oid->oid_kind & OFP_CTLFLAG_DYING) == 0,
				    ("%s found DYING node %p", __func__, oid));
				return (0);
			}
			lsp = SYSCTL_CHILDREN(oid);
		} else if (indx == (int)namelen) {
			*noid = oid;
			if (nindx != NULL)
				*nindx = indx;
			KASSERT((oid->oid_kind & OFP_CTLFLAG_DYING) == 0,
			    ("%s found DYING node %p", __func__, oid));
			return (0);
		} else {
			return (OFP_ENOTDIR);
		}
	}
	return (OFP_ENOENT);
}

/*
 * Traverse our tree, and find the right node, execute whatever it points
 * to, and return the resulting error code.
 */

static int
sysctl_root(OFP_SYSCTL_HANDLER_ARGS)
{
	struct ofp_sysctl_oid *oid;
	int error, indx;
	(void)oidp;

	SYSCTL_ASSERT_XLOCKED();

	error = ofp_sysctl_find_oid(arg1, arg2, &oid, &indx, req);
	if (error)
		return (error);

	if ((oid->oid_kind & OFP_CTLTYPE) == OFP_CTLTYPE_NODE) {
		/*
		 * You can't call a sysctl when it's a node, but has
		 * no handler.  Inform the user that it's a node.
		 * The indx may or may not be the same as namelen.
		 */
		if (oid->oid_handler == NULL)
			return (OFP_EISDIR);
	}

	/* Is this sysctl writable? */
	if (req->newptr && !(oid->oid_kind & OFP_CTLFLAG_WR))
		return (OFP_EPERM);

	//KASSERT(req->td != NULL, ("sysctl_root(): req->td == NULL"));

#ifdef CAPABILITY_MODE
	/*
	 * If the process is in capability mode, then don't permit reading or
	 * writing unless specifically granted for the node.
	 */
	if (IN_CAPABILITY_MODE(req->td)) {
		if (req->oldptr && !(oid->oid_kind & OFP_CTLFLAG_CAPRD))
			return (OFP_EPERM);
		if (req->newptr && !(oid->oid_kind & OFP_CTLFLAG_CAPWR))
			return (OFP_EPERM);
	}
#endif

#if 0 /* HJo */
	/* Is this sysctl sensitive to securelevels? */
	if (req->newptr && (oid->oid_kind & OFP_CTLFLAG_SECURE)) {
		lvl = (oid->oid_kind & OFP_CTLMASK_SECURE) >> CTLSHIFT_SECURE;
		error = securelevel_gt(req->td->td_ucred, lvl);
		if (error)
			return (error);
	}

	/* Is this sysctl writable by only privileged users? */
	if (req->newptr && !(oid->oid_kind & OFP_CTLFLAG_ANYBODY)) {
		int priv;

		if (oid->oid_kind & OFP_CTLFLAG_PRISON)
			priv = PRIV_SYSCTL_WRITEJAIL;
		else
			priv = PRIV_SYSCTL_WRITE;
		error = priv_check(req->td, priv);
		if (error)
			return (error);
	}
#endif

	if (!oid->oid_handler)
		return (OFP_EINVAL);

	if ((oid->oid_kind & OFP_CTLTYPE) == OFP_CTLTYPE_NODE) {
		arg1 = (int *)arg1 + indx;
		arg2 -= indx;
	} else {
		arg1 = oid->oid_arg1;
		arg2 = oid->oid_arg2;
	}
	oid->oid_running++;
	SYSCTL_XUNLOCK();

#if 0 /* HJo */
	if (!(oid->oid_kind & OFP_CTLFLAG_MPSAFE))
		mtx_lock(&Giant);
#endif
	error = oid->oid_handler(oid, arg1, arg2, req);
#if 0 /* HJo */
	if (!(oid->oid_kind & OFP_CTLFLAG_MPSAFE))
		mtx_unlock(&Giant);
#endif
#ifndef UINET
	/* HJo KFAIL_POINT_ERROR(_debug_fail_point, sysctl_running, error); */
#endif

	SYSCTL_XLOCK();
	oid->oid_running--;
	if (oid->oid_running == 0 && (oid->oid_kind & OFP_CTLFLAG_DYING) != 0)
		ofp_wakeup(&oid->oid_running);
	return (error);
}

#if 0
/*
 * This is used from various compatibility syscalls too.  That's why name
 * must be in kernel space.
 */
static int
userland_sysctl(struct thread *td, const int *name, u_int namelen, void *old,
    size_t *oldlenp, int inkernel, const void *new, size_t newlen, size_t *retval,
    int flags)
{
	int error = 0;
	struct ofp_sysctl_req req;

	bzero(&req, sizeof req);

	req.td = td;
	req.flags = flags;

	if (oldlenp) {
		if (inkernel) {
			req.oldlen = *oldlenp;
		} else {
			error = copyin(oldlenp, &req.oldlen, sizeof(*oldlenp));
			if (error)
				return (error);
		}
	}
	req.validlen = req.oldlen;

	if (old) {
		/* HJo
		if (!useracc(old, req.oldlen, VM_PROT_WRITE))
			return (OFP_EFAULT);
		*/
		req.oldptr= old;
	}

	if (new != NULL) {
		/* HJo
		if (!useracc(new, newlen, VM_PROT_READ))
			return (OFP_EFAULT);
		*/
		req.newlen = newlen;
		req.newptr = new;
	}

	req.oldfunc = sysctl_old_user;
	req.newfunc = sysctl_new_user;
	req.lock = REQ_UNWIRED;

#ifdef KTRACE
	if (KTRPOINT(curthread, KTR_SYSCTL))
		ktrsysctl(name, namelen);
#endif
#if 0 /* HJo */
	if (req.oldlen > PAGE_SIZE) {
		memlocked = 1;
		sx_xlock(&sysctlmemlock);
	} else
		memlocked = 0;
#endif

	for (;;) {
		req.oldidx = 0;
		req.newidx = 0;
		SYSCTL_XLOCK();
		error = sysctl_root(0, (void *)(intptr_t)name, namelen, &req);
		SYSCTL_XUNLOCK();
		if (error != OFP_EAGAIN)
			break;
		/* HJo kern_yield(PRI_USER); */
	}
#if 0 /* HJo */
	if (req.lock == REQ_WIRED && req.validlen > 0)
		vsunlock(req.oldptr, req.validlen);
	if (memlocked)
		sx_xunlock(&sysctlmemlock);
#endif
	if (error && error != OFP_ENOMEM)
		return (error);

	if (retval) {
		if (req.oldptr && req.oldidx > req.validlen)
			*retval = req.validlen;
		else
			*retval = req.oldidx;
	}
	return (error);
}

/*
 * Drain into a sysctl struct.  The user buffer should be wired if a page
 * fault would cause issue.
 */
static int
sbuf_sysctl_drain(void *arg, const char *data, int len)
{
	struct ofp_sysctl_req *req = arg;
	int error;

	error = SYSCTL_OUT(req, data, len);
	KASSERT(error >= 0, ("Got unexpected negative value %d", error));
	return (error == 0 ? len : -error);
}

struct sbuf *
sbuf_new_for_sysctl(struct sbuf *s, char *buf, int length,
		    struct ofp_sysctl_req *req)
{

	s = sbuf_new(s, buf, length, SBUF_FIXEDLEN);
	sbuf_set_drain(s, sbuf_sysctl_drain, req);
	return (s);
}
#endif

//extern void *__start_set_sysctl_set;
//extern void *__stop_set_sysctl_set;

void
ofp_register_sysctls(void)
{
	sysctl_register_all(NULL);
	sysctl_sysctl_debug(NULL, NULL,	0, NULL);
}

int
ofp_unregister_sysctls(void)
{
	return sysctl_unregister_all(NULL);
}

void
ofp_sysctl_write_tree(int fd)
{
	SYSCTL_XLOCK();
	sysctl_sysctl_debug_dump_node(fd, &sysctl__children, 0);
	SYSCTL_XUNLOCK();
}

int
ofp_sysctl(const char *name, void *old, size_t *oldlenp,
	     const void *new, size_t newlen, size_t *retval)
{
	return kernel_sysctlbyname(NULL, name, old, oldlenp,
				   new, newlen, retval, 0);
}
