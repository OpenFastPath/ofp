/*-
 * Copyright (c) 2015 Nokia Solutions and Networks
 * Copyright (c) 2015 ENEA Software AB
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ofpi_log.h"
#include "ofpi_cli.h"
#include "ofpi_route.h"
#include "ofpi_arp.h"
#include "ofpi_util.h"
#include "ofpi_sysctl.h"


void f_sysctl_dump(struct cli_conn *conn, const char *s)
{
	(void)s;
	ofp_sysctl_write_tree(conn->fd);
	sendcrlf(conn);
}

void f_sysctl_read(struct cli_conn *conn, const char *s)
{
	int oid[OFP_CTL_MAXNAME];
	size_t oidlen;
	uint64_t old[32];
	size_t oldlen;
	size_t retval, plen;
	int error;
	int slen;
	char str[128], *p;
	struct ofp_sysctl_oid *noid;
	int nindx;
	struct ofp_sysctl_oid_list *l;

	strncpy(str, s, sizeof(str));
	str[sizeof(str)-1] = 0;
	p = strchr(str, ' ');
	if (p)
		*p = 0;
	slen = strlen(str);

	if (slen == 0) {
		l = &sysctl__children;
		goto err;
	}

	if (!strncmp(s, "-a", 2)) {
		ofp_sysctl_write_tree(conn->fd);
		return;
	}

	oid[0] = 0;		/* sysctl internal magic */
	oid[1] = 3;		/* name2oid */
	oidlen = sizeof(oid);

	error = ofp_kernel_sysctl(NULL, oid, 2, oid, &oidlen,
				    (const void *)str, slen, &plen, 0);
	if (error) {
		ofp_sendf(conn->fd, "Not valid string: '%s'\r\n", str);
		str[0] = 0;
		l = &sysctl__children;
		goto err;
	}

	plen /= sizeof(int);

	error = ofp_sysctl_find_oid(oid, plen, &noid, &nindx, NULL);
	if (error)
		return;

	if ((noid->oid_kind & OFP_CTLTYPE) == OFP_CTLTYPE_NODE) {
		ofp_sendf(conn->fd, "Not a variable.\r\n");
		l = noid->oid_arg1;
		goto err;
	}

	oldlen = sizeof(old) - 1;

	error = ofp_kernel_sysctl(NULL, oid, plen, old, &oldlen,
				    NULL, 0, &retval, 0);

	if (error) {
		ofp_sendf(conn->fd, "Cannot access: '%s'", str);
		sendcrlf(conn);
		return;
	}

	ofp_sendf(conn->fd, "%s = ", str);

	switch (noid->oid_kind & OFP_CTLTYPE) {
	case OFP_CTLTYPE_INT: {
		int *r = (int *)old;
		ofp_sendf(conn->fd, "%d\r\n", *r);
		break;
	}
	case OFP_CTLTYPE_UINT: {
		unsigned int *r = (unsigned int *)old;
		ofp_sendf(conn->fd, "%u\r\n", *r);
		break;
	}
	case OFP_CTLTYPE_LONG: {
		long int *r = (long int *)old;
		ofp_sendf(conn->fd, "%ld\r\n", *r);
		break;
	}
	case OFP_CTLTYPE_ULONG: {
		unsigned long *r = (unsigned long *)old;
		ofp_sendf(conn->fd, "%lu\r\n", *r);
		break;
	}
	case OFP_CTLTYPE_STRING: {
		char *r = (char *)old;
		r[oldlen] = 0;
		ofp_sendf(conn->fd, "%s\r\n", r);
		break;
	}
	case OFP_CTLTYPE_U64: {
		uint64_t *r = (uint64_t *)old;
		ofp_sendf(conn->fd, "%lu\r\n", *r);
		break;
	}
	case OFP_CTLTYPE_S64: {
		int64_t *r = (int64_t *)old;
		ofp_sendf(conn->fd, "%ld\r\n", *r);
		break;
	}
	case OFP_CTLTYPE_OPAQUE: {
		unsigned int i;
		unsigned char *r = (unsigned char *)old;
		for (i = 0; i < oldlen; i++)
			ofp_sendf(conn->fd, " %02x", r[i]);
		ofp_sendf(conn->fd, "\r\n");
		break;
	}
	default: ofp_sendf(conn->fd, "unknown type\r\n");
	}

	sendcrlf(conn);
	return;

err:
	ofp_sendf(conn->fd, "Alternatives:\r\n");

	struct ofp_sysctl_oid *oidp;
	OFP_SLIST_FOREACH(oidp, l, oid_link) {
		ofp_sendf(conn->fd, "  %s%s%s (%s)\r\n",
			    str, str[0] ? "." : "",
			    oidp->oid_name, oidp->oid_descr);
	}

	sendcrlf(conn);
}

void f_sysctl_write(struct cli_conn *conn, const char *s)
{
	int oid[OFP_CTL_MAXNAME];
	size_t oidlen;
	uint64_t new[32];
	size_t newlen;
	size_t retval, plen;
	int error;
	int slen;
	char str[128], *p, *p1;
	struct ofp_sysctl_oid *noid;
	int nindx;
	struct ofp_sysctl_oid_list *l = &sysctl__children;

	strncpy(str, s, sizeof(str));
	str[sizeof(str)-1] = 0;
	p = strchr(str, ' ');
	if (p) {
		*p = 0;
		p++;

		p1 = strchr(p, ' ');
		if (p1)
			*p1 = 0;
	}

	slen = strlen(str);

	if (slen == 0) {
		l = &sysctl__children;
		goto err;
	}

	oid[0] = 0;		/* sysctl internal magic */
	oid[1] = 3;		/* name2oid */
	oidlen = sizeof(oid);

	error = ofp_kernel_sysctl(NULL, oid, 2, oid, &oidlen,
				    (const void *)str, slen, &plen, 0);
	if (error) {
		ofp_sendf(conn->fd, "Not valid string: '%s'\r\n", str);
		str[0] = 0;
		goto err;
	}

	plen /= sizeof(int);

	error = ofp_sysctl_find_oid(oid, plen, &noid, &nindx, NULL);
	if (error)
		return;

	if ((noid->oid_kind & OFP_CTLTYPE) == OFP_CTLTYPE_NODE) {
		ofp_sendf(conn->fd, "Not a variable.\r\n");
		l = noid->oid_arg1;
		goto err;
	}

	switch (noid->oid_kind & OFP_CTLTYPE) {
	case OFP_CTLTYPE_UINT:
	case OFP_CTLTYPE_INT: {
		int *r = (int *)new;
		*r = atoi(p);
		newlen = sizeof(int);
		break;
	}
	case OFP_CTLTYPE_ULONG:
	case OFP_CTLTYPE_LONG: {
		long int *r = (long int *)new;
		*r = atol(p);
		newlen = sizeof(long int);
		break;
	}
	case OFP_CTLTYPE_STRING: {
		newlen = strlen(p);
		if (newlen > sizeof(new) - 1)
			newlen = sizeof(new) - 1;
		p[newlen] = 0;
		memcpy(new, p, newlen+1);
		break;
	}
	case OFP_CTLTYPE_S64:
	case OFP_CTLTYPE_U64: {
		int64_t *r = (int64_t *)new;
		*r = atoll(p);
		newlen = sizeof(int64_t);
		break;
	}
	default: ofp_sendf(conn->fd, "unsupported type for writing\r\n");
		goto err;
	}

	error = ofp_kernel_sysctl(NULL, oid, plen, NULL, NULL,
				    new, newlen, &retval, 0);

	if (error) {
		ofp_sendf(conn->fd, "Cannot write: '%s'", str);
		sendcrlf(conn);
		return;
	}

	sendcrlf(conn);
	return;

err:
	ofp_sendf(conn->fd, "Alternatives:\r\n");

	struct ofp_sysctl_oid *oidp;
	OFP_SLIST_FOREACH(oidp, l, oid_link) {
		ofp_sendf(conn->fd, "  %s%s%s\r\n",
			    str, str[0] ? "." : "", oidp->oid_name);
	}

	sendcrlf(conn);
}
