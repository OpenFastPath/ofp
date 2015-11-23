/*-
 * Copyright (c) 2014 ENEA Software AB
 * Copyright (c) 2014 Nokia
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


void f_arp(struct cli_conn *conn, const char *s)
{
	(void)s;

	ofp_show_routes(conn->fd, OFP_SHOW_ARP);
	ofp_arp_show_saved_packets(conn->fd);
	sendcrlf(conn);
}

void f_arp_flush(struct cli_conn *conn, const char *s)
{
	(void)s;

	ofp_arp_init_tables();
	sendcrlf(conn);
}

void f_arp_cleanup(struct cli_conn *conn, const char *s)
{
	int cli = 1;

	(void)s;

	ofp_arp_age_cb(&cli);
	sendcrlf(conn);
}

void f_help_arp(struct cli_conn *conn, const char *s)
{
	(void)s;
	ofp_sendf(conn->fd,
		"Show arp table:\r\n"
		"  arp\r\n\r\n");

	ofp_sendf(conn->fd,
		"Flush arp table:\r\n"
		"  arp flush\r\n\r\n");

	ofp_sendf(conn->fd,
		"Clean old entries from arp table:\r\n"
		"  arp cleanup\r\n\r\n");

	ofp_sendf(conn->fd,
		"Show (this) help:\r\n"
		"  arp help\r\n\r\n");

	sendcrlf(conn);
}
