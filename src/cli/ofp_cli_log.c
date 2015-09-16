/*-
 * Copyright (c) 2014 ENEA Software AB
 * Copyright (c) 2014 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ofpi_cli.h"
#include "ofpi_log.h"
#include "ofpi_util.h"

const char *loglevel_descript[] = {
	"abort",
	"error",
	"info",
	"debug"
};

/* loglevel help */
/* help loglevel */
void f_help_loglevel(struct cli_conn *conn, const char *s)
{
	(void)s;

	ofp_sendf(conn->fd, "Show log level\r\n"
		"  loglevel show\r\n");
	ofp_sendf(conn->fd, "Set log level\r\n"
		"  loglevel set <debug|info|error|abort>\r\n"
		"  Example: loglevel set debug\r\n");
	ofp_sendf(conn->fd, "Show log level help (this help)\r\n"
		"  loglevel help\r\n");

	sendcrlf(conn);
}

/* loglevel */
/* loglevel show */
void f_loglevel_show(struct cli_conn *conn, const char *s)
{
	(void)s;
	ofp_sendf(conn->fd, "Log level: %s\r\n",
		loglevel_descript[ofp_loglevel]);

	sendcrlf(conn);
}

/* loglevel <debug|info|error|abort> */
void f_loglevel(struct cli_conn *conn, const char *s)
{
	int i;

	for (i = 0; i < OFP_LOG_MAX_LEVEL; i++) {
		if (strncmp(loglevel_descript[i], s,
			strlen(loglevel_descript[i])) == 0) {
			ofp_loglevel = i;
			sendcrlf(conn);
			return;
		}
	}

	ofp_sendf(conn->fd, "Invalid value!\r\nUsage:\r\n");

	f_help_loglevel(conn, NULL);
}
