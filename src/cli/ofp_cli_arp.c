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
#ifdef OFP_USE_LIBCK
	(void)cli;
	/* Aging not defined in arp ck impl */
#else
	ofp_arp_age_cb(&cli);
#endif
	sendcrlf(conn);
}

void f_arp_add(struct cli_conn *conn, const char *s)
{
	int a, b, c, d, e, f, g, h, i, j;
	char dev[16];
	int port, vlan;
	struct ofp_ifnet *itf;
	uint32_t ipv4_addr;
	uint8_t mac[OFP_ETHER_ADDR_LEN];

	if (sscanf(s, " %d.%d.%d.%d %x:%x:%x:%x:%x:%x %s",
		   &a, &b, &c, &d, &e, &f, &g, &h, &i, &j, dev) != 11)
		return;

	ipv4_addr = odp_cpu_to_be_32((a << 24) | (b << 16) | (c << 8) | d);
	mac[0] = e;
	mac[1] = f;
	mac[2] = g;
	mac[3] = h;
	mac[4] = i;
	mac[5] = j;

	port = ofp_name_to_port_vlan(dev, &vlan);
	if (port == -1 || !PHYS_PORT(port)) {
		ofp_sendf(conn->fd, "Invalid device name.\r\n");
		sendcrlf(conn);
		return;
	}

	itf = ofp_get_ifnet(port, vlan);
	if (itf == NULL) {
		ofp_sendf(conn->fd, "Device not found.\r\n");
		sendcrlf(conn);
		return;
	}

	if (ofp_arp_ipv4_insert(ipv4_addr, mac, itf)) {
		ofp_sendf(conn->fd, "Failed to insert arp entry.\r\n");
		sendcrlf(conn);
		return;
	}

	sendcrlf(conn);
}

void f_help_arp(struct cli_conn *conn, const char *s)
{
	(void)s;
	ofp_sendf(conn->fd,
		"Show arp table:\r\n"
		"  arp\r\n\r\n");

	ofp_sendf(conn->fd,
		  "Add arp entry:\r\n"
		  "  arp set IP4ADDR HWADDR dev DEV\r\n"
		  "    IP4ADDR: ip address in a.b.c.d format\r\n"
		  "    HWADDR: mac address in a:b:c:d:e:f format\r\n"
		  "    DEV: ethernet interface name\r\n"
		  "  Example:\r\n"
		  "    arp set 192.168.0.20 90:1b:0e:9a:cf:fc dev fp0\r\n\r\n");

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
