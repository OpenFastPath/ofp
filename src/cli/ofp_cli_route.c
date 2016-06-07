/*-
 * Copyright (c) 2014 ENEA Software AB
 * Copyright (c) 2014 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <odp.h>

#include "ofpi_cli.h"
#include "ofpi_route.h"
#include "ofpi_util.h"
#include "ofpi_log.h"

/* route show */
void f_route_show(struct cli_conn *conn, const char *s)
{
	(void)s;

	ofp_show_routes(conn->fd, OFP_SHOW_ROUTES);

	sendcrlf(conn);
}

/* route add IP4NET gw IP4ADDR dev DEV */
/* route -A inet4 add IP4NET gw IP4ADDR dev DEV */
void f_route_add(struct cli_conn *conn, const char *s)
{
	uint32_t gwaddr, destaddr;
	int a, b, c, d, e, f, g, h, port, mlen, vlan;
	char dev[16];

	if (sscanf(s, "%d.%d.%d.%d/%d %d.%d.%d.%d %s",
		   &a, &b, &c, &d, &mlen,
		   &e, &f, &g, &h, dev) != 10)
		return;
	destaddr = odp_cpu_to_be_32((a << 24) | (b << 16) | (c << 8) | d);
	gwaddr = odp_cpu_to_be_32((e << 24) | (f << 16) | (g << 8) | h);

	port = ofp_name_to_port_vlan(dev, &vlan);
	if (port < 0 || port >= ofp_get_num_ports()) {
		ofp_sendf(conn->fd, "Invalid port!\r\n");
		sendcrlf(conn);
		return;
	}

	ofp_set_route_params(OFP_ROUTE_ADD, 0 /*vrf*/, vlan, port,
			     destaddr, mlen, gwaddr, OFP_RTF_GATEWAY);

	sendcrlf(conn);
}

/* route add vrf NUMBER IP4NET gw IP4ADDR dev DEV */
/* route -A inet4 add vrf NUMBER IP4NET gw IP4ADDR dev DEV */
void f_route_add_vrf(struct cli_conn *conn, const char *s)
{
	uint32_t gwaddr, destaddr;
	int a, b, c, d, e, f, g, h, port, mlen, vrf, vlan;
	char dev[16];

	if (sscanf(s, "%d %d.%d.%d.%d/%d %d.%d.%d.%d %s",
		   &vrf, &a, &b, &c, &d, &mlen,
		   &e, &f, &g, &h, dev) != 11)
		return;
	destaddr = odp_cpu_to_be_32((a << 24) | (b << 16) | (c << 8) | d);
	gwaddr = odp_cpu_to_be_32((e << 24) | (f << 16) | (g << 8) | h);

	port = ofp_name_to_port_vlan(dev, &vlan);
	if (port < 0 || port >= ofp_get_num_ports()) {
		ofp_sendf(conn->fd, "Invalid port!\r\n");
		sendcrlf(conn);
		return;
	}

	ofp_set_route_params(OFP_ROUTE_ADD, vrf, vlan, port, destaddr,
			     mlen, gwaddr, OFP_RTF_GATEWAY);

	sendcrlf(conn);
}

/* route -A inet6 add IP6NET gw IP6ADDR dev DEV */
#ifdef INET6
void f_route_add_v6(struct cli_conn *conn, const char *s)
{
	uint8_t dst6[16];
	uint8_t gw6[16];
	int port, vlan, mlen;
	const char *tk;
	const char *tk_end;
	const char *last;

	last = s + strlen(s);

/* get IP6NET address*/
	tk = s;
	tk_end = strstr(tk, "/");
	if (!tk_end) {
		ofp_sendf(conn->fd, "Invalid IP6NET\r\n");
		sendcrlf(conn);
		return;
	}

	if (!ip6addr_get(tk, tk_end - tk, dst6)) {
		ofp_sendf(conn->fd, "Invalid IP6NET\r\n");
		sendcrlf(conn);
		return;
	}

/* get IP6NET prefix len*/
	tk = tk_end + 1;
	if (tk >= last) {
		ofp_sendf(conn->fd, "Invalid IP6NET\r\n");
		sendcrlf(conn);
		return;
	}

	tk_end = strstr(tk, " ");
	if (!tk_end || (tk == tk_end)) {
		ofp_sendf(conn->fd, "Invalid IP6NET\r\n");
		sendcrlf(conn);
		return;
	}

	mlen = atoi(tk);

/* get IP6ADDR */
	tk = tk_end + 1;
	if (tk >= last) {
		ofp_sendf(conn->fd, "Invalid IP6NET\r\n");
		sendcrlf(conn);
		return;
	}
	tk_end = strstr(tk, " ");
	if (tk_end == NULL) {
		ofp_sendf(conn->fd, "Invalid IP6ADDR\r\n");
		sendcrlf(conn);
		return;
	}

	if (!ip6addr_get(tk, tk_end - tk, gw6)) {
		ofp_sendf(conn->fd, "Invalid IP6NET\r\n");
		sendcrlf(conn);
		return;
	}

/* get DEV */
	tk = tk_end + 1;
	if (tk >= last) {
		ofp_sendf(conn->fd, "Invalid DEV\r\n");
		sendcrlf(conn);
		return;
	}
	tk_end = last;

	port = ofp_name_to_port_vlan(tk, &vlan);
	if (port < 0 || port >= ofp_get_num_ports()) {
		ofp_sendf(conn->fd, "Invalid port!\r\n");
		sendcrlf(conn);
		return;
	}

	ofp_set_route6_params(OFP_ROUTE6_ADD, 0 /*vrf*/, vlan, port, dst6,
			      mlen, gw6, OFP_RTF_GATEWAY);

	sendcrlf(conn);
}
#endif /* INET6*/

/* route delete IP4NET */
/* route -A inet4 delete IP4NET */
void f_route_del(struct cli_conn *conn, const char *s)
{
	uint32_t destaddr;
	int a, b, c, d, mlen;

	if (sscanf(s, "%d.%d.%d.%d/%d",
		&a, &b, &c, &d, &mlen) != 5)
		return;
	destaddr = odp_cpu_to_be_32((a << 24) | (b << 16) | (c << 8) | d);

	ofp_set_route_params(OFP_ROUTE_DEL, 0 /*vrf*/, 0 /*vlan*/, 0 /*port*/,
			     destaddr, mlen, 0 /*gw*/, 0 /*flags*/);

	sendcrlf(conn);
}

/* route delete vrf NUMBER IP4NET */
/* route -A inet4 delete vrf NUMBER IP4NET */
void f_route_del_vrf(struct cli_conn *conn, const char *s)
{
	uint32_t destaddr;
	int a, b, c, d, mlen, vrf;

	if (sscanf(s, "%d %d.%d.%d.%d/%d",
		&vrf, &a, &b, &c, &d, &mlen) != 6)
		return;
	destaddr = odp_cpu_to_be_32((a << 24) | (b << 16) | (c << 8) | d);

	ofp_set_route_params(OFP_ROUTE_DEL, vrf, 0 /*vlan*/, 0 /*port*/,
			     destaddr, mlen, 0 /*gw*/, 0 /*flags*/);

	sendcrlf(conn);
}

/* route -A inet6 delete IP6NET */
#ifdef INET6
void f_route_del_v6(struct cli_conn *conn, const char *s)
{
	uint8_t dst6[16];
	uint8_t gw6[16];
	int mlen;
	const char *tk;
	const char *tk_end;
	const char *last;

	last = s + strlen(s);

/* get IP6NET address*/
	tk = s;
	tk_end = strstr(tk, "/");
	if (!tk_end) {
		ofp_sendf(conn->fd, "Invalid IP6NET\r\n");
		sendcrlf(conn);
		return;
	}

	if (!ip6addr_get(tk, tk_end - tk, dst6)) {
		ofp_sendf(conn->fd, "Invalid IP6NET\r\n");
		sendcrlf(conn);
		return;
	}

/* get IP6NET prefix len*/
	tk = tk_end + 1;
	if (tk >= last) {
		ofp_sendf(conn->fd, "Invalid IP6NET\r\n");
		sendcrlf(conn);
		return;
	}

	tk_end = last;
	if (tk == tk_end) {
		ofp_sendf(conn->fd, "Invalid IP6NET\r\n");
		sendcrlf(conn);
		return;
	}

	mlen = atoi(tk);

	ofp_set_route6_params(OFP_ROUTE6_DEL, 0 /*vrf*/, 0 /*vlan*/, 0 /*port*/,
			      dst6, mlen, gw6, 0);

	sendcrlf(conn);
}
#endif /* INET6 */

/* route add from DEV to DEV */
void f_route_add_dev_to_dev(struct cli_conn *conn, const char *s)
{

	char dev[16], from[16];
	int from_port, to_port, vlan;

	if (sscanf(s, "%s %s", from, dev) != 2)
		return;
	from_port = ofp_name_to_port_vlan(from, &vlan);
	to_port = ofp_name_to_port_vlan(dev, &vlan);
	from_port = from_port; /* remove warnings*/
	to_port = to_port;
	/*set_port_params(16, ofp_ifnet_data[32].address,
	  ufp_ifnet_data[32].masklen, ufp_ifnet_data[32].mac,
	  ufp_ifnet_data[32].link_local);
	add_to_next_hop_table(ADD_ENTRY, ufp_ifnet_data[to_port].address,
	from_port, ufp_ifnet_data[to_port].masklen,
	  NH_FLAGS_TO_LOCAL_SEGMENT, to_port, 0, to_port, NULL, 0);*/
	sendcrlf(conn);
}

void f_help_route(struct cli_conn *conn, const char *s)
{
	(void)s;

	ofp_sendf(conn->fd, "Show configured routes:\r\n"
		"  route show\r\n\r\n");

	ofp_sendf(conn->fd, "Add IPv4 route:\r\n"
		"  route [-A inet4 ] add IP4NET gw IP4ADDR dev DEV\r\n"
		"    IP4NET: network address in a.b.c.d/e format\r\n"
		"    IP4ADDR: IP address in a.b.c.d format\r\n"
		"    DEV: ethernet interface name\r\n"
		"  Example:\r\n"
		"    route add 192.168.200.0/24 gw 192.168.100.1"
		" dev %s0\r\n\r\n", OFP_IFNAME_PREFIX);

	ofp_sendf(conn->fd, "Delete IPv4 route:\r\n"
		"  route [-A inet4] delete IP4NET\r\n"
		"    IP4NET: network address in a.b.c.d/e format\r\n"
		"  Example:\r\n"
		"    route delete 192.168.200.0/24\r\n\r\n");

	ofp_sendf(conn->fd, "Add IPv4 route to virtual route table:\r\n"
		"  route [-A inet4 ] add vrf VRF IP4NET gw IP4ADDR dev DEV\r\n"
		"    VRF: number\r\n"
		"    IP4NET: network address in a.b.c.d/n format\r\n"
		"    IP4ADDR: IP address in a.b.c.d format\r\n"
		"    DEV: ethernet interface name\r\n"
		"  Example:\r\n"
		"    route add vrf 2 192.168.200.0/24 gw 192.168.100.1"
		" dev %s0\r\n\r\n", OFP_IFNAME_PREFIX);

	ofp_sendf(conn->fd, "Delete IPv4 route from virtual route table:\r\n"
		"  route [-A inet4] delete vrf VRF IP4NET\r\n"
		"    VRF: number\r\n"
		"    IP4NET: network address in a.b.c.d/e format\r\n"
		"  Example:\r\n"
		"    route del vrf 2 192.168.200.0/24\r\n\r\n");
#ifdef INET6
	ofp_sendf(conn->fd, "Add IPv6 route:\r\n"
		"  route -A inet6 add IP6NET gw IP6ADDR dev DEV\r\n"
		"    IP6NET: network address in a:b:c:d:e:f:g:h/n or"
		" compressed format\r\n"
		"    IP6ADDR: IPv6 address in a:b:c:d:e:f:g:h or"
		" compressed format\r\n"
		"    DEV: ethernet interface name\r\n"
		"  Example:\r\n"
		"    route -A inet6 add 2000:1baf::/64 gw 2001:db8:0:f101:0:0:0:1"
		" dev %s0\r\n\r\n", OFP_IFNAME_PREFIX);

	ofp_sendf(conn->fd, "Delete IPv6 route:\r\n"
		"  route -A inet6 delete IP6NET\r\n"
		"    IP6NET: network address in a:b:c:d:e:f:g:h/n or"
		" compressed format\r\n"
		"  Example:\r\n"
		"    route -A inet6 delete 2000:1baf::/64\r\n\r\n");
#endif /* INET6 */
	ofp_sendf(conn->fd, "Show (this) help.\r\n"
		"  route help\r\n\r\n");
	sendcrlf(conn);
}
