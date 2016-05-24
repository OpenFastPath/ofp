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
#include "ofpi_portconf.h"
#include "ofpi_util.h"


/* "ifconfig" */
/* "ifconfig show" */
/* "show ifconfig" */
void f_ifconfig_show(struct cli_conn *conn, const char *s)
{
	(void)s;

	ofp_show_interfaces(conn->fd);

	sendcrlf(conn);
}

/* "ifconfig help" */
/* "help ifconfig" */
void f_help_ifconfig(struct cli_conn *conn, const char *s)
{
	(void)s;

	ofp_sendf(conn->fd, "Show interfaces:\r\n"
		"  ifconfig [show]\r\n\r\n");

	ofp_sendf(conn->fd, "Create interface:\r\n"
		"  ifconfig [-A inet4] DEV IP4NET\r\n"
		"    DEV: ethernet interface name or local interface(lo0, lo1,...)\r\n"
		"    IP4NET: network address in a.b.c.d/e format\r\n"
		"  Example:\r\n"
		"    ifconfig %s0 192.168.200.1/24\r\n\r\n",
		OFP_IFNAME_PREFIX);

	ofp_sendf(conn->fd, "Create interface on virtual route table:\r\n"
		"  ifconfig [-A inet4] DEV IP4NET vrf VRF\r\n"
		"    DEV: ethernet interface name or local interface(lo0, lo1,...)\r\n"
		"    IP4NET: network address in a.b.c.d/e format\r\n"
		"    VRF: number\r\n"
		"  Example:\r\n"
		"    ifconfig %s0 192.168.200.1/24 vrf 2\r\n\r\n",
		OFP_IFNAME_PREFIX);
	ofp_sendf(conn->fd, "Create GRE tunnel:\r\n"
		"  ifconfig tunnel gre DEV local IP4ADDR remote IP4ADDR peer IP4ADDR IP4ADDR\r\n"
		"    DEV: gre interface name\r\n"
		"    local: tunnel local ip address in a.b.c.d format\r\n"
		"    remote: tunnel remote ip address in a.b.c.d format\r\n"
		"    peer: pointtopoint ip address in a.b.c.d format\r\n"
		"    IP4ADDR: interface ip address in a.b.c.d format\r\n"
		"  Example:\r\n"
		"    ifconfig %s100 local 192.168.200.1 remote 192.168.200.2 peer 10.10.10.2 10.10.10.1\r\n\r\n",
		OFP_GRE_IFNAME_PREFIX);
	ofp_sendf(conn->fd, "Create GRE tunnel on virtual route table :\r\n"
		"  ifconfig tunnel gre DEV local IP4ADDR remote IP4ADDR peer IP4ADDR IP4ADDR vrf VRF\r\n"
		"    DEV: gre interface name\r\n"
		"    local: tunnel local ip address in a.b.c.d format\r\n"
		"    remote: tunnel remote ip address in a.b.c.d format\r\n"
		"    peer: pointtopoint ip address in a.b.c.d format\r\n"
		"    IP4ADDR: interface ip address in a.b.c.d format\r\n"
		"    vrf: number\r\n"
		"  Example:\r\n"
		"    ifconfig %s100 local 192.168.200.1 remote 192.168.200.2 peer 10.10.10.2 10.10.10.1 vrf 2\r\n\r\n",
		OFP_GRE_IFNAME_PREFIX);
	ofp_sendf(conn->fd, "Create VXLAN interface:\r\n"
		"  ifconfig vxlan DEV group IP4ADDR dev DEV_PHYS IP4NET\r\n"
		"    DEV: vxlan interface name (interface number is the vni)\r\n"
		"    IP4ADDR: group ip address in a.b.c.d format\r\n"
		"    DEV_PHYS: interface name of the physical device\r\n"
		"    IP4NET: network address in a.b.c.d/e format\r\n"
		"  Example:\r\n"
		"    ifconfig vxlan %s42 group 239.1.1.1 dev fp0 10.10.10.1/24\r\n"
		"    (vni = 42)\r\n\r\n",
		OFP_VXLAN_IFNAME_PREFIX);
#ifdef INET6
	ofp_sendf(conn->fd, "Create IPv6 interface or add IPv6 address to local interface:\r\n"
		"  ifconfig -A inet6 DEV IP6NET\r\n"
		"    DEV: ethernet interface name\r\n"
		"    IP6NET: network address in a:b:c:d:e:f:g:h/n or"
		" compressed format\r\n"
		"  Example:\r\n"
		"    ifconfig -A inet6 %s0 2000:1baf::/64\r\n\r\n",
		OFP_IFNAME_PREFIX);
#endif /* INET6 */
	ofp_sendf(conn->fd, "Delete interface:\r\n"
		"  ifconfig DEV down\r\n"
		"    DEV: ethernet interface name\r\n"
		"  Example:\r\n"
		"    ifconfig %s0 down\r\n\r\n",
		OFP_IFNAME_PREFIX);

	ofp_sendf(conn->fd, "Show (this) help:\r\n"
		"  ifconfig help\r\n\r\n");

	sendcrlf(conn);
}

/* "ifconfig [-A inet 4] DEV IP4NET";*/
void f_ifconfig(struct cli_conn *conn, const char *s)
{

	char dev[16];
	int port, a, b, c, d, m, vlan, vrf = 0;
	uint32_t addr;
	const char *err;

	if (sscanf(s, "%s %d.%d.%d.%d/%d %d", dev, &a, &b,
		&c, &d, &m, &vrf) < 6)
		return;
	addr = odp_cpu_to_be_32((a << 24) | (b << 16) | (c << 8) | d);
	port = ofp_name_to_port_vlan(dev, &vlan);

	if (port == GRE_PORTS || port == VXLAN_PORTS) {
		ofp_sendf(conn->fd, "Invalid device name.\r\n");
		return;
	}

	if (PHYS_PORT(port))
		err = ofp_config_interface_up_v4(port, vlan, vrf,
						 addr, m);
	else
		err = ofp_config_interface_up_local(vlan, vrf,
						    addr, m);
	if (err != NULL)
		ofp_sendf(conn->fd, err);
	sendcrlf(conn);
}

/* "ifconfig tunnel gre DEV local IP4ADDR remote IP4ADDR peer IP4ADDR IP4ADDR vrf NUMBER";*/
void f_ifconfig_tun(struct cli_conn *conn, const char *s)
{
	char dev[16], loc[16], rem[16], ip[16], peer[16];
	uint32_t tun_loc, tun_rem, addr, p2p;
	int port, vlan, vrf = 0, masklen = 32;
	const char *err;

	if (sscanf(s, "%s %s %s %s %s %d", dev, loc, rem, peer, ip, &vrf) < 5)
		return;

	port = ofp_name_to_port_vlan(dev, &vlan);

	if (port != GRE_PORTS) {
		ofp_sendf(conn->fd, "Invalid device name.\r\n");
		sendcrlf(conn);
		return;
	}

	if (!ip4addr_get(loc, &tun_loc))
		return;
	if (!ip4addr_get(rem, &tun_rem))
		return;
	if (!ip4addr_get(peer, &p2p))
		return;
	if (!ip4addr_get(ip, &addr))
		return;


	err = ofp_config_interface_up_tun(port, vlan, vrf, tun_loc, tun_rem,
					    p2p, addr, masklen);
	if (err != NULL)
		ofp_sendf(conn->fd, err);
	sendcrlf(conn);
}

/* ifconfig vxlan DEV group IP4ADDR dev DEV IP4NET */
void f_ifconfig_vxlan(struct cli_conn *conn, const char *s)
{
	char dev[16], physdev[16], group[16];
	uint32_t vxlan_group, addr;
	int n, port, vlan, physport, physvlan, a, b, c, d, m;
	const char *err;

	if ((n = sscanf(s, "%s %s %s %d.%d.%d.%d/%d",
			dev, group, physdev,
			&a, &b, &c, &d, &m)) != 8) {
		return;
	}

	addr = odp_cpu_to_be_32((a << 24) | (b << 16) | (c << 8) | d);
	port = ofp_name_to_port_vlan(dev, &vlan);

	if (port != VXLAN_PORTS) {
		ofp_sendf(conn->fd, "Invalid device name %s.\r\n", dev);
		sendcrlf(conn);
		return;
	}

	physport = ofp_name_to_port_vlan(physdev, &physvlan);

	if (!ip4addr_get(group, &vxlan_group)) {
		ofp_sendf(conn->fd, "Invalid group address.\r\n");
		sendcrlf(conn);
		return;
	}

	/* vrf is copied from the physical port */
	err = ofp_config_interface_up_vxlan(0, addr, m, vlan, vxlan_group,
					    physport, physvlan);
	if (err != NULL)
		ofp_sendf(conn->fd, err);

	sendcrlf(conn);
}

/* ifconfig -A inet6 DEV IP6NET */
#ifdef INET6
void f_ifconfig_v6(struct cli_conn *conn, const char *s)
{
	char dev[16];
	uint8_t addr6[16];
	int prefix, port, vlan;
	const char *tk;
	const char *tk_end;
	const char *err;

	/*get DEV*/
	tk = s;
	tk_end = strstr(tk, " ");

	if (!tk_end || ((int)(tk_end - tk) > (int)(sizeof(dev) - 1))) {
		ofp_sendf(conn->fd, "Invalid device name.\r\n");
		sendcrlf(conn);
		return;
	}
	memcpy(dev, tk, tk_end - tk);
	dev[tk_end - tk] = 0;

	port = ofp_name_to_port_vlan(dev, &vlan);
	if (port == -1 || port == GRE_PORTS) {
		ofp_sendf(conn->fd, "Invalid device name.\r\n");
		sendcrlf(conn);
		return;
	}

	/*get IP6NET address*/
	tk = tk_end + 1;
	tk_end = strstr(tk, "/");

	if (!tk_end || tk_end - tk > 40) {
		ofp_sendf(conn->fd, "Invalid IP6NET address.\r\n");
		sendcrlf(conn);
		return;
	}

	if (!ip6addr_get(tk, tk_end - tk, addr6)) {
		ofp_sendf(conn->fd, "Invalid IP6NET address.\r\n");
		sendcrlf(conn);
		return;
	}

	/* get IP6NET prefix len*/
	tk = tk_end + 1;
	if (sscanf(tk, "%d", &prefix) < 1) {
		ofp_sendf(conn->fd, "Invalid IP6NET prefix.\r\n");
		sendcrlf(conn);
		return;
	}

	if (port == LOCAL_PORTS)
		err = ofp_config_interface_up_local_v6(vlan, addr6, prefix);
	else
		err = ofp_config_interface_up_v6(port, vlan, addr6, prefix);
	if (err != NULL)
		ofp_sendf(conn->fd, err);
	sendcrlf(conn);
}
#endif /* INET6 */

void f_ifconfig_down(struct cli_conn *conn, const char *s)
{
	/* "ifconfig DEV down"; */
	char dev[16];
	int port, vlan;
	const char *err;

	if (sscanf(s, "%s", dev) < 1)
		return;
	port = ofp_name_to_port_vlan(dev, &vlan);

	err = ofp_config_interface_down(port, vlan);

	if (err != NULL)
		ofp_sendf(conn->fd, err);
	sendcrlf(conn);
}
