/*-
 * Copyright (c) 2018 ENEA Software AB
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#include "ofpi_log.h"
#include "ofpi_cli.h"
#include "ofpi_portconf.h"
#include "ofpi_util.h"

void f_address_help(struct cli_conn *conn, const char *s)
{
	(void)s;

	ofp_sendf(conn->fd, "Add ipv4 address:\r\n"
		"  address add IP4NET DEV\r\n"
		"    DEV: ethernet interface name or local interface(lo0, lo1,...)\r\n"
		"    IP4NET: network address in a.b.c.d/e format\r\n"
		"  Example:\r\n"
		"    address add 192.168.200.1/24 %s0\r\n\r\n",
		OFP_IFNAME_PREFIX);

	ofp_sendf(conn->fd, "Remove ipv4 address:\r\n"
		"  address del IP4NET DEV\r\n"
		"    DEV: ethernet interface name or local interface(lo0, lo1,...)\r\n"
		"    IP4NET: network address in a.b.c.d/e format\r\n"
		"  Example:\r\n"
		"    address del 192.168.200.1/24 %s0\r\n\r\n",
		OFP_IFNAME_PREFIX);

	ofp_sendf(conn->fd, "Show ipv4 addresses:\r\n"
			"  address show\r\n"
			"  Example:\r\n"
			"    address show\r\n\r\n");

}

void f_address_show(struct cli_conn *conn, const char *s)
{
	/* addressr [show] */
	(void)s;

	ofp_show_ifnet_ip_addrs(conn->fd);

	sendcrlf(conn);
}


void f_address_add(struct cli_conn *conn, const char *s)
{
	/* address add IP4NET DEV */
	char dev[16];
	int port, a, b, c, d, m, vlan, vrf = 0;
	uint32_t addr;
	const char *err;
	int ret;

	ret = sscanf(s, "%d.%d.%d.%d/%d %s", &a, &b,
		&c, &d, &m, dev);

	if (ret < 6) {
		return;
	}

	addr = odp_cpu_to_be_32((a << 24) | (b << 16) | (c << 8) | d);
	port = ofp_name_to_port_vlan(dev, &vlan);

	if (port == GRE_PORTS || port == VXLAN_PORTS || port == LOCAL_PORTS) {
		ofp_sendf(conn->fd, "Invalid device name.\r\n");
		return;
	}

	err = ofp_config_interface_add_ip_v4(port, vlan, vrf,
						 addr, m);
	if (err != NULL)
		ofp_sendf(conn->fd, err);

	sendcrlf(conn);
}

void f_address_del(struct cli_conn *conn, const char *s)
{
	/* addressr delete IP4NET DEV */
	char dev[16];
	int port, a, b, c, d, m, vlan, vrf = 0;
	const char *err;
	int ret;
	uint32_t addr;

	ret = sscanf(s, "%d.%d.%d.%d/%d %s", &a, &b,
			&c, &d, &m, dev);

	if (ret < 6) {
		return;
	}
	addr = odp_cpu_to_be_32((a << 24) | (b << 16) | (c << 8) | d);
	port = ofp_name_to_port_vlan(dev, &vlan);
	err = ofp_config_interface_del_ip_v4(port, vlan, vrf, addr, m);

	if (err != NULL)
		ofp_sendf(conn->fd, err);

	sendcrlf(conn);
}
