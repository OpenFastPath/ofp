/*-
 * Copyright (c) 2014 ENEA Software AB
 * Copyright (c) 2014 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#include "ofp.h"

#include "ioctl_test.h"

#define logfilename "/tmp/iocrl-test.log"
static FILE *logfile;

#define IFNAME "fp0"
#define GRENAME "gre1"

#define IP4(a,b,c,d) (a|(b<<8)|(c<<16)|(d<<24))

static uint32_t
get_ip_address(int fd, const char *name)
{
	struct ofp_ifreq ifr;

	strcpy(ifr.ifr_name, name);
	if (ofp_ioctl(fd, OFP_SIOCGIFADDR, &ifr) < 0) {
		OFP_ERR("ofp_ioctl failed, err='%s'",
			ofp_strerror(ofp_errno));
		return 0;
	} else {
		struct ofp_sockaddr_in *ipaddr;
		ipaddr = (struct ofp_sockaddr_in *)&ifr.ifr_addr;
		return ipaddr->sin_addr.s_addr;
	}
}

static uint32_t
get_netmask(int fd, const char *name)
{
	struct ofp_ifreq ifr;

	strcpy(ifr.ifr_name, name);
	if (ofp_ioctl(fd, OFP_SIOCGIFNETMASK, &ifr) < 0) {
		OFP_ERR("ofp_ioctl failed, err='%s'",
			ofp_strerror(ofp_errno));
		return 0;
	} else {
		struct ofp_sockaddr_in *ipaddr;
		ipaddr = (struct ofp_sockaddr_in *)&ifr.ifr_addr;
		return ipaddr->sin_addr.s_addr;
	}
}

static uint32_t
get_broadcast_address(int fd, const char *name)
{
	struct ofp_ifreq ifr;

	strcpy(ifr.ifr_name, name);
	if (ofp_ioctl(fd, OFP_SIOCGIFBRDADDR, &ifr) < 0) {
		OFP_ERR("ofp_ioctl failed, err='%s'",
			ofp_strerror(ofp_errno));
		return 0;
	} else {
		struct ofp_sockaddr_in *ipaddr;
		ipaddr = (struct ofp_sockaddr_in *)&ifr.ifr_addr;
		return ipaddr->sin_addr.s_addr;
	}
}

static void
set_ip_address_and_mask(int fd, const char *name, uint32_t addr, uint32_t mask)
{
	struct ofp_in_aliasreq ifra;

	strcpy(ifra.ifra_name, name);
	ifra.ifra_addr.sin_family = OFP_AF_INET;
	ifra.ifra_addr.sin_addr.s_addr = addr;
	ifra.ifra_mask.sin_addr.s_addr = mask;
	if (ofp_ioctl(fd, OFP_SIOCSIFADDR, &ifra) < 0) {
		OFP_ERR("ofp_ioctl failed, err='%s'",
			ofp_strerror(ofp_errno));
	}
}

static void
delete_if_address(int fd, const char *name)
{
	struct ofp_in_aliasreq ifra;

	strcpy(ifra.ifra_name, name);
	ifra.ifra_addr.sin_family = OFP_AF_INET;
	if (ofp_ioctl(fd, OFP_SIOCDIFADDR, &ifra) < 0) {
		OFP_ERR("ofp_ioctl failed, err='%s'",
			ofp_strerror(ofp_errno));
	}
}

static void
receive_non_blocking(void)
{
	int s, ret, nb = 1;
	struct ofp_sockaddr_in addr;
	struct ofp_sockaddr_in remote;
	ofp_socklen_t remote_len;
	char buf[64];
	int len = sizeof(buf);

	s = ofp_socket(OFP_AF_INET, OFP_SOCK_DGRAM, OFP_IPPROTO_UDP);

	addr.sin_family = OFP_AF_INET;
	addr.sin_addr.s_addr = 0;
	addr.sin_port = odp_cpu_to_be_16(2048);
	addr.sin_len = sizeof(addr);

	if ((ret = ofp_bind(s, (struct ofp_sockaddr *)&addr, sizeof(addr)))) {
		OFP_ERR("ofp_bind failed ret=%d %s", ret, ofp_strerror(ofp_errno));
	}

	/*
	 * Set non-blocking mode.
	 */
	if (ofp_ioctl(s, OFP_FIONBIO, &nb) < 0) {
		OFP_ERR("ofp_ioctl failed, err='%s'",
			ofp_strerror(ofp_errno));
	}

	/*
	 * No data expected. Immediate return.
	 */
	ret = ofp_recvfrom(s, buf, len, 0,
			     (struct ofp_sockaddr *)&remote, &remote_len);
	ofp_close(s);
}

static int
get_sockbuf_data(int fd, uint32_t cmd)
{
	int val;
	if (ofp_ioctl(fd, cmd, &val) < 0) {
		OFP_ERR("ofp_ioctl failed, err='%s'",
			ofp_strerror(ofp_errno));
	}
	return val;
}

static void
get_if_conf(int fd, struct ofp_ifconf *conf)
{
	if (ofp_ioctl(fd, OFP_SIOCGIFCONF, conf) < 0) {
		OFP_ERR("ofp_ioctl failed, err='%s'",
			ofp_strerror(ofp_errno));
	}
}

static void
set_gre_tunnel(int fd, const char *name, uint32_t addr, uint32_t p2p,
	       uint32_t local, uint32_t remote, int vrf)
{
	struct ofp_in_tunreq treq;

	strcpy(treq.iftun_name, name);
	treq.iftun_addr.sin_addr.s_addr = addr;
	treq.iftun_p2p_addr.sin_addr.s_addr = p2p;
	treq.iftun_local_addr.sin_addr.s_addr = local;
	treq.iftun_remote_addr.sin_addr.s_addr = remote;
	treq.iftun_vrf = vrf;

	if (ofp_ioctl(fd, OFP_SIOCSIFTUN, &treq) < 0) {
		OFP_ERR("ofp_ioctl failed, err='%s'",
			ofp_strerror(ofp_errno));
	}
}

static void
set_vrf(int fd, const char *name, int vrf)
{
	struct ofp_ifreq ifr;

	strcpy(ifr.ifr_name, name);
	ifr.ifr_fib = vrf;

	if (ofp_ioctl(fd, OFP_SIOCSIFFIB, &ifr) < 0) {
		OFP_ERR("ofp_ioctl failed, err='%s'",
			ofp_strerror(ofp_errno));
	}
}

static void
set_route(int fd, const char *dev, int vrf,
	  uint32_t dst, uint32_t mask, uint32_t gw)
{
	struct ofp_rtentry rt;

	rt.rt_vrf = vrf;
	rt.rt_dev = (char *)(uintptr_t)dev;
	((struct ofp_sockaddr_in *)&rt.rt_dst)->sin_addr.s_addr = dst;
	((struct ofp_sockaddr_in *)&rt.rt_genmask)->sin_addr.s_addr = mask;
	((struct ofp_sockaddr_in *)&rt.rt_gateway)->sin_addr.s_addr = gw;

	if (ofp_ioctl(fd, OFP_SIOCADDRT, &rt) < 0) {
		OFP_ERR("ofp_ioctl failed, err='%s'",
			ofp_strerror(ofp_errno));
	}
}

static void *
ioctl_test(void *arg)
{
	int fd;
	uint32_t addr, origaddr, origmask;

	(void)arg;

	logfile = fopen(logfilename, "w");
	OFP_INFO("ioctl_test thread started");

	if (odp_init_local(ODP_THREAD_CONTROL)) {
		OFP_ERR("Error: ODP local init failed.\n");
		return NULL;
	}
	if (ofp_init_local()) {
		OFP_ERR("Error: OFP local init failed.\n");
		return NULL;
	}
	sleep(2);

	if ((fd = ofp_socket(OFP_AF_INET, OFP_SOCK_DGRAM, OFP_IPPROTO_UDP)) < 0) {
		OFP_ERR("ofp_socket failed, err='%s'",
			ofp_strerror(ofp_errno));
		return NULL;
	}

	OFP_INFO("=====================================");
	OFP_INFO("Get IP address of %s", IFNAME);
	origaddr = get_ip_address(fd, IFNAME);
	OFP_INFO("  %s", ofp_print_ip_addr(origaddr));

	OFP_INFO("=====================================");
	OFP_INFO("Get netmask of %s", IFNAME);
	origmask = get_netmask(fd, IFNAME);
	OFP_INFO("  %s", ofp_print_ip_addr(origmask));

	OFP_INFO("=====================================");
	OFP_INFO("Get broadcast address of %s", IFNAME);
	OFP_INFO("  %s",
		 ofp_print_ip_addr(get_broadcast_address(fd, IFNAME)));

	OFP_INFO("=====================================");
	OFP_INFO("Delete IP address of %s", IFNAME);
	delete_if_address(fd, IFNAME);

	OFP_INFO("=====================================");
	addr = IP4(192,168,156,111);
	OFP_INFO("Set IP address of %s to %s/%d",
		 IFNAME, ofp_print_ip_addr(addr), 25);
	set_ip_address_and_mask(fd, IFNAME, addr, odp_cpu_to_be_32(0xffffff80));

	OFP_INFO("Set back original address and mask");
	set_ip_address_and_mask(fd, IFNAME, origaddr, origmask);

	OFP_INFO("=====================================");
	OFP_INFO("Receiving from socket");
	receive_non_blocking();
	OFP_INFO("Immediate return");

	OFP_INFO("=====================================");
	OFP_INFO("Get sockbuf bytes to read");
	OFP_INFO("  %d", get_sockbuf_data(fd, OFP_FIONREAD));

	OFP_INFO("=====================================");
	OFP_INFO("Get sockbuf bytes yet to write");

	OFP_INFO("  %d", get_sockbuf_data(fd, OFP_FIONWRITE));

	OFP_INFO("=====================================");
	OFP_INFO("Get sockbuf send space");

	OFP_INFO("  %d", get_sockbuf_data(fd, OFP_FIONSPACE));

	OFP_INFO("=====================================");
	OFP_INFO("Set GRE tunnel");
	set_gre_tunnel(fd, GRENAME, IP4(10,3,4,1), IP4(10,3,4,2),
		       origaddr, IP4(192,168,56,104), 0);

	OFP_INFO("=====================================");
	OFP_INFO("Change GRE tunnel's VRF");
	set_vrf(fd, GRENAME, 7);

	OFP_INFO("=====================================");
	OFP_INFO("Get all interfaces");

	struct ofp_ifconf conf;
	char data[1024];
	struct ofp_ifreq *ifr;
	int i = 1;

	conf.ifc_len = sizeof(data);
	conf.ifc_buf = (char *)data;

	get_if_conf(fd, &conf);

	ifr = (struct ofp_ifreq *)data;
	while ((char *)ifr < data + conf.ifc_len) {
		switch (ifr->ifr_addr.sa_family) {
		case OFP_AF_INET:
			OFP_INFO("  %d. %s : %s", i, ifr->ifr_name,
				 ofp_print_ip_addr(((struct ofp_sockaddr_in *)
						      &ifr->ifr_addr)->sin_addr.s_addr));
			break;
		}
		ifr++;
		i++;
	}

	OFP_INFO("=====================================");
	OFP_INFO("Set routes");

	set_route(fd, GRENAME, 0, IP4(10,1,1,0), IP4(255,255,255,0), IP4(10,3,4,2));
	/*
	 * If output device is not set it will be found using the route to gateway.
	 */
	set_route(fd, NULL, 0, IP4(10,7,0,0), IP4(255,255,0,0), IP4(192,168,56,254));

	OFP_INFO("=====================================");
	ofp_close(fd);
	OFP_INFO("Ioctl test exit");
	OFP_INFO("=====================================");

	fclose(logfile);
	if (system("cat " logfilename) < 0)
		OFP_ERR("system failed");
	return NULL;
}

void ofp_start_ioctl_thread(int core_id)
{
	odph_linux_pthread_t test_linux_pthread;
	odp_cpumask_t cpumask;

	odp_cpumask_zero(&cpumask);
	odp_cpumask_set(&cpumask, core_id);

	ofp_linux_pthread_create(&test_linux_pthread,
				  &cpumask,
				  ioctl_test,
				  NULL,
				  ODP_THREAD_WORKER
				);
}
