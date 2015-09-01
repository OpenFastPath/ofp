/* Copyright (c) 2014, Nokia
 * Copyright (c) 2014, ENEA Software AB
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef OFP_TESTMODE_AUTO
#define OFP_TESTMODE_AUTO 1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>

#if OFP_TESTMODE_AUTO
#include <CUnit/Automated.h>
#else
#include <CUnit/Basic.h>
#endif

#include <odp.h>
#include <ofpi.h>
#include <ofpi_log.h>
#include <ofpi_portconf.h>
#include <ofpi_route.h>
#include <ofpi_rt_lookup.h>
#include <ofpi_avl.h>
#include <ofpi_arp.h>
#include <ofpi_pkt_processing.h>
#include <ofpi_timer.h>
#include <ofpi_hook.h>
#include <ofpi_util.h>
#include <ofpi_debug.h>

/*
 * Test data
 */
#define SHM_PKT_POOL_SIZE      (32*2048)
#define SHM_PKT_POOL_BUF_SIZE  3000

uint8_t ifmac[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
uint32_t ifmtu = 1480;
uint8_t link_local[16];
#ifdef SP
int sp_status = OFP_SP_DOWN;
#endif

/*
 * INIT
 */
static int
init_suite(void)
{
	odp_pool_param_t pool_params;
	ofp_pkt_hook pkt_hook[OFP_HOOK_MAX];
	struct ofp_ifnet *dev;

	/* Init ODP before calling anything else */
	if (odp_init_global(NULL, NULL)) {
		OFP_ERR("Error: ODP global init failed.\n");
		return -1;
	}

	/* Init this thread */
	if (odp_init_local(ODP_THREAD_CONTROL)) {
		OFP_ERR("Error: ODP local init failed.\n");
		return -1;
	}

	memset(pkt_hook, 0, sizeof(pkt_hook));

	pool_params.pkt.seg_len = SHM_PKT_POOL_BUF_SIZE;
	pool_params.pkt.len     = SHM_PKT_POOL_BUF_SIZE;
	pool_params.pkt.num     = SHM_PKT_POOL_SIZE / SHM_PKT_POOL_BUF_SIZE;
	pool_params.type        = ODP_POOL_PACKET;

	(void) ofp_init_pre_global("packet_pool", &pool_params, pkt_hook);

	ofp_arp_init_local();

	dev = ofp_get_ifnet(0, 0);
	dev->if_mtu = ifmtu;
	memcpy(dev->mac, ifmac, OFP_ETHER_ADDR_LEN);
	ofp_mac_to_link_local(ifmac, link_local);

	return 0;
}

static int
clean_suite(void)
{
	return 0;
}

static void assert_next_hop(struct ofp_nh_entry *nh, uint32_t gw,
			    uint16_t port, uint16_t vlan)
{
	CU_ASSERT_PTR_NOT_NULL_FATAL(nh);
	CU_ASSERT_EQUAL(nh->gw, gw);
	CU_ASSERT_EQUAL(nh->port, port);
	CU_ASSERT_EQUAL(nh->vlan, vlan);
}

static void assert_dev(struct ofp_ifnet *dev, int port, uint16_t vlan,
		       uint16_t vrf, uint32_t ifaddr, uint32_t ifmtu,
		       int masklen, uint32_t bcast, uint8_t *link_local)
{
	CU_ASSERT_PTR_NOT_NULL_FATAL(dev);
	CU_ASSERT_EQUAL(dev->port, port);
	CU_ASSERT_EQUAL(dev->vlan, vlan);
	CU_ASSERT_EQUAL(dev->vrf, vrf);
	CU_ASSERT_EQUAL(dev->if_mtu, ifmtu);
	CU_ASSERT_EQUAL(dev->ip_addr, ifaddr);
	CU_ASSERT_EQUAL(dev->bcast_addr, bcast);
	CU_ASSERT_EQUAL(dev->masklen, masklen);
#ifdef SP
	CU_ASSERT_EQUAL(dev->sp_status, sp_status);
#endif
#ifdef INET6
	if (memcmp(dev->link_local, link_local, 16))
		CU_FAIL("Link local address");
#endif /* INET6 */
}

/*
 * Tests
 */

static void
test_sinlge_port_basic(void)
{
	int port = 0;
	uint16_t vlan = 0;
	uint16_t vrf = 1;
	uint32_t ifaddr = 0x650AA8C0; /* C0.A8.0A.65 = 192.168.10.101 */
	int masklen = 24;
	uint32_t bcast = ifaddr | odp_cpu_to_be_32(0xFF);
	struct ofp_ifnet *dev;
	struct ofp_nh_entry *nh;
	const char *res;

	res = ofp_config_interface_up_v4(port, vlan, vrf, ifaddr, masklen);
	CU_ASSERT_PTR_NULL_FATAL(res);

	dev = ofp_get_ifnet(port, vlan);
	assert_dev(dev, port, vlan, vrf, ifaddr, ifmtu, masklen, bcast,
		   link_local);
	nh = ofp_get_next_hop(vrf, ifaddr, NULL);
	assert_next_hop(nh, 0, port, vlan);


	res = ofp_config_interface_down(port, vlan);
	CU_ASSERT_PTR_NULL_FATAL(res);

	dev = ofp_get_ifnet(port, vlan);
	assert_dev(dev, port, vlan, vrf, 0, ifmtu, masklen, bcast, link_local);
	nh = ofp_get_next_hop(vrf, ifaddr, NULL);
	CU_ASSERT_PTR_NULL(nh);
}

static void
test_two_ports_vlan(void)
{
	int port = 0;
	uint16_t vlan = 0, vlan1 = 100;
	uint16_t vrf = 1, vrf1 = 2;
	uint32_t ifaddr = 0x650AA8C0; /* C0.A8.0A.65 = 192.168.10.101 */
	uint32_t ifaddr1 = 0x650AA8C1;
	int masklen = 24, masklen1 = 20;
	uint32_t bcast = ifaddr | odp_cpu_to_be_32(0xFF);
	uint32_t bcast1 = ifaddr1 | odp_cpu_to_be_32(0xFFF);
	struct ofp_ifnet *dev;
	struct ofp_nh_entry *nh;
	const char *res;

	res = ofp_config_interface_up_v4(port, vlan, vrf, ifaddr, masklen);
	CU_ASSERT_PTR_NULL_FATAL(res);
	res = ofp_config_interface_up_v4(port, vlan1, vrf1, ifaddr1, masklen1);
	CU_ASSERT_PTR_NULL_FATAL(res);

	dev = ofp_get_ifnet(port, vlan);
	CU_ASSERT_PTR_NOT_NULL_FATAL(dev);
	assert_dev(dev, port, vlan, vrf, ifaddr, ifmtu, masklen, bcast,
		   link_local);
	nh = ofp_get_next_hop(vrf, ifaddr, NULL);
	assert_next_hop(nh, 0, port, vlan);

	dev = ofp_get_ifnet(port, vlan1);
	assert_dev(dev, port, vlan1, vrf1, ifaddr1, ifmtu, masklen1, bcast1,
		   link_local);
	nh = ofp_get_next_hop(vrf1, ifaddr1, NULL);
	assert_next_hop(nh, 0, port, vlan1);

	res = ofp_config_interface_down(port, vlan);
	CU_ASSERT_PTR_NULL_FATAL(res);
	res = ofp_config_interface_down(port, vlan1);
	CU_ASSERT_PTR_NULL_FATAL(res);

	dev = ofp_get_ifnet(port, vlan);
	assert_dev(dev, port, vlan, vrf, 0, ifmtu, masklen, bcast, link_local);
	nh = ofp_get_next_hop(vrf, ifaddr, NULL);
	CU_ASSERT_PTR_NULL(nh);

	dev = ofp_get_ifnet(port, vlan1);
	CU_ASSERT_PTR_NULL_FATAL(dev);
	nh = ofp_get_next_hop(vrf1, ifaddr1, NULL);
	CU_ASSERT_PTR_NULL(nh);
}

static void
test_gre_port(void)
{
	int port = 0;
	uint16_t vlan = 10;
	uint16_t vrf = 1;
	uint32_t ifaddr = 0x650AA8C0; /* C0.A8.0A.65 = 192.168.10.101 */
	int masklen = 24, gre_ml = 32;
	uint16_t greid = 100;
	uint32_t greaddr = 0x010A0A0A;
	uint32_t grep2p = 0x020A0A0A;
	struct ofp_ifnet *dev;
	struct ofp_nh_entry *nh;
	const char *res;

	res = ofp_config_interface_up_v4(port, vlan, vrf, ifaddr, masklen);
	CU_ASSERT_PTR_NULL_FATAL(res);

	/* Non-existent endpoint in vrf */
	res = ofp_config_interface_up_tun(GRE_PORTS, greid, vrf + 1, ifaddr,
					    ifaddr + 1, greaddr, grep2p,
					    gre_ml);
	CU_ASSERT_PTR_NOT_NULL_FATAL(res);
	dev = ofp_get_ifnet(GRE_PORTS, greid);
	CU_ASSERT_PTR_NULL_FATAL(dev);

	/* Successful test */
	res = ofp_config_interface_up_tun(GRE_PORTS, greid, vrf, ifaddr,
					    ifaddr + 1, grep2p, greaddr,
					    gre_ml);
	CU_ASSERT_PTR_NULL_FATAL(res);
	dev = ofp_get_ifnet(GRE_PORTS, greid);
	CU_ASSERT_PTR_NOT_NULL_FATAL(dev);
	CU_ASSERT_EQUAL(dev->ip_local, ifaddr);
	CU_ASSERT_EQUAL(dev->ip_remote, ifaddr + 1);
	CU_ASSERT_EQUAL(dev->ip_addr, greaddr);
	CU_ASSERT_EQUAL(dev->ip_p2p, grep2p);
	CU_ASSERT_EQUAL(dev->masklen, gre_ml);
	CU_ASSERT_EQUAL(dev->if_mtu, ifmtu - 24);

	nh = ofp_get_next_hop(vrf, grep2p, NULL);
	assert_next_hop(nh, 0, GRE_PORTS, greid);

	res = ofp_config_interface_down(port, vlan);
	CU_ASSERT_PTR_NULL_FATAL(res);
	res = ofp_config_interface_down(GRE_PORTS, greid);
	CU_ASSERT_PTR_NULL_FATAL(res);
	dev = ofp_get_ifnet(GRE_PORTS, greid);
	CU_ASSERT_PTR_NULL_FATAL(dev);
}

/*
 * Main
 */
int
main(void)
{
	CU_pSuite ptr_suite = NULL;
	int nr_of_failed_tests = 0;
	int nr_of_failed_suites = 0;

	/* Initialize the CUnit test registry */
	if (CUE_SUCCESS != CU_initialize_registry())
		return CU_get_error();

	/* add a suite to the registry */
	ptr_suite = CU_add_suite("ofp port config", init_suite, clean_suite);
	if (NULL == ptr_suite) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if (NULL == CU_ADD_TEST(ptr_suite,
				test_sinlge_port_basic)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if (NULL == CU_ADD_TEST(ptr_suite,
				test_two_ports_vlan)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if (NULL == CU_ADD_TEST(ptr_suite,
				test_gre_port)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

#if OFP_TESTMODE_AUTO
	CU_set_output_filename("CUnit-Port-conf");
	CU_automated_run_tests();
#else
	/* Run all tests using the CUnit Basic interface */
	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
#endif

	nr_of_failed_tests = CU_get_number_of_tests_failed();
	nr_of_failed_suites = CU_get_number_of_suites_failed();
	CU_cleanup_registry();

	return (nr_of_failed_suites > 0 ?
		nr_of_failed_suites : nr_of_failed_tests);
}
