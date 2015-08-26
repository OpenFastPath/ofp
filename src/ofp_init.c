/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

/**
 * @file
 *
 * @example
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <odp.h>
#include <odp/helper/linux.h>

#include "ofpi_init.h"
#include "ofpi_sysctl.h"
#include "ofpi_util.h"
#include "ofpi_stat.h"
#include "config.h"
#include "ofpi_netlink.h"
#include "ofpi_portconf.h"
#include "ofpi_route.h"
#include "ofpi_rt_lookup.h"
#include "ofpi_arp.h"
#include "ofpi_avl.h"
#include "ofpi_cli.h"
#include "ofpi_pkt_processing.h"
#include "ofpi_timer.h"
#include "ofpi_hook.h"

#include "ofpi_tcp_var.h"
#include "ofpi_socketvar.h"
#include "ofpi_socket.h"
#include "ofpi_reass.h"
#include "ofpi_inet.h"

#include "ofpi_log.h"
#include "ofpi_debug.h"

#define LINUX_THREADS_MAX	4
#define SHM_PKT_POOL_SIZE	(512*2048)
#define SHM_PKT_POOL_BUFFER_SIZE	1856

odp_pool_t ofp_init_pre_global(const char *pool_name,
			       odp_pool_param_t *pool_params,
			       ofp_pkt_hook hooks[])
{
	odp_pool_t pool;

	/* Init shared memories */
	ofp_register_sysctls();

	ofp_portconf_alloc_shared_memory();
	ofp_route_alloc_shared_memory();
	ofp_avl_alloc_shared_memory();

	ofp_reassembly_alloc_shared_memory();
	ofp_reassembly_init_global();

	ofp_pcap_alloc_shared_memory();
	ofp_pcap_init_global();

	ofp_stat_alloc_shared_memory();
	ofp_stat_init_global();

	ofp_timer_init(OFP_TIMER_RESOLUTION_US,
			 OFP_TIMER_MIN_US,
			 OFP_TIMER_MAX_US,
			 OFP_TIMER_TMO_COUNT);

	ofp_hook_alloc_shared_memory();
	ofp_hook_init_global(hooks);

	ofp_arp_alloc_shared_memory();
	ofp_arp_init_global();

	ofp_init_ifnet_data();

	ofp_route_init_global();
	ofp_arp_init_global();

	pool = odp_pool_create(pool_name, pool_params);
	if (pool == ODP_POOL_INVALID) {
		OFP_ERR("Error: odp_pool_create failed.\n");
		return pool;
	}

	ofp_socket_alloc_shared_memory(pool);
	ofp_inet_init();

	return pool;
}

int ofp_init_global(ofp_init_global_t *params)
{
	odp_pool_t pool;
	odp_pool_param_t pool_params;
	int thr_id = 0;
	int i, ret;
	odp_queue_param_t qparam;
	char q_name[ODP_QUEUE_NAME_LEN];
	odp_cpumask_t cpumask;
#ifdef SP
	odph_linux_pthread_t nl_thread;
#endif /* SP */

	/* Define pkt.seg_len so that l2/l3/l4 offset fits in first segment */
	pool_params.pkt.seg_len = SHM_PKT_POOL_BUFFER_SIZE;
	pool_params.pkt.len     = SHM_PKT_POOL_BUFFER_SIZE;
	pool_params.pkt.num     = SHM_PKT_POOL_SIZE / SHM_PKT_POOL_BUFFER_SIZE;
	pool_params.type        = ODP_POOL_PACKET;

	pool = ofp_init_pre_global("packet_pool", &pool_params, params->pkt_hook);

	/* cpu mask for slow path threads */
	odp_cpumask_zero(&cpumask);
	odp_cpumask_set(&cpumask, params->linux_core_id);

	printf("Slow path threads will run on core %d\n", odp_cpumask_first(&cpumask));

	/* Create interfaces */
	for (i = 0; i < params->if_count; ++i) {
		int16_t port = i;

		if (port >= GRE_PORTS) {
			OFP_ERR("BUG! Interfaces are depleted\n");
			break;
		}

		OFP_DBG("if %s becomes %s%d, port %d\n", params->if_names[i],
		       OFP_IFNAME_PREFIX, port, port);
		struct ofp_ifnet *ifnet = ofp_get_ifnet((uint16_t)port, 0);

		strncpy(ifnet->if_name, params->if_names[i], OFP_IFNAMSIZ);
		ifnet->if_name[OFP_IFNAMSIZ-1] = 0;
		ifnet->pkt_pool = pool;

		/* Open a packet IO instance for this device */
		ifnet->pktio = odp_pktio_open(ifnet->if_name, ifnet->pkt_pool);
		if (ifnet->pktio == ODP_PKTIO_INVALID) {
			OFP_ERR("Error: pktio create failed\n");
			abort();
		}


		/*
		 * Create and set the default INPUT queue associated with the 'pktio'
		 * resource
		 */
		if (params->burst_recv_mode == 0) {
			memset(&qparam, 0, sizeof(odp_queue_param_t));
			qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
			qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
			qparam.sched.group = ODP_SCHED_GROUP_DEFAULT;
			snprintf(q_name, sizeof(q_name), "%" PRIu64 "-pktio_inq_def",
				 odp_pktio_to_u64(ifnet->pktio));
			q_name[ODP_QUEUE_NAME_LEN - 1] = '\0';

			ifnet->inq_def = odp_queue_create(q_name,
							  ODP_QUEUE_TYPE_PKTIN,
							  &qparam);
			if (ifnet->inq_def == ODP_QUEUE_INVALID) {
				OFP_ERR("  [%02i] Error: pktio queue creation failed\n",
					  thr_id);
				abort();
			}

			ret = odp_pktio_inq_setdef(ifnet->pktio, ifnet->inq_def);
			if (ret != 0) {
				OFP_ERR("  [%02i] Error: default input-Q setup\n",
					  thr_id);
				abort();
			}
		}

		ifnet->outq_def = odp_pktio_outq_getdef(ifnet->pktio);
		if (ifnet->outq_def == ODP_QUEUE_INVALID) {
			OFP_ERR("  [%02i] Error: default output-Q setup\n", thr_id);
			abort();
		}

		/* Set device outq queue context */
		odp_queue_set_context(ifnet->outq_def, ifnet);

#ifdef SP
		/* Create VIF local input queue */
		memset(&qparam, 0, sizeof(odp_queue_param_t));
		qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
		qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
		qparam.sched.group = ODP_SCHED_GROUP_DEFAULT;
		snprintf(q_name, sizeof(q_name), "%s_inq_def", ifnet->if_name);
		q_name[ODP_QUEUE_NAME_LEN - 1] = '\0';

		ifnet->spq_def = odp_queue_create(q_name,
						ODP_QUEUE_TYPE_POLL,
						&qparam);

		if (ifnet->spq_def == ODP_QUEUE_INVALID) {
			OFP_ERR("Schedule queue create failed.\n");
			abort();
		}
#endif /*SP*/

		/* Create loop queue */
		snprintf(q_name, sizeof(q_name), "%s_loopq_def",
				ifnet->if_name);
		q_name[ODP_QUEUE_NAME_LEN - 1] = '\0';

		memset(&qparam, 0, sizeof(odp_queue_param_t));
		qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
		qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
		qparam.sched.group = ODP_SCHED_GROUP_DEFAULT;

		ifnet->loopq_def = odp_queue_create(q_name,
						ODP_QUEUE_TYPE_SCHED,
						&qparam);
		if (ifnet->loopq_def == ODP_QUEUE_INVALID) {
			OFP_ERR("Schedule queue create failed.\n");
			abort();
		}

		/* Set device loopq queue context */
		odp_queue_set_context(ifnet->loopq_def, ifnet);

		/* Set interface MTU*/
		ifnet->if_mtu = odp_pktio_mtu(ifnet->pktio);
		OFP_DBG("device %s MTU %d\n", ifnet->if_name, ifnet->if_mtu);

		/* RFC 791, p. 24, "Every internet module must be able
		 * to forward a datagram of 68 octets without further
		 * fragmentation."*/
		if (ifnet->if_mtu < 68 || ifnet->if_mtu > 9000) {
			OFP_DBG("Invalid MTU. Overwrite MTU value to 1500\n");
			ifnet->if_mtu = 1500;
		}

		/* Set interface MAC address */
		if (odp_pktio_mac_addr(ifnet->pktio, ifnet->mac,
			sizeof(ifnet->mac)) < 0) {
			OFP_ERR("Failed to retrieve MAC address.\n");
			abort();
		}
		if (!ofp_has_mac(ifnet->mac)) {
			ifnet->mac[0] = port;
			OFP_ERR("MAC overwritten as the value returned by \
				odp_pktio_mac_addr was 00:00:00:00:00:00\n");
		}
		OFP_DBG("device %s addr %s\n", ifnet->if_name,
			ofp_print_mac((uint8_t *)ifnet->mac));

#ifdef SP
		/* Create the kernel representation of the FP interface. */
		ifnet->fd = sp_setup_device(ifnet);

		/* Maintain table to access ifnet from linux ifindex */
		ofp_update_ifindex_lookup_tab(ifnet);

#ifdef INET6
		/* ifnet MAC was set in sp_setup_device() */
		ofp_mac_to_link_local(ifnet->mac, ifnet->link_local);
#endif /* INET6 */

		/* Start VIF slowpath receiver thread */
		odph_linux_pthread_create(ifnet->rx_tbl,
					 &cpumask,
					 sp_rx_thread,
					 ifnet);

		/* Start VIF slowpath transmitter thread */
		odph_linux_pthread_create(ifnet->tx_tbl,
					 &cpumask,
					 sp_tx_thread,
					 ifnet);
#endif /* SP */
	}

#ifdef SP
	/* Start Netlink server process */
	odph_linux_pthread_create(&nl_thread,
				  &cpumask,
				  START_NL_SERVER,
				  NULL);
#endif /* SP */

	return 0;
}


int ofp_init_local(void)
{
	/* Lookup shared memories */
	ofp_portconf_lookup_shared_memory();
	ofp_route_lookup_shared_memory();
	ofp_avl_lookup_shared_memory();
	ofp_reassembly_lookup_shared_memory();
	ofp_pcap_lookup_shared_memory();
	ofp_stat_lookup_shared_memory();
	ofp_socket_lookup_shared_memory();
	ofp_timer_lookup_shared_memory();
	ofp_hook_lookup_shared_memory();
	ofp_arp_lookup_shared_memory();

	ofp_arp_init_local();

	return 0;
}
