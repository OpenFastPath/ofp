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
#include "odp/helper/linux.h"

#include "ofpi_config.h"
#include "ofpi_init.h"
#include "ofpi_sysctl.h"
#include "ofpi_util.h"
#include "ofpi_stat.h"
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
#include "ofpi_igmp_var.h"
#include "ofpi_vxlan.h"

#include "ofpi_log.h"
#include "ofpi_debug.h"

#define SHM_PACKET_POOL_NAME "packet_pool"

static void schedule_shutdown(void);

int ofp_init_pre_global(const char *pool_name,
			       odp_pool_param_t *pool_params,
			       ofp_pkt_hook hooks[], odp_pool_t *pool)
{
	/* Init shared memories */
	ofp_register_sysctls();

	HANDLE_ERROR(ofp_avl_init_global());

	HANDLE_ERROR(ofp_reassembly_init_global());

	HANDLE_ERROR(ofp_pcap_init_global());

	HANDLE_ERROR(ofp_stat_init_global());

	HANDLE_ERROR(ofp_timer_alloc_shared_memory());
	HANDLE_ERROR(ofp_timer_init_global(OFP_TIMER_RESOLUTION_US,
			OFP_TIMER_MIN_US,
			OFP_TIMER_MAX_US,
			OFP_TIMER_TMO_COUNT));

	HANDLE_ERROR(ofp_hook_alloc_shared_memory());
	HANDLE_ERROR(ofp_hook_init_global(hooks));

	HANDLE_ERROR(ofp_arp_alloc_shared_memory());
	HANDLE_ERROR(ofp_arp_init_global());

	HANDLE_ERROR(ofp_route_alloc_shared_memory());
	HANDLE_ERROR(ofp_route_init_global());

	HANDLE_ERROR(ofp_portconf_alloc_shared_memory());
	HANDLE_ERROR(ofp_portconf_init_global());

	HANDLE_ERROR(ofp_vxlan_alloc_shared_memory());
	HANDLE_ERROR(ofp_vxlan_init_global());

	*pool = odp_pool_create(pool_name, pool_params);
	if (*pool == ODP_POOL_INVALID) {
		OFP_ERR("odp_pool_create failed");
		return -1;
	}

	HANDLE_ERROR(ofp_socket_alloc_shared_memory());
	HANDLE_ERROR(ofp_socket_init_global(*pool));
	HANDLE_ERROR(ofp_inet_init());

	return 0;
}

odp_pool_t ofp_packet_pool;

int ofp_init_global(ofp_init_global_t *params)
{
	odp_pool_param_t pool_params;
	int i, ret;
	odp_queue_param_t qparam;
	char q_name[ODP_QUEUE_NAME_LEN];
	odp_cpumask_t cpumask;
	odp_pktio_param_t pktio_param;
#ifdef SP
	odph_linux_pthread_t nl_thread;
#endif /* SP */

	/* Define pkt.seg_len so that l2/l3/l4 offset fits in first segment */
	pool_params.pkt.seg_len    = SHM_PKT_POOL_BUFFER_SIZE;
	pool_params.pkt.len        = SHM_PKT_POOL_BUFFER_SIZE;
	pool_params.pkt.num        = SHM_PKT_POOL_SIZE / SHM_PKT_POOL_BUFFER_SIZE;
	pool_params.pkt.uarea_size = SHM_PKT_POOL_USER_AREA_SIZE;
	pool_params.type           = ODP_POOL_PACKET;

	HANDLE_ERROR(ofp_init_pre_global(SHM_PACKET_POOL_NAME, &pool_params,
		params->pkt_hook, &ofp_packet_pool));

	/* cpu mask for slow path threads */
	odp_cpumask_zero(&cpumask);
	odp_cpumask_set(&cpumask, params->linux_core_id);

	OFP_INFO("Slow path threads on core %d", odp_cpumask_first(&cpumask));

	memset(&pktio_param, 0, sizeof(pktio_param));
	pktio_param.in_mode = (params->burst_recv_mode) ? ODP_PKTIN_MODE_RECV : ODP_PKTIN_MODE_SCHED;

	HANDLE_ERROR(ofp_set_vxlan_interface_queue());

	/* Create interfaces */
	for (i = 0; i < params->if_count; ++i) {
		int16_t port = i;

		if (port >= VXLAN_PORTS) {
			OFP_ERR("Interfaces are depleted");
			break;
		}

		OFP_DBG("Interface '%s' becomes '%s%d', port %d",
			params->if_names[i], OFP_IFNAME_PREFIX, port, port);

		struct ofp_ifnet *ifnet = ofp_get_ifnet((uint16_t)port, 0);

		strncpy(ifnet->if_name, params->if_names[i], OFP_IFNAMSIZ);
		ifnet->if_name[OFP_IFNAMSIZ-1] = 0;
		ifnet->pkt_pool = ofp_packet_pool;

		/* Open a packet IO instance for this device */
		ifnet->pktio = odp_pktio_open(ifnet->if_name, ifnet->pkt_pool, &pktio_param);
		if (ifnet->pktio == ODP_PKTIO_INVALID) {
			OFP_ERR("odp_pktio_open failed");
			return -1;
		}


		/*
		 * Create and set the default INPUT queue associated with the 'pktio'
		 * resource
		 */
		if (params->burst_recv_mode == 0) {
			memset(&qparam, 0, sizeof(odp_queue_param_t));
			qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
			qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
			qparam.sched.group = ODP_SCHED_GROUP_ALL;
			snprintf(q_name, sizeof(q_name), "%" PRIu64 "-pktio_inq_def",
				 odp_pktio_to_u64(ifnet->pktio));
			q_name[ODP_QUEUE_NAME_LEN - 1] = '\0';

			ifnet->inq_def = odp_queue_create(q_name,
							  ODP_QUEUE_TYPE_PKTIN,
							  &qparam);
			if (ifnet->inq_def == ODP_QUEUE_INVALID) {
				OFP_ERR("odp_queue_create failed");
				return -1;
			}

			ret = odp_pktio_inq_setdef(ifnet->pktio, ifnet->inq_def);
			if (ret != 0) {
				OFP_ERR("odp_pktio_inq_setdef failed");
				return -1;
			}
		}

		ifnet->outq_def = odp_pktio_outq_getdef(ifnet->pktio);
		if (ifnet->outq_def == ODP_QUEUE_INVALID) {
			OFP_ERR("odp_pktio_outq_getdef failed");
			return -1;
		}

		/* Set device outq queue context */
		odp_queue_context_set(ifnet->outq_def, ifnet);

#ifdef SP
		/* Create VIF local input queue */
		memset(&qparam, 0, sizeof(odp_queue_param_t));
		qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
		qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
		qparam.sched.group = ODP_SCHED_GROUP_ALL;
		snprintf(q_name, sizeof(q_name), "%s_inq_def", ifnet->if_name);
		q_name[ODP_QUEUE_NAME_LEN - 1] = '\0';

		ifnet->spq_def = odp_queue_create(q_name,
						ODP_QUEUE_TYPE_POLL,
						&qparam);

		if (ifnet->spq_def == ODP_QUEUE_INVALID) {
			OFP_ERR("odp_queue_create failed");
			return -1;
		}
#endif /*SP*/

		/* Create loop queue */
		snprintf(q_name, sizeof(q_name), "%s_loopq_def",
				ifnet->if_name);
		q_name[ODP_QUEUE_NAME_LEN - 1] = '\0';

		memset(&qparam, 0, sizeof(odp_queue_param_t));
		qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
		qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
		qparam.sched.group = ODP_SCHED_GROUP_ALL;

		ifnet->loopq_def = odp_queue_create(q_name,
						ODP_QUEUE_TYPE_SCHED,
						&qparam);
		if (ifnet->loopq_def == ODP_QUEUE_INVALID) {
			OFP_ERR("odp_queue_create failed");
			return -1;
		}

		/* Set device loopq queue context */
		odp_queue_context_set(ifnet->loopq_def, ifnet);

		/* Set interface MTU*/
		ifnet->if_mtu = odp_pktio_mtu(ifnet->pktio);
		OFP_INFO("Device '%s' MTU=%d", ifnet->if_name, ifnet->if_mtu);

		/* RFC 791, p. 24, "Every internet module must be able
		 * to forward a datagram of 68 octets without further
		 * fragmentation."*/
		if (ifnet->if_mtu < 68 || ifnet->if_mtu > 9000) {
			OFP_INFO("Invalid MTU. Overwrite MTU value to 1500");
			ifnet->if_mtu = 1500;
		}

		/* Set interface MAC address */
		if (odp_pktio_mac_addr(ifnet->pktio, ifnet->mac,
			sizeof(ifnet->mac)) < 0) {
			OFP_ERR("Failed to retrieve MAC address");
			return -1;
		}
		if (!ofp_has_mac(ifnet->mac)) {
			ifnet->mac[0] = port;
			OFP_ERR("MAC overwritten");
		}
		OFP_INFO("Device '%s' addr %s", ifnet->if_name,
			ofp_print_mac((uint8_t *)ifnet->mac));

		/* Multicasting. */
		struct ofp_in_ifinfo *ii = &ifnet->ii_inet;
		ii->ii_igmp = ofp_igmp_domifattach(ifnet);

#ifdef SP
		/* Create the kernel representation of the FP interface. */
		ifnet->fd = sp_setup_device(ifnet);
		if (ifnet->fd == -1) {
			OFP_ERR("Failed to setup TAP interface.");
			return -1;
		}

		/* Maintain table to access ifnet from linux ifindex */
		ofp_update_ifindex_lookup_tab(ifnet);

#ifdef INET6
		/* ifnet MAC was set in sp_setup_device() */
		ofp_mac_to_link_local(ifnet->mac, ifnet->link_local);
#endif /* INET6 */

		/* Start packet receiver or transmitter */
		odp_pktio_start(ifnet->pktio);

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
		ifnet->if_state = OFP_IFT_STATE_USED;
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
	HANDLE_ERROR(ofp_portconf_lookup_shared_memory());
	HANDLE_ERROR(ofp_route_lookup_shared_memory());
	HANDLE_ERROR(ofp_avl_lookup_shared_memory());
	HANDLE_ERROR(ofp_reassembly_lookup_shared_memory());
	HANDLE_ERROR(ofp_pcap_lookup_shared_memory());
	HANDLE_ERROR(ofp_stat_lookup_shared_memory());
	HANDLE_ERROR(ofp_socket_lookup_shared_memory());
	HANDLE_ERROR(ofp_timer_lookup_shared_memory());
	HANDLE_ERROR(ofp_hook_lookup_shared_memory());
	HANDLE_ERROR(ofp_arp_lookup_shared_memory());
	HANDLE_ERROR(ofp_vxlan_lookup_shared_memory());

	HANDLE_ERROR(ofp_arp_init_local());

	return 0;
}

int ofp_term_global(void)
{
	int rc = 0;

	if (ofp_term_post_global(SHM_PACKET_POOL_NAME)) {
		OFP_ERR("Failed to cleanup resources\n");
		rc = -1;
	}

	return rc;
}

int ofp_term_post_global(const char *pool_name)
{
	odp_pool_t pool;
	int rc = 0;

	if (ofp_inet_term()) {
		OFP_ERR("Failed to cleanup inet/inet6 domains.\n");
		rc = -1;
	}

	/* Cleanup sockets */
	ofp_socket_term_global();
	ofp_socket_free_shared_memory();

	/* Cleanup vxlan */
	ofp_vxlan_term_global();
	ofp_vxlan_free_shared_memory();

	/* Cleanup interface related objects */
	ofp_portconf_term_global();
	ofp_portconf_free_shared_memory();

	/* Cleanup routes */
	ofp_route_term_global();
	ofp_route_free_shared_memory();

	/* Cleanup ARP*/
	ofp_arp_term_global();
	ofp_arp_free_shared_memory();

	/* Cleanup hooks */
	ofp_hook_term_global();
	ofp_hook_free_shared_memory();

	/* Cleanup stats */
	CHECK_ERROR(ofp_stat_term_global(), rc);

	/* Cleanup packet capture */
	CHECK_ERROR(ofp_pcap_term_global(), rc);

	/* Cleanup reassembly queues*/
	CHECK_ERROR(ofp_reassembly_term_global(), rc);

	/* Cleanup avl trees*/
	CHECK_ERROR(ofp_avl_term_global(), rc);

	/* Cleanup timers - phase 1*/
	ofp_timer_stop_global();

	/* Cleanup pending events */
	schedule_shutdown();

	/* Cleanup timers - phase 2*/
	ofp_timer_term_global();
	ofp_timer_free_shared_memory();

	/* Cleanup packet pool */
	pool = odp_pool_lookup(pool_name);
	if (pool == ODP_POOL_INVALID) {
		OFP_ERR("Failed to locate pool %s\n", pool_name);
		rc = -1;
	} else {
		odp_pool_destroy(pool);
		pool = ODP_POOL_INVALID;
	}

	return rc;
}

int ofp_term_local(void)
{
	return 0;
}

static void schedule_shutdown(void)
{
	odp_event_t evt;
	odp_queue_t from;

	while (1) {
		evt = odp_schedule(&from, ODP_SCHED_NO_WAIT);
		if (evt == ODP_EVENT_INVALID)
			break;
		switch (odp_event_type(evt)) {
		case ODP_EVENT_TIMEOUT:
			{
				ofp_timer_evt_cleanup(evt);
				break;
			}
		case ODP_EVENT_PACKET:
			{
				odp_packet_free(odp_packet_from_event(evt));
				break;
			}
		case ODP_EVENT_BUFFER:
			{
				odp_buffer_free(odp_buffer_from_event(evt));
				break;
			}
		case ODP_EVENT_CRYPTO_COMPL:
			{
				odp_crypto_compl_free(
					odp_crypto_compl_from_event(evt));
				break;
			}
		}
	}

	odp_schedule_pause();
}
