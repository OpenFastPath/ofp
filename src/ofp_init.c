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

#if ODP_VERSION == 103
#include "linux.h"
#else
#include "odp/helper/linux.h"
#endif

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

#define SHM_NAME_GLOBAL_CONFIG "OfpGlobalConfigShMem"
#define SHM_PACKET_POOL_NAME "packet_pool"


static __thread struct ofp_global_config_mem *shm;

static void schedule_shutdown(void);
static void cleanup_pkt_queue(odp_queue_t pkt_queue);

static int ofp_global_config_alloc_shared_memory(void)
{
	shm = ofp_shared_memory_alloc(SHM_NAME_GLOBAL_CONFIG, sizeof(*shm));
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}
	return 0;
}

static int ofp_global_config_free_shared_memory(void)
{
	int rc = 0;

	if (ofp_shared_memory_free(SHM_NAME_GLOBAL_CONFIG) == -1) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}
	shm = NULL;
	return rc;
}

static int ofp_global_config_lookup_shared_memory(void)
{
	shm = ofp_shared_memory_lookup(SHM_NAME_GLOBAL_CONFIG);
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}

	return 0;
}

struct ofp_global_config_mem *ofp_get_global_config(void)
{
	if (ofp_global_config_lookup_shared_memory() == -1)
		return NULL;
	return shm;
}

static void ofp_stop(void)
{
	shm->is_running = 0;
}

int ofp_init_pre_global(const char *pool_name,
			       odp_pool_param_t *pool_params,
			       ofp_pkt_hook hooks[], odp_pool_t *pool)
{
	/* Init shared memories */

	HANDLE_ERROR(ofp_global_config_alloc_shared_memory());
	memset(shm, 0, sizeof(*shm));
	shm->is_running = 1;
#ifdef SP
	shm->nl_thread_is_running = 0;
#endif /* SP */
	shm->cli_thread_is_running = 0;

	ofp_register_sysctls();

	HANDLE_ERROR(ofp_avl_init_global());

	HANDLE_ERROR(ofp_reassembly_init_global());

	HANDLE_ERROR(ofp_pcap_init_global());

	HANDLE_ERROR(ofp_stat_init_global());

	HANDLE_ERROR(ofp_timer_init_global(OFP_TIMER_RESOLUTION_US,
			OFP_TIMER_MIN_US,
			OFP_TIMER_MAX_US,
			OFP_TIMER_TMO_COUNT));

	HANDLE_ERROR(ofp_hook_init_global(hooks));

	HANDLE_ERROR(ofp_arp_init_global());

	HANDLE_ERROR(ofp_route_init_global());

	HANDLE_ERROR(ofp_portconf_init_global());

	HANDLE_ERROR(ofp_vxlan_init_global());

	*pool = ofp_pool_create(pool_name, pool_params);
	if (*pool == ODP_POOL_INVALID) {
		OFP_ERR("odp_pool_create failed");
		return -1;
	}

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

#if ODP_VERSION >= 103
	odp_pktio_param_t pktio_param;
	memset(&pktio_param, 0, sizeof(pktio_param));
	pktio_param.in_mode = (params->burst_recv_mode) ? ODP_PKTIN_MODE_RECV : ODP_PKTIN_MODE_SCHED;
#endif

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

		if (!ifnet) {
			OFP_ERR("Failed to locate interface for port %d", port);
			return -1;
		}

		ifnet->if_state = OFP_IFT_STATE_USED;

		strncpy(ifnet->if_name, params->if_names[i], OFP_IFNAMSIZ);
		ifnet->if_name[OFP_IFNAMSIZ-1] = 0;
		ifnet->pkt_pool = ofp_packet_pool;

		/* Open a packet IO instance for this device */
#if ODP_VERSION >= 103
		ifnet->pktio = odp_pktio_open(ifnet->if_name, ifnet->pkt_pool, &pktio_param);
#else
		ifnet->pktio = odp_pktio_open(ifnet->if_name, ifnet->pkt_pool);
#endif

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
		} else
			ifnet->inq_def = ODP_QUEUE_INVALID;

		ifnet->outq_def = odp_pktio_outq_getdef(ifnet->pktio);
		if (ifnet->outq_def == ODP_QUEUE_INVALID) {
			OFP_ERR("odp_pktio_outq_getdef failed");
			return -1;
		}

		/* Set device outq queue context */
		if (odp_queue_context_set(ifnet->outq_def, ifnet) < 0) {
			OFP_ERR("odp_queue_context_set failed");
			return -1;
		}

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
		if (odp_queue_context_set(ifnet->loopq_def, ifnet) < 0) {
			OFP_ERR("odp_queue_context_set failed");
			return -1;
		}

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
		/* Start packet receiver or transmitter */
		odp_pktio_start(ifnet->pktio);
	}


#ifdef SP
	/* Start Netlink server process */
	if (!odph_linux_pthread_create(&shm->nl_thread,
				  &cpumask,
				  START_NL_SERVER,
				  NULL)) {
		OFP_ERR("Failed to start Netlink thread.");
		return -1;
	}
	shm->nl_thread_is_running = 1;
#endif /* SP */

	odp_schedule_resume();
	return 0;
}


int ofp_init_local(void)
{
	/* Lookup shared memories */
	HANDLE_ERROR(ofp_global_config_lookup_shared_memory());
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
	uint16_t i;
	struct ofp_ifnet *ifnet;

	ofp_stop();

	/* Terminate CLI thread*/
	CHECK_ERROR(ofp_stop_cli_thread(), rc);

#ifdef SP
	/* Terminate Netlink thread*/
	if (shm->nl_thread_is_running) {
		odph_linux_pthread_join(&shm->nl_thread, 1);
		shm->nl_thread_is_running = 0;
	}
#endif /* SP */

	/* Cleanup interfaces: queues and pktios*/
	for (i = 0; i < VXLAN_PORTS; i++) {
		ifnet = ofp_get_ifnet((uint16_t)i, 0);
		if (!ifnet) {
			OFP_ERR("Failed to locate interface for port %d", i);
			rc = -1;
			continue;
		}
		if (ifnet->if_state == OFP_IFT_STATE_FREE)
			continue;

		if (ifnet->pktio == ODP_PKTIO_INVALID)
			continue;

		OFP_INFO("Cleaning device '%s' addr %s", ifnet->if_name,
			ofp_print_mac((uint8_t *)ifnet->mac));

		CHECK_ERROR(odp_pktio_stop(ifnet->pktio), rc);
#ifdef SP
		close(ifnet->fd);
		odph_linux_pthread_join(ifnet->rx_tbl, 1);
		odph_linux_pthread_join(ifnet->tx_tbl, 1);
		ifnet->fd = -1;
#endif /*SP*/

		/* Multicasting. */
		ofp_igmp_domifdetach(ifnet);
		ifnet->ii_inet.ii_igmp = NULL;

		if (ifnet->loopq_def != ODP_QUEUE_INVALID) {
			if (odp_queue_destroy(ifnet->loopq_def) < 0) {
				OFP_ERR("Failed to destroy loop queue for %s",
					ifnet->if_name);
				rc = -1;
			}
			ifnet->loopq_def = ODP_QUEUE_INVALID;
		}
#ifdef SP
		if (ifnet->spq_def != ODP_QUEUE_INVALID) {
			cleanup_pkt_queue(ifnet->spq_def);
			if (odp_queue_destroy(ifnet->spq_def) < 0) {
				OFP_ERR("Failed to destroy slow path "
					"queue for %s", ifnet->if_name);
				rc = -1;
			}
			ifnet->spq_def = ODP_QUEUE_INVALID;
		}
#endif /*SP*/
		ifnet->outq_def = ODP_QUEUE_INVALID;

		if (ifnet->pktio != ODP_PKTIO_INVALID) {
			if (odp_pktio_close(ifnet->pktio) < 0) {
				OFP_ERR("Failed to destroy pktio for %s",
					ifnet->if_name);
				rc = -1;
			}
			ifnet->pktio = ODP_PKTIO_INVALID;
		}

		if (ifnet->inq_def != ODP_QUEUE_INVALID) {
			cleanup_pkt_queue(ifnet->inq_def);
			if (odp_queue_destroy(ifnet->inq_def) < 0) {
				OFP_ERR("Failed to destroy default input "
					"queue for %s", ifnet->if_name);
				rc = -1;
			}
			ifnet->inq_def = ODP_QUEUE_INVALID;
		}
	}

	CHECK_ERROR(ofp_clean_vxlan_interface_queue(), rc);

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
	CHECK_ERROR(ofp_socket_term_global(), rc);

	/* Cleanup vxlan */
	CHECK_ERROR(ofp_vxlan_term_global(), rc);

	/* Cleanup interface related objects */
	CHECK_ERROR(ofp_portconf_term_global(), rc);

	/* Cleanup routes */
	CHECK_ERROR(ofp_route_term_global(), rc);

	/* Cleanup ARP*/
	CHECK_ERROR(ofp_arp_term_global(), rc);

	/* Cleanup hooks */
	CHECK_ERROR(ofp_hook_term_global(), rc);

	/* Cleanup stats */
	CHECK_ERROR(ofp_stat_term_global(), rc);

	/* Cleanup packet capture */
	CHECK_ERROR(ofp_pcap_term_global(), rc);

	/* Cleanup reassembly queues*/
	CHECK_ERROR(ofp_reassembly_term_global(), rc);

	/* Cleanup avl trees*/
	CHECK_ERROR(ofp_avl_term_global(), rc);

	/* Cleanup timers - phase 1*/
	CHECK_ERROR(ofp_timer_stop_global(), rc);

	/* Cleanup pending events */
	schedule_shutdown();

	/* Cleanup timers - phase 2*/
	CHECK_ERROR(ofp_timer_term_global(), rc);

	/* Cleanup packet pool */
	pool = odp_pool_lookup(pool_name);
	if (pool == ODP_POOL_INVALID) {
		OFP_ERR("Failed to locate pool %s\n", pool_name);
		rc = -1;
	} else if (odp_pool_destroy(pool) < 0) {
		OFP_ERR("Failed to destroy pool %s.\n", pool_name);
		rc = -1;
		pool = ODP_POOL_INVALID;
	}

	CHECK_ERROR(ofp_global_config_free_shared_memory(), rc);

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

static void cleanup_pkt_queue(odp_queue_t pkt_queue)
{
	odp_event_t evt;

	while (1) {
		evt = odp_queue_deq(pkt_queue);
		if (evt == ODP_EVENT_INVALID)
			break;
		odp_packet_free(odp_packet_from_event(evt));
	}
}
