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

#include "ofpi.h"
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
#include "ofpi_ifnet.h"

#include "ofpi_tcp_var.h"
#include "ofpi_socketvar.h"
#include "ofpi_socket.h"
#include "ofpi_reass.h"
#include "ofpi_inet.h"
#include "ofpi_igmp_var.h"
#include "ofpi_vxlan.h"
#include "ofpi_uma.h"

#include "ofpi_log.h"
#include "ofpi_debug.h"

static __thread struct ofp_global_config_mem *shm;

__thread ofp_global_param_t *global_param = NULL;

static void schedule_shutdown(void);
static void cleanup_pkt_queue(odp_queue_t pkt_queue);

static int ofp_global_config_alloc_shared_memory(void)
{
	shm = ofp_shared_memory_alloc(SHM_NAME_GLOBAL_CONFIG, sizeof(*shm));
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}
	global_param = &shm->global_param;
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
	global_param = &shm->global_param;

	return 0;
}

struct ofp_global_config_mem *ofp_get_global_config(void)
{
	if (ofp_global_config_lookup_shared_memory() == -1)
		return NULL;
	return shm;
}

void ofp_stop_processing(void)
{
	shm->is_running = 0;
}

odp_bool_t *ofp_get_processing_state(void)
{
	if (ofp_global_config_lookup_shared_memory() == -1)
		return NULL;
	return &shm->is_running;
}

void ofp_init_global_param(ofp_global_param_t *params)
{
	memset(params, 0, sizeof(*params));
	params->sched_group = ODP_SCHED_GROUP_ALL;
#ifdef SP
	params->enable_nl_thread = 1;
#endif /* SP */
	params->arp.age_interval = ARP_AGE_INTERVAL;
	params->arp.entry_timeout = ARP_ENTRY_TIMEOUT;
	params->evt_rx_burst_size = OFP_EVT_RX_BURST_SIZE;
	params->pcb_tcp_max = OFP_NUM_PCB_TCP_MAX;
	params->pkt_pool_nb_pkts = SHM_PKT_POOL_NB_PKTS;
	params->pkt_pool_buffer_size = SHM_PKT_POOL_BUFFER_SIZE;
}

static int ofp_init_pre_global(ofp_global_param_t *params)
{
	/* Init shared memories */
	HANDLE_ERROR(ofp_uma_init_global());

	HANDLE_ERROR(ofp_global_config_alloc_shared_memory());
	memset(shm, 0, sizeof(*shm));
	shm->is_running = 1;
#ifdef SP
	shm->nl_thread_is_running = 0;
#endif /* SP */
	shm->cli_thread_is_running = 0;

	*global_param = *params;

	ofp_register_sysctls();

	HANDLE_ERROR(ofp_avl_init_global());

	HANDLE_ERROR(ofp_reassembly_init_global());

	HANDLE_ERROR(ofp_pcap_init_global());

	HANDLE_ERROR(ofp_stat_init_global());

	HANDLE_ERROR(ofp_timer_init_global(OFP_TIMER_RESOLUTION_US,
			OFP_TIMER_MIN_US,
			OFP_TIMER_MAX_US,
			OFP_TIMER_TMO_COUNT,
			params->sched_group));

	HANDLE_ERROR(ofp_hook_init_global(params->pkt_hook));

	HANDLE_ERROR(ofp_arp_init_global(params->arp.age_interval,
			params->arp.entry_timeout));

	HANDLE_ERROR(ofp_route_init_global());

	HANDLE_ERROR(ofp_portconf_init_global());

	HANDLE_ERROR(ofp_vlan_init_global());

	HANDLE_ERROR(ofp_vxlan_init_global());

	odp_pool_param_t pool_params;
	odp_pool_param_init(&pool_params);
	/* Define pkt.seg_len so that l2/l3/l4 offset fits in first segment */
	pool_params.pkt.seg_len    = global_param->pkt_pool_buffer_size;
	pool_params.pkt.len        = global_param->pkt_pool_buffer_size;
	pool_params.pkt.num        = params->pkt_pool_nb_pkts;
	pool_params.pkt.uarea_size = SHM_PKT_POOL_USER_AREA_SIZE;
	pool_params.type           = ODP_POOL_PACKET;

	ofp_packet_pool = ofp_pool_create(SHM_PKT_POOL_NAME, &pool_params);
	if (ofp_packet_pool == ODP_POOL_INVALID) {
		OFP_ERR("odp_pool_create failed");
		return -1;
	}

	HANDLE_ERROR(ofp_socket_init_global(ofp_packet_pool));
	HANDLE_ERROR(ofp_tcp_var_init_global());
	HANDLE_ERROR(ofp_inet_init());

	return 0;
}

odp_pool_t ofp_packet_pool;
odp_cpumask_t cpumask;
int ofp_init_global_called = 0;

int ofp_init_global(odp_instance_t instance, ofp_global_param_t *params)
{
	int i;
	odp_pktio_param_t pktio_param;
	odp_pktin_queue_param_t pktin_param;

	ofp_init_global_called = 1;

	HANDLE_ERROR(ofp_init_pre_global(params));

	/* cpu mask for slow path threads */
	odp_cpumask_zero(&cpumask);
	odp_cpumask_set(&cpumask, params->linux_core_id);

	OFP_INFO("Slow path threads on core %d", odp_cpumask_first(&cpumask));

	HANDLE_ERROR(ofp_set_vxlan_interface_queue());

	/* Create interfaces */
	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = params->burst_recv_mode ? ODP_PKTIN_MODE_DIRECT :
						ODP_PKTIN_MODE_SCHED;
	pktio_param.out_mode = ODP_PKTOUT_MODE_DIRECT;

	ofp_pktin_queue_param_init(&pktin_param, pktio_param.in_mode,
			params->sched_group);

	for (i = 0; i < params->if_count; ++i)
		HANDLE_ERROR(ofp_ifnet_create(instance, params->if_names[i],
			&pktio_param, &pktin_param, NULL));

#ifdef SP
	if (params->enable_nl_thread) {
		odph_linux_thr_params_t thr_params;

		/* Start Netlink server process */
		thr_params.start = START_NL_SERVER;
		thr_params.arg = NULL;
		thr_params.thr_type = ODP_THREAD_CONTROL;
		thr_params.instance = instance;
		if (!odph_linux_pthread_create(&shm->nl_thread, &cpumask, &thr_params)) {
			OFP_ERR("Failed to start Netlink thread.");
			return -1;
		}
		shm->nl_thread_is_running = 1;
	}
#endif /* SP */

	odp_schedule_resume();
	return 0;
}


int ofp_init_local(void)
{
	/* Lookup shared memories */
	HANDLE_ERROR(ofp_uma_lookup_shared_memory());
	HANDLE_ERROR(ofp_global_config_lookup_shared_memory());
	HANDLE_ERROR(ofp_portconf_lookup_shared_memory());
	HANDLE_ERROR(ofp_vlan_lookup_shared_memory());
	HANDLE_ERROR(ofp_route_lookup_shared_memory());
	HANDLE_ERROR(ofp_vrf_route_lookup_shared_memory());
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
	HANDLE_ERROR(ofp_tcp_var_lookup_shared_memory());
	HANDLE_ERROR(ofp_send_pkt_out_init_local());

	return 0;
}

int ofp_term_global(void)
{
	int rc = 0;
	uint16_t i, j;
	struct ofp_ifnet *ifnet;

	ofp_stop_processing();

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
	for (i = 0; PHYS_PORT(i); i++) {
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
		odph_linux_pthread_join(ifnet->rx_tbl, 1);
		odph_linux_pthread_join(ifnet->tx_tbl, 1);
		close(ifnet->fd);
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
		for (j = 0; j < OFP_PKTOUT_QUEUE_MAX; j++)
			ifnet->out_queue_queue[j] = ODP_QUEUE_INVALID;

		if (ifnet->pktio != ODP_PKTIO_INVALID) {
			odp_queue_t in_queue[OFP_PKTIN_QUEUE_MAX];
			int num_in_queue, idx;

			num_in_queue = odp_pktin_event_queue(ifnet->pktio,
					in_queue, OFP_PKTIN_QUEUE_MAX);
			for (idx = 0; idx < num_in_queue; idx++)
				cleanup_pkt_queue(in_queue[idx]);

			if (odp_pktio_close(ifnet->pktio) < 0) {
				OFP_ERR("Failed to destroy pktio for %s",
					ifnet->if_name);
				rc = -1;
			}
			ifnet->pktio = ODP_PKTIO_INVALID;
		}

	}

	CHECK_ERROR(ofp_clean_vxlan_interface_queue(), rc);
	CHECK_ERROR(ofp_local_interfaces_destroy(), rc);

	if (ofp_term_post_global(SHM_PKT_POOL_NAME)) {
		OFP_ERR("Failed to cleanup resources\n");
		rc = -1;
	}

	return rc;
}

int ofp_term_post_global(const char *pool_name)
{
	odp_pool_t pool;
	int rc = 0;

	ofp_igmp_uninit(NULL);

	/* Cleanup sockets */
	CHECK_ERROR(ofp_socket_term_global(), rc);

	/* Cleanup of TCP content */
	CHECK_ERROR(ofp_tcp_var_term_global(), rc);

	/* Cleanup vxlan */
	CHECK_ERROR(ofp_vxlan_term_global(), rc);

	/* Cleanup interface related objects */
	CHECK_ERROR(ofp_vlan_term_global(), rc);
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
	CHECK_ERROR(ofp_unregister_sysctls(), rc);

	CHECK_ERROR(ofp_uma_term_global(), rc);

	return rc;
}

int ofp_term_local(void)
{
	int rc = 0;

	CHECK_ERROR(ofp_send_pkt_out_term_local(), rc);

	return rc;
}

static void schedule_shutdown(void)
{
	odp_event_t evt;
	odp_queue_t from;

	while (1) {
		/* should be called from a thread within OFP's schedule group */
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
		if (odp_event_type(evt) == ODP_EVENT_PACKET)
			odp_packet_free(odp_packet_from_event(evt));
	}
}
