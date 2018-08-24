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
#include <odp_api.h>

#include "ofp_cli.h"

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
#include "ofpi_pkt_processing.h"
#include "ofpi_ifnet.h"
#include "ofpi_ip.h"
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

static void drain_scheduler(void);
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
	if (shm)
		shm->is_running = 0;
}

odp_bool_t *ofp_get_processing_state(void)
{
	if (ofp_global_config_lookup_shared_memory() == -1)
		return NULL;
	return &shm->is_running;
}

#ifdef OFP_USE_LIBCONFIG

#include <ctype.h>
#include <libconfig.h>

#define OFP_CONF_FILE_ENV "OFP_CONF_FILE"
#define STR(x) #x

struct lookup_entry {
	const char *name;
	int value;
};

#define ENTRY(x) { #x, (int)x }

struct lookup_entry lt_pktin_mode[] = {
	ENTRY(ODP_PKTIN_MODE_DIRECT),
	ENTRY(ODP_PKTIN_MODE_SCHED),
	ENTRY(ODP_PKTIN_MODE_QUEUE),
	ENTRY(ODP_PKTIN_MODE_DISABLED),
};

struct lookup_entry lt_pktout_mode[] = {
	ENTRY(ODP_PKTOUT_MODE_DIRECT),
	ENTRY(ODP_PKTOUT_MODE_QUEUE),
	ENTRY(ODP_PKTOUT_MODE_TM),
	ENTRY(ODP_PKTOUT_MODE_DISABLED),
};

struct lookup_entry lt_sched_sync[] = {
	ENTRY(ODP_SCHED_SYNC_PARALLEL),
	ENTRY(ODP_SCHED_SYNC_ATOMIC),
	ENTRY(ODP_SCHED_SYNC_ORDERED),
};

struct lookup_entry lt_sched_group[] = {
	ENTRY(ODP_SCHED_GROUP_ALL),
	ENTRY(ODP_SCHED_GROUP_WORKER),
	ENTRY(ODP_SCHED_GROUP_CONTROL),
};

/*
 * Based on a string, lookup a value in a struct lookup_entry
 * array. Return the value from the entry or -1 if not found.
 */
static int lookup(const struct lookup_entry *table, int n, const char *str)
{
#define BUF_LEN 32
	int i, len = strnlen(str, BUF_LEN-1);
	char ustr[BUF_LEN];

	memcpy(ustr, str, len);
	ustr[len] = 0;

	for (i = 0; i < len; i++)
		ustr[i] = toupper(ustr[i]);

	for (i = 0; i < n; i++)
		if (strstr(table[i].name, ustr))
			return table[i].value;

	return -1;
}

static void read_conf_file(ofp_global_param_t *params, const char *filename)
{
	config_t conf;
	config_setting_t *setting;
	int length;
	const char *str;
	int i;

	if (!filename) {
		filename = OFP_DEFAULT_CONF_FILE;
		char *filename_env = getenv(OFP_CONF_FILE_ENV);
		if (filename_env) filename = filename_env;
	}

	if (!*filename) return;

	config_init(&conf);
	OFP_DBG("Using configuration file: %s\n", filename);

	if (!config_read_file(&conf, filename)) {
		OFP_ERR("%s(%d): %s\n", config_error_file(&conf),
			config_error_line(&conf), config_error_text(&conf));
		goto done;
	}

	setting = config_lookup(&conf, "ofp_global_param.if_names");

	if (setting && (length = config_setting_length(setting)) > 0) {
		params->if_count = 0;
		params->if_names = malloc(length * sizeof(char *));
		while (params->if_count < length) {
			/* These strings are never freed. */
			params->if_names[params->if_count] =
				strndup(config_setting_get_string_elem(setting, params->if_count), OFP_IFNAMSIZ);
			params->if_count++;
		}
	}

#define GET_CONF_STR(p)							\
	if (config_lookup_string(&conf, "ofp_global_param." STR(p), &str)) { \
		i = lookup(lt_ ## p, sizeof(lt_ ## p) / sizeof(lt_ ## p[0]), str); \
		if (i >= 0) params->p = i;				\
	}

	GET_CONF_STR(pktin_mode);
	GET_CONF_STR(pktout_mode);
	GET_CONF_STR(sched_sync);
	GET_CONF_STR(sched_group);

#define GET_CONF_INT(type, p)						\
	if (config_lookup_ ## type(&conf, "ofp_global_param." STR(p), &i)) \
		params->p = i;

	GET_CONF_INT(int, linux_core_id);
	GET_CONF_INT(bool, enable_nl_thread);
	GET_CONF_INT(int, arp.entries);
	GET_CONF_INT(int, arp.hash_bits);
	GET_CONF_INT(int, arp.entry_timeout);
	GET_CONF_INT(int, arp.saved_pkt_timeout);
	GET_CONF_INT(bool, arp.check_interface);
	GET_CONF_INT(int, evt_rx_burst_size);
	GET_CONF_INT(int, pkt_tx_burst_size);
	GET_CONF_INT(int, pcb_tcp_max);
	GET_CONF_INT(int, pkt_pool.nb_pkts);
	GET_CONF_INT(int, pkt_pool.buffer_size);
	GET_CONF_INT(int, num_vlan);
	GET_CONF_INT(int, mtrie.routes);
	GET_CONF_INT(int, mtrie.table8_nodes);
	GET_CONF_INT(int, num_vrf);
	GET_CONF_INT(bool, chksum_offload.ipv4_rx_ena);
	GET_CONF_INT(bool, chksum_offload.udp_rx_ena);
	GET_CONF_INT(bool, chksum_offload.tcp_rx_ena);
	GET_CONF_INT(bool, chksum_offload.ipv4_tx_ena);
	GET_CONF_INT(bool, chksum_offload.udp_tx_ena);
	GET_CONF_INT(bool, chksum_offload.tcp_tx_ena);

done:
	config_destroy(&conf);
}

#else
#define read_conf_file(params, filename) ((void)filename)
#endif

void ofp_init_global_param_from_file(ofp_global_param_t *params, const char *filename)
{
	memset(params, 0, sizeof(*params));
	params->pktin_mode = ODP_PKTIN_MODE_SCHED;
	params->pktout_mode = ODP_PKTIN_MODE_DIRECT;
	params->sched_sync = ODP_SCHED_SYNC_ATOMIC;
	params->sched_group = ODP_SCHED_GROUP_ALL;
#ifdef SP
	params->enable_nl_thread = 1;
#endif /* SP */
	params->arp.entries = OFP_ARP_ENTRIES;
	params->arp.hash_bits = OFP_ARP_HASH_BITS;
	params->arp.entry_timeout = OFP_ARP_ENTRY_TIMEOUT;
	params->arp.saved_pkt_timeout = OFP_ARP_SAVED_PKT_TIMEOUT;
	params->evt_rx_burst_size = OFP_EVT_RX_BURST_SIZE;
	params->pcb_tcp_max = OFP_NUM_PCB_TCP_MAX;
	params->pkt_pool.nb_pkts = SHM_PKT_POOL_NB_PKTS;
	params->pkt_pool.buffer_size = SHM_PKT_POOL_BUFFER_SIZE;
	params->pkt_tx_burst_size = OFP_PKT_TX_BURST_SIZE;
	params->num_vlan = OFP_NUM_VLAN;
	params->mtrie.routes = OFP_ROUTES;
	params->mtrie.table8_nodes = OFP_MTRIE_TABLE8_NODES;
	params->num_vrf = OFP_NUM_VRF;
	params->chksum_offload.ipv4_rx_ena = OFP_CHKSUM_OFFLOAD_IPV4_RX;
	params->chksum_offload.udp_rx_ena = OFP_CHKSUM_OFFLOAD_UDP_RX;
	params->chksum_offload.tcp_rx_ena = OFP_CHKSUM_OFFLOAD_TCP_RX;
	params->chksum_offload.ipv4_tx_ena = OFP_CHKSUM_OFFLOAD_IPV4_TX;
	params->chksum_offload.udp_tx_ena = OFP_CHKSUM_OFFLOAD_UDP_TX;
	params->chksum_offload.tcp_tx_ena = OFP_CHKSUM_OFFLOAD_TCP_TX;
	read_conf_file(params, filename);
}

void ofp_init_global_param(ofp_global_param_t *params)
{
	ofp_init_global_param_from_file(params, NULL);
}

static void ofp_init_prepare(void)
{
	/*
	 * Shared memory preallocations or other preparations before
	 * actual global initializations can be done here.
	 *
	 * ODP has been fully initialized but OFP not yet. At this point
	 * global_param can be accessed and ofp_shared_memory_prealloc()
	 * can be called.
	 */
        ofp_uma_init_prepare();
	ofp_avl_init_prepare();
	ofp_reassembly_init_prepare();
	ofp_pcap_init_prepare();
	ofp_stat_init_prepare();
	ofp_timer_init_prepare();
	ofp_hook_init_prepare();
	ofp_arp_init_prepare();
	ofp_route_init_prepare();
	ofp_portconf_init_prepare();
	ofp_vlan_init_prepare();
	ofp_vxlan_init_prepare();
	ofp_socket_init_prepare();
	ofp_tcp_var_init_prepare();
	ofp_ip_init_prepare();
}

static int ofp_init_pre_global(ofp_global_param_t *params)
{
        /*
	 * Allocate and initialize global config memory first so that it
	 * is available to later init phases.
	 */
	HANDLE_ERROR(ofp_global_config_alloc_shared_memory());
	memset(shm, 0, sizeof(*shm));
	shm->is_running = 1;
#ifdef SP
	shm->nl_thread_is_running = 0;
#endif /* SP */
	shm->cli_thread_is_running = 0;

	*global_param = *params;

	/* Initialize shared memory infra before preallocations */
	HANDLE_ERROR(ofp_shared_memory_init_global());
	/* Let different code modules preallocate shared memory */
	ofp_init_prepare();
	/* Finish preallocation phase before the corresponding allocations */
	HANDLE_ERROR(ofp_shared_memory_prealloc_finish());

        /* Initialize the UM allocator before doing other inits */
	HANDLE_ERROR(ofp_uma_init_global());

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

	HANDLE_ERROR(ofp_arp_init_global());

	HANDLE_ERROR(ofp_route_init_global());

	HANDLE_ERROR(ofp_vlan_init_global());

	HANDLE_ERROR(ofp_portconf_init_global());

	HANDLE_ERROR(ofp_vxlan_init_global());

	odp_pool_param_t pool_params;
	odp_pool_param_init(&pool_params);
	/* Define pkt.seg_len so that l2/l3/l4 offset fits in first segment */
	pool_params.pkt.seg_len    = global_param->pkt_pool.buffer_size;
	pool_params.pkt.len        = global_param->pkt_pool.buffer_size;
	pool_params.pkt.num        = params->pkt_pool.nb_pkts;
	pool_params.pkt.uarea_size = ofp_packet_min_user_area();
	pool_params.type           = ODP_POOL_PACKET;

	ofp_packet_pool = ofp_pool_create(SHM_PKT_POOL_NAME, &pool_params);
	if (ofp_packet_pool == ODP_POOL_INVALID) {
		OFP_ERR("odp_pool_create failed");
		return -1;
	}

	HANDLE_ERROR(ofp_socket_init_global(ofp_packet_pool));
	HANDLE_ERROR(ofp_tcp_var_init_global());
	HANDLE_ERROR(ofp_inet_init());
	HANDLE_ERROR(ofp_ip_init_global());

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
	pktio_param.in_mode = params->pktin_mode;
	pktio_param.out_mode = params->pktout_mode;

	ofp_pktin_queue_param_init(&pktin_param, pktio_param.in_mode,
				   params->sched_sync,
				   params->sched_group);

	for (i = 0; i < params->if_count; ++i)
		HANDLE_ERROR(ofp_ifnet_create(instance, params->if_names[i],
			&pktio_param, &pktin_param, NULL));

#ifdef SP
	if (params->enable_nl_thread) {
		odph_odpthread_params_t thr_params;

		/* Start Netlink server process */
		thr_params.start = START_NL_SERVER;
		thr_params.arg = NULL;
		thr_params.thr_type = ODP_THREAD_CONTROL;
		thr_params.instance = instance;
		if (!odph_odpthreads_create(&shm->nl_thread, &cpumask,
					    &thr_params)) {
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
	/* This must be done first */
	HANDLE_ERROR(ofp_shared_memory_init_local());

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
	HANDLE_ERROR(ofp_ip_init_local());

	return 0;
}

int ofp_term_global(void)
{
	int rc = 0;
	uint16_t i, j;
	struct ofp_ifnet *ifnet;

	ofp_stop_processing();
#ifdef CLI
	/* Terminate CLI thread*/
	CHECK_ERROR(ofp_stop_cli_thread(), rc);
#endif

#ifdef SP
	/* Terminate Netlink thread*/
	if (shm->nl_thread_is_running) {
		odph_odpthreads_join(&shm->nl_thread);
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
		odph_odpthreads_join(ifnet->rx_tbl);
		odph_odpthreads_join(ifnet->tx_tbl);
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
			int num_queues = odp_pktin_event_queue(ifnet->pktio, NULL, 0);
			odp_queue_t in_queue[num_queues];
			int num_in_queue, idx;

			num_in_queue = odp_pktin_event_queue(ifnet->pktio,
					in_queue, num_queues);
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

	/* Terminate shared memory now that all blocks have been freed. */
	CHECK_ERROR(ofp_shared_memory_term_global(), rc);

	return rc;
}

int ofp_term_post_global(const char *pool_name)
{
	odp_pool_t pool;
	int rc = 0;

	ofp_igmp_uninit(NULL);

	CHECK_ERROR(ofp_ip_term_global(), rc);

	/* Cleanup sockets */
	CHECK_ERROR(ofp_socket_term_global(), rc);

	/* Cleanup of TCP content */
	CHECK_ERROR(ofp_tcp_var_term_global(), rc);

	/* Cleanup vxlan */
	CHECK_ERROR(ofp_vxlan_term_global(), rc);

	/* Cleanup interface related objects */
	CHECK_ERROR(ofp_portconf_term_global(), rc);
	CHECK_ERROR(ofp_vlan_term_global(), rc);

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

	/*
	 * ofp_term_local() has paused scheduling for this thread. Resume
	 * scheduling temporarily for draining events created during global
	 * termination.
	 */
	odp_schedule_resume();

	/* Cleanup pending events */
	drain_scheduler();

	/*
	 * Now pause scheduling permanently and drain events once more
	 * as suggested by the ODP API.
	 */
	odp_schedule_pause();
	drain_scheduler();

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

	odp_schedule_pause();
	drain_scheduler();

	CHECK_ERROR(ofp_ip_term_local(), rc);
	CHECK_ERROR(ofp_send_pkt_out_term_local(), rc);

	return rc;
}

static void drain_scheduler(void)
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
		default:
			odp_event_free(evt);
		}
	}
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
