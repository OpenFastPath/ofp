/* Copyright (c) 2015, ENEA Software AB
 * Copyright (c) 2015, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include "ofpi.h"
#include "ofpi_ifnet.h"
#include "ofpi_igmp_var.h"
#include "ofpi_util.h"

#include "ofp_errno.h"
#include "ofp_log.h"

/* Open a packet IO instance for this ifnet device for the pktin_mode. */
int ofp_pktio_open(struct ofp_ifnet *ifnet, odp_pktio_param_t *pktio_param)
{
	ifnet->pktio = odp_pktio_open(ifnet->if_name, ifnet->pkt_pool,
			pktio_param);

	if (ifnet->pktio == ODP_PKTIO_INVALID) {
		OFP_ERR("odp_pktio_open failed");
		return -1;
	}

	return 0;
}

static int ofp_pktio_config(struct ofp_ifnet *ifnet)
{
	odp_pktio_capability_t capa;
	odp_pktio_config_t config;

	HANDLE_ERROR(odp_pktio_capability(ifnet->pktio, &capa));

	odp_pktio_config_init(&config);

	if (capa.config.pktin.bit.ipv4_chksum &
		global_param->chksum_offload.ipv4_rx_ena) {
		ifnet->chksum_offload_flags |= OFP_IF_IPV4_RX_CHKSUM;
		config.pktin.bit.ipv4_chksum = 1;
		config.pktin.bit.drop_ipv4_err = 1;
		OFP_DBG("Interface '%s' supports IPv4 RX checksum offload",
			ifnet->if_name);
	}

	if (capa.config.pktout.bit.ipv4_chksum &
		global_param->chksum_offload.ipv4_tx_ena) {
		ifnet->chksum_offload_flags |= OFP_IF_IPV4_TX_CHKSUM;
		config.pktout.bit.ipv4_chksum = 1;
		config.pktout.bit.ipv4_chksum_ena = 1;
		OFP_DBG("Interface '%s' supports IPv4 TX checksum offload",
			ifnet->if_name);
	}

	if (capa.config.pktin.bit.udp_chksum &
		global_param->chksum_offload.udp_rx_ena) {
		ifnet->chksum_offload_flags |= OFP_IF_UDP_RX_CHKSUM;
		config.pktin.bit.udp_chksum = 1;
		config.pktin.bit.drop_udp_err = 0;
		OFP_DBG("Interface '%s' supports UDP RX checksum offload",
			ifnet->if_name);
	}

	if (capa.config.pktout.bit.udp_chksum &
		global_param->chksum_offload.udp_tx_ena) {
		ifnet->chksum_offload_flags |= OFP_IF_UDP_TX_CHKSUM;
		/*
		 * UDP checksum insertion will be requested explicitly
		 * for each packet when necessary.
		 */
		config.pktout.bit.udp_chksum = 0;
		config.pktout.bit.udp_chksum_ena = 1;
		OFP_DBG("Interface '%s' supports UDP TX checksum offload",
			ifnet->if_name);
	}

	if (capa.config.pktin.bit.tcp_chksum &
		global_param->chksum_offload.tcp_rx_ena) {
		ifnet->chksum_offload_flags |= OFP_IF_TCP_RX_CHKSUM;
		config.pktin.bit.tcp_chksum = 1;
		config.pktin.bit.drop_tcp_err = 0;
		OFP_DBG("Interface '%s' supports TCP RX checksum offload",
			ifnet->if_name);
        }

        if (capa.config.pktout.bit.tcp_chksum &
		global_param->chksum_offload.tcp_tx_ena) {
                ifnet->chksum_offload_flags |= OFP_IF_TCP_TX_CHKSUM;
                /*
                 * TCP checksum insertion will be requested explicitly
                 * for each packet when necessary.
                 */
                config.pktout.bit.tcp_chksum = 0;
                config.pktout.bit.tcp_chksum_ena = 1;
                OFP_DBG("Interface '%s' supports TCP TX checksum offload",
                        ifnet->if_name);
        }

	HANDLE_ERROR(odp_pktio_config(ifnet->pktio, &config));

	return 0;
}

void ofp_pktin_queue_param_init(odp_pktin_queue_param_t *param,
				odp_pktin_mode_t in_mode,
				odp_schedule_sync_t sched_sync,
				odp_schedule_group_t sched_group)
{
	odp_queue_param_t *queue_param;

	odp_pktin_queue_param_init(param);

	param->num_queues = 1;
	queue_param = &param->queue_param;
	odp_queue_param_init(queue_param);
	if (in_mode == ODP_PKTIN_MODE_SCHED) {
		queue_param->type = ODP_QUEUE_TYPE_SCHED;
		queue_param->enq_mode = ODP_QUEUE_OP_MT;
		queue_param->deq_mode = ODP_QUEUE_OP_MT;
		queue_param->context = NULL;
		queue_param->sched.prio = ODP_SCHED_PRIO_DEFAULT;
		queue_param->sched.sync = sched_sync;
		queue_param->sched.group = sched_group;
	} else if (in_mode == ODP_PKTIN_MODE_QUEUE) {
		queue_param->type = ODP_QUEUE_TYPE_PLAIN;
		queue_param->enq_mode = ODP_QUEUE_OP_MT;
		queue_param->deq_mode = ODP_QUEUE_OP_MT;
		queue_param->context = NULL;
	}
}

static int ofp_pktin_queue_config(struct ofp_ifnet *ifnet,
	odp_pktin_queue_param_t *pktin_param)
{
	if (odp_pktin_queue_config(ifnet->pktio, pktin_param) < 0) {
		OFP_ERR("Failed to create input queues.");
		return -1;
	}

	return 0;
}

static void ofp_pktout_queue_param_init(odp_pktout_queue_param_t *param)
{
	odp_pktout_queue_param_init(param);

	param->op_mode = ODP_PKTIO_OP_MT;
	param->num_queues = 1;
}

static int ofp_pktout_queue_config(struct ofp_ifnet *ifnet,
	odp_pktout_queue_param_t *pktout_param)
{
	if (OFP_PKTOUT_QUEUE_MAX < pktout_param->num_queues) {
		OFP_ERR("Number of output queues too big. Max: %d",
			OFP_PKTOUT_QUEUE_MAX);
		return -1;
	}

	if (odp_pktout_queue_config(ifnet->pktio, pktout_param) < 0) {
		OFP_ERR("Failed to create output queues.");
		return -1;
	}

	return 0;
}

/* Create loop queue */
int ofp_loopq_create(struct ofp_ifnet *ifnet)
{
	odp_queue_param_t qparam;
	char q_name[ODP_QUEUE_NAME_LEN];

	/* Create loop queue */
	snprintf(q_name, sizeof(q_name), "%.20s_loopq_def",
			ifnet->if_name);
	q_name[ODP_QUEUE_NAME_LEN - 1] = '\0';

	odp_queue_param_init(&qparam);
	qparam.type = ODP_QUEUE_TYPE_SCHED;
	qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;

	ifnet->loopq_def = odp_queue_create(q_name, &qparam);
	if (ifnet->loopq_def == ODP_QUEUE_INVALID) {
		OFP_ERR("odp_queue_create failed");
		return -1;
	}

	/* Set device loopq queue context */
	if (odp_queue_context_set(ifnet->loopq_def, ifnet, sizeof(ifnet)) < 0) {
		OFP_ERR("odp_queue_context_set failed");
		return -1;
	}

	return 0;
}

/* Set ifnet interface MAC address */
int ofp_mac_set(struct ofp_ifnet *ifnet)
{
	if (odp_pktio_mac_addr(ifnet->pktio, ifnet->mac,
		sizeof(ifnet->mac)) < 0) {
		OFP_ERR("Failed to retrieve MAC address");
		return -1;
	}
	if (!ofp_has_mac(ifnet->mac)) {
		ifnet->mac[0] = ifnet->port;
		OFP_ERR("MAC overwritten");
	}
	OFP_INFO("Device '%s' addr %s", ifnet->if_name,
		ofp_print_mac((uint8_t *)ifnet->mac));

	return 0;
}

/* Set interface MTU*/
int ofp_mtu_set(struct ofp_ifnet *ifnet)
{
	uint32_t max_frame_size = odp_pktout_maxlen(ifnet->pktio);

	ifnet->if_mtu = OFP_MTU_SIZE;

	if (max_frame_size < OFP_ETHER_HDR_LEN + 68) {
		/* RFC 791, p. 24, "Every internet module must be able
		 * to forward a datagram of 68 octets without further
		 * fragmentation."*/
		OFP_ERR("odp_pktout_maxlen returned too small value: %d",
			 max_frame_size);
		return -1;
	} else if (max_frame_size < OFP_ETHER_HDR_LEN + OFP_MTU_SIZE)
		ifnet->if_mtu = max_frame_size - OFP_ETHER_HDR_LEN;

	OFP_INFO("Device '%s' MTU=%d", ifnet->if_name, ifnet->if_mtu);

	return 0;
}

/* IGMP protocol used for multicasting. */
void ofp_igmp_attach(struct ofp_ifnet *ifnet)
{
	struct ofp_in_ifinfo *ii = &ifnet->ii_inet;

	ii->ii_igmp = ofp_igmp_domifattach(ifnet);
}

#ifdef SP
/* Create VIF local input queue */
int ofp_sp_inq_create(struct ofp_ifnet *ifnet)
{
	odp_queue_param_t qparam;
	char q_name[ODP_QUEUE_NAME_LEN];

	odp_queue_param_init(&qparam);
	qparam.type = ODP_QUEUE_TYPE_PLAIN;
	qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;

	snprintf(q_name, sizeof(q_name), "%.20s_inq_def", ifnet->if_name);
	q_name[ODP_QUEUE_NAME_LEN - 1] = '\0';

	ifnet->spq_def = odp_queue_create(q_name, &qparam);

	if (ifnet->spq_def == ODP_QUEUE_INVALID) {
		OFP_ERR("odp_queue_create failed");
		return -1;
	}

	return 0;
}
#endif /*SP*/

int ofp_ifnet_create(odp_instance_t instance,
	char *if_name,
	odp_pktio_param_t *pktio_param,
	odp_pktin_queue_param_t *pktin_param,
	odp_pktout_queue_param_t *pktout_param)
{
	int port;
	struct ofp_ifnet *ifnet;
	odp_pktio_param_t pktio_param_local;
	odp_pktin_queue_param_t pktin_param_local;
	odp_pktout_queue_param_t pktout_param_local;
#ifdef SP
	odph_odpthread_params_t thr_params;
#endif /* SP */

	(void)instance;

	port = ofp_free_port_alloc();
	ifnet = ofp_get_ifnet((uint16_t)port, 0);
	if (ifnet == NULL) {
		OFP_ERR("Got ifnet NULL");
		return -1;
	}

	OFP_DBG("Interface '%s' becomes '%s%d', port %d",
		if_name, OFP_IFNAME_PREFIX, port, port);

	ifnet->if_state = OFP_IFT_STATE_USED;
	strncpy(ifnet->if_name, if_name, OFP_IFNAMSIZ);
	ifnet->if_name[OFP_IFNAMSIZ-1] = 0;
	ifnet->pkt_pool = ofp_packet_pool;

	if (!pktio_param) {
		pktio_param = &pktio_param_local;
		odp_pktio_param_init(&pktio_param_local);
		pktio_param_local.in_mode = ODP_PKTIN_MODE_SCHED;
		pktio_param_local.out_mode = ODP_PKTOUT_MODE_DIRECT;
	} else if (pktio_param->in_mode != ODP_PKTIN_MODE_DIRECT &&
		pktio_param->in_mode != ODP_PKTIN_MODE_SCHED &&
		pktio_param->in_mode != ODP_PKTIN_MODE_QUEUE &&
		pktio_param_local.out_mode != ODP_PKTOUT_MODE_DIRECT &&
		pktio_param_local.out_mode != ODP_PKTOUT_MODE_QUEUE) {
			OFP_ERR("Invalid pktio configuration parameters.");
			return -1;
	}

	HANDLE_ERROR(ofp_pktio_open(ifnet, pktio_param));

	HANDLE_ERROR(ofp_pktio_config(ifnet));

	if (!pktin_param) {
		pktin_param = &pktin_param_local;
		ofp_pktin_queue_param_init(&pktin_param_local,
					   pktio_param->in_mode,
					   ODP_SCHED_SYNC_ATOMIC,
					   ODP_SCHED_GROUP_ALL);
	}

	HANDLE_ERROR(ofp_pktin_queue_config(ifnet, pktin_param));

	if (!pktout_param) {
		pktout_param = &pktout_param_local;
		ofp_pktout_queue_param_init(pktout_param);
	}

	HANDLE_ERROR(ofp_pktout_queue_config(ifnet, pktout_param));

	HANDLE_ERROR(ofp_loopq_create(ifnet));

	HANDLE_ERROR(ofp_mac_set(ifnet));
	HANDLE_ERROR(ofp_mtu_set(ifnet));

	ofp_igmp_attach(ifnet);

#ifdef SP
	HANDLE_ERROR(ofp_sp_inq_create(ifnet));

	/* Create the kernel representation of the FP interface. */
	HANDLE_ERROR(sp_setup_device(ifnet));

	/* Maintain table to access ifnet from linux ifindex */
	ofp_update_ifindex_lookup_tab(ifnet);
#ifdef INET6
	/* ifnet MAC was set in sp_setup_device() */
	ofp_mac_to_link_local(ifnet->mac, ifnet->link_local);
#endif /* INET6 */

#endif /* SP */
	/* Start packet receiver or transmitter */
	if (odp_pktio_start(ifnet->pktio) != 0) {
		OFP_ERR("Failed to start pktio.");
		return -1;
	}

	if (pktio_param->out_mode == ODP_PKTOUT_MODE_DIRECT) {
		ifnet->out_queue_type = OFP_OUT_QUEUE_TYPE_PKTOUT;
		ifnet->out_queue_num = pktout_param->num_queues;
		if (odp_pktout_queue(ifnet->pktio,
			ifnet->out_queue_pktout,
			pktout_param->num_queues) <
				(int)pktout_param->num_queues) {
			OFP_ERR("Failed to get pkt output queues on %s.",
				ifnet->if_name);
			return -1;
		}
	} else if (pktio_param->out_mode == ODP_PKTOUT_MODE_QUEUE) {
		ifnet->out_queue_type = OFP_OUT_QUEUE_TYPE_QUEUE;
		ifnet->out_queue_num = pktout_param->num_queues;
		if (odp_pktout_event_queue(ifnet->pktio,
			ifnet->out_queue_queue,	pktout_param->num_queues) <
			(int)pktout_param->num_queues) {
			OFP_ERR("Failed to get event output queues on %s.",
				ifnet->if_name);
			return -1;
		}
	}

	odp_pktio_stats_reset(ifnet->pktio);

#ifdef SP
	/* Start VIF slowpath receiver thread */
	thr_params.start = sp_rx_thread;
	thr_params.arg = ifnet;
	thr_params.thr_type = ODP_THREAD_CONTROL;
	thr_params.instance = instance;
	odph_odpthreads_create(ifnet->rx_tbl,
			       &cpumask,
			       &thr_params);

	/* Start VIF slowpath transmitter thread */
	thr_params.start = sp_tx_thread;
	thr_params.arg = ifnet;
	thr_params.thr_type = ODP_THREAD_CONTROL;
	thr_params.instance = instance;
	odph_odpthreads_create(ifnet->tx_tbl,
			       &cpumask,
			       &thr_params);
#endif /* SP */

	return 0;
}
