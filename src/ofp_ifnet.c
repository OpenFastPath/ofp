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

static void ofp_pktin_queue_param_init(odp_pktin_queue_param_t *param,
		odp_pktin_mode_t in_mode)
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
		queue_param->sched.sync = ODP_SCHED_SYNC_ATOMIC;
		queue_param->sched.group = ODP_SCHED_GROUP_ALL;
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
	if (OFP_PKTIN_QUEUE_MAX < pktin_param->num_queues) {
		OFP_ERR("Number of input queues too big. Max: %d",
			OFP_PKTIN_QUEUE_MAX);
		return -1;
	}

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
	snprintf(q_name, sizeof(q_name), "%s_loopq_def",
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
	if (ofp_queue_context_set(ifnet->loopq_def, ifnet) < 0) {
		OFP_ERR("ofp_queue_context_set failed");
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
	ifnet->if_mtu = odp_pktio_mtu(ifnet->pktio);
	OFP_INFO("Device '%s' MTU=%d", ifnet->if_name, ifnet->if_mtu);

	/* RFC 791, p. 24, "Every internet module must be able
	 * to forward a datagram of 68 octets without further
	 * fragmentation."*/
	if (ifnet->if_mtu < 68 || ifnet->if_mtu > 9000) {
		OFP_INFO("Invalid MTU. Overwrite MTU value to 1500");
		ifnet->if_mtu = 1500;
	}

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

	snprintf(q_name, sizeof(q_name), "%s_inq_def", ifnet->if_name);
	q_name[ODP_QUEUE_NAME_LEN - 1] = '\0';

	ifnet->spq_def = odp_queue_create(q_name, &qparam);

	if (ifnet->spq_def == ODP_QUEUE_INVALID) {
		OFP_ERR("odp_queue_create failed");
		return -1;
	}

	return 0;
}
#endif /*SP*/

int ofp_ifnet_create(char *if_name, odp_pktio_param_t *pktio_param,
	odp_pktin_queue_param_t *pktin_param,
	odp_pktout_queue_param_t *pktout_param)
{
	int port;
	struct ofp_ifnet *ifnet;
	odp_pktio_param_t pktio_param_local;
	odp_pktin_queue_param_t pktin_param_local;
	odp_pktout_queue_param_t pktout_param_local;

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
	}

	HANDLE_ERROR(ofp_pktio_open(ifnet, pktio_param));

	if (!pktin_param) {
		pktin_param = &pktin_param_local;
		ofp_pktin_queue_param_init(&pktin_param_local,
			pktio_param->in_mode);
	}

	HANDLE_ERROR(ofp_pktin_queue_config(ifnet, pktin_param));

	if (pktout_param)
		ifnet->out_queue_type = OFP_OUT_QUEUE_TYPE_PKTOUT;
	else
		ifnet->out_queue_type = OFP_OUT_QUEUE_TYPE_QUEUE;

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

	if (ifnet->out_queue_type == OFP_OUT_QUEUE_TYPE_PKTOUT) {
		ifnet->out_queue_num = pktout_param->num_queues;
		if (odp_pktout_queue(ifnet->pktio,
			ifnet->out_queue_pktout,
			pktout_param->num_queues) <
				(int)pktout_param->num_queues) {
			OFP_ERR("Failed to get output queues.");
			return -1;
		}
	} else {
		ifnet->out_queue_num = 1;
		ifnet->outq_def = odp_pktio_outq_getdef(ifnet->pktio);
		if (ifnet->outq_def == ODP_QUEUE_INVALID) {
			OFP_ERR("odp_pktio_outq_getdef failed");
			return -1;
		}
	}

#ifdef SP
		/* Start VIF slowpath receiver thread */
	odph_linux_pthread_create(ifnet->rx_tbl,
				 &cpumask,
				 sp_rx_thread,
				 ifnet,
				 ODP_THREAD_CONTROL);

	/* Start VIF slowpath transmitter thread */
	odph_linux_pthread_create(ifnet->tx_tbl,
				 &cpumask,
				 sp_tx_thread,
				 ifnet,
				 ODP_THREAD_CONTROL);
#endif /* SP */

	return 0;
}
