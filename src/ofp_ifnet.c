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
int ofp_pktio_open(struct ofp_ifnet *ifnet, int pktin_mode)
{
#if ODP_VERSION >= 103
	odp_pktio_param_t pktio_param;

	memset(&pktio_param, 0, sizeof(pktio_param));
	pktio_param.in_mode = pktin_mode;

	ifnet->pktio = odp_pktio_open(ifnet->if_name, ifnet->pkt_pool, &pktio_param);
#else
	/* Open a packet IO instance for this device */
	ifnet->pktio = odp_pktio_open(ifnet->if_name, ifnet->pkt_pool);
#endif

	if (ifnet->pktio == ODP_PKTIO_INVALID) {
		OFP_ERR("odp_pktio_open failed");
		return -1;
	}

	return 0;
}
/*
 * Create and set the default INPUT queue associated with the 'pktio'
 * resource
 */
static int ofp_pktio_inq_def_set(struct ofp_ifnet *ifnet, int pktin_mode)
{
	if (pktin_mode == ODP_PKTIN_MODE_SCHED) {
		odp_queue_param_t qparam;
		char q_name[ODP_QUEUE_NAME_LEN];

		odp_queue_param_init(&qparam);
		qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
		qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
		qparam.sched.group = ODP_SCHED_GROUP_ALL;
		snprintf(q_name, sizeof(q_name), "%" PRIu64 "-pktio_inq_def",
			 odp_pktio_to_u64(ifnet->pktio));
		q_name[ODP_QUEUE_NAME_LEN - 1] = '\0';

		ifnet->inq_def = ofp_queue_create(q_name,
						  ODP_QUEUE_TYPE_PKTIN,
						  &qparam);
		if (ifnet->inq_def == ODP_QUEUE_INVALID) {
			OFP_ERR("ofp_queue_create failed");
			return -1;
		}

		if (odp_pktio_inq_setdef(ifnet->pktio, ifnet->inq_def) != 0) {
			OFP_ERR("odp_pktio_inq_setdef failed");
			return -1;
		}
	} else
		ifnet->inq_def = ODP_QUEUE_INVALID;

	return 0;
}

static int ofp_pktio_outq_def_set(struct ofp_ifnet *ifnet)
{
	ifnet->outq_def = odp_pktio_outq_getdef(ifnet->pktio);
	if (ifnet->outq_def == ODP_QUEUE_INVALID) {
		OFP_ERR("odp_pktio_outq_getdef failed");
		return -1;
	}

	/* Set device outq queue context */
	if (ofp_queue_context_set(ifnet->outq_def, ifnet) < 0) {
		OFP_ERR("ofp_queue_context_set failed");
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
	qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;

	ifnet->loopq_def = ofp_queue_create(q_name,
					ODP_QUEUE_TYPE_SCHED,
					&qparam);
	if (ifnet->loopq_def == ODP_QUEUE_INVALID) {
		OFP_ERR("ofp_queue_create failed");
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
	qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;

	snprintf(q_name, sizeof(q_name), "%s_inq_def", ifnet->if_name);
	q_name[ODP_QUEUE_NAME_LEN - 1] = '\0';

	ifnet->spq_def = ofp_queue_create(q_name,
					ODP_QUEUE_TYPE_PLAIN,
					&qparam);

	if (ifnet->spq_def == ODP_QUEUE_INVALID) {
		OFP_ERR("ofp_queue_create failed");
		return -1;
	}

	return 0;
}
#endif /*SP*/

int ofp_ifnet_create(char *if_name, int recv_mode)
{
	int port = ofp_free_port_alloc();
	struct ofp_ifnet *ifnet = ofp_get_ifnet((uint16_t)port, 0);

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

	HANDLE_ERROR(ofp_pktio_open(ifnet, recv_mode));
	HANDLE_ERROR(ofp_pktio_inq_def_set(ifnet, recv_mode));
	HANDLE_ERROR(ofp_pktio_outq_def_set(ifnet));
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

	/* Start VIF slowpath receiver thread */
	ofp_linux_pthread_create(ifnet->rx_tbl,
				 &cpumask,
				 sp_rx_thread,
				 ifnet,
				 ODP_THREAD_CONTROL);

	/* Start VIF slowpath transmitter thread */
	ofp_linux_pthread_create(ifnet->tx_tbl,
				 &cpumask,
				 sp_tx_thread,
				 ifnet,
				 ODP_THREAD_CONTROL);
#endif /* SP */
	/* Start packet receiver or transmitter */
	if (odp_pktio_start(ifnet->pktio) != 0) {
		OFP_ERR("Failed to start pktio.");
		return -1;
	}

	return 0;
}
