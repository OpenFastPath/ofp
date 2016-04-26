/* Copyright (c) 2015, ENEA Software AB
 * Copyright (c) 2015, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include "ofpi.h"
#include "ofpi_pkt_processing.h"
#include "ofpi_util.h"
#include "ofpi_log.h"
#include "ofpi_debug.h"
#include "ofpi_stat.h"


static __thread struct burst_send {
	odp_packet_t pkt_tbl[OFP_PKT_TX_BURST_SIZE];
	uint32_t pkt_tbl_cnt;
} send_pkt_tbl[NUM_PORTS] __attribute__((__aligned__(ODP_CACHE_LINE_SIZE)));


static inline enum ofp_return_code
send_table(struct ofp_ifnet *ifnet, odp_packet_t *pkt_tbl,
		uint32_t *pkt_tbl_cnt)
{
	int pkts_sent;
	enum ofp_return_code ret = OFP_PKT_PROCESSED;

	pkts_sent = ofp_send_pkt_multi(ifnet, pkt_tbl, *pkt_tbl_cnt,
			odp_cpu_id());

	if (pkts_sent < 0)
		pkts_sent = 0;
	else
		OFP_UPDATE_PACKET_STAT(tx_fp, pkts_sent);

	if (pkts_sent < (int)(*pkt_tbl_cnt)) {
		int pkt_cnt = (int)(*pkt_tbl_cnt);

		OFP_DBG("odp_pktio_send failed: %d/%d packets dropped",
			pkt_cnt - pkts_sent, pkt_cnt);

		for (; pkts_sent < pkt_cnt; pkts_sent++)
			odp_packet_free(pkt_tbl[pkts_sent]);

		ret = OFP_PKT_DROP;
	}

	*pkt_tbl_cnt = 0;
	return ret;
}

enum ofp_return_code send_pkt_burst_out(struct ofp_ifnet *dev,
	odp_packet_t pkt)
{
	uint32_t *pkt_tbl_cnt = &send_pkt_tbl[dev->port].pkt_tbl_cnt;
	odp_packet_t *pkt_tbl = (odp_packet_t *)send_pkt_tbl[dev->port].pkt_tbl;

	pkt_tbl[(*pkt_tbl_cnt)++] = pkt;

	OFP_DEBUG_PACKET(OFP_DEBUG_PKT_SEND_NIC, pkt, dev->port);

	if ((*pkt_tbl_cnt) == OFP_PKT_TX_BURST_SIZE)
		return send_table(ofp_get_ifnet(dev->port, 0),
				pkt_tbl,
				pkt_tbl_cnt);

	return OFP_PKT_PROCESSED;
}

enum ofp_return_code ofp_send_pending_pkt_burst(void)
{
	uint32_t i;
	uint32_t *pkt_tbl_cnt;
	odp_packet_t *pkt_tbl;
	enum ofp_return_code ret = OFP_PKT_PROCESSED;
	enum ofp_return_code ret_send = OFP_PKT_PROCESSED;

	for (i = 0; i < NUM_PORTS; i++) {
		pkt_tbl_cnt = &send_pkt_tbl[i].pkt_tbl_cnt;

		if  (!(*pkt_tbl_cnt))
			continue;

		pkt_tbl = (odp_packet_t *)send_pkt_tbl[i].pkt_tbl;

		ret_send = send_table(ofp_get_ifnet(i, 0), pkt_tbl,
			pkt_tbl_cnt);
		if (ret_send != OFP_PKT_PROCESSED)
			ret = ret_send;
	}

	return ret;
}

int ofp_send_pkt_burst_out_init_local(void)
{
	uint32_t i, j;

	for (i = 0; i < NUM_PORTS; i++) {
		for (j = 0; j < OFP_PKT_TX_BURST_SIZE; j++)
			send_pkt_tbl[i].pkt_tbl[j] = ODP_PACKET_INVALID;
		send_pkt_tbl[i].pkt_tbl_cnt = 0;
	}

	return 0;
}

int ofp_send_pkt_burst_out_term_local(void)
{
	uint32_t i, j;

	for (i = 0; i < NUM_PORTS; i++) {
		if (!send_pkt_tbl[i].pkt_tbl_cnt)
			continue;

		for (j = 0; j < send_pkt_tbl[i].pkt_tbl_cnt; j++)
			odp_packet_free(send_pkt_tbl[i].pkt_tbl[j]);

		send_pkt_tbl[i].pkt_tbl_cnt = 0;
	}

	return 0;
}
