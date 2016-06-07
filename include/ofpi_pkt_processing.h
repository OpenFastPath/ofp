/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef _OFPI_APP_H
#define _OFPI_APP_H

#include <odp.h>
#include "api/ofp_types.h"
#include "api/ofp_pkt_processing.h"
#include "ofpi_in.h"

struct ip_out {
	struct ofp_ifnet *dev_out;
	struct ofp_nh_entry *nh;
	struct ofp_ip *ip;
	struct ofp_nh_entry nh_vxlan;
	int out_port;
	uint32_t gw;
	uint16_t vlan;
	uint16_t vrf;
	uint8_t is_local_address;
};

enum ofp_return_code send_pkt_out(struct ofp_ifnet *dev,
			odp_packet_t pkt);
enum ofp_return_code send_pkt_loop(struct ofp_ifnet *dev,
			odp_packet_t pkt);

enum ofp_return_code ipv4_transport_classifier(odp_packet_t pkt,
			uint8_t ip_proto);
enum ofp_return_code ipv6_transport_classifier(odp_packet_t pkt,
			uint8_t ip6_nxt);

int ofp_send_pkt_out_init_local(void);
int ofp_send_pkt_out_term_local(void);


static inline int ofp_send_pkt_multi(struct ofp_ifnet *ifnet,
			odp_packet_t *pkt_tbl, uint32_t pkt_tbl_cnt,
			int core_id)
{
	int out_idx;

	out_idx = core_id % ifnet->out_queue_num;

	if (ifnet->out_queue_type == OFP_OUT_QUEUE_TYPE_PKTOUT) {
		return odp_pktout_send(ifnet->out_queue_pktout[out_idx],
			pkt_tbl, pkt_tbl_cnt);
	} else {
		uint32_t i;
		odp_event_t ev_tbl[OFP_PKT_TX_BURST_SIZE];

		for (i = 0; i < pkt_tbl_cnt; i++)
			ev_tbl[i] = odp_packet_to_event(pkt_tbl[i]);

		return odp_queue_enq_multi(ifnet->out_queue_queue[out_idx],
			ev_tbl, pkt_tbl_cnt);
	}
}

#endif /* _OFPI_APP_H */
