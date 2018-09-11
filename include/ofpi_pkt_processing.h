/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef _OFPI_APP_H
#define _OFPI_APP_H

#include <odp_api.h>
#include <string.h>
#include "api/ofp_types.h"
#include "api/ofp_pkt_processing.h"
#include "ofpi_in.h"
#include "ofpi_init.h"
#include "ofpi_vxlan.h"
#include "ofpi_ipsec.h"

struct ip_out {
	struct ofp_ifnet *dev_out;
	struct ofp_nh_entry *nh;
	struct ofp_ip *ip;
	uint32_t gw;
	uint16_t vrf;
	uint8_t is_local_address;
	uint8_t insert_checksum;
};

/*
 * Limit for IP output recursion that occurs with nested tunneling.
 * Other resource limits, such as the available headroom in the
 * packet, may limit the nesting before this limit is reached.
 */
#define OFP_IP_OUTPUT_MAX_RECURSION 8

#define OFP_L3_CHKSUM_STATUS_VALID  0x1
#define OFP_L4_CHKSUM_STATUS_VALID  0x2
#define OFP_UDP_CHKSUM_INSERT       0x4
#define OFP_TCP_CHKSUM_INSERT       0x8

struct ofp_packet_user_area {
	uint8_t ipsec_flags;
	uint8_t recursion_count;
	uint8_t chksum_flags;
	struct vxlan_user_data vxlan;
};

static inline void ofp_packet_user_area_reset(odp_packet_t pkt)
{
	struct ofp_packet_user_area *ua = odp_packet_user_area(pkt);
	memset(ua, 0, sizeof(*ua));
}

static inline struct ofp_packet_user_area *ofp_packet_user_area(odp_packet_t pkt)
{
	return odp_packet_user_area(pkt);
}

static inline odp_packet_t ofp_packet_alloc_from_pool(odp_pool_t pool,
						      uint32_t len)
{
	odp_packet_t pkt = odp_packet_alloc(pool, len);
	if (pkt != ODP_PACKET_INVALID)
		ofp_packet_user_area_reset(pkt);
	return pkt;
}

static inline odp_packet_t ofp_packet_alloc(uint32_t len)
{
	return ofp_packet_alloc_from_pool(ofp_packet_pool, len);
}

enum ofp_return_code send_pkt_out(struct ofp_ifnet *dev,
			odp_packet_t pkt);
enum ofp_return_code send_pkt_loop(struct ofp_ifnet *dev,
			odp_packet_t pkt);

enum ofp_return_code ipv4_transport_classifier(odp_packet_t *pkt,
			uint8_t ip_proto);
enum ofp_return_code ipv6_transport_classifier(odp_packet_t *pkt,
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
		odp_event_t ev_tbl[pkt_tbl_cnt];

		odp_packet_to_event_multi(pkt_tbl, ev_tbl, pkt_tbl_cnt);

		return odp_queue_enq_multi(ifnet->out_queue_queue[out_idx],
			ev_tbl, pkt_tbl_cnt);
	}
}

enum ofp_return_code ofp_ip_output_common(odp_packet_t pkt,
					  struct ofp_nh_entry *nh,
					  int is_local_out,
					  ofp_ipsec_sa_handle sa);

enum ofp_return_code ofp_ip_output(odp_packet_t pkt, struct ofp_nh_entry *nh);

enum ofp_return_code ofp_ip_output_recurse(odp_packet_t pkt,
					   struct ofp_nh_entry *nh);

struct ofp_ip_moptions;
struct inpcb;
enum ofp_return_code ofp_ip_output_opt(odp_packet_t pkt,
				       odp_packet_t opt,
				       struct ofp_nh_entry *nh_param,
				       int flags,
				       struct ofp_ip_moptions *imo,
				       struct inpcb *inp);
enum ofp_return_code ofp_ip6_output(odp_packet_t pkt,
				    struct ofp_nh6_entry *nh_param);

enum ofp_return_code ofp_sp_input(odp_packet_t pkt,
				  struct ofp_ifnet *ifnet);

#endif /* _OFPI_APP_H */
