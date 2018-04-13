/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef __OFP_APP_H__
#define __OFP_APP_H__

#include <odp_api.h>
#include "ofp_types.h"

#if __GNUC__ >= 4
#pragma GCC visibility push(default)
#endif

typedef enum ofp_return_code (*ofp_pkt_processing_func)(odp_packet_t *pkt);

struct ofp_ifnet;

int default_event_dispatcher(void *arg);

/**
 * Return the minimum size of the user area that must be present in all
 * ODP packets passed to OFP.
 */
uint32_t ofp_packet_min_user_area(void);

/**
 * Input a packet and process it using the function supplied by the
 * caller.
 *
 * @param pkt      Packet to process. pkt_func may require some of
 *                 L2/L3/L4 offsets to be set.
 * @param in_queue ODP queue from which the packet was dequeued, or
 *                 ODP_QUEUE_INVALID.
 * @param pkt_func Packet processing function. This may be one of the
 *                 ofp_*_processing() functions.
 */
enum ofp_return_code ofp_packet_input(odp_packet_t pkt,
	odp_queue_t in_queue, ofp_pkt_processing_func pkt_func);

/**
 * Process a packet, starting with L2.
 *
 * To be used with ofp_packet_input(), not to be called directly.
 *
 * @param[in,out] pkt Packet to process. L2 and L3 offsets must be
 *                    set.
 */
enum ofp_return_code ofp_eth_vlan_processing(odp_packet_t *pkt);

/**
 * Process an IPv4 packet.
 *
 * To be used with ofp_packet_input(), not to be called directly.
 *
 * @param[in,out] pkt Packet to process. L3 offset must be set.
 */
enum ofp_return_code ofp_ipv4_processing(odp_packet_t *pkt);

/**
 * Process an IPv6 packet.
 *
 * To be used with ofp_packet_input(), not to be called directly.
 *
 * @param[in,out] pkt Packet to process. L3 offset must be set.
 */
enum ofp_return_code ofp_ipv6_processing(odp_packet_t *pkt);

/**
 * Process a GRE packet.
 *
 * To be used with ofp_packet_input(), not to be called directly.
 *
 * @param[in,out] pkt Packet to process. L3 offset must be set.
 */
enum ofp_return_code ofp_gre_processing(odp_packet_t *pkt);

/**
 * Process an ARP packet.
 *
 * To be used with ofp_packet_input(), not to be called directly.
 *
 * @param[in,out] pkt Packet to process. L3 offset must be set.
 */
enum ofp_return_code ofp_arp_processing(odp_packet_t *pkt);

/**
 * Process a UDP packet.
 *
 * To be used with ofp_packet_input(), not to be called directly.
 *
 * @param[in,out] pkt Packet to process. L3 offset must be set.
 */
enum ofp_return_code ofp_udp4_processing(odp_packet_t *pkt);

/**
 * Process a TCP packet.
 *
 * To be used with ofp_packet_input(), not to be called directly.
 *
 * @param[in,out] pkt Packet to process. L3 offset must be set.
 */
enum ofp_return_code ofp_tcp4_processing(odp_packet_t *pkt);

enum ofp_return_code ofp_send_frame(struct ofp_ifnet *dev, odp_packet_t pkt);
enum ofp_return_code ofp_send_pending_pkt(void);

enum ofp_return_code ofp_ip_send(odp_packet_t pkt,
				 struct ofp_nh_entry *nh_param);
enum ofp_return_code ofp_ip6_send(odp_packet_t pkt,
				  struct ofp_nh6_entry *nh_param);

#if __GNUC__ >= 4
#pragma GCC visibility pop
#endif

#endif /*__OFP_APP_H__*/
