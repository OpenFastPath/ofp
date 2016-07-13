/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef __OFP_DEBUG_H__
#define __OFP_DEBUG_H__


#if __GNUC__ >= 4
#pragma GCC visibility push(default)
#endif

/*
 * Debug configure interface
 */
#define OFP_DEBUG_PRINT_RECV_NIC 1
#define OFP_DEBUG_PRINT_SEND_NIC 2
#define OFP_DEBUG_PRINT_RECV_KNI 4
#define OFP_DEBUG_PRINT_SEND_KNI 8
#define OFP_DEBUG_PRINT_CONSOLE 16
#define OFP_DEBUG_CAPTURE       64

void ofp_set_debug_flags(int flags);
int ofp_get_debug_flags(void);

#define OFP_DEBUG_PCAP_PORT_MASK 0x3f
#define OFP_DEBUG_PCAP_CONF_ADD_INFO 0x80000000

void ofp_set_debug_capture_ports(int ports);
int ofp_get_debug_capture_ports(void);

/*
 * Debug PCAP interface
 */
void ofp_set_capture_file(const char *filename);
void ofp_get_capture_file(char *filename, int max_size);

/*
 * Debug PRINT interface
 */
void ofp_print_packet(const char *comment, odp_packet_t pkt);

#if __GNUC__ >= 4
#pragma GCC visibility pop
#endif

#endif /*__OFP_DEBUG_H__*/
