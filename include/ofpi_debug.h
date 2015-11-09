/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 * Copyright (c) 2014, Nokia
 * Copyright (c) 2014, Enea Software AB
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
/**
 * @file
 *
 * ofp debug
 */

#ifndef _OFPI_DEBUG_H_
#define _OFPI_DEBUG_H_

#include <odp.h>
#include <stdio.h>
#include <stdlib.h>
#include "api/ofp_debug.h"

#ifdef __cplusplus
extern "C" {
#endif


extern int ofp_debug_flags;

#define OFP_DEBUG_PCAP_KNI       0x40
#define OFP_DEBUG_PCAP_TX        0x80
extern int ofp_debug_capture_ports;

#define DEFAULT_DEBUG_TXT_FILE_NAME "packets.txt"
#define DEFAULT_DEBUG_PCAP_FILE_NAME "/root/packets.pcap"

int ofp_pcap_lookup_shared_memory(void);
int ofp_pcap_init_global(void);
int ofp_pcap_term_global(void);

void ofp_save_packet_to_pcap_file(uint32_t flag, odp_packet_t pkt, int port);
void ofp_print_packet_buffer(const char *comment, uint8_t *p);

/*
 * Debug LOG interface
 */
struct ofp_flag_descript_s {
	uint32_t flag;
	const char *flag_descript;
};

enum ofp_log_packet {
	OFP_DEBUG_PKT_RECV_NIC = 0,
	OFP_DEBUG_PKT_SEND_NIC,
	OFP_DEBUG_PKT_RECV_KNI,
	OFP_DEBUG_PKT_SEND_KNI
};

extern struct ofp_flag_descript_s ofp_flag_descript[];

#define OFP_DEBUG_PACKET(_type_, pkt, port) do {\
	if (ofp_debug_flags & ofp_flag_descript[_type_].flag) { \
		ofp_print_packet( \
			ofp_flag_descript[_type_].flag_descript, \
				pkt); \
		if (ofp_debug_flags & OFP_DEBUG_CAPTURE) { \
			ofp_save_packet_to_pcap_file( \
				ofp_flag_descript[_type_].flag, \
					pkt, port); \
		} \
	} \
} while (0)

#ifdef __cplusplus
}
#endif

#endif
