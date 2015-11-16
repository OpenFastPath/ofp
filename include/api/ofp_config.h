/* Copyright (c) 2015, ENEA Software AB
 * Copyright (c) 2015, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef __OFP_CONFIG_H__
#define __OFP_CONFIG_H__

/**
 * @file
 *
 * @brief Configuration file for OFP
 *
 */

/* Enable features */

/**Enable PERFORMANCE measurements mode. Some validations are skipped.*/
/* #define OFP_PERFORMANCE */

/**Enable burst send of packets.*/
#ifdef OFP_PERFORMANCE
/* #define OFP_SEND_PKT_BURST */
#endif

/**Enable static socket configuration mode.
 * It is meant to be used with application where the socket
 * configuration does not change during intensive packet
 * processing phase of application.
 * The purpose is to increase performance by removing locks.
 * Application run time is divided in two phases:
 *  - Initialization phase: all socket creation and configuration
 *    is done during this phase. It starts after completion of
 *    OFP global/local initialization and may expand until after
 * creation of dispatched threads.
 *  - Intensive packet processing phase: no new sockets / binds
 *    are permitted.
 * Restrictions:
 *  During "Initialization phase", all socket operations must be
 *  serialized.
 *  During "Intensive packet processing phase", calls to
 *  ofp_socket(), ofp_bind(), ofp_accept(), ofp_connect(),
 *  ofp_listen(), ofp_shutdown() and ofp_close() are forbidden.
 *  Also, socket must be bound (preferably not to OFP_INADDR_ANY).
 * Implementation details:
 *   Implementation is based on disabling locks on UDP and TCP
 *   hash of PCBs. When OFP_STATIC_SOCKET_CONFIG is defined then
 *   protocols PCB hash will not be protected against concurrent
 *   adding or removing of items.
 */
/* #define OFP_STATIC_SOCKET_CONFIG */

/**OFP configured to send ICMP redirect*/
/* #define OFP_SEND_ICMP_REDIRECT */


/* Configure values */

/** Packet pool size. */
#define SHM_PKT_POOL_SIZE		(512*2048)
/** Packet pool buffer size. */
#define SHM_PKT_POOL_BUFFER_SIZE	1856
/** Packet pool user area size. */
#define SHM_PKT_POOL_USER_AREA_SIZE	16

/**Maximum number of sockets. */
#define OFP_NUM_SOCKETS_MAX 1024

/**Maximum number of fastpath interfaces used.
 * For each fastpath interface a PKTIO in opened by OFP.*/
#define OFP_FP_INTERFACE_MAX 8

/**Value of burst size used in default_event_dispatcher.*/
#define OFP_EVENT_BURST_SIZE 16
/**Maximum number of packets received when scheduling with schedule_multi.
 * Value in default_event_dispatcher().*/
#define OFP_PKT_SCHED_MULTI_EVENT_SIZE 16
/**Number of packets sent at once in send_pkt_burst_out() */
#define OFP_PKT_TX_BURST_SIZE 16

#ifdef MTRIE
/**Controls memory size for IPv4 MTRIE 16/8/8 data structure.
 * It defines the number of large tables (16) used to store routes.
 * MTRIE should be defined*/
#define ROUTE4_MTRIE16_TABLE_NODES 8
/**Controls memory size for IPv4 MTRIE 16/8/8 data structure.
 * It defines the number of small tables (8) used to store routes.
 * MTRIE should be defined*/
#define ROUTE4_MTRIE8_TABLE_NODES 128
/** Defines the maximum number of routes that are stored in the MTRIE.*/
#define ROUTE4_RULE_LIST_SIZE 65536
#else
/**Controls memory size for IPv4 radix tree data structure.
 * It defines the number of radix tree nodes used to store routes.
 * MTRIE feature should not be defined*/
#define ROUTE4_NODES 65536
#endif

/**Controls memory size for IPv6 radix tree data structure.
 * It defines the number of radix tree nodes used to store routes.*/
#define ROUTE6_NODES 65536

/**Arp entry table size. Controls memory size for arp entries.
 * Must be power of two */
#define ARP_ENTRY_TABLE_SIZE 2048
/**Total number of arp entries that can be stored. */
#define ARP_ENTRIES_SIZE (NUM_SETS * 4)
/**Cleanup Timer Interval (s)*/
#define ARP_CLEANUP_TIMER_INTERVAL 60
/**Arp entries are removed after this timeout interval(s)*/
#define ARP_ENTRY_TIMEOUT 1200
/**Timer trigger(s) to scan for old arp entries.*/
#define ARP_ENTRY_UPD_TIMEOUT 2
/**Time interval(s) while a packet is saved and waiting for an ARP reply. */
#define ARP_SAVED_PKT_TIMEOUT 10
/**Maximum number of saved packets waiting for an ARP reply. */
#define ARP_WAITING_PKTS_SIZE 2048

#endif
