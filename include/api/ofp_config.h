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

/**Maximum number of CPUs.
 * Used to define the size of internal structures. */
#define OFP_MAX_NUM_CPU 64


/* OFP Configuration flavors */

#define OFP_CONFIG_DEFAULT 0
#define OFP_CONFIG_WEBSERVER 1
#define OFP_CONFIG_NETWRAP_WEBSERVER 2

#define OFP_CONFIG OFP_CONFIG_DEFAULT

/* Enable features */

/**Enable PERFORMANCE measurements mode. Some validations are skipped.*/
/* #define OFP_PERFORMANCE */


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
#if OFP_CONFIG == OFP_CONFIG_WEBSERVER || \
	OFP_CONFIG == OFP_CONFIG_NETWRAP_WEBSERVER
# define SHM_PKT_POOL_SIZE		(512*2048*16)
#else /*OFP_CONFIG_DEFAULT*/
# define SHM_PKT_POOL_SIZE		(512*2048)
#endif /* OFP_CONFIG */

/** Packet pool buffer size. */
#define SHM_PKT_POOL_BUFFER_SIZE	1856
/** Packet pool user area size. */
#define SHM_PKT_POOL_USER_AREA_SIZE	16
/** Packet pool name. */
#define SHM_PKT_POOL_NAME "packet_pool"

/**Socket handle values returned are in the interval:
 * [OFP_SOCK_NUM_OFFSET, OFP_SOCK_NUM_OFFSET + OFP_NUM_SOCKETS_MAX] */
#if OFP_CONFIG == OFP_CONFIG_WEBSERVER
/**Maximum number of sockets. */
# define OFP_NUM_SOCKETS_MAX 60000
/**First socket number value. */
# define OFP_SOCK_NUM_OFFSET 1024

/**Maximum number of TCP PCBs. */
# define OFP_NUM_PCB_TCP_MAX 60000

# define OFP_TCP_MAX_CONNECTION_RATE

#elif OFP_CONFIG == OFP_CONFIG_NETWRAP_WEBSERVER
/**Maximum number of sockets. */
# define OFP_NUM_SOCKETS_MAX 1000
/**First socket number value. */
# define OFP_SOCK_NUM_OFFSET 20
/**Maximum number of TCP PCBs. */
# define OFP_NUM_PCB_TCP_MAX 65534
# define OFP_TCP_MAX_CONNECTION_RATE

#else /*OFP_CONFIG_DEFAULT*/
/**Maximum number of sockets. */
# define OFP_NUM_SOCKETS_MAX 1024
/**First socket number value. */
# define OFP_SOCK_NUM_OFFSET 1024

/**Maximum number of TCP PCBs. */
# define OFP_NUM_PCB_TCP_MAX 2048
#endif /* OFP_CONFIG*/

/**Maximum number of fastpath interfaces used.
 * For each fastpath interface a PKTIO in opened by OFP.*/
#define OFP_FP_INTERFACE_MAX 8

/**Maximum number of input queues that can be configured for an
   * OFP interface*/
#define OFP_PKTIN_QUEUE_MAX 64

/**Maximum number of output queues that can be configured for an
 * OFP interface*/
#define OFP_PKTOUT_QUEUE_MAX 64

/**Maximum number of packets received at once in direct mode in
 * example applications - default value.*/
#define OFP_PKT_RX_BURST_SIZE 16

/**Maximum number of events received at once in scheduling mode
 * in default_event_dispatcher().*/
#define OFP_EVT_RX_BURST_SIZE 16

/**Number of packets sent at once (>= 1)   */
#define OFP_PKT_TX_BURST_SIZE 1

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
/**Default ARP age interval (in seconds) */
#define ARP_AGE_INTERVAL 60
/**Default ARP entry timeout (in seconds) */
#define ARP_ENTRY_TIMEOUT 1200
/**Timer trigger(s) to scan for old arp entries.*/
#define ARP_ENTRY_UPD_TIMEOUT 2
/**Time interval(s) while a packet is saved and waiting for an ARP reply. */
#define ARP_SAVED_PKT_TIMEOUT 10
/**Maximum number of saved packets waiting for an ARP reply. */
#define ARP_WAITING_PKTS_SIZE 2048

/**Enable IPv4 UDP checksum validation mechanism on input
 * packets. If enabled, validation is performed on input
 * packets. */
/*#define OFP_IPv4_UDP_CSUM_VALIDATE*/

/**Enable IPv4 UDP checksum computation mechanism for outgoing
 * packets. If enabled, computation is performed based on
 * sysctl() option net.inet.udp.checksum (default: compute
 * checksum). */
#define OFP_IPv4_UDP_CSUM_COMPUTE

/**Enable IPv4 TCP checksum validation mechanism on input
 * packets. If enabled, validation is performed on input
 * packets. */
/*#define OFP_IPv4_TCP_CSUM_VALIDATE*/

#endif
