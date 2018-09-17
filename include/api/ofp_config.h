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
 * @brief Configuration defaults for OFP
 *
 */

/* Enable features */

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
# define SHM_PKT_POOL_NB_PKTS		10240

/** Packet pool buffer size. */
#define SHM_PKT_POOL_BUFFER_SIZE	1856
/** Packet pool name. */
#define SHM_PKT_POOL_NAME "packet_pool"

/** Maximum size of transmitted IP datagram fragments. */
#define OFP_MTU_SIZE 1500

/**Socket handle values returned are in the interval:
 * [OFP_SOCK_NUM_OFFSET, OFP_SOCK_NUM_OFFSET + OFP_NUM_SOCKETS_MAX] */
#if defined(OFP_CONFIG_WEBSERVER)
/**Maximum number of sockets. */
# define OFP_NUM_SOCKETS_MAX 60000
/**First socket number value. */
# define OFP_SOCK_NUM_OFFSET 1024

/**Maximum number of TCP PCBs. */
# define OFP_NUM_PCB_TCP_MAX 60000

# define OFP_TCP_MAX_CONNECTION_RATE

#elif defined(OFP_CONFIG_NETWRAP_WEBSERVER)
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
#endif /* OFP_CONFIGS*/

/** Epoll set size */
#define EPOLL_SET_SIZE 16

/**Maximum number of fastpath interfaces used.
 * For each fastpath interface a PKTIO in opened by OFP.*/
#define OFP_FP_INTERFACE_MAX 8

/* Maximum number of VLANs. */
#define OFP_NUM_VLAN 256

/* Maximum number of IPs per ifnet */
#define OFP_NUM_IFNET_IP_ADDRS 8

/**Maximum number of output queues that can be configured for an
 * OFP interface*/
#define OFP_PKTOUT_QUEUE_MAX 64

/**Maximum number of events received at once in scheduling mode
 * in default_event_dispatcher().*/
#define OFP_EVT_RX_BURST_SIZE 16

/**Number of packets sent at once (>= 1)   */
#define OFP_PKT_TX_BURST_SIZE 1

/**Controls memory size for IPv4 MTRIE 16/8/8 data structure.
 * It defines the number of small tables (8) used to store routes.*/
#define OFP_MTRIE_TABLE8_NODES 128
/** Defines the maximum number of routes that are stored in the MTRIE.*/
#define OFP_ROUTES 65536

/** Number of VRFs. */
#define OFP_NUM_VRF 1

/**Controls memory size for IPv4 radix tree data structure.
 * It defines the number of radix tree nodes used to store routes.*/
#define ROUTE4_NODES 65536

/**Controls memory size for IPv6 radix tree data structure.
 * It defines the number of radix tree nodes used to store routes.*/
#define ROUTE6_NODES 65536

/**ARP hash bits. */
#define OFP_ARP_HASH_BITS 11
/**Total number of ARP entries that can be stored. */
#define OFP_ARP_ENTRIES 128
/**Default ARP entry timeout (in seconds). */
#define OFP_ARP_ENTRY_TIMEOUT 1200
/**Time interval(s) while a packet is saved and waiting for an ARP reply. */
#define OFP_ARP_SAVED_PKT_TIMEOUT 10

/**Enable IPv4 UDP checksum validation mechanism on input
 * packets. If enabled, validation is performed on input
 * packets. */
#define OFP_IPv4_UDP_CSUM_VALIDATE

/**Enable IPv4 UDP checksum computation mechanism for outgoing
 * packets. If enabled, computation is performed based on
 * sysctl() option net.inet.udp.checksum (default: compute
 * checksum). */
#define OFP_IPv4_UDP_CSUM_COMPUTE

/**Enable IPv4 TCP checksum validation mechanism on input
 * packets. If enabled, validation is performed on input
 * packets. */
#define OFP_IPv4_TCP_CSUM_VALIDATE

/**Enable (1) or disable (0) offloading of IPv4/UDP/TCP checksum
 * validation and insertion. If enabled, checksum calculation will
 * be performed by HW, if possible. See ofp_chksum_offload_config_t.*/
#define OFP_CHKSUM_OFFLOAD_IPV4_RX 1
#define OFP_CHKSUM_OFFLOAD_UDP_RX  1
#define OFP_CHKSUM_OFFLOAD_TCP_RX  1
#define OFP_CHKSUM_OFFLOAD_IPV4_TX 1
#define OFP_CHKSUM_OFFLOAD_UDP_TX  1
#define OFP_CHKSUM_OFFLOAD_TCP_TX  1

#endif
