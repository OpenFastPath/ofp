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

/**OFP configured to send ICMP redirect*/
/* #define OFP_SEND_ICMP_REDIRECT */


/* Configure values */

/**Value of burst size used in default_event_dispatcher.*/
#define OFP_EVENT_BURST_SIZE 16

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

#endif
