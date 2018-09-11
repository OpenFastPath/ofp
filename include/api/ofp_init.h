/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

/**
 * @file
 *
 * @brief OFP initialization.
 *
 * OFP requires a global level init for the API library and a local init per
 * thread before the other OFP APIs may be called.
 * - ofp_init_global()
 * - ofp_init_local()
 *
 * For a graceful termination the matching termination APIs exit
 * - ofp_term_global()
 * - ofp_term_local()
 */

#ifndef __OFP_INIT_H__
#define __OFP_INIT_H__

#include <odp_api.h>
#include "ofp_hook.h"
#include "ofp_ipsec_init.h"

#if __GNUC__ >= 4
#pragma GCC visibility push(default)
#endif

/**
 * Checksum offloading configuration options bit field
 *
 * Packet IP/UDP/TCP checksum validation and insertion offloading
 * may be enabled or disabled:
 *
 * 0: Disable offloading.
 * 1: Enable offloading. This is the default value.
 *
 * When offloading is disabled, related checksums will be calculated by
 * software, if needed.
 *
 * When offloading is enabled, related checksums will be calculated either
 * by HW (if packet_io supports offloading) or by SW (if packet_io doesn't
 * support offloading), if needed.
 */
typedef struct ofp_chksum_offload_config_t {
	/** Enable IPv4 header checksum validation offload */
	uint16_t ipv4_rx_ena : 1;

	/** Enable UDP checksum validation offload */
	uint16_t udp_rx_ena  : 1;

	/** Enable TCP checksum validation offload */
	uint16_t tcp_rx_ena  : 1;

	/** Enable IPv4 header checksum insertion offload */
	uint16_t ipv4_tx_ena : 1;

	/** Enable UDP checksum insertion offload */
	uint16_t udp_tx_ena  : 1;

	/** Enable TCP checksum insertion offload */
	uint16_t tcp_tx_ena  : 1;
} ofp_chksum_offload_config_t;

/**
 * OFP API initialization data
 *
 * @see ofp_init_global_param()
 */
typedef struct ofp_global_param_t {
	/**
	 * Count of interfaces to be initialized. The default value is
	 * 0.
	 */
	uint16_t if_count;

	/**
	 * CPU core to which internal OFP control threads are pinned.
	 * The default value is 0.
	 */
	uint16_t linux_core_id;

	/**
	 * Names of the interfaces to be initialized. The naming
	 * convention depends on the operating system and the ODP
	 * implementation. Must point to an array of at least if_count
	 * zero terminated strings.
	 */
	char **if_names;

	/**
	 * Packet input mode of the interfaces initialized by OFP.
	 * Must be ODP_PKTIN_MODE_SCHED if default_event_dispatcher()
	 * is used.
	 *
	 * Default value is ODP_PKTIN_MODE_SCHED.
	 */
	odp_pktin_mode_t pktin_mode;

	/**
	 * Packet output mode of the interfaces initialized by OFP.
	 *
	 * Default value is ODP_PKTOUT_MODE_DIRECT.
	 */
	odp_pktout_mode_t pktout_mode;

	/**
	 * Scheduler synchronization method of the pktin queues of the
	 * interfaces initialized by OFP in the scheduled mode.
	 * Ignored when pktin_mode is not ODP_PKTIN_MODE_SCHED.
	 *
	 * Default value is ODP_SCHED_SYNC_ATOMIC.
	 */
	odp_schedule_sync_t sched_sync;

	/**
	 * ODP event scheduling group for all scheduled event queues
	 * (pktio queues, timer queues and other queues) created in
	 * OFP initialization. The default value is
	 * ODP_SCHED_GROUP_ALL.
	 */
	odp_schedule_group_t sched_group;

	/**
	 * Packet processing hooks. The default value is NULL for
	 * every hook.
	 *
	 * @see ofp_hook.h
	 */
	ofp_pkt_hook pkt_hook[OFP_HOOK_MAX];

	/**
	 * Create netlink listener thread. If slow path is enabled,
	 * then default is TRUE, otherwise default is FALSE.
	 */
	odp_bool_t enable_nl_thread;

	/**
	 * Global ARP parameters.
	 */
	struct arp_s {
		/** Maximum number of ARP entries. Default is OFP_ARP_ENTRIES. */
		int entries;

		/** ARP hash bits. Default is OFP_ARP_HASH_BITS. */
		int hash_bits;

		/** Entry timeout in seconds. Default is OFP_ARP_ENTRY_TIMEOUT. */
		int entry_timeout;

		/**
		 * Timeout (in seconds) for a packet waiting for ARP
		 * to complete. Default is OFP_ARP_SAVED_PKT_TIMEOUT.
		 */
		int saved_pkt_timeout;

		/**
		 * Reply to an ARP request only if the target address of the
		 * request is an address of the receiving interface.
		 * Ignore the request otherwise.
		 *
		 * If not set, reply to an ARP request for any local IP
		 * address regardless of the receiving interface.
		 *
		 * See net.ipv4.conf.all.arp_ignore sysctl in Linux.
		 *
		 * Default value is 0.
		 */
		odp_bool_t check_interface;
	} arp;

	/**
	 * Maximum number of events received at once. Default is
	 * OFP_EVT_RX_BURST_SIZE.
	 */
	int evt_rx_burst_size;

	/**
	 * Number of packets sent at once (>= 1).
	 * Default is OFP_PKT_TX_BURST_SIZE
	 */
	uint32_t pkt_tx_burst_size;

	/**
	 * Maximum number of TCP PCBs.
	 * Default value is OFP_NUM_PCB_TCP_MAX
	 */
	int pcb_tcp_max;

	struct pkt_pool_s {
		/** Packet pool size; Default value is SHM_PKT_POOL_NB_PKTS */
		int nb_pkts;

		/**
		 * Packet pool buffer size;
		 * Default value is SHM_PKT_POOL_BUFFER_SIZE
		 */
		unsigned long buffer_size;
	} pkt_pool;

	/**
	 * Maximum number of VLANs. Default is OFP_NUM_VLAN.
	 */
	int num_vlan;

	/**
	 * IPv4 route mtrie parameters.
	 */
	struct mtrie_s {
		/** Number of routes. Default is OFP_ROUTES. */
		int routes;
		/** Number of 8 bit mtrie nodes. Default is OFP_MTRIE_TABLE8_NODES. */
		int table8_nodes;
	} mtrie;

	/**
	 * Maximum number of VRFs. Default is OFP_NUM_VRF.
	 *
	 * VRF IDs used in interfaces and routes must be less than
	 * this value.
	 */
	int num_vrf;

	/**
	 * Checksum offloading options.
	 */
	ofp_chksum_offload_config_t chksum_offload;

	/*
	 * IPsec parameters
	 */
	struct ofp_ipsec_param ipsec;
} ofp_global_param_t;

/**
 * Initialize ofp_global_param_t to its default values.
 *
 * This function should be called to initialize the supplied parameter
 * structure to default values before setting application specific values
 * and before passing the parameter structure to ofp_init_global().
 *
 * Using this function makes the application to some extent forward
 * compatible with future versions of OFP that may add new fields in
 * the parameter structure.
 *
 * If libconfig is enabled, a configuration file may be used. The
 * configuration file location may be set using the environment
 * variable OFP_CONF_FILE. If the environment variable is not set, the
 * file is read from $(sysconfdir)/ofp.conf, normally
 * /usr/local/etc/ofp.conf.
 *
 * The file uses libconfig format. See
 * http://www.hyperrealm.com/libconfig/libconfig_manual.html#Configuration-File-Grammar
 *
 * <pre>
 * ofp_global_param: {
 *     if_names = [ string, string, ... ]
 *     linux_core_id = integer
 *     pktin_mode = "direct" | "sched" | "queue" | "disabled"
 *     pktout_mode = "direct" | "queue" | "tm" | "disabled"
 *     sched_sync = "parallel" | "atomic" | ordered"
 *     sched_group = "all | "worker" | "control"
 *     enable_nl_thread = boolean
 *     arp: {
 *         entries = integer
 *         hash_bits = integer
 *         entry_timeout = integer
 *         saved_pkt_timeout = integer
 *         check_interface = boolean
 *     }
 *     evt_rx_burst_size = integer
 *     pkt_tx_burst_size = integer
 *     pcb_tcp_max = integer
 *     pkt_pool: {
 *         nb_pkts = integer
 *         buffer_size = integer
 *     }
 *     num_vlan = integer
 *     mtrie: {
 *         routes = integer
 *         table8_nodes = integer
 *     }
 *     num_vrf = integer
 *     chksum_offload: {
 *         ipv4_rx_ena = true
 *         udp_rx_ena = true
 *         tcp_rx_ena = true
 *         ipv4_tx_ena = true
 *         udp_tx_ena = true
 *         tcp_tx_ena = true
 *     }
 * }
 * </pre>
 *
 * @param params structure to initialize
 *
 * @see ofp_init_global()
 */
void ofp_init_global_param(ofp_global_param_t *params);

/**
 * Initialize ofp_global_param_t according to a configuration file.
 *
 * This function is similar to ofp_init_global_param(), but allows the
 * caller to specify the location of the configuration file. Calling
 * this function with filename = NULL has the same effect as calling
 * ofp_init_global_param(). Passing a zero-length string as filename
 * means that no configuration file will be used, not even the default
 * or the file specified by the environment variable.
 *
 * @see ofp_init_global_param()
 *
 * @param params structure to initialize
 * @param filename name of the configuration file
 */
void ofp_init_global_param_from_file(ofp_global_param_t *params, const char *filename);

/**
 * OFP global initialization
 *
 * This function must be called once in an ODP control thread before calling any
 * other OFP API functions.
 *
 * @param instance ODP instance
 * @param params Structure with parameters for global init of OFP API
 *
 * @retval 0 on success
 * @retval -1 on failure
 *
 * @see ofp_init_local() which is required per thread before use.
 */
int ofp_init_global(odp_instance_t instance, ofp_global_param_t *params);

/**
 * Thread local OFP initialization
 *
 * All threads must call this function before calling any other OFP API
 * functions.
 *
 * @retval 0 on success
 * @retval -1 on failure
 *
 * @see ofp_init_global() which must have been called prior to this.
 */
int ofp_init_local(void);

/**
 * OFP global termination
 *
 * This function must be called only once in an ODP control
 * thread before exiting application.
 *
 * Should be called from a thread within the same schedule group specified in
 * the parameters of ofp_init_global().
 *
 * @retval 0 on success
 * @retval -1 on failure
 *
 * @see ofp_term_local() which is required per thread before
 *      use.
 */
int ofp_term_global(void);

/**
 * Thread local OFP termination
 *
 * All threads must call this function before thread
 * termination.
 *
 * @retval 0 on success
 * @retval -1 on failure
 *
 * @see ofp_term_global() which may be called after this.
 */
int ofp_term_local(void);


/**
 * Stop packet processing
 *
 * Stop processing threads
 *
 *
 * @retval ofp_get_processing_state() which may be called get
 *         the processing state
 *
 *
 * @see
 */
void ofp_stop_processing(void);

/**
 * Get address of processing state variable
 *
 * All processing loops should stop when
 * processing state turns 0
 *
 * @retval non NULL on success
 * @retval NULL on failure
 *
 * @see ofp_stop_processing() which may be called to stop the
 *      processing.
 */

odp_bool_t *ofp_get_processing_state(void);

#if __GNUC__ >= 4
#pragma GCC visibility pop
#endif

#endif /* __OFP_INIT_H__ */
