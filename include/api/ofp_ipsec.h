/*
 * Copyright (c) 2017, Cavium Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef OFP_IPSEC_H
#define OFP_IPSEC_H

#include <odp_api.h>
#include <ofp_in.h>
#include <ofp_in6.h>

/***********************************************************************
 * OFP Security Association Database Structures
 **********************************************************************/

/**
 * IPSEC SA handle
 */
typedef struct ofp_ipsec_sa *ofp_ipsec_sa_handle;
#define OFP_IPSEC_SA_INVALID ((ofp_ipsec_sa_handle)0)

/**
 * IPSEC SA/SP direction
 */
typedef enum ofp_ipsec_dir_t {
	/** Inbound IPSEC SA/SP */
	OFP_IPSEC_DIR_INBOUND = ODP_IPSEC_DIR_INBOUND,
	/** Outbound IPSEC SA/SP */
	OFP_IPSEC_DIR_OUTBOUND = ODP_IPSEC_DIR_OUTBOUND
} ofp_ipsec_dir_t;

/**
 * IPSEC protocol
 */
typedef enum ofp_ipsec_proto_t {
	/** ESP protocol */
	OFP_IPSEC_PROTO_ESP = ODP_IPSEC_ESP,
	/** AH protocol */
	OFP_IPSEC_PROTO_AH = ODP_IPSEC_AH
} ofp_ipsec_proto_t;

/**
 * IPSEC mode
 */
typedef enum ofp_ipsec_mode_t {
	/** IPSEC tunnel mode */
	OFP_IPSEC_MODE_TUNNEL = ODP_IPSEC_MODE_TUNNEL,
	/** IPSEC transport mode */
	OFP_IPSEC_MODE_TRANSPORT = ODP_IPSEC_MODE_TRANSPORT
} ofp_ipsec_mode_t;

/**
 * IPSEC cipher algorithm
 */
typedef enum ofp_ipsec_cipher_alg_t {
	/** No cipher algorithm specified */
	OFP_IPSEC_CIPHER_ALG_NULL = ODP_CIPHER_ALG_NULL,
	/** Triple DES with cipher block chaining */
	OFP_IPSEC_CIPHER_ALG_3DES_CBC = ODP_CIPHER_ALG_3DES_CBC,
	/** AES with cipher block chaining */
	OFP_IPSEC_CIPHER_ALG_AES_CBC = ODP_CIPHER_ALG_AES_CBC,
	/** AES in Galois/Counter Mode
	 *
	 *  @note Must be paired with cipher OFP_IPSEC_AUTH_ALG_AES_GCM
	 */
	OFP_IPSEC_CIPHER_ALG_AES_GCM = ODP_CIPHER_ALG_AES_GCM
} ofp_ipsec_cipher_alg_t;

/**
 * IPSEC maximum key size
 */
#define OFP_IPSEC_MAX_KEY_SZ 512

/**
 * IPSEC key structure
 */
typedef struct ofp_ipsec_key_t {
	/** Key length in bytes
	 *
	 * @note With AES_GCM the key must be 4 bytes longer than the AES key.
	 * The last 4 bytes of the key are used as the salt value.
	 */
	uint16_t key_len;
	/** Key data */
	uint8_t key_data[OFP_IPSEC_MAX_KEY_SZ];
} ofp_ipsec_key_t;

/**
 * IPSEC authentication algorithm
 */
typedef enum ofp_ipsec_auth_alg_t {
	/** No authentication algorithm specified */
	OFP_IPSEC_AUTH_ALG_NULL = ODP_AUTH_ALG_NULL,
	/** HMAC-MD5
	 *
	 * MD5 algorithm in HMAC mode
	 */
	OFP_IPSEC_AUTH_ALG_MD5_HMAC = ODP_AUTH_ALG_MD5_HMAC,
	/** HMAC-SHA-1
	 *
	 * SHA-1 algorithm in HMAC mode
	 */
	OFP_IPSEC_AUTH_ALG_SHA1_HMAC = ODP_AUTH_ALG_SHA1_HMAC,
	/** HMAC-SHA-256
	 *
	 *  SHA-256 algorithm in HMAC mode
	 */
	OFP_IPSEC_AUTH_ALG_SHA256_HMAC = ODP_AUTH_ALG_SHA256_HMAC,
	/** HMAC-SHA-512
	 *
	 *  SHA-512 algorithm in HMAC mode
	 */
	OFP_IPSEC_AUTH_ALG_SHA512_HMAC = ODP_AUTH_ALG_SHA512_HMAC,
	/** AES in Galois/Counter Mode
	 *
	 *  @note Must be paired with cipher OFP_IPSEC_CIPHER_ALG_AES_GCM
	 */
	OFP_IPSEC_AUTH_ALG_AES_GCM = ODP_AUTH_ALG_AES_GCM,
	/** AES Galois Message Authentication Code
	 *
	 *  @note Must be paired with cipher OFP_IPSEC_CIPHER_ALG_NULL
	 */
	OFP_IPSEC_AUTH_ALG_AES_GMAC = ODP_AUTH_ALG_AES_GMAC
} ofp_ipsec_auth_alg_t;

/**
 * IPSEC crypto parameters
 */
typedef struct ofp_ipsec_crypto_param_t {
	/** Cipher algorithm */
	ofp_ipsec_cipher_alg_t cipher_alg;
	/** Cipher key */
	ofp_ipsec_key_t cipher_key;
	/** Authentication algorithm */
	ofp_ipsec_auth_alg_t auth_alg;
	/** Authentication key */
	ofp_ipsec_key_t auth_key;
} ofp_ipsec_crypto_param_t;

/**
 * IPSEC tunnel type
 */
typedef enum ofp_ipsec_tunnel_type_t {
	/** Outer header is IPv4 */
	OFP_IPSEC_TUNNEL_IPV4 = ODP_IPSEC_TUNNEL_IPV4,
	/** Outer header is IPv6 */
	OFP_IPSEC_TUNNEL_IPV6 = ODP_IPSEC_TUNNEL_IPV6
} ofp_ipsec_tunnel_type_t;

/**
 * IPSEC tunnel parameters
 *
 * These parameters are used to build outbound tunnel headers.
 * All values are passed in CPU native byte / bit order if not
 * specified otherwise. IP addresses must be in NETWORK byte order.
 */
typedef struct ofp_ipsec_tunnel_param_t {
	/** Tunnel type: IPv4 or IPv6 */
	ofp_ipsec_tunnel_type_t type;
	union {
		/** IPv4 header parameters */
		struct {
			/** IPv4 source address (NETWORK ENDIAN) */
			struct ofp_in_addr src_addr;
			/** IPv4 destination address (NETWORK ENDIAN) */
			struct ofp_in_addr dst_addr;
			/** IPv4 Differentiated Services Code Point */
			uint8_t dscp;
			/** IPv4 Time To Live */
			uint8_t ttl;
		} ipv4;
		/** IPv6 header parameters */
		struct {
			/** IPv6 source address (NETWORK ENDIAN) */
			struct ofp_in6_addr src_addr;
			/** IPv6 destination address (NETWORK ENDIAN) */
			struct ofp_in6_addr dst_addr;
			/** IPv6 flow label */
			uint32_t flabel;
			/** IPv6 Differentiated Services Code Point */
			uint8_t dscp;
			/** IPv6 hop limit */
			uint8_t hlimit;
		} ipv6;
	};
} ofp_ipsec_tunnel_param_t;

/**
 * IPSEC SA option flags
 */
typedef struct ofp_ipsec_sa_opt_t {
	/** Extended Sequence Numbers (ESN)
	 *
	 * * 1: Use extended (64 bit) sequence numbers
	 * * 0: Use normal sequence numbers
	 */
	uint32_t esn : 1;
	/** UDP encapsulation
	 *
	 * * 1: Do UDP encapsulation/decapsulation so that IPSEC packets can
	 *      traverse through NAT boxes.
	 * * 0: No UDP encapsulation
	 */
	uint32_t udp_encap : 1;
	/** Copy DSCP bits
	 *
	 * * 1: Copy IPv4 or IPv6 DSCP bits from inner IP header to
	 *      the outer IP header in encapsulation, and vice versa in
	 *      decapsulation.
	 * * 0: Use values from ofp_ipsec_tunnel_param_t in encapsulation and
	 *      do not change DSCP field in decapsulation.
	 */
	uint32_t copy_dscp : 1;
	/** Copy IPv6 Flow Label
	 *
	 * * 1: Copy IPv6 flow label from inner IPv6 header to the
	 *      outer IPv6 header.
	 * * 0: Use value from ofp_ipsec_tunnel_param_t
	 */
	uint32_t copy_flabel : 1;
} ofp_ipsec_sa_opt_t;

/**
 * IPSEC SA lifetime limits
 *
 * These limits are used for setting up SA lifetime. IPSEC operations
 * check against the limits and output a status code when a limit is
 * crossed. Any number of limits may be used simultaneously.
 * Use zero when there is no limit.
 */
typedef odp_ipsec_lifetime_t ofp_ipsec_lifetime_t;

/**
 * IPSEC Security Association (SA) parameters
 */
typedef struct ofp_ipsec_sa_param_t {
	/** IPSEC SA direction: inbound or outbound */
	ofp_ipsec_dir_t dir;
	/** IPSEC protocol: ESP or AH */
	ofp_ipsec_proto_t proto;
	/** IPSEC protocol mode: transport or tunnel */
	ofp_ipsec_mode_t mode;
	/** Parameters for crypto and authentication algorithms */
	ofp_ipsec_crypto_param_t crypto;
	/** Parameters for tunnel mode */
	ofp_ipsec_tunnel_param_t tunnel;
	/** Various SA option flags */
	ofp_ipsec_sa_opt_t opt;
	/** SA lifetime parameters */
	ofp_ipsec_lifetime_t lifetime;
	/** Minimum anti-replay window size. Use 0 to disable anti-replay
	  * service. */
	uint32_t antireplay_ws;
	/** SPI value */
	uint32_t spi;
	/** VFR to use */
	uint16_t vrf;
	/** Unique identifier for the SA */
	uint32_t id;
} ofp_ipsec_sa_param_t;

typedef enum ofp_ipsec_sa_status_t {
	OFP_IPSEC_SA_ACTIVE,         /** SA is usable */
	OFP_IPSEC_SA_DISABLED,       /** SA destruction is in progress */
	OFP_IPSEC_SA_DESTROYED       /** SA has been destroyed */
} ofp_ipsec_sa_status_t;

typedef struct ofp_ipsec_sa_info_t {
	ofp_ipsec_sa_status_t status; /** SA status */
	ofp_ipsec_sa_param_t  param;  /** Creation parameters of the SA */
} ofp_ipsec_sa_info_t;

/***********************************************************************
 * OFP Security Association Database API
 **********************************************************************/

/**
 * Initialize IPSEC SA parameters
 *
 * Initialize an ofp_ipsec_sa_param_t to its default values for
 * all fields.
 *
 * @param param		Pointer to the parameter structure
 */
void ofp_ipsec_sa_param_init(ofp_ipsec_sa_param_t *param);

/**
 * Create IPSEC SA
 *
 * Create a new reference counted IPsec SA according to the parameters.
 * Set the reference count of the newly created SA to 2 (one for SAD and
 * one for the returned handle). Handles to the SA stay valid as long as
 * the reference count is positive.
 *
 * @param param		IPSEC SA parameters
 *
 * @return IPSEC SA handle
 * @retval OFP_IPSEC_SA_INVALID on failure
 *
 * @see ofp_ipsec_sa_param_init()
 */
ofp_ipsec_sa_handle ofp_ipsec_sa_create(const ofp_ipsec_sa_param_t *param);

/**
 * Destroy IPSEC SA
 *
 * Remove the specified IPsec SA from SAD and decrement its reference count.
 *
 * @param sa	IPSEC SA to be destroyed
 *
 * @retval 0	On success
 * @retval <0	On failure
 *
 * @see ofp_ipsec_sa_create()
 */
int ofp_ipsec_sa_destroy(ofp_ipsec_sa_handle sa);

/**
 * Flush IPSEC SAs
 *
 * Flush (destroy all) the IPSEC security associations in the given VRF.
 *
 * @param vrf	VRF to flush
 *
 * @retval 0	On success
 * @retval <0	On failure
 *
 * @see ofp_ipsec_sa_destroy()
 */
int ofp_ipsec_sa_flush(uint16_t vrf);

/**
 * Find IPSEC SA by ID and return a handle to it. The returned handle
 * stays valid (even through SA destruction) until unreferenced through
 * ofp_ipsec_sa_unref().
 *
 * @param id    ID of the SA
 *
 * @return IPSEC SA handle
 * @retval OFP_IPSEC_SA_INVALID on failure
 */
ofp_ipsec_sa_handle ofp_ipsec_sa_find_by_id(uint32_t id);

/**
 * Increment SA reference count.
 *
 * @param sa	IPSEC SA
 */
void ofp_ipsec_sa_ref(ofp_ipsec_sa_handle sa);

/**
 * Decrement SA reference count
 *
 * @param sa	IPSEC SA
 */
void ofp_ipsec_sa_unref(ofp_ipsec_sa_handle sa);

/**
 * Get the "first" SA for iteration through the SAs. Increment the reference
 * count of the returned SA so that the handle stays valid until unreferenced.
 *
 * @return IPSEC SA handle
 * @retval OFP_IPSEC_SA_INVALID when there are no SAs
 */
ofp_ipsec_sa_handle ofp_ipsec_sa_first(void);

/**
 * Return the "next" SA in iteration through the SAs. Increment the reference
 * count of the returned SA and decrement that of the passed SA.
 *
 * @return IPSEC SA handle
 * @retval OFP_IPSEC_SA_INVALID when there are no more SAs
 */
ofp_ipsec_sa_handle ofp_ipsec_sa_next(ofp_ipsec_sa_handle sa);

/**
 * Get SA information.
 *
 * @param sa	  IPSEC SA
 * @param status  Pointer to caller allocated info structure to be filled.
 */
void ofp_ipsec_sa_get_info(ofp_ipsec_sa_handle sa, ofp_ipsec_sa_info_t *info);

/***********************************************************************
 * OFP Security Policy Database Structures
 **********************************************************************/

/**
 * IPSEC SP handle
 */
typedef struct ofp_ipsec_sp *ofp_ipsec_sp_handle;
#define OFP_IPSEC_SP_INVALID ((ofp_ipsec_sp_handle)0)

/**
 * IPSEC SP actions
 */
typedef enum ofp_ipsec_action_t {
	/** IPSEC DISCARD action */
	OFP_IPSEC_ACTION_DISCARD = 0,
	/** IPSEC BYPASS action*/
	OFP_IPSEC_ACTION_BYPASS,
	/** IPSEC PROTECT action*/
	OFP_IPSEC_ACTION_PROTECT
} ofp_ipsec_action_t;

/**
 * IPSEC SP selector type
 */
typedef enum ofp_ipsec_selector_type_t {
	/** Security policy selector is IPv4 */
	OFP_IPSEC_SELECTOR_IPV4 = 0,
	/** Security policy selector is IPv6 */
	OFP_IPSEC_SELECTOR_IPV6
} ofp_ipsec_selector_type_t;

/**
 * IPSEC IPv4 address range
 *
 * For ANY address set first = last = 0
 */
typedef struct ofp_ipsec_ipv4_range {
	/** IPv4 first source address in range (NETWORK ENDIAN) */
	struct ofp_in_addr first_addr;
	/** IPv4 last source address in range (NETWORK ENDIAN) */
	struct ofp_in_addr last_addr;
} ofp_ipsec_ipv4_range_t;

/**
 * IPSEC IPv6 address range
 *
 * For ANY address set first = last = 0
 */
typedef struct ofp_ipsec_ipv6_range {
	/** IPv6 first source address in range (NETWORK ENDIAN) */
	struct ofp_in6_addr first_addr;
	/** IPv6 last source address in range (NETWORK ENDIAN) */
	struct ofp_in6_addr last_addr;
} ofp_ipsec_ipv6_range_t;

/**
 * IPSEC port range
 *
 * For ANY port set first = last = 0
 * For OPAQUE set first > last
 */
typedef struct ofp_ipsec_port_range {
	/** First source port in range (NETWORK ENDIAN) */
	uint16_t first_port;
	/** Last source port in range (NETWORK ENDIAN) */
	uint16_t last_port;
} ofp_ipsec_port_range_t;

/**
 * IPSEC selectors
 *
 * These selectors are used to match inbound / outbound packets.
 * All values are passed in CPU native byte / bit order if not specified
 * otherwise.
 * IP addresses must be in NETWORK byte order as those are passed in with
 * pointers and copied byte-by-byte from memory to the packet.
 */
typedef struct ofp_ipsec_selectors_t {
	/** Selector type: IPv4 or IPv6 */
	ofp_ipsec_selector_type_t type;
	/** Source IP address range selector */
	union {
		/** IPv4 address range */
		ofp_ipsec_ipv4_range_t src_ipv4_range;
		/** IPv6 address range */
		ofp_ipsec_ipv6_range_t src_ipv6_range;
	};
	/** Destination IP address range selector */
	union {
		/** IPv4 address range */
		ofp_ipsec_ipv4_range_t dst_ipv4_range;
		/** IPv6 address range */
		ofp_ipsec_ipv6_range_t dst_ipv6_range;
	};
	/** Source port range selector */
	ofp_ipsec_port_range_t src_port_range;
	/** Destination port range selector */
	ofp_ipsec_port_range_t dst_port_range;
	/**
	 * IP protocol selector.
	 * For ANY set ip_proto = 0
	 */
	uint16_t ip_proto;
} ofp_ipsec_selectors_t;

/**
 * IPSEC Security Policy (SP) parameters
 */
typedef struct ofp_ipsec_sp_param_t {
	/** Security Policy priority */
	uint32_t priority;
	/** Security Policy action */
	ofp_ipsec_action_t action;
	/** Security Association Database handle to use */
	ofp_ipsec_sa_handle sa;
	/** SP direction: inbound or outbound */
	ofp_ipsec_dir_t dir;
	/** SP selector */
	ofp_ipsec_selectors_t selectors;
	/** VFR to use */
	uint16_t vrf;
	/** Unique identifier for the SP */
	uint32_t id;
} ofp_ipsec_sp_param_t;

typedef enum ofp_ipsec_sp_status_t {
	OFP_IPSEC_SP_ACTIVE,         /** SP is usable */
	OFP_IPSEC_SP_DESTROYED       /** SP has been destroyed */
} ofp_ipsec_sp_status_t;

typedef struct ofp_ipsec_sp_info_t {
	ofp_ipsec_sp_status_t status; /** SP status */
	ofp_ipsec_sp_param_t  param;  /** Creation parameters of the SP */
} ofp_ipsec_sp_info_t;

/***********************************************************************
 * OFP Security Policy Database API
 **********************************************************************/

/**
 * Initialize IPSEC SP parameters
 *
 * Initialize an ofp_ipsec_sp_param_t to its default values for all fields.
 *
 * @param param	Pointer to the parameter structure
 */
void ofp_ipsec_sp_param_init(ofp_ipsec_sp_param_t *param);

/**
 * Create IPSEC SP
 *
 * Create a new reference counted IPsec SP according to the parameters.
 * Set the reference count of the newly created SP to 2 (one for SPD and
 * one for the returned handle). Handles to the SP stay valid as long as
 * the reference count is positive.
 *
 * @param param	IPSEC SP parameters
 *
 * @return IPSEC SP handle
 * @retval OFP_IPSEC_SP_INVALID on failure
 *
 * @see ofp_ipsec_sp_param_init()
 */
ofp_ipsec_sp_handle ofp_ipsec_sp_create(const ofp_ipsec_sp_param_t *param);

/**
 * Bind IPSEC SP to SA
 *
 * Binding outbound SP to outbound SA: the SA will be applied to all
 * packets matched by the SP.
 *
 * Binding inbound SA to inbound SP: packets processed with the inbound
 * SA must also match the selectors of the inbound SP. Single inbound SP
 * could be bound to several inbound SAs.
 *
 * Bind fails if SP and SA directions do not match.
 *
 * @param sp	IPSEC SP to bind
 * @param sa	IPSEC SA to bind
 *
 * @retval 0	On success
 * @retval <0	On failure
 *
 * @see ofp_ipsec_sp_create()
 */
int ofp_ipsec_sp_bind(ofp_ipsec_sp_handle sp, ofp_ipsec_sa_handle sa);

/**
 * Destroy IPSEC SP
 *
 * Remove the specified IPsec SP from SPD and decrement its reference count.
 *
 * @param sp	IPSEC SP to be destroyed
 *
 * @retval 0	On success
 * @retval <0	On failure
 *
 * @see ofp_ipsec_sp_create()
 */
int ofp_ipsec_sp_destroy(ofp_ipsec_sp_handle sp);

/**
 * Flush IPSEC SPs
 *
 * Flush (destroy all) the IPSEC security policies.
 *
 * @retval 0	On success
 * @retval <0	On failure
 *
 * @param vrf	VRF to flush
 *
 * @see ofp_ipsec_sp_destroy()
 */
int ofp_ipsec_sp_flush(uint16_t vrf);

/**
 * Find IPSEC SP by ID and return a handle to it. The returned handle
 * stays valid (even through SP destruction) until unreferenced through
 * ofp_ipsec_sp_unref().
 *
 * @param id    ID of the SP
 *
 * @return IPSEC SP handle
 * @retval OFP_IPSEC_SP_INVALID on failure
 */
ofp_ipsec_sp_handle ofp_ipsec_sp_find_by_id(uint32_t id);

/**
 * Increment SP reference count.
 *
 * @param sp	IPSEC SP
 */
void ofp_ipsec_sp_ref(ofp_ipsec_sp_handle sp);

/**
 * Decrement SP reference count.
 *
 * @param sp	IPSEC SP
 */
void ofp_ipsec_sp_unref(ofp_ipsec_sp_handle sp);

/**
 * Get the "first" SP for iteration through the SPs. Increment the reference
 * count of the returned SP so that the handle stays valid until unreferenced.
 *
 * @return IPSEC SP handle
 * @retval OFP_IPSEC_SP_INVALID when there are no SPs
 */
ofp_ipsec_sp_handle ofp_ipsec_sp_first(void);

/**
 * Return the "next" SP in iteration through the SPs. Increment the reference
 * count of the returned SP and decrement that of the passed SP.
 *
 * @return IPSEC SP handle
 * @retval OFP_IPSEC_SP_INVALID when there are no more SPs
 */
ofp_ipsec_sp_handle ofp_ipsec_sp_next(ofp_ipsec_sp_handle sp);

/**
 * Get SP information.
 *
 * @param sp	  IPSEC SP
 * @param status  Pointer to caller allocated info structure to be filled.
 */
void ofp_ipsec_sp_get_info(ofp_ipsec_sp_handle sp, ofp_ipsec_sp_info_t *info);

/***********************************************************************
 * OFP IPsec packet processing API
 **********************************************************************/

/**
 * Handle an IPsec packet event.
 *
 * In asynchronous and inline operation modes the result of an ODP IPsec
 * operation is delivered as an event through a queue. An OFP application
 * must provide these events to OFP using this function unless it uses
 * the default event dispatcher. The provided event will be freed.
 *
 * This function must be called with events that have type ODP_EVENT_PACKET
 * and subtype ODP_EVENT_PACKET_IPSEC.
 *
 * @param ev       Event handle
 * @param queue    Handle of the queue through which the event was received
 */
void ofp_ipsec_packet_event(odp_event_t ev, odp_queue_t queue);

/**
 * Handle an IPsec packet event.
 *
 * In asynchronous and inline operation modes the result of an ODP IPsec
 * operation may result in a status event. An OFP application must provide
 * these events to OFP using this function unless it uses the default event
 * dispatcher. The provided event will be freed.
 *
 * This function must be called with events of type ODP_EVENT_IPSEC_STATUS.
 *
 * @param ev       Event handle
 * @param queue    Handle of the queue through which the event was received
 */
void ofp_ipsec_status_event(odp_event_t ev, odp_queue_t queue);

#endif /* OFP_IPSEC_H */
