/*
 * Copyright (c) 2018, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#ifndef OFPI_IPSEC_H
#define OFPI_IPSEC_H

#include <odp_api.h>
#include "api/ofp_types.h"
#include "api/ofp_ip.h"
#include "api/ofp_ipsec.h"
#include "ofpi_ipsec_spd.h"
#include "ofpi_ipsec_sad.h"
#include "ofpi_brlock.h"

struct ofp_ipsec_param;

/*
 * Global IPsec state
 */
struct ofp_ipsec {
	odp_atomic_u32_t ipsec_active;
	odp_ipsec_op_mode_t inbound_op_mode;
	odp_ipsec_op_mode_t outbound_op_mode;
	ofp_brlock_t processing_lock;
	uint32_t max_num_sa;
	odp_queue_t in_queue;
	odp_queue_t out_queue;
};

extern __thread struct ofp_ipsec *ofp_ipsec_shm;

/*
 * Initialize IPsec parameters to their default values.
 */
void ofp_ipsec_param_init(struct ofp_ipsec_param *param);

/*
 * Prepare for global init
 */
void ofp_ipsec_init_prepare(const struct ofp_ipsec_param *param);

/*
 * Initialize IPsec. Must be called in single thread before starting
 * traffic processing.
 *
 * Returns nonzero on error.
 */
int ofp_ipsec_init_global(const struct ofp_ipsec_param *param);

/*
 * Thread specific IPsec initialization.
 */
int ofp_ipsec_init_local(void);

/*
 * Stop IPsec before termination. This may generate status events that need
 * to be handled to finalize SA destruction.
 */
int ofp_ipsec_stop_global(void);

/*
 * Return true if ofp_ipsec_term_global() can be called, i.e. if all
 * SAs have been destroyed.
 */
int ofp_ipsec_term_global_ok(void);

/*
 * IPsec module termination
 */
int ofp_ipsec_term_global(void);

/*
 * IPsec packet flags stored in the user area of packets
 */
enum ofp_ipsec_pkt_flags {
	/*
	 * Inbound IPsec decapsulation has been done for the packet.
	 *
	 * Prevents inbound policy check from dropping clear text packets
	 * decapsulated from IPsec.
	 */
	OFP_IPSEC_INBOUND_DONE = 1
};

/*
 * Set IPsec packet flags, clearing the old flags.
 */
void ofp_ipsec_flags_set(odp_packet_t pkt, uint8_t flags);

/*
 * Get IPsec packet flags.
 */
uint8_t ofp_ipsec_flags(const odp_packet_t pkt);

/*
 * Return true if inbound or outbound IPsec policies are not empty.
 * For fast skipping of IPsec processing when there is no IPsec config.
 */
static inline int ofp_ipsec_active(void)
{
	return odp_atomic_load_u32(&ofp_ipsec_shm->ipsec_active);
}

/*
 * Perform outbound IPsec processing using the given SA.
 * The SA must have been acquired through ofp_ipsec_out_lookup().
 */
enum ofp_return_code ofp_ipsec_output(odp_packet_t pkt,
				       ofp_ipsec_sa_handle sa);

/*
 * Private to ofp_ipsec.
 */
ofp_ipsec_action_t ofp_ipsec_in_lookup(uint16_t vrf, odp_packet_t pkt);

/*
 * Check if an incoming packet should be dropped or not according to
 * inbound IPsec policy.
 */
static inline enum ofp_return_code ofp_ipsec_inbound_check(uint16_t vrf,
							   odp_packet_t pkt,
							   struct ofp_ip *ip,
							   int is_ours)
{
	if (!ofp_ipsec_active())
		return OFP_PKT_CONTINUE;

	if (is_ours && (ip->ip_p == OFP_IPPROTO_ESP ||
			ip->ip_p == OFP_IPPROTO_AH))
		return OFP_PKT_CONTINUE;

	if ((ofp_ipsec_flags(pkt) & OFP_IPSEC_INBOUND_DONE) ||
	    ofp_ipsec_in_lookup(vrf, pkt) == OFP_IPSEC_ACTION_BYPASS)
		return OFP_PKT_CONTINUE;

	return OFP_PKT_DROP;
}

/*
 * Private to ofp_ipsec.
 */
ofp_ipsec_action_t ofp_ipsec_out_lookup_priv(uint16_t vrf,
					     odp_packet_t pkt,
					     ofp_ipsec_sa_handle *sa);

/*
 * Perform outbound IPsec policy lookup.
 *
 * Return value indicates if the packet should be dropped.
 *
 * If an outbound policy with a PROTECT action and a valid SA matches the
 * packet, set *sa to the SA handle. The SA must be released by calling
 * ofp_ipsec_output() or ofp_ipsec_output_cancel() in the same thread before
 * calling any other IPsec functions.
 */
static inline enum ofp_return_code ofp_ipsec_out_lookup(uint16_t vrf,
							odp_packet_t pkt,
							ofp_ipsec_sa_handle *sa)
{
	ofp_ipsec_action_t action;

	*sa = OFP_IPSEC_SA_INVALID;
	if (ofp_ipsec_active()) {
		action = ofp_ipsec_out_lookup_priv(vrf, pkt, sa);
		if (action == OFP_IPSEC_ACTION_DISCARD)
			return OFP_PKT_DROP;
		if (action == OFP_IPSEC_ACTION_PROTECT && *sa == NULL)
			return OFP_PKT_DROP;
	}
	return OFP_PKT_CONTINUE;
}

/*
 * Release the SA processing context created in ofp_ipsec_out_lookup()
 * when ofp_ipsec_output() is not called.
 */
static inline void ofp_ipsec_output_cancel(ofp_ipsec_sa_handle sa)
{
	if (sa != OFP_IPSEC_SA_INVALID)
		ofp_brlock_read_unlock(&ofp_ipsec_shm->processing_lock);
}

/*
 * Protosw function for incoming ESP and AH packets.
 */
enum ofp_return_code ofp_ipsec_input(odp_packet_t *pkt, int off);

#endif /* OFPI_IPSEC_H */
