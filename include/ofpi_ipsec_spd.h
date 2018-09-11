/*
 * Copyright (c) 2018, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#ifndef OFPI_IPSEC_SPD_H
#define OFPI_IPSEC_SPD_H

#include <odp_api.h>
#include "api/ofp_types.h"
#include "api/ofp_ipsec.h"
#include "ofpi_ipsec_sad.h"

void ofp_ipsec_spd_init_prepare(uint32_t max_num_sp);
int ofp_ipsec_spd_init_global(uint32_t max_num_sp);
int ofp_ipsec_spd_init_local(void);
int ofp_ipsec_spd_term_global(void);

/****************************************************************************
 * SP management
 ****************************************************************************/

/*
 * Create a SP. The parameter struct can be freed after the call.
 *
 * Returns nonzero on error.
 */
struct ofp_ipsec_sp *ofp_ipsec_sp_add(const ofp_ipsec_sp_param_t *param);

/*
 * Delete a SP.
 */
int ofp_ipsec_sp_del(struct ofp_ipsec_sp *sp);

/*
 * Delete all SPs in the given VRF.
 */
int ofp_ipsec_sp_del_all(uint16_t vrf);

/*
 * Get the parameters of a SP.
 */
const ofp_ipsec_sp_param_t *ofp_ipsec_sp_get_param(struct ofp_ipsec_sp *sp);

/****************************************************************************
 * Lookup support
 ****************************************************************************/

/*
 * Add SP to policy lookup
 *
 * Not multi-thread safe with respect to the other lookup related functions.
 */
void ofp_ipsec_sp_lookup_add_sp(struct ofp_ipsec_sp *sp);

/*
 * Delete SP from policy lookup and indicate if the lookup tables became empty.
 *
 * Not multi-thread safe with respect to the other lookup related functions.
 */
int ofp_ipsec_sp_lookup_del_sp(struct ofp_ipsec_sp *sp, int *empty);

/*
 * Get pointer to storage for user managed SA handle. The user is
 * responsible of SA refcounting and inter-thread synchronization when
 * the SA handle is changed.
 */
ofp_ipsec_sa_handle *ofp_ipsec_sp_get_sa_area(struct ofp_ipsec_sp *sp);

/*
 * Lookup the outbound policy mathing to a given packet.
 * Returns the action of the policy and for IPSEC actions
 * the associated SA or OFP_IPSEC_SA_INVALID.
 */
ofp_ipsec_action_t ofp_ipsec_sp_out_lookup(uint16_t vrf, odp_packet_t pkt,
					   ofp_ipsec_sa_handle *sa);

/*
 * Lookup the inbound policy matching to a given packet.
 */
ofp_ipsec_action_t ofp_ipsec_sp_in_lookup(uint16_t vrf, odp_packet_t pkt);

#endif /* OFPI_IPSEC_SPD_H */
