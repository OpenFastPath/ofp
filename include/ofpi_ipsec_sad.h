/*
 * Copyright (c) 2018, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#ifndef OFPI_IPSEC_SAD_H
#define OFPI_IPSEC_SAD_H

#include <odp_api.h>
#include "api/ofp_types.h"
#include "api/ofp_ipsec.h"

struct ofp_ipsec_global_param;

void ofp_ipsec_sad_init_prepare(uint32_t max_num_sa);
int ofp_ipsec_sad_init_global(uint32_t max_num_sa,
			      odp_queue_t inbound_queue,
			      odp_queue_t outbound_queue);
int ofp_ipsec_sad_init_local(void);
int ofp_ipsec_sad_term_global(void);

/*
 * Disable SA so that it will no longer be used in new IPsec encapsulation
 * or decapsulation operations. Can be called when other theads
 * are still actively using the SA for IPsec input or output.
 *
 * For inbound SAs with offloaded SA lookup odp_ipsec_sa_disable() is
 * called. For other SAs the SA is merely marked disabled.
 *
 * This is the first step in fully destroying an SA. The complete sequence
 * consists of ofp_ipsec_sa_disable(), ofp_ipsec_sa_disable_finish() and
 * ofp_ipsec_sa_destroy_finish().
 */
int ofp_ipsec_sa_disable(struct ofp_ipsec_sa *sa);

/*
 * Finish disabling an SA. The caller must guarantee that the SA is no
 * longer passed as a parameter to any IPsec packet input or output
 * operation. ofp_ipsec_sa_disable() must have been called first.
 *
 * Calls odp_ipsec_sa_disable() if not done already by ofp_ipsec_sa_disable().
 */
int ofp_ipsec_sa_disable_finish(struct ofp_ipsec_sa *sa);

/*
 * Return nonzero if the SA has been marked disabled.
 *
 * The caller is responsible of inter-thread synchronization between
 * ofp_ipsec_sa_disable() and this call.
 */
int ofp_ipsec_sa_disabled(struct ofp_ipsec_sa *sa);

/*
 * Finish destroying an SA. ofp_ipsec_sa_disable() must have been
 * called first. The underlying ODP SA is destroyed but the OFP SA
 * will be freed only after its reference count goes to zero.
 */
int ofp_ipsec_sa_destroy_finish(struct ofp_ipsec_sa *sa);

/*
 * Return ODP SA associated with an SA.
 */
odp_ipsec_sa_t ofp_ipsec_sa_get_odp_sa(struct ofp_ipsec_sa *sa);

/*
 * Get the parameters of an SA.
 */
const ofp_ipsec_sa_param_t *ofp_ipsec_sa_get_param(struct ofp_ipsec_sa *sa);

#endif /* OFPI_IPSEC_SAD_H */
