/*
 * Copyright (c) 2018, Nokia.
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef OFP_IPSEC_INIT_H
#define OFP_IPSEC_INIT_H

#include <odp_api.h>

/**
 * Default values for the corresponding initialization parameters
 */
#define OFP_IPSEC_MAX_NUM_SA 8
#define OFP_IPSEC_MAX_NUM_SP 8
#define OFP_IPSEC_MAX_INBOUND_SPI 100

/**
 * IPsec initialization parameters
 */
struct ofp_ipsec_param {
	/**
	 * Maximum number of security policies that can exist at a time.
	 */
	uint32_t max_num_sp;

	/**
	 * Maximum number of SAs that can exist at a time.
	 */
	uint32_t max_num_sa;

	/**
	 * Maximum inbound SPI value that may be used.
	 */
	uint32_t max_inbound_spi;
};

#endif /* OFP_IPSEC_INIT_H */
