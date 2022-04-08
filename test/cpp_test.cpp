/* Copyright (c) 2014, ENEA Software AB
 * Copyrighy (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:    BSD-3-Clause
 */
#include "ofp.h"

// Test for successful compile & link.
int main() {
	static ofp_global_param_t oig;
	odp_instance_t instance;

	if (odp_init_global(&instance, NULL, NULL)) {
		OFP_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		OFP_ERR("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}
	ofp_init_global_param(&oig);
	if (ofp_init_global(instance, &oig)) {
		OFP_ERR("Error: OFP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	OFP_INFO("Init successful.\n");

	if (ofp_term_global())
		OFP_ERR("Error: OFP global term failed.\n");

	if (odp_term_local())
		OFP_ERR("Error: ODP local term failed.\n");

	if (odp_term_global(instance))
		OFP_ERR("Error: ODP global term failed.\n");

	return 0;
}
