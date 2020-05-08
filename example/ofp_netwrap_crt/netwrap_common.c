/* Copyright (c) 2020.
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "netwrap_common.h"

ofp_global_param_t ofp_global_params = {0};
odp_bool_t netwrap_constructor_called;      /* = 0 */

int setup_common_vars(void)
{
	if (ofp_get_global_parameters(&ofp_global_params))
		return -1;

	netwrap_constructor_called = 1;

	return 0;
}
