/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef __OFP_CLI_H__
#define __OFP_CLI_H__

#include "odp.h"

/** CLI Start thread
 */
int ofp_start_cli_thread(odp_instance_t instance, int core_id,
	char *conf_file);
int ofp_stop_cli_thread(void);

#endif /* __OFP_CLI_H__ */
