/*-
 * Copyright (c) 2014 ENEA Software AB
 * Copyright (c) 2014 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _UDP_SERVER_H_
#define _UDP_SERVER_H_

#include <odp_api.h>

void ofp_start_udpserver_thread(odp_instance_t instance, int core_id);

#endif
