/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef _OFPI_ROUTE_H_
#define _OFPI_ROUTE_H_

#include <stdint.h>

#include "odp.h"
#include "api/ofp_route_arp.h"
#include "ofpi_portconf.h"

#define OFP_LOCK_READ(name)       odp_rwlock_read_lock(&ofp_locks_shm->lock_##name##_rw)
#define OFP_UNLOCK_READ(name)     odp_rwlock_read_unlock(&ofp_locks_shm->lock_##name##_rw)
#define OFP_LOCK_WRITE(name)      odp_rwlock_write_lock(&ofp_locks_shm->lock_##name##_rw)
#define OFP_UNLOCK_WRITE(name)    odp_rwlock_write_unlock(&ofp_locks_shm->lock_##name##_rw)

struct ofp_locks_str {
	odp_rwlock_t lock_config_rw;
	odp_rwlock_t lock_route_rw;
};

extern struct ofp_locks_str *ofp_locks_shm;

int ofp_route_lookup_shared_memory(void);
int ofp_route_init_global(void);
int ofp_route_term_global(void);

int32_t ofp_is_mobile(uint32_t addr);
enum ofp_return_code ofp_route_save_ipv6_pkt(odp_packet_t pkt, uint8_t *addr,
		struct ofp_ifnet *dev);

#endif
