/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef __OFP_TIMER_H__
#define __OFP_TIMER_H__

typedef void (*ofp_timer_callback)(void *arg);

odp_timer_t ofp_timer_start(uint64_t tmo_us, ofp_timer_callback callback,
		       void *arg, int arglen);
int ofp_timer_cancel(odp_timer_t tim);
void ofp_timer_handle(odp_event_t buf);
int ofp_timer_ticks(int timer_num);
odp_timer_pool_t ofp_timer(int timer_num);

#endif /* __OFP_TIMER_H__ */
