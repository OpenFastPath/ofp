/* Copyright (c) 2015, ENEA Software AB
 * Copyright (c) 2015, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFPI_ODP_COMPAT__
#define __OFPI_ODP_COMPAT__

#if ODP_VERSION < 103
#define ODP_PKTIN_MODE_RECV 0
#define ODP_PKTIN_MODE_SCHED 1
#define odp_pktio_start(x) 0
#define odp_pktio_stop(x) 0
#define odp_queue_context(x) odp_queue_get_context(x)
#define odp_queue_context_set(q, ctx) odp_queue_set_context(q, ctx)
#endif /* ODP_VERSION < 103 */

#if ODP_VERSION < 105
#define ODP_TIME_USEC_IN_NS ODP_TIME_USEC
#define ODP_TIME_MSEC_IN_NS ODP_TIME_MSEC
#define ODP_TIME_SEC_IN_NS ODP_TIME_SEC
#define ENTRY_USETIME_INVALID 0xFFFFFFFF
#define ODP_TIME_NULL ENTRY_USETIME_INVALID
#define odp_time_diff(x, y) odp_time_diff_cycles(y, x)
#define odp_time_to_ns(x) odp_time_cycles_to_ns(x)
#define odp_time_local_from_ns(x) (x)
#define odp_time_to_u64(x) (x)

#if ODP_VERSION < 104
#define odp_time_local(x) odp_time_cycles(x)
#else
#define odp_time_local(x) odp_cpu_cycles(x)
#endif /* ODP_VERSION < 104 */

#endif /* ODP_VERSION < 105 */

#if ODP_VERSION < 102
#define odp_pool_create(name, params) odp_pool_create(name, ODP_SHM_NULL, params)
#endif /* ODP_VERSION < 102 */

#if ODP_VERSION == 100
#define odp_packet_user_area(pkt) (struct vxlan_user_data *)odp_packet_user_ptr(pkt)
#endif /* ODP_VERSION == 100 */

#if ODP_VERSION < 106
#define odp_mb_release() odp_sync_stores()
#endif /* ODP_VERSION < 106 */

#endif
