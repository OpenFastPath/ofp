/* Copyright (c) 2015, ENEA Software AB
 * Copyright (c) 2015, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFP_ODP_COMPAT__
#define __OFP_ODP_COMPAT__

#if ODP_VERSION == 102
#include "linux.h"
#else
#include "odp/helper/linux.h"
#endif /* odp_version == 102 */

#if ODP_VERSION < 105
typedef uint64_t odp_time_t;
#endif /* ODP_VERSION < 105 */

#if ODP_VERSION < 104 && ODP_VERSION > 101
#define odp_cpumask_default_worker(cpumask, num_workers) odp_cpumask_def_worker(cpumask, num_workers)
#elif ODP_VERSION < 102
#define odp_cpumask_default_worker(cpumask, num_workers) odp_cpumask_count(cpumask)
#define ODP_THREAD_WORKER
#define ODP_THREAD_CONTROL
#endif

#endif