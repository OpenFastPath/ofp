/* Copyright (c) 2014, Nokia
 * Copyright (c) 2014, ENEA Software AB
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _STAT_H_
#define _STAT_H_

#include "api/ofp_stat.h"
#include "ofpi_timer.h"

int ofp_stat_lookup_shared_memory(void);
int ofp_stat_init_global(void);
int ofp_stat_term_global(void);

#define OFP_UPDATE_PACKET_STAT(_s, _n) do {				\
	struct ofp_packet_stat *st = ofp_get_packet_statistics(); \
	if (st)							\
		st->per_core[odp_cpu_id()]._s += _n;	\
} while (0)

extern unsigned long int ofp_stat_flags;

#define _UPDATE_LATENCY(_core, _current_cycle, _n) do {\
	if (odp_time_to_u64(st->per_core[_core].last_input_cycles)) \
		st->per_core[_core].input_latency[\
			ilog2(odp_time_to_u64(odp_time_diff(\
				_current_cycle, \
				st->per_core[_core]\
				.last_input_cycles)))]\
			+= _n;	\
	st->per_core[_core].last_input_cycles = _current_cycle;\
} while (0)

#define OFP_UPDATE_PACKET_LATENCY_STAT(_n) do {\
	if (ofp_stat_flags & OFP_STAT_COMPUTE_LATENCY) { \
		struct ofp_packet_stat *st = ofp_get_packet_statistics(); \
		if (st)	{						\
			odp_time_t _in_cycles = odp_time_local(); \
			int _core = odp_cpu_id(); \
			_UPDATE_LATENCY(_core, _in_cycles, _n);\
		} \
	} \
} while (0)

#endif
