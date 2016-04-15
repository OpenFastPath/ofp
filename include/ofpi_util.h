/* Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdio.h>
#include <stdlib.h>
#include <odp.h>
#include <stdio.h>
#include <stdlib.h>

#include "api/ofp_log.h"
#include "api/ofp_utils.h"
#include "ofpi_timer.h"
#include "ofpi_shared_mem.h"

#define L2_HEADER_NO_VLAN_SIZE 14

/* Test a condition at compile time. */
#define _BA1_(cond, line) \
	extern int __build_assertion_ ## line[1 - 2*!(cond)] \
	__attribute__ ((unused))
#define _BA0_(c, x) _BA1_(c, x)
#define BUILD_ASSERT(cond) _BA0_(cond, __LINE__)

#define KASSERT(x, y)  do {						\
		if (!(x)) {						\
			OFP_ERR y ;					\
		}							\
	} while (0)

/* HANDLE_ERROR will not log any message.
   LOGGING must be done during execution of (x) statement (usually a function)
*/
#define HANDLE_ERROR(x)  do {						\
		if ((x))						\
			return -1;					\
	} while (0)

/* CHECK_ERROR will not log any message.
   LOGGING must be done during execution of (x) statement (usually a function)
   '_ret_code' is set to -1 on error.
*/
#define CHECK_ERROR(x, _ret_code)  do {					\
		if ((x))						\
			_ret_code = -1;					\
	} while (0)

#define panic(x)  do {							\
		OFP_ERR(x);						\
		abort();						\
	} while (0)

static inline char *print_th_flags(uint8_t f, int or) {
	const char *t[8] = {"FIN", "SYN", "RST", "PUSH", "ACK", "URG", "ECE", "CWR"};
	static char buf[64];
	uint8_t m = 1;
	int i, n = 0;
	buf[0] = 0;
	for (i = 0; i < 8; i++) {
		if (or && (f & m)) n += sprintf(buf+n, " %s", t[i]);
		else if (!or && !(f & m)) n += sprintf(buf+n, " %s", t[i]);
		m = m << 1;
	}
	return buf;
}

static inline char *print_flags(uint32_t f, int or) {
	const char *t[] = {"ACKNOW", "DELACK", "NODEALY", "NOOPT", "SENTFIN",
			    "REQ_SCALE", "RCVD_SCALE", "REQ_TSTMP", "RCVD_TSTMP",
			    "SACK_PERMIT", "NEEDSYN", "NEEDFIN", "NOPUSH", "PREVVALID",
			   "", "",
			    "MORETOCOME", "LQ_OVERFLOW","LASTIDLE","RXWIN0SENT",
			    "FASTRECOVERY", "WASFRECOVERY", "SIGNATURE", "FORCEDATA",
			    "TSO", "TOE", "ECN_PERMIT", "ECN_SND_CWR",
			   "ECN_SND_ECE", "CONGRECOVERY", "WASCRECOVERY", ""};
	static char buf[128];
	uint32_t m = 1;
	int i, n = 0;
	buf[0] = 0;
	for (i = 0; i < 29; i++) {
		if (or && (f & m)) n += sprintf(buf+n, " %s", t[i]);
		else if (!or && !(f & m)) n += sprintf(buf+n, " %s", t[i]);
		m = m << 1;
	}
	return buf;
}

#define t_flags_or(_f, _v) do { _f |= _v;				\
		/*OFP_LOG("t_flags OR %s 0x%x\n", print_flags(_v, 1), (uint32_t)_v);*/ } while (0)
#define t_flags_and(_f, _v) do { _f &= _v;				\
		/*OFP_LOG("t_flags AND %s 0x%x\n", print_flags(_v, 0), (uint32_t)_v);*/ } while (0)

void ofp_print_hex(uint8_t log_level,
	unsigned char *data, int len);
void ofp_generate_coredump(void);
int ofp_hex_to_num(char *s);
void ofp_mac_to_link_local(uint8_t *mac, uint8_t *lladdr);
void ofp_ip6_masklen_to_mask(int masklen, uint8_t *mask);
int ofp_mask_length(int masklen, uint8_t *mask);
int ofp_name_to_port_vlan(const char *dev, int *vlan);
char *ofp_port_vlan_to_ifnet_name(int port, int vlan);
int ofp_sendf(int fd, const char *fmt, ...);
int ofp_has_mac(uint8_t *mac);

static inline odp_pool_t ofp_pool_create(const char *name,
	odp_pool_param_t *params)
{
	return odp_pool_create(name, params);
}

void *rpl_malloc (size_t n);

static inline int ilog2(unsigned long long n)
{
	return 63 - __builtin_clzll(n);
}

static inline odp_bool_t ofp_ip6_is_set(uint8_t *addr)
{
	return ((*(uint64_t *)addr | *(uint64_t *)(addr + 8)) == 0 ? 0 : 1);
}
static inline odp_bool_t ofp_ip6_equal(uint8_t *addr1, uint8_t *addr2)
{
	return (((*(uint64_t *)addr1 ==  *(uint64_t *)addr2) &&
		(*(uint64_t *)(addr1 + 8) ==  *(uint64_t *)(addr2 + 8)))
	? 1 : 0);
}

#define ofp_copy_mac(dst_8, src_8) do { \
	uint32_t *dst_32 = (uint32_t *)(uintptr_t)dst_8; \
	uint32_t *src_32 = (uint32_t *)(uintptr_t)src_8; \
	uint16_t *dst_16 = (uint16_t *)(uintptr_t)dst_8; \
	uint16_t *src_16 = (uint16_t *)(uintptr_t)src_8; \
	*dst_32 = *src_32; \
	dst_16[2] = src_16[2]; \
} while (0)

#endif
