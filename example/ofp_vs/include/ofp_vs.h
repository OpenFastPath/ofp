/**
 * Copyright (c) 2016 lvsgate@163.com
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFP_VS_H__
#define __OFP_VS_H__

#include "ofp.h"
#include "ofpi_portconf.h"
#include "ofpi_debug.h"
#include "ofpi_stat.h"
#include "ofpi_util.h"

#include <rte_config.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_byteorder.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>
#include <rte_hash_crc.h>

#include "ofp_vs_kern_compat.h"
#include "ofp_vs_tcpip.h"
#include "kern_list.h"
#include "net/ip_vs.h"

extern unsigned ofp_vs_num_workers;
extern odp_cpumask_t ofp_vs_workers_cpumask;

enum ofp_return_code ofp_vs_in(odp_packet_t pkt, void *arg);
enum ofp_return_code ofp_vs_out(odp_packet_t pkt, void *arg);
int ofp_vs_init(odp_instance_t instance, ofp_init_global_t *app_init_params);
void ofp_vs_finish(void);
void ofp_vs_ctl_thread_start(odp_instance_t instance, int core_id);
int ofp_vs_ctl_init(odp_instance_t instance, ofp_init_global_t *app_init_params);
void ofp_vs_ctl_finish(void);

int ip_vs_rr_init(void);
void ip_vs_rr_cleanup(void);
int ip_vs_snat_init(void);
void ip_vs_snat_cleanup(void);

int ofp_vs_snat_enable(void);

void ofp_vs_cli_cmd_init(void);

#define IP_VS_CONN_TAB_BITS	20
#define IP_VS_CONN_TAB_SIZE     (1 << IP_VS_CONN_TAB_BITS)
#define IP_VS_CONN_TAB_MASK     (IP_VS_CONN_TAB_SIZE - 1)


static inline __be32 inet_make_mask(int logmask)
{
	if (logmask)
		return rte_cpu_to_be_32(~((1<<(32-logmask))-1));
	return 0;
}

static inline unsigned int inet_mask_len(__be32 mask) {
	uint8_t u8_mask = rte_be_to_cpu_32(mask);
	return ofp_mask_length(32, (uint8_t *)&u8_mask);
}


#endif
