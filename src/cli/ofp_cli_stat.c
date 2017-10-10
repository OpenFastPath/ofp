/*-
 * Copyright (c) 2014 ENEA Software AB
 * Copyright (c) 2014 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ofpi_log.h"
#include "ofpi_cli.h"
#include "ofpi_avl.h"
#include "ofpi_rt_lookup.h"
#include "ofpi_stat.h"
#include "ofpi_util.h"

static void print_latency_entry(struct cli_conn *conn,
	struct ofp_packet_stat *st, int thread, int entry)
{
	int j;
	uint64_t input_latency = st->per_thr[thread].input_latency[entry];
	int input_latency_log = ilog2(input_latency);

	ofp_sendf(conn->fd, "\r\n%3d| ", entry);

	if (input_latency == 0)
		return;

	if (input_latency < 100000)
		ofp_sendf(conn->fd, "[%05d]", input_latency);
	else
		ofp_sendf(conn->fd, "[99999]");

	for (j = 0; j < input_latency_log + 1; j++)
		ofp_sendf(conn->fd, "*");
}

static void print_thread_stat(struct cli_conn *conn,
	struct ofp_packet_stat *st, odp_thrmask_t thrmask)
{
	int next_thr;

	ofp_sendf(conn->fd, " Thread        ODP_to_FP        FP_to_ODP"
		"     FP_to_SP    SP_to_ODP      Tx_frag   Rx_IP_frag"
		"   Rx_IP_reas\r\n\r\n");
	next_thr = odp_thrmask_first(&thrmask);
	while (next_thr >= 0) {
		ofp_sendf(conn->fd, "%7u %16llu %16llu %12llu %12llu"
			" %12llu %12llu %12llu\r\n",
			next_thr,
			st->per_thr[next_thr].rx_fp,
			st->per_thr[next_thr].tx_fp,
			st->per_thr[next_thr].rx_sp,
			st->per_thr[next_thr].tx_sp,
			st->per_thr[next_thr].tx_eth_frag,
			st->per_thr[next_thr].rx_ip_frag,
			st->per_thr[next_thr].rx_ip_reass);
		next_thr = odp_thrmask_next(&thrmask, next_thr);
	}
	ofp_sendf(conn->fd, "\r\n");
}

void f_stat_show(struct cli_conn *conn, const char *s)
{
	struct ofp_packet_stat *st = ofp_get_packet_statistics();
	int i, j;
	int next_thr;
	odp_thrmask_t thrmask;
	int last_entry;

	(void)s;

	if (!st)
		return;

	ofp_sendf(conn->fd, "Settings: \r\n"
		"  compute latency - %s\r\n"
		"  compute performance - %s\r\n\r\n",
		ofp_stat_flags & OFP_STAT_COMPUTE_LATENCY ? "yes" : "no",
		ofp_stat_flags & OFP_STAT_COMPUTE_PERF ? "yes" : "no");

	odp_thrmask_control(&thrmask);
	ofp_sendf(conn->fd, "Packet counters of control threads:\r\n\r\n");
	print_thread_stat(conn, st, thrmask);

	odp_thrmask_worker(&thrmask);
	ofp_sendf(conn->fd, "Packet counters of worker threads:\r\n\r\n");
	print_thread_stat(conn, st, thrmask);

/*TODO: print interface related stats colected from ODP or linux IP stack*/

	ofp_sendf(conn->fd, "Allocated memory:\r\n");
	ofp_print_avl_stat(conn->fd);
	ofp_print_rt_stat(conn->fd);

	if (ofp_stat_flags & OFP_STAT_COMPUTE_LATENCY) {
		ofp_sendf(conn->fd, "\r\n  Latency graph | log/log scale | "
			"X = occurrences, Y = cycles");

		next_thr = odp_thrmask_first(&thrmask);
		while (next_thr >= 0) {
			ofp_sendf(conn->fd, "\r\nWorker thread %d:\r\n", next_thr);

			/* Skip to the first entry where there's data */
			for (i = 0; i < OFP_LATENCY_SLICES; i++)
				if (st->per_thr[next_thr].input_latency[i] != 0)
					break;

			if (i < OFP_LATENCY_SLICES) {
				/* Check what's the last entry with data */
				last_entry = i;
				for (j = i; j < OFP_LATENCY_SLICES; j++)
					if (st->per_thr[next_thr].input_latency[j])
						last_entry = j;

				/* Now we have cut the ends with zeros */
				for (; i < last_entry + 1; i++)
					print_latency_entry(conn, st, next_thr, i);
				ofp_sendf(conn->fd, "\r\n");
			}
			next_thr = odp_thrmask_next(&thrmask, next_thr);
		}
	}
	if (ofp_stat_flags & OFP_STAT_COMPUTE_PERF) {
		struct ofp_perf_stat *ps = ofp_get_perf_statistics();

		ofp_sendf(conn->fd, "\r\n");
		ofp_sendf(conn->fd, "Throughput: %4.3f Mpps\r\n",
				((float)ps->rx_fp_pps)/1000000);
	}
	sendcrlf(conn);
}

void f_stat_set(struct cli_conn *conn, const char *s)
{
	(void)s;

	ofp_set_stat_flags(strtol(s, NULL, 0));

	sendcrlf(conn);
}

void f_stat_perf(struct cli_conn *conn, const char *s)
{
	(void)s;

	if (ofp_stat_flags & OFP_STAT_COMPUTE_PERF) {
		struct ofp_perf_stat *ps = ofp_get_perf_statistics();

		ofp_sendf(conn->fd, "%4.3f Mpps - Throughput\r\n",
		((float)ps->rx_fp_pps)/1000000);
	} else
		ofp_sendf(conn->fd, "N/A\r\n");

	sendcrlf(conn);
}
void f_stat_clear(struct cli_conn *conn, const char *s)
{
	struct ofp_packet_stat *st = ofp_get_packet_statistics();

	(void)s;

	memset(st, 0, sizeof(struct ofp_packet_stat));

	sendcrlf(conn);
}

void f_help_stat(struct cli_conn *conn, const char *s)
{
	(void)s;

	ofp_sendf(conn->fd, "Show statistics:\r\n"
		"  stat [show]\r\n\r\n");

	ofp_sendf(conn->fd, "Set options for statistics:\r\n"
		"  stat set <bit mask of options>\r\n"
		"    bit 0: compute packets latency\r\n"
		"    bit 1: compute throughput (mpps)\r\n"
		"  Example:\r\n"
		"    stat set 0x1\r\n\r\n");

	ofp_sendf(conn->fd, "Get performance statistics:\r\n"
		"  stat perf\r\n\r\n");

	ofp_sendf(conn->fd, "Clear statistics:\r\n"
		"  stat clear\r\n\r\n");

	ofp_sendf(conn->fd, "Show (this) help:\r\n"
		"  stat help\r\n\r\n");

	sendcrlf(conn);
}
