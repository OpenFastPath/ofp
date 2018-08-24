/* Copyright (c) 2017, Nokia
 * Copyright (c) 2017, ENEA Software AB
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <getopt.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <odp_api.h>
#include <ofp.h>
#include <ofpi.h>

/*
 * Ethernet, VLAN tagged / IPv4 / UDP, destination port 65000.
 *
 * Our initial packets always have a VLAN header, but if VLANs are not
 * used, then OFP outputs packets without VLAN header.
 */
uint8_t frame[68] = {
0xf0, 0x00, 0x00, 0x00, 0x00, 0x01, 0xf0, 0x00,
0x00, 0x00, 0x00, 0x02,
0x81, 0x00, 0x00, 0x00,
0x08, 0x00, 0x45, 0x00,
0x00, 0x32, 0xb9, 0x12, 0x40, 0x00, 0x40, 0x11,
0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00,
0x00, 0x02, 0xb7, 0x8a, 0xfd, 0xe8, 0x00, 0x1e,
0x2e, 0xe6, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x0a,
};

struct ODP_ALIGNED_CACHE tstate_s {
	volatile uint64_t packets;
	volatile odp_time_t time;
	volatile int stop;
} tstate[ODP_THREAD_COUNT_MAX];

#define STR(x) #x
#define ASSERT(x)						\
	do {							\
		if (!(x)) {					\
			printf(__FILE__ "(%d): assert failed: "	\
			       STR(x) "\n", __LINE__);		\
			exit(1);				\
		}						\
	} while (0)

odp_instance_t instance;
struct ofp_ifnet *ifnet;
odp_queue_t dummyq;
odp_pool_t pool;
odp_spinlock_t lock;

#define C_PORT 0
#define C_VLAN 0
#define C_VRF 0
#define C_TTL 64
#define C_L_ADDR 0x7d000000
#define C_GW_ADDR 0x7e000000
#define C_SRC_ADDR 0x7c000000
#define C_DST_ADDR 0x1000000

const uint8_t ether_dhost[OFP_ETHER_ADDR_LEN] = {0xa, 0xb, 0, 0, 0, 0};

struct arg_s {
	volatile uint32_t batch, dispw, interval, ivals, loglevel, masklen,
		neighbor_bits, route_bits, tx_burst, verify, vlans, warmup, workers;
} arg, default_arg = {
	.batch = 64,
	.dispw = 0,
	.interval = 5000,
	.ivals = 1,
	.loglevel = OFP_LOG_ERROR,
	.masklen = 24,
	.neighbor_bits = 0,
	.route_bits = 0,
	.tx_burst = 8,
	.verify = 0,
	.vlans = 0,
	.warmup = 5,
	.workers = 1,
};



uint32_t addr_mask = ~0U;
__thread unsigned int seedp;

static inline uint32_t dst_addr(void)
{
	return htonl(C_DST_ADDR + ((uint32_t)rand_r(&seedp) & addr_mask));
}



static int worker(void *p)
{
	(void)p;

	ASSERT(!ofp_init_local());

	int res;
	odp_packet_t burst[arg.batch];
	odp_event_t ev[arg.batch];
	uint32_t c;
	uint16_t cksum_base = 0;

	odp_spinlock_lock(&lock);

	static volatile int next_tid = 0;
	int tid = next_tid++;
	seedp = tid + 1;

	/*
	 * Use a lock around packet allocation so that each thread
	 * gets consecutive packets from the pool.
	 */
	for (c = 0; c < arg.batch; c++) {
		odp_packet_t pkt = odp_packet_alloc(pool, sizeof(frame));
		ASSERT(pkt != ODP_PACKET_INVALID);

		uint8_t *buf = odp_packet_data(pkt);
		memcpy(buf, frame, sizeof(frame));

		struct ofp_ether_vlan_header *eth = (struct ofp_ether_vlan_header *)buf;
		eth->evl_tag = htons(OFP_EVL_MAKETAG(arg.vlans, 0, 0));

		struct ofp_ip *ip = (struct ofp_ip *)(eth + 1);
		ip->ip_src.s_addr = C_SRC_ADDR;
		ip->ip_ttl = C_TTL;
		ip->ip_sum = 0;
		if (!c) {
			ip->ip_dst.s_addr = 0;
			cksum_base = odp_be_to_cpu_16(~ofp_cksum_buffer((uint16_t *)ip, ip->ip_hl<<2));
		}
		ip->ip_dst.s_addr = dst_addr();
		ip->ip_sum = ofp_cksum_buffer((uint16_t *)ip, ip->ip_hl<<2);
		odp_packet_has_eth_set(pkt, 1);
		odp_packet_has_ipv4_set(pkt, 1);
		odp_packet_l2_offset_set(pkt, 0);
		odp_packet_l3_offset_set(pkt, sizeof(struct ofp_ether_vlan_header));
		odp_packet_l4_offset_set(pkt, sizeof(struct ofp_ether_vlan_header) + (ip->ip_hl<<2));

		ASSERT(ofp_packet_input(pkt, dummyq, ofp_eth_vlan_processing) == OFP_PKT_PROCESSED);

		tstate[tid].packets++;
	}

	odp_spinlock_unlock(&lock);

	res = ofp_send_pending_pkt();
	/*
	 * In order to get packets back on the same worker, the
	 * following must match the queue selection in
	 * ofp_send_pkt_multi().
	 */
	odp_queue_t outq = ifnet->out_queue_queue[odp_cpu_id() % ifnet->out_queue_num];

	while (1) {
		uint32_t num = 0;

		while (num < arg.batch) {
			res = odp_queue_deq_multi(outq, &ev[num], arg.batch-num);
			if (res < 0) break;
			num += res;
		}

		if (odp_unlikely(arg.verify)) {
			for (c = 0; c < num; c++) {
				odp_packet_t pkt = odp_packet_from_event(ev[c]);
				struct ofp_ether_header *eth =
					(struct ofp_ether_header *)odp_packet_l2_ptr(pkt, NULL);
				struct ofp_ip *ip = (struct ofp_ip *)odp_packet_l3_ptr(pkt, NULL);

				ASSERT(ip->ip_ttl == C_TTL-1);
				ASSERT(eth->ether_dhost[0] == ether_dhost[0] &&
				       eth->ether_dhost[1] == ether_dhost[1] &&
				       eth->ether_dhost[2] == (C_GW_ADDR>>24));

				memset(eth->ether_dhost, 0, sizeof(eth->ether_dhost));
			}
		}

		for (c = 0; c < num; c++) {
			burst[c] = odp_packet_from_event(ev[c]);
			/*
			 * Assume ether header is at the start of
			 * packet data, followed by IP header.
			 */
			struct ofp_ether_header *eth =
				(struct ofp_ether_header *)odp_packet_data(burst[c]);
			struct ofp_ip *ip = (struct ofp_ip *)(eth + 1);

			if (ntohs(eth->ether_type) == OFP_ETHERTYPE_VLAN)
				ip = (struct ofp_ip *)((uint8_t *)ip + OFP_ETHER_VLAN_ENCAP_LEN);

			ip->ip_ttl = C_TTL;
			ip->ip_dst.s_addr = dst_addr();
			uint32_t cksum = cksum_base;
			cksum += ntohs(ip->ip_dst.s_addr&0xffff);
			cksum += ntohs(ip->ip_dst.s_addr>>16);
			cksum = (cksum & 0xffff) + (cksum >> 16);
			ip->ip_sum = htons(~cksum);
		}

		if (odp_unlikely(tstate[tid].stop)) {
			for (c = 0; c < num; c++)
				odp_packet_free(burst[c]);
			break;
		}

		odp_time_t start = odp_time_global();

		for (c = 0; c < num; c++)
			ASSERT(ofp_packet_input(burst[c], dummyq, ofp_eth_vlan_processing) == OFP_PKT_PROCESSED);

		res = ofp_send_pending_pkt();

		tstate[tid].time = odp_time_sum(tstate[tid].time, odp_time_diff(odp_time_global(), start));
		tstate[tid].packets += num;
	}

	return 0;
}



static void usage(const char *prog)
{
	printf("\nUsage: %s [options]\n\n"
	       "All options take an unsigned integer argument.\n\n", prog);

	printf("Options:\n");
	printf("-a, --vlans         Number of VLANs. (%u)\n", default_arg.vlans);
	printf("-b, --batch         Number of packets in each batch. (%u)\n", default_arg.batch);
	printf("-d, --dispw         Display packet rates for workers\n"
	       "                    individually. (%u)\n", default_arg.dispw);
	printf("-t, --interval      Reporting interval in milliseconds. (%u)\n", default_arg.interval);
	printf("-i, --ivals         Number of intervals. (%u)\n", default_arg.ivals);
	printf("-l, --loglevel      OFP log level. (%u)\n", default_arg.loglevel);
	printf("-m, --masklen       Route subnet mask length. (%u)\n", default_arg.masklen);
	printf("-n, --neighbor-bits Neighbor address range in bits. Number of\n"
	       "                    neighbors is 2**<neighbor-bits>. (%u)\n", default_arg.neighbor_bits);
	printf("-r, --route-bits    Route range in bits. Number of routes is\n"
	       "                    2**<route-bits>. (%u)\n", default_arg.route_bits);
	printf("-v, --verify        Verify output packets. (%u)\n", default_arg.verify);
	printf("-u, --warmup        Warm up period in seconds. (%u)\n", default_arg.warmup);
	printf("-w, --workers       Number of worker threads. (%u)\n", default_arg.workers);
	printf("-x, --tx-burst      TX burst size. (%u)\n", default_arg.tx_burst);

	printf("\n");

	exit(1);
}



static void parse_args(int argc, char *argv[])
{
	arg = default_arg;

	while (1) {
		static struct option long_options[] = {
			{"vlans",         required_argument, 0, 'a'},
			{"batch",         required_argument, 0, 'b'},
			{"dispw",         required_argument, 0, 'd'},
			{"ivals",         required_argument, 0, 'i'},
			{"loglevel",      required_argument, 0, 'l'},
			{"masklen",       required_argument, 0, 'm'},
			{"neighbor-bits", required_argument, 0, 'n'},
			{"route-bits",    required_argument, 0, 'r'},
			{"interval",      required_argument, 0, 't'},
			{"warmup",        required_argument, 0, 'u'},
			{"verify",        required_argument, 0, 'v'},
			{"workers",       required_argument, 0, 'w'},
			{"tx-burst",      required_argument, 0, 'x'},
			{0,               0,                 0,  0 }
		};

		int c = getopt_long(argc, argv, "a:b:d:i:l:m:n:r:t:u:v:w:x:",
				    long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'a': arg.vlans = atoi(optarg); break;
		case 'b': arg.batch = atoi(optarg); break;
		case 'd': arg.dispw = atoi(optarg); break;
		case 'i': arg.ivals = atoi(optarg); break;
		case 'l': arg.loglevel = atoi(optarg); break;
		case 'm': arg.masklen = atoi(optarg); break;
		case 'n': arg.neighbor_bits = atoi(optarg); break;
		case 'r': arg.route_bits = atoi(optarg); break;
		case 't': arg.interval = atoi(optarg); break;
		case 'u': arg.warmup = atoi(optarg); break;
		case 'v': arg.verify = atoi(optarg); break;
		case 'w': arg.workers = atoi(optarg); break;
		case 'x': arg.tx_burst = atoi(optarg); break;
		default:
			usage(argv[0]);
		}
	}

	if (optind < argc) {
		printf("Invalid argument: %s\n", argv[optind]);
		usage(argv[0]);
	}
}



static void print_info(void)
{
	printf("\n"
	       "ODP system info\n"
	       "---------------\n"
	       "ODP API version: %s\n"
	       "CPU model:       %s\n"
	       "CPU freq (hz):   %lu\n"
	       "Cache line size: %i\n"
	       "Core count:      %i\n"
	       "\n",
	       odp_version_api_str(), odp_cpu_model_str(), odp_cpu_hz(),
	       odp_sys_cache_line_size(), odp_cpu_count());
}



static double odp_time_to_sec(odp_time_t t)
{
	return (double)odp_time_to_ns(t)/(double)ODP_TIME_SEC_IN_NS;
}



int main(int argc, char *argv[])
{
	parse_args(argc, argv);

	if (arg.workers > ODP_THREAD_COUNT_MAX)
		arg.workers = ODP_THREAD_COUNT_MAX;

	uint32_t neighbors = 1<<arg.neighbor_bits, routes = 1<<arg.route_bits;
	addr_mask = (1 << (arg.route_bits + (32 - arg.masklen))) - 1;
	ofp_loglevel = arg.loglevel;

	ASSERT(!odp_init_global(&instance, NULL, NULL));
	ASSERT(!odp_init_local(instance, ODP_THREAD_CONTROL));

	print_info();

	ofp_global_param_t params;
	ofp_init_global_param(&params);
	params.enable_nl_thread = 0;
	params.arp.entries = neighbors + 1;
	params.mtrie.routes = routes + 2;
	params.mtrie.table8_nodes = routes/2 + (routes>>8) + 4;
	params.pkt_tx_burst_size = arg.tx_burst;
	params.num_vlan = arg.vlans;
	ASSERT(!ofp_init_global(instance, &params));
	ASSERT(!ofp_init_local());

	uint32_t vlan;
	for (vlan = 0; vlan <= arg.vlans; vlan++)
		ASSERT(!ofp_config_interface_up_v4(C_PORT, vlan, C_VRF, odp_cpu_to_be_32(C_L_ADDR), 24));

	vlan = arg.vlans;

	ifnet = ofp_get_ifnet(C_PORT, C_VLAN);
	ASSERT((ifnet->pkt_pool = odp_pool_lookup("packet_pool")) != ODP_POOL_INVALID);

	odp_queue_param_t qpar;
	odp_queue_param_init(&qpar);
	qpar.enq_mode = ODP_QUEUE_OP_MT_UNSAFE;
	qpar.deq_mode = ODP_QUEUE_OP_MT_UNSAFE;

	char str[128];
	uint32_t i;

	for (i = 0; i < arg.workers; ++i) {
		sprintf(str, "out_queue:%d", i);
		ASSERT((ifnet->out_queue_queue[i] = odp_queue_create(str, &qpar)) != ODP_QUEUE_INVALID);
	}

	ifnet->out_queue_num = arg.workers;
	ifnet->out_queue_type = OFP_OUT_QUEUE_TYPE_QUEUE;

	sprintf(str, "in_queue:%d", C_PORT);
	ASSERT((dummyq = odp_queue_create(str, NULL)) != ODP_QUEUE_INVALID);
	ASSERT(!odp_queue_context_set(dummyq, ifnet, sizeof(ifnet)));
	ASSERT((pool = odp_pool_lookup("packet_pool")) != ODP_POOL_INVALID);

	for (i = 0; i < routes; i++) {
		struct ofp_ifnet *ifnet_vlan = ofp_get_ifnet(C_PORT, vlan);
		uint32_t dst = odp_cpu_to_be_32(C_DST_ADDR + (i << (32 - arg.masklen)));
		uint32_t gw = odp_cpu_to_be_32(C_GW_ADDR + (i & (neighbors - 1)));
		ASSERT(!ofp_set_route_params(OFP_ROUTE_ADD, C_VRF, vlan, C_PORT,
					     dst, arg.masklen, gw, OFP_RTF_GATEWAY));
		if (i < neighbors) {
			uint8_t gw_ether_dhost[OFP_ETHER_ADDR_LEN];
			memcpy(gw_ether_dhost, ether_dhost, 2);
			memcpy(gw_ether_dhost+2, &gw, OFP_ETHER_ADDR_LEN-2);
			ASSERT(!ofp_add_mac(ifnet_vlan, gw, gw_ether_dhost));
		}
	}

	memset(tstate, 0, sizeof(tstate));
	odp_spinlock_init(&lock);

	odph_odpthread_t thread_tbl[ODP_THREAD_COUNT_MAX];
	memset(thread_tbl, 0, sizeof(thread_tbl));

	for (i = 0; i < arg.workers; ++i) {
		odph_odpthread_params_t thr_params;
		memset(&thr_params, 0, sizeof(thr_params));
		thr_params.start = worker;
		thr_params.thr_type = ODP_THREAD_WORKER;
		thr_params.instance = instance;

		odp_cpumask_t cpu_mask;
		odp_cpumask_zero(&cpu_mask);
		odp_cpumask_set(&cpu_mask, i);

		ASSERT(odph_odpthreads_create(&thread_tbl[i], &cpu_mask, &thr_params));
	}

	sleep(arg.warmup);

	odp_time_t ltime = odp_time_global();
	struct tstate_s ltstate[ODP_THREAD_COUNT_MAX], ntstate[ODP_THREAD_COUNT_MAX];
	memcpy(ntstate, tstate, sizeof(tstate));

	for (uint32_t n = 0; n < arg.ivals; n++) {
		poll(0, 0, arg.interval);
		memcpy(ltstate, ntstate, sizeof(ntstate));
		odp_time_t ntime = odp_time_global();
		memcpy(ntstate, tstate, sizeof(tstate));
		odp_time_t time = odp_time_diff(ntime, ltime);
		ltime = ntime;
		uint64_t packets = 0, tpackets = 0;
		odp_time_t utime = odp_time_diff(ntime, ntime);
		for (i = 0; i < arg.workers; i++) {
			packets += ntstate[i].packets - ltstate[i].packets;
			tpackets += ntstate[i].packets;
			utime = odp_time_sum(utime, odp_time_diff(ntstate[i].time, ltstate[i].time));
		}
		double dtime = odp_time_to_sec(time);
		double pps = packets / dtime;
		double util = odp_time_to_sec(utime)/dtime/(double)arg.workers;
		printf("pps=%g pps/worker=%g work=%.3f ", pps, pps/(double)arg.workers, util);

		double wpps = 0, high = 0, low = 0;
		for (i = 0; i < arg.workers; i++) {
			packets = ntstate[i].packets - ltstate[i].packets;
			utime = odp_time_diff(ntstate[i].time, ltstate[i].time);
			wpps = (double)packets/dtime;
			if (arg.dispw) printf("%g ", wpps);
			if (!i) {
				high = low = wpps;
			} else {
				if (wpps > high) high = wpps;
				if (wpps < low) low = wpps;
			}
		}
		printf("lowest/highest=%.3f\n", low/high);
	}

	for (i = 0; i < arg.workers; ++i) tstate[i].stop = 1;

	odph_odpthreads_join(thread_tbl);

	for (i = 0; i < arg.workers; ++i)
		ASSERT(!odp_queue_destroy(ifnet->out_queue_queue[i]));

	ASSERT(!odp_queue_destroy(dummyq));

	ofp_term_local();
	ofp_term_global();
	odp_term_local();
	odp_term_global(instance);

	return 0;
}
