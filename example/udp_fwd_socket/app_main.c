/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <getopt.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <inttypes.h>

#include "ofp.h"
#include "udp_fwd_socket.h"

#define MAX_WORKERS		64

/**
 * Parsed command line application arguments
 */
typedef struct {
	int core_count;
	int if_count;		/**< Number of interfaces to use */
	int sock_count;		/**< Number of sockets to use */
	char **if_names;	/**< Array of pointers to interface names */
	char *conf_file;
	char *laddr;
	char *raddr;
} appl_args_t;

struct pktio_thr_arg {
	odp_pktin_queue_t pktin;
	ofp_pkt_processing_func pkt_func;
};

/* helper funcs */
static void parse_args(int argc, char *argv[], appl_args_t *appl_args);
static void print_info(char *progname, appl_args_t *appl_args);
static void usage(char *progname);


ofp_global_param_t app_init_params; /**< global OFP init parms */

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
				strrchr((file_name), '/') + 1 : (file_name))

#define PKT_BURST_SIZE OFP_PKT_RX_BURST_SIZE

static void *pkt_io_recv(void *arg)
{
	odp_pktin_queue_t pktin;
	odp_packet_t pkt, pkt_tbl[PKT_BURST_SIZE];
	int pkt_idx, pkt_cnt;
	struct pktio_thr_arg *thr_args;
	ofp_pkt_processing_func pkt_func;

	thr_args = arg;
	pkt_func = thr_args->pkt_func;
	pktin = thr_args->pktin;

	if (ofp_init_local()) {
		OFP_ERR("Error: OFP local init failed.\n");
		return NULL;
	}

	OFP_DBG("PKT-IO receive starting on cpu: %d", odp_cpu_id());

	while (1) {
		pkt_cnt = odp_pktin_recv(pktin, pkt_tbl, PKT_BURST_SIZE);

		for (pkt_idx = 0; pkt_idx < pkt_cnt; pkt_idx++) {
			pkt = pkt_tbl[pkt_idx];

			if (odp_unlikely(odp_packet_has_error(pkt))) {
				OFP_DBG("Packet with error dropped.\n");
				odp_packet_free(pkt);
				continue;
			}

			ofp_packet_input(pkt, ODP_QUEUE_INVALID, pkt_func);
		}
		ofp_send_pending_pkt();
	}

	/* Never reached */
	return NULL;
}

/*
 * Should receive timeouts only
 */
static void *event_dispatcher(void *arg)
{
	odp_event_t ev;

	(void)arg;

	if (ofp_init_local()) {
		OFP_ERR("Error: OFP local init failed.\n");
		return NULL;
	}

	while (1) {
		ev = odp_schedule(NULL, ODP_SCHED_WAIT);

		if (ev == ODP_EVENT_INVALID)
			continue;

		if (odp_event_type(ev) == ODP_EVENT_TIMEOUT) {
			ofp_timer_handle(ev);
			continue;
		}

		OFP_ERR("Error: unexpected event type: %u\n",
			  odp_event_type(ev));

		odp_buffer_free(odp_buffer_from_event(ev));
	}

	/* Never reached */
	return NULL;
}

/** main() Application entry point
 *
 * @param argc int
 * @param argv[] char*
 * @return int
 *
 */
int main(int argc, char *argv[])
{
	odph_linux_pthread_t thread_tbl[MAX_WORKERS], dispatcher_thread;
	appl_args_t params;
	int core_count, num_workers;
	odp_cpumask_t cpu_mask;
	int first_cpu, i;
	struct pktio_thr_arg pktio_thr_args[MAX_WORKERS];
	odp_pktio_param_t pktio_param;
	odp_pktin_queue_param_t pktin_param;
	odp_pktout_queue_param_t pktout_param;
	odp_pktio_t pktio;
	int port, queue_id;
	odph_linux_thr_params_t thr_params;
	odp_instance_t instance;

	struct pktin_table_s {
		int	num_in_queue;
		odp_pktin_queue_t in_queue[OFP_PKTIN_QUEUE_MAX];
	} pktin_table[OFP_FP_INTERFACE_MAX];

	/* Parse and store the application arguments */
	parse_args(argc, argv, &params);

	if (params.if_count > OFP_FP_INTERFACE_MAX) {
		printf("Error: Invalid number of interfaces: maximum %d\n",
			OFP_FP_INTERFACE_MAX);
		exit(EXIT_FAILURE);
	}

	if (odp_init_global(&instance, NULL, NULL)) {
		OFP_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		OFP_ERR("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &params);

	core_count = odp_cpu_count();
	num_workers = core_count;

	if (params.core_count && params.core_count < core_count)
		num_workers = params.core_count;
	if (num_workers > MAX_WORKERS)
		num_workers = MAX_WORKERS;
	/*
	 * By default core #0 runs Linux kernel background tasks.
	 * Start mapping thread from core #1
	 */
	if (num_workers > 1) {
		num_workers--;
		first_cpu = 1;
	} else {
		OFP_ERR("Burst mode requires multiple cores.\n");
		exit(EXIT_FAILURE);
	}

	if (num_workers < params.if_count) {
		OFP_ERR("At least %u fastpath cores required.\n",
			  params.if_count);
		exit(EXIT_FAILURE);
	}

	printf("Num worker threads: %i\n", num_workers);
	printf("first CPU:          %i\n", first_cpu);

	memset(&app_init_params, 0, sizeof(app_init_params));
	app_init_params.linux_core_id = 0;

	if (ofp_init_global(instance, &app_init_params)) {
		OFP_ERR("Error: OFP global init failed.\n");
		exit(EXIT_FAILURE);
	}
	if (ofp_init_local()) {
		OFP_ERR("Error: OFP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_DIRECT;
	pktio_param.out_mode = ODP_PKTOUT_MODE_DIRECT;

	odp_pktin_queue_param_init(&pktin_param);
	pktin_param.op_mode = ODP_PKTIO_OP_MT;
	pktin_param.hash_enable = 0;
	pktin_param.hash_proto.all_bits = 0;
	pktin_param.num_queues = 1;

	odp_pktout_queue_param_init(&pktout_param);
	pktout_param.num_queues = 1;
	pktout_param.op_mode = ODP_PKTIO_OP_MT;

	for (i = 0; i < params.if_count; i++) {
		if (ofp_ifnet_create(instance, params.if_names[i],
				&pktio_param,
				&pktin_param,
				&pktout_param) < 0) {
			OFP_ERR("Failed to init interface %s",
				params.if_names[i]);
			exit(EXIT_FAILURE);
		}

		pktio = odp_pktio_lookup(params.if_names[i]);
		if (pktio == ODP_PKTIO_INVALID) {
			OFP_ERR("Failed locate pktio %s",
				params.if_names[i]);
			exit(EXIT_FAILURE);
		}
		pktin_table[i].num_in_queue = odp_pktin_queue(pktio,
			pktin_table[i].in_queue, OFP_PKTIN_QUEUE_MAX);

		if (pktin_table[i].num_in_queue < 0) {
			OFP_ERR("Failed get input queues for %s",
				params.if_names[i]);
			exit(EXIT_FAILURE);
		}
	}

	memset(thread_tbl, 0, sizeof(thread_tbl));
	memset(pktio_thr_args, 0, sizeof(pktio_thr_args));

	for (i = 0; i < num_workers; ++i) {
		pktio_thr_args[i].pkt_func = ofp_eth_vlan_processing;

		port = i % params.if_count;
		queue_id = (i / params.if_count) %
			pktin_table[port].num_in_queue;
		pktio_thr_args[i].pktin = pktin_table[port].in_queue[queue_id];

		odp_cpumask_zero(&cpu_mask);
		odp_cpumask_set(&cpu_mask, first_cpu + i);

		thr_params.start = pkt_io_recv;
		thr_params.arg = &pktio_thr_args[i];
		thr_params.thr_type = ODP_THREAD_WORKER;
		thr_params.instance = instance;
		odph_linux_pthread_create(&thread_tbl[i],
					  &cpu_mask,
					  &thr_params);
	}

	odp_cpumask_zero(&cpu_mask);
	odp_cpumask_set(&cpu_mask, app_init_params.linux_core_id);

	thr_params.start = event_dispatcher;
	thr_params.arg = NULL;
	thr_params.thr_type = ODP_THREAD_WORKER;
	thr_params.instance = instance;
	odph_linux_pthread_create(&dispatcher_thread,
				  &cpu_mask,
				  &thr_params);

	/* Start CLI */
	ofp_start_cli_thread(instance, app_init_params.linux_core_id,
		params.conf_file);
	sleep(1);

	udp_fwd_cfg(params.sock_count, params.laddr, params.raddr);

	odph_linux_pthread_join(thread_tbl, num_workers);

	printf("End Main()\n");
	return 0;
}

/**
 * Parse and store the command line arguments
 *
 * @param argc       argument count
 * @param argv[]     argument vector
 * @param appl_args  Store application arguments here
 */
static void parse_args(int argc, char *argv[], appl_args_t *appl_args)
{
	int opt;
	int long_index;
	char *names, *str, *token, *save;
	size_t len;
	int i;
	static struct option longopts[] = {
		{"count", required_argument, NULL, 'c'},
		{"interface", required_argument, NULL, 'i'},	/* return 'i' */
		{"help", no_argument, NULL, 'h'},		/* return 'h' */
		{"configuration file", required_argument,
			NULL, 'f'},/* return 'f' */
		{"local address", required_argument,
			NULL, 'l'},/* return 'l' */
		{"remote address", required_argument,
			NULL, 'r'},/* return 'r' */
		{"local sockets", required_argument,
			NULL, 's'},/* return 's' */
		{NULL, 0, NULL, 0}
	};

	memset(appl_args, 0, sizeof(*appl_args));

	while (1) {
		opt = getopt_long(argc, argv, "+c:i:hf:l:r:s:",
				  longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'c':
			appl_args->core_count = atoi(optarg);
			break;
			/* parse packet-io interface names */
		case 'i':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1;	/* add room for '\0' */

			names = malloc(len);
			if (names == NULL) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			/* count the number of tokens separated by ',' */
			strcpy(names, optarg);
			for (str = names, i = 0;; str = NULL, i++) {
				token = strtok_r(str, ",", &save);
				if (token == NULL)
					break;
			}
			appl_args->if_count = i;

			if (appl_args->if_count == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			/* allocate storage for the if names */
			appl_args->if_names =
				calloc(appl_args->if_count, sizeof(char *));

			/* store the if names (reset names string) */
			strcpy(names, optarg);
			for (str = names, i = 0;; str = NULL, i++) {
				token = strtok_r(str, ",", &save);
				if (token == NULL)
					break;
				appl_args->if_names[i] = token;
			}
			break;

		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;

		case 'f':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1;	/* add room for '\0' */

			appl_args->conf_file = malloc(len);
			if (appl_args->conf_file == NULL) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			strcpy(appl_args->conf_file, optarg);
			break;
		case 'l':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1;	/* add room for '\0' */
			appl_args->laddr = malloc(len);
			if (appl_args->laddr == NULL) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			strcpy(appl_args->laddr, optarg);
			break;
		case 'r':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1;	/* add room for '\0' */
			appl_args->raddr = malloc(len);
			if (appl_args->raddr == NULL) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			strcpy(appl_args->raddr, optarg);
			break;
		case 's':
			len = strlen(optarg);
			if (len == 0 || atoi(optarg) < 1) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			appl_args->sock_count = atoi(optarg);
			break;

		default:
			break;
		}
	}

	if (appl_args->if_count == 0) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	optind = 1;		/* reset 'extern optind' from the getopt lib */
}

/**
 * Print system and application info
 */
static void print_info(char *progname, appl_args_t *appl_args)
{
	int i;

	printf("\n"
		   "ODP system info\n"
		   "---------------\n"
		   "ODP API version: %s\n"
		   "CPU model:       %s\n"
		   "CPU freq (hz):   %"PRIu64"\n"
		   "Cache line size: %i\n"
		   "Core count:      %i\n"
		   "\n",
		   odp_version_api_str(), odp_cpu_model_str(),
		   odp_cpu_hz(), odp_sys_cache_line_size(),
		   odp_cpu_count());

	printf("Running ODP appl: \"%s\"\n"
		   "-----------------\n"
		   "IF-count:        %i\n"
		   "Using IFs:      ",
		   progname, appl_args->if_count);
	for (i = 0; i < appl_args->if_count; ++i)
		printf(" %s", appl_args->if_names[i]);
	printf("\n\n");
	fflush(NULL);
}

/**
 * Prinf usage information
 */
static void usage(char *progname)
{
	printf("\n"
		   "Usage: %s OPTIONS\n"
		   "  E.g. %s -i eth1,eth2,eth3\n"
		   "\n"
		   "ODPFastpath application.\n"
		   "\n"
		   "Mandatory OPTIONS:\n"
		   "  -i, --interface Eth interfaces (comma-separated, no spaces)\n"
		   "  -l, local address\n"
		   "  -r, remote address\n"
		   "  -s, number of local sockets, at least one(default)\n"
		   "\n"
		   "Optional OPTIONS\n"
		   "  -c, --count <number> Core count.\n"
		   "  -h, --help           Display help and exit.\n"
		   "\n", NO_PATH(progname), NO_PATH(progname)
		);
}


