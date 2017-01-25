/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <getopt.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "ofp.h"
#include "httpd.h"

#define MAX_WORKERS		32
#define MAX_CORE_FILE_SIZE	200000000

enum execution_mode {
	EXEC_MODE_SCHEDULER = 0,
	EXEC_MODE_DIRECT_RSS,
	EXEC_MODE_MAX = EXEC_MODE_DIRECT_RSS
};

/**
 * Parsed command line application arguments
 */
typedef struct {
	enum execution_mode mode;
	int core_count;
	int core_start;
	int if_count;		/**< Number of interfaces to be used */
	char **if_names;	/**< Array of pointers to interface names */
	char *conf_file;
	char *root_dir;
	char *laddr;
	uint16_t lport;
} appl_args_t;

struct worker_arg {
	int num_pktin;
	odp_pktin_queue_t pktin[OFP_FP_INTERFACE_MAX];
};

/* helper funcs */
static void parse_args(int argc, char *argv[], appl_args_t *appl_args);
static void print_info(char *progname, appl_args_t *appl_args);
static void usage(char *progname);
static int resource_cfg(void);
static int validate_cores_settings(int req_core_start, int req_core_count,
	int *core_start, int *core_count);

ofp_init_global_t app_init_params; /**< global OFP init parms */

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
				strrchr((file_name), '/') + 1 : (file_name))

#define PKT_BURST_SIZE OFP_PKT_RX_BURST_SIZE

/** pkt_io_direct_mode_recv() Custom event dispatcher
 *
 * @param arg void*  Worker argument
 * @return void* Never returns
 *
 */
static void *pkt_io_direct_mode_recv(void *arg)
{
	odp_packet_t pkt, pkt_tbl[PKT_BURST_SIZE];
	odp_event_t events[PKT_BURST_SIZE], ev;
	int pkt_idx, pkt_cnt, event_cnt;
	struct worker_arg *thr_args;
	int num_pktin, i;
	odp_pktin_queue_t pktin[OFP_FP_INTERFACE_MAX];
	uint8_t *ptr;

	thr_args = arg;
	num_pktin = thr_args->num_pktin;

	for (i = 0; i < num_pktin; i++)
		pktin[i] = thr_args->pktin[i];

	if (ofp_init_local()) {
		OFP_ERR("Error: OFP local init failed.\n");
		return NULL;
	}
	ptr = (uint8_t *)&pktin[0];

	printf("PKT-IO receive starting on cpu: %i, %i, %x:%x\n", odp_cpu_id(),
	       num_pktin, ptr[0], ptr[8]);

	while (1) {
		event_cnt = odp_schedule_multi(NULL, ODP_SCHED_NO_WAIT,
			events, PKT_BURST_SIZE);
		for (i = 0; i < event_cnt; i++) {
			ev = events[i];

			if (ev == ODP_EVENT_INVALID)
				continue;

			if (odp_event_type(ev) == ODP_EVENT_TIMEOUT)
				ofp_timer_handle(ev);
			else
				odp_buffer_free(odp_buffer_from_event(ev));
		}
		for (i = 0; i < num_pktin; i++) {
			pkt_cnt = odp_pktin_recv(pktin[i], pkt_tbl,
						 PKT_BURST_SIZE);

			for (pkt_idx = 0; pkt_idx < pkt_cnt; pkt_idx++) {
				pkt = pkt_tbl[pkt_idx];

				ofp_packet_input(pkt, ODP_QUEUE_INVALID,
					ofp_eth_vlan_processing);
			}
		}
		ofp_send_pending_pkt();
	}

	/* Never reached */
	return NULL;
}

/** create_interfaces_direct_rss() Create OFP interfaces with
 * pktios open in direct mode, thread unsafe and using RSS with
 * hashing by IPv4 addresses and TCP ports
 *
 * @param if_count int  Interface count
 * @param if_names char** Interface names
 * @param tx_queue int Number of requested transmision queues
 *    per interface
 * @param rx_queue int Number of requested reciver queues per
 *    interface
 * @return int 0 on success, -1 on error
 *
 */
static int create_interfaces_direct_rss(odp_instance_t instance,
	int if_count, char **if_names,
	int tx_queues, int rx_queues)
{
	odp_pktio_param_t pktio_param;
	odp_pktin_queue_param_t pktin_param;
	odp_pktout_queue_param_t pktout_param;
	int i;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_DIRECT;
	pktio_param.out_mode = ODP_PKTOUT_MODE_DIRECT;

	odp_pktin_queue_param_init(&pktin_param);
	pktin_param.op_mode = ODP_PKTIO_OP_MT_UNSAFE;
	pktin_param.hash_enable = 1;
	pktin_param.hash_proto.proto.ipv4_tcp = 1;
	pktin_param.num_queues = rx_queues;

	odp_pktout_queue_param_init(&pktout_param);
	pktout_param.op_mode    = ODP_PKTIO_OP_MT_UNSAFE;
	pktout_param.num_queues = tx_queues;

	for (i = 0; i < if_count; i++)
		if (ofp_ifnet_create(instance, if_names[i],
				&pktio_param,
				&pktin_param,
				&pktout_param) < 0) {
			OFP_ERR("Failed to init interface %s",
				if_names[i]);
			return -1;
		}

	return 0;
}

/** configure_workers_arg_direct_rss() Configure workers
 *  argument
 *
 * @param num_workers int  Number of workers
 * @param workers_arg struct worker_arg* Array of workers
 *    argument
 * @param if_count int  Interface count
 * @param if_names char** Interface names
 * @return int 0 on success, -1 on error
 *
 */
static int configure_workers_arg_direct_rss(int num_workers,
	struct worker_arg *workers_arg,
	int if_count, char **if_names)
{
	int i, j;
	odp_pktio_t pktio;
	odp_pktin_queue_t pktin[MAX_WORKERS];

	for (i = 0; i < num_workers; i++)
		workers_arg[i].num_pktin = if_count;

	for (i = 0; i < if_count; i++) {
		pktio = odp_pktio_lookup(if_names[i]);
		if (pktio == ODP_PKTIO_INVALID) {
			OFP_ERR("Failed locate pktio %s", if_names[i]);
			return -1;
		}

		if (odp_pktin_queue(pktio, pktin, num_workers) != num_workers) {
			OFP_ERR("Too few pktin queues for %s", if_names[i]);
			return -1;
		}

		for (j = 0; j < num_workers; j++)
			workers_arg[j].pktin[i] = pktin[j];
	}

	return 0;
}

/**
 * main() Application entry point
 *
 * This is the main function of the application. See 'usage'
 * function for available arguments and usage.
 *
 * @param argc int
 * @param argv[] char*
 * @return int
 *
 */
int main(int argc, char *argv[])
{
	odph_linux_pthread_t thread_tbl[MAX_WORKERS];
	appl_args_t params;
	int num_workers, first_worker, linux_sp_core, i;
	struct worker_arg workers_arg_direct_rss[MAX_WORKERS];
	odp_cpumask_t cpu_mask;
	odph_linux_thr_params_t thr_params;
	odp_instance_t instance;

	/* Setup system resources */
	resource_cfg();

	/* Parse application arguments */
	parse_args(argc, argv, &params);

	if (params.if_count > OFP_FP_INTERFACE_MAX) {
		printf("Error: Invalid number of interfaces: maximum %d\n",
		       OFP_FP_INTERFACE_MAX);
		exit(EXIT_FAILURE);
	}

	/* Initialize ODP*/
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

	/*
	 * By default core #0 runs Slow Path background tasks.
	 * It is recommanded to start mapping threads from core 1. Else,
	 * Slow Path processing will be affected by workers processing.
	 * However, if Slow Path is disabled, core 0 may be used as well.
	 */
	if (validate_cores_settings(params.core_start, params.core_count,
		&first_worker, &num_workers) < 0) {
		odp_term_local();
		odp_term_global(instance);
		exit(EXIT_FAILURE);
	}
	linux_sp_core = 0;
	OFP_INFO("SP core: %d\nWorkers core start: %d\n"
		"Workers core count: %d\n",
		linux_sp_core, first_worker, num_workers);

	/* Initialize OFP*/
	memset(&app_init_params, 0, sizeof(app_init_params));
	app_init_params.linux_core_id = linux_sp_core;
	if (params.mode == EXEC_MODE_SCHEDULER) {
		app_init_params.burst_recv_mode = 0;
		app_init_params.if_count = params.if_count;
		app_init_params.if_names = params.if_names;
	}

	if (ofp_init_global(instance, &app_init_params)) {
		OFP_ERR("Error: OFP global init failed.\n");
		exit(EXIT_FAILURE);
	}
	if (ofp_init_local()) {
		OFP_ERR("Error: OFP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	if (params.mode == EXEC_MODE_DIRECT_RSS) {
		if (create_interfaces_direct_rss(instance,
			params.if_count, params.if_names,
			num_workers, num_workers)) {
			OFP_ERR("Failed to initialize interfaces.");
			exit(EXIT_FAILURE);
		}

		if (configure_workers_arg_direct_rss(num_workers,
			workers_arg_direct_rss,
			params.if_count, params.if_names)) {
			OFP_ERR("Failed to initialize workers arguments.");
			exit(EXIT_FAILURE);
		}
	}

	memset(thread_tbl, 0, sizeof(thread_tbl));

	/* Create worker threads */
	for (i = 0; i < num_workers; i++) {
		if (params.mode == EXEC_MODE_DIRECT_RSS) {
			thr_params.start = pkt_io_direct_mode_recv;
			thr_params.arg = &workers_arg_direct_rss[i];
		} else {
			thr_params.start = default_event_dispatcher;
			thr_params.arg = ofp_eth_vlan_processing;
		}
		thr_params.thr_type = ODP_THREAD_WORKER;
		thr_params.instance = instance;

		odp_cpumask_zero(&cpu_mask);
		odp_cpumask_set(&cpu_mask, first_worker + i);

		odph_linux_pthread_create(&thread_tbl[i], &cpu_mask,
					  &thr_params);
	}

	/* Start CLI */
	ofp_start_cli_thread(instance, app_init_params.linux_core_id,
		params.conf_file);

	sleep(2);
	/* webserver */
	if (setup_webserver(params.root_dir, params.laddr, params.lport)) {
		OFP_ERR("Error: Failed to setup webserver.\n");
		exit(EXIT_FAILURE);
	}

	odph_linux_pthread_join(thread_tbl, num_workers);
	printf("End Main()\n");

	return 0;
}

/**
 * resource_cfg() Setup system resources
 *
 * @return int 0 on success, -1 on error
 *
 */
static int resource_cfg(void)
{
	struct rlimit rlp;

	getrlimit(RLIMIT_CORE, &rlp);
	printf("RLIMIT_CORE: %ld/%ld\n", rlp.rlim_cur, rlp.rlim_max);
	rlp.rlim_cur = MAX_CORE_FILE_SIZE;
	printf("Setting to max: %d\n", setrlimit(RLIMIT_CORE, &rlp));

	return 0;
}

/**
 * validate_cores_settings() Validate requested core settings
 * and computed actual values
 *
 *
 * @param req_core_start int Requested worker core start
 * @param req_core_count int Requested worker core count
 * @param core_start int* Computed worker core start
 * @param core_count int* Computed worker core count
 * @return int 0 on success, -1 on error
 *
 */
static int validate_cores_settings(int req_core_start, int req_core_count,
	 int *core_start, int *core_count)
{
	int total_core_count = odp_cpu_count();

	if (req_core_start >= total_core_count) {
		OFP_ERR("ERROR: Invalid 'core start' parameter: %d. Max = %d\n",
			req_core_start, total_core_count - 1);
		return -1;
	}
	*core_start = req_core_start;

	if (req_core_count) {
		if (*core_start + req_core_count > total_core_count) {
			OFP_ERR("ERROR: Invalid 'core start' 'core count' "
				"configuration: %d,%d\n"
				"Exeeds number of avilable cores: %d",
				*core_start, req_core_count, total_core_count);
			return -1;
		}
		*core_count = req_core_count;
	} else
		*core_count = total_core_count - *core_start;

	if (*core_count < 0) {
		OFP_ERR("ERROR: At least 1 core is required.\n");
		return -1;
	}
	if (*core_count > MAX_WORKERS)  {
		OFP_ERR("ERROR: Number of processing cores %d"
			" exeeds maximum number for this test %d.\n",
			*core_count, MAX_WORKERS);
		return -1;
	}
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
		{"mode", required_argument, NULL, 'm'},
		{"core_count", required_argument, NULL, 'c'},
		{"core_start", required_argument, NULL, 's'},
		{"interface", required_argument, NULL, 'i'},	/* return 'i' */
		{"help", no_argument, NULL, 'h'},		/* return 'h' */
		{"configuration_file", required_argument,
			NULL, 'f'},/* return 'f' */
		{"root", required_argument, NULL, 'r'},	/* return 'r' */
		{"laddr", required_argument, NULL, 'l'},	/* return 'l' */
		{"lport", required_argument, NULL, 'p'},	/* return 'p' */
		{NULL, 0, NULL, 0}
	};

	memset(appl_args, 0, sizeof(*appl_args));
	appl_args->core_start = 1;
	appl_args->core_count = 0; /* all above core start */

	while (1) {
		opt = getopt_long(argc, argv, "+c:s:i:hf:r:l:p:m:",
				  longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'm':
		{
			int mode_arg = atoi(optarg);

			if (mode_arg < 0 || mode_arg > EXEC_MODE_MAX) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			appl_args->mode = mode_arg;
			break;
		}
		case 'c':
			appl_args->core_count = atoi(optarg);
			break;
		case 's':
			appl_args->core_start = atoi(optarg);
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
		case 'r':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1;	/* add room for '\0' */

			appl_args->root_dir = malloc(len);
			if (appl_args->root_dir == NULL) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			strcpy(appl_args->root_dir, optarg);
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
		case 'p':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1;	/* add room for '\0' */

			appl_args->lport = (uint64_t)atoi(optarg);
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
	printf("\n");

	printf("Execution mode:  %s\n",
		appl_args->mode == EXEC_MODE_DIRECT_RSS ?
		"direct_rss" : "scheduler");
	printf("\n");
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
		   "\n"
		   "Optional OPTIONS\n"
		   "  -m, --mode <number> Execution mode: 0 scheduler mode, 1 direct_rss mode. Default 0.\n"
		   "  -c, --core_count <number> Core count. Default 0: all above core start\n"
		   "  -s, --core_start <number> Core start. Default 1.\n"
		   "  -r, --root <web root folder> Webserver root folder.\n"
		   "  -f, --configuration_file <file> OFP configuration file.\n"
			"\tDefault: "DEFAULT_ROOT_DIRECTORY"\n"
		   "  -l, --laddr <IPv4 address> IPv4 address were webserver binds.\n"
			"\tDefault: %s\n"
		   "  -p, --lport <port> Port address were webserver binds.\n"
			"\tDefault: %d\n"
		   "  -h, --help           Display help and exit.\n"
		   "\n", NO_PATH(progname), NO_PATH(progname),
		   ofp_print_ip_addr(DEFAULT_BIND_ADDRESS), DEFAULT_BIND_PORT
		);
}
