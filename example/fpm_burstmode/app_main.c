/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <getopt.h>
#include <string.h>
#include <sys/socket.h>

#include "ofp.h"

#define MAX_WORKERS		32

/**
 * Parsed command line application arguments
 */
typedef struct {
	int core_count;
	int if_count;		/**< Number of interfaces to be used */
	char **if_names;	/**< Array of pointers to interface names */
	char *conf_file;
} appl_args_t;

/* helper funcs */
static void parse_args(int argc, char *argv[], appl_args_t *appl_args);
static void print_info(char *progname, appl_args_t *appl_args);
static void usage(char *progname);

ofp_init_global_t app_init_params; /**< global OFP init parms */

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
				strrchr((file_name), '/') + 1 : (file_name))


/** local hook
 *
 * @param pkt odp_packet_t
 * @param protocol int
 * @return int
 *
 */
static enum ofp_return_code fastpath_local_hook(odp_packet_t pkt, void *arg)
{
	int protocol = *(int *)arg;
	(void) pkt;
	(void) protocol;
	return OFP_PKT_CONTINUE;
}

#define OFP_PKT_BURST_SIZE 16

struct pktio_thr_arg {
	int port;
	ofp_pkt_processing_func pkt_func;
};

static void *pkt_io_recv(void *arg)
{
	odp_pktio_t pktio;
	odp_packet_t pkt, pkt_tbl[OFP_PKT_BURST_SIZE];
	int pkt_idx, pkt_cnt;
	struct pktio_thr_arg *thr_args;
	ofp_pkt_processing_func pkt_func;

	thr_args = arg;
	pkt_func = thr_args->pkt_func;

	ofp_init_local();

	pktio = ofp_port_pktio_get(thr_args->port);

	OFP_DBG("PKT-IO receive starting on port: %d, pktio-id: %"PRIX64"\n",
		  thr_args->port, odp_pktio_to_u64(pktio));

	while (1) {
		pkt_cnt = odp_pktio_recv(pktio, pkt_tbl, OFP_PKT_BURST_SIZE);

		for (pkt_idx = 0; pkt_idx < pkt_cnt; pkt_idx++) {
			pkt = pkt_tbl[pkt_idx];

			if (odp_unlikely(odp_packet_has_error(pkt))) {
				OFP_DBG("Packet with error dropped.\n");
				odp_packet_free(pkt);
			}

			ofp_packet_input(pkt, ODP_QUEUE_INVALID, pkt_func);
		}
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

	ofp_init_local();

	while (1) {
		ev = odp_schedule(NULL, ODP_SCHED_WAIT);

		if (ev == ODP_EVENT_INVALID)
			continue;

		if (odp_event_type(ev) == ODP_EVENT_TIMEOUT) {
			ofp_timer_handle(ev);
			continue;
		}

		OFP_ERR("Event_dispatcher: "
			  "Error, unexpected event type: %u\n",
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
	char cpumaskstr[64];
	int cpu, first_cpu, i;
	struct pktio_thr_arg pktio_thr_args[MAX_WORKERS];

	/* Parse and store the application arguments */
	parse_args(argc, argv, &params);

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &params);

	if (odp_init_global(NULL, NULL)) {
		OFP_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}
	odp_init_local();

	memset(thread_tbl, 0, sizeof(thread_tbl));
	memset(pktio_thr_args, 0, sizeof(pktio_thr_args));

	core_count = odp_cpu_count();
	num_workers = core_count;
	first_cpu = 1;

	if (params.core_count)
		num_workers = params.core_count;
	if (num_workers > MAX_WORKERS)
		num_workers = MAX_WORKERS;

	/*
	 * By default core #0 runs Linux kernel background tasks.
	 * Start mapping thread from core #1
	 */
	memset(&app_init_params, 0, sizeof(app_init_params));

	app_init_params.linux_core_id = 0;

	if (core_count <= 1) {
		OFP_ERR("Burst mode requires multiple cores.\n");
		exit(EXIT_FAILURE);
	}
	num_workers--;

	printf("Num worker threads: %i\n", num_workers);
	printf("first CPU:          %i\n", first_cpu);

	app_init_params.if_count = params.if_count;
	app_init_params.if_names = params.if_names;
	app_init_params.pkt_hook[OFP_HOOK_LOCAL] = fastpath_local_hook;
	app_init_params.burst_recv_mode = 1;
	ofp_init_global(&app_init_params);

	if (num_workers < params.if_count) {
		OFP_ERR("At least %u fastpath cores required.\n",
			  params.if_count);
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < num_workers; ++i) {
		pktio_thr_args[i].pkt_func = ofp_eth_vlan_processing;
		pktio_thr_args[i].port = i % params.if_count;

		odp_cpumask_zero(&cpu_mask);
		cpu = first_cpu + i;
		odp_cpumask_set(&cpu_mask, cpu);
		odp_cpumask_to_str(&cpu_mask, cpumaskstr, sizeof(cpumaskstr));

		OFP_DBG("Starting pktio receive on core: %d port: %d\n",
			  cpu, pktio_thr_args[i].port);
		OFP_DBG("cpu mask: %s\n", cpumaskstr);

		odph_linux_pthread_create(&thread_tbl[i],
					  &cpu_mask,
					  pkt_io_recv,
					  &pktio_thr_args[i]);
	}

	odp_cpumask_zero(&cpu_mask);
	odp_cpumask_set(&cpu_mask, app_init_params.linux_core_id);
	odph_linux_pthread_create(&dispatcher_thread,
				  &cpu_mask,
				  event_dispatcher,
				  NULL);

	/* other app code here.*/
	/* Start CLI */
	ofp_start_cli_thread(app_init_params.linux_core_id, params.conf_file);

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
		{NULL, 0, NULL, 0}
	};

	memset(appl_args, 0, sizeof(*appl_args));

	while (1) {
		opt = getopt_long(argc, argv, "+c:i:hf:",
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
		   odp_version_api_str(), odp_sys_cpu_model_str(),
		   odp_sys_cpu_hz(), odp_sys_cache_line_size(),
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
		   "\n"
		   "Optional OPTIONS\n"
		   "  -c, --count <number> Core count.\n"
		   "  -h, --help           Display help and exit.\n"
		   "\n", NO_PATH(progname), NO_PATH(progname)
		);
}
