/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <getopt.h>
#include <string.h>
#include <inttypes.h>
#include <sys/socket.h>

#include "ofp.h"

#include "ioctl_test.h"

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
static void *app_dispatcher_thread(void *arg);

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


/** Application Dispatcher worker threads
 *
 * @param arg void*
 * @return void*
 *
 */
static void *app_dispatcher_thread(void *arg)
{
	odp_event_t ev;
	odp_packet_t pkt;
	odp_queue_t in_queue;

	(void)arg;

	if (ofp_init_local()) {
		OFP_ERR("Error: OFP local init failed.\n");
		return NULL;
	}

	/* PER CORE DISPATCHER */
	while (1) {
		ev = odp_schedule(&in_queue, ODP_SCHED_WAIT);

		if (ev == ODP_EVENT_INVALID)
			continue;

		if (odp_event_type(ev) == ODP_EVENT_TIMEOUT) {
			ofp_timer_handle(ev);
			continue;
		}

		if (odp_event_type(ev) == ODP_EVENT_PACKET) {
			pkt = odp_packet_from_event(ev);

			ofp_packet_input(pkt, in_queue,
					   ofp_eth_vlan_processing);
			ofp_send_pending_pkt();
			continue;
		}

		printf("App_dispatcher: Error, unexpected event type: %u\n",
		       odp_event_type(ev));

		/* Free events by type */
		if (odp_event_type(ev) == ODP_EVENT_BUFFER) {
			odp_buffer_free(odp_buffer_from_event(ev));
			continue;
		}

		if (odp_event_type(ev) == ODP_EVENT_CRYPTO_COMPL) {
			odp_crypto_compl_free(odp_crypto_compl_from_event(ev));
			continue;
		}

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
#include <sys/time.h>
#include <sys/resource.h>

int main(int argc, char *argv[])
{
	odph_linux_pthread_t thread_tbl[MAX_WORKERS];
	appl_args_t params;
	int core_count, num_workers;
	odp_cpumask_t cpumask;
	char cpumaskstr[64];
	odph_linux_thr_params_t thr_params;
	odp_instance_t instance;

	struct rlimit rlp;
	getrlimit(RLIMIT_CORE, &rlp);
	printf("RLIMIT_CORE: %ld/%ld\n", rlp.rlim_cur, rlp.rlim_max);
	rlp.rlim_cur = 200000000;
	printf("Setting to max: %d\n", setrlimit(RLIMIT_CORE, &rlp));

	/* Parse and store the application arguments */
	parse_args(argc, argv, &params);

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

	if (core_count > 1)
		num_workers--;

	num_workers = odp_cpumask_default_worker(&cpumask, num_workers);
	odp_cpumask_to_str(&cpumask, cpumaskstr, sizeof(cpumaskstr));

	printf("Num worker threads: %i\n", num_workers);
	printf("first CPU:          %i\n", odp_cpumask_first(&cpumask));
	printf("cpu mask:           %s\n", cpumaskstr);

	app_init_params.if_count = params.if_count;
	app_init_params.if_names = params.if_names;
	app_init_params.pkt_hook[OFP_HOOK_LOCAL] = fastpath_local_hook;
	if (ofp_init_global(instance, &app_init_params)) {
		OFP_ERR("Error: OFP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	memset(thread_tbl, 0, sizeof(thread_tbl));
	/* Start dataplane dispatcher worker threads */

	thr_params.start = app_dispatcher_thread;
	thr_params.arg = NULL;
	thr_params.thr_type = ODP_THREAD_WORKER;
	thr_params.instance = instance;
	odph_linux_pthread_create(thread_tbl,
				  &cpumask,
				  &thr_params);

	/* other app code here.*/
	/* Start CLI */
	ofp_start_cli_thread(instance, app_init_params.linux_core_id,
		params.conf_file);

	/* ioctl test thread */
	ofp_start_ioctl_thread(instance, app_init_params.linux_core_id);

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
		   "\n"
		   "Optional OPTIONS\n"
		   "  -c, --count <number> Core count.\n"
		   "  -h, --help           Display help and exit.\n"
		   "\n", NO_PATH(progname), NO_PATH(progname)
		);
}
