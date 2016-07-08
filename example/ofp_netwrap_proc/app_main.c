/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <inttypes.h>
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

/**
 * helper funcs
 */
static int parse_env(appl_args_t *appl_args);
static void print_info(char *progname, appl_args_t *appl_args);
static void usage(char *progname);

 /**
  * global OFP init parms
  */
ofp_init_global_t app_init_params;

/**
 * Get rid of path in filename - only for unix-type paths using '/'
 */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
				strrchr((file_name), '/') + 1 : (file_name))

#define ENV_ARG "OFP_NETWRAP_ENV"
#define ENV_ARG_TKN_NUMBER_MAX 101

enum netwrap_state_enum {
	NETWRAP_UNINT = 0,
	NETWRAP_ODP_INIT_GLOBAL,
	NETWRAP_ODP_INIT_LOCAL,
	NETWRAP_OFP_INIT_GLOBAL,
	NETWRAP_OFP_INIT_LOCAL,
	NETWRAP_WORKERS_STARTED
};

static enum netwrap_state_enum netwrap_state;
static odph_linux_pthread_t thread_tbl[MAX_WORKERS];
static int num_workers;
odp_instance_t netwrap_proc_instance;

__attribute__((destructor)) static void ofp_netwrap_main_dtor();

__attribute__((constructor))
static void ofp_netwrap_main_ctor()
{
	appl_args_t params;
	int core_count, ret_val;
	odp_cpumask_t cpumask;
	char cpumaskstr[64];
	odph_linux_thr_params_t thr_params;

	memset(&params, 0, sizeof(params));
	if (parse_env(&params) != EXIT_SUCCESS)
		return;

	/*
	 * Before any ODP API functions can be called, we must first init ODP
	 * globals, e.g. availale accelerators or software implementations for
	 * shared memory, threads, pool, qeueus, sheduler, pktio, timer, crypto
	 * and classification.
	 */
	if (odp_init_global(&netwrap_proc_instance, NULL, NULL)) {
		printf("Error: ODP global init failed.\n");
		return;
	}
	netwrap_state = NETWRAP_ODP_INIT_GLOBAL;
	/*
	 * When the global ODP level init has been done, we can now issue a
	 * local init per thread. This must also be done before any other ODP
	 * API calls may be made. Local inits are made here for shared memory,
	 * threads, pktio and scheduler.
	 */
	if (odp_init_local(netwrap_proc_instance, ODP_THREAD_CONTROL) != 0) {
		printf("Error: ODP local init failed.\n");
		ofp_netwrap_main_dtor();
		return;
	}
	netwrap_state = NETWRAP_ODP_INIT_LOCAL;

	/* Print both system and application information */
	print_info("ofp_netwrap", &params);

	/*
	 * Get the number of cores available to ODP, one run-to-completion
	 * thread will be created per core.
	 */
	core_count = odp_cpu_count();
	num_workers = core_count;

	if (params.core_count && params.core_count < core_count)
		num_workers = params.core_count;
	if (num_workers > MAX_WORKERS)
		num_workers = MAX_WORKERS;

	/*
	 * This example assumes that core #0 runs Linux kernel background tasks.
	 * By default, cores #1 and beyond will be populated with a OFP
	 * processing thread each.
	 */
	memset(&app_init_params, 0, sizeof(app_init_params));

	app_init_params.linux_core_id = 0;

	if (core_count > 1)
		num_workers--;

	/*
	 * Initializes cpumask with CPUs available for worker threads.
	 * Sets up to 'num' CPUs and returns the count actually set.
	 * Use zero for all available CPUs.
	 */
	num_workers = odp_cpumask_default_worker(&cpumask, num_workers);
	if (odp_cpumask_to_str(&cpumask, cpumaskstr, sizeof(cpumaskstr)) < 0) {
		printf("Error: Too small buffer provided to "
			"odp_cpumask_to_str\n");
		ofp_netwrap_main_dtor();
		return;
	}

	printf("Num worker threads: %i\n", num_workers);
	printf("first CPU:          %i\n", odp_cpumask_first(&cpumask));
	printf("cpu mask:           %s\n", cpumaskstr);

	app_init_params.if_count = params.if_count;
	app_init_params.if_names = params.if_names;

	/*
	 * Now that ODP has been initalized, we can initialize OFP. This will
	 * open a pktio instance for each interface supplied as argument by the
	 * user.
	 *
	 * General configuration will be to pktio and schedluer queues here in
	 * addition will fast path interface configuration.
	 */
	if (ofp_init_global(netwrap_proc_instance, &app_init_params) != 0) {
		printf("Error: OFP global init failed.\n");
		netwrap_state = NETWRAP_OFP_INIT_GLOBAL;
		ofp_netwrap_main_dtor();
		return;
	}
	netwrap_state = NETWRAP_OFP_INIT_GLOBAL;

	if (ofp_init_local() != 0) {
		printf("Error: OFP local init failed.\n");
		netwrap_state = NETWRAP_OFP_INIT_LOCAL;
		ofp_netwrap_main_dtor();
		return;
	}
	netwrap_state = NETWRAP_OFP_INIT_LOCAL;

	/*
	 * Create and launch dataplane dispatcher worker threads to be placed
	 * according to the cpumask, thread_tbl will be populated with the
	 * created pthread IDs.
	 *
	 * In this case, all threads will run the default_event_dispatcher
	 * function with ofp_eth_vlan_processing as argument.
	 *
	 * If different dispatchers should run, or the same be run with differnt
	 * input arguments, the cpumask is used to control this.
	 */
	memset(thread_tbl, 0, sizeof(thread_tbl));
	thr_params.start = default_event_dispatcher;
	thr_params.arg = ofp_eth_vlan_processing;
	thr_params.thr_type = ODP_THREAD_WORKER;
	thr_params.instance = netwrap_proc_instance;
	ret_val = odph_linux_pthread_create(thread_tbl,
					    &cpumask,
					    &thr_params);
	if (ret_val != num_workers) {
		OFP_ERR("Error: Failed to create worker threads, "
			"expected %d, got %d",
			num_workers, ret_val);
		ofp_netwrap_main_dtor();
		return;
	}
	netwrap_state = NETWRAP_WORKERS_STARTED;


	/*
	 * Now when the ODP dispatcher threads are running, further applications
	 * can be launched, in this case, we will start the OFP CLI thread on
	 * the management core, i.e. not competing for cpu cycles with the
	 * worker threads
	 */
	if (ofp_start_cli_thread(netwrap_proc_instance,
		app_init_params.linux_core_id,
		params.conf_file) < 0) {
		OFP_ERR("Error: Failed to init CLI thread");
		ofp_netwrap_main_dtor();
		return;
	}

	sleep(1);

	OFP_INFO("End Netwrap processing constructor()\n");
}

__attribute__((destructor))
static void ofp_netwrap_main_dtor()
{
	ofp_stop_processing();

	switch (netwrap_state) {
	case NETWRAP_WORKERS_STARTED:
	/*
	 * Wait here until all worker threads have terminated, then free up all
	 * resources allocated by odp_init_global().
	 */
		odph_linux_pthread_join(thread_tbl, num_workers);

	case NETWRAP_OFP_INIT_LOCAL:
		if (ofp_term_local() < 0)
			printf("Error: ofp_term_local failed\n");

	case NETWRAP_OFP_INIT_GLOBAL:
		if (ofp_term_global() < 0)
			printf("Error: ofp_term_global failed\n");

	case NETWRAP_ODP_INIT_LOCAL:
		if (odp_term_local() < 0)
			printf("Error: odp_term_local failed\n");

	case NETWRAP_ODP_INIT_GLOBAL:
		if (odp_term_global(netwrap_proc_instance) < 0)
			printf("Error: odp_term_global failed\n");
	};
}

/**
 * Parse and store the command line arguments
 *
 * @param argc       argument count
 * @param argv[]     argument vector
 * @param appl_args  Store application arguments here
 */
static int parse_args(int argc, char *argv[], appl_args_t *appl_args)
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
		opt = getopt_long(argc, argv, "+c:i:hpf:",
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
				return EXIT_FAILURE;
			}
			len += 1;	/* add room for '\0' */

			names = malloc(len);
			if (names == NULL) {
				usage(argv[0]);
				return EXIT_FAILURE;
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
				return EXIT_FAILURE;
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
			return EXIT_FAILURE;

		case 'f':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				return EXIT_FAILURE;
			}
			len += 1;	/* add room for '\0' */

			appl_args->conf_file = malloc(len);
			if (appl_args->conf_file == NULL) {
				usage(argv[0]);
				return EXIT_FAILURE;
			}

			strcpy(appl_args->conf_file, optarg);
			break;

		default:
			break;
		}
	}

	if (appl_args->if_count == 0) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	optind = 1;		/* reset 'extern optind' from the getopt lib */

	return EXIT_SUCCESS;
}

static int parse_env(appl_args_t *appl_args)
{
	char *netwrap_env;
	char *netwrap_env_temp;
	char *argv[ENV_ARG_TKN_NUMBER_MAX];
	int argc = 0;

	netwrap_env = getenv(ENV_ARG);
	if (!netwrap_env)
		return EXIT_FAILURE;

	netwrap_env = strdup(netwrap_env);

	argv[argc++] = NULL;
	netwrap_env_temp = strtok(netwrap_env, " \0");
	while (netwrap_env_temp && argc < ENV_ARG_TKN_NUMBER_MAX) {
		argv[argc++] = netwrap_env_temp;
		netwrap_env_temp = strtok(NULL, " \0");
	}

	/* Parse and store the application arguments */
	if (parse_args(argc, argv, appl_args) != EXIT_SUCCESS)
		return EXIT_FAILURE;

	free(netwrap_env);
	return EXIT_SUCCESS;
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

