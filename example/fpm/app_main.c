/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <sys/socket.h>

#include "ofp.h"
#include "ofp_odp_compat.h"
#include "linux_sigaction.h"

#define MAX_WORKERS		32



/**
 * Parsed command line application arguments
 */
typedef struct {
	int core_count;
	int if_count;		/**< Number of interfaces to be used */
	char **if_names;	/**< Array of pointers to interface names */
	char *conf_file;
	int perf_stat;
} appl_args_t;

/**
 * helper funcs
 */
static int parse_args(int argc, char *argv[], appl_args_t *appl_args);
static void print_info(char *progname, appl_args_t *appl_args);
static void usage(char *progname);
static int start_performance(int core_id);

 /**
  * global OFP init parms
  */
ofp_init_global_t app_init_params;

/**
 * Get rid of path in filename - only for unix-type paths using '/'
 */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
				strrchr((file_name), '/') + 1 : (file_name))


/**
 * local hook
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

/**
 * Signal handler function
 *
 * @param signum int
 * @return void
 *
 */
static void ofp_sig_func_stop(int signum)
{
	printf("Signal handler (signum = %d) ... exiting.\n", signum);

	ofp_stop_processing();
}


/**
 * main() Application entry point
 *
 * This is the main function of the FPM application, it's a minimalistic
 * example, see 'usage' function for available arguments and usage.
 *
 * Using the number of available cores as input, this example sets up
 * ODP dispatcher threads executing OFP VLAN processesing and starts
 * a CLI function on a managment core.
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
	int core_count, num_workers, ret_val;
	odp_cpumask_t cpumask;
	char cpumaskstr[64];

	/* Parse and store the application arguments */
	if (parse_args(argc, argv, &params) != EXIT_SUCCESS)
		return EXIT_FAILURE;

	if (ofp_sigactions_set(ofp_sig_func_stop)) {
		printf("Error: failed to set signal actions.\n");
		return EXIT_FAILURE;
	}

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &params);

	/*
	 * Before any ODP API functions can be called, we must first init the ODP
	 * globals, e.g. availale accelerators or software implementations for
	 * shared memory, threads, pool, qeueus, sheduler, pktio, timer, crypto
	 * and classification.
	 */
	if (odp_init_global(NULL, NULL)) {
		printf("Error: ODP global init failed.\n");
		return EXIT_FAILURE;
	}

	/*
	 * When the gloabel ODP level init has been done, we can now issue a
	 * local init per thread. This must also be done before any other ODP API
	 * calls may be made. Local inits are made here for shared memory,
	 * threads, pktio and scheduler.
	 */
	if (odp_init_local(ODP_THREAD_CONTROL) != 0) {
		printf("Error: ODP local init failed.\n");
		odp_term_global();
		return EXIT_FAILURE;
	}

	/*
	 * Get the number of cores available to ODP, one run-to-completion thread
	 * will be created per core.
	 */
	core_count = odp_cpu_count();
	num_workers = core_count;

	if (params.core_count)
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
		odp_term_local();
		odp_term_global();
		return EXIT_FAILURE;
	}

	printf("Num worker threads: %i\n", num_workers);
	printf("first CPU:          %i\n", odp_cpumask_first(&cpumask));
	printf("cpu mask:           %s\n", cpumaskstr);

	app_init_params.if_count = params.if_count;
	app_init_params.if_names = params.if_names;
	app_init_params.pkt_hook[OFP_HOOK_LOCAL] = fastpath_local_hook;

	/*
	 * Now that ODP has been initalized, we can initialize OFP. This will
	 * open a pktio instance for each interface supplied as argument by the
	 * user.
	 *
	 * General configuration will be to pktio and schedluer queues here in
	 * addition will fast path interface configuration.
	 */
	if (ofp_init_global(&app_init_params) != 0) {
		printf("Error: OFP global init failed.\n");
		ofp_term_global();
		odp_term_local();
		odp_term_global();
		return EXIT_FAILURE;
	}

	if (ofp_init_local() != 0) {
		printf("Error: OFP local init failed.\n");
		ofp_term_local();
		ofp_term_global();
		odp_term_local();
		odp_term_global();
		return EXIT_FAILURE;
	}

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
	ret_val = ofp_linux_pthread_create(thread_tbl,
					    &cpumask,
					    default_event_dispatcher,
					    ofp_eth_vlan_processing,
					    ODP_THREAD_CONTROL
					  );
	if (ret_val != num_workers) {
		OFP_ERR("Error: Failed to create worker threads, "
			"expected %d, got %d",
			num_workers, ret_val);
		ofp_stop_processing();
		odph_linux_pthread_join(thread_tbl, num_workers);
		ofp_term_local();
		ofp_term_global();
		odp_term_local();
		odp_term_global();
		return EXIT_FAILURE;
	}

	/*
	 * Now when the ODP dispatcher threads are running, further applications
	 * can be launched, in this case, we will start the OFP CLI thread on
	 * the management core, i.e. not competing for cpu cycles with the
	 * worker threads
	 */
	if (ofp_start_cli_thread(app_init_params.linux_core_id,
		params.conf_file) < 0) {
		OFP_ERR("Error: Failed to init CLI thread");
		ofp_stop_processing();
		odph_linux_pthread_join(thread_tbl, num_workers);
		ofp_term_local();
		ofp_term_global();
		odp_term_local();
		odp_term_global();
		return EXIT_FAILURE;
	}

	/*
	 * If we choose to check performance, a performance monitoring client
	 * will be started on the management core. Once every second it will
	 * read the statistics from the workers from a shared memory region.
	 * Using this has negligible performance impact (<<0.01%).
	 */
	if (params.perf_stat) {
		if (start_performance(app_init_params.linux_core_id) <= 0) {
			OFP_ERR("Error: Failed to init performance monitor");
			ofp_stop_processing();
			odph_linux_pthread_join(thread_tbl, num_workers);
			ofp_term_local();
			ofp_term_global();
			odp_term_local();
			odp_term_global();
			return EXIT_FAILURE;
		}
	}

	/*
	 * Wait here until all worker threads have terminated, then free up all
	 * resources allocated by odp_init_global().
	 */
	odph_linux_pthread_join(thread_tbl, num_workers);

	if (ofp_term_local() < 0)
		printf("Error: ofp_term_local failed\n");

	if (ofp_term_global() < 0)
		printf("Error: ofp_term_global failed\n");

	if (odp_term_local() < 0)
		printf("Error: odp_term_local failed\n");

	if (odp_term_global() < 0)
		printf("Error: odp_term_global failed\n");

	printf("FPM End Main()\n");

	return EXIT_SUCCESS;
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
		{"performance", no_argument, NULL, 'p'},	/* return 'p' */
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

		case 'p':
			appl_args->perf_stat = 1;
			break;

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
		   "  -p, --performance    Performance Statistics\n"
		   "  -h, --help           Display help and exit.\n"
		   "\n", NO_PATH(progname), NO_PATH(progname)
		);
}

static void *perf_client(void *arg)
{
	(void) arg;

#if ODP_VERSION < 106
	if (odp_init_local(ODP_THREAD_CONTROL) != 0) {
		OFP_ERR("Error: ODP local init failed.\n");
		return NULL;
	}
#endif
	if (ofp_init_local()) {
		OFP_ERR("Error: OFP local init failed.\n");
		return NULL;
	}

	ofp_set_stat_flags(OFP_STAT_COMPUTE_PERF);

	while (1) {
		struct ofp_perf_stat *ps = ofp_get_perf_statistics();
		printf ("Mpps:%4.3f\n", ((float)ps->rx_fp_pps)/1000000);
		usleep(1000000UL);
	}

	return NULL;
}

static int start_performance(int core_id)
{
	odph_linux_pthread_t cli_linux_pthread;
	odp_cpumask_t cpumask;

	odp_cpumask_zero(&cpumask);
	odp_cpumask_set(&cpumask, core_id);

	return ofp_linux_pthread_create(&cli_linux_pthread,
					 &cpumask,
					 perf_client,
					 NULL,
					 ODP_THREAD_WORKER
					);

}
