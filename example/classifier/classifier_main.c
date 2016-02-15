/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include "ofp.h"
#include "ofp_odp_compat.h"

#define MAX_WORKERS		32
#define TEST_PORT 54321

#define IP4(a, b, c, d) (a|(b<<8)|(c<<16)|(d<<24))

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
static int build_classifier(int if_count, char **if_names);
static odp_cos_t build_cos_w_queue(const char *name);
static odp_cos_t build_cos_set_queue(const char *name, odp_queue_t queue_cos);
static odp_pmr_t build_udp_prm(void);
static void app_processing(void);

ofp_init_global_t app_init_params; /**< global OFP init parms */

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
				strrchr((file_name), '/') + 1 : (file_name))


/** main() Application entry point
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
	int core_count, num_workers;
	odp_cpumask_t cpumask;
	char cpumaskstr[64];

	/* Parse and store the application arguments */
	parse_args(argc, argv, &params);

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &params);

	if (odp_init_global(NULL, NULL)) {
		OFP_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}
	if (odp_init_local(ODP_THREAD_CONTROL)) {
		OFP_ERR("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	core_count = odp_cpu_count();
	num_workers = core_count;

	if (params.core_count)
		num_workers = params.core_count;
	if (num_workers > MAX_WORKERS)
		num_workers = MAX_WORKERS;

	if (core_count > 1)
		num_workers--;

	num_workers = odp_cpumask_default_worker(&cpumask, num_workers);
	odp_cpumask_to_str(&cpumask, cpumaskstr, sizeof(cpumaskstr));

	printf("Num worker threads: %i\n", num_workers);
	printf("first CPU:          %i\n", odp_cpumask_first(&cpumask));
	printf("cpu mask:           %s\n", cpumaskstr);

	memset(&app_init_params, 0, sizeof(app_init_params));
	app_init_params.linux_core_id = 0;
	app_init_params.if_count = params.if_count;
	app_init_params.if_names = params.if_names;

	if (ofp_init_global(&app_init_params)) {
		OFP_ERR("Error: OFP global init failed.\n");
		exit(EXIT_FAILURE);
	}
	if (ofp_init_local()) {
		OFP_ERR("Error: OFP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	build_classifier(app_init_params.if_count, app_init_params.if_names);

	/* Start CLI */
	ofp_start_cli_thread(app_init_params.linux_core_id, params.conf_file);
	sleep(1);

	memset(thread_tbl, 0, sizeof(thread_tbl));
	/* Start dataplane dispatcher worker threads */
	ofp_linux_pthread_create(thread_tbl,
				  &cpumask,
				  default_event_dispatcher,
				  ofp_udp4_processing,
				  ODP_THREAD_CONTROL
				);

	app_processing();

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

int build_classifier(int if_count, char **if_names)
{
	odp_pktio_t pktio;
	odp_cos_t cos_def;
	odp_cos_t cos_udp;
	odp_pmr_t pmr_udp;
	char name[80];
	int i;

	cos_udp = build_cos_w_queue("cos_udp");
	if (cos_udp == ODP_COS_INVALID) {
		OFP_ERR("Failed to create UDP COS");
		return -1;
	}

	pmr_udp = build_udp_prm();
	if (pmr_udp == ODP_PMR_INVAL) {
		OFP_ERR("Failed to create UDP PRM");
		return -1;
	}

	for (i = 0; i < if_count; i++) {
		pktio = odp_pktio_lookup(if_names[i]);
		if (pktio == ODP_PKTIO_INVALID) {
			OFP_ERR("Failed to get pktio for interface %s\n",
				if_names[i]);
			return -1;
		}

		sprintf(name, "cos_default_%s", if_names[i]);
		cos_def = build_cos_set_queue(name, ofp_pktio_spq_get(pktio));
		if (cos_def == ODP_COS_INVALID) {
			OFP_ERR("Failed to create default COS "
				"for interface %s\n", if_names[i]);
			return -1;
		}

		if (odp_pktio_default_cos_set(pktio, cos_def) < 0) {
			OFP_ERR("Failed to set default COS on interface %s\n",
				if_names[i]);
			return -1;
		}

		if (odp_pktio_error_cos_set(pktio, cos_def) < 0) {
			OFP_ERR("Failed to set error COS on interface %s\n",
				if_names[i]);
			return -1;
		}

		if (odp_pktio_pmr_cos(pmr_udp, pktio, cos_udp) < 0) {
			OFP_ERR("Failed to set UDP PRM on interface %s\n",
				if_names[i]);
			return 1;
		}
	}

	return 0;
}

static odp_cos_t build_cos_w_queue(const char *name)
{
	odp_cos_t cos;
	odp_queue_t queue_cos;
	odp_queue_param_t qparam;

	cos = odp_cls_cos_create(name, &qparam);
	if (cos == ODP_COS_INVALID) {
		OFP_ERR("Failed to create COS");
		return ODP_COS_INVALID;
	}

	odp_queue_param_init(&qparam);
	qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;

	queue_cos = ofp_queue_create(name,
				ODP_QUEUE_TYPE_SCHED,
				&qparam);
	if (queue_cos == ODP_QUEUE_INVALID) {
		OFP_ERR("Failed to create queue\n");
		odp_cos_destroy(cos);
		return ODP_COS_INVALID;
	}

#if ODP_VERSION < 104
	if (odp_cos_set_queue(cos, queue_cos) < 0) {
#else
	if (odp_cos_queue_set(cos, queue_cos) < 0) {
#endif
		OFP_ERR("Failed to set queue on COS");
		odp_cos_destroy(cos);
		odp_queue_destroy(queue_cos);
		return ODP_COS_INVALID;
	}

	return cos;
}

static odp_cos_t build_cos_set_queue(const char *name, odp_queue_t queue_cos)
{
	odp_cos_t cos;
	odp_queue_param_t qparam;

	cos = odp_cls_cos_create(name, &qparam);
	if (cos == ODP_COS_INVALID) {
		OFP_ERR("Failed to create COS");
		return ODP_COS_INVALID;
	}

#if ODP_VERSION < 104
	if (odp_cos_set_queue(cos, queue_cos) < 0) {
#else
	if (odp_cos_queue_set(cos, queue_cos) < 0) {
#endif
		OFP_ERR("Failed to set queue on COS");
		odp_cos_destroy(cos);
		return ODP_COS_INVALID;
	}

	return cos;
}

static odp_pmr_t build_udp_prm(void)
{
	uint32_t pmr_udp_val = TEST_PORT;
	uint32_t pmr_udp_mask = 0xffffffff;

#if ODP_VERSION < 104
	return odp_pmr_create(ODP_PMR_UDP_DPORT,
			      &pmr_udp_val,
			      &pmr_udp_mask,
			      1);
#else
	const odp_pmr_match_t match = {
		.term = ODP_PMR_UDP_DPORT,
		.val = &pmr_udp_val,
		.mask = &pmr_udp_mask,
		.val_sz = 1
	};

	return odp_pmr_create(&match);
#endif
}

static void app_processing(void)
{
	int fd_rcv = -1;
	char buf[1500];
	int len = sizeof(buf);

	do {
		struct ofp_sockaddr_in addr = {0};

		fd_rcv = ofp_socket(OFP_AF_INET, OFP_SOCK_DGRAM,
				OFP_IPPROTO_UDP);
		if (fd_rcv == -1) {
			OFP_ERR("Faild to create RCV socket (errno = %d)\n",
				ofp_errno);
			break;
		}

		addr.sin_len = sizeof(struct ofp_sockaddr_in);
		addr.sin_family = OFP_AF_INET;
		addr.sin_port = odp_cpu_to_be_16(TEST_PORT);
		addr.sin_addr.s_addr = IP4(192, 168, 100, 1);

		if (ofp_bind(fd_rcv, (const struct ofp_sockaddr *)&addr,
			sizeof(struct ofp_sockaddr_in)) == -1) {
			OFP_ERR("Faild to bind socket (errno = %d)\n",
				ofp_errno);
			break;
		}

		len = ofp_recv(fd_rcv, buf, len, 0);
		if (len == -1)
			OFP_ERR("Faild to receive data (errno = %d)\n",
				ofp_errno);
		else
			OFP_INFO("Data received: length = %d.\n", len);

	} while (0);

	if (fd_rcv != -1) {
		ofp_close(fd_rcv);
		fd_rcv = -1;
	}
	OFP_INFO("Test ended.\n");
}

