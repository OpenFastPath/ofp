/*
 * Copyright (c) 2016, lvsgate@163.com
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <getopt.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>

#include "ofp.h"

#include "ofp_vs.h"

#define MAX_WORKERS		32

/**
 * Parsed command line application arguments
 */
typedef struct {
	int core_count;
	int if_count;		/**< Number of interfaces to be used */
	char **if_names;	/**< Array of pointers to interface names */
	char *conf_file;
	int inner_port;
	int outer_port;
} appl_args_t;

static appl_args_t appl_params;


/* helper funcs */
static void parse_args(int argc, char *argv[], appl_args_t *appl_args);
static void print_info(char *progname, appl_args_t *appl_args);
static void usage(char *progname);

ofp_init_global_t app_init_params; /**< global OFP init parms */

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
				strrchr((file_name), '/') + 1 : (file_name))


static unsigned int ofp_vs_num_workers;
odp_cpumask_t ofp_vs_worker_cpumask;

unsigned int ofp_vs_worker_count(void)
{
	return ofp_vs_num_workers;
}

int ofp_vs_outer_port(void)
{
	return appl_params.outer_port;
}

int ofp_vs_inner_port(void)
{
	return appl_params.inner_port;
}

struct pktin_table_s {
	int	num_in_queue;
	odp_pktin_queue_t in_queue[OFP_PKTIN_QUEUE_MAX];
} pktin_table[OFP_FP_INTERFACE_MAX];

static odp_pktin_queue_t if_iq_bind_to_core[OFP_FP_INTERFACE_MAX][OFP_MAX_NUM_CPU];

static void signal_handler(int signal)
{
  const char *signal_name;

  switch (signal) {
    case SIGILL:
        signal_name = "SIGILL";   break;
    case SIGFPE:
        signal_name = "SIGFPE";   break;
    case SIGSEGV:
        signal_name = "SIGSEGV";  break;
    case SIGTERM:
        signal_name = "SIGTERM";  break;
    case SIGINT:
        signal_name = "SIGINT";  break; 
    case SIGBUS:
        signal_name = "SIGBUS";   break;
    default:
        signal_name = "UNKNOWN";  break;
  }
  ofp_stop_processing();
  fprintf(stderr, "Recv signal %u (%s) exiting.\n", signal, signal_name);
}

static void direct_recv(const appl_args_t *appl_params)
{
	int i;
	int port;
	int cpu = odp_cpu_id();
	ofp_pkt_processing_func pkt_func = ofp_eth_vlan_processing;

	for (port = 0; port < appl_params->if_count; port++) {
		int pkts;
		odp_pktin_queue_t in_queue;
		odp_packet_t pkt_tbl[OFP_PKT_RX_BURST_SIZE];

		in_queue = if_iq_bind_to_core[port][cpu];
			
		pkts = odp_pktin_recv(in_queue, pkt_tbl,
				      OFP_PKT_RX_BURST_SIZE);
		if (odp_unlikely(pkts) <= 0)
			continue;

		for (i = 0; i < pkts; i++) {
			odp_packet_t pkt = pkt_tbl[i];
#if 0
			if (odp_unlikely(odp_packet_has_error(pkt))) {
				OFP_DBG("Dropping packet with error");
				odp_packet_free(pkt);
				continue;
			}
#endif	
			ofp_packet_input(pkt, ODP_QUEUE_INVALID, pkt_func);
		}
	}
}

static void *event_dispatcher(void *arg)
{
	odp_event_t ev;
	odp_packet_t pkt;
	odp_queue_t in_queue;
	odp_event_t events[OFP_EVT_RX_BURST_SIZE];
	int event_idx = 0;
	int event_cnt = 0;
	uint64_t loop_cnt = 0;
	//ofp_pkt_processing_func pkt_func = (ofp_pkt_processing_func)arg;
	ofp_pkt_processing_func pkt_func = ofp_eth_vlan_processing;
	odp_bool_t *is_running = NULL;
	//int cpuid = odp_cpu_id();
	//odp_queue_t time_queue_cpu;
	const appl_args_t *appl_params = (appl_args_t *)arg; 

	if (ofp_init_local()) {
		OFP_ERR("ofp_init_local failed");
		return NULL;
	}

	is_running = ofp_get_processing_state();
	if (is_running == NULL) {
		OFP_ERR("ofp_get_processing_state failed");
		ofp_term_local();
		return NULL;
	}

	//time_queue_cpu = ofp_timer_queue_cpu(cpuid);

	/* PER CORE DISPATCHER */
	while (*is_running) {
		if (odp_likely(app_init_params.burst_recv_mode)) {
			direct_recv(appl_params);
		}  else {
			event_cnt = odp_schedule_multi(&in_queue,
						 ODP_SCHED_WAIT,
						 events, OFP_EVT_RX_BURST_SIZE);
			for (event_idx = 0; event_idx < event_cnt; event_idx++) {
				ev = events[event_idx];

				if (ev == ODP_EVENT_INVALID)
					continue;

				if (odp_event_type(ev) == ODP_EVENT_TIMEOUT) {
					ofp_timer_handle(ev);
					continue;
				}

				if (odp_event_type(ev) == ODP_EVENT_PACKET) {
					pkt = odp_packet_from_event(ev);
#if 0
					if (odp_unlikely(odp_packet_has_error(pkt))) {
						OFP_DBG("Dropping packet with error");
						odp_packet_free(pkt);
						continue;
					}
#endif
					ofp_packet_input(pkt, in_queue, pkt_func);
					continue;
				}

				OFP_ERR("Unexpected event type: %u", odp_event_type(ev));

				/* Free events by type */
				if (odp_event_type(ev) == ODP_EVENT_BUFFER) {
					odp_buffer_free(odp_buffer_from_event(ev));
					continue;
				}

				if (odp_event_type(ev) == ODP_EVENT_CRYPTO_COMPL) {
					odp_crypto_compl_free(
						odp_crypto_compl_from_event(ev));
					continue;
				}

			}
		}

		ofp_send_pending_pkt();

		/* per cpu ofp timer schedule */
		/*
		event_cnt = odp_queue_deq_multi(time_queue_cpu,
					events,
					OFP_EVT_RX_BURST_SIZE);
		for (event_idx = 0; event_idx < event_cnt; event_idx++) {
			ev = events[event_idx];
			if (odp_event_type(ev) == ODP_EVENT_TIMEOUT) {
				ofp_timer_handle(ev);
				continue;
			} else {
				OFP_ERR("Unexpected event type: %u",
					odp_event_type(ev));
			}
		}
		*/

		if ((loop_cnt++)%1024) {
			/* dpdk timer schedule */
			rte_timer_manage();
		}
	}

	if (ofp_term_local())
		OFP_ERR("ofp_term_local failed");

	return NULL;
}

static void ofp_pktin_queue_param_init(odp_pktin_queue_param_t *param,
		odp_pktin_mode_t in_mode, uint16_t rx_queues)
{
	odp_queue_param_t *queue_param;

	odp_pktin_queue_param_init(param);

	param->num_queues = rx_queues;
	queue_param = &param->queue_param;
	odp_queue_param_init(queue_param);
	if (in_mode == ODP_PKTIN_MODE_SCHED) {
		queue_param->type = ODP_QUEUE_TYPE_SCHED;
		queue_param->enq_mode = ODP_QUEUE_OP_MT;
		queue_param->deq_mode = ODP_QUEUE_OP_MT;
		queue_param->context = NULL;
		queue_param->sched.prio = ODP_SCHED_PRIO_DEFAULT;
		queue_param->sched.sync = ODP_SCHED_SYNC_ATOMIC;
		queue_param->sched.group = ODP_SCHED_GROUP_ALL;
	} else if (in_mode == ODP_PKTIN_MODE_QUEUE) {
		queue_param->type = ODP_QUEUE_TYPE_PLAIN;
		queue_param->enq_mode = ODP_QUEUE_OP_MT;
		queue_param->deq_mode = ODP_QUEUE_OP_MT;
		queue_param->context = NULL;
	}

	if (in_mode == ODP_PKTIN_MODE_DIRECT) {
		param->op_mode = ODP_PKTIO_OP_MT_UNSAFE;
	}
}


static void ofp_pktout_queue_param_init(
		odp_pktout_queue_param_t *param,
		uint16_t tx_queues)
{
	odp_pktout_queue_param_init(param);

	param->op_mode = ODP_PKTIO_OP_MT;
	param->num_queues = tx_queues;
}


static int create_ifnet_and_bind_queues(odp_instance_t instance,
					appl_args_t *params,
					const odp_cpumask_t *cpumask)
{
	int i;
	unsigned cpu_count = odp_cpumask_count(cpumask);
	
	for (i = 0; i < params->if_count; i++) {
		int cpu;
		int rx_q;
		odp_pktio_param_t pktio_param;
		odp_pktin_queue_param_t pktin_param;
		odp_pktout_queue_param_t pktout_param;
		odp_pktio_t pktio;
		odp_pktio_config_t pktio_config;
		unsigned short port_mask = 0x0;
		unsigned int laddr_mask = 0x0;

		if (i == params->outer_port)
			port_mask = __roundup_pow_of_two(cpu_count) - 1;

		if (i == params->inner_port)
			laddr_mask = 0xffffffff;

		odp_pktio_param_init(&pktio_param);
		pktio_param.in_mode = ODP_PKTIN_MODE_DIRECT;
		pktio_param.out_mode = ODP_PKTOUT_MODE_DIRECT;

		ofp_pktin_queue_param_init(
			&pktin_param,
			pktio_param.in_mode,
			cpu_count);

		ofp_pktout_queue_param_init(&pktout_param, cpu_count);

		/* Configure fdir for FULLNAT local address */
		odp_pktio_config_init(&pktio_config);
		pktio_config.fdir_conf.fdir_mode = RTE_FDIR_MODE_PERFECT;
		pktio_config.fdir_conf.src_ipv4_mask =
			rte_cpu_to_be_32(0x00000000);
		pktio_config.fdir_conf.dst_ipv4_mask =
			rte_cpu_to_be_32(laddr_mask);
		pktio_config.fdir_conf.src_port_mask =
			rte_cpu_to_be_16(0x0000);
		pktio_config.fdir_conf.dst_port_mask =
			rte_cpu_to_be_16(port_mask);

		if (ofp_ifnet_create(instance, params->if_names[i],
				&pktio_param,
				&pktin_param,
				&pktout_param,
				&pktio_config) < 0) {
			OFP_ERR("Failed to init interface %s",
				params->if_names[i]);
			return -1;
		}
		
		pktio = odp_pktio_lookup(params->if_names[i]);
		if (pktio == ODP_PKTIO_INVALID) {
			OFP_ERR("Failed locate pktio %s",
				params->if_names[i]);
			return -1;
		}

		pktin_table[i].num_in_queue = odp_pktin_queue(pktio,
			pktin_table[i].in_queue, OFP_PKTIN_QUEUE_MAX);

		if (pktin_table[i].num_in_queue < 0) {
			OFP_ERR("Failed get input queues for %s",
				params->if_names[i]);
			return -1;	
		}
		
		cpu = odp_cpumask_first(cpumask);	
		if (cpu < 0)
			return -1;

		for (rx_q = 0; rx_q < pktin_table[i].num_in_queue; rx_q++) {
			if (cpu < 0)
				cpu = odp_cpumask_first(cpumask);	

			if_iq_bind_to_core[i][cpu] =
				pktin_table[i].in_queue[rx_q];

			OFP_INFO("if %d rx_q %d bind to cpu %d",
				 i, rx_q, cpu);

			cpu = odp_cpumask_next(cpumask, cpu);
		}
		
	}

	return 0;
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
	int core_count, num_workers;
	odp_cpumask_t cpumask;
	char cpumaskstr[64];
	odph_linux_thr_params_t thr_params;
	odp_instance_t instance;
	struct sigaction signal_action;
	struct rlimit rlp;

	memset(&signal_action, 0, sizeof(signal_action));
	signal_action.sa_handler = signal_handler;
	sigfillset(&signal_action.sa_mask);
	//sigaction(SIGILL,  &signal_action, NULL);
	//sigaction(SIGFPE,  &signal_action, NULL);
	//sigaction(SIGSEGV, &signal_action, NULL);
	sigaction(SIGTERM, &signal_action, NULL);
	sigaction(SIGINT, &signal_action, NULL);
	//sigaction(SIGBUS,  &signal_action, NULL);
	signal(SIGPIPE, SIG_IGN);

	getrlimit(RLIMIT_CORE, &rlp);
	printf("RLIMIT_CORE: %ld/%ld\n", rlp.rlim_cur, rlp.rlim_max);
	rlp.rlim_cur = 200000000;
	printf("Setting to max: %d\n", setrlimit(RLIMIT_CORE, &rlp));

	/* Parse and store the application arguments */
	parse_args(argc, argv, &appl_params);

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &appl_params);

	if (odp_init_global(&instance, NULL, NULL)) {
		OFP_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		OFP_ERR("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	core_count = odp_cpu_count();
	num_workers = core_count;

	if (appl_params.core_count)
		num_workers = appl_params.core_count;
	if (num_workers > MAX_WORKERS)
		num_workers = MAX_WORKERS;

	num_workers = odp_cpumask_default_worker(&cpumask, num_workers);
	odp_cpumask_to_str(&cpumask, cpumaskstr, sizeof(cpumaskstr));

	ofp_vs_num_workers = num_workers;
	odp_cpumask_copy(&ofp_vs_worker_cpumask, &cpumask);

	printf("odp_cpu_count : %i\n", core_count);
	printf("Num worker threads: %i\n", num_workers);
	printf("first CPU:          %i\n", odp_cpumask_first(&cpumask));
	printf("cpu mask:           %s\n", cpumaskstr);

	
	/*
	 * By default core #0 runs Linux kernel background tasks.
	 * Start mapping thread from core #1
	 */
	memset(&app_init_params, 0, sizeof(app_init_params));

	app_init_params.linux_core_id = 0;
	app_init_params.burst_recv_mode = 1;
	app_init_params.pkt_hook[OFP_HOOK_PREROUTING] = ofp_vs_in;
	app_init_params.pkt_hook[OFP_HOOK_FWD_IPv4] = ofp_vs_out;

	
	if (!app_init_params.burst_recv_mode) {
		app_init_params.if_count = appl_params.if_count;
		app_init_params.if_names = appl_params.if_names;
	}

	if (ofp_init_global(instance, &app_init_params)) {
		OFP_ERR("Error: OFP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	if (app_init_params.burst_recv_mode &&
	    create_ifnet_and_bind_queues(instance, &appl_params, &cpumask) != 0) {
		OFP_ERR("create_ifnet_and_bind_queues failed\n");
		exit(EXIT_FAILURE);
	}

	memset(thread_tbl, 0, sizeof(thread_tbl));
	/* Start dataplane dispatcher worker threads */

	//thr_params.start = default_event_dispatcher;
	thr_params.start = event_dispatcher;
	//thr_params.arg = ofp_eth_vlan_processing;
	thr_params.arg = &appl_params; 
	thr_params.thr_type = ODP_THREAD_WORKER;
	thr_params.instance = instance;
	odph_linux_pthread_create(thread_tbl,
				  &cpumask,
				  &thr_params);

	
	ofp_vs_cli_cmd_init();
	
	if (ofp_vs_init(instance, &app_init_params) < 0) {
		ofp_stop_processing();
		OFP_ERR("ofp_vs_init() failed\n");
	}


	/* other app code here.*/
	/* Start CLI */
	ofp_start_cli_thread(instance, app_init_params.linux_core_id,
			appl_params.conf_file);

	rte_timer_subsystem_init();


	odph_linux_pthread_join(thread_tbl, num_workers);
	printf("End Worker\n");

	ofp_vs_finish();
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
		{"outer interface", required_argument, NULL, 'o'},	/* return 'i' */
		{"inter interface", required_argument, NULL, 'p'},	/* return 'i' */
		{"help", no_argument, NULL, 'h'},		/* return 'h' */
		{"configuration file", required_argument,
			NULL, 'f'},/* return 'f' */
		{NULL, 0, NULL, 0}
	};

	memset(appl_args, 0, sizeof(*appl_args));
	appl_params.inner_port = -1;
	appl_params.outer_port = -1;

	while (1) {
		opt = getopt_long(argc, argv, "+c:i:o:p:hf:",
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

		case 'o':
			appl_args->outer_port = atoi(optarg);
			break;

		case 'p':
			appl_args->inner_port = atoi(optarg);
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
		   "Outer port:      %i\n"
		   "Inner port:      %i\n"
		   "\n",
		   odp_version_api_str(), odp_cpu_model_str(),
		   odp_cpu_hz(), odp_sys_cache_line_size(),
		   odp_cpu_count(), appl_args->outer_port,
		   appl_args->inner_port);

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
		   "  -o, Outer interface to set snat fdir rules\n"
		   "  -p, Inner interface to set fnat laddr fdir rules\n"
		   "\n"
		   "Optional OPTIONS\n"
		   "  -c, --count <number> Core count.\n"
		   "  -h, --help           Display help and exit.\n"
		   "\n", NO_PATH(progname), NO_PATH(progname)
		);
}
