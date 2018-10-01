/* Copyright (c) 2017, Nokia
 * Copyright (c) 2017, ENEA Software AB
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <getopt.h>
#include <string.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>

#include "ofp.h"

#include <odp/helper/ip.h>

/** Server bind address */
#define DEF_BIND_ADDR OFP_INADDR_ANY

/** Server bind port */
#define DEF_BIND_PORT 5001

/** Statistics print interval in seconds */
#define DEF_PRINT_INTERVAL 10

/** Server socket backlog */
#define SOCKET_BACKLOG 10

/** Number of worker threads */
#define NUM_WORKERS 2

/** Maximum number of packet in a burst */
#define PKT_BURST_SIZE  16

/** Socket receive buffer length */
#define SOCKET_RX_BUF_LEN	(32 * 1024)

/** Socket transmit buffer length */
#define SOCKET_TX_BUF_LEN	(32 * 1024)

/** Interval to schedule timers */
#define TIMER_SCHED_INT 10

/** Receive call timeout in nanoseconds */
#define RECV_TMO 100

/**
 * Sizes for sorting incoming packets
 */
#define PKT_LEN_XS 128
#define PKT_LEN_S  512
#define PKT_LEN_M  1024
#define PKT_LEN_L  1280
#define PKT_LEN_XL 1518

/**
 * Application modes
 */
typedef enum appl_mode_t {
	MODE_SERVER = 0,
	MODE_CLIENT
} appl_mode_t;

/**
 * Packet counters
 */
typedef struct {
	uint64_t total;
	uint64_t xs;
	uint64_t s;
	uint64_t m;
	uint64_t l;
	uint64_t xl;
} packet_counters_t;

/**
 * Parsed command line application arguments
 */
typedef struct {
	appl_mode_t mode;	/**< Application mode (client/server) */
	char *if_name;		/**< Interface name */
	char *daddr;		/**< Destination IPv4 address */
	uint16_t dport;		/**< Destination port number */
	char *laddr;		/**< Listening IPv4 address */
	uint16_t lport;		/**< Listening port number */
	char *cli_file;		/**< CLI file passed to CLI */
	int single_thread;	/**< Run pktio and application in same thread */
} appl_args_t;

/**
 * Thread specific arguments
 */
typedef struct {
	odp_pktin_queue_t pktin;
} thread_args_t;

/**
 * Grouping of all global data
 */
typedef struct {
	appl_args_t appl;	/**< Application (parsed) arguments */
	/** Thread specific arguments */
	thread_args_t thread[NUM_WORKERS];
	int server_fd;		/**< Socket for incoming client connections */
	int client_fd;		/**< Socket for active client connection */
	uint64_t recv_calls;	/**< Number of recv() function calls */
	uint64_t recv_bytes;	/**< Bytes received */
	uint64_t send_calls;	/**< Number of send() function calls */
	uint64_t send_bytes;	/**< Bytes sent */
	packet_counters_t pkts; /**< Packet size statistics */
	int con_status;		/**< Client connection status */
	ofp_in_addr_t s_addr;   /**< Server address */
} args_t;

/** Global pointer to args */
static args_t *gbl_args;

/** Break workers loop if set to 1 */
static int exit_threads;

/** Global OFP init parms */
ofp_global_param_t app_init_params;

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
				strrchr((file_name), '/') + 1 : (file_name))

/**
 * Signal handler for SIGINT
 */
static void sig_handler(int signo ODP_UNUSED)
{
	exit_threads = 1;
}

/**
 * Update packet size statistics
 */
static inline void update_pkt_stats(odp_packet_t pkt, packet_counters_t *stats)
{
	uint32_t len = odp_packet_len(pkt);

	stats->total++;
	if (len < PKT_LEN_XS)
		stats->xs++;
	else if (len < PKT_LEN_S)
		stats->s++;
	else if (len < PKT_LEN_M)
		stats->m++;
	else if (len < PKT_LEN_L)
		stats->l++;
	else
		stats->xl++;
}

/**
 * Handle timeout events
 */
static inline void handle_timeouts(void)
{
	odp_event_t ev;

	ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT);
	while (ev != ODP_EVENT_INVALID) {
		if (odp_event_type(ev) == ODP_EVENT_TIMEOUT) {
			ofp_timer_handle(ev);
		} else {
			OFP_ERR("Error: unexpected event type: %u\n",
				odp_event_type(ev));
			odp_event_free(ev);
		}
		ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT);
	}
}

/**
 * Wait for incoming client connection
 */
static inline int wait_for_client(int server_fd)
{
	struct ofp_sockaddr_in caller;
	ofp_socklen_t alen = sizeof(caller);
	int fd = -1;

	while (!exit_threads) {
		ofp_fd_set set;
		struct ofp_timeval timeout = {0};
		int ret;

		OFP_FD_ZERO(&set);
		OFP_FD_SET(server_fd, &set);
		ret = ofp_select(server_fd + 1, &set, NULL, NULL, &timeout);
		if (ret == 0) {
			continue;
		} else if (odp_unlikely(ret < 0)) {
			OFP_ERR("Error: ofp_select failed\n");
			return -1;
		}

		fd = ofp_accept(server_fd, (struct ofp_sockaddr *)&caller,
				&alen);
		if (fd < 0) {
			OFP_ERR("Error: ofp_accept failed\n");
			return -1;
		}
		break;
	}
	if (fd >= 0)
		printf("\nClient connected: %s\n\n",
		       ofp_print_ip_addr(caller.sin_addr.s_addr));

	return fd;
}

static inline int rx_burst(odp_pktin_queue_t pktin)
{
	odp_packet_t pkt_tbl[PKT_BURST_SIZE];
	int pkts, i;

	pkts = odp_pktin_recv(pktin, pkt_tbl, PKT_BURST_SIZE);

	for (i = 0; i < pkts; i++) {
		update_pkt_stats(pkt_tbl[i], &gbl_args->pkts);
		ofp_packet_input(pkt_tbl[i], ODP_QUEUE_INVALID,
				 ofp_eth_vlan_processing);
	}

	return pkts;
}

/**
 * Receive packets directly from the NIC and pass them to OFP stack
 */
static int pktio_recv(void *arg)
{
	thread_args_t *thr_args = arg;
	odp_pktin_queue_t pktin = thr_args->pktin;
	int timer_count = 0;

	printf("PKTIO thread starting on CPU: %i\n", odp_cpu_id());

	if (ofp_init_local()) {
		OFP_ERR("Error: ofp_init_local failed\n");
		goto exit;
	}

	while (!exit_threads) {
		int pkts;

		timer_count++;
		if (odp_unlikely(timer_count > TIMER_SCHED_INT)) {
			timer_count = 0;
			handle_timeouts();
		}
		pkts = rx_burst(pktin);
		if (odp_unlikely(pkts < 0)) {
			OFP_ERR("Error: odp_pktin_recv failed\n");
			goto exit;
		}
		if (pkts == PKT_BURST_SIZE) continue;

		/* NOP unless OFP_PKT_TX_BURST_SIZE > 1 */
		ofp_send_pending_pkt();
	}
exit:
	exit_threads = 1;

	if (ofp_term_local())
		OFP_ERR("Error: ofp_term_local failed\n");

	return 0;
}

/**
 * Setup server
 */
static int setup_server(char *laddr, uint16_t lport)
{
	struct ofp_sockaddr_in own_addr;
	int fd;

	fd = ofp_socket(OFP_AF_INET, OFP_SOCK_STREAM, OFP_IPPROTO_TCP);
	if (fd < 0) {
		OFP_ERR("Error: ofp_socket failed\n");
		return -1;
	}

	memset(&own_addr, 0, sizeof(own_addr));
	own_addr.sin_family = OFP_AF_INET;
	own_addr.sin_port = odp_cpu_to_be_16(lport);

	if (laddr == NULL) {
		own_addr.sin_addr.s_addr = DEF_BIND_ADDR;
	} else {
		struct in_addr laddr_lin;

		if (inet_aton(laddr, &laddr_lin) == 0) {
			OFP_ERR("Error: invalid local address: %s", laddr);
			ofp_close(fd);
			return -1;
		}
		own_addr.sin_addr.s_addr = laddr_lin.s_addr;
	}
	own_addr.sin_len = sizeof(own_addr);

	if (ofp_bind(fd, (struct ofp_sockaddr *)&own_addr,
		     sizeof(struct ofp_sockaddr)) < 0) {
		OFP_ERR("Error: ofp_bind failed, err='%s'",
			ofp_strerror(ofp_errno));
		ofp_close(fd);
		return -1;
	}

	if (ofp_listen(fd, SOCKET_BACKLOG)) {
		OFP_ERR("Error: ofp_listen failed, err='%s'",
			ofp_strerror(ofp_errno));
		ofp_close(fd);
		return -1;
	}
	gbl_args->server_fd = fd;

	return 0;
}

/**
 * Run server thread
 */
static int run_server(void *arg ODP_UNUSED)
{
	printf("Server thread starting on CPU: %i\n", odp_cpu_id());

	if (ofp_init_local()) {
		OFP_ERR("Error: OFP local init failed\n");
		exit_threads = 1;
		return -1;
	}

	printf("\nWaiting for client connection...\n");

	gbl_args->client_fd = wait_for_client(gbl_args->server_fd);
	if (exit_threads || gbl_args->client_fd < 0) {
		exit_threads = 1;
		return -1;
	}
	gbl_args->con_status = 1;

	/** In single thread mode this function is used for accepting client
	 *  connections as non-blocking accept is not yet supported in OFP. */
	if (gbl_args->appl.single_thread) {
		if (ofp_term_local())
			OFP_ERR("Error: ofp_term_local failed\n");
		return -1;
	}

	while (!exit_threads) {
		uint8_t pkt_buf[SOCKET_RX_BUF_LEN];
		int ret;

		ret = ofp_recv(gbl_args->client_fd, pkt_buf, SOCKET_RX_BUF_LEN,
			       OFP_MSG_NBIO);
		if (ret < 0 && ofp_errno == OFP_EWOULDBLOCK)
			continue;

		if (ret < 0) {
			OFP_ERR("Error: ofp_recv failed: %d, err=%s\n",
				ofp_errno, ofp_strerror(ofp_errno));
			break;
		}
		if (ret) {
			gbl_args->recv_bytes += ret;
			gbl_args->recv_calls++;
		} else {
			printf("\nClient disconnected\n\n");
			break;
		}
	}
	exit_threads = 1;

	if (ofp_term_local())
		OFP_ERR("Error: ofp_term_local failed\n");

	return 0;
}

/**
 * Run server and pktio in the same thread
 */
static int run_server_single(void *arg)
{
	thread_args_t *thr_args = arg;
	odp_pktin_queue_t pktin = thr_args->pktin;
	uint64_t timer_count = 0;

	if (ofp_init_local()) {
		OFP_ERR("Error: OFP local init failed\n");
		exit_threads = 1;
		return -1;
	}

	while (!exit_threads) {
		uint8_t pkt_buf[SOCKET_RX_BUF_LEN];
		int bytes;
		int pkts;

		timer_count++;
		if (odp_unlikely(timer_count > TIMER_SCHED_INT)) {
			timer_count = 0;
			handle_timeouts();
		}

		pkts = rx_burst(pktin);
		if (odp_unlikely(pkts < 0)) {
			OFP_ERR("Error: odp_pktin_recv failed\n");
			exit_threads = 1;
			return -1;
		if (pkts == PKT_BURST_SIZE) continue;
		}

		/* Server thread takes care of accepting incoming connections */
		if (gbl_args->con_status == 0)
			continue;

		bytes = ofp_recv(gbl_args->client_fd, pkt_buf,
				 SOCKET_RX_BUF_LEN, OFP_MSG_NBIO);
		if (bytes < 0 && ofp_errno == OFP_EWOULDBLOCK)
			continue;

		if (odp_unlikely(bytes < 0)) {
			OFP_ERR("Error: ofp_recv failed: %d, err=%s\n",
				ofp_errno, ofp_strerror(ofp_errno));
			break;
		}
		if (bytes) {
			gbl_args->recv_bytes += bytes;
			gbl_args->recv_calls++;
		} else {
			printf("\nClient disconnected\n\n");
			break;
		}
		/* NOP unless OFP_PKT_TX_BURST_SIZE > 1 */
		ofp_send_pending_pkt();
	}
	exit_threads = 1;

	if (ofp_term_local())
		OFP_ERR("Error: ofp_term_local failed\n");

	return 0;
}

/**
 * Setup client
 */
static int setup_client(char *daddr, uint16_t lport ODP_UNUSED)
{
	int fd;
	struct in_addr laddr_lin;

	fd = ofp_socket(OFP_AF_INET, OFP_SOCK_STREAM, OFP_IPPROTO_TCP);
	if (fd < 0) {
		OFP_ERR("Error: ofp_socket failed\n");
		return -1;
	}

	if (inet_aton(daddr, &laddr_lin) == 0) {
		OFP_ERR("Error: invalid address: %s", daddr);
		return -1;
	}

	gbl_args->client_fd = fd;
	gbl_args->s_addr = laddr_lin.s_addr;

	return 0;
}

/**
 * Run client thread
 */
static int run_client(void *arg ODP_UNUSED)
{
	struct ofp_sockaddr_in addr = {0};
	int ret = -1;
	int retry = 0;

	if (ofp_init_local()) {
		OFP_ERR("Error: OFP local init failed\n");
		exit_threads = 1;
		return -1;
	}

	printf("Client thread starting on CPU: %i\n", odp_cpu_id());

	addr.sin_len = sizeof(struct ofp_sockaddr_in);
	addr.sin_family = OFP_AF_INET;
	addr.sin_port = odp_cpu_to_be_16(gbl_args->appl.lport);
	addr.sin_addr.s_addr = gbl_args->s_addr;

	ret = ofp_connect(gbl_args->client_fd, (struct ofp_sockaddr *)&addr,
		sizeof(addr));

	if ((ret == -1) && (ofp_errno != OFP_EINPROGRESS)) {
		OFP_ERR("Error: Failed to connect (errno = %d)\n", ofp_errno);
		exit_threads = 1;
		return -1;
	}
	sleep(2);

	/* ToFix: ofp_connect() is not blocking as it should, so spin here
	 * until send succeeds. */
	do {
		uint8_t pkt_buf;

		if (retry > 10) {
			OFP_ERR("Error: Failed to connect (errno = %d)\n",
				ofp_errno);
			exit_threads = 1;
			return -1;
		}
		ret = ofp_send(gbl_args->client_fd, &pkt_buf, 1, 0);
		retry++;
		sleep(1);
	} while (ret < 0 && !exit_threads);
	gbl_args->con_status = 1;
	printf("\nConnected to server\n\n");

	while (!exit_threads) {
		uint8_t pkt_buf[SOCKET_TX_BUF_LEN] ODP_ALIGNED_CACHE;

		ret = ofp_send(gbl_args->client_fd, pkt_buf,
			       SOCKET_TX_BUF_LEN, 0);
		if (odp_unlikely(ret < 0)) {
			OFP_ERR("Failed to send (errno = %d)\n", ofp_errno);
			exit_threads = 1;
			break;
		}
		gbl_args->send_bytes += ret;
		gbl_args->send_calls++;

		/* NOP unless OFP_PKT_TX_BURST_SIZE > 1 */
		ofp_send_pending_pkt();
	}
	printf("\nServer disconnected\n\n");

	if (ofp_term_local())
		OFP_ERR("Error: ofp_term_local failed\n");

	return 0;
}

static int run_client_single(void *arg ODP_UNUSED)
{
	struct ofp_sockaddr_in addr = {0};
	int ret = -1;
	int retry = 0;

	thread_args_t *thr_args = arg;
	int timer_count = 0;

	if (ofp_init_local()) {
		OFP_ERR("Error: OFP local init failed\n");
		exit_threads = 1;
		return -1;
	}

	printf("Client thread starting on CPU: %i\n", odp_cpu_id());

	addr.sin_len = sizeof(struct ofp_sockaddr_in);
	addr.sin_family = OFP_AF_INET;
	addr.sin_port = odp_cpu_to_be_16(gbl_args->appl.lport);
	addr.sin_addr.s_addr = gbl_args->s_addr;

	ret = ofp_connect(gbl_args->client_fd, (struct ofp_sockaddr *)&addr,
		sizeof(addr));

	if ((ret == -1) && (ofp_errno != OFP_EINPROGRESS)) {
		OFP_ERR("Error: Failed to connect (errno = %d)\n", ofp_errno);
		exit_threads = 1;
		return -1;
	}
	sleep(2);

	/* ToFix: ofp_connect() is not blocking as it should, so spin here
	 * until send succeeds. */
	do {
		uint8_t pkt_buf;

		rx_burst(thr_args->pktin);
		ofp_send_pending_pkt();

		if (retry > 10) {
			OFP_ERR("Error: Failed to connect (errno = %d)\n",
				ofp_errno);
			exit_threads = 1;
			return -1;
		}
		ret = ofp_send(gbl_args->client_fd, &pkt_buf, 1, 0);
		retry++;
		sleep(1);
	} while (ret < 0 && !exit_threads);
	gbl_args->con_status = 1;
	printf("\nConnected to server\n\n");

	while (!exit_threads) {
		timer_count++;
		if (odp_unlikely(timer_count > TIMER_SCHED_INT)) {
			timer_count = 0;
			handle_timeouts();
		}
		int pkts = rx_burst(thr_args->pktin);
		if (odp_unlikely(pkts < 0)) {
			OFP_ERR("Error: odp_pktin_recv failed\n");
			break;
		}
		if (pkts == PKT_BURST_SIZE) continue;

		uint8_t pkt_buf[SOCKET_TX_BUF_LEN] ODP_ALIGNED_CACHE;

		ret = ofp_send(gbl_args->client_fd, pkt_buf,
			       SOCKET_TX_BUF_LEN, OFP_MSG_NBIO);
		if (ret < 0) {
			if (ofp_errno != OFP_EAGAIN) {
				OFP_ERR("Failed to send (errno = %d)\n", ofp_errno);
				exit_threads = 1;
				ret = 0;
				break;
			}
		} else {
			gbl_args->send_bytes += ret;
			gbl_args->send_calls++;
		}

		/* NOP unless OFP_PKT_TX_BURST_SIZE > 1 */
		ofp_send_pending_pkt();
	}
	printf("\nServer disconnected\n\n");

	if (ofp_term_local())
		OFP_ERR("Error: ofp_term_local failed\n");

	return 0;
}

/**
 * Get pktio device capability
 */
static int pktio_capability(const char *name, odp_pktio_capability_t *capa)
{
	odp_pktio_t pktio;
	odp_pool_t pool;
	odp_pool_param_t params;
	int ret;

	odp_pool_param_init(&params);
	params.pkt.seg_len = 1518;
	params.pkt.len     = 1518;
	params.pkt.num     = 32;
	params.type        = ODP_POOL_PACKET;

	pool = odp_pool_create("dummy packet pool", &params);
	if (pool == ODP_POOL_INVALID) {
		OFP_ERR("Error: packet pool create failed\n");
		return -1;
	}

	pktio = odp_pktio_open(name, pool, NULL);
	if (pktio == ODP_PKTIO_INVALID) {
		OFP_ERR("Error: failed to open %s\n", name);
		odp_pool_destroy(pool);
		return -1;
	}

	ret =  odp_pktio_capability(pktio, capa);

	odp_pktio_close(pktio);
	odp_pool_destroy(pool);

	return ret;
}

/**
 * printing verbose statistics
 *
 */
static void print_global_stats(void)
{
	uint64_t rx_calls, rx_calls_prev = 0, rx_cps, rx_maximum_cps = 0;
	uint64_t rx_bits, rx_bits_prev = 0, rx_bps, rx_maximum_bps = 0;
	uint64_t tx_calls, tx_calls_prev = 0, tx_cps, tx_maximum_cps = 0;
	uint64_t tx_bits, tx_bits_prev = 0, tx_bps, tx_maximum_bps = 0;
	odp_time_t ts_prev;

	ts_prev = odp_time_local();

	while (!exit_threads) {
		odp_time_t ts;
		odp_time_t span;
		uint64_t time_sec;

		sleep(DEF_PRINT_INTERVAL);
		if (gbl_args->con_status == 0)
			continue;
		if (exit_threads)
			break;

		rx_calls = gbl_args->recv_calls;
		rx_bits = gbl_args->recv_bytes * 8;
		tx_calls = gbl_args->send_calls;
		tx_bits = gbl_args->send_bytes * 8;
		ts = odp_time_local();

		span = odp_time_diff(ts, ts_prev);

		time_sec = odp_time_to_ns(span) / ODP_TIME_SEC_IN_NS;
		if (time_sec == 0)
			continue;

		rx_cps = (rx_calls - rx_calls_prev) / time_sec;
		if (rx_cps > rx_maximum_cps)
			rx_maximum_cps = rx_cps;

		rx_bps = (rx_bits - rx_bits_prev) / time_sec;
		if (rx_bps > rx_maximum_bps)
			rx_maximum_bps = rx_bps;

		tx_cps = (tx_calls - tx_calls_prev) / time_sec;
		if (tx_cps > tx_maximum_cps)
			tx_maximum_cps = tx_cps;

		tx_bps = (tx_bits - tx_bits_prev) / time_sec;
		if (tx_bps > tx_maximum_bps)
			tx_maximum_bps = tx_bps;
		if (gbl_args->appl.mode == MODE_SERVER)
			printf("RX %.2f Gbps (max %.2f), %" PRIu64 " "
			       "recv() calls per sec (max %" PRIu64 ")\n",
			       (double)rx_bps / 1000000000,
			       (double)rx_maximum_bps / 1000000000, rx_cps,
			       rx_maximum_cps);
		else
			printf("TX %.2f Gbps (max %.2f), %" PRIu64 " "
			       "send() calls per sec (max %" PRIu64 ")\n",
			       (double)tx_bps / 1000000000,
			       (double)tx_maximum_bps / 1000000000, tx_cps,
			       tx_maximum_cps);

		ts_prev = ts;
		rx_calls_prev = rx_calls;
		rx_bits_prev = rx_bits;
		tx_calls_prev = tx_calls;
		tx_bits_prev = tx_bits;
	}

	if (gbl_args->appl.mode == MODE_CLIENT) {
		if (gbl_args->send_calls == 0)
			return;

		printf("\nTotal TX %.2f GBytes, number of send() calls "
		       "%" PRIu64 ", avg bytes per call %.1f\n\n",
		       (double)(gbl_args->send_bytes) / 1000000000,
		       gbl_args->send_calls,
		       (double)gbl_args->send_bytes / gbl_args->send_calls);
	} else {
		if (gbl_args->recv_calls == 0)
			return;

		printf("\nTotal RX %.2f GBytes, number of recv() calls "
		       "%" PRIu64 ", avg bytes per call %.1f\n\n",
		       (double)(gbl_args->recv_bytes) / 1000000000,
		       gbl_args->recv_calls,
		       (double)gbl_args->recv_bytes / gbl_args->recv_calls);

		printf("Total packets: %" PRIu64 "\n"
		       "Per size:\n"
		       "     0-%4d: %" PRIu64 "\n"
		       "  %4d-%4d: %" PRIu64 "\n"
		       "  %4d-%4d: %" PRIu64 "\n"
		       "  %4d-%4d: %" PRIu64 "\n"
		       "  %4d- MTU: %" PRIu64 "\n\n",
		       gbl_args->pkts.total,
		       PKT_LEN_XS, gbl_args->pkts.xs,
		       PKT_LEN_XS, PKT_LEN_S, gbl_args->pkts.s,
		       PKT_LEN_S, PKT_LEN_M, gbl_args->pkts.m,
		       PKT_LEN_M, PKT_LEN_L, gbl_args->pkts.l,
		       PKT_LEN_L, gbl_args->pkts.xl);
	}
}

/**
 * Prinf usage information
 */
static void usage(char *progname)
{
	printf("\n"
	       "Usage: %s OPTIONS\n"
	       "  E.g. HOST1: %s -i eth0 -f ofp.cli\n"
	       "       HOST2: iperf -c 10.10.10.1\n"
	       "\n"
	       "Mandatory OPTIONS:\n"
	       "  -i, --interface <if>  Eth interface\n"
	       "Optional OPTIONS:\n"
	       "  -s, --server          Run in server mode (default)\n"
	       "  -c, --client <host>   Run in client mode connecting to IPv4 host (experimental)\n"
	       "  -t, --single-thread   0: Run pktio and server code in separate threads\n"
	       "                        1: Run pktio and server code in the same thread (default)\n"
	       "  -l, --laddr <addr>    IPv4 address were server binds\n"
	       "                            Default: %s\n"
	       "  -p, --port <port>    Port address\n"
	       "                            Default: %d\n"
	       "  -f, --cli-file <file> OFP CLI file\n"
	       "  -h, --help            Display help and exit\n"
	       "\n", NO_PATH(progname), NO_PATH(progname),
	       ofp_print_ip_addr(DEF_BIND_ADDR), DEF_BIND_PORT);
}

/**
 * Parse and store the command line arguments
 *
 * @param argc       argument count
 * @param argv[]     argument vector
 * @param appl_args  Store application arguments here
 */
static void parse_args(int argc, char *argv[], appl_args_t *args)
{
	int opt;
	int long_index;
	size_t len;
	static struct option longopts[] = {
		{"client", required_argument, NULL, 'c'},
		{"cli-file", required_argument, NULL, 'f'},
		{"help", no_argument, NULL, 'h'},
		{"interface", required_argument, NULL, 'i'},
		{"laddr", required_argument, NULL, 'l'},
		{"port", required_argument, NULL, 'p'},
		{"server", no_argument, NULL, 's'},
		{"single-thread", required_argument, NULL, 't'},
		{NULL, 0, NULL, 0}
	};

	memset(args, 0, sizeof(appl_args_t));

	args->lport = DEF_BIND_PORT;
	args->single_thread = 1;

	while (1) {
		opt = getopt_long(argc, argv, "+c:f:hi:l:p:st:",
				  longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'c':
			args->mode = MODE_CLIENT;
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1;	/* add room for '\0' */

			args->daddr = malloc(len);
			if (args->daddr == NULL) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			strcpy(args->daddr, optarg);
			break;
		case 'f':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1;	/* add room for '\0' */

			args->cli_file = malloc(len);
			if (args->cli_file == NULL) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			strcpy(args->cli_file, optarg);
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;
		case 'i':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1;	/* add room for '\0' */

			args->if_name = malloc(len);
			if (args->if_name == NULL) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			strcpy(args->if_name, optarg);
			break;
		case 'l':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1;	/* add room for '\0' */

			args->laddr = malloc(len);
			if (args->laddr == NULL) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			strcpy(args->laddr, optarg);
			break;
		case 'p':
			args->lport = (uint16_t)atoi(optarg);
			break;
		case 's':
			args->mode = MODE_SERVER;
			break;
		case 't':
			args->single_thread = atoi(optarg);
			break;
		default:
			break;
		}
	}

	if (args->if_name == NULL ||
	    (args->mode == MODE_CLIENT && args->daddr == 0)) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	optind = 1; /* reset 'extern optind' from the getopt lib */
}

/**
 * Print system and application info
 */
static void print_info(char *progname, appl_args_t *appl_args)
{
	printf("\n"
	       "ODP system info\n"
	       "---------------\n"
	       "ODP API version: %s\n"
	       "CPU model:       %s\n"
	       "CPU freq (hz):   %" PRIu64 "\n"
	       "Cache line size: %i\n"
	       "Core count:      %i\n"
	       "\n",
	       odp_version_api_str(), odp_cpu_model_str(), odp_cpu_hz(),
	       odp_sys_cache_line_size(), odp_cpu_count());

	printf("Running ODP appl: \"%s\"\n"
	       "-----------------\n"
	       "Using IF:        %s\n"
	       "Dst IP:          %s\n"
	       "Bind IP:         %s\n"
	       "Port:            %d\n",
	       progname, appl_args->if_name, appl_args->daddr,
	       appl_args->laddr, appl_args->lport);
	fflush(NULL);
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
	odph_odpthread_t thread_tbl[NUM_WORKERS];
	odp_shm_t shm;
	int num_workers, next_worker;
	odp_cpumask_t cpu_mask;
	thread_args_t thr_args;
	odp_pktio_param_t pktio_param;
	odp_pktin_queue_param_t pktin_param;
	odp_pktout_queue_param_t pktout_param;
	odph_odpthread_params_t thr_params;
	odp_instance_t instance;
	odp_pktio_t pktio;
	odp_pktio_capability_t capa;
	odp_pktin_queue_t pktin;
	int num_output_q;

	if (odp_init_global(&instance, NULL, NULL)) {
		OFP_ERR("Error: ODP global init failed\n");
		exit(EXIT_FAILURE);
	}
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		OFP_ERR("Error: ODP local init failed\n");
		exit(EXIT_FAILURE);
	}

	/* Reserve shared memory */
	shm = odp_shm_reserve("shm", sizeof(args_t), ODP_CACHE_LINE_SIZE, 0);
	gbl_args = odp_shm_addr(shm);

	if (gbl_args == NULL) {
		OFP_ERR("Error: shared mem alloc failed\n");
		exit(EXIT_FAILURE);
	}
	memset(gbl_args, 0, sizeof(args_t));
	gbl_args->client_fd = -1;
	gbl_args->server_fd = -1;

	/* Parse and store the application arguments */
	parse_args(argc, argv, &gbl_args->appl);

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &gbl_args->appl);

	signal(SIGINT, sig_handler);

	/*
	 * By default core #0 runs Linux kernel background tasks. Start mapping
	 * worker threads from core #1. Core #0 requires its own TX queue.
	 */
	next_worker = 1;
	num_workers = (gbl_args->appl.single_thread) ? 1 : 2;
	if ((odp_cpu_count() - 1) < num_workers) {
		OFP_ERR("ERROR: At least %d cores required\n", num_workers + 1);
		exit(EXIT_FAILURE);
	}

	printf("Worker threads:  %i\n", num_workers);
	printf("First worker:    %i\n\n", next_worker);

	ofp_init_global_param(&app_init_params);

	if (ofp_init_global(instance, &app_init_params)) {
		OFP_ERR("Error: OFP global init failed\n");
		exit(EXIT_FAILURE);
	}
	if (ofp_init_local()) {
		OFP_ERR("Error: OFP local init failed\n");
		exit(EXIT_FAILURE);
	}

	/* Get pktio capability */
	if (pktio_capability(gbl_args->appl.if_name, &capa)) {
		OFP_ERR("Error: failed to fetch pktio capability\n");
		exit(EXIT_FAILURE);
	}

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_DIRECT;
	pktio_param.out_mode = ODP_PKTOUT_MODE_DIRECT;

	odp_pktin_queue_param_init(&pktin_param);
	pktin_param.op_mode = ODP_PKTIO_OP_MT_UNSAFE;
	pktin_param.num_queues = 1;

	odp_pktout_queue_param_init(&pktout_param);
	if (capa.max_output_queues > 1) {
		pktout_param.op_mode    = ODP_PKTIO_OP_MT_UNSAFE;
		num_output_q = 2;
	} else {
		pktout_param.op_mode    = ODP_PKTIO_OP_MT;
		num_output_q = 1;
	}
	pktout_param.num_queues = num_output_q;

	memset(&thr_args, 0, sizeof(thread_args_t));

	if (ofp_ifnet_create(instance, gbl_args->appl.if_name,
			     &pktio_param, &pktin_param, &pktout_param) < 0) {
		OFP_ERR("Error: failed to init interface %s",
			gbl_args->appl.if_name);
		exit(EXIT_FAILURE);
	}

	pktio = odp_pktio_lookup(gbl_args->appl.if_name);
	if (pktio == ODP_PKTIO_INVALID) {
		OFP_ERR("Error: failed locate pktio %s",
			gbl_args->appl.if_name);
		exit(EXIT_FAILURE);
	}

	if (odp_pktin_queue(pktio, &pktin, 1) != 1) {
		OFP_ERR("Error: too few pktin queues for %s",
			gbl_args->appl.if_name);
		exit(EXIT_FAILURE);
	}

	if (odp_pktout_queue(pktio, NULL, 0) != num_output_q) {
		OFP_ERR("Error: too few pktout queues for %s",
			gbl_args->appl.if_name);
		exit(EXIT_FAILURE);
	}

	thr_args.pktin = pktin;

	/* Start CLI */
	ofp_start_cli_thread(instance, app_init_params.linux_core_id,
			     gbl_args->appl.cli_file);

	/** Wait for the stack to create the FP interface. Otherwise ofp_bind()
	 *  call will fail.
	 */
	sleep(2);

	memset(thread_tbl, 0, sizeof(thread_tbl));

	if (gbl_args->appl.mode == MODE_SERVER) {
		if (setup_server(gbl_args->appl.laddr, gbl_args->appl.lport)) {
			OFP_ERR("Error: failed to setup server\n");
			exit(EXIT_FAILURE);
		}
	} else {
		if (setup_client(gbl_args->appl.daddr, gbl_args->appl.dport)) {
			OFP_ERR("Error: failed to setup client\n");
			exit(EXIT_FAILURE);
		}
	}

	/*
	 * We don't need a second thread iff we are a single thread
	 * client.
	 */
	if (!(gbl_args->appl.single_thread == 1 && gbl_args->appl.mode == MODE_CLIENT)) {
		thr_params.start = pktio_recv;
		/*
		 * If single thread server, then we need a separate
		 * run_server thread to call blocking ofp_accept().
		 */
		if (gbl_args->appl.single_thread == 1 && gbl_args->appl.mode == MODE_SERVER)
			thr_params.start = run_server;
		thr_params.arg = &thr_args;
		thr_params.thr_type = ODP_THREAD_WORKER;
		thr_params.instance = instance;
		odp_cpumask_zero(&cpu_mask);
		odp_cpumask_set(&cpu_mask, next_worker);
		odph_odpthreads_create(&thread_tbl[0], &cpu_mask, &thr_params);
		next_worker++;
	}

	/* Create server/client thread */
	if (gbl_args->appl.single_thread) {
		thr_params.start = (gbl_args->appl.mode == MODE_SERVER) ?
			run_server_single : run_client_single;
	} else {
		thr_params.start = (gbl_args->appl.mode == MODE_SERVER) ?
			run_server : run_client;
	}
	thr_params.arg = &thr_args;
	thr_params.thr_type = ODP_THREAD_WORKER;
	thr_params.instance = instance;
	odp_cpumask_zero(&cpu_mask);
	odp_cpumask_set(&cpu_mask, next_worker);
	odph_odpthreads_create(&thread_tbl[next_worker-1], &cpu_mask, &thr_params);

	print_global_stats();

	odph_odpthreads_join(thread_tbl);

	if (gbl_args->client_fd >= 0)
		ofp_close(gbl_args->client_fd);
	if (gbl_args->server_fd >= 0)
		ofp_close(gbl_args->server_fd);

	free(gbl_args->appl.if_name);
	if (gbl_args->appl.cli_file)
		free(gbl_args->appl.cli_file);
	if (gbl_args->appl.daddr)
		free(gbl_args->appl.daddr);
	if (gbl_args->appl.laddr)
		free(gbl_args->appl.laddr);

	if (ofp_term_local() < 0)
		printf("Error: ofp_term_local failed\n");

	if (ofp_term_global() < 0)
		printf("Error: ofp_term_global failed\n");

	if (odp_shm_free(shm))
		printf("Error: odp_shm_free failed\n");

	if (odp_term_local())
		printf("Error: odp_term_local failed\n");

	if (odp_term_global(instance))
		printf("Error: odp_term_global failed\n");

	return 0;
}
