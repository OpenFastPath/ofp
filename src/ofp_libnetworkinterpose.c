/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#ifndef RTLD_NEXT
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "ofp.h"
#include "ofpi_odp_compat.h"

static int (*libc_socket)(int, int, int);
static int (*libc_bind)(int, const struct sockaddr*, socklen_t);
static int (*libc_accept)(int, struct sockaddr*, socklen_t*);
static int (*libc_connect)(int, const struct sockaddr*, socklen_t);
static int (*libc_listen)(int, int);
static int (*libc_shutdown)(int, int);
static int (*libc_close)(int);
static int (*libc_setsockopt)(int, int, int, const void*, socklen_t);
static ssize_t (*libc_read)(int, void*, size_t);
static ssize_t (*libc_recv)(int, void*, size_t, int);
static ssize_t (*libc_write)(int, void*, size_t);
static ssize_t (*libc_send)(int, const void*, size_t, int);

int socket(int domain, int type, int protocol);
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int listen(int sockfd, int backlog);
int shutdown(int sockfd, int how);
int close(int sockfd);
int setsockopt(int sockfd, int level, int opt_name,
	const void *opt_val, socklen_t opt_len);
ssize_t read(int sockfd, void *buf, size_t len);
ssize_t recv(int sockfd, void *buf, size_t len, int flags);
ssize_t write(int sockfd, void *buf, size_t len);
ssize_t send(int sockfd, const void *buf, size_t len, int flags);

static int ofp_libc_init(void)
{
#define LIBC_FUNCTION(func) \
	libc_##func = dlsym(RTLD_NEXT, #func);\
	if(dlerror()) { \
		errno = EACCES; \
		return EXIT_FAILURE; \
	}

	LIBC_FUNCTION(socket);
	LIBC_FUNCTION(bind);
	LIBC_FUNCTION(accept);
	LIBC_FUNCTION(connect);
	LIBC_FUNCTION(listen);
	LIBC_FUNCTION(shutdown);
	LIBC_FUNCTION(close);
	LIBC_FUNCTION(setsockopt);
	LIBC_FUNCTION(read);
	LIBC_FUNCTION(recv);
	LIBC_FUNCTION(write);
	LIBC_FUNCTION(send);

	return EXIT_SUCCESS;
}


static void ofp_ifconfig(void)
{
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_in *sa;
	int port = 0;

	getifaddrs(&ifap);
	for (ifa = ifap; ifa; ifa = ifa->ifa_next)
		if (ifa->ifa_addr->sa_family == AF_INET) {
			sa = (struct sockaddr_in *) ifa->ifa_addr;
			OFP_DBG("Interface: %s\tAddress: %x\n",
				ifa->ifa_name, sa->sin_addr.s_addr);

			ofp_ifnet_create(ifa->ifa_name , ODP_PKTIN_MODE_SCHED);
			ofp_config_interface_up_v4(port++, 0, 0,
				 sa->sin_addr.s_addr, 24);
		}

	freeifaddrs(ifap);
	return;
}

static int ofp_lib_start(void)
{
	ofp_init_global_t app_init_params;

	odph_linux_pthread_t thread_tbl[32];
	int ret_val, num_workers = 1;
	odp_cpumask_t cpumask;
	char cpumaskstr[64];

	/*
	 * Before any ODP API functions can be called, we must first init the ODP
	 * globals, e.g. availale accelerators or software implementations for
	 * shared memory, threads, pool, qeueus, sheduler, pktio, timer, crypto
	 * and classification.
	 */
	if (odp_init_global(NULL, NULL)) {
		OFP_ERR("ODP global init failed.");
		return EXIT_FAILURE;
	}

	/*
	 * When the gloabel ODP level init has been done, we can now issue a
	 * local init per thread. This must also be done before any other ODP API
	 * calls may be made. Local inits are made here for shared memory,
	 * threads, pktio and scheduler.
	 */
	if (odp_init_local(ODP_THREAD_CONTROL) != 0) {
		OFP_ERR("ODP local init failed.");
		odp_term_global();
		return EXIT_FAILURE;
	}

	/*
	 * Initializes cpumask with CPUs available for worker threads.
	 * Sets up to 'num' CPUs and returns the count actually set.
	 * Use zero for all available CPUs.
	 */
	num_workers = odp_cpumask_default_worker(&cpumask, num_workers);
	if (odp_cpumask_to_str(&cpumask, cpumaskstr, sizeof(cpumaskstr)) < 0) {
		OFP_ERR("Error: Too small buffer provided to "
			"odp_cpumask_to_str");
		odp_term_local();
		odp_term_global();
		return EXIT_FAILURE;
	}

	printf("Num worker threads: %i\n", num_workers);
	printf("first CPU: %i\n", odp_cpumask_first(&cpumask));
	printf("cpu mask:  %s\n", cpumaskstr);

	/*
	 * Now that ODP has been initalized, we can initialize OFP. This will
	 * open a pktio instance for each interface supplied as argument by the
	 * user.
	 *
	 * General configuration will be to pktio and schedluer queues here in
	 * addition will fast path interface configuration.
	 */
	memset(&app_init_params, 0, sizeof(app_init_params));
	if (ofp_init_global(&app_init_params) != 0) {
		OFP_ERR("OFP global init failed.");
		ofp_term_global();
		odp_term_local();
		odp_term_global();
		return EXIT_FAILURE;
	}

	if (ofp_init_local() != 0) {
		OFP_ERR("Error: OFP local init failed.");
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
			ODP_THREAD_CONTROL);

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

	ofp_ifconfig();

	return EXIT_SUCCESS;
}


int socket(int domain, int type, int protocol)
{
	int sockfd = -1, ret_val;
	static int init_socket = 0;

	if (odp_unlikely(init_socket == 0)) {
		ret_val = ofp_libc_init();
		if (ret_val == EXIT_FAILURE)
			return sockfd;

		init_socket = 1;

		ret_val = ofp_lib_start();
		if (ret_val == EXIT_SUCCESS)
			init_socket = 2;
		else
			init_socket = 3;
	}

	if (odp_unlikely(domain != AF_INET || init_socket != 2))
		sockfd = (*libc_socket)(domain, type, protocol);
	else
		sockfd = ofp_socket(domain, type, protocol);

	OFP_DBG("Created socket '%d' with domain:%d, type:%d, protocol:%d.",
		sockfd, domain, type, protocol);

	return sockfd;
}


int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	int bind_value = -1;

	if (sockfd < OFP_SOCK_NUM_OFFSET) {
		bind_value = (*libc_bind)(sockfd, addr, addrlen);
	} else if (addr->sa_family == AF_INET) {
		struct ofp_sockaddr_in ofp_addr;

		bzero((char *) &ofp_addr, sizeof(ofp_addr));
		ofp_addr.sin_family = AF_INET;
		ofp_addr.sin_addr.s_addr =
			((const struct sockaddr_in *)addr)->sin_addr.s_addr;
		ofp_addr.sin_port =
			((const struct sockaddr_in *)addr)->sin_port;
		ofp_addr.sin_len = sizeof(struct ofp_sockaddr_in);

		bind_value = ofp_bind(sockfd,
				(const struct ofp_sockaddr *)&ofp_addr,
				addrlen);
	}

	OFP_DBG("Binding socket '%d' to the address '%x:%d' returns:%d",
		sockfd,	((const struct sockaddr_in *)addr)->sin_addr.s_addr,
		ntohs(((const struct sockaddr_in *)addr)->sin_port),
		bind_value);

	return bind_value;
}


int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	int accept_value = -1;

	if (sockfd < OFP_SOCK_NUM_OFFSET)
		accept_value = (*libc_accept)(sockfd, addr, addrlen);
	else
		accept_value = ofp_accept(sockfd,
			(struct ofp_sockaddr *)addr, addrlen);

	OFP_DBG("Accepting socket '%d' to the address '%x:%d' returns:'%d'",
		sockfd, ((struct sockaddr_in *)addr)->sin_addr.s_addr,
		ntohs(((struct sockaddr_in *)addr)->sin_port), accept_value);

	return accept_value;
}



int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	int connect_value;

	if (sockfd < OFP_SOCK_NUM_OFFSET)
		connect_value = (*libc_connect)(sockfd, addr, addrlen);
	else
		connect_value = ofp_connect(sockfd,
			(const struct ofp_sockaddr *)addr,
			addrlen);

	OFP_DBG("Connecting socket '%d' to the address '%x:%d' returns:'%d'",
		sockfd, ((const struct sockaddr_in *)addr)->sin_addr.s_addr,
		ntohs(((const struct sockaddr_in *)addr)->sin_port),
		connect_value);

	return connect_value;
}


int listen(int sockfd, int backlog)
{
	int listen_value;

	if (sockfd < OFP_SOCK_NUM_OFFSET)
		listen_value = (*libc_listen)(sockfd, backlog);
	else
		listen_value = ofp_listen(sockfd, backlog);

	OFP_DBG("Listen called on socket '%d' returns:'%d'",
		sockfd, listen_value);

	return listen_value;
}



int shutdown(int sockfd, int how)
{
	int shutdown_value;

	if (sockfd < OFP_SOCK_NUM_OFFSET)
		shutdown_value = (*libc_shutdown)(sockfd, how);
	else
		shutdown_value = ofp_shutdown(sockfd, how);

	OFP_DBG("Socket '%d' shutdown with option '%d' returns:'%d'",
		sockfd, how, shutdown_value);

	return shutdown_value;
}

int close(int sockfd)
{
	int close_value;

	if (sockfd < OFP_SOCK_NUM_OFFSET) {
		if (libc_close == NULL)
			ofp_libc_init();
		close_value = (*libc_close)(sockfd);
	} else
		close_value = ofp_close(sockfd);

	OFP_DBG("Socket '%d' closed returns:'%d'",
		sockfd, close_value);

	return close_value;
}


int setsockopt(int sockfd, int level, int opt_name, const void *opt_val,
	socklen_t opt_len)
{
	int setsockopt_value;

	if (sockfd < OFP_SOCK_NUM_OFFSET)
		setsockopt_value = (*libc_setsockopt)(sockfd, level, opt_name,
			opt_val, opt_len);
	else
		setsockopt_value = ofp_setsockopt(sockfd, level, opt_name,
			opt_val, opt_len);

	OFP_DBG("Setsockopt on sock:'%d',level:'%d',opt_name:'%d'",
		sockfd, level, opt_name);

	return setsockopt_value;
}


ssize_t read(int sockfd, void *buf, size_t len)
{
	ssize_t read_value;

	if (sockfd < OFP_SOCK_NUM_OFFSET) {
		if (libc_read == NULL)
			ofp_libc_init();

		read_value = (*libc_read)(sockfd, buf, len);
	} else
		read_value = ofp_recv(sockfd, buf, len, 0);

	OFP_DBG("Read called on socket '%d'", sockfd);

	return read_value;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
	ssize_t recv_value;

	if (sockfd < OFP_SOCK_NUM_OFFSET)
		recv_value = (*libc_recv)(sockfd, buf, len, flags);
	else
		recv_value = ofp_recv(sockfd, buf, len, flags);

	OFP_DBG("Recv called on socket '%d'", sockfd);

	return recv_value;
}


ssize_t write(int sockfd, void *buf, size_t len)
{
	ssize_t write_value;

	if (sockfd < OFP_SOCK_NUM_OFFSET) {
		if (libc_write == NULL)
			ofp_libc_init();

		write_value = (*libc_write)(sockfd, buf, len);
	} else
		write_value = ofp_send(sockfd, buf, len, 0);

	OFP_DBG("Write called on socket '%d'", sockfd);

	return write_value;
}


ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
	ssize_t send_value;

	if (sockfd < OFP_SOCK_NUM_OFFSET)
		send_value = (*libc_send)(sockfd, buf, len, flags);
	else
		send_value = ofp_send(sockfd, buf, len, flags);

	OFP_DBG("Send called on socket '%d'", sockfd);

	return send_value;
}
