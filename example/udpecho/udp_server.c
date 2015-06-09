/*-
 * Copyright (c) 2014 ENEA Software AB
 * Copyright (c) 2014 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#include "ofp.h"

#include "udp_server.h"

#define INVALID_SOCKET  -1
#define SOCKET_ERROR    -1

//#define logprint(a...) do {} while (0)
#define logprint OFP_LOG

static void notify(union ofp_sigval sv)
{
	struct ofp_sock_sigval *ss = sv.sival_ptr;
	int s = ss->sockfd;
	int event = ss->event;
	odp_packet_t pkt = ss->pkt;
	int n;
	struct ofp_sockaddr_in addr;
	ofp_socklen_t addr_len = sizeof(addr);

	/*
	 * Only receive events are accepted.
	 */
	if (event != OFP_EVENT_RECV)
		return;

	/*
	 * L2, L3, and L4 pointers are as they were when the packet was
	 * received. L2 and L3 areas may have ancillary data written
	 * over original headers. Only L4 pointer and data after that is valid.
	 * Note that short packets may have padding. Thus odp_packet_length()
	 * may give wrong results. Sender information is over L2 area.
	 * It is best to use function ofp_udp_packet_parse() to
	 * retrieve the information. It also sets the packet's data pointer
	 * to payload and removes padding from the end.
	 */
	uint8_t *p = ofp_udp_packet_parse(pkt, &n,
					    (struct ofp_sockaddr *)&addr,
					    &addr_len);
	/* Pointer and length are not used here. */
	(void)p;
	(void)n;

	/*
	 * There are two alternatives to send a respond.
	 */
#if 1
	/*
	 * Reuse received packet.
	 * Here we want to send the same payload back prepended with "ECHO:".
	 */
	odp_packet_push_head(pkt, 5);
	memcpy(odp_packet_data(pkt), "ECHO:", 5);
	ofp_udp_pkt_sendto(s, pkt, (struct ofp_sockaddr *)&addr, sizeof(addr));
#else
	/*
	 * Send using usual sendto(). Remember to free the packet.
	 */
	ofp_sendto(s, p, r, 0,
		     (struct ofp_sockaddr *)&addr, sizeof(addr));
	odp_packet_free(pkt);
#endif
	/*
	 * Mark ss->pkt invalid to indicate it was released or reused by us.
	 */
	ss->pkt = ODP_PACKET_INVALID;
}

static void *udpecho(void *arg)
{
	int serv_fd;
	struct ofp_sockaddr_in my_addr;
	uint32_t my_ip_addr;
	ofp_fd_set read_fd;
	(void)arg;

	logprint("UDP server thread started\n");

	odp_init_local();
	ofp_init_local();
	sleep(1);

	my_ip_addr = ofp_port_get_ipv4_addr(0, 0, OFP_PORTCONF_IP_TYPE_IP_ADDR);

	if ((serv_fd = ofp_socket(OFP_AF_INET, OFP_SOCK_DGRAM, OFP_IPPROTO_UDP)) < 0) {
		logprint("Cannot open UDP socket (%s)!\n",
			 ofp_strerror(ofp_errno));
		return NULL;
	}

	memset(&my_addr, 0, sizeof(my_addr));
	my_addr.sin_family = OFP_AF_INET;
	my_addr.sin_port = odp_cpu_to_be_16(2048);
	my_addr.sin_addr.s_addr = my_ip_addr;
	my_addr.sin_len = sizeof(my_addr);

	if (ofp_bind(serv_fd, (struct ofp_sockaddr *)&my_addr,
		       sizeof(struct ofp_sockaddr)) < 0) {
		logprint("Cannot bind http socket (%s)!\n",
			 ofp_strerror(ofp_errno));
		return NULL;
	}

	struct ofp_sigevent ev;
	struct ofp_sock_sigval ss;
	ss.sockfd = serv_fd;
	ss.event = 0;
	ss.pkt = ODP_PACKET_INVALID;
	ev.ofp_sigev_notify = 1;
	ev.ofp_sigev_notify_function = notify;
	ev.ofp_sigev_value.sival_ptr = &ss;
	ofp_socket_sigevent(&ev);

	OFP_FD_ZERO(&read_fd);
	OFP_FD_SET(serv_fd, &read_fd);

	while (1) {
		sleep(1);
	}

	logprint("UDP server exit\n");
	return NULL;
}

void ofp_start_udpserver_thread(int core_id)
{
	odph_linux_pthread_t test_linux_pthread;
	odp_cpumask_t cpumask;

	odp_cpumask_zero(&cpumask);
	odp_cpumask_set(&cpumask, core_id);

	odph_linux_pthread_create(&test_linux_pthread,
				  &cpumask,
				  udpecho,
				  NULL);
}
