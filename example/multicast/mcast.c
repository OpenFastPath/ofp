#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#include "ofp.h"

#include "mcast.h"

#define logprint(a...) do {} while (0)
//#define logprint OFP_LOG

#define IP4(a, b, c, d) (a|(b<<8)|(c<<16)|(d<<24))

static uint32_t myaddr;

static void *mcasttest(void *arg)
{
	int fd;
	struct ofp_sockaddr_in my_addr;
	struct ofp_ip_mreq mreq;
	(void)arg;

	logprint("Multicast thread started\n");

	if (odp_init_local(ODP_THREAD_CONTROL)) {
		OFP_ERR("Error: ODP local init failed.\n");
		return NULL;
	}
	if (ofp_init_local()) {
		OFP_ERR("Error: OFP local init failed.\n");
		return NULL;
	}
	sleep(1);

	while (myaddr == 0) {
		myaddr = ofp_port_get_ipv4_addr(0, 0, OFP_PORTCONF_IP_TYPE_IP_ADDR);
		sleep(1);
	}

	if ((fd = ofp_socket(OFP_AF_INET, OFP_SOCK_DGRAM, OFP_IPPROTO_UDP)) < 0) {
		perror("socket");
		logprint("Cannot open socket!\n");
		return NULL;
	}

	memset(&my_addr, 0, sizeof(my_addr));
	my_addr.sin_family = OFP_AF_INET;
	my_addr.sin_port = odp_cpu_to_be_16(2048);
	my_addr.sin_addr.s_addr = 0;
	my_addr.sin_len = sizeof(my_addr);

	if (ofp_bind(fd, (struct ofp_sockaddr *)&my_addr,
		       sizeof(struct ofp_sockaddr)) < 0) {
		logprint("Cannot bind socket (%s)!\n", ofp_strerror(ofp_errno));
		return NULL;
	}

	memset(&mreq, 0, sizeof(mreq));
        mreq.imr_multiaddr.s_addr = IP4(234,5,5,5);
        mreq.imr_interface.s_addr = myaddr;
        if (ofp_setsockopt(fd, OFP_IPPROTO_IP, OFP_IP_ADD_MEMBERSHIP,
			   &mreq, sizeof(mreq)) == -1) {
		perror("setsockopt");
        }

	memset(&mreq, 0, sizeof(mreq));
        mreq.imr_multiaddr.s_addr = IP4(234,7,7,7);
        mreq.imr_interface.s_addr = myaddr;
        if (ofp_setsockopt(fd, OFP_IPPROTO_IP, OFP_IP_ADD_MEMBERSHIP,
			   &mreq, sizeof(mreq)) == -1) {
		perror("setsockopt");
        }

	for (;;) {
		char buf[100];
		int len = sizeof(buf);
		struct ofp_sockaddr_in addr = {0};
		ofp_socklen_t addr_len = 0;

		len = ofp_recvfrom(fd, buf, len, 0,
				   (struct ofp_sockaddr *)&addr, &addr_len);
		if (len == -1) {
			OFP_ERR("Faild to rcv data(errno = %d)\n", ofp_errno);
			continue;
		}

		buf[len] = 0;
		OFP_INFO("Data (%s, len = %d) was received.\n", buf, len);

		if (addr_len != sizeof(addr)) {
			OFP_ERR("Faild to rcv source address: %d (errno = %d)\n",
				addr_len, ofp_errno);
			continue;
		}

		if (strstr(buf, "add")) {
			OFP_INFO("Add membership to 234.7.7.7\n");
			memset(&mreq, 0, sizeof(mreq));
			mreq.imr_multiaddr.s_addr = IP4(234,7,7,7);
			mreq.imr_interface.s_addr = myaddr;
			if (ofp_setsockopt(fd, OFP_IPPROTO_IP, OFP_IP_ADD_MEMBERSHIP,
					   &mreq, sizeof(mreq)) == -1) {
				perror("setsockopt");
			}
		} else if (strstr(buf, "drop")) {
			OFP_INFO("Drop membership from 234.7.7.7\n");
			memset(&mreq, 0, sizeof(mreq));
			mreq.imr_multiaddr.s_addr = IP4(234,7,7,7);
			mreq.imr_interface.s_addr = myaddr;
			if (ofp_setsockopt(fd, OFP_IPPROTO_IP, OFP_IP_DROP_MEMBERSHIP,
					   &mreq, sizeof(mreq)) == -1) {
				perror("setsockopt");
			}
		} else if (strstr(buf, "quit")) {
			exit(0);
		}

		OFP_INFO("Data was received from address 0x%x, port = %d.\n",
			 odp_be_to_cpu_32(addr.sin_addr.s_addr),
			 odp_be_to_cpu_16(addr.sin_port));

		sprintf(buf, "%d bytes\n", len);

		if (ofp_sendto(fd, buf, strlen(buf), 0,
			       (struct ofp_sockaddr *)&addr,
			       sizeof(addr)) == -1) {
			OFP_ERR("Faild to send data (errno = %d)\n", ofp_errno);
		}
	}

	logprint("mcast exit\n");
	return NULL;
}

void ofp_multicast_thread(int core_id)
{
	odph_linux_pthread_t test_linux_pthread;
	odp_cpumask_t cpumask;

	odp_cpumask_zero(&cpumask);
	odp_cpumask_set(&cpumask, core_id);

	odph_linux_pthread_create(&test_linux_pthread,
				  &cpumask,
				  mcasttest,
				  NULL,
				  ODP_THREAD_WORKER
				);
}
