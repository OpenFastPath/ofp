/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <netinet/if_ether.h>
#include <stropts.h>

#include <odp.h>
#include "linux.h"
#include "ofpi_portconf.h"
#include "ofpi_if_vlan.h"
#include "ofpi_debug.h"
#include "ofpi_pkt_processing.h"
#include "ofpi_stat.h"
#include "ofpi_log.h"
#include "ofpi_util.h"

#define FPM_DEBUG

static int tap_alloc(char *dev, int flags) {

	struct ifreq ifr;
	int fd, err;
	const char *clonedev = "/dev/net/tun";

	/* Arguments taken by the function:
	 *
	 * char *dev: the name of an interface (or '\0'). MUST have enough
	 *   space to hold the interface name if '\0' is passed
	 * int flags: interface flags (eg, IFF_TUN etc.)
	 */

	/* open the clone device */
	if ((fd = open(clonedev, O_RDWR)) < 0 ) {
		OFP_ERR("open failed");
		return fd;
	}

	/* preparation of the struct ifr, of type "struct ifreq" */
	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = flags;   /* IFF_TUN or IFFemacs_TAP, plus maybe IFF_NO_PI */

	if (*dev) {
		/* if a device name was specified, put it in the structure; otherwise,
		 * the kernel will try to allocate the "next" device of the
		 * specified type */
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	}

	/* try to create the device */
	if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
		OFP_ERR("ioctl failed");
		close(fd);
		return -1;
	}

	/* if the operation was successful, write back the name of the
	 * interface to the variable "dev", so the caller can know
	 * it. Note that the caller MUST reserve space in *dev (see calling
	 * code below) */
	strcpy(dev, ifr.ifr_name);

	/* Let hardware do checksum */
	ioctl(fd, TUNSETNOCSUM, 1);

	/* DEBUG */
	ioctl(fd, TUNSETDEBUG, 1);


	/* this is the special file descriptor that the caller will use to talk
	 * with the virtual interface */
	return fd;
}

/* Return the fd of the tap */
int sp_setup_device(struct ofp_ifnet *ifnet) {
	int fd;
	struct ifreq ifr;
	int gen_fd;
	char fp_name[IFNAMSIZ];
	struct sockaddr hwaddr;

	memset(&hwaddr, 0x0, sizeof(hwaddr));

	/* Prepare FP device name*/
	snprintf(fp_name, IFNAMSIZ, "fp%d", ifnet->port);
	fp_name[IFNAMSIZ - 1] = 0;

	/* Create device */
	fd = tap_alloc(fp_name, IFF_TAP  | IFF_NO_PI);
	if (fd < 0) {
		OFP_ABORT("tap_alloc failed");
	}

	hwaddr.sa_family = AF_UNIX;
	memcpy(hwaddr.sa_data, ifnet->mac, sizeof(ifnet->mac));

	/* Set the same MAC address as reported by ODP */
	memset(&ifr, 0x0, sizeof(ifr));
	strncpy(ifr.ifr_name, fp_name, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = 0;
	memcpy(&ifr.ifr_hwaddr, &hwaddr, sizeof(ifr.ifr_hwaddr));

	OFP_DBG("Fastpath device %s addr %s",
		  fp_name, ofp_print_mac((uint8_t *)ifr.ifr_hwaddr.sa_data));

	/* Setting HW address of FP kernel representation */
	if (ioctl(fd, SIOCSIFHWADDR, &ifr) < 0) {
		perror("SIOCSIFHWADDR");
		OFP_ABORT("ioctl failed");
	}

	gen_fd = socket(PF_INET, SOCK_DGRAM, 0);

	/* Setting MTU of FP kernel representation */
	memset(&ifr, 0x0, sizeof(ifr));
	strncpy(ifr.ifr_name, fp_name, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = 0;
	ifr.ifr_mtu = ifnet->if_mtu;

	OFP_DBG("Fastpath device %s MTU %i", fp_name, ifr.ifr_mtu);

	if (ioctl(gen_fd, SIOCSIFMTU, &ifr) < 0) {
		perror("SIOCSIFMTU");
		OFP_ABORT("ioctl failed");
	}

	/* Get flags */
	memset(&ifr, 0x0, sizeof(ifr));
	strncpy(ifr.ifr_name, fp_name, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = 0;
	if (ioctl(gen_fd, SIOCGIFFLAGS, &ifr) < 0) {
		perror("SIOCGIFFLAGS");
		OFP_ABORT("ioctl failed");
	}

	/* Set flags - ifconfig up*/
	if (!(ifr.ifr_flags & IFF_UP)) {
		/* ifconfig up */
		ifr.ifr_flags |= IFF_UP;
		if (ioctl(gen_fd, SIOCSIFFLAGS, &ifr) < 0) {
			perror("SIOCSIFFLAGS");
			OFP_ABORT("ioctl failed");
		}
	}

	/* Get interface index */
	memset(&ifr, 0x0, sizeof(ifr));
	strncpy(ifr.ifr_name, fp_name, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = 0;
	if (ioctl(gen_fd, SIOCGIFINDEX, &ifr) < 0) {
		perror("SIOCSIFINDEX");
		OFP_ABORT("ioctl failed");
	}

	/* Store ifindex in viu and create table */
	ifnet->linux_index = ifr.ifr_ifindex;
	ifnet->sp_status = OFP_SP_UP;

	close(gen_fd);
	return fd;
}

void * sp_rx_thread(void *ifnet_void) {
	struct ofp_ifnet *ifnet = (struct ofp_ifnet *) ifnet_void;
	struct ofp_ifnet *pkt_ifnet;
	struct ofp_ether_header *eth;
	struct ofp_ether_vlan_header *vlan_hdr;
	uint16_t vlan = 0;
	odp_packet_t pkt;
	odp_event_t ev;
	int len;

	(void) len;

	ofp_init_local();

	while(1) {
		ev = odp_queue_deq(ifnet->spq_def);

		if (ev == ODP_EVENT_INVALID ||
		    odp_event_type(ev) != ODP_EVENT_PACKET) {
			/* FIXME: Blocking queue popping in ODP ? */
			usleep(2000);
			continue;
		}
		pkt = odp_packet_from_event(ev);

		if (ifnet->sp_status != OFP_SP_UP) {
			odp_packet_free(pkt);
			continue;
		}

		eth = odp_packet_l2_ptr(pkt, NULL);
		if (odp_be_to_cpu_16(eth->ether_type) == OFP_ETHERTYPE_VLAN) {
			vlan_hdr = (struct ofp_ether_vlan_header *)eth;
			vlan = OFP_EVL_VLANOFTAG(vlan_hdr->evl_tag);
		} else {
			vlan = 0;
		}

		pkt_ifnet = ofp_get_ifnet(ifnet->port, vlan);
		if (pkt_ifnet == NULL ||
		    pkt_ifnet->sp_status != OFP_SP_UP){
			odp_packet_free(pkt);
			continue;
		}

		OFP_DEBUG_PACKET(OFP_DEBUG_PKT_RECV_KNI, pkt, ifnet->port);

		OFP_UPDATE_PACKET_STAT(rx_sp, 1);

		len = write(ifnet->fd,
			    (void *)odp_packet_l2_ptr(pkt, NULL),
			    (size_t)odp_packet_len(pkt));

		odp_packet_free(pkt);
	}

	/* Never returns */
	return NULL;
}

void * sp_tx_thread(void *ifnet_void) {
	int len;
	odp_packet_t pkt;
	uint8_t *buf_pnt;
	struct ofp_ifnet *ifnet = (struct ofp_ifnet *)ifnet_void;

	ofp_init_local();

	while (1) {
		/* FIXME: coalese syscalls and speed this up */

		pkt = odp_packet_alloc(ifnet->pkt_pool,
				       ifnet->if_mtu + OFP_ETHER_HDR_LEN +
				       OFP_ETHER_VLAN_ENCAP_LEN);

		if (pkt == ODP_PACKET_INVALID) {
			OFP_ERR("odp_packet_alloc failed");
			usleep(1000);
			continue;
		}

		buf_pnt = odp_packet_data(pkt);

		/* Blocking read */
	drop_pkg:
		len = read(ifnet->fd, buf_pnt, odp_packet_len(pkt));
		if (len <= 0) {
			OFP_ERR("read failed");
			goto drop_pkg;
		}

		if (len > 0) {
			odp_packet_reset(pkt, (size_t)len);
			odp_packet_l2_offset_set(pkt, 0);

			OFP_DEBUG_PACKET(OFP_DEBUG_PKT_SEND_KNI, pkt,
				ifnet->port);

			OFP_UPDATE_PACKET_STAT(tx_sp, 1);

			/* Enqueue the packet to
			   fastpath device */
			odp_queue_enq(ifnet->outq_def, odp_packet_to_event(pkt));
		}
	}

	/* Never returns */
	return NULL;
}
