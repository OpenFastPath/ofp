/* Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "ofpi.h"
#include "ofpi_util.h"
#include "ofpi_log.h"

int ofp_first_log_time = 0;

uint16_t ofp_in_cksum(register uint16_t *addr, register int len)
{
	register int nleft = len;
	register uint16_t *w = addr;
	register uint16_t answer;
	register int sum = 0;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1)
		sum += odp_cpu_to_be_16(*(u_char *)w << 8);

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
	sum += (sum >> 16);                 /* add carry */
	answer = ~sum;                      /* truncate to 16 bits */
	return answer;
}

#define ADDCARRY(x)  (x > 65535 ? x -= 65535 : x)
#define REDUCE do {						\
l_util.l = sum; sum = l_util.s[0] + l_util.s[1]; ADDCARRY(sum);	\
} while (0)

static int __ofp_cksum(const odp_packet_t pkt, unsigned int off,
			 unsigned int len)
{
	int sum = 0;
	uint16_t tmp = 0;
	odp_packet_seg_t seg;
	uint32_t seglen, cksum_len, done = 0;
	uint8_t *cksum_data;
	union {
		uint16_t s[2];
		uint32_t l;
	} l_util;

	seg = odp_packet_first_seg(pkt);
	while (seg != ODP_PACKET_SEG_INVALID) {
		seglen = odp_packet_seg_data_len(pkt, seg);

		if (off >= seglen) {
			off -= seglen;
			continue;
		}

		cksum_len = seglen - off;
		if (cksum_len > len)
			cksum_len = len;

		cksum_data = (uint8_t *)odp_packet_seg_data(pkt, seg) + off;
		tmp = ~ofp_in_cksum((uint16_t *)cksum_data, cksum_len);

		/* swap bytes on odd boundary */
		if (done % 2)
			tmp = ((tmp&0x00ff) << 8) | ((tmp&0xff00) >> 8);

		sum += tmp;
		off = 0;
		done += cksum_len;

		if (done == len)
			break;

		seg = odp_packet_next_seg(pkt, seg);
	}

	REDUCE;
	return sum;
}

int ofp_cksum(const odp_packet_t pkt, unsigned int off, unsigned int len)
{
	return (~__ofp_cksum(pkt, off, len)) & 0xffff;
}

int ofp_getsum(const odp_packet_t pkt, unsigned int off, unsigned int len)
{
	return __ofp_cksum(pkt, off, len);
}

struct ofp_ipovly {
	uint8_t  ih_x1[9];             /* (unused) */
	uint8_t  ih_pr;                /* protocol */
	uint16_t ih_len;               /* protocol length */
	struct   ofp_in_addr ih_src;       /* source internet address */
	struct   ofp_in_addr ih_dst;       /* destination internet address */
} __attribute__((__packed__));

static inline int __ofp_in4_cksum(const odp_packet_t pkt)
{
	struct ofp_ip *ip;
	int off, len, sum = 0;
	uint16_t *w, tmp;
	union {
		uint16_t s[2];
		uint32_t l;
	} l_util;
	union {
		struct ofp_ipovly ipov;
		uint16_t w[10];
	} u;

	ip = (struct ofp_ip *)odp_packet_l3_ptr(pkt, NULL);
	off = ip->ip_hl << 2;
	/* pseudo header used to compute UDP checksum */
	memset(&u.ipov, 0, sizeof(u.ipov));
	u.ipov.ih_len = odp_cpu_to_be_16(odp_be_to_cpu_16(ip->ip_len) - off);
	u.ipov.ih_pr = ip->ip_p;
	u.ipov.ih_src = ip->ip_src;
	u.ipov.ih_dst = ip->ip_dst;
	w = u.w;
	/* assumes sizeof(ipov) == 20 */
	sum += w[0]; sum += w[1]; sum += w[2]; sum += w[3]; sum += w[4];
	sum += w[5]; sum += w[6]; sum += w[7]; sum += w[8]; sum += w[9];

	len = odp_be_to_cpu_16(ip->ip_len) - off;
	tmp = ~ofp_cksum(pkt, odp_packet_l3_offset(pkt) + off, len);
	sum += tmp;
	REDUCE;
	return (~sum & 0xffff);
}

int ofp_in4_cksum(const odp_packet_t pkt)
{
	return __ofp_in4_cksum(pkt);
}

/**
 * Helper function to print MAC address.
 */
char *ofp_print_mac(uint8_t *mac)
{
	static char buf[2][24];
	static int sel = 0;
	int i, n = 0;

	sel = sel ^ 1;
	for (i = 0; i < 6; i++)
		n += sprintf(&buf[sel][n],
			     "%c%02x", i == 0 ? ' ' : ':', mac[i]);
	return buf[sel];
}

/**
 * Helper function to print IP address.
 */
char *ofp_print_ip_addr(uint32_t addr)
{
	static char buf[4][24];
	static int sel = 0;
	uint32_t ip = odp_be_to_cpu_32(addr);

	sel++;
	if (sel > 3)
		sel = 0;
	sprintf(buf[sel], "%d.%d.%d.%d",
		ip>>24, (ip>>16)&0xff, (ip>>8)&0xff, ip&0xff);

	return buf[sel];
}

char *ofp_print_ip6_addr(uint8_t *addr)
{
	int i, n = 0;
	static char buf[2][OFP_INET6_ADDRSTRLEN];
	static int sel = 0;

	sel = sel ^ 1;
	for (i = 0; i < 16; i += 2)
		n += sprintf(buf[sel] + n, "%s%02x%02x",
			     i == 0 ? "" : ":", addr[i], addr[i+1]);

	return buf[sel];
}

void ofp_print_hex(uint8_t log_level,
	unsigned char *data, int len)
{
	int i;

	if (!data) {
		OFP_LOG_NO_CTX(log_level, "* ofp_print_hex: no data!*");
		return;
	}

	for (i = 0; i < len; i++)
		OFP_LOG_NO_CTX(log_level, "%02x ", data[i]);
}

/*
 * In develepment environment this will generate a core dump.
 * In production environment this should be re-defined to
 * product specific function
 */
void ofp_generate_coredump(void)
{
	int a = 0;
	int b = 7;
	int c = b/a;

	a = c;
}

int ofp_hex_to_num(char *s)
{
	int n = 0;

	while (s && *s) {
		if (*s >= '0' && *s <= '9')
			n = (n << 4) | (*s - '0');
		else if (*s >= 'a' && *s <= 'f')
			n = (n << 4) | (*s - 'a' + 10);
		else if (*s >= 'A' && *s <= 'F')
			n = (n << 4) | (*s - 'A' + 10);
		else
			break;
		s++;
	}

	return n;
}

void ofp_mac_to_link_local(uint8_t *mac, uint8_t *lladdr)
{
	memset(lladdr, 0, 16);
	memcpy(lladdr + 8, mac, 3);
	memcpy(lladdr + 13, mac + 3, 3);
	lladdr[8] ^= 0x02;
	lladdr[11] = 0xff;
	lladdr[12] = 0xfe;
	lladdr[0] = 0xfe;
	lladdr[1] = 0x80;
}

int ofp_has_mac(uint8_t *mac)
{
	int i;

	for (i = 0; i < OFP_ETHER_ADDR_LEN; ++i)
		if (mac[i])
			return 1;

	return 0;
}

void ofp_ip6_masklen_to_mask(int masklen, uint8_t *mask)
{
	int i;
	int bytes = masklen/8;
	int bits = 8 - (masklen%8);

	for (i = 0; i < 16; i++)
		mask[i] = 0;

	for (i = 0; i < bytes; i++)
		mask[i] = 0xff;

	if (i < 16 && bits < 8)
		mask[i] = (~0) << bits;
}

/*
 * mask in little endian order
 */
int ofp_mask_length(int masklen, uint8_t *mask)
{
	int i, j, m, ml = masklen;

	for (i = 0; i < masklen/8; i++) {
		for (j = 0; j < 8; j++) {
			m = 1 << j;
			if (mask[i] & m)
				return ml;
			ml--;
		}
	}
	return 0;
}

int ofp_name_to_port_vlan(const char *dev, int *vlan)
{
	int port = -1;
	char *p;

	if (!dev)
		return -1;

	/* gre */
	if (strncmp(dev, OFP_GRE_IFNAME_PREFIX,
		    strlen(OFP_GRE_IFNAME_PREFIX)) == 0) {
		*vlan = atoi(dev + strlen(OFP_GRE_IFNAME_PREFIX));
		return GRE_PORTS;
	}

	/* fp */
	if (strncmp(dev, OFP_IFNAME_PREFIX, strlen(OFP_IFNAME_PREFIX)))
		return -1;

	port = atoi(dev + strlen(OFP_IFNAME_PREFIX));

	p = strchr(dev, '.');

	if (p)
		*vlan = atoi(p+1);
	else
		*vlan = 0;

	return port;
}

char *ofp_port_vlan_to_ifnet_name(int port, int vlan)
{
	static char buf[2][18];
	static int sel = 0;

	sel = sel ^ 1;

	if (vlan)
		if (port == GRE_PORTS)
			sprintf(buf[sel], "%s%d",
				OFP_GRE_IFNAME_PREFIX, vlan);
		else
			sprintf(buf[sel], "%s%d.%d",
				OFP_IFNAME_PREFIX, port, vlan);
	else
		sprintf(buf[sel], "%s%d", OFP_IFNAME_PREFIX, port);

	return buf[sel];
}

int ofp_sendf(int fd, const char *fmt, ...)
{
	char buf[1024];
	int ret, n;
	va_list ap;
	struct stat statbuf;

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	fstat(fd, &statbuf);
	if (S_ISSOCK(fd))
		ret = send(fd, buf, n, 0);
	else
		ret = write(fd, buf, n);

	return ret;
}

void *ofp_shared_memory_alloc(const char *name, uint64_t size)
{
	odp_shm_t shm_h;
	void *shm;

	shm_h = odp_shm_reserve(name, size, ODP_CACHE_LINE_SIZE, 0);
	if (shm_h == ODP_SHM_INVALID)
		return NULL;

	shm = odp_shm_addr(shm_h);

	if (shm == NULL) {
		odp_shm_free(shm_h);
		return NULL;
	}

	return shm;
}

int ofp_shared_memory_free(const char *name)
{
	odp_shm_t shm_h;

	shm_h = odp_shm_lookup(name);
	if (shm_h == ODP_SHM_INVALID)
		return -1;

	odp_shm_free(shm_h);
	return 0;
}

void *ofp_shared_memory_lookup(const char *name)
{
	odp_shm_t shm_h;
	void *shm;

	shm_h = odp_shm_lookup(name);
	if (shm_h == ODP_SHM_INVALID)
		return NULL;

	shm = odp_shm_addr(shm_h);
	if (shm == NULL) {
		odp_shm_free(shm_h);
		return NULL;
	}

	return shm;
}
