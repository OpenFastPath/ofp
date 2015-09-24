/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */


#ifndef __OFPI_IN6_H__
#define __OFPI_IN6_H__

#include "odp.h"
#include "api/ofp_in6.h"

extern  uint8_t ofp_ip6_protox[];
extern  uint8_t ofp_inet6ctlerrmap[];

#define OFP_IN6_IS_SOLICITED_NODE_MC(maddr, taddr) \
	((maddr.ofp_s6_addr16[0] == OFP_IPV6_ADDR_INT16_MLL) && \
	(maddr.ofp_s6_addr16[1] == 0) && \
	(maddr.ofp_s6_addr32[1] == 0) && \
	(maddr.ofp_s6_addr32[2] == OFP_IPV6_ADDR_INT32_ONE) && \
	(maddr.ofp_s6_addr[12] == 0xff) && \
	(maddr.ofp_s6_addr[13] == taddr[13]) && \
	(maddr.ofp_s6_addr[14] == taddr[14]) && \
	(maddr.ofp_s6_addr[15] == taddr[15]))

struct ofp_sockaddr;
struct ofp_sockaddr_in;
void ofp_in6_sin6_2_sin(struct ofp_sockaddr_in *sin,
	struct ofp_sockaddr_in6 *sin6);

void ofp_in6_sin_2_v4mapsin6 __P((struct ofp_sockaddr_in *sin,
				 struct ofp_sockaddr_in6 *sin6));
void ofp_in6_sin6_2_sin_in_sock(struct ofp_sockaddr *nam);

uint16_t ofp_in6_getscope(struct ofp_in6_addr *);
int ofp_in6_clearscope(struct ofp_in6_addr *);

struct ofp_ip6_hdr;
int ofp_in6_cksum_pseudo(struct ofp_ip6_hdr *, uint32_t, uint8_t, uint16_t);

#endif /* __OFPI_IN6_H__ */
