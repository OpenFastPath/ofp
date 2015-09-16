/* Copyright (c) 2014, ENEA Software AB
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_arp.h>
#include <linux/if_tunnel.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "odp.h"
#include "ofpi_avl.h"
#include "ofpi_portconf.h"
#include "ofpi_rt_lookup.h"
#include "ofpi_pkt_processing.h"
#include "ofpi_route.h"
#include "ofpi_log.h"
#include "ofpi_util.h"
#include "ofpi_netlink.h"

#define BUFFER_SIZE 4096
static char buffer[BUFFER_SIZE];

static int handle_ipv4v6_route(struct nlmsghdr *nlp)
{
	/* string to hold content of the route */
	/* table (i.e. one entry) */
	char *dsts = NULL, *gws = NULL;
	char  dsts_str[24], gws_str[24], ifs[16], ms[24];
	uint32_t destination = 0 , gateway = 0, ix = 0;

	int dst_len = 0, gw_len = 0;
	char *dst6 = NULL, *gw6 = NULL;
	struct rtmsg *rtp;
	struct rtattr *rtap;
	int rtl;


	/* get route entry header */
	rtp = (struct rtmsg *) NLMSG_DATA(nlp);

	/* TABLE_MAIN is the one that stores
	the routes needed for a forwarding router*/
	if (rtp->rtm_table != RT_TABLE_MAIN)
		return 0;

	OFP_DBG("* ROUTE rtm_dst_len=%d", rtp->rtm_dst_len);

	/* init all the strings */
	bzero(dsts_str, sizeof(dsts_str));
	bzero(gws_str, sizeof(gws_str));
	bzero(ifs, sizeof(ifs));
	bzero(ms, sizeof(ms));
	/* inner loop: loop thru all the attributes of
	   one route entry */
	rtap = (struct rtattr *) RTM_RTA(rtp);
	rtl = RTM_PAYLOAD(nlp);

	for (; RTA_OK(rtap, rtl); rtap = RTA_NEXT(rtap, rtl)) {
#ifdef NETLINK_DEBUG
		OFP_DBG("  rta_type=%d data=%p len=%ld\n",
			rtap->rta_type, RTA_DATA(rtap), RTA_PAYLOAD(rtap));
		ofp_print_hex(OFP_LOG_DBG, RTA_DATA(rtap),
			RTA_PAYLOAD(rtap));
		OFP_LOG_NO_CTX(OFP_LOG_DBG, "\n");
#endif
		switch (rtap->rta_type) {
			/* destination IPv4 address */
		case RTA_DST:
			dst_len = RTA_PAYLOAD(rtap);

			if (dst_len == 4) {
				destination = *((uint32_t *)(RTA_DATA(rtap)));
				dsts = ofp_print_ip_addr(destination);
				OFP_DBG("Dest: %s", dsts);
			} else if (dst_len == 16) {
				dst6 = RTA_DATA(rtap);
				dsts  = ofp_print_ip6_addr((uint8_t *)dst6);
				OFP_DBG("Dest: %s", dsts);
			} else
				OFP_DBG(">>> RTA_DST: len=%d <<<",
					dst_len);

			break;

			/* next hop IPv4 address */
		case RTA_GATEWAY:
			gw_len = RTA_PAYLOAD(rtap);
			if (gw_len == 4) {
				gateway = *((uint32_t *)(RTA_DATA(rtap)));
				gws = ofp_print_ip_addr(gateway);
				OFP_DBG("Gateway: %s", gws);
			} else if (gw_len == 16) {
				gw6 = RTA_DATA(rtap);
				gws = ofp_print_ip6_addr((uint8_t *)gw6);
				OFP_DBG("Gateway: %s", gws);
			}

			break;
			/* unique ID associated with the network
			   interface */
		case RTA_OIF:
			ix = *((uint32_t *) RTA_DATA(rtap));
			sprintf(ifs, "%d", *((int *) RTA_DATA(rtap)));
			OFP_DBG("Interface: %d", ix);
		default:
			break;
		}
	}
	if (dsts == NULL)
		dsts = dsts_str;
	if (gws == NULL)
		gws = gws_str;
	sprintf(ms, "%d", rtp->rtm_dst_len);
	OFP_DBG("%s dst=%s/%s gw=%s if=%d dst_len=%d",
		   (nlp->nlmsg_type == RTM_NEWROUTE)?"New":"Del",
		   dsts, ms, gws, ix, dst_len);

	if (nlp->nlmsg_type == RTM_NEWROUTE) {
		struct ofp_ifnet *dev = ofp_get_ifnet_by_linux_ifindex(ix);

		if (dev) {
			struct ofp_route_msg msg;

			msg.vrf = 0;
			if (dst_len == 4 || dst_len == 16) {
				msg.port = dev->port;
				msg.vlan = dev->vlan;
				if (dst_len == 4) {
					msg.type = OFP_ROUTE_ADD;
					msg.dst = destination;
					msg.masklen = rtp->rtm_dst_len;
					msg.gw = gateway;
					ofp_set_route_msg(&msg);
				} else if (dst6) {
					msg.type = OFP_ROUTE6_ADD;
					memcpy(msg.dst6, dst6, dst_len);
					msg.masklen = rtp->rtm_dst_len;
					if (gw6)
						memcpy(msg.gw6, gw6, gw_len);
					else
						memset(msg.gw6, 0, 16);
					ofp_set_route_msg(&msg);
				}
			} else if (dst_len == 0) {
				/* default route */
				msg.type = OFP_ROUTE_ADD;
				msg.dst = 0;
				msg.masklen = 0;
				msg.gw = gateway;
				msg.port = dev->port;
				msg.vlan = dev->vlan;
				ofp_set_route_msg(&msg);
			}
		} else
			OFP_DBG("Cannot find dev ix=%d", ix);
	} else {
		struct ofp_route_msg msg;

		msg.vrf = 0;
		if (dst_len == 0) {
			/* default route */
			msg.type = OFP_ROUTE_DEL;
			msg.dst = 0;
			msg.masklen = 0;
		} else {
			msg.type = dst_len == 4 ?
				OFP_ROUTE_DEL : OFP_ROUTE6_DEL;
			if (dst6)
				memcpy(msg.dst6, dst6, dst_len);
			else
				msg.dst = destination;
			msg.masklen = rtp->rtm_dst_len;
		}
		ofp_set_route_msg(&msg);
	}
	return 0;
}
static int add_ipv4v6_addr(struct ifaddrmsg *if_entry, struct ofp_ifnet *dev,
			   unsigned char *addr, unsigned char *bcast,
			   unsigned char *laddr)
{
	uint32_t namespace = 0;  /* TODO: vrf in netlink */

	if (if_entry->ifa_family == AF_INET)	{
		if (dev->port == GRE_PORTS) {
			dev->ip_p2p = *((uint32_t *)addr);
			dev->ip_addr = *((uint32_t *)laddr);
		} else {
			dev->ip_addr = *((uint32_t *)addr);
			if(dev->vlan == 0)
				ofp_ifaddr_elem_add(dev);
		}
		/* dev->linux_index = if_entry->ifa_index;*/
		dev->vrf = namespace;
		dev->masklen = if_entry->ifa_prefixlen;
		dev->bcast_addr = bcast ? *(uint32_t *)bcast : 0;
		dev->sp_status = OFP_SP_UP;
		/* update quick access table */
		ofp_update_ifindex_lookup_tab(dev);
	}
#ifdef INET6
	else if (if_entry->ifa_family == AF_INET6) {

		/* dev->linux_index = if_entry->ifa_index;*/
		dev->vrf = namespace;
		if (if_entry->ifa_scope == RT_SCOPE_LINK) {
			memcpy(dev->link_local, addr, 16);
		} else {
			memcpy(dev->ip6_addr, addr, 16);
			dev->ip6_prefix = if_entry->ifa_prefixlen;
			dev->sp_status = OFP_SP_UP;
			if(dev->vlan == 0)
				ofp_ifaddr6_elem_add(dev);
		}
		/* update quick access table */
		ofp_update_ifindex_lookup_tab(dev);
	}
#endif /* INET6 */

	return 0;
}
static int del_ipv4v6_addr(struct ifaddrmsg *if_entry, struct ofp_ifnet *dev,
			   unsigned char *addr, unsigned char *laddr)
{
	(void)addr;
	(void)laddr;

	if (if_entry->ifa_family == AF_INET)	{
		ofp_set_route_params(
			OFP_ROUTE_DEL, dev->vrf, dev->vlan,dev->port,
			(dev->port == GRE_PORTS) ? dev->ip_p2p : dev->ip_addr,
			dev->masklen, 0 /*gw*/);
		dev->ip_addr = 0;
		if (dev->port == GRE_PORTS)
			dev->ip_p2p = 0;
		else if (dev->vlan == 0)
			ofp_ifaddr_elem_del(dev);
	}
#ifdef INET6
	else if (if_entry->ifa_family == AF_INET6) {
		uint8_t gw6[16];

		memset(gw6, 0, 16);

		ofp_set_route6_params(OFP_ROUTE6_DEL, 0 /*vrf*/, dev->vlan,
				      dev->port, dev->ip6_addr, dev->ip6_prefix,
				      gw6);
		memset(dev->ip6_addr, 0, 16);

		if (dev->vlan == 0)
			ofp_ifaddr6_elem_del(dev);
	}
#endif /* INET6 */
	return 0;
}
static int handle_ipv4v6_addr(struct nlmsghdr *nlh)
{
	/* msg RTM_NEWADDR / RTM_DELADDR contain an ifaddrmsg structure,
	optionally followed by rtattr routing attributes */
	struct ifaddrmsg *if_entry;
	char if_address[32];
	char *name = NULL;
	unsigned char *addr = NULL , *bcast = NULL, *laddr = NULL;
	struct rtattr *rtap;
	int rtl;
	struct ofp_ifnet *dev;

	memset(if_address, 0, sizeof(if_address));
	/* Get the addr data */
	if_entry = (struct ifaddrmsg *) NLMSG_DATA(nlh);

/* note : problem with IFLA_() macros : should be used for RTM_GETLINK,
RTM_NEWLINK messages, which start with ifinfomsg.
The processed msg here RTM_NEWADDR, RTM_DELADDR start with ifaddrmsg
*/
	OFP_DBG("* INTERFACE: ifa_family=%d ifa_prefixlen=%d ifa_flags=0x%x"
		" ifa_scope=%d ifa_index=%d",
		   if_entry->ifa_family, if_entry->ifa_prefixlen,
		   if_entry->ifa_flags, if_entry->ifa_scope,
		   if_entry->ifa_index);

	rtap = (struct rtattr *) IFA_RTA(if_entry);
	rtl = IFA_PAYLOAD(nlh);
	for (; RTA_OK(rtap, rtl); rtap = RTA_NEXT(rtap, rtl)) {
#ifdef NETLINK_DEBUG
		OFP_DBG("  rta_type=%d data=%p len=%ld\n", rtap->rta_type,
			RTA_DATA(rtap), RTA_PAYLOAD(rtap));
		ofp_print_hex(OFP_LOG_DBG,
			RTA_DATA(rtap), RTA_PAYLOAD(rtap));
		OFP_LOG_NO_CTX(OFP_LOG_DBG, "\n");
#endif
		switch (rtap->rta_type) {
		case IFA_LABEL:
			name = RTA_DATA(rtap);
			OFP_DBG("Interface name = %s", name);
			break;

		case IFA_ADDRESS:
			addr = RTA_DATA(rtap);
			if (if_entry->ifa_family == AF_INET) {
				OFP_DBG("Addr = %s",
					ofp_print_ip_addr(*(uint32_t *)addr));
			} else if (if_entry->ifa_family == AF_INET6) {
				OFP_DBG("IP6 Addr = %s",
					ofp_print_ip6_addr(addr));
			}
			break;

		case IFA_LOCAL:
			if (if_entry->ifa_family == AF_INET) {
				/* For P2P Interfaces(GRE):
				   IFA_LOCAL is local address,
				   IFA_ADDR is destination address */
				laddr = RTA_DATA(rtap);
				OFP_DBG("Local addr = %s",
					  ofp_print_ip_addr(
						  *(uint32_t *)laddr));
			}
			break;

		case IFA_BROADCAST:
			/* addr = bcast = RTA_DATA(rtap); */
			bcast = RTA_DATA(rtap);
			OFP_DBG("Bcast = %s",
				  ofp_print_ip_addr(*(uint32_t *)bcast));
			break;

		default:
			break;
		}
	}

	if (!addr) {
		OFP_ERR("Address not received!");
		return -1;
	}

	dev = ofp_get_ifnet_by_linux_ifindex(if_entry->ifa_index);
	if (!dev) {
		OFP_ERR("Interface not found!");
		return -1;
	}

	if (dev->port == GRE_PORTS && if_entry->ifa_family == AF_INET) {
		if (!laddr) {
			OFP_ERR("Local address not received for GRE IF!");
			return -1;
		}
	}

	if (!name)
		name = ofp_port_vlan_to_ifnet_name(dev->port, dev->vlan);

	OFP_DBG("%s addr to ifx --> %s OIF %d name %s",
		nlh->nlmsg_type == RTM_NEWADDR ? "Adding" : "Deleting",
		ofp_print_ip_addr(*(uint32_t *)laddr),
		if_entry->ifa_index, name);

	if (nlh->nlmsg_type == RTM_DELADDR)
		return del_ipv4v6_addr(if_entry, dev, addr, laddr);
	else if (nlh->nlmsg_type == RTM_NEWADDR)
		return add_ipv4v6_addr(if_entry, dev, addr, bcast, laddr);

	return 0;
}

static int add_link(struct ifinfomsg *ifinfo_entry, int vlan, int link,
		    unsigned int mtu, uint32_t tun_loc, uint32_t tun_rem)
{
	struct ofp_ifnet *dev_root = NULL;
	struct ofp_ifnet *dev = NULL;
	struct ofp_ifnet key;
	uint32_t vrf = 0; /* TODO: vrf in netlink */

	if (vlan != -1) {
		if (ifinfo_entry->ifi_type == ARPHRD_IPGRE) {
			dev_root = ofp_get_ifnet(GRE_PORTS, 0);
			if (ofp_get_ifnet_by_ip(tun_loc, vrf) == NULL) {
				OFP_DBG("Tunnel local IP not configured. Interface ignored.");
				return -1;
			}
		} else
			dev_root = ofp_get_ifnet_by_linux_ifindex(link);

		if (!dev_root) {
			OFP_ERR("Root interface not found: %d", link);
			return -1;
		}

		key.vlan = vlan;
		if (ofp_vlan_get_by_key(
			dev_root->vlan_structs,
			&key,
			(void **)&dev)) {

			dev = malloc(sizeof(struct ofp_ifnet));
			memset(dev, 0, sizeof(struct ofp_ifnet));
			dev->port = dev_root->port;
			dev->vlan = vlan;
			dev->vrf = vrf;
			memcpy(dev->mac, dev_root->mac, 6);
			dev->sp_status = OFP_SP_UP;
#ifdef INET6
			memcpy(dev->link_local, dev_root->link_local, 16);
#endif /* INET6 */
			vlan_ifnet_insert(dev_root->vlan_structs, dev);
		}

		/* Update linux index in case dev was created by portconf */
		/* when linux interface index was not available yet (cli) */
		if (!dev->linux_index) {
			dev->linux_index = ifinfo_entry->ifi_index;
			ofp_update_ifindex_lookup_tab(dev);
		} else if (dev->linux_index == 0) {
			dev->linux_index = ifinfo_entry->ifi_index;
			ofp_update_ifindex_lookup_tab(dev);
		}

		if (tun_loc)
			dev->ip_local = tun_loc;
		if (tun_rem)
			dev->ip_remote = tun_rem;

	} else {
		dev = ofp_get_ifnet_by_linux_ifindex(ifinfo_entry->ifi_index);
	}

	if (mtu && dev != NULL) {
		OFP_DBG("Interface updated OIF=%d MTU=%u",
			ifinfo_entry->ifi_index, mtu);
		dev->if_mtu = mtu;
	}

	return 0;
}

static int del_link(struct ifinfomsg *ifinfo_entry, int vlan, int link)
{
	struct ofp_ifnet *dev_root = NULL;
	struct ofp_ifnet *dev = NULL;
	struct ofp_ifnet key;

	ifinfo_entry = ifinfo_entry;

	if (vlan != -1) {
		if (ifinfo_entry->ifi_type == ARPHRD_IPGRE) {
			dev_root = ofp_get_ifnet(GRE_PORTS, 0);
		} else
			dev_root = ofp_get_ifnet_by_linux_ifindex(link);

		if (!dev_root) {
			OFP_ERR("Root interface not found: %d", link);
			return -1;
		}

		key.vlan = vlan;
		if (ofp_vlan_get_by_key(dev_root->vlan_structs,
			&key, (void **)&dev)) {
			OFP_DBG("Vlan %d not found", vlan);
			return 0;
		}
		vlan_ifnet_delete(
			dev_root->vlan_structs,
			&key,
			free_key);
		OFP_DBG("Interface deleted port: %d, vlan: %d, OIF=%d",
			  dev_root->port, vlan, ifinfo_entry->ifi_index);
	}

	return 0;
}

static void _parse_ifla_link_info(struct rtattr *rt, int rl,
				  uint32_t *tun_loc, uint32_t *tun_rem)
{
	struct rtattr *rtap = rt;
	int rtl = rl;

	if (RTA_OK(rtap, rtl) && rtap->rta_type == IFLA_INFO_KIND &&
	    strncmp(RTA_DATA(rtap), "gre", sizeof("gre")) == 0) {
		OFP_DBG("IFLA_INFO_KIND: %s", (char *) RTA_DATA(rtap));
		rtap = RTA_NEXT(rtap, rtl);
	} else
		return;

	if (RTA_OK(rtap, rtl) && rtap->rta_type == IFLA_INFO_DATA) {
		OFP_DBG("IFLA_INFO_DATA");
		/* next level nest */
		rtl = RTA_PAYLOAD(rtap);
		rtap = RTA_DATA(rtap);
	} else
		return;

	for (; RTA_OK(rtap, rtl); rtap = RTA_NEXT(rtap, rtl)) {
#ifdef NETLINK_DEBUG
		OFP_DBG("  rta_type=%d data=%p len=%ld\n", rtap->rta_type,
			  RTA_DATA(rtap), RTA_PAYLOAD(rtap));
		ofp_print_hex(OFP_LOG_DBG, RTA_DATA(rtap),
				RTA_PAYLOAD(rtap));
		OFP_LOG_NO_CTX(OFP_LOG_DBG, "\n");
#endif
		switch (rtap->rta_type) {
		case IFLA_GRE_LOCAL:
			*tun_loc = *(uint32_t *)RTA_DATA(rtap);
			OFP_DBG("GRE tunnel local addr = %s",
				  ofp_print_ip_addr(*tun_loc));
			break;
		case IFLA_GRE_REMOTE:
			*tun_rem = *(uint32_t *)RTA_DATA(rtap);
			OFP_DBG("GRE tunnel remote addr = %s",
				  ofp_print_ip_addr(*tun_rem));
			break;
		default:
			break;
		}
	}
}

static int handle_ifinfo(struct nlmsghdr *nlh)
{
	struct ifinfomsg *ifinfo_entry;
	struct rtattr *rtap;
	int rtl;
	unsigned int mtu = 0; /* to match type in struct rtattr*/
	char *name = NULL;
	int link = -1;
	int vlan = -1;
	uint32_t tun_loc = 0, tun_rem = 0;
	char *vlan_txt = NULL;

	ifinfo_entry = (struct ifinfomsg *)NLMSG_DATA(nlh);

	OFP_DBG("* IFINFO: ifi_family=%u ifi_type=%u ifi_index=%d"
		  " ifi_flags=0x%x ifi_change=%u",
		  ifinfo_entry->ifi_family, ifinfo_entry->ifi_type,
		  ifinfo_entry->ifi_index, ifinfo_entry->ifi_flags,
		  ifinfo_entry->ifi_change);

	rtap = (struct rtattr *) IFLA_RTA(ifinfo_entry);
	rtl = IFLA_PAYLOAD(nlh);

	for (; RTA_OK(rtap, rtl); rtap = RTA_NEXT(rtap, rtl)) {
#ifdef NETLINK_DEBUG
		OFP_DBG("  rta_type=%d data=%p len=%ld\n", rtap->rta_type,
			  RTA_DATA(rtap), RTA_PAYLOAD(rtap));
		ofp_print_hex(OFP_LOG_DBG, RTA_DATA(rtap),
				RTA_PAYLOAD(rtap));
		OFP_LOG_NO_CTX(OFP_LOG_DBG, "\n");
#endif
		switch (rtap->rta_type) {
		case IFLA_MTU:
			mtu = *(unsigned int *)RTA_DATA(rtap);
			OFP_DBG("MTU = %u", mtu);
			break;
		case IFLA_LINK:
			link = *(unsigned int *)RTA_DATA(rtap);
			OFP_DBG("Link = %d", link);
			break;
		case IFLA_IFNAME:
			name = RTA_DATA(rtap);
			OFP_DBG("Interface name = %s", name);
			break;
		case IFLA_LINKINFO:
			OFP_DBG("IFLA_LINKINFO");
			_parse_ifla_link_info(RTA_DATA(rtap), RTA_PAYLOAD(rtap),
					      &tun_loc, &tun_rem);
		default:
			break;
		}
	}

	OFP_DBG("%s received to interface OIF %d",
		nlh->nlmsg_type == RTM_DELLINK ? "DELLINK" : "NEWLINK",
		ifinfo_entry->ifi_index);

	if (ifinfo_entry->ifi_type == ARPHRD_IPGRE) { /* GRE */
		if (!name) {
			OFP_ERR("Interface name not received: %d",
				ifinfo_entry->ifi_index);
			return -1;
		}
		if (strncmp(name, OFP_GRE_IFNAME_PREFIX,
			    strlen(OFP_GRE_IFNAME_PREFIX))) {
			OFP_ERR("Invalid GRE interface name: %s", name);
			return -1;
		}
		vlan = atoi(name + strlen(OFP_GRE_IFNAME_PREFIX));
		if (vlan == 0) {
			OFP_ERR("Invalid tunnel id: %d", vlan);
			return -1;
		}
		OFP_DBG("GRE id = %d", vlan);
	} else if ((link != -1) && (link != ifinfo_entry->ifi_index)) {/*vlan*/
		if (!name) {
			OFP_ERR("Interface name not received: %d",
				ifinfo_entry->ifi_index);
			return -1;
		}
		vlan_txt = strrchr(name, '.');
		if (!vlan_txt) {
			OFP_ERR("Interface vlan ID not found: %d",
				ifinfo_entry->ifi_index);
			return -1;
		}
		vlan = atoi(vlan_txt + 1);
		if (vlan == 0) {
			OFP_ERR("Invalid vlan id: %d", vlan);
			return -1;
		}
		OFP_DBG("Vlan id = %d", vlan);
	}

	if (nlh->nlmsg_type == RTM_DELLINK)
		return del_link(ifinfo_entry, vlan, link);
	else if (nlh->nlmsg_type == RTM_NEWLINK)
		return add_link(ifinfo_entry, vlan, link, mtu, tun_loc,
				tun_rem);

	return 0;
}

static void route_read(int nll)
{
	struct  nlmsghdr *nlh = (struct nlmsghdr *) buffer;

	for ( ; NLMSG_OK(nlh, nll);
		  nlh = NLMSG_NEXT(nlh, nll)) {

		switch (nlh->nlmsg_type) {
		/* ARP now managed by ofp */
		case RTM_NEWNEIGH:
		case RTM_DELNEIGH:
			break;

		case RTM_DELROUTE:
		case RTM_NEWROUTE:
			handle_ipv4v6_route(nlh);
			break;

		case RTM_NEWADDR:
		case RTM_DELADDR:
			handle_ipv4v6_addr(nlh);
			break;

		case RTM_NEWLINK:
		case RTM_DELLINK:
			handle_ifinfo(nlh);
			break;

		default:
			OFP_DBG("Unknown message type, %i",
				  nlh->nlmsg_type);
			break;
		}
	}
}

static int route_recv(int route_fd, unsigned int nl_groups)
{
	struct nlmsghdr *nlp;
	int rtn, nll;
	char *p;
	/* initialize the socket read buffer */
	bzero(buffer, BUFFER_SIZE);
	p = buffer;
	nll = 0;
	/* read from the socket until the NLMSG_DONE is
	   returned in the type of the RTNETLINK message
	   or if it was a monitoring socket */
	while (1) {
		rtn = recv(route_fd, p, BUFFER_SIZE - nll, 0);
		if (rtn <= 0) {
			OFP_ERR("recv failed");
			break;
		}
		nlp = (struct nlmsghdr *) p;
		if (nlp->nlmsg_type == NLMSG_DONE)
			break;
		/* increment the buffer pointer to place
		   next message */
		p += rtn;
		/* TODO: sanity check code in case (p - buffer) > BUFFER_SIZE */
		/* increment the total size by the size of
		   the last received message */
		nll += rtn;
		if ((nl_groups & RTMGRP_IPV4_ROUTE)
		   == RTMGRP_IPV4_ROUTE)
			break;
	}
	return nll;
}

void *start_netlink_nl_server(void *arg)
{
	int route_fd = -1;
	int r , nll;
	struct sockaddr_nl la;
	(void)arg;
	fd_set read_fd, fds;
	struct timeval timeout;

	/* Lookup shared memories */
	ofp_init_local();

	if ((route_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
		OFP_ERR("socket failed");
		exit(-1);
	}
	bzero(&la, sizeof(la));
	la.nl_family = AF_NETLINK;
	la.nl_pid = getpid();
	la.nl_groups = RTMGRP_IPV4_ROUTE | RTMGRP_IPV4_IFADDR | RTMGRP_NOTIFY |
#ifdef INET6
		RTMGRP_IPV6_ROUTE | RTMGRP_IPV6_IFADDR |
#endif /* INET6 */
		RTMGRP_LINK;
	if (bind(route_fd, (struct sockaddr *) &la, sizeof(la)) < 0) {
		OFP_ERR("bind failed");
		exit(-1);
	}

	FD_ZERO(&read_fd);
	if (route_fd <= 0) {
		OFP_ERR("Invalid route fd=%d", route_fd);
		return NULL;
	}
	FD_SET(route_fd, &read_fd);

	while (1) {
		fds = read_fd;

		timeout.tv_sec = 0;
		timeout.tv_usec = 10000;

		r = select(FD_SETSIZE, &fds, NULL, NULL, &timeout);

		if (r < 0)
			continue;

		if (route_fd > 0 && FD_ISSET(route_fd, &fds)) {
			nll = route_recv(route_fd, la.nl_groups);
			route_read(nll);
		}

	}


	/* Close socket */
	if (route_fd > 0)
		close(route_fd);
	route_fd = -1;
	OFP_DBG("Netlink server exiting");
	return 0;
}
