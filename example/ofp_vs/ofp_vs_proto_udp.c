/*
 * ip_vs_proto_udp.c:	UDP load balancing support for IPVS
 *
 * Authors:     Wensong Zhang <wensong@linuxvirtualserver.org>
 *              Julian Anastasov <ja@ssi.bg>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Changes:
 *
 */

#define KMSG_COMPONENT "IPVS"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include "ofp_vs.h"
#include "net/ip_vs.h"

static struct ip_vs_conn *udp_conn_in_get(int af, const struct rte_mbuf *skb,
					  struct ip_vs_protocol *pp,
					  const struct ip_vs_iphdr *iph,
					  unsigned int proto_off, int inverse,
					  int *res_dir)
{
	__be16 *pptr;
	(void)pp;

	pptr = rte_pktmbuf_mtod_offset(skb, __be16 *,
			sizeof(struct ether_hdr) + proto_off);
	if (pptr == NULL)
		return NULL;

	if (likely(!inverse)) {
		return ip_vs_conn_get(af, iph->protocol,
				      &iph->saddr, pptr[0],
				      &iph->daddr, pptr[1], res_dir);
	} else {
		return ip_vs_conn_get(af, iph->protocol,
				      &iph->daddr, pptr[1],
				      &iph->saddr, pptr[0], res_dir);
	}
}

static struct ip_vs_conn *udp_conn_out_get(int af, const struct rte_mbuf *skb,
					   struct ip_vs_protocol *pp,
					   const struct ip_vs_iphdr *iph,
					   unsigned int proto_off, int inverse,
					   int *res_dir)
{
	__be16 *pptr;
	(void)pp;

	pptr = rte_pktmbuf_mtod_offset(skb, __be16 *,
			sizeof(struct ether_hdr) + proto_off);
	if (pptr == NULL)
		return NULL;

	if (likely(!inverse)) {
		return ip_vs_conn_get(af, iph->protocol,
				      &iph->saddr, pptr[0],
				      &iph->daddr, pptr[1], res_dir);
	} else {
		return ip_vs_conn_get(af, iph->protocol,
				      &iph->daddr, pptr[1],
				      &iph->saddr, pptr[0], res_dir);
	}
}

static int
udp_conn_schedule(int af, struct rte_mbuf *skb, struct ip_vs_protocol *pp,
		  int *verdict, struct ip_vs_conn **cpp, int fwmark)
{
	struct ip_vs_service *svc;
	struct iphdr *ih = ip_hdr(skb);
	struct udphdr *uh = udp_hdr(ih);
	struct ip_vs_iphdr iph;

	ip_vs_fill_iphdr(af, ih, &iph);

	if (uh == NULL) {
		*verdict = NF_DROP;
		return 0;
	}

	svc = ip_vs_service_get(af, fwmark, iph.protocol,
				&iph.daddr, uh->dest);
	if (svc) {
		if (ip_vs_todrop()) {
			/*
			 * It seems that we are very loaded.
			 * We have to drop this packet :(
			 */
			ip_vs_service_put(svc);
			*verdict = NF_DROP;
			return 0;
		}

		/*
		 * Let the virtual server select a real server for the
		 * incoming connection, and create a connection entry.
		 */
		*cpp = ip_vs_schedule(svc, skb, 0);
		if (!*cpp) {
			*verdict = ip_vs_leave(svc, skb, pp);
			return 0;
		}
		ip_vs_service_put(svc);
	}
	return 1;
}

static int
udp_snat_handler(struct rte_mbuf *skb,
		 struct ip_vs_protocol *pp, struct ip_vs_conn *cp)
{
	struct iphdr *iph = ip_hdr(skb);
	struct udphdr *udph = udp_hdr(iph);
	(void)pp;

	udph->source = cp->vport;
	udph->dest = cp->cport;

	if (sysctl_ip_vs_csum_offload) {
		skb->ol_flags |= PKT_TX_TCP_CKSUM;
		udph->check = rte_ipv4_phdr_cksum((struct ipv4_hdr *)iph,
						skb->ol_flags);	
	} else {
		udph->check = 0;
		udph->check = ofp_vs_ipv4_udptcp_cksum(iph, udph);
	}

	return 1;
}

static int
udp_dnat_handler(struct rte_mbuf *skb,
		 struct ip_vs_protocol *pp, struct ip_vs_conn *cp)
{
	struct iphdr *iph = ip_hdr(skb);
	struct udphdr *udph = udp_hdr(iph);
	(void)pp;

	udph->source = cp->lport;
	udph->dest = cp->dport;

	if (sysctl_ip_vs_csum_offload) {
		skb->ol_flags |= PKT_TX_TCP_CKSUM;
		udph->check = rte_ipv4_phdr_cksum((struct ipv4_hdr *)iph,
						skb->ol_flags);	
	} else {
		udph->check = 0;
		udph->check = ofp_vs_ipv4_udptcp_cksum(iph, udph);
	}
	return 1;
}


static int udp_timeouts[IP_VS_UDP_S_LAST + 1] = {
	[IP_VS_UDP_S_NORMAL] = 5 * HZ,
	[IP_VS_UDP_S_LAST] = 2 * HZ,
};

static const char *const udp_state_name_table[IP_VS_UDP_S_LAST + 1] = {
	[IP_VS_UDP_S_NORMAL] = "UDP",
	[IP_VS_UDP_S_LAST] = "BUG!",
};

static int udp_set_state_timeout(struct ip_vs_protocol *pp, char *sname, int to)
{
	return ip_vs_set_state_timeout(pp->timeout_table, IP_VS_UDP_S_LAST,
				       udp_state_name_table, sname, to);
}

static const char *udp_state_name(int state)
{
	if (state >= IP_VS_UDP_S_LAST)
		return "ERR!";
	return udp_state_name_table[state] ? udp_state_name_table[state] : "?";
}

static int
udp_state_transition(struct ip_vs_conn *cp, int direction,
		     const struct rte_mbuf *skb, struct ip_vs_protocol *pp)
{
	(void)skb;
	(void)direction;
	cp->timeout = pp->timeout_table[IP_VS_UDP_S_NORMAL];
	return 1;
}

static void udp_init(struct ip_vs_protocol *pp)
{
	pp->timeout_table = udp_timeouts;
}

static void udp_exit(struct ip_vs_protocol *pp)
{
	(void)pp;
}

struct ip_vs_protocol ip_vs_protocol_udp = {
	.name = "UDP",
	.protocol = IPPROTO_UDP,
	.num_states = IP_VS_UDP_S_LAST,
	.dont_defrag = 0,
	.init = udp_init,
	.exit = udp_exit,
	.conn_schedule = udp_conn_schedule,
	.conn_in_get = udp_conn_in_get,
	.conn_out_get = udp_conn_out_get,
	.snat_handler = udp_snat_handler,
	.dnat_handler = udp_dnat_handler,
	.fnat_out_handler = udp_snat_handler,
	.fnat_in_handler = udp_dnat_handler,
	.state_transition = udp_state_transition,
	.state_name = udp_state_name,
	.debug_packet = ip_vs_tcpudp_debug_packet,
	.timeout_change = NULL,
	.set_state_timeout = udp_set_state_timeout,
};
