/*
 * ip_vs_xmit.c: various packet transmitters for IPVS
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

static inline void
ipv4_cksum(struct iphdr *iphdr, struct rte_mbuf *skb)
{
	struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(skb, struct ether_hdr *);
	uint16_t ethertype;

	iphdr->check = 0;
	if (sysctl_ip_vs_csum_offload) {
		/* Use hardware csum offload */
		//skb->ol_flags |= PKT_TX_OUTER_IP_CKSUM;
		//skb->ol_flags |= PKT_TX_OUTER_IPV4;
		skb->ol_flags |= PKT_TX_IPV4;
		skb->ol_flags |= PKT_TX_IP_CKSUM;
		skb->l3_len = ip_hdrlen(iphdr);
		skb->l2_len = sizeof(struct ether_hdr);
		ethertype = rte_be_to_cpu_16(eth_hdr->ether_type);
		//skb->outer_l3_len = ip_hdrlen(iphdr);
		//skb->outer_l2_len = sizeof(struct ether_hdr);

		if (ethertype == ETHER_TYPE_VLAN) {
			skb->l2_len  += sizeof(struct vlan_hdr);
		}
	} else {
		iphdr->check = ofp_vs_ipv4_cksum(iphdr);
	}
}

/* just for fullnat mode */
static int
ip_vs_fast_xmit(struct rte_mbuf *skb, struct ip_vs_protocol *pp,
		struct ip_vs_conn *cp)
{
	(void)skb;
	(void)pp;
	(void)cp;
	return -1;
}

static int
ip_vs_fast_response_xmit(struct rte_mbuf *skb,
			 struct ip_vs_protocol *pp,
			 struct ip_vs_conn *cp)
{
	(void)skb;
	(void)pp;
	(void)cp;
	return -1;
}

/*
 *      FULLNAT transmitter (only for outside-to-inside fullnat forwarding)
 *      Not used for related ICMP
 */
int
ip_vs_fnat_xmit(struct rte_mbuf *skb, struct ip_vs_conn *cp,
		struct ip_vs_protocol *pp)
{
	struct iphdr *iphdr = ip_hdr(skb);
	
	EnterFunction(10);
	/* check if it is a connection of no-client-port */
	if (unlikely(cp->flags & IP_VS_CONN_F_NO_CPORT)) {
		__be16 *p;
		p = (__be16 *)((unsigned char *)iphdr + iphdr->ihl * 4);
		if (p == NULL)
			goto tx_error;
		ip_vs_conn_fill_cport(cp, *p);
		IP_VS_DBG(10, "filled cport=%d\n", ntohs(*p));
	}

	//ip_vs_save_xmit_outside_info(skb, cp);

	if (sysctl_ip_vs_fast_xmit_inside && !ip_vs_fast_xmit(skb, pp, cp))
		return NF_STOLEN;

	iphdr->saddr = cp->laddr.ip;
	iphdr->daddr = cp->daddr.ip;

	ipv4_cksum(iphdr, skb);

	if (pp->fnat_in_handler && !pp->fnat_in_handler(skb, pp, cp))
		goto tx_error;
	
	LeaveFunction(10);
	return ofp_ip_output((odp_packet_t)skb, NULL);
		
tx_error:
	LeaveFunction(10);
	return NF_DROP;
}

/* Response transmit to client
 * Used for FULLNAT.
 */
int
ip_vs_fnat_response_xmit(struct rte_mbuf *skb, struct ip_vs_protocol *pp,
			 struct ip_vs_conn *cp, int ihl)
{
	struct iphdr *iphdr = ip_hdr(skb);
	(void)ihl;

	EnterFunction(10);

	//ip_vs_save_xmit_inside_info(skb, cp);

	if (sysctl_ip_vs_fast_xmit &&
	    !ip_vs_fast_response_xmit(skb, pp, cp))
		return NF_STOLEN;
		
	iphdr->saddr = cp->vaddr.ip;
	iphdr->daddr = cp->caddr.ip;
	ipv4_cksum(iphdr, skb);

	if (pp->fnat_out_handler && !pp->fnat_out_handler(skb, pp, cp))
			goto err;
	
	LeaveFunction(10);
	return ofp_ip_output((odp_packet_t)skb, NULL);

err:
	LeaveFunction(10);
	return NF_DROP;
}

int
ip_vs_nat_xmit(struct rte_mbuf *skb, struct ip_vs_conn *cp,
	       struct ip_vs_protocol *pp)
{
	struct iphdr *iphdr = ip_hdr(skb);

	EnterFunction(10);

	/* check if it is a connection of no-client-port */
	if (unlikely(cp->flags & IP_VS_CONN_F_NO_CPORT)) {
		__be16 *p;
		p = (__be16 *)((unsigned char *)iphdr + iphdr->ihl * 4);
		if (p == NULL)
			goto tx_error;
		ip_vs_conn_fill_cport(cp, *p);
		IP_VS_DBG(10, "filled cport=%d\n", ntohs(*p));
	}

	
	iphdr->daddr = cp->daddr.ip;

	ipv4_cksum(iphdr, skb);

	/* mangle the packet */
	if (pp->dnat_handler && !pp->dnat_handler(skb, pp, cp))
		goto tx_error;

	IP_VS_DBG_PKT(10, pp, skb, 0, "After DNAT");


	LeaveFunction(10);
	
	return ofp_ip_output((odp_packet_t)skb, NULL);

tx_error:
	LeaveFunction(10);
	return NF_DROP;
}

/* Response transmit to client
 * Used for NAT/Local.
 */
int
ip_vs_normal_response_xmit(struct rte_mbuf *skb, struct ip_vs_protocol *pp,
			   struct ip_vs_conn *cp, int ihl)
{
	struct iphdr *iphdr = ip_hdr(skb);
	(void)ihl;

	EnterFunction(10);

	iphdr->saddr = cp->vaddr.ip;

	ipv4_cksum(iphdr, skb);

	/* mangle the packet */
	if (pp->snat_handler && !pp->snat_handler(skb, pp, cp))
		goto drop;

	return ofp_ip_output((odp_packet_t)skb, NULL);

drop:
	LeaveFunction(10);
	return NF_DROP;
}

/*
 *      Direct Routing transmitter
 *      Used for ANY protocol
 */
int
ip_vs_dr_xmit(struct rte_mbuf *skb, struct ip_vs_conn *cp,
	      struct ip_vs_protocol *pp)
{
	int ret;
	uint32_t flags;
	uint32_t vrf;
	struct ofp_ifnet *send_ctx = odp_packet_user_ptr((odp_packet_t)skb);
	struct ofp_nh_entry *nh;
	(void)pp;

	EnterFunction(10);

	vrf = send_ctx ? send_ctx->vrf : 0;
	nh = ofp_get_next_hop(vrf, cp->daddr.ip, &flags);
	if (!nh)
		goto drop;;

	if (!nh->gw)
		nh->gw = cp->daddr.ip;

	ret = ofp_ip_output((odp_packet_t)skb, nh);
	IP_VS_DBG(12, "ofp_ip_output dst:"
			  PRINT_IP_FORMAT" gw:"
			  PRINT_IP_FORMAT
			  " port:%d vlan:%d return %d\n",
		      PRINT_NIP(cp->dest->addr.ip),
		      PRINT_NIP(nh->gw), nh->port, nh->vlan, ret);
	LeaveFunction(10);
	return ret;	

drop:
	LeaveFunction(10);
	return NF_DROP;
}
