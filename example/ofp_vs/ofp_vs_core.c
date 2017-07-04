/*
 * Copyright (c) 2016, lvsgate@163.com
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <getopt.h>
#include <string.h>
#include <signal.h>

#include "ofp.h"

#include "ofp_vs.h"

const char *ip_vs_proto_name(unsigned proto)
{
	static char buf[20];

	switch (proto) {
	case IPPROTO_IP:
		return "IP";
	case IPPROTO_UDP:
		return "UDP";
	case IPPROTO_TCP:
		return "TCP";
	case IPPROTO_ICMP:
		return "ICMP";
#ifdef CONFIG_IP_VS_IPV6
	case IPPROTO_ICMPV6:
		return "ICMPv6";
#endif
	default:
		sprintf(buf, "IP_%d", proto);
		return buf;
	}
}


/*
 *	Handle ICMP messages in the outside-to-inside direction (incoming).
 *	Find any that might be relevant, check against existing connections,
 *	forward to the right destination host if relevant.
 *	Currently handles error types - unreachable, quench, ttl exceeded.
 */

static inline int
ip_vs_set_state(struct ip_vs_conn *cp, int direction,
		const struct rte_mbuf *skb, struct ip_vs_protocol *pp)
{
	if (unlikely(!pp->state_transition))
		return 0;
	return pp->state_transition(cp, direction, skb, pp);
}


static int
ip_vs_in_icmp(struct rte_mbuf *skb, int *related)
{
	(void)skb;
	*related = 0;
	return NF_ACCEPT;
}



/* Handle response packets: rewrite addresses and send away...
 * Used for NAT / local client / FULLNAT.
 */
static inline unsigned int
handle_response(int af, struct rte_mbuf *skb, struct ip_vs_protocol *pp,
		struct ip_vs_conn *cp, int ihl)
{
	int ret = NF_DROP;
	(void)af;

	/* statistics */
	ip_vs_out_stats(cp, skb);

	/*
	 * Syn-proxy step 3 logic: receive syn-ack from rs.
	 */
	/*
	if ((cp->flags & IP_VS_CONN_F_SYNPROXY) &&
		(cp->state == IP_VS_TCP_S_SYNPROXY) &&
		(ip_vs_synproxy_synack_rcv(skb, cp, pp, ihl, &ret) == 0)) {
		goto out;
	}
	*/

	/* state transition */
	ip_vs_set_state(cp, IP_VS_DIR_OUTPUT, skb, pp);
	/* transmit */

	if (cp->flags & IP_VS_CONN_F_FULLNAT) {
		ret = ip_vs_fnat_response_xmit(skb, pp, cp, ihl);
	} else {
		ret = ip_vs_normal_response_xmit(skb, pp, cp, ihl);
	}

//out:
	ip_vs_conn_put(cp);
	return ret;
}

static inline __u16
ip_vs_onepacket_enabled(struct ip_vs_service *svc, struct ip_vs_iphdr *iph)
{
	return (svc->flags & IP_VS_SVC_F_ONEPACKET
		&& iph->protocol == IPPROTO_UDP)
	    ? IP_VS_CONN_F_ONE_PACKET : 0;
}

/*
 *  IPVS main scheduling function
 *  It selects a server according to the virtual service, and
 *  creates a connection entry.
 *  Protocols supported: TCP, UDP
 */
struct ip_vs_conn *ip_vs_schedule(struct ip_vs_service *svc,
				  struct rte_mbuf *skb, int is_synproxy_on)
{
	struct ip_vs_conn *cp = NULL;
	struct ip_vs_iphdr iph;
	struct ip_vs_dest *dest;
	__be16 *pptr;

	ip_vs_fill_iphdr(svc->af, ip_hdr(skb), &iph);
	pptr = rte_pktmbuf_mtod_offset(skb, __be16 *,
			sizeof(struct ether_hdr) + iph.len);
	if (pptr == NULL)
		return NULL;

	/*
	 *    Persistent service
	 */
	/*
	if (svc->flags & IP_VS_SVC_F_PERSISTENT)
		return ip_vs_sched_persist(svc, skb, pptr, is_synproxy_on);
	*/

	/*
	 *    Non-persistent service
	 */
	if (!svc->fwmark && pptr[1] != svc->port) {
		if (!svc->port)
			pr_err("Schedule: port zero only supported "
			       "in persistent services, "
			       "check your ipvs configuration\n");
		return NULL;
	}

	dest = svc->scheduler->schedule(svc, skb);
	if (dest == NULL) {
		IP_VS_DBG(1, "Schedule: no dest found.\n");
		return NULL;
	}

	/*
	 *    Create a connection entry.
	 */
	if (IS_SNAT_SVC(svc))
		cp = ip_vs_conn_new(svc->af, iph.protocol,
				    &iph.saddr, pptr[0],
				    &iph.daddr, pptr[1],
				    &iph.daddr, pptr[1],
				    ip_vs_onepacket_enabled(svc, &iph),
				    dest, skb, is_synproxy_on);
	else
		cp = ip_vs_conn_new(svc->af, iph.protocol,
				    &iph.saddr, pptr[0],
				    &iph.daddr, pptr[1],
				    &dest->addr,
				    dest->port ? dest->port : pptr[1],
				    ip_vs_onepacket_enabled(svc, &iph),
				    dest, skb, is_synproxy_on);

	if (cp == NULL)
		return NULL;

	IP_VS_DBG_BUF(6, "Schedule fwd:%c c:%s:%u v:%s:%u l:%s:%u "
		      "d:%s:%u conn->flags:%X conn->refcnt:%d cpu%d\n",
		      ip_vs_fwd_tag(cp),
		      IP_VS_DBG_ADDR(svc->af, &cp->caddr), ntohs(cp->cport),
		      IP_VS_DBG_ADDR(svc->af, &cp->vaddr), ntohs(cp->vport),
		      IP_VS_DBG_ADDR(svc->af, &cp->laddr), ntohs(cp->lport),
		      IP_VS_DBG_ADDR(svc->af, &cp->daddr), ntohs(cp->dport),
		      cp->flags, atomic_read(&cp->refcnt), cp->cpuid);

	ip_vs_conn_stats(cp, svc);
	return cp;
}

/*
 *  Pass or drop the packet.
 *  Called by ip_vs_in, when the virtual service is available but
 *  no destination is available for a new connection.
 */
int ip_vs_leave(struct ip_vs_service *svc, struct rte_mbuf *skb,
		struct ip_vs_protocol *pp)
{
	__be16 *pptr;
	struct ip_vs_iphdr iph;
	(void)pp;

	ip_vs_fill_iphdr(svc->af, ip_hdr(skb), &iph);

	pptr = rte_pktmbuf_mtod_offset(skb, __be16 *,
			sizeof(struct ether_hdr) + iph.len);
	if (pptr == NULL) {
		ip_vs_service_put(svc);
		return NF_DROP;
	}

	/*
	 * When the virtual ftp service is presented, packets destined
	 * for other services on the VIP may get here (except services
	 * listed in the ipvs table), pass the packets, because it is
	 * not ipvs job to decide to drop the packets.
	 */
	if ((svc->port == FTPPORT) && (pptr[1] != FTPPORT)) {
		ip_vs_service_put(svc);
		return NF_ACCEPT;
	}

	ip_vs_service_put(svc);

	/*
	 * Notify the client that the destination is unreachable, and
	 * release the socket buffer.
	 * Since it is in IP layer, the TCP socket is not actually
	 * created, the TCP RST packet cannot be sent, instead that
	 * ICMP_PORT_UNREACH is sent here no matter it is TCP/UDP. --WZ
	 */
#ifdef CONFIG_IP_VS_IPV6
	if (svc->af == AF_INET6)
		icmpv6_send(skb, ICMPV6_DEST_UNREACH, ICMPV6_PORT_UNREACH, 0,
			    skb->dev);
	else
#endif
		//icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);

	IP_VS_INC_ESTATS(ip_vs_esmib, CONN_SCHED_UNREACH);

	return NF_DROP;
}

enum ofp_return_code ofp_vs_in(odp_packet_t pkt, void *arg)
{
	struct rte_mbuf *skb = (struct rte_mbuf *)pkt;
	struct iphdr *iphdr;
	struct ip_vs_iphdr iph;
	struct ip_vs_protocol *pp;
	struct ip_vs_conn *cp;
	int ret, af;
	int res_dir;
	int tot_len;
	(void)arg;

	/* Only support IPV4 */
    	if(!RTE_ETH_IS_IPV4_HDR(skb->packet_type))
		return NF_ACCEPT;

	af = AF_INET;
	iphdr = rte_pktmbuf_mtod_offset(skb, struct iphdr *,
					sizeof(struct ether_hdr));

	tot_len = rte_be_to_cpu_16(iphdr->tot_len);
	if (tot_len > skb->data_len || tot_len < ip_hdrlen(iphdr)) {
		return NF_DROP;
	}

	ip_vs_fill_iphdr(af, iphdr, &iph);

	if (unlikely(iph.protocol == IPPROTO_ICMP)) {
		int related, verdict = ip_vs_in_icmp(skb, &related);

		if (related)
			return verdict;
		ip_vs_fill_iphdr(af, iphdr, &iph);
	}

	
	/* Protocol supported? */
	pp = ip_vs_proto_get(iph.protocol);
	if (unlikely(!pp))
		return NF_ACCEPT;

	/*
	 * Check if the packet belongs to an existing connection entry
	 */
	cp = pp->conn_in_get(af, skb, pp, &iph, iph.len, 0, &res_dir);

	if (likely(cp != NULL)) {
		/* For full-nat/local-client packets, it could be a response */
		if (res_dir == IP_VS_CIDX_F_IN2OUT) {
			return handle_response(af, skb, pp, cp, iph.len);
		}
	} else {
		/* create a new connection */
		int v;

		if (!pp->conn_schedule(af, skb, pp, &v, &cp, 0))
			return v;
	}

	if (unlikely(!cp)) {
		/* sorry, all this trouble for a no-hit :) */
		IP_VS_DBG_PKT(12, pp, skb, 0,
			      "packet continues traversal as normal");
		return NF_ACCEPT;
	}

	IP_VS_DBG_PKT(11, pp, skb, 0, "Incoming packet");

	/* Check the server status */
	if (cp->dest && !(cp->dest->flags & IP_VS_DEST_F_AVAILABLE)) {
		/* the destination server is not available */

		if (sysctl_ip_vs_expire_nodest_conn) {
			/* try to expire the connection immediately */
			ip_vs_conn_expire_now(cp);
		}
		/* don't restart its timer, and silently
		   drop the packet. */
		__ip_vs_conn_put(cp);
		return NF_DROP;
	}

	ip_vs_in_stats(cp, skb);

	/*
	 * Filter out-in ack packet when cp is at SYN_SENT state.
	 * DROP it if not a valid packet, STORE it if we have 
	 * space left. 
	 */
	/*
	if ((cp->flags & IP_VS_CONN_F_SYNPROXY) &&
	    (0 == ip_vs_synproxy_filter_ack(skb, cp, pp, &iph, &v))) {
		ip_vs_conn_put(cp);
		return v;
	}
	*/

	/*
	 * "Reuse" syn-proxy sessions.
	 * "Reuse" means update syn_proxy_seq struct and clean ack_skb etc.
	 */
	/*
	if ((cp->flags & IP_VS_CONN_F_SYNPROXY) &&
	    (0 != sysctl_ip_vs_synproxy_conn_reuse)) {
		int v = NF_DROP;

		if (0 == ip_vs_synproxy_reuse_conn(af, skb, cp, pp, &iph, &v)) {
			ip_vs_conn_put(cp);
			return v;
		}
	}
	*/

	ip_vs_set_state(cp, IP_VS_DIR_INPUT, skb, pp);
	if (cp->packet_xmit)
		ret = cp->packet_xmit(skb, cp, pp);
	/* do not touch skb anymore */
	else {
		IP_VS_DBG_RL("warning: packet_xmit is null");
		ret = NF_ACCEPT;
	}

	cp->old_state = cp->state;

	ip_vs_conn_put(cp);
	return ret;
}

static unsigned int
ip_vs_snat_out(int af, struct rte_mbuf *skb, struct ip_vs_protocol *pp,
	int *v, struct ip_vs_conn *cp, struct ofp_nh_entry *nh)
{
	if (af != AF_INET)
		return 1;

	if (cp && NOT_SNAT_CP(cp))
		return 1;

	EnterFunction(1);
	if (!cp) {
		skb->userdata = nh;
		if (!pp->conn_schedule(af, skb, pp, v, &cp, 1))
			return 0;

		if (unlikely(!cp)) {
			IP_VS_DBG_PKT(12, pp, skb, 0,
			              "packet continues traversal as normal");
			*v = NF_ACCEPT;
			return 0;
		}
	}

	IP_VS_DBG_PKT(11, pp, skb, 0, "Forward packet");
	ip_vs_in_stats(cp, skb);

	ip_vs_set_state(cp, IP_VS_DIR_INPUT, skb, pp);

	if (cp->packet_xmit)
		*v = cp->packet_xmit(skb, cp, pp);
		/* do not touch skb anymore */
	else {
		IP_VS_DBG_RL("warning: packet_xmit is null");
		*v = NF_ACCEPT;
	}

	cp->old_state = cp->state;
	ip_vs_conn_put(cp);
	return 0;
}

enum ofp_return_code ofp_vs_out(odp_packet_t pkt, void *arg)
{
	struct ofp_nh_entry *nh = (struct ofp_nh_entry *)arg;
	struct rte_mbuf *skb = (struct rte_mbuf *)pkt;
	struct iphdr *iphdr;
	struct ip_vs_iphdr iph;
	struct ip_vs_protocol *pp;
	struct ip_vs_conn *cp;
	int af;
	int res_dir;
	int verdict;

	/* Only support IPV4 */
    	if(!RTE_ETH_IS_IPV4_HDR(skb->packet_type))
		return NF_ACCEPT;	

	af = AF_INET;
	iphdr = rte_pktmbuf_mtod_offset(skb, struct iphdr *,
					sizeof(struct ether_hdr));
	ip_vs_fill_iphdr(af, iphdr, &iph);

	pp = ip_vs_proto_get(iph.protocol);
	if (unlikely(!pp))
		return NF_ACCEPT;

	/*
	 * Check if the packet belongs to an existing entry
	 */
	cp = pp->conn_out_get(af, skb, pp, &iph, iph.len, 0, &res_dir);

	if (0 == ip_vs_snat_out(af, skb, pp, &verdict, cp, nh)) {
		return verdict;
	}

	return handle_response(af, skb, pp, cp, iph.len);
}

int ofp_vs_init(odp_instance_t instance, ofp_init_global_t *app_init_params)
{
	int ret;
	
		
	if ((ret = ofp_vs_timer_init()) < 0) {
		OFP_ERR("ofp_vs_timer_init %s %d\n", strerror(ret), ret);
		return ret;
	}

	if ((ret = ofp_vs_ctl_init(instance, app_init_params)) < 0) {
		OFP_ERR("ofp_vs_ctl_init %s %d\n", strerror(ret), ret);
		return ret;
	}

	if ((ret = ip_vs_protocol_init() < 0)) {
		OFP_ERR("ip_vs_protocol_init %s %d\n", strerror(ret), ret);
		return ret;
	}

	if ((ret = ip_vs_conn_init()) < 0) {
		OFP_ERR("ip_vs_conn_init %s %d\n", strerror(ret), ret);
		return ret;
	}
	
	if ((ret = ip_vs_rr_init()) < 0) {
		OFP_ERR("ip_vs_rr_init failed %d\n", ret);
		return ret;
	}

	if ((ret = ip_vs_snat_init()) < 0) {
		OFP_ERR("ip_vs_snat_init failed %d\n", ret);
		return ret;
	}


	return ret;
}

void ofp_vs_finish(void)
{
	ip_vs_rr_cleanup();
	ip_vs_snat_cleanup();
	ip_vs_protocol_cleanup();
	ip_vs_conn_cleanup();
	ofp_vs_ctl_finish();
	ofp_vs_timer_finish();
}
