/*
 * IPVS         An implementation of the IP virtual server support for the
 *              LINUX operating system.  IPVS is now implemented as a module
 *              over the NetFilter framework. IPVS can be used to build a
 *              high-performance and highly available server based on a
 *              cluster of servers.
 *
 * Authors:     Wensong Zhang <wensong@linuxvirtualserver.org>
 *              Peter Kese <peter.kese@ijs.si>
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

static struct ip_vs_conn *tcp_conn_in_get(int af, const struct rte_mbuf *skb,
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

static struct ip_vs_conn *tcp_conn_out_get(int af, const struct rte_mbuf *skb,
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
tcp_conn_schedule(int af, struct rte_mbuf *skb, struct ip_vs_protocol *pp,
		  int *verdict, struct ip_vs_conn **cpp, int fwmark)
{
	struct ip_vs_service *svc;
	struct iphdr *ih = ip_hdr(skb);
	struct tcphdr *th = tcp_hdr(ih);
	struct ip_vs_iphdr iph;

	ip_vs_fill_iphdr(af, ih, &iph);

	if (th == NULL) {
		*verdict = NF_DROP;
		return 0;
	}

	/*
	 * Syn-proxy step 2 logic: receive client's
	 * 3-handshake Ack packet
	 */
	/*
	if (ip_vs_synproxy_ack_rcv(af, skb, th, pp, cpp, &iph, verdict) == 0) {
		return 0;
	}
	*/

	if (th->syn && !th->ack && !th->fin && !th->rst &&
	    (svc = ip_vs_service_get(af, fwmark, iph.protocol, &iph.daddr,
				     th->dest))) {
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

		/*
		 * Set private establish state timeout into cp from svc,
		 * due cp may use its user establish state timeout
		 * different from sysctl_ip_vs_tcp_timeouts
		 */
		(*cpp)->est_timeout = svc->est_timeout;

		ip_vs_service_put(svc);
		return 1;
	}

	/* drop tcp packet which send to vip and !vport */
	if (sysctl_ip_vs_tcp_drop_entry &&
	    (svc = ip_vs_lookup_vip(af, iph.protocol, &iph.daddr))) {
		IP_VS_INC_ESTATS(ip_vs_esmib, DEFENCE_TCP_DROP);
		*verdict = NF_DROP;
		return 0;
	}

	return 1;
}

static inline void
tcp_mss_csum_update(struct tcphdr *tcph, __be16 oldmss, __be16 newmss)
{
	(void)tcph;
	(void)oldmss;
	(void)newmss;
}

/* adjust tcp opt mss, sub TCPOLEN_CIP */
static void tcp_opt_adjust_mss(int af, struct tcphdr *tcph)
{
	unsigned char *ptr;
	int length;
	(void)af;

	if (sysctl_ip_vs_mss_adjust_entry == 0)
		return;

	ptr = (unsigned char *)(tcph + 1);
	length = (tcph->doff * 4) - sizeof(struct tcphdr);

	while (length > 0) {
		int opcode = *ptr++;
		int opsize;

		switch (opcode) {
		case TCPOPT_EOL:
			return;
		case TCPOPT_NOP:	/* Ref: RFC 793 section 3.1 */
			length--;
			continue;
		default:
			opsize = *ptr++;
			if (opsize < 2)	/* "silly options" */
				return;
			if (opsize > length)
				return;	/* don't parse partial options */
			if ((opcode == TCPOPT_MSS) && (opsize == TCPOLEN_MSS)) {
				__be16 old = *(__be16 *) ptr;
				__u16 in_mss = ntohs(*(__be16 *) ptr);
#ifdef CONFIG_IP_VS_IPV6
				if (af == AF_INET6)
					in_mss -= TCPOLEN_ADDR_V6;
				else
#endif
					in_mss -= TCPOLEN_ADDR;
				/* set mss, 16bit */
				*((__be16 *) ptr) = htons(in_mss);
				tcp_mss_csum_update(tcph, old, *(__be16 *)ptr);
				return;
			}

			ptr += opsize - 2;
			length -= opsize;
		}
	}
}

/* save tcp sequense for fullnat/nat, INside to OUTside */
static void
tcp_save_out_seq(struct rte_mbuf *skb, struct ip_vs_conn *cp,
		 struct tcphdr *th, int ihl)
{
	if (unlikely(th == NULL) || unlikely(cp == NULL) ||
	    unlikely(skb == NULL))
		return;

	if (sysctl_ip_vs_conn_expire_tcp_rst && !th->rst) {

		/* seq out of order. just skip */
		if (before(ntohl(th->ack_seq), ntohl(cp->rs_ack_seq)) &&
							(cp->rs_ack_seq != 0))
			return;

		if (th->syn && th->ack)
			cp->rs_end_seq = htonl(ntohl(th->seq) + 1);
		else
			cp->rs_end_seq = htonl(ntohl(th->seq) + skb->data_len
					       - ihl - (th->doff << 2));
		cp->rs_ack_seq = th->ack_seq;
		IP_VS_DBG_RL("packet from RS, seq:%u ack_seq:%u.",
			     ntohl(th->seq), ntohl(th->ack_seq));
		IP_VS_DBG_RL("port:%u->%u", ntohs(th->source), ntohs(th->dest));
	}
}

static inline void
tcp_seq_csum_update(struct tcphdr *tcph, __u32 oldseq, __u32 newseq)
{
	(void)tcph;
	(void)oldseq;
	(void)newseq;
}

/*
 * 1. adjust tcp ack/sack sequence for FULL-NAT, INside to OUTside
 * 2. adjust tcp sequence for SYNPROXY, OUTside to INside
 */
static int tcp_out_adjust_seq(struct ip_vs_conn *cp, struct tcphdr *tcph)
{
	__u8 i;
	__u8 *ptr;
	int length;
	__be32 old_seq;

	/*
	 * Syn-proxy seq change, include tcp hdr and
	 * check ack storm.
	 */
	/*
	if (ip_vs_synproxy_snat_handler(tcph, cp) == 0) {
		return 0;
	}
	*/

	/*
	 * FULLNAT ack-seq change
	 */

	old_seq = tcph->ack_seq;
	/* adjust ack sequence */
	tcph->ack_seq = htonl(ntohl(tcph->ack_seq) - cp->fnat_seq.delta);
	/* update checksum */
	tcp_seq_csum_update(tcph, old_seq, tcph->ack_seq);

	/* adjust sack sequence */
	ptr = (__u8 *) (tcph + 1);
	length = (tcph->doff * 4) - sizeof(struct tcphdr);

	/* Fast path for timestamp-only option */
	if (length == TCPOLEN_TSTAMP_ALIGNED &&
		*(__be32 *) ptr == htonl((TCPOPT_NOP << 24) |
					(TCPOPT_NOP << 16) |
					(TCPOPT_TIMESTAMP << 8) |
					TCPOLEN_TIMESTAMP))
		return 1;

	while (length > 0) {
		int opcode = *ptr++;
		int opsize;

		switch (opcode) {
		case TCPOPT_EOL:
			return 1;
		case TCPOPT_NOP:	/* Ref: RFC 793 section 3.1 */
			length--;
			continue;
		default:
			opsize = *ptr++;
			if (opsize < 2)	/* "silly options" */
				return 1;
			if (opsize > length)
				return 1;	/* don't parse partial options */
			if ((opcode == TCPOPT_SACK) &&
			(opsize >= (TCPOLEN_SACK_BASE + TCPOLEN_SACK_PERBLOCK))
			&& !((opsize - TCPOLEN_SACK_BASE) %
						TCPOLEN_SACK_PERBLOCK)) {
				for (i = 0; i < opsize - TCPOLEN_SACK_BASE;
						i += TCPOLEN_SACK_PERBLOCK) {
					__be32 *tmp = (__be32 *) (ptr + i);
					old_seq = *tmp;
					*tmp = htonl(ntohl(*tmp) -
							cp->fnat_seq.delta);
					tcp_seq_csum_update(tcph, old_seq, *tmp);

					tmp++;

					old_seq = *tmp;
					*tmp = htonl(ntohl(*tmp) -
							cp->fnat_seq.delta);
					tcp_seq_csum_update(tcph, old_seq, *tmp);
				}
				return 1;
			}

			ptr += opsize - 2;
			length -= opsize;
		}
	}

	return 1;
}

/*
 * init first data sequence, INside to OUTside;
 */
static inline void
tcp_out_init_seq(struct ip_vs_conn *cp, struct tcphdr *tcph)
{
	cp->fnat_seq.fdata_seq = ntohl(tcph->seq) + 1;
}


static int
tcp_fnat_out_handler(struct rte_mbuf *skb,
		     struct ip_vs_protocol *pp, struct ip_vs_conn *cp)
{
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *tcph;
	unsigned int tcphoff;
	(void)pp;

#ifdef CONFIG_IP_VS_IPV6
	if (cp->af == AF_INET6)
		tcphoff = sizeof(struct ipv6hdr);
	else
#endif
		tcphoff = ip_hdrlen(iph);



	tcph = tcp_hdr(iph);
	tcp_save_out_seq(skb, cp, tcph, tcphoff);
	tcph->source = cp->vport;
	tcph->dest = cp->cport;

	/*
	 * for syn_ack
	 * 1. adjust tcp opt mss in rs->client
	 */
	if (tcph->syn && tcph->ack) {
		tcp_opt_adjust_mss(cp->af, tcph);
	}

	/* adjust tcp ack/sack sequence */
	if (tcp_out_adjust_seq(cp, tcph) == 0) {
		return 0;
	}

	/*
	 * for syn_ack
	 * 2. init sequence
	 */
	if (tcph->syn && tcph->ack) {
		tcp_out_init_seq(cp, tcph);
	}

	/* do csum later */
	tcph->check = 0;
	if (sysctl_ip_vs_csum_offload) {
		skb->ol_flags |= PKT_TX_TCP_CKSUM;
		tcph->check = rte_ipv4_phdr_cksum((struct ipv4_hdr *)iph,
					skb->ol_flags);
	} else {
		tcph->check = ofp_vs_ipv4_udptcp_cksum(iph, tcph);
	}

	IP_VS_DBG(11, "O-pkt: %s O-csum=%d (+%zd)\n",
		pp->name, tcph->check,
		(char *)&(tcph->check) - (char *)tcph);
	return 1;
}

/*
 * remove tcp timestamp opt in one packet, just set it to TCPOPT_NOP
 * reference to tcp_parse_options in tcp_input.c
 */
static void tcp_opt_remove_timestamp(struct tcphdr *tcph)
{
	(void)tcph;
	if (sysctl_ip_vs_timestamp_remove_entry == 0)
		return;
}

static u32 net_secret;

static int net_secret_init(void)
{
	return odp_random_data((uint8_t *)&net_secret, sizeof(net_secret), true);
}

static __u32 secure_tcp_sequence_number(__be32 saddr, __be32 daddr,
				 __be16 sport, __be16 dport)
{
	u32 hash[4];

	hash[0] = (u32)saddr;
	hash[1] = (u32)daddr;
	hash[2] = ((u16)sport << 16) + (u16)dport;
	hash[3] = net_secret;

	return rte_hash_crc((void *)hash, sizeof(hash), net_secret) + 
		((__u64)(1E6*(ofp_timer_ticks(0)/HZ)) >> 6);
}

/*
 * recompute tcp sequence, OUTside to INside;
 */
static void
tcp_in_init_seq(struct ip_vs_conn *cp, struct rte_mbuf *skb,
		struct tcphdr *tcph)
{
	struct ip_vs_seq *fseq = &(cp->fnat_seq);
	__u32 seq = ntohl(tcph->seq);
	int conn_reused_entry;
	(void)tcph;
	(void)skb;

	if ((fseq->delta == fseq->init_seq - seq) && (fseq->init_seq != 0)) {
		/* retransmit */
		return;
	}

	/* init syn seq, lvs2rs */
	conn_reused_entry = (sysctl_ip_vs_conn_reused_entry == 1)
	    && (fseq->init_seq != 0)
	    && ((cp->state == IP_VS_TCP_S_SYN_RECV)
		|| (cp->state == IP_VS_TCP_S_SYN_SENT));
	if ((fseq->init_seq == 0) || conn_reused_entry) {
#ifdef CONFIG_IP_VS_IPV6
		if (cp->af == AF_INET6)
			fseq->init_seq =
			    secure_tcpv6_sequence_number(cp->laddr.ip6,
							 cp->daddr.ip6,
							 cp->lport, cp->dport);
		else
#endif
			fseq->init_seq =
			    secure_tcp_sequence_number(cp->laddr.ip,
						       cp->daddr.ip, cp->lport,
						       cp->dport);
		fseq->delta = fseq->init_seq - seq;

		if (conn_reused_entry) {
			IP_VS_INC_ESTATS(ip_vs_esmib, FULLNAT_CONN_REUSED);
			switch (cp->old_state) {
			case IP_VS_TCP_S_CLOSE:
				IP_VS_INC_ESTATS(ip_vs_esmib,
						 FULLNAT_CONN_REUSED_CLOSE);
				break;
			case IP_VS_TCP_S_TIME_WAIT:
				IP_VS_INC_ESTATS(ip_vs_esmib,
						 FULLNAT_CONN_REUSED_TIMEWAIT);
				break;
			case IP_VS_TCP_S_FIN_WAIT:
				IP_VS_INC_ESTATS(ip_vs_esmib,
						 FULLNAT_CONN_REUSED_FINWAIT);
				break;
			case IP_VS_TCP_S_CLOSE_WAIT:
				IP_VS_INC_ESTATS(ip_vs_esmib,
						 FULLNAT_CONN_REUSED_CLOSEWAIT);
				break;
			case IP_VS_TCP_S_LAST_ACK:
				IP_VS_INC_ESTATS(ip_vs_esmib,
						 FULLNAT_CONN_REUSED_LASTACK);
				break;
			case IP_VS_TCP_S_ESTABLISHED:
				IP_VS_INC_ESTATS(ip_vs_esmib,
						 FULLNAT_CONN_REUSED_ESTAB);
				break;
			}
		}
	}
}
/* adjust tcp sequence, OUTside to INside */
static void tcp_in_adjust_seq(struct ip_vs_conn *cp, struct tcphdr *tcph)
{
	__be32 old_seq = tcph->seq;
	/* adjust seq for FULLNAT */
	tcph->seq = htonl(ntohl(tcph->seq) + cp->fnat_seq.delta);
	/* update checksum */
	tcp_seq_csum_update(tcph, old_seq, tcph->seq);

	/* adjust ack_seq for SYNPROXY, include tcp hdr and sack opt */
	//ip_vs_synproxy_dnat_handler(tcph, &cp->syn_proxy_seq);
}

/*
 * add client (ip and port) in tcp option
 * return 0 if success
 */
static int tcp_opt_add_toa(struct ip_vs_conn *cp,
		       struct rte_mbuf *skb,
		       struct tcphdr **tcph)
{
    __u16 mtu;
	struct ip_vs_tcpo_addr *toa;
    struct iphdr *iph;
	struct tcphdr *th;
	__u8 *p, *q;


    iph = ip_hdr(skb);
	th = tcp_hdr(iph);

	/* now only process IPV4 */
	if (cp->af != AF_INET) {
		IP_VS_INC_ESTATS(ip_vs_esmib, FULLNAT_ADD_TOA_FAIL_PROTO);
		return 1;
	}

	/* skb length and tcp option length checking */
    rte_eth_dev_get_mtu(skb->port, &mtu);

	if (rte_pktmbuf_data_len(skb) > (mtu - sizeof(struct ip_vs_tcpo_addr))) {
		IP_VS_INC_ESTATS(ip_vs_esmib, FULLNAT_ADD_TOA_FAIL_LEN);
		return 1;
	}

	/* the maximum length of TCP head is 60 bytes, so only 40 bytes for options */
	if ((60 - (th->doff << 2)) < (int)sizeof(struct ip_vs_tcpo_addr)) {
		IP_VS_INC_ESTATS(ip_vs_esmib, FULLNAT_ADD_TOA_HEAD_FULL);
		return 1;
	}

	/* expand skb if needed */
	if ((sizeof(struct ip_vs_tcpo_addr) > rte_pktmbuf_tailroom(skb)) &&
			rte_pktmbuf_append(skb, sizeof(struct ip_vs_tcpo_addr))){
		IP_VS_INC_ESTATS(ip_vs_esmib, FULLNAT_ADD_TOA_FAIL_MEM);
		return 1;
	}

	/*
	 * add client ip
	 */
    iph = ip_hdr(skb);
	*tcph = th = tcp_hdr(iph);

	/* ptr to old opts */
	p = (__u8 *)iph + iph->tot_len;
	q = (__u8 *)p + sizeof(struct ip_vs_tcpo_addr);

	/* move data down, offset is sizeof(struct ip_vs_tcpo_addr) */
	while (p >= ((__u8 *) th + sizeof(struct tcphdr))) {
		*q = *p;
		p--;
		q--;
	}

	/* put client ip opt , ptr point to opts */
	toa = (struct ip_vs_tcpo_addr *)(th + 1);
	toa->opcode = TCPOPT_ADDR;
	toa->opsize = TCPOLEN_ADDR;
	toa->port = cp->cport;
	toa->addr = cp->caddr.ip;

	/* reset tcp header length */
	th->doff += sizeof(struct ip_vs_tcpo_addr) / 4;
	/* reset ip header totoal length */
	iph->tot_len =
	    htons(ntohs(iph->tot_len) +
		  sizeof(struct ip_vs_tcpo_addr));
	/* reset skb length */
	skb->data_len += sizeof(struct ip_vs_tcpo_addr);
	skb->pkt_len += sizeof(struct ip_vs_tcpo_addr);




	IP_VS_INC_ESTATS(ip_vs_esmib, FULLNAT_ADD_TOA_OK);
	return 0;
}

static int
tcp_fnat_in_handler(struct rte_mbuf *skb,
		    struct ip_vs_protocol *pp, struct ip_vs_conn *cp)
{
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *tcph = tcp_hdr(iph);
	(void)pp;


	/*
	 * for syn packet
	 * 1. remove tcp timestamp opt,
	 *    because local address with diffrent client have the diffrent timestamp;
	 * 2. recompute tcp sequence
	 * 3. add toa
	 */
	if (tcph->syn & !tcph->ack) {
		tcp_opt_remove_timestamp(tcph);
		tcp_in_init_seq(cp, skb, tcph);
#ifdef CONFIG_IP_VS_IPV6
		if (cp->af == AF_INET6)
			tcp_opt_add_toa_v6(cp, skb, &tcph);
		else
#endif
			tcp_opt_add_toa(cp, skb, &tcph);
	}

	/* TOA: add client ip */
	if ((sysctl_ip_vs_toa_entry == 1)
	    && (ntohl(tcph->ack_seq) == cp->fnat_seq.fdata_seq)
	    && !tcph->syn && !tcph->rst && !tcph->fin) {
#ifdef CONFIG_IP_VS_IPV6
		if (cp->af == AF_INET6)
			tcp_opt_add_toa_v6(cp, skb, &tcph);
		else
#endif
			tcp_opt_add_toa(cp, skb, &tcph);
	}

	/*
	 * adjust tcp sequence, becase
	 * 1. FULLNAT: local address with diffrent client have the diffrent sequence
	 * 2. SYNPROXY: dont know rs->client synack sequence
	 */
	tcp_in_adjust_seq(cp, tcph);

	/* adjust src/dst port */
	tcph->source = cp->lport;
	tcph->dest = cp->dport;

	tcph->check = 0;
	if (sysctl_ip_vs_csum_offload) {
		skb->ol_flags |= PKT_TX_TCP_CKSUM;
		tcph->check = rte_ipv4_phdr_cksum((struct ipv4_hdr *)iph,
						skb->ol_flags);	
	} else {
		tcph->check = ofp_vs_ipv4_udptcp_cksum(iph, tcph);
	}

	return 1;
}

static int
tcp_dnat_handler(struct rte_mbuf *skb,
		 struct ip_vs_protocol *pp, struct ip_vs_conn *cp)
{
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *tcph = tcp_hdr(iph);
	(void)pp;

	tcph->dest = cp->dport;

	/*
	 * Syn-proxy ack_seq change, include tcp hdr and sack opt.
	 */
	//ip_vs_synproxy_dnat_handler(tcph, &cp->syn_proxy_seq);

	/*
	 *      Adjust TCP checksums
	 */
	if (sysctl_ip_vs_csum_offload) {
		skb->ol_flags |= PKT_TX_TCP_CKSUM;
		tcph->check = rte_ipv4_phdr_cksum((struct ipv4_hdr *)iph,
						skb->ol_flags);	
	} else {
		tcph->check = 0;
		tcph->check = ofp_vs_ipv4_udptcp_cksum(iph, tcph);
	}

	return 1;
}

static int
tcp_snat_handler(struct rte_mbuf *skb,
		 struct ip_vs_protocol *pp, struct ip_vs_conn *cp)
{
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *tcph = tcp_hdr(iph);
	(void)pp;

	tcph->source = cp->vport;

	/*
	 * Syn-proxy seq change, include tcp hdr and
	 * check ack storm.
	 */
	/*
	if (ip_vs_synproxy_snat_handler(tcph, cp) == 0) {
		return 0;
	}
	*/

	if (sysctl_ip_vs_csum_offload) {
		skb->ol_flags |= PKT_TX_TCP_CKSUM;
		tcph->check = rte_ipv4_phdr_cksum((struct ipv4_hdr *)iph,
						skb->ol_flags);	
	} else {
		tcph->check = 0;
		tcph->check = ofp_vs_ipv4_udptcp_cksum(iph, tcph);
	}
	return 1;
}

static void
tcp_conn_expire_handler(struct ip_vs_protocol *pp, struct ip_vs_conn *cp)
{
	(void)pp;
	/* support fullnat and nat */
	if (sysctl_ip_vs_conn_expire_tcp_rst &&
	    (cp->flags & (IP_VS_CONN_F_FULLNAT | IP_VS_CONN_F_MASQ))) {
		/* send reset packet to RS */
		//tcp_send_rst_in(pp, cp);
		/* send reset packet to client */
		//tcp_send_rst_out(pp, cp);
	}
}

#define TCP_DIR_INPUT		0
#define TCP_DIR_OUTPUT		4
#define TCP_DIR_INPUT_ONLY	8

static const int tcp_state_off[IP_VS_DIR_LAST] = {
	[IP_VS_DIR_INPUT] = TCP_DIR_INPUT,
	[IP_VS_DIR_OUTPUT] = TCP_DIR_OUTPUT,
	[IP_VS_DIR_INPUT_ONLY] = TCP_DIR_INPUT_ONLY,
};

/*
 *	Timeout table[state]
 */
int sysctl_ip_vs_tcp_timeouts[IP_VS_TCP_S_LAST + 1] = {
	[IP_VS_TCP_S_NONE] = 2 * HZ,
	[IP_VS_TCP_S_ESTABLISHED] = 90 * HZ,
	[IP_VS_TCP_S_SYN_SENT] = 3 * HZ,
	[IP_VS_TCP_S_SYN_RECV] = 30 * HZ,
	[IP_VS_TCP_S_FIN_WAIT] = 7 * HZ,
	[IP_VS_TCP_S_TIME_WAIT] = 7 * HZ,
	[IP_VS_TCP_S_CLOSE] = 3 * HZ,
	[IP_VS_TCP_S_CLOSE_WAIT] = 7 * HZ,
	[IP_VS_TCP_S_LAST_ACK] = 7 * HZ,
	[IP_VS_TCP_S_LISTEN] = 2 * 60 * HZ,
	[IP_VS_TCP_S_SYNACK] = 30 * HZ,
	[IP_VS_TCP_S_LAST] = 2 * HZ,
};

static const char *const tcp_state_name_table[IP_VS_TCP_S_LAST + 1] = {
	[IP_VS_TCP_S_NONE] = "NONE",
	[IP_VS_TCP_S_ESTABLISHED] = "ESTABLISHED",
	[IP_VS_TCP_S_SYN_SENT] = "SYN_SENT",
	[IP_VS_TCP_S_SYN_RECV] = "SYN_RECV",
	[IP_VS_TCP_S_FIN_WAIT] = "FIN_WAIT",
	[IP_VS_TCP_S_TIME_WAIT] = "TIME_WAIT",
	[IP_VS_TCP_S_CLOSE] = "CLOSE",
	[IP_VS_TCP_S_CLOSE_WAIT] = "CLOSE_WAIT",
	[IP_VS_TCP_S_LAST_ACK] = "LAST_ACK",
	[IP_VS_TCP_S_LISTEN] = "LISTEN",
	[IP_VS_TCP_S_SYNACK] = "SYNACK",
	[IP_VS_TCP_S_LAST] = "BUG!",
};

#define sNO IP_VS_TCP_S_NONE
#define sES IP_VS_TCP_S_ESTABLISHED
#define sSS IP_VS_TCP_S_SYN_SENT
#define sSR IP_VS_TCP_S_SYN_RECV
#define sFW IP_VS_TCP_S_FIN_WAIT
#define sTW IP_VS_TCP_S_TIME_WAIT
#define sCL IP_VS_TCP_S_CLOSE
#define sCW IP_VS_TCP_S_CLOSE_WAIT
#define sLA IP_VS_TCP_S_LAST_ACK
#define sLI IP_VS_TCP_S_LISTEN
#define sSA IP_VS_TCP_S_SYNACK

struct tcp_states_t {
	int next_state[IP_VS_TCP_S_LAST];
};

static const char *tcp_state_name(int state)
{
	if (state >= IP_VS_TCP_S_LAST)
		return "ERR!";
	return tcp_state_name_table[state] ? tcp_state_name_table[state] : "?";
}

static struct tcp_states_t tcp_states[] = {
/*	INPUT */
/*        sNO, sES, sSS, sSR, sFW, sTW, sCL, sCW, sLA, sLI, sSA	*/
/*syn*/ {{sSR, sES, sES, sSR, sSR, sSR, sSR, sSR, sSR, sSR, sSR}},
/*fin*/ {{sCL, sCW, sSS, sTW, sTW, sTW, sCL, sCW, sLA, sLI, sTW}},
/*ack*/ {{sCL, sES, sSS, sES, sFW, sTW, sCL, sCW, sCL, sLI, sES}},
/*rst*/ {{sCL, sCL, sCL, sSR, sCL, sCL, sCL, sCL, sLA, sLI, sSR}},

/*	OUTPUT */
/*        sNO, sES, sSS, sSR, sFW, sTW, sCL, sCW, sLA, sLI, sSA	*/
/*syn*/ {{sSS, sES, sSS, sSR, sSS, sSS, sSS, sSS, sSS, sLI, sSR}},
/*fin*/ {{sTW, sFW, sSS, sTW, sFW, sTW, sCL, sTW, sLA, sLI, sTW}},
/*ack*/ {{sES, sES, sSS, sES, sFW, sTW, sCL, sCW, sLA, sES, sES}},
/*rst*/ {{sCL, sCL, sSS, sCL, sCL, sTW, sCL, sCL, sCL, sCL, sCL}},

/*	INPUT-ONLY */
/*        sNO, sES, sSS, sSR, sFW, sTW, sCL, sCW, sLA, sLI, sSA	*/
/*syn*/ {{sSR, sES, sES, sSR, sSR, sSR, sSR, sSR, sSR, sSR, sSR}},
/*fin*/ {{sCL, sFW, sSS, sTW, sFW, sTW, sCL, sCW, sLA, sLI, sTW}},
/*ack*/ {{sCL, sES, sSS, sES, sFW, sTW, sCL, sCW, sCL, sLI, sES}},
/*rst*/ {{sCL, sCL, sCL, sSR, sCL, sCL, sCL, sCL, sLA, sLI, sCL}},
};

static struct tcp_states_t tcp_states_dos[] = {
/*	INPUT */
/*        sNO, sES, sSS, sSR, sFW, sTW, sCL, sCW, sLA, sLI, sSA	*/
/*syn*/ {{sSR, sES, sES, sSR, sSR, sSR, sSR, sSR, sSR, sSR, sSA}},
/*fin*/ {{sCL, sCW, sSS, sTW, sTW, sTW, sCL, sCW, sLA, sLI, sSA}},
/*ack*/ {{sCL, sES, sSS, sSR, sFW, sTW, sCL, sCW, sCL, sLI, sSA}},
/*rst*/ {{sCL, sCL, sCL, sSR, sCL, sCL, sCL, sCL, sLA, sLI, sCL}},

/*	OUTPUT */
/*        sNO, sES, sSS, sSR, sFW, sTW, sCL, sCW, sLA, sLI, sSA	*/
/*syn*/ {{sSS, sES, sSS, sSA, sSS, sSS, sSS, sSS, sSS, sLI, sSA}},
/*fin*/ {{sTW, sFW, sSS, sTW, sFW, sTW, sCL, sTW, sLA, sLI, sTW}},
/*ack*/ {{sES, sES, sSS, sES, sFW, sTW, sCL, sCW, sLA, sES, sES}},
/*rst*/ {{sCL, sCL, sSS, sCL, sCL, sTW, sCL, sCL, sCL, sCL, sCL}},

/*	INPUT-ONLY */
/*        sNO, sES, sSS, sSR, sFW, sTW, sCL, sCW, sLA, sLI, sSA	*/
/*syn*/ {{sSA, sES, sES, sSR, sSA, sSA, sSA, sSA, sSA, sSA, sSA}},
/*fin*/ {{sCL, sFW, sSS, sTW, sFW, sTW, sCL, sCW, sLA, sLI, sTW}},
/*ack*/ {{sCL, sES, sSS, sES, sFW, sTW, sCL, sCW, sCL, sLI, sES}},
/*rst*/ {{sCL, sCL, sCL, sSR, sCL, sCL, sCL, sCL, sLA, sLI, sCL}},
};

static struct tcp_states_t *tcp_state_table = tcp_states;

static void tcp_timeout_change(struct ip_vs_protocol *pp, int flags)
{
	int on = (flags & 1);	/* secure_tcp */
	(void)pp;

	/*
	 ** FIXME: change secure_tcp to independent sysctl var
	 ** or make it per-service or per-app because it is valid
	 ** for most if not for all of the applications. Something
	 ** like "capabilities" (flags) for each object.
	 */
	tcp_state_table = (on ? tcp_states_dos : tcp_states);
}

static int tcp_set_state_timeout(struct ip_vs_protocol *pp, char *sname, int to)
{
	return ip_vs_set_state_timeout(pp->timeout_table, IP_VS_TCP_S_LAST,
				       tcp_state_name_table, sname, to);
}

static inline int tcp_state_idx(struct tcphdr *th)
{
	if (th->rst)
		return 3;
	if (th->syn)
		return 0;
	if (th->fin)
		return 1;
	if (th->ack)
		return 2;
	return -1;
}

static inline void
set_tcp_state(struct ip_vs_protocol *pp, struct ip_vs_conn *cp,
	      int direction, struct tcphdr *th)
{
	int state_idx;
	int new_state = IP_VS_TCP_S_CLOSE;
	int state_off = tcp_state_off[direction];
	(void)pp;

	/*
	 *    Update state offset to INPUT_ONLY if necessary
	 *    or delete NO_OUTPUT flag if output packet detected
	 */
	if (cp->flags & IP_VS_CONN_F_NOOUTPUT) {
		if (state_off == TCP_DIR_OUTPUT)
			cp->flags &= ~IP_VS_CONN_F_NOOUTPUT;
		else
			state_off = TCP_DIR_INPUT_ONLY;
	}

	if ((state_idx = tcp_state_idx(th)) < 0) {
		IP_VS_DBG(8, "tcp_state_idx=%d!!!\n", state_idx);
		goto tcp_state_out;
	}

	new_state =
	    tcp_state_table[state_off + state_idx].next_state[cp->state];

      tcp_state_out:
	if (new_state != cp->state) {
		struct ip_vs_dest *dest = cp->dest;

		IP_VS_DBG_BUF(8, "%s %s [%c%c%c%c] %s:%d->"
			      "%s:%d state: %s->%s conn->refcnt:%d\n",
			      pp->name,
			      ((state_off == TCP_DIR_OUTPUT) ?
			       "output " : "input "),
			      th->syn ? 'S' : '.',
			      th->fin ? 'F' : '.',
			      th->ack ? 'A' : '.',
			      th->rst ? 'R' : '.',
			      IP_VS_DBG_ADDR(cp->af, &cp->daddr),
			      ntohs(cp->dport),
			      IP_VS_DBG_ADDR(cp->af, &cp->caddr),
			      ntohs(cp->cport),
			      tcp_state_name(cp->state),
			      tcp_state_name(new_state),
			      atomic_read(&cp->refcnt));

		if (dest) {
			if (!(cp->flags & IP_VS_CONN_F_INACTIVE) &&
			    (new_state != IP_VS_TCP_S_ESTABLISHED)) {
				atomic_dec(&dest->activeconns);
				atomic_inc(&dest->inactconns);
				cp->flags |= IP_VS_CONN_F_INACTIVE;
			} else if ((cp->flags & IP_VS_CONN_F_INACTIVE) &&
				   (new_state == IP_VS_TCP_S_ESTABLISHED)) {
				atomic_inc(&dest->activeconns);
				atomic_dec(&dest->inactconns);
				cp->flags &= ~IP_VS_CONN_F_INACTIVE;
			}
		}
	}

	cp->old_state = cp->state;	// old_state called when connection reused
	cp->timeout = ((cp->state = new_state) == IP_VS_TCP_S_ESTABLISHED) ?
			cp->est_timeout : sysctl_ip_vs_tcp_timeouts[new_state];
}

/*
 *	Handle state transitions
 */
static int
tcp_state_transition(struct ip_vs_conn *cp, int direction,
		     const struct rte_mbuf *skb, struct ip_vs_protocol *pp)
{
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *th = tcp_hdr(iph);

	if (th == NULL)
		return 0;

	spin_lock(&cp->lock);
	set_tcp_state(pp, cp, direction, th);
	spin_unlock(&cp->lock);

	return 1;
}

static void ip_vs_tcp_init(struct ip_vs_protocol *pp)
{
	net_secret_init();
	pp->timeout_table = sysctl_ip_vs_tcp_timeouts;
}

static void ip_vs_tcp_exit(struct ip_vs_protocol *pp)
{
	(void)pp;
}

struct ip_vs_protocol ip_vs_protocol_tcp = {
	.name = "TCP",
	.protocol = IPPROTO_TCP,
	.num_states = IP_VS_TCP_S_LAST,
	.dont_defrag = 0,
	.appcnt = ATOMIC_INIT(0),
	.init = ip_vs_tcp_init,
	.exit = ip_vs_tcp_exit,
	.conn_schedule = tcp_conn_schedule,
	.conn_in_get = tcp_conn_in_get,
	.conn_out_get = tcp_conn_out_get,
	.fnat_in_handler = tcp_fnat_in_handler,
	.fnat_out_handler = tcp_fnat_out_handler,
	.dnat_handler = tcp_dnat_handler,
	.snat_handler = tcp_snat_handler,
	.state_name = tcp_state_name,
	.state_transition = tcp_state_transition,
	.debug_packet = ip_vs_tcpudp_debug_packet,
	.timeout_change = tcp_timeout_change,
	.set_state_timeout = tcp_set_state_timeout,
	.conn_expire_handler = tcp_conn_expire_handler,
};
