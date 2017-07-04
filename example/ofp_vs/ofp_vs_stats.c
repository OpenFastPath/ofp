#include "ofp_vs.h"

RTE_DEFINE_PER_LCORE(struct ip_vs_stats, ip_vs_stats);

void ip_vs_zero_stats(struct ip_vs_stats* stats)
{
	(void)stats;
	/*
	int i = 0;

	if(NULL == stats) {
		pr_err("%s: Invaild point \n", __func__);
		return;
	}

	for_each_online_cpu(i) {
		ip_vs_stats_cpu(stats, i).conns    = 0;
		ip_vs_stats_cpu(stats, i).inpkts   = 0;
		ip_vs_stats_cpu(stats, i).outpkts  = 0;
		ip_vs_stats_cpu(stats, i).inbytes  = 0;
		ip_vs_stats_cpu(stats, i).outbytes = 0;
	}

	return;
	*/
}

void ip_vs_in_stats(struct ip_vs_conn *cp, struct rte_mbuf *skb)
{
	struct ip_vs_dest *dest = cp->dest;
	if (dest && (dest->flags & IP_VS_DEST_F_AVAILABLE)) {
		dest->stats.inpkts++;
		dest->stats.inbytes += skb->data_len;

		dest->svc->stats.inpkts++;
		dest->svc->stats.inbytes += skb->data_len;

		ip_vs_stats_this_cpu(ip_vs_stats).inpkts++;
		ip_vs_stats_this_cpu(ip_vs_stats).inbytes += skb->data_len;
	}

	return;
}

void ip_vs_out_stats(struct ip_vs_conn *cp, struct rte_mbuf *skb)
{
	struct ip_vs_dest *dest = cp->dest;
	if (dest && (dest->flags & IP_VS_DEST_F_AVAILABLE)) {
		dest->stats.outpkts++;
		dest->stats.outbytes += skb->data_len;

		dest->svc->stats.outpkts++;
		dest->svc->stats.outbytes += skb->data_len;

		ip_vs_stats_this_cpu(ip_vs_stats).outpkts++;
		ip_vs_stats_this_cpu(ip_vs_stats).outbytes += skb->data_len;
	}
	return;
}

void ip_vs_conn_stats(struct ip_vs_conn *cp, struct ip_vs_service *svc)
{
	struct ip_vs_dest *dest = cp->dest;
	(void)svc;
	if(dest) {
		dest->stats.conns++;

		dest->svc->stats.conns++;

		ip_vs_stats_this_cpu(ip_vs_stats).conns++;
	}

	return;
}

