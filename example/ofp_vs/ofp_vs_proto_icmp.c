#define KMSG_COMPONENT "IPVS"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include "ofp_vs.h"
#include <net/ip_vs.h>

static struct ip_vs_conn *icmp_conn_in_get(int af, const struct rte_mbuf *skb,
		struct ip_vs_protocol *pp,
		const struct ip_vs_iphdr *iph,
		unsigned int proto_off, int inverse,
		int *res_dir) {
	struct ip_vs_conn *cp;
	struct iphdr *ih = ip_hdr(skb);
	struct icmphdr *icmph = icmp_hdr(ih);
	(void)proto_off;

	if (icmph == NULL) {
		return NULL;
	}

	IP_VS_DBG(8, "%s (%d,%d) %pI4->%pI4\n",
		  pp->name, icmph->type, ntohs(icmph->un.echo.id),
		  &iph->saddr, &iph->daddr);

	if (likely(!inverse)) {
		cp = ip_vs_conn_get(af, iph->protocol,
				    &iph->saddr, icmph->un.echo.id,
				    &iph->daddr, icmph->un.echo.id, res_dir);
	} else {
		cp = ip_vs_conn_get(af, iph->protocol,
				    &iph->daddr, icmph->un.echo.id,
				    &iph->saddr, icmph->un.echo.id, res_dir);
	}

	return cp;
}

static struct ip_vs_conn *icmp_conn_out_get(int af, const struct rte_mbuf *skb,
		struct ip_vs_protocol *pp,
		const struct ip_vs_iphdr *iph,
		unsigned int proto_off, int inverse,
		int *res_dir) {
	struct ip_vs_conn *cp;
	struct iphdr *ih = ip_hdr(skb);
	struct icmphdr *icmph = icmp_hdr(ih);
	(void)proto_off;

	if (icmph == NULL) {
		return NULL;
	}

	IP_VS_DBG_BUF(8, "%s (%d,%d) %s->%s\n",
		  pp->name, icmph->type, ntohs(icmph->un.echo.id),
		  IP_VS_DBG_ADDR(af, &iph->saddr),
		  IP_VS_DBG_ADDR(af, &iph->daddr));

	if (likely(!inverse)) {
		cp = ip_vs_conn_get(af, iph->protocol,
				    &iph->saddr, icmph->un.echo.id,
				    &iph->daddr, icmph->un.echo.id, res_dir);
	} else {
		cp = ip_vs_conn_get(af, iph->protocol,
				    &iph->daddr, icmph->un.echo.id,
				    &iph->saddr, icmph->un.echo.id, res_dir);
	}

	return cp;
}

static int
icmp_conn_schedule(int af, struct rte_mbuf *skb, struct ip_vs_protocol *pp,
	    int *verdict, struct ip_vs_conn **cpp, int fwmark) {
	struct ip_vs_service *svc;
	struct iphdr *ih = ip_hdr(skb);
	struct icmphdr *icmph = icmp_hdr(ih);
	struct ip_vs_dest *dest;
	struct ip_vs_iphdr iph;

	*verdict = NF_DROP;
	ip_vs_fill_iphdr(af, ih, &iph);

	if (icmph == NULL)
		return 0;

	if (ICMP_ECHO != icmph->type) {
		*verdict = NF_ACCEPT;
		return 0;
	}

	svc = ip_vs_service_get(af, fwmark, iph.protocol, &iph.daddr, 0);
	if (svc && IS_SNAT_SVC(svc)) {
		if (ip_vs_todrop()) {
			/*
			 It seems that we are very loaded.
			 We have to drop this packet :(
			*/
			ip_vs_service_put(svc);
			return 0;
		}

		/*
		 Let the virtual server select a real server for the
		 incoming connection, and create a connection entry.
		 */
		dest = svc->scheduler->schedule(svc, skb);
		if (dest == NULL) {
			ip_vs_service_put(svc);
			IP_VS_DBG(1, "Schedule: no dest found.\n");
			return 0;
		}

		//*cpp = ip_vs_schedule(svc, skb, 0);
		*cpp = ip_vs_conn_new(svc->af, iph.protocol,
			&iph.saddr, icmph->un.echo.id,
			&iph.daddr, icmph->un.echo.id,
			&iph.daddr, icmph->un.echo.id,
			0,
			dest, skb, 0);
		if (!*cpp) {
			*verdict = ip_vs_leave(svc, skb, pp);
			return 0;
		}
		ip_vs_service_put(svc);
	}

	return 1;
}

static void
ip_vs_icmp_debug_packet(struct ip_vs_protocol *pp,
		struct rte_mbuf *skb,
		int offset, const char *msg) {
	char buf[128];
	struct iphdr *ih = ip_hdr(skb);
	(void)offset;

	if (ih == NULL)
		sprintf(buf, "%s TRUNCATED", pp->name);
	else
		sprintf(buf, "%s %pI4->%pI4 port %d",
			pp->name, &ih->saddr, &ih->daddr, skb->port);

	IP_VS_DBG(8, "%s %s %s\n", __func__, msg, buf);
}

static int icmp_timeouts[IP_VS_ICMP_S_LAST + 1] = {
	[IP_VS_ICMP_S_NORMAL] = 5 * HZ,
	[IP_VS_ICMP_S_LAST] = 2 * HZ,
};

static const char *const icmp_state_name_table[IP_VS_ICMP_S_LAST + 1] = {
	[IP_VS_ICMP_S_NORMAL] = "ICMP",
	[IP_VS_ICMP_S_LAST] = "BUG!",
};

static int icmp_set_state_timeout(struct ip_vs_protocol *pp, char *sname, int to) {
	return ip_vs_set_state_timeout(pp->timeout_table, IP_VS_ICMP_S_LAST,
			icmp_state_name_table, sname, to);
}

static const char *icmp_state_name(int state) {
	if (state >= IP_VS_ICMP_S_LAST)
		return "ERR!";
	return icmp_state_name_table[state] ? icmp_state_name_table[state] : "?";
}

static int
icmp_state_transition(struct ip_vs_conn *cp, int direction,
		const struct rte_mbuf *skb, struct ip_vs_protocol *pp) {
	(void)skb;
	(void)direction;
	cp->timeout = pp->timeout_table[IP_VS_ICMP_S_NORMAL];
	return 1;
}

static void icmp_init(struct ip_vs_protocol *pp) {
	pp->timeout_table = icmp_timeouts;
}

static void icmp_exit(struct ip_vs_protocol *pp) {
	(void)pp;
}

struct ip_vs_protocol ip_vs_protocol_icmp = {
	.name = "ICMP",
	.protocol = IPPROTO_ICMP,
	.num_states = IP_VS_ICMP_S_LAST,
	.dont_defrag = 1,
	.init = icmp_init,
	.exit = icmp_exit,
	.conn_schedule = icmp_conn_schedule,
	.conn_in_get = icmp_conn_in_get,
	.conn_out_get = icmp_conn_out_get,
	.csum_check = NULL,
	.state_transition = icmp_state_transition,
	.state_name = icmp_state_name,
	.register_app = NULL,
	.unregister_app = NULL,
	.debug_packet = ip_vs_icmp_debug_packet,
	.timeout_change = NULL,
	.set_state_timeout = icmp_set_state_timeout,
};

