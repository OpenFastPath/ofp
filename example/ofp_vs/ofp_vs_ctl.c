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
 *              Port to ofp. author:lvsgate@163.com 
 *
 */

#define KMSG_COMPONENT "IPVS"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/errno.h>

#include "ofp_vs.h"

//static int ipvs_genl_family;
static struct nl_sock *sock = NULL;

/* semaphore for IPVS sockopts. And, [gs]etsockopt may sleep. */
static pthread_mutex_t __ip_vs_mutex = PTHREAD_MUTEX_INITIALIZER;

/* percpu lock for service table */
DEFINE_PER_CPU(spinlock_t, ip_vs_svc_lock);

/*
 *	Hash table: for virtual service lookups
 */
#define IP_VS_SVC_TAB_BITS 12
#define IP_VS_SVC_TAB_SIZE (1 << IP_VS_SVC_TAB_BITS)
#define IP_VS_SVC_TAB_MASK (IP_VS_SVC_TAB_SIZE - 1)

/* the service table hashed by <protocol, addr, port> */
DEFINE_PER_CPU(struct list_head *, ip_vs_svc_tab_percpu);
/* the service table hashed by fwmark */
DEFINE_PER_CPU(struct list_head *, ip_vs_svc_fwm_tab_percpu);

/*
 *	Trash for destinations
 */
DEFINE_PER_CPU(struct list_head, ip_vs_dest_trash_percpu);

/*
 *	FTP & NULL virtual service counters
 */
static atomic_t ip_vs_ftpsvc_counter = ATOMIC_INIT(0);
static atomic_t ip_vs_nullsvc_counter = ATOMIC_INIT(0);

/* number of virtual services */
static int ip_vs_num_services = 0;

/* 1/rate drop and drop-entry variables */
int ip_vs_drop_rate = 0;
int ip_vs_drop_counter = 0;

/* sysctl variables */
int sysctl_ip_vs_expire_quiescent_template = 1;
int sysctl_ip_vs_expire_nodest_conn = 1;

/*
 * sysctl for FULLNAT
 */
int sysctl_ip_vs_timestamp_remove_entry = 1;
int sysctl_ip_vs_mss_adjust_entry = 1;
int sysctl_ip_vs_conn_reused_entry = 1;
int sysctl_ip_vs_toa_entry = 1;
extern int sysctl_ip_vs_tcp_timeouts[IP_VS_TCP_S_LAST + 1];
/*
static int ip_vs_entry_min = 0;
static int ip_vs_entry_max = 1;
*/

/*
 * sysctl for SYNPROXY
 */
/* syn-proxy sysctl variables */
/*
int sysctl_ip_vs_synproxy_init_mss = IP_VS_SYNPROXY_INIT_MSS_DEFAULT;
int sysctl_ip_vs_synproxy_sack = IP_VS_SYNPROXY_SACK_DEFAULT;
int sysctl_ip_vs_synproxy_wscale = IP_VS_SYNPROXY_WSCALE_DEFAULT;
int sysctl_ip_vs_synproxy_timestamp = IP_VS_SYNPROXY_TIMESTAMP_DEFAULT;
int sysctl_ip_vs_synproxy_synack_ttl = IP_VS_SYNPROXY_TTL_DEFAULT;
int sysctl_ip_vs_synproxy_defer = IP_VS_SYNPROXY_DEFER_DEFAULT;
int sysctl_ip_vs_synproxy_conn_reuse = IP_VS_SYNPROXY_CONN_REUSE_DEFAULT;
int sysctl_ip_vs_synproxy_conn_reuse_cl = IP_VS_SYNPROXY_CONN_REUSE_CL_DEFAULT;
int sysctl_ip_vs_synproxy_conn_reuse_tw = IP_VS_SYNPROXY_CONN_REUSE_TW_DEFAULT;
int sysctl_ip_vs_synproxy_conn_reuse_fw = IP_VS_SYNPROXY_CONN_REUSE_FW_DEFAULT;
int sysctl_ip_vs_synproxy_conn_reuse_cw = IP_VS_SYNPROXY_CONN_REUSE_CW_DEFAULT;
int sysctl_ip_vs_synproxy_conn_reuse_la = IP_VS_SYNPROXY_CONN_REUSE_LA_DEFAULT;
int sysctl_ip_vs_synproxy_dup_ack_thresh = IP_VS_SYNPROXY_DUP_ACK_DEFAULT;
int sysctl_ip_vs_synproxy_msg_store_thresh = IP_VS_SYNPROXY_SKB_STORE_DEFAULT;
int sysctl_ip_vs_synproxy_syn_retry = IP_VS_SYNPROXY_SYN_RETRY_DEFAULT;

static int ip_vs_synproxy_switch_min = 0;
static int ip_vs_synproxy_switch_max = 1;
static int ip_vs_synproxy_wscale_min = 0;
static int ip_vs_synproxy_wscale_max = IP_VS_SYNPROXY_WSCALE_MAX;
static int ip_vs_synproxy_init_mss_min = 0;
static int ip_vs_synproxy_init_mss_max = 65535;
static int ip_vs_synproxy_synack_ttl_min = IP_VS_SYNPROXY_TTL_MIN;
static int ip_vs_synproxy_synack_ttl_max = IP_VS_SYNPROXY_TTL_MAX;
static int ip_vs_synproxy_dup_ack_cnt_min = 0;
static int ip_vs_synproxy_dup_ack_cnt_max = 65535;
static int ip_vs_synproxy_syn_retry_min = 0;
static int ip_vs_synproxy_syn_retry_max = 6;
static int ip_vs_synproxy_msg_store_thresh_min = 0;
static int ip_vs_synproxy_msg_store_thresh_max = 5;
*/

/* local address port range */
int sysctl_ip_vs_lport_max = 65535;
int sysctl_ip_vs_lport_min = 5000;
int sysctl_ip_vs_lport_tries = 10000;
/*
static int ip_vs_port_min = 1025;
static int ip_vs_port_max = 65535;
static int ip_vs_port_try_min = 10;
static int ip_vs_port_try_max = 60000;
*/

/*
 * sysctl for DEFENCE ATTACK
 */
int sysctl_ip_vs_frag_drop_entry = 1;
int sysctl_ip_vs_tcp_drop_entry = 1;
int sysctl_ip_vs_udp_drop_entry = 1;
/* send rst when tcp session expire */
int sysctl_ip_vs_conn_expire_tcp_rst = 1;
/* L2 fast xmit, response only (to client) */
int sysctl_ip_vs_fast_xmit = 1;
/* L2 fast xmit, inside (to RS) */
int sysctl_ip_vs_fast_xmit_inside = 1;
/* msg csum offload */
int sysctl_ip_vs_csum_offload = 0;

/* reserve core for the control flow */
int sysctl_ip_vs_reserve_core = 1;
/*
static int ip_vs_reserve_core_min = 0;
static int ip_vs_reserve_core_max = 6;
*/

#ifdef OFP_DEBUG
static int sysctl_ip_vs_debug_level = 12;

int ip_vs_get_debug_level(void)
{
	return sysctl_ip_vs_debug_level;
}
#endif

extern int sysctl_ip_vs_tcp_timeouts[IP_VS_TCP_S_LAST + 1];

int ip_vs_use_count_inc(void)
{
	return 0;
}

void ip_vs_use_count_dec(void)
{
}

static struct nl_msg *ipvs_nl_message(const struct genl_info *info,
	                                    int cmd, int flags)
{
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg)
		return NULL;

	genlmsg_put(msg, info->who->nl_pid, info->nlh->nlmsg_seq,
	            info->nlh->nlmsg_type, 0, flags,
	            cmd, IPVS_GENL_VERSION);

	return msg;
}

static int ipvs_nl_reply(const struct genl_info *info,
	                                          struct nl_msg *msg)
{
	nl_socket_set_peer_port(sock, info->who->nl_pid);
	return nl_send_auto_complete(sock, msg);
}

static int ipvs_nl_multi_reply_done(const struct genl_info *info, int cmd)
{
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;
	
	/*
	return genl_send_simple(sock, NLMSG_DONE, cmd,
	                        IPVS_GENL_VERSION, NLM_F_MULTI);
	*/

	genlmsg_put(msg, info->who->nl_pid, info->nlh->nlmsg_seq,
	            NLMSG_DONE, 0, NLM_F_MULTI, cmd,
	            IPVS_GENL_VERSION);

	return ipvs_nl_reply(info, msg); 
}

static int ipvs_nl_reply_error(const struct genl_info *info,
	          int cmd, int err)
{
	struct nl_msg *msg;
	struct nlmsgerr *e;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	genlmsg_put(msg, info->who->nl_pid, info->nlh->nlmsg_seq,
	            NLMSG_ERROR, sizeof(struct nlmsgerr), 0, cmd,
	            IPVS_GENL_VERSION);
	
	e = nlmsg_data(nlmsg_hdr(msg));
	e->error = err;

	return ipvs_nl_reply(info, msg);
}

/*
 *	Returns hash value for virtual service
 */
static __inline__ unsigned
ip_vs_svc_hashkey(int af, unsigned proto, const union nf_inet_addr *addr)
{
	__be32 addr_fold = addr->ip;
	(void)af;

#ifdef CONFIG_IP_VS_IPV6
	if (af == AF_INET6)
		addr_fold = addr->ip6[0] ^ addr->ip6[1] ^
		    addr->ip6[2] ^ addr->ip6[3];
#endif

	return (proto ^ ntohl(addr_fold)) & IP_VS_SVC_TAB_MASK;
}

/*
 *	Returns hash value of fwmark for virtual service lookup
 */
static __inline__ unsigned ip_vs_svc_fwm_hashkey(__u32 fwmark)
{
	return fwmark & IP_VS_SVC_TAB_MASK;
}


static int ip_vs_svc_hash_cpuid(struct ip_vs_service *svc, int cpu)
{
	unsigned hash;
	struct list_head *ip_vs_svc_tab;

	if (svc->flags & IP_VS_SVC_F_HASHED) {
		pr_err("%s(): request for already hashed, called from %pF\n",
		       __func__, __builtin_return_address(0));
		return 0;
	}

	if (svc->fwmark == 0) {
		/*
		 *  Hash it by <protocol,addr,port> in ip_vs_svc_table
		 */
		hash = ip_vs_svc_hashkey(svc->af, svc->protocol, &svc->addr);
		ip_vs_svc_tab = per_cpu(ip_vs_svc_tab_percpu, cpu);
		list_add(&svc->s_list, ip_vs_svc_tab + hash);
	} else {
		/*
		 *  Hash it by fwmark in ip_vs_svc_fwm_table
		 */
		hash = ip_vs_svc_fwm_hashkey(svc->fwmark);
		ip_vs_svc_tab = per_cpu(ip_vs_svc_fwm_tab_percpu, cpu);
		list_add(&svc->f_list, ip_vs_svc_tab + hash);
	}

	svc->flags |= IP_VS_SVC_F_HASHED;
	/* increase its refcnt because it is referenced by the svc table */
	atomic_inc(&svc->refcnt);
	return 1;
}

/*
 *	Unhashes a service from ip_vs_svc_table/ip_vs_svc_fwm_table.
 *	Should be called with locked tables.
 */
static int ip_vs_svc_unhash(struct ip_vs_service *svc)
{
	if (!(svc->flags & IP_VS_SVC_F_HASHED)) {
		pr_err("%s(): request for unhash flagged, called from %pF\n",
		       __func__, __builtin_return_address(0));
		return 0;
	}

	if (svc->fwmark == 0) {
		/* Remove it from the ip_vs_svc_table table */
		list_del(&svc->s_list);
	} else {
		return 0;
		/* Remove it from the ip_vs_svc_fwm_table table */
		//list_del(&svc->f_list);
	}

	svc->flags &= ~IP_VS_SVC_F_HASHED;
	atomic_dec(&svc->refcnt);
	return 1;
}

/*
 *	Get service by {proto,addr,port} in the service table.
 */
static inline struct ip_vs_service *__ip_vs_service_get(int af, __u16 protocol,
							const union nf_inet_addr
							*vaddr, __be16 vport)
{
	unsigned hash;
	struct ip_vs_service *svc;
	struct list_head *ip_vs_svc_tab;

	ip_vs_svc_tab = __get_cpu_var(ip_vs_svc_tab_percpu);
	/* Check for "full" addressed entries */
	hash = ip_vs_svc_hashkey(af, protocol, vaddr);

	list_for_each_entry(svc, ip_vs_svc_tab + hash, s_list) {
		if ((svc->af == af)
		    && ip_vs_addr_equal(af, &svc->addr, vaddr)
		    && (svc->port == vport)
		    && (svc->protocol == protocol)) {
			/* HIT */
			//atomic_inc(&svc->usecnt);
			return svc;
		}
	}

	return NULL;
}

/*
 *	Get service by {fwmark} in the service table.
 */
static inline struct ip_vs_service *__ip_vs_svc_fwm_get(int af, __u32 fwmark)
{
	unsigned hash;
	struct ip_vs_service *svc;
	struct list_head *ip_vs_svc_fwm_tab;

	ip_vs_svc_fwm_tab = __get_cpu_var(ip_vs_svc_fwm_tab_percpu);
	/* Check for fwmark addressed entries */
	hash = ip_vs_svc_fwm_hashkey(fwmark);

	list_for_each_entry(svc, ip_vs_svc_fwm_tab + hash, f_list) {
		if (svc->fwmark == fwmark && svc->af == af) {
			/* HIT */
			return svc;
		}
	}

	return NULL;
}

struct ip_vs_service *ip_vs_service_get(int af, __u32 fwmark, __u16 protocol,
					const union nf_inet_addr *vaddr,
					__be16 vport)
{
	struct ip_vs_service *svc;

	spin_lock(&__get_cpu_var(ip_vs_svc_lock));

	/*
	 *      Check the table hashed by fwmark first
	 */
	if (fwmark && (svc = __ip_vs_svc_fwm_get(af, fwmark)))
		goto out;

	/*
	 *      Check the table hashed by <protocol,addr,port>
	 *      for "full" addressed entries
	 */
	svc = __ip_vs_service_get(af, protocol, vaddr, vport);

	if (svc == NULL
	    && protocol == IPPROTO_TCP && atomic_read(&ip_vs_ftpsvc_counter)
	    && (vport == FTPDATA || ntohs(vport) >= PROT_SOCK)) {
		/*
		 * Check if ftp service entry exists, the packet
		 * might belong to FTP data connections.
		 */
		svc = __ip_vs_service_get(af, protocol, vaddr, FTPPORT);
	}

	if (svc == NULL && atomic_read(&ip_vs_nullsvc_counter)) {
		/*
		 * Check if the catch-all port (port zero) exists
		 */
		svc = __ip_vs_service_get(af, protocol, vaddr, 0);
	}

out:
	/* unlock by ip_vs_service_put */
	if (svc == NULL)
		spin_unlock(&__get_cpu_var(ip_vs_svc_lock));

	IP_VS_DBG_BUF(9, "lookup service: fwm %u %s %s:%u %s\n",
		      fwmark, ip_vs_proto_name(protocol),
		      IP_VS_DBG_ADDR(af, vaddr), ntohs(vport),
		      svc ? "hit" : "not hit");

	return svc;
}

struct ip_vs_service *ip_vs_lookup_vip(int af, __u16 protocol,
				       const union nf_inet_addr *vaddr)
{
	struct ip_vs_service *svc;
	struct list_head *ip_vs_svc_tab;
	unsigned hash;

	spin_lock(&__get_cpu_var(ip_vs_svc_lock));

	ip_vs_svc_tab = __get_cpu_var(ip_vs_svc_tab_percpu);
	hash = ip_vs_svc_hashkey(af, protocol, vaddr);
	list_for_each_entry(svc, ip_vs_svc_tab + hash, s_list) {
		if ((svc->af == af)
		    && ip_vs_addr_equal(af, &svc->addr, vaddr)
		    && (svc->protocol == protocol)) {
			/* HIT */
			spin_unlock(&__get_cpu_var(ip_vs_svc_lock));
			return svc;
		}
	}

	spin_unlock(&__get_cpu_var(ip_vs_svc_lock));
	return NULL;
}

static inline void
__ip_vs_bind_svc(struct ip_vs_dest *dest, struct ip_vs_service *svc)
{
	atomic_inc(&svc->refcnt);
	dest->svc = svc;
}

static inline void __ip_vs_unbind_svc(struct ip_vs_dest *dest)
{
	int cpu;
	struct ip_vs_service *svc = dest->svc;
	struct ip_vs_service *this_svc;

	dest->svc = NULL;
//	if (atomic_dec_and_test(&svc->refcnt))
//		rte_free(svc);

	atomic_dec(&svc->refcnt);

	for_each_possible_cpu(cpu) {
		this_svc = svc->svc0 + cpu;
		if (atomic_read(&this_svc->refcnt)) {
			IP_VS_DBG_BUF(2, "%s(): cpu%d refers to svc %s:%d,"
					"refcnt=%d\n", __func__, cpu,
					IP_VS_DBG_ADDR(svc->af, &svc->addr),
					ntohs(svc->port),
					atomic_read(&this_svc->refcnt));
			break;
		}
	}

	if (cpu == num_possible_cpus())
		rte_free(svc->svc0);
}

/*
 *	Lookup destination by {addr,port} in the given service
 */
static struct ip_vs_dest *ip_vs_lookup_dest(struct ip_vs_service *svc,
					    const union nf_inet_addr *daddr,
					    __be16 dport)
{
	struct ip_vs_dest *dest;

	/*
	 * Find the destination for the given service
	 */
	list_for_each_entry(dest, &svc->destinations, n_list) {
		if ((dest->af == svc->af)
		    && ip_vs_addr_equal(svc->af, &dest->addr, daddr)
		    && (dest->port == dport)) {
			/* HIT */
			return dest;
		}
	}

	return NULL;
}

/*
 * Find destination by {daddr,dport,vaddr,protocol}
 * Cretaed to be used in ip_vs_process_message() in
 * the backup synchronization daemon. It finds the
 * destination to be bound to the received connection
 * on the backup.
 *
 * ip_vs_lookup_real_service() looked promissing, but
 * seems not working as expected.
 */
struct ip_vs_dest *ip_vs_find_dest(int af, const union nf_inet_addr *daddr,
				   __be16 dport,
				   const union nf_inet_addr *vaddr,
				   __be16 vport, __u16 protocol)
{
	struct ip_vs_dest *dest;
	struct ip_vs_service *svc;

	svc = ip_vs_service_get(af, 0, protocol, vaddr, vport);
	if (!svc)
		return NULL;
	dest = ip_vs_lookup_dest(svc, daddr, dport);
	if (dest)
		atomic_inc(&dest->refcnt);
	ip_vs_service_put(svc);
	return dest;
}

/*
 *  Lookup dest by {svc,addr,port} in the destination trash.
 *  The destination trash is used to hold the destinations that are removed
 *  from the service table but are still referenced by some conn entries.
 *  The reason to add the destination trash is when the dest is temporary
 *  down (either by administrator or by monitor program), the dest can be
 *  picked back from the trash, the remaining connections to the dest can
 *  continue, and the counting information of the dest is also useful for
 *  scheduling.
 */
static struct ip_vs_dest *ip_vs_trash_get_dest_cpuid(struct ip_vs_service *svc,
					       const union nf_inet_addr *daddr,
					       __be16 dport, int cpu)
{
	struct ip_vs_dest *dest, *nxt;

	/*
	 * Find the destination in trash
	 */
	list_for_each_entry_safe(dest, nxt,
			&per_cpu(ip_vs_dest_trash_percpu, cpu), n_list) {
		IP_VS_DBG_BUF(3, "Destination %u/%s:%u still in trash-%d, "
			      "dest->refcnt=%d\n",
			      dest->vfwmark,
			      IP_VS_DBG_ADDR(svc->af, &dest->addr),
			      ntohs(dest->port),
				cpu, atomic_read(&dest->refcnt));
		if (dest->af == svc->af &&
		    ip_vs_addr_equal(svc->af, &dest->addr, daddr) &&
		    dest->port == dport &&
		    dest->vfwmark == svc->fwmark &&
		    dest->protocol == svc->protocol &&
		    (svc->fwmark ||
		     (ip_vs_addr_equal(svc->af, &dest->vaddr, &svc->addr) &&
		      dest->vport == svc->port))) {
			/* HIT */
			return dest;
		}

		/*
		 * Try to purge the destination from trash if not referenced
		 */
		if (atomic_read(&dest->refcnt) == 1) {
			IP_VS_DBG_BUF(3, "Removing destination %u/%s:%u "
				      "from trash-%d\n",
				      dest->vfwmark,
				      IP_VS_DBG_ADDR(svc->af, &dest->addr),
				      ntohs(dest->port), cpu);
			list_del(&dest->n_list);
			//ip_vs_dst_reset(dest);
			__ip_vs_unbind_svc(dest);
			rte_free(dest);
		}
	}

	return NULL;
}

/*
 *  Clean up all the destinations in the trash
 *  Called by the ip_vs_control_cleanup()
 *
 *  When the ip_vs_control_clearup is activated by ipvs module exit,
 *  the service tables must have been flushed and all the connections
 *  are expired, and the refcnt of each destination in the trash must
 *  be 1, so we simply release them here.
 */
static void ip_vs_trash_cleanup(void)
{
	int cpu;
	struct ip_vs_dest *dest, *nxt;

	for_each_possible_cpu(cpu) {
		list_for_each_entry_safe(dest, nxt,
				&per_cpu(ip_vs_dest_trash_percpu, cpu),
				n_list) {
			list_del(&dest->n_list);
			//ip_vs_dst_reset(dest);
			__ip_vs_unbind_svc(dest);
			rte_free(dest);
		}
	}
}

/*
 *	Update a destination in the given service
 */
static void
__ip_vs_update_dest(struct ip_vs_service *svc,
		    struct ip_vs_dest *dest, struct ip_vs_dest_user_kern *udest)
{
	int conn_flags;

	/* set the weight and the flags */
	atomic_set(&dest->weight, udest->weight);
	conn_flags = udest->conn_flags | IP_VS_CONN_F_INACTIVE;

	/* check if local node and update the flags */
#ifdef CONFIG_IP_VS_IPV6
	if (svc->af == AF_INET6) {
		if (__ip_vs_addr_is_local_v6(&udest->addr.in6)) {
			conn_flags = (conn_flags & ~IP_VS_CONN_F_FWD_MASK)
			    | IP_VS_CONN_F_LOCALNODE;
		}
	} else
#endif
	/*
	if (inet_addr_type(&init_net, udest->addr.ip) == RTN_LOCAL) {
		conn_flags = (conn_flags & ~IP_VS_CONN_F_FWD_MASK)
		    | IP_VS_CONN_F_LOCALNODE;
	}
	*/

	/* set the IP_VS_CONN_F_NOOUTPUT flag if not masquerading/NAT */
	if ((conn_flags & IP_VS_CONN_F_FWD_MASK) != 0) {
		conn_flags |= IP_VS_CONN_F_NOOUTPUT;
	}
	atomic_set(&dest->conn_flags, conn_flags);

	/* bind the service */
	if (!dest->svc) {
		__ip_vs_bind_svc(dest, svc);
	} else {
		if (dest->svc != svc) {
			__ip_vs_unbind_svc(dest);
			memset(&dest->stats, 0, sizeof(struct ip_vs_stats));
			__ip_vs_bind_svc(dest, svc);
		}
	}

	/* set the dest status flags */
	dest->flags |= IP_VS_DEST_F_AVAILABLE;

	if (udest->u_threshold == 0 || udest->u_threshold > dest->u_threshold)
		dest->flags &= ~IP_VS_DEST_F_OVERLOAD;
	dest->u_threshold = udest->u_threshold;
	dest->l_threshold = udest->l_threshold;
}

/*
 *	Create a destination for the given service
 */
static int
ip_vs_new_dest(struct ip_vs_service *svc, struct ip_vs_dest_user_kern *udest,
	       struct ip_vs_dest **dest_p)
{
	struct ip_vs_dest *dest;
	//unsigned atype;

#ifdef CONFIG_IP_VS_IPV6
	if (svc->af == AF_INET6) {
		atype = ipv6_addr_type(&udest->addr.in6);
		if ((!(atype & IPV6_ADDR_UNICAST) ||
		     atype & IPV6_ADDR_LINKLOCAL) &&
		    !__ip_vs_addr_is_local_v6(&udest->addr.in6))
			return -EINVAL;
	} else
#endif
	{
	  /*
		atype = inet_addr_type(&init_net, udest->addr.ip);
		if (atype != RTN_LOCAL && atype != RTN_UNICAST)
			return -EINVAL;
	    */
	}

	if (IS_SNAT_SVC(svc))
		dest = rte_zmalloc(NULL, sizeof(struct ip_vs_dest_snat), 0);
	else
		dest = rte_zmalloc(NULL, sizeof(struct ip_vs_dest), 0);
	if (dest == NULL) {
		pr_err("%s(): no memory.\n", __func__);
		return -ENOMEM;
	}

	dest->af = svc->af;
	dest->protocol = svc->protocol;
	dest->vaddr = svc->addr;
	dest->vport = svc->port;
	dest->vfwmark = svc->fwmark;
	ip_vs_addr_copy(svc->af, &dest->addr, &udest->addr);
	dest->port = udest->port;

	atomic_set(&dest->activeconns, 0);
	atomic_set(&dest->inactconns, 0);
	atomic_set(&dest->persistconns, 0);
	atomic_set(&dest->refcnt, 0);

	INIT_LIST_HEAD(&dest->d_list);
	spin_lock_init(&dest->dst_lock);

	__ip_vs_update_dest(svc, dest, udest);

	*dest_p = dest;

	return 0;
}

static void
ip_vs_add_dest_rollback(struct ip_vs_service *,
			const union nf_inet_addr *,
			__be16, int);

/*
 *	Add a destination into an existing service
 */
static int
ip_vs_add_dest(struct ip_vs_service *svc, struct ip_vs_dest_user_kern *udest)
{
	struct ip_vs_dest *dest;
	union nf_inet_addr daddr;
	__be16 dport = udest->port;
	int ret;
	int cpu = 0;
	struct ip_vs_service *this_svc = NULL;

	if (udest->weight < 0) {
		pr_err("%s(): server weight less than zero\n", __func__);
		return -ERANGE;
	}

	if (udest->l_threshold > udest->u_threshold) {
		pr_err("%s(): lower threshold is higher than upper threshold\n",
		       __func__);
		return -ERANGE;
	}

	ip_vs_addr_copy(svc->af, &daddr, &udest->addr);

	/*
	 * Check if the dest already exists in the list
	 */
	dest = ip_vs_lookup_dest(svc, &daddr, dport);

	if (dest != NULL) {
		IP_VS_DBG(1, "%s(): dest already exists\n", __func__);
		return -EEXIST;
	}


	for_each_possible_cpu(cpu) {
		this_svc = svc->svc0 + cpu;
		/*
		 * Check if the dest already exists in the trash and
		 * is from the same service
		 */
		dest = ip_vs_trash_get_dest_cpuid(this_svc,
					&daddr, dport, cpu);

		if (dest != NULL) {
			IP_VS_DBG_BUF(3, "Get destination %s:%u from trash, "
			      "dest->refcnt=%d, service %u/%s:%u\n",
			      IP_VS_DBG_ADDR(svc->af, &daddr), ntohs(dport),
			      atomic_read(&dest->refcnt),
			      dest->vfwmark,
			      IP_VS_DBG_ADDR(svc->af, &dest->vaddr),
			      ntohs(dest->vport));

			__ip_vs_update_dest(this_svc, dest, udest);

			/*
			 * Get the destination from the trash
			 */
			list_del(&dest->n_list);

			/* Reset the statistic value */
			memset(&dest->stats, 0, sizeof(struct ip_vs_stats));

			spin_lock_bh(&per_cpu(ip_vs_svc_lock, cpu));

			list_add(&dest->n_list, &this_svc->destinations);
			this_svc->num_dests++;
			this_svc->weight += udest->weight;

			/* call the update_service function of its scheduler */
			if (this_svc->scheduler->update_service)
				this_svc->scheduler->update_service(this_svc);

			spin_unlock_bh(&per_cpu(ip_vs_svc_lock, cpu));
			continue;
		}

		/*
		 * Allocate and initialize the dest structure
		 */
		ret = ip_vs_new_dest(this_svc, udest, &dest);
		if (ret) {
			ip_vs_add_dest_rollback(svc, &daddr, dport, cpu);
			return ret;
		}

		/*
		 * Add the dest entry into the list
		 */
		atomic_inc(&dest->refcnt);

		spin_lock_bh(&per_cpu(ip_vs_svc_lock, cpu));

		list_add(&dest->n_list, &this_svc->destinations);
		this_svc->num_dests++;
		this_svc->weight += udest->weight;

		/* call the update_service function of its scheduler */
		if (this_svc->scheduler->update_service)
			this_svc->scheduler->update_service(this_svc);

		spin_unlock_bh(&per_cpu(ip_vs_svc_lock, cpu));
	}

	return 0;
}

/*
 *	Edit a destination in the given service
 */
static int
ip_vs_edit_dest(struct ip_vs_service *svc, struct ip_vs_dest_user_kern *udest)
{
	struct ip_vs_dest *dest;
	union nf_inet_addr daddr;
	__be16 dport = udest->port;
	__u32 old_weight;
	int cpu;
	struct ip_vs_service *this_svc;

	if (udest->weight < 0) {
		pr_err("%s(): server weight less than zero\n", __func__);
		return -ERANGE;
	}

	if (udest->l_threshold > udest->u_threshold) {
		pr_err("%s(): lower threshold is higher than upper threshold\n",
		       __func__);
		return -ERANGE;
	}

	ip_vs_addr_copy(svc->af, &daddr, &udest->addr);

	for_each_possible_cpu(cpu) {
		this_svc = svc->svc0 + cpu;
		/*
		 *  Lookup the destination list
		 */
		dest = ip_vs_lookup_dest(this_svc, &daddr, dport);

		if (dest == NULL) {
			IP_VS_DBG(1, "%s(): dest doesn't exist\n", __func__);
			return -ENOENT;
		}

		/* save old weight */
		old_weight = atomic_read(&dest->weight);

		__ip_vs_update_dest(this_svc, dest, udest);

		spin_lock_bh(&per_cpu(ip_vs_svc_lock, cpu));

		 /* update service weight */
		this_svc->weight = this_svc->weight -
				old_weight + udest->weight;
		if(this_svc->weight < 0) {
			struct ip_vs_dest *tdest;
			this_svc->weight = 0;
			list_for_each_entry(tdest, &this_svc->destinations, n_list) {
				this_svc->weight += atomic_read(&tdest->weight);
			}
			IP_VS_ERR_RL("ip_vs_edit_dest:vs weight < 0\n");
		}

		/* update service, because server weight may be changed */
		if (this_svc->scheduler->update_service)
			this_svc->scheduler->update_service(this_svc);

		spin_unlock_bh(&per_cpu(ip_vs_svc_lock, cpu));
	}

	return 0;
}

/*
 *	Delete a destination (must be already unlinked from the service)
 */
static void __ip_vs_del_dest(struct ip_vs_dest *dest)
{
	/*
	 *  Decrease the refcnt of the dest, and free the dest
	 *  if nobody refers to it (refcnt=0). Otherwise, throw
	 *  the destination into the trash.
	 */
	if (atomic_dec_and_test(&dest->refcnt)) {
		//ip_vs_dst_reset(dest);
		/* simply decrease svc->refcnt here, let the caller check
		   and release the service if nobody refers to it.
		   Only user context can release destination and service,
		   and only one user context can update virtual service at a
		   time, so the operation here is OK */
		atomic_dec(&dest->svc->refcnt);

		rte_free(dest);
	} else {
		IP_VS_DBG_BUF(3, "Moving dest %s:%u into trash, "
			      "dest->refcnt=%d\n",
			      IP_VS_DBG_ADDR(dest->af, &dest->addr),
			      ntohs(dest->port), atomic_read(&dest->refcnt));
		list_add(&dest->n_list, &per_cpu(ip_vs_dest_trash_percpu,
				(dest->svc - dest->svc->svc0)));
		atomic_inc(&dest->refcnt);
	}
}

/*
 *	Unlink a destination from the given service
 */
static void __ip_vs_unlink_dest(struct ip_vs_service *svc,
				struct ip_vs_dest *dest, int svcupd)
{
	dest->flags &= ~IP_VS_DEST_F_AVAILABLE;

	/*
	 *  Remove it from the d-linked destination list.
	 */
	list_del(&dest->n_list);
	svc->num_dests--;
	svc->weight -= atomic_read(&dest->weight);
	if(svc->weight < 0) {
		struct ip_vs_dest *tdest;
	              svc->weight = 0;
		list_for_each_entry(tdest, &svc->destinations, n_list) {
			svc->weight += atomic_read(&tdest->weight);
		}
	              IP_VS_ERR_RL("__ip_vs_unlink_dest:vs weight < 0\n");
	}

	/*
	 *  Call the update_service function of its scheduler
	 */
	if (svcupd && svc->scheduler->update_service)
		svc->scheduler->update_service(svc);
}

static void
ip_vs_add_dest_rollback(struct ip_vs_service *svc,
			const union nf_inet_addr *daddr,
			__be16 dport, int cpu)
{
	int i;
	struct ip_vs_dest *dest;
	struct ip_vs_service *this_svc;

	for(i = 0; i < cpu; i++)
	{
		this_svc = svc->svc0 + i;
		dest = ip_vs_lookup_dest(this_svc, daddr, dport);
		if(dest == NULL)
			continue;

		spin_lock_bh(&per_cpu(ip_vs_svc_lock, i));
		__ip_vs_unlink_dest(this_svc, dest, 1);
		spin_unlock_bh(&per_cpu(ip_vs_svc_lock, i));

		__ip_vs_del_dest(dest);
	}
}

/*
 *	Delete a destination server in the given service
 */
static int
ip_vs_del_dest(struct ip_vs_service *svc, struct ip_vs_dest_user_kern *udest)
{
	struct ip_vs_dest *dest;
	__be16 dport = udest->port;
	int cpu;
	struct ip_vs_service *this_svc;

	for_each_possible_cpu(cpu) {
		this_svc = svc->svc0 + cpu;
		dest = ip_vs_lookup_dest(this_svc, &udest->addr, dport);

		if (dest == NULL) {
			IP_VS_DBG(1, "%s(): destination not found!\n",
							__func__);
			return -ENOENT;
		}

		spin_lock_bh(&per_cpu(ip_vs_svc_lock, cpu));

		/*
		 *      Unlink dest from the service
		 */
		__ip_vs_unlink_dest(this_svc, dest, 1);

		spin_unlock_bh(&per_cpu(ip_vs_svc_lock, cpu));

		/*
		 *      Delete the destination
		 */
		__ip_vs_del_dest(dest);
	}

	return 0;
}

#define LADDR_MASK 0x000000ff
static inline int laddr_to_cpuid(int af, const union nf_inet_addr *addr)
{
	int cpu;
	unsigned seed;
	unsigned pos;
	unsigned idx = 0;

	if(af == AF_INET6)
		seed = rte_be_to_cpu_32(addr->in6.s6_addr32[3]) & LADDR_MASK;
	else
		seed = rte_be_to_cpu_32(addr->ip) & LADDR_MASK;

	pos = seed % ofp_vs_num_workers; 

	for_each_odp_cpumask(cpu, &ofp_vs_workers_cpumask) {
		if (idx++ == pos)
			break;
	}

	return cpu;
}

void ip_vs_laddr_hold(struct ip_vs_laddr *laddr)
{
	atomic_inc(&laddr->refcnt);
}

void ip_vs_laddr_put(struct ip_vs_laddr *laddr)
{
	if (atomic_dec_and_test(&laddr->refcnt)) {
		rte_free(laddr);
	}
}

static int
ip_vs_new_laddr(struct ip_vs_service *svc, struct ip_vs_laddr_user_kern *uladdr,
		struct ip_vs_laddr **laddr_p)
{
	struct ip_vs_laddr *laddr;

	laddr = rte_zmalloc(NULL, sizeof(struct ip_vs_laddr), 0);
	if (!laddr) {
		pr_err("%s(): no memory.\n", __func__);
		return -ENOMEM;
	}

	laddr->af = svc->af;
	ip_vs_addr_copy(svc->af, &laddr->addr, &uladdr->addr);
	atomic64_set(&laddr->port_conflict, 0);
	laddr->port = 0;
	atomic_set(&laddr->refcnt, 0);
	atomic_set(&laddr->conn_counts, 0);
	laddr->cpuid = laddr_to_cpuid(svc->af, &uladdr->addr);
	IP_VS_DBG_BUF(0, "local address %s is assigned to cpu%d\n",
			IP_VS_DBG_ADDR(svc->af, &uladdr->addr), laddr->cpuid);

	*laddr_p = laddr;

	return 0;
}

static struct ip_vs_laddr *ip_vs_lookup_laddr(struct ip_vs_service *svc,
					      const union nf_inet_addr *addr)
{
	int cpu;
	struct ip_vs_service *this_svc;
	struct ip_vs_laddr *laddr;

	this_svc = svc->svc0;
	for_each_possible_cpu(cpu) {
		/*
		 * Find the local address for the given service
		 */
		list_for_each_entry(laddr, &this_svc->laddr_list, n_list) {
			if ((laddr->af == svc->af)
			    && ip_vs_addr_equal(svc->af, &laddr->addr, addr)) {
				/* HIT */
				return laddr;
			}
		}
		this_svc++;
	}

	return NULL;
}

static int
ip_vs_add_laddr(struct ip_vs_service *svc, struct ip_vs_laddr_user_kern *uladdr)
{
	struct ip_vs_laddr *laddr;
	struct ip_vs_service *this_svc;
	int cpu;
	int ret;

	IP_VS_DBG_BUF(0, "vip %s:%d add local address %s\n",
		      IP_VS_DBG_ADDR(svc->af, &svc->addr), ntohs(svc->port),
		      IP_VS_DBG_ADDR(svc->af, &uladdr->addr));

	if (uladdr->addr.ip == 0)
		return -EINVAL;

	/*
	 * Check if the local address already exists in the list
	 */
	laddr = ip_vs_lookup_laddr(svc, &uladdr->addr);
	if (laddr) {
		IP_VS_DBG(1, "%s(): local address already exists\n", __func__);
		return -EEXIST;
	}

	/*
	 * Allocate and initialize the dest structure
	 */
	ret = ip_vs_new_laddr(svc, uladdr, &laddr);
	if (ret) {
		return ret;
	}

	/*
	 * Add the local adress entry into the list
	 */
	ip_vs_laddr_hold(laddr);

	cpu = laddr->cpuid;
	this_svc = svc->svc0 + cpu;

	spin_lock_bh(&per_cpu(ip_vs_svc_lock, cpu));

	list_add_tail(&laddr->n_list, &this_svc->laddr_list);
	this_svc->num_laddrs++;

#ifdef OFP_DEBUG
	/* Dump the destinations */
	IP_VS_DBG_BUF(0, "	cpu%d svc %s:%d num %d curr %p \n",
			cpu, IP_VS_DBG_ADDR(svc->af, &svc->addr),
			ntohs(this_svc->port), this_svc->num_laddrs,
			this_svc->curr_laddr);
	list_for_each_entry(laddr, &this_svc->laddr_list, n_list) {
		IP_VS_DBG_BUF(0, "		laddr %p %s:%d \n",
			      laddr, IP_VS_DBG_ADDR(svc->af, &laddr->addr), 0);
	}
#endif

	spin_unlock_bh(&per_cpu(ip_vs_svc_lock, cpu));

	return 0;
}

static int
ip_vs_del_laddr(struct ip_vs_service *svc, struct ip_vs_laddr_user_kern *uladdr)
{
	struct ip_vs_laddr *laddr;
	struct ip_vs_service *this_svc;
	int cpu;

	IP_VS_DBG_BUF(0, "vip %s:%d del local address %s\n",
		      IP_VS_DBG_ADDR(svc->af, &svc->addr), ntohs(svc->port),
		      IP_VS_DBG_ADDR(svc->af, &uladdr->addr));

	laddr = ip_vs_lookup_laddr(svc, &uladdr->addr);

	if (laddr == NULL) {
		IP_VS_DBG(1, "%s(): local address not found!\n", __func__);
		return -ENOENT;
	}

	cpu = laddr->cpuid;
	this_svc = svc->svc0 + cpu;

	spin_lock_bh(&per_cpu(ip_vs_svc_lock, cpu));

	/* update svc->curr_laddr */
	if (this_svc->curr_laddr == &laddr->n_list)
		this_svc->curr_laddr = laddr->n_list.next;
	/*
	 *      Unlink dest from the service
	 */
	list_del(&laddr->n_list);
	this_svc->num_laddrs--;

#ifdef OFP_DEBUG
	IP_VS_DBG_BUF(0, "	cpu%d svc %s:%d num %d curr %p \n",
			cpu, IP_VS_DBG_ADDR(svc->af, &svc->addr),
			ntohs(svc->port), this_svc->num_laddrs,
			this_svc->curr_laddr);
	list_for_each_entry(laddr, &this_svc->laddr_list, n_list) {
		IP_VS_DBG_BUF(0, "		laddr %p %s:%d \n",
			      laddr, IP_VS_DBG_ADDR(svc->af, &laddr->addr), 0);
	}
#endif

	ip_vs_laddr_put(laddr);

	spin_unlock_bh(&per_cpu(ip_vs_svc_lock, cpu));

	return 0;
}

/*
 *	Add a service into the service hash table
 */
static int
ip_vs_add_service(struct ip_vs_service_user_kern *u,
		  struct ip_vs_service **svc_p)
{
	int ret = 0, cpu = 0;
	struct ip_vs_scheduler *sched = NULL;
	struct ip_vs_service *svc = NULL;
	struct ip_vs_service *this_svc = NULL;

	/* increase the module use count */
	ip_vs_use_count_inc();

	/* Lookup the scheduler by 'u->sched_name' */
	sched = ip_vs_scheduler_get(u->sched_name);
	if (sched == NULL) {
		pr_info("Scheduler module ip_vs_%s not found\n", u->sched_name);
		ret = -ENOENT;
		goto out_mod_dec;
	}
#ifdef CONFIG_IP_VS_IPV6
	if (u->af == AF_INET6 && (u->netmask < 1 || u->netmask > 128)) {
		ret = -EINVAL;
		goto out_sched;
	}
#endif

	svc = rte_zmalloc("ip_vs_svc",
		sizeof(struct ip_vs_service) * num_possible_cpus(), 0);

	if (svc == NULL) {
		IP_VS_DBG(1, "%s(): no memory\n", __func__);
		ret = -ENOMEM;
		goto out_sched;
	}

	for_each_possible_cpu(cpu) {
		this_svc = svc + cpu;
		atomic_set(&this_svc->refcnt, 0);

		this_svc->af = u->af;
		this_svc->protocol = u->protocol;
		ip_vs_addr_copy(u->af, &this_svc->addr, &u->addr);
		this_svc->port = u->port;
		this_svc->fwmark = u->fwmark;
		this_svc->flags = u->flags;
		this_svc->timeout = u->timeout * HZ;
		this_svc->netmask = u->netmask;
		this_svc->est_timeout = u->est_timeout * HZ;

		/* Init the local address stuff */
		rwlock_init(&this_svc->laddr_lock);
		INIT_LIST_HEAD(&this_svc->laddr_list);
		this_svc->num_laddrs = 0;
		this_svc->curr_laddr = &this_svc->laddr_list;

		INIT_LIST_HEAD(&this_svc->destinations);
		rwlock_init(&this_svc->sched_lock);

		/* Bind the scheduler */
		ret = ip_vs_bind_scheduler(this_svc, sched);
		if (ret)
			goto out_err;

		/* Hash the service into the service table */
		spin_lock_bh(&per_cpu(ip_vs_svc_lock, cpu));
		ip_vs_svc_hash_cpuid(this_svc, cpu);
		spin_unlock_bh(&per_cpu(ip_vs_svc_lock, cpu));

		this_svc->svc0 = svc;	/* save the first svc */
	}

	sched = NULL;
	/* Update the virtual service counters */
	if (svc->port == FTPPORT)
		atomic_inc(&ip_vs_ftpsvc_counter);
	else if (svc->port == 0)
		atomic_inc(&ip_vs_nullsvc_counter);

	/* Count only IPv4 services for old get/setsockopt interface */
	if (svc->af == AF_INET)
		ip_vs_num_services++;

	/* svc is percpu, NULL is OK */
	*svc_p = NULL;
	return 0;

out_err:
	for_each_possible_cpu(cpu) {
		this_svc = svc + cpu;
		spin_lock_bh(&per_cpu(ip_vs_svc_lock, cpu));
		ip_vs_svc_unhash(this_svc);
		spin_unlock_bh(&per_cpu(ip_vs_svc_lock, cpu));
		if (this_svc->scheduler)
			ip_vs_unbind_scheduler(this_svc);
		if (this_svc->inc) {
			//local_bh_disable();
			//ip_vs_app_inc_put(this_svc->inc);
			//local_bh_enable();
		}
	}
	rte_free(svc);
out_sched:
	ip_vs_scheduler_put(sched);
out_mod_dec:
	/* decrease the module use count */
	ip_vs_use_count_dec();

	return ret;
}

/*
 *	Edit a service and bind it with a new scheduler
 */
static int
ip_vs_edit_service(struct ip_vs_service *svc, struct ip_vs_service_user_kern *u)
{
	struct ip_vs_scheduler *sched, *old_sched;
	struct ip_vs_service *this_svc;
	int ret = 0;
	int cpu = 0;

	/*
	 * Lookup the scheduler, by 'u->sched_name'
	 */
	sched = ip_vs_scheduler_get(u->sched_name);
	if (sched == NULL) {
		pr_info("Scheduler module ip_vs_%s not found\n", u->sched_name);
		return -ENOENT;
	}
	old_sched = sched;

#ifdef CONFIG_IP_VS_IPV6
	if (u->af == AF_INET6 && (u->netmask < 1 || u->netmask > 128)) {
		ret = -EINVAL;
		goto out;
	}
#endif

	for_each_possible_cpu(cpu) {
		this_svc = svc->svc0 + cpu;
		spin_lock_bh(&per_cpu(ip_vs_svc_lock, cpu));
		/*
		 * Set the flags and timeout value
		 */
		this_svc->flags = u->flags | IP_VS_SVC_F_HASHED;
		this_svc->timeout = u->timeout*HZ;
		this_svc->netmask = u->netmask;
		this_svc->est_timeout = u->est_timeout*HZ;

		spin_unlock_bh(&per_cpu(ip_vs_svc_lock, cpu));
	}

	for_each_possible_cpu(cpu) {
		this_svc = svc->svc0 + cpu;
		spin_lock_bh(&per_cpu(ip_vs_svc_lock, cpu));

		old_sched = this_svc->scheduler;
		if (sched != old_sched) {
			/*
			 * Unbind the old scheduler
			 */
			if ((ret = ip_vs_unbind_scheduler(this_svc))) {
				old_sched = sched;
				spin_unlock_bh(&per_cpu(ip_vs_svc_lock, cpu));
				goto out_sched;
			}

			/*
			 * Bind the new scheduler
			 */
			if ((ret = ip_vs_bind_scheduler(this_svc, sched))) {
				/*
				 * If ip_vs_bind_scheduler fails, restore
				 * the old scheduler.
				 * The main reason of failure is out of memory.
				 *
				 * The question is if the old scheduler can be
				 * restored all the time. TODO: if it cannot be
				 * restored some time, we must delete the
				 * service, otherwise the system may crash.
				 */
				ip_vs_bind_scheduler(this_svc, old_sched);
				old_sched = sched;
				spin_unlock_bh(&per_cpu(ip_vs_svc_lock, cpu));
				goto out_sched;
			}
		}
		spin_unlock_bh(&per_cpu(ip_vs_svc_lock, cpu));
	}

out_sched:
	/* todo: rollback scheduler if error */

#ifdef CONFIG_IP_VS_IPV6
	    out:
#endif

	if (old_sched)
		ip_vs_scheduler_put(old_sched);

	return ret;
}

/*
 *	Delete a service from the service list
 *	- The service must be unlinked, unlocked and not referenced!
 *	- We are called under _bh lock
 */
static void __ip_vs_del_service(struct ip_vs_service *svc)
{
	struct ip_vs_dest *dest, *nxt;
	struct ip_vs_laddr *laddr, *laddr_next;
	struct ip_vs_scheduler *old_sched;
	struct ip_vs_service *this_svc;
	int cpu = 0;

	/* Count only IPv4 services for old get/setsockopt interface */
	if (svc->af == AF_INET)
		ip_vs_num_services--;

	for_each_possible_cpu(cpu) {
		this_svc = svc->svc0 + cpu;
		spin_lock_bh(&per_cpu(ip_vs_svc_lock, cpu));

		/* Unbind scheduler */
		old_sched = this_svc->scheduler;
		ip_vs_unbind_scheduler(this_svc);

		/* Unbind app inc */
		if (this_svc->inc) {
			//ip_vs_app_inc_put(this_svc->inc);
			this_svc->inc = NULL;
		}

		/* Unlink the whole local address list */
		list_for_each_entry_safe(laddr, laddr_next,
				&this_svc->laddr_list, n_list) {
			list_del(&laddr->n_list);
			ip_vs_laddr_put(laddr);
		}

		/*
		 *    Unlink the whole destination list
		 */
		list_for_each_entry_safe(dest, nxt,
				&this_svc->destinations, n_list) {
			__ip_vs_unlink_dest(this_svc, dest, 0);
			__ip_vs_del_dest(dest);
		}

		spin_unlock_bh(&per_cpu(ip_vs_svc_lock, cpu));
	}

	if (old_sched)
		ip_vs_scheduler_put(old_sched);
	/*
	 *    Update the virtual service counters
	 */
	if (svc->port == FTPPORT)
		atomic_dec(&ip_vs_ftpsvc_counter);
	else if (svc->port == 0)
		atomic_dec(&ip_vs_nullsvc_counter);

	/*
	 *    Free the service if nobody refers to it
	 */
	this_svc = svc->svc0;
	for_each_possible_cpu(cpu) {
		if (atomic_read(&this_svc->refcnt)) {
			IP_VS_DBG_BUF(2, "%s(): cpu%d refers to svc %s:%d,"
					"refcnt=%d\n", __func__, cpu,
					IP_VS_DBG_ADDR(svc->af, &svc->addr),
					ntohs(svc->port),
					atomic_read(&this_svc->refcnt));
			break;
		}
		this_svc++;
	}

	if (cpu == num_possible_cpus())
		rte_free(svc->svc0);

	/* decrease the module use count */
	ip_vs_use_count_dec();
}

/*
 *	Delete a service from the service list
 */
static int ip_vs_del_service(struct ip_vs_service *svc)
{
	struct ip_vs_service *this_svc;
	int cpu = 0;

	if (svc == NULL)
		return -EEXIST;

	/*
	 * Unhash it from the service table
	 */
	this_svc = svc->svc0;
	for_each_possible_cpu(cpu) {
		spin_lock_bh(&per_cpu(ip_vs_svc_lock, cpu));

		ip_vs_svc_unhash(this_svc);
		spin_unlock_bh(&per_cpu(ip_vs_svc_lock, cpu));

		this_svc++;
	}

	__ip_vs_del_service(svc);

	return 0;
}

/*
 * Generic Netlink interface
 */

/* Policy used for first-level command attributes */
static struct nla_policy ip_vs_cmd_policy[IPVS_CMD_ATTR_MAX + 1] = {
	[IPVS_CMD_ATTR_SERVICE] = {.type = NLA_NESTED},
	[IPVS_CMD_ATTR_DEST] = {.type = NLA_NESTED},
	[IPVS_CMD_ATTR_DAEMON] = {.type = NLA_NESTED},
	[IPVS_CMD_ATTR_TIMEOUT_TCP] = {.type = NLA_U32},
	[IPVS_CMD_ATTR_TIMEOUT_TCP_FIN] = {.type = NLA_U32},
	[IPVS_CMD_ATTR_TIMEOUT_UDP] = {.type = NLA_U32},
	[IPVS_CMD_ATTR_LADDR] = {.type = NLA_NESTED},
}; 

/* Policy used for attributes in nested attribute IPVS_CMD_ATTR_DAEMON */
/*
static struct nla_policy ip_vs_daemon_policy[IPVS_DAEMON_ATTR_MAX + 1] = {
	[IPVS_DAEMON_ATTR_STATE] = {.type = NLA_U32},
	[IPVS_DAEMON_ATTR_MCAST_IFN] = {.type = NLA_STRING,
					.minlen = IP_VS_IFNAME_MAXLEN},
	[IPVS_DAEMON_ATTR_SYNC_ID] = {.type = NLA_U32},
};
*/

/* Policy used for attributes in nested attribute IPVS_CMD_ATTR_SERVICE */
static struct nla_policy ip_vs_svc_policy[IPVS_SVC_ATTR_MAX + 1] = {
	[IPVS_SVC_ATTR_AF] = {.type = NLA_U16},
	[IPVS_SVC_ATTR_PROTOCOL] = {.type = NLA_U16},
	[IPVS_SVC_ATTR_ADDR] = {.type = NLA_UNSPEC,
				.minlen = sizeof(union nf_inet_addr)},
	[IPVS_SVC_ATTR_PORT] = {.type = NLA_U16},
	[IPVS_SVC_ATTR_FWMARK] = {.type = NLA_U32},
	[IPVS_SVC_ATTR_SCHED_NAME] = {.type = NLA_STRING,
				      .maxlen = IP_VS_SCHEDNAME_MAXLEN},
	[IPVS_SVC_ATTR_FLAGS] = {.type = NLA_UNSPEC,
				 .minlen = sizeof(struct ip_vs_flags)},
	[IPVS_SVC_ATTR_TIMEOUT] = {.type = NLA_U32},
	[IPVS_SVC_ATTR_NETMASK] = {.type = NLA_U32},
	[IPVS_SVC_ATTR_STATS] = {.type = NLA_NESTED},
};

/* Policy used for attributes in nested attribute IPVS_CMD_ATTR_DEST */
static struct nla_policy ip_vs_dest_policy[IPVS_DEST_ATTR_MAX + 1] = {
	[IPVS_DEST_ATTR_ADDR] = {.type = NLA_UNSPEC,
				 .minlen = sizeof(union nf_inet_addr)},
	[IPVS_DEST_ATTR_PORT] = {.type = NLA_U16},
	[IPVS_DEST_ATTR_FWD_METHOD] = {.type = NLA_U32},
	[IPVS_DEST_ATTR_WEIGHT] = {.type = NLA_U32},
	[IPVS_DEST_ATTR_U_THRESH] = {.type = NLA_U32},
	[IPVS_DEST_ATTR_L_THRESH] = {.type = NLA_U32},
	[IPVS_DEST_ATTR_ACTIVE_CONNS] = {.type = NLA_U32},
	[IPVS_DEST_ATTR_INACT_CONNS] = {.type = NLA_U32},
	[IPVS_DEST_ATTR_PERSIST_CONNS] = {.type = NLA_U32},
	[IPVS_DEST_ATTR_STATS] = {.type = NLA_NESTED},
};

static struct nla_policy ip_vs_laddr_policy[IPVS_LADDR_ATTR_MAX + 1] = {
	[IPVS_LADDR_ATTR_ADDR] = {.type = NLA_UNSPEC,
				  .minlen = sizeof(union nf_inet_addr)},
	[IPVS_LADDR_ATTR_PORT_CONFLICT] = {.type = NLA_U64},
	[IPVS_LADDR_ATTR_CONN_COUNTS] = {.type = NLA_U32},
};




static int ip_vs_genl_parse_service(struct ip_vs_service_user_kern *usvc,
				    struct nlattr *nla, int full_entry)
{
	struct nlattr *attrs[IPVS_SVC_ATTR_MAX + 1];
	struct nlattr *nla_af, *nla_port, *nla_fwmark, *nla_protocol, *nla_addr;
	int ret = 0;

	/* Parse mandatory identifying service fields first */
	if (nla == NULL ||
	    (ret = nla_parse_nested(attrs, IPVS_SVC_ATTR_MAX, nla, ip_vs_svc_policy))) {
		OFP_ERR("%s %s:%d nla %p nla_parse_nested return %d\n",
	          __func__, __FILE__, __LINE__, nla, ret);
		return -EINVAL;
	}

	nla_af = attrs[IPVS_SVC_ATTR_AF];
	nla_protocol = attrs[IPVS_SVC_ATTR_PROTOCOL];
	nla_addr = attrs[IPVS_SVC_ATTR_ADDR];
	nla_port = attrs[IPVS_SVC_ATTR_PORT];
	nla_fwmark = attrs[IPVS_SVC_ATTR_FWMARK];

	if (!(nla_af && (nla_fwmark || (nla_port && nla_protocol && nla_addr)))) {
		OFP_ERR("return EINVAL %s %s:%d\n", __func__, __FILE__, __LINE__);
		return -EINVAL;
	}

	memset(usvc, 0, sizeof(*usvc));

	usvc->af = nla_get_u16(nla_af);
#ifdef CONFIG_IP_VS_IPV6
	if (usvc->af != AF_INET && usvc->af != AF_INET6)
#else
	if (usvc->af != AF_INET)
#endif
		return -EAFNOSUPPORT;

	if (nla_fwmark) {
		usvc->protocol = IPPROTO_TCP;
		usvc->fwmark = nla_get_u32(nla_fwmark);
	} else {
		usvc->protocol = nla_get_u16(nla_protocol);
		nla_memcpy(&usvc->addr, nla_addr, sizeof(usvc->addr));
		usvc->port = nla_get_u16(nla_port);
		usvc->fwmark = 0;
	}

	/* If a full entry was requested, check for the additional fields */
	if (full_entry) {
		struct nlattr *nla_sched, *nla_flags, *nla_timeout,
		    *nla_netmask, *nla_est_timeout;
		struct ip_vs_flags flags;
		struct ip_vs_service *svc;

		nla_sched = attrs[IPVS_SVC_ATTR_SCHED_NAME];
		nla_flags = attrs[IPVS_SVC_ATTR_FLAGS];
		nla_timeout = attrs[IPVS_SVC_ATTR_TIMEOUT];
		nla_netmask = attrs[IPVS_SVC_ATTR_NETMASK];
		nla_est_timeout = attrs[IPVS_SVC_ATTR_EST_TIMEOUT];

		if (!(nla_sched && nla_flags && nla_timeout && nla_netmask)) {
	    OFP_ERR("return EINVAL %s %s:%d\n", __func__, __FILE__, __LINE__);
			return -EINVAL;
	  }

		nla_memcpy(&flags, nla_flags, sizeof(flags));

		/* prefill flags from service if it already exists */
		if (usvc->fwmark)
			svc = __ip_vs_svc_fwm_get(usvc->af, usvc->fwmark);
		else
			svc = __ip_vs_service_get(usvc->af, usvc->protocol,
						  &usvc->addr, usvc->port);
		if (svc) {
			usvc->flags = svc->flags;
			//ip_vs_service_put(svc);
		} else
			usvc->flags = 0;

		/* set new flags from userland */
		usvc->flags = (usvc->flags & ~flags.mask) |
		    (flags.flags & flags.mask);
		usvc->sched_name = nla_data(nla_sched);
		usvc->timeout = nla_get_u32(nla_timeout);
		usvc->netmask = nla_get_u32(nla_netmask);
		if(IPPROTO_TCP == usvc->protocol) {
			if(nla_est_timeout) /* Be compatible with different version of libipvs2.6 */
				usvc->est_timeout = nla_get_u32(nla_est_timeout);
			if(!usvc->est_timeout)
				usvc->est_timeout = sysctl_ip_vs_tcp_timeouts[IP_VS_TCP_S_ESTABLISHED]/HZ ;
		}
	}

	return 0;
}

static struct ip_vs_service *ip_vs_genl_find_service(struct nlattr *nla)
{
	struct ip_vs_service_user_kern usvc;
	int ret;

	ret = ip_vs_genl_parse_service(&usvc, nla, 0);
	if (ret)
		return ERR_PTR(ret);

	if (usvc.fwmark)
		return __ip_vs_svc_fwm_get(usvc.af, usvc.fwmark);
	else
		return __ip_vs_service_get(usvc.af, usvc.protocol,
					   &usvc.addr, usvc.port);
}

static int ip_vs_genl_fill_stats(struct nl_msg *msg, int container_type,
				 struct ip_vs_stats *stats)
{
	struct nlattr *nl_stats = nla_nest_start(msg, container_type);

	if (!nl_stats)
		return -EMSGSIZE;

	NLA_PUT_U64(msg, IPVS_STATS_ATTR_CONNS, stats->conns);
	NLA_PUT_U64(msg, IPVS_STATS_ATTR_INPKTS, stats->inpkts);
	NLA_PUT_U64(msg, IPVS_STATS_ATTR_OUTPKTS, stats->outpkts);
	NLA_PUT_U64(msg, IPVS_STATS_ATTR_INBYTES, stats->inbytes);
	NLA_PUT_U64(msg, IPVS_STATS_ATTR_OUTBYTES, stats->outbytes);
	NLA_PUT_U32(msg, IPVS_STATS_ATTR_CPS, 0);
	NLA_PUT_U32(msg, IPVS_STATS_ATTR_INPPS, 0);
	NLA_PUT_U32(msg, IPVS_STATS_ATTR_OUTPPS, 0);
	NLA_PUT_U32(msg, IPVS_STATS_ATTR_INBPS, 0);
	NLA_PUT_U32(msg, IPVS_STATS_ATTR_OUTBPS, 0);

	nla_nest_end(msg, nl_stats);

	return 0;

nla_put_failure:
	nla_nest_cancel(msg, nl_stats);
	return -EMSGSIZE;
}

static int ip_vs_genl_fill_service(struct nl_msg *msg,
				   struct ip_vs_service *svc)
{
	int cpu;
	struct ip_vs_stats tmp_stats;
	struct ip_vs_service *this_svc;
	struct nlattr *nl_service;
	struct ip_vs_flags flags = {.flags = svc->flags,
		.mask = ~0
	};

	nl_service = nla_nest_start(msg, IPVS_CMD_ATTR_SERVICE);
	if (!nl_service)
		return -EMSGSIZE;

	NLA_PUT_U16(msg, IPVS_SVC_ATTR_AF, svc->af);

	if (svc->fwmark) {
		NLA_PUT_U32(msg, IPVS_SVC_ATTR_FWMARK, svc->fwmark);
	} else {
		NLA_PUT_U16(msg, IPVS_SVC_ATTR_PROTOCOL, svc->protocol);
		NLA_PUT(msg, IPVS_SVC_ATTR_ADDR, sizeof(svc->addr), &svc->addr);
		NLA_PUT_U16(msg, IPVS_SVC_ATTR_PORT, svc->port);
	}

	NLA_PUT_STRING(msg, IPVS_SVC_ATTR_SCHED_NAME, svc->scheduler->name);
	NLA_PUT(msg, IPVS_SVC_ATTR_FLAGS, sizeof(flags), &flags);
	NLA_PUT_U32(msg, IPVS_SVC_ATTR_TIMEOUT, svc->timeout);
	NLA_PUT_U32(msg, IPVS_SVC_ATTR_NETMASK, svc->netmask);
	NLA_PUT_U32(msg, IPVS_SVC_ATTR_EST_TIMEOUT, svc->est_timeout/HZ);

	memset((void*)(&tmp_stats), 0, sizeof(struct ip_vs_stats));
	this_svc = svc->svc0;
	for_each_possible_cpu(cpu) {
		tmp_stats.conns += this_svc->stats.conns;
		tmp_stats.inpkts += this_svc->stats.inpkts;
		tmp_stats.outpkts += this_svc->stats.outpkts;
		tmp_stats.inbytes += this_svc->stats.inbytes;
		tmp_stats.outbytes += this_svc->stats.outbytes;

		this_svc++;
	}

	if (ip_vs_genl_fill_stats(msg, IPVS_SVC_ATTR_STATS, &tmp_stats))
		goto nla_put_failure;

	nla_nest_end(msg, nl_service);

	return 0;

nla_put_failure:
	nla_nest_cancel(msg, nl_service);
	return -EMSGSIZE;
}

static int ip_vs_genl_dump_services(struct genl_cmd *cmd,
	                                  struct genl_info *info,
	                                  void *arg);

static inline void __ip_vs_get_timeouts(struct ip_vs_timeout_user *u)
{
	(void)u;
#ifdef CONFIG_IP_VS_PROTO_TCP
	u->tcp_timeout =
	    ip_vs_protocol_tcp.timeout_table[IP_VS_TCP_S_ESTABLISHED]/HZ;
	u->tcp_fin_timeout =
	    ip_vs_protocol_tcp.timeout_table[IP_VS_TCP_S_FIN_WAIT]/HZ;
#endif
#ifdef CONFIG_IP_VS_PROTO_UDP
	u->udp_timeout =
	    ip_vs_protocol_udp.timeout_table[IP_VS_UDP_S_NORMAL]/HZ;
#endif
}



static int ip_vs_genl_get_cmd(struct nl_cache_ops *ops,
	                            struct genl_cmd *cmd,
	                            struct genl_info *info,
	                            void *arg)
{
	struct nl_msg *msg;
	//struct nlattr *nl_attr;
	int ret = 0, cmd_id, reply_cmd;
	struct nlattr *attrs[IPVS_CMD_ATTR_MAX + 1];

	(void)arg;
	(void)ops;
	cmd_id = info->genlhdr->cmd;
	
	OFP_DBG("Get command: %s\n", cmd->c_name);

	if (cmd_id == IPVS_CMD_GET_SERVICE) {
		if (info->nlh->nlmsg_flags & NLM_F_DUMP) {
	  		return ip_vs_genl_dump_services(cmd, info, arg);
		}
		reply_cmd = IPVS_CMD_NEW_SERVICE;
	} else if (cmd_id == IPVS_CMD_GET_INFO)
		reply_cmd = IPVS_CMD_SET_INFO;
	else if (cmd_id == IPVS_CMD_GET_CONFIG)
		reply_cmd = IPVS_CMD_SET_CONFIG;
	else {
		OFP_ERR("unknown Generic Netlink command\n");
		return -EINVAL;
	}

	msg = ipvs_nl_message(info, reply_cmd, 0);
	if (!msg)
		return -ENOMEM;

	mutex_lock(&__ip_vs_mutex);

	
	/* Try to find the service for which to dump destinations */
	if (nlmsg_parse(info->nlh, GENL_HDRLEN, attrs,
			IPVS_CMD_ATTR_MAX, ip_vs_cmd_policy)) {
		ret = -EINVAL;
		goto out_err;
	}


	switch (cmd_id) {
	case IPVS_CMD_GET_INFO:
		NLA_PUT_U32(msg, IPVS_INFO_ATTR_VERSION, IP_VS_VERSION_CODE);
		NLA_PUT_U32(msg, IPVS_INFO_ATTR_CONN_TAB_SIZE, IP_VS_CONN_TAB_SIZE);
		break;

	case IPVS_CMD_GET_SERVICE:
		{
			struct ip_vs_service *svc;

			svc =
			    ip_vs_genl_find_service(attrs[IPVS_CMD_ATTR_SERVICE]);
			if (IS_ERR(svc)) {
				ret = PTR_ERR(svc);
				goto out_err;
			} else if (svc) {
				ret = ip_vs_genl_fill_service(msg, svc);
			//	ip_vs_service_put(svc);
				if (ret)
					goto nla_put_failure;
			} else {
				ret = -ESRCH;
				goto out_err;
			}

			break;
		}
	case IPVS_CMD_GET_CONFIG:
		{
			struct ip_vs_timeout_user t;

			__ip_vs_get_timeouts(&t);
#ifdef CONFIG_IP_VS_PROTO_TCP
			NLA_PUT_U32(msg, IPVS_CMD_ATTR_TIMEOUT_TCP,
				    t.tcp_timeout);
			NLA_PUT_U32(msg, IPVS_CMD_ATTR_TIMEOUT_TCP_FIN,
				    t.tcp_fin_timeout);
#endif
#ifdef CONFIG_IP_VS_PROTO_UDP
			NLA_PUT_U32(msg, IPVS_CMD_ATTR_TIMEOUT_UDP,
				    t.udp_timeout);
#endif

			break;
		} 
	}

	ret = ipvs_nl_reply(info, msg);
	if (ret < 0)
		OFP_ERR("ipvs_nl_reply return %d\n", ret);
	goto out; 

nla_put_failure:
	pr_err("not enough space in Netlink message\n");
	ret = -EMSGSIZE;

out_err:
	nlmsg_free(msg);
	ret = ipvs_nl_reply_error(info, reply_cmd, ret);
	if (ret < 0)
		OFP_ERR("nl reply return %d\n", ret);

out:
	mutex_unlock(&__ip_vs_mutex);

	return ret;
}

static int ip_vs_genl_fill_laddr(struct nl_msg *msg, struct ip_vs_laddr *laddr)
{
	struct nlattr *nl_laddr;

	nl_laddr = nla_nest_start(msg, IPVS_CMD_ATTR_LADDR);
	if (!nl_laddr)
		return -EMSGSIZE;

	NLA_PUT(msg, IPVS_LADDR_ATTR_ADDR, sizeof(laddr->addr), &laddr->addr);
	NLA_PUT_U64(msg, IPVS_LADDR_ATTR_PORT_CONFLICT,
		    atomic64_read(&laddr->port_conflict));
	NLA_PUT_U32(msg, IPVS_LADDR_ATTR_CONN_COUNTS,
		    atomic_read(&laddr->conn_counts));

	nla_nest_end(msg, nl_laddr);

	return 0;

nla_put_failure:
	nla_nest_cancel(msg, nl_laddr);
	return -EMSGSIZE;
}

static int ip_vs_genl_dump_laddr(struct genl_info *info,
	                               struct ip_vs_laddr *laddr) {
	int ret;
	struct nl_msg *msg;

	if (!laddr) {
		OFP_ERR("laddr is NULL\n");
		return -EMSGSIZE;
	}

	msg = ipvs_nl_message(info, IPVS_CMD_NEW_LADDR, NLM_F_MULTI);
	if (!msg)
		return -EMSGSIZE;

	if (ip_vs_genl_fill_laddr(msg, laddr) < 0)
		goto nla_put_failure;

	ret = ipvs_nl_reply(info, msg);
	if (ret < 0)
		OFP_ERR("ipvs_nl_reply return %d\n", ret);
	return ret;

nla_put_failure:
	return -EMSGSIZE;
}

static int ip_vs_genl_dump_laddrs(struct nl_cache_ops *ops,
	                                struct genl_cmd *cmd,
	                                struct genl_info *info,
	                                void *arg)
{
	int idx = 0;
	int cpu;
	int start = 0;
	int ret = 0;
	struct ip_vs_service *svc;
	struct ip_vs_service *svc_per;
	struct ip_vs_laddr *laddr;
	struct nlattr *attrs[IPVS_CMD_ATTR_MAX + 1];

	(void)arg;
	(void)ops;
	OFP_DBG("Dump command: %s\n", cmd->c_name);

	mutex_lock(&__ip_vs_mutex);

	/* Try to find the service for which to dump destinations */
	if (nlmsg_parse(info->nlh, GENL_HDRLEN, attrs,
			IPVS_CMD_ATTR_MAX, ip_vs_cmd_policy))
		goto out_err;

	svc = ip_vs_genl_find_service(attrs[IPVS_CMD_ATTR_SERVICE]);
	if (IS_ERR(svc) || svc == NULL) {
		ret = -EINVAL;
		goto out_err;
	}

	IP_VS_DBG_BUF(0, "vip %s:%d get local address \n",
		      IP_VS_DBG_ADDR(svc->af, &svc->addr), ntohs(svc->port));

	for_each_online_cpu(cpu){
		svc_per = svc->svc0 + cpu;
		/* Dump the destinations */
		list_for_each_entry(laddr, &svc_per->laddr_list, n_list) {
			if (++idx <= start)
				continue;

			if (ip_vs_genl_dump_laddr(info, laddr) < 0) {
				idx--;
				goto nla_put_failure;
			}
		}
		//svc_per++;
	}

nla_put_failure:
	//ip_vs_service_put(svc);

out_err:
	if (ret < 0)
		ret = ipvs_nl_reply_error(info, IPVS_CMD_NEW_DEST, ret);
	else
		ret = ipvs_nl_multi_reply_done(info, IPVS_CMD_NEW_DEST);

	if (ret < 0)
		OFP_ERR("nl reply return %d\n", ret);
	mutex_unlock(&__ip_vs_mutex);
	return 0;
}

static int ip_vs_genl_fill_dest(struct nl_msg *msg, struct ip_vs_dest *dest)
{
	u32 activeconns, inactconns, persistconns;
	int cpu;
	struct ip_vs_stats tmp_stats;
	struct nlattr *nl_dest;
	struct ip_vs_dest *per_dest;
	struct ip_vs_service *svc;

	nl_dest = nla_nest_start(msg, IPVS_CMD_ATTR_DEST);
	if (!nl_dest)
		return -EMSGSIZE;

	NLA_PUT(msg, IPVS_DEST_ATTR_ADDR, sizeof(dest->addr), &dest->addr);
	NLA_PUT_U16(msg, IPVS_DEST_ATTR_PORT, dest->port);

	NLA_PUT_U32(msg, IPVS_DEST_ATTR_FWD_METHOD,
		    atomic_read(&dest->conn_flags) & IP_VS_CONN_F_FWD_MASK);
	NLA_PUT_U32(msg, IPVS_DEST_ATTR_WEIGHT, atomic_read(&dest->weight));
	NLA_PUT_U32(msg, IPVS_DEST_ATTR_U_THRESH, dest->u_threshold);
	NLA_PUT_U32(msg, IPVS_DEST_ATTR_L_THRESH, dest->l_threshold);

	activeconns = 0;
	inactconns = 0;
	persistconns = 0;
	memset((void*)(&tmp_stats), 0, sizeof(struct ip_vs_stats));
	svc = dest->svc->svc0;
	for_each_possible_cpu(cpu) {
		per_dest = ip_vs_lookup_dest(svc, &dest->addr, dest->port);
		if(per_dest == NULL) {
			IP_VS_ERR_RL("%s():dest doesn't exist on cpu%d\n",
					__func__, cpu);
			goto nla_put_failure;
		}

		activeconns += atomic_read(&per_dest->activeconns);
		inactconns += atomic_read(&per_dest->inactconns);
		persistconns += atomic_read(&per_dest->persistconns);

		tmp_stats.conns += per_dest->stats.conns;
		tmp_stats.inpkts += per_dest->stats.inpkts;
		tmp_stats.outpkts += per_dest->stats.outpkts;
		tmp_stats.inbytes += per_dest->stats.inbytes;
		tmp_stats.outbytes += per_dest->stats.outbytes;

		svc++;
	}

	NLA_PUT_U32(msg, IPVS_DEST_ATTR_ACTIVE_CONNS, activeconns);
	NLA_PUT_U32(msg, IPVS_DEST_ATTR_INACT_CONNS, inactconns);
	NLA_PUT_U32(msg, IPVS_DEST_ATTR_PERSIST_CONNS, persistconns);

	if (ip_vs_genl_fill_stats(msg, IPVS_DEST_ATTR_STATS, &tmp_stats))
		goto nla_put_failure;

	nla_nest_end(msg, nl_dest);

	return 0;

nla_put_failure:
	nla_nest_cancel(msg, nl_dest);
	return -EMSGSIZE;
}

static int ip_vs_genl_dump_dest(struct genl_info *info, struct ip_vs_dest *dest)
{
	int ret;
	struct nl_msg *msg;

	if (!dest) {
		OFP_ERR("dest is NULL\n");
		return -EMSGSIZE;
	}

	msg = ipvs_nl_message(info, IPVS_CMD_NEW_DEST, NLM_F_MULTI);
	if (!msg)
		return -EMSGSIZE;

	if (ip_vs_genl_fill_dest(msg, dest) < 0)
		goto nla_put_failure;

	ret = ipvs_nl_reply(info, msg);
	if (ret < 0)
		OFP_ERR("ipvs_nl_reply return %d\n", ret);
	return ret;

nla_put_failure:
	return -EMSGSIZE;
}

static int ip_vs_genl_dump_dests(struct nl_cache_ops *ops,
	                            struct genl_cmd *cmd,
	                            struct genl_info *info,
	                            void *arg)
{
	int idx = 0;
	int start = 0;
	int ret = 0;
	struct ip_vs_service *svc;
	struct ip_vs_dest *dest;
	struct nlattr *attrs[IPVS_CMD_ATTR_MAX + 1];

	(void)arg;
	(void)ops;
	OFP_DBG("Dump command: %s\n", cmd->c_name);

	mutex_lock(&__ip_vs_mutex);

	/* Try to find the service for which to dump destinations */
	if (nlmsg_parse(info->nlh, GENL_HDRLEN, attrs,
			IPVS_CMD_ATTR_MAX, ip_vs_cmd_policy)) {
	 	ret = -EINVAL;
		goto out_err;
	}

	svc = ip_vs_genl_find_service(attrs[IPVS_CMD_ATTR_SERVICE]);
	if (IS_ERR(svc)) {
		ret = PTR_ERR(svc); 
		goto out_err;
	} else if (svc == NULL) {
		ret = -ENOENT;  
		goto out_err;
	}

	/* Dump the destinations */
	list_for_each_entry(dest, &svc->destinations, n_list) {
		if (++idx <= start)
			continue;
		if ((ret = ip_vs_genl_dump_dest(info, dest)) < 0) {
			idx--;
			goto nla_put_failure;
		}
	}

nla_put_failure:
//	ip_vs_service_put(svc);

out_err:
	if (ret < 0)
		ret = ipvs_nl_reply_error(info, IPVS_CMD_NEW_DEST, ret);
	else
		ret = ipvs_nl_multi_reply_done(info, IPVS_CMD_NEW_DEST);

	if (ret < 0)
		OFP_ERR("nl reply return %d\n", ret);
	mutex_unlock(&__ip_vs_mutex);

	return ret;
}

static int ip_vs_genl_dump_daemons(struct nl_cache_ops *ops,
	                            struct genl_cmd *cmd,
	                            struct genl_info *info,
	                            void *arg)
{
	(void)arg;
	(void)ops;
	(void)info;
	OFP_DBG("Dump command: %s\n", cmd->c_name);
	return 0;
}

static int ip_vs_genl_dump_service(const struct genl_info *info,
				   struct ip_vs_service *svc)
{
	int ret;
	struct nl_msg *msg;

	if (!svc) {
		OFP_ERR("ip_vs_genl_dump_service:svc is NULL\n");
		return -EMSGSIZE;
	}

	msg = ipvs_nl_message(info, IPVS_CMD_NEW_SERVICE, NLM_F_MULTI);
	if (!msg)
		return -EMSGSIZE;

	if (ip_vs_genl_fill_service(msg, svc) < 0)
		goto nla_put_failure;

	ret = ipvs_nl_reply(info, msg);
	if (ret < 0)
		OFP_ERR("ipvs_nl_reply return %d\n", ret);
	return ret;

nla_put_failure:
	return -EMSGSIZE;
}

static int ip_vs_genl_dump_services(struct genl_cmd *cmd,
	                                  struct genl_info *info,
	                                  void *arg)
{
	int idx = 0, i;
	int start = 0;
	int ret = 0;
	struct ip_vs_service *svc;
	struct list_head *ip_vs_svc_tab;

	(void)arg;
	
	OFP_DBG("Dump command: %s\n", cmd->c_name);

	mutex_lock(&__ip_vs_mutex);
	for (i = 0; i < IP_VS_SVC_TAB_SIZE; i++) {
		ip_vs_svc_tab = __get_cpu_var(ip_vs_svc_tab_percpu);
		list_for_each_entry(svc, ip_vs_svc_tab + i, s_list) {
			if (++idx <= start)
				continue;
			if ((ret = ip_vs_genl_dump_service(info, svc)) < 0) {
				idx--;
				goto nla_put_failure;
			}
		}
	}

	for (i = 0; i < IP_VS_SVC_TAB_SIZE; i++) {
		ip_vs_svc_tab = __get_cpu_var(ip_vs_svc_fwm_tab_percpu);
		list_for_each_entry(svc, ip_vs_svc_tab + i, f_list) {
			if (++idx <= start)
				continue;
			if (ip_vs_genl_dump_service(info, svc) < 0) {
				idx--;
				goto nla_put_failure;
			}
		}
	}

nla_put_failure:
	if (ret < 0)
		ret = ipvs_nl_reply_error(info, IPVS_CMD_NEW_SERVICE, ret);
	else
		ret = ipvs_nl_multi_reply_done(info, IPVS_CMD_NEW_SERVICE);

	if (ret < 0)
		OFP_ERR("nl reply return %d\n", ret);
	mutex_unlock(&__ip_vs_mutex);

	return ret;
}


static int ofp_vs_nl_msg_handler(struct nl_msg *msg, void *arg)
{
	genl_handle_msg(msg, arg);
	return NL_OK;
}

/*
 *	Flush all the virtual services
 */
static int ip_vs_flush(void)
{
	int idx;
	struct ip_vs_service *svc, *nxt;
	struct list_head *ip_vs_svc_tab;
	struct list_head *ip_vs_svc_fwm_tab;

	/*
	 * Flush the service table hashed by <protocol,addr,port>
	 */
	for (idx = 0; idx < IP_VS_SVC_TAB_SIZE; idx++) {
		ip_vs_svc_tab = __get_cpu_var(ip_vs_svc_tab_percpu);
		list_for_each_entry_safe(svc, nxt, ip_vs_svc_tab + idx,
					 s_list) {
			ip_vs_del_service(svc);
		}
	}

	/*
	 * Flush the service table hashed by fwmark
	 */
	for (idx = 0; idx < IP_VS_SVC_TAB_SIZE; idx++) {
		ip_vs_svc_fwm_tab = __get_cpu_var(ip_vs_svc_fwm_tab_percpu);
		list_for_each_entry_safe(svc, nxt,
					 ip_vs_svc_fwm_tab + idx, f_list) {
			ip_vs_del_service(svc);
		}
	}

	return 0;
}



static int ip_vs_genl_parse_dest(struct ip_vs_dest_user_kern *udest,
				 struct nlattr *nla, int full_entry)
{
	struct nlattr *attrs[IPVS_DEST_ATTR_MAX + 1];
	struct nlattr *nla_addr, *nla_port;

	/* Parse mandatory identifying destination fields first */
	if (nla == NULL ||
	    nla_parse_nested(attrs, IPVS_DEST_ATTR_MAX, nla, ip_vs_dest_policy))
		return -EINVAL;

	nla_addr = attrs[IPVS_DEST_ATTR_ADDR];
	nla_port = attrs[IPVS_DEST_ATTR_PORT];

	if (!(nla_addr && nla_port))
		return -EINVAL;

	memset(udest, 0, sizeof(*udest));

	nla_memcpy(&udest->addr, nla_addr, sizeof(udest->addr));
	udest->port = nla_get_u16(nla_port);

	/* If a full entry was requested, check for the additional fields */
	if (full_entry) {
		struct nlattr *nla_fwd, *nla_weight, *nla_u_thresh,
		    *nla_l_thresh;

		nla_fwd = attrs[IPVS_DEST_ATTR_FWD_METHOD];
		nla_weight = attrs[IPVS_DEST_ATTR_WEIGHT];
		nla_u_thresh = attrs[IPVS_DEST_ATTR_U_THRESH];
		nla_l_thresh = attrs[IPVS_DEST_ATTR_L_THRESH];

		if (!(nla_fwd && nla_weight && nla_u_thresh && nla_l_thresh))
			return -EINVAL;

		udest->conn_flags = nla_get_u32(nla_fwd)
		    & IP_VS_CONN_F_FWD_MASK;
		udest->weight = nla_get_u32(nla_weight);
		udest->u_threshold = nla_get_u32(nla_u_thresh);
		udest->l_threshold = nla_get_u32(nla_l_thresh);
	}

	return 0;
}

static int ip_vs_genl_parse_laddr(struct ip_vs_laddr_user_kern *uladdr,
				  struct nlattr *nla, int full_entry)
{
	struct nlattr *attrs[IPVS_LADDR_ATTR_MAX + 1];
	struct nlattr *nla_addr;
	(void)full_entry;

	/* Parse mandatory identifying destination fields first */
	if (nla == NULL ||
	    nla_parse_nested(attrs, IPVS_LADDR_ATTR_MAX, nla,
			     ip_vs_laddr_policy))
		return -EINVAL;

	nla_addr = attrs[IPVS_LADDR_ATTR_ADDR];
	if (!nla_addr)
		return -EINVAL;

	memset(uladdr, 0, sizeof(*uladdr));
	nla_memcpy(&uladdr->addr, nla_addr, sizeof(uladdr->addr));

	return 0;
}

/*
 *	Set timeout values for tcp tcpfin udp in the timeout_table.
 */
static int ip_vs_set_timeout(struct ip_vs_timeout_user *u)
{
	IP_VS_DBG(2, "Setting timeout tcp:%d tcpfin:%d udp:%d\n",
		  u->tcp_timeout, u->tcp_fin_timeout, u->udp_timeout);

#ifdef CONFIG_IP_VS_PROTO_TCP
	if (u->tcp_timeout) {
		ip_vs_protocol_tcp.timeout_table[IP_VS_TCP_S_ESTABLISHED]
		    = u->tcp_timeout*HZ;
	}

	if (u->tcp_fin_timeout) {
		ip_vs_protocol_tcp.timeout_table[IP_VS_TCP_S_FIN_WAIT]
		    = u->tcp_fin_timeout*HZ;
	}
#endif

#ifdef CONFIG_IP_VS_PROTO_UDP
	if (u->udp_timeout) {
		ip_vs_protocol_udp.timeout_table[IP_VS_UDP_S_NORMAL]
		    = u->udp_timeout*HZ;
	}
#endif
	return 0;
}

static int ip_vs_genl_set_config(struct nlattr **attrs)
{
	struct ip_vs_timeout_user t;

	__ip_vs_get_timeouts(&t);

	if (attrs[IPVS_CMD_ATTR_TIMEOUT_TCP])
		t.tcp_timeout = nla_get_u32(attrs[IPVS_CMD_ATTR_TIMEOUT_TCP]);

	if (attrs[IPVS_CMD_ATTR_TIMEOUT_TCP_FIN])
		t.tcp_fin_timeout =
		    nla_get_u32(attrs[IPVS_CMD_ATTR_TIMEOUT_TCP_FIN]);

	if (attrs[IPVS_CMD_ATTR_TIMEOUT_UDP])
		t.udp_timeout = nla_get_u32(attrs[IPVS_CMD_ATTR_TIMEOUT_UDP]);

	return ip_vs_set_timeout(&t);
}

static int ip_vs_genl_set_cmd(struct nl_cache_ops *ops,
	                            struct genl_cmd *genl_cmd,
	                            struct genl_info *info,
	                            void *arg)
{
	struct ip_vs_service *svc = NULL;
	struct ip_vs_service_user_kern usvc;
	struct ip_vs_dest_user_kern udest;
	struct ip_vs_laddr_user_kern uladdr;
	struct nlattr *attrs[IPVS_CMD_ATTR_MAX + 1];

	int ret = 0;
	int need_full_svc = 0, need_full_dest = 0;
	int cmd = info->genlhdr->cmd;

	(void)arg;
	(void)ops;
	OFP_DBG("Set command: %d %s\n", cmd, genl_cmd->c_name);

	mutex_lock(&__ip_vs_mutex);

	if (nlmsg_parse(info->nlh, GENL_HDRLEN, attrs,
			IPVS_CMD_ATTR_MAX, ip_vs_cmd_policy)) {
		ret = -EINVAL;
		goto out;
	}

	info->attrs = attrs;

	if (cmd == IPVS_CMD_FLUSH) {
		ret = ip_vs_flush();
		goto out;
	} else if (cmd == IPVS_CMD_SET_CONFIG) {
		ret = ip_vs_genl_set_config(info->attrs);
		goto out;
	} else if (cmd == IPVS_CMD_ZERO && !info->attrs[IPVS_CMD_ATTR_SERVICE]) {
		ret = -EACCES;	//ip_vs_zero_all();
		goto out;
	}

	/* All following commands require a service argument, so check if we
	 * received a valid one. We need a full service specification when
	 * adding / editing a service. Only identifying members otherwise. */
	if (cmd == IPVS_CMD_NEW_SERVICE || cmd == IPVS_CMD_SET_SERVICE)
		need_full_svc = 1;

	ret = ip_vs_genl_parse_service(&usvc,
				       info->attrs[IPVS_CMD_ATTR_SERVICE],
				       need_full_svc);
	if (ret)
		goto out;

	/* Lookup the exact service by <protocol, addr, port> or fwmark */
	if (usvc.fwmark == 0)
		svc = __ip_vs_service_get(usvc.af, usvc.protocol,
					  &usvc.addr, usvc.port);
	else
		svc = __ip_vs_svc_fwm_get(usvc.af, usvc.fwmark);

	/* Unless we're adding a new service, the service must already exist */
	if ((cmd != IPVS_CMD_NEW_SERVICE) && (svc == NULL)) {
		ret = -ESRCH;
		goto out;
	}

	/* Destination commands require a valid destination argument. For
	 * adding / editing a destination, we need a full destination
	 * specification. */
	if (cmd == IPVS_CMD_NEW_DEST || cmd == IPVS_CMD_SET_DEST ||
	    cmd == IPVS_CMD_DEL_DEST) {
		if (cmd != IPVS_CMD_DEL_DEST)
			need_full_dest = 1;

		ret = ip_vs_genl_parse_dest(&udest,
					    info->attrs[IPVS_CMD_ATTR_DEST],
					    need_full_dest);
		if (ret)
			goto out;
	}

	if (cmd == IPVS_CMD_NEW_LADDR || cmd == IPVS_CMD_DEL_LADDR) {
		ret = ip_vs_genl_parse_laddr(&uladdr,
					     info->attrs[IPVS_CMD_ATTR_LADDR],
					     1);
		if (ret)
			goto out;
	}

	switch (cmd) {
	case IPVS_CMD_NEW_SERVICE:
		if (svc == NULL)
			ret = ip_vs_add_service(&usvc, &svc);
		else
			ret = -EEXIST;
		break;
	case IPVS_CMD_SET_SERVICE:
		ret = ip_vs_edit_service(svc, &usvc);
		break;
	case IPVS_CMD_DEL_SERVICE:
		ret = ip_vs_del_service(svc);
		break;
	case IPVS_CMD_NEW_DEST:
		ret = ip_vs_add_dest(svc, &udest);
		break;
	case IPVS_CMD_SET_DEST:
		ret = ip_vs_edit_dest(svc, &udest);
		break;
	case IPVS_CMD_DEL_DEST:
		ret = ip_vs_del_dest(svc, &udest);
		break;
	case IPVS_CMD_ZERO:
		ret = -EACCES;	//ip_vs_zero_service(svc);
		break;
	case IPVS_CMD_NEW_LADDR:
		ret = ip_vs_add_laddr(svc, &uladdr);
		break;
	case IPVS_CMD_DEL_LADDR:
		ret = ip_vs_del_laddr(svc, &uladdr);
		break;
	default:
		ret = -EINVAL;
	}

out:
//	if (svc)
//		ip_vs_service_put(svc);
	mutex_unlock(&__ip_vs_mutex);

	if (ret < 0)
		OFP_ERR("%s error %d\n", __func__, ret);

	ret = ipvs_nl_reply_error(info, cmd, ret);
	if (ret < 0)
		OFP_ERR("%s ipvs_nl_reply_error return %d\n", __func__, ret);
	return ret; 
}

static struct ip_vs_dest_snat *ofp_vs_snat_lookup_rule(
		struct ip_vs_service *svc, const struct snat_args *args)
{
	struct ip_vs_dest *dest;

	list_for_each_entry(dest, &svc->destinations, n_list) {
		struct ip_vs_dest_snat *rule = (struct ip_vs_dest_snat *)dest;

		if ((rule->saddr.ip == args->saddr)
		    && (rule->daddr.ip == args->daddr)
		    && (rule->smask.ip == args->smask)
		    && (rule->dmask.ip == args->dmask)) {
			return rule;
		}
	}

	return NULL;
}

int ofp_vs_snat_del_rule(const struct snat_args *args)
{
	int ret = 0, cpu;
	struct ip_vs_service *svc, *this_svc;
	struct ip_vs_dest_snat *rule;
	struct ip_vs_dest *dest;

	mutex_lock(&__ip_vs_mutex);

	svc = __ip_vs_svc_fwm_get(AF_INET, 1);
	if (NULL == svc) {
		ret = ENOENT;
		goto out;
	}

	for_each_possible_cpu(cpu) {
		this_svc = svc->svc0 + cpu;
	
		rule = ofp_vs_snat_lookup_rule(this_svc, args);
		if (rule == NULL) {
			ret = ENOENT;
			break;
		}

		dest = (struct ip_vs_dest *)rule;

		spin_lock_bh(&per_cpu(ip_vs_svc_lock, cpu));

		/*
		 *      Unlink dest from the service
		 */
		__ip_vs_unlink_dest(this_svc, dest, 1);

		spin_unlock_bh(&per_cpu(ip_vs_svc_lock, cpu));

		/*
		 *      Delete the destination
		 */
		__ip_vs_del_dest(dest);
	}

out:
	mutex_unlock(&__ip_vs_mutex);
	return ret;
}

int ofp_vs_snat_add_rule(const struct snat_args *args)
{
	int ret = 0, cpu;
	struct ip_vs_service *svc, *this_svc;
	struct ip_vs_dest_snat *rule;
	struct ip_vs_dest *dest;
	struct ip_vs_dest_user_kern udest;

	mutex_lock(&__ip_vs_mutex);

	svc = __ip_vs_svc_fwm_get(AF_INET, 1);
	if (NULL == svc) {
		ret = ENOENT;
		goto out;
	}

	rule = ofp_vs_snat_lookup_rule(svc, args);
	if (rule) {
		ret = EEXIST;
		goto out;
	}

	memset(&udest, 0, sizeof(udest));
	udest.conn_flags |= IP_VS_CONN_F_FULLNAT;

	for_each_possible_cpu(cpu) {
		this_svc = svc->svc0 + cpu;
		ret = ip_vs_new_dest(this_svc, &udest, &dest);
		if (ret) {
			return ret;
		}

		rule = (struct ip_vs_dest_snat *)dest;
		rule->saddr.ip = args->saddr;
		rule->daddr.ip = args->daddr;
		rule->smask.ip = args->smask;
		rule->dmask.ip = args->dmask;
		rule->minip.ip = args->minip;
		rule->maxip.ip = args->maxip;
		rule->out_port = args->out_port;
		rule->ip_sel_algo = args->ip_sel_algo;
		dest->addr.ip = args->saddr;
		dest->port = rte_cpu_to_be_16(inet_mask_len(args->smask));

		/*
		 * Add the dest entry into the list
		 */
		atomic_inc(&dest->refcnt);

		spin_lock_bh(&per_cpu(ip_vs_svc_lock, cpu));

		list_add(&dest->n_list, &this_svc->destinations);
		this_svc->num_dests++;

		/* call the update_service function of its scheduler */
		if (this_svc->scheduler->update_service)
			this_svc->scheduler->update_service(this_svc);

		spin_unlock_bh(&per_cpu(ip_vs_svc_lock, cpu));
	}
	 
out:
	mutex_unlock(&__ip_vs_mutex);
	return ret;
}

int ofp_vs_snat_dump_rules(struct snat_args *args, int cnt)
{
	int ret = 0, idx = 0;
	struct ip_vs_service *svc;
	struct ip_vs_dest *dest;
	struct ip_vs_dest_snat *rule;

	mutex_lock(&__ip_vs_mutex);

	svc = __ip_vs_svc_fwm_get(AF_INET, 1);
	if (NULL == svc) {
		ret = -ENOENT;
		goto out;
	}

	list_for_each_entry(dest, &svc->destinations, n_list) {
		if (idx >= cnt)
			break;
		
		rule = (struct ip_vs_dest_snat *)dest;
		args[idx].saddr = rule->saddr.ip;
		args[idx].daddr = rule->daddr.ip;
		args[idx].smask = rule->smask.ip;
		args[idx].minip = rule->minip.ip;
		args[idx].maxip = rule->maxip.ip;
		args[idx].out_port = rule->out_port;
		args[idx].ip_sel_algo = rule->ip_sel_algo;
	}

	ret = idx + 1;
out:
	mutex_unlock(&__ip_vs_mutex);
	return ret;
}

int ofp_vs_snat_enable(void)
{
	int ret = 0;
	struct ip_vs_service *snat_svc;
	struct ip_vs_service_user_kern usvc;

	memset(&usvc, 0, sizeof(usvc));
	usvc.af = AF_INET;
	usvc.fwmark = 1;
	usvc.sched_name = "snat_sched";

	
	mutex_lock(&__ip_vs_mutex);

	snat_svc = __ip_vs_svc_fwm_get(usvc.af, usvc.fwmark);
	if (NULL == snat_svc)
		ret = ip_vs_add_service(&usvc, &snat_svc); 
	else
		ret = EEXIST;

	mutex_unlock(&__ip_vs_mutex);
	return ret;
}




static struct genl_cmd ip_vs_genl_cmds[] = {
	{
	 .c_id = IPVS_CMD_NEW_SERVICE,
	 .c_name = "IPVS_CMD_NEW_SERVICE",
	 .c_maxattr = IPVS_CMD_ATTR_MAX,
	 .c_attr_policy = ip_vs_cmd_policy,
	 .c_msg_parser = &ip_vs_genl_set_cmd,
	},
	{
	 .c_id = IPVS_CMD_SET_SERVICE,
	 .c_name = "IPVS_CMD_SET_SERVICE",
	 .c_attr_policy = ip_vs_cmd_policy,
	 .c_msg_parser = ip_vs_genl_set_cmd,
	 },
	{
	 .c_id = IPVS_CMD_DEL_SERVICE,
	 .c_name = "IPVS_CMD_DEL_SERVICE",
	 .c_attr_policy = ip_vs_cmd_policy,
	 .c_msg_parser = ip_vs_genl_set_cmd,
	 },
	{
	 .c_id = IPVS_CMD_GET_SERVICE,
	 .c_name = "IPVS_CMD_GET_SERVICE",
	 .c_msg_parser = ip_vs_genl_get_cmd, 
	 .c_attr_policy = ip_vs_cmd_policy,
	 },
	{
	 .c_id = IPVS_CMD_NEW_DEST,
	 .c_name = "IPVS_CMD_NEW_DEST",
	 .c_attr_policy = ip_vs_cmd_policy,
	 .c_msg_parser = ip_vs_genl_set_cmd,
	 },
	{
	 .c_id = IPVS_CMD_SET_DEST,
	 .c_name = "IPVS_CMD_SET_DEST",
	 .c_attr_policy = ip_vs_cmd_policy,
	 .c_msg_parser = ip_vs_genl_set_cmd,
	 },
	{
	 .c_id = IPVS_CMD_DEL_DEST,
	 .c_name = "IPVS_CMD_DEL_DEST",
	 .c_attr_policy = ip_vs_cmd_policy,
	 .c_msg_parser = ip_vs_genl_set_cmd,
	 },
	{
	 .c_id = IPVS_CMD_GET_DEST,
	 .c_name = "IPVS_CMD_GET_DEST",
	 .c_attr_policy = ip_vs_cmd_policy,
	 .c_msg_parser = ip_vs_genl_dump_dests,
	 },
	{
	 .c_id = IPVS_CMD_NEW_DAEMON,
	 .c_name = "IPVS_CMD_NEW_DAEMON",
	 .c_attr_policy = ip_vs_cmd_policy,
	 .c_msg_parser = ip_vs_genl_set_cmd,
	 },
	{
	 .c_id = IPVS_CMD_DEL_DAEMON,
	 .c_name = "IPVS_CMD_DEL_DAEMON",
	 .c_attr_policy = ip_vs_cmd_policy,
	 .c_msg_parser = ip_vs_genl_set_cmd,
	 },
	{
	 .c_id = IPVS_CMD_GET_DAEMON,
	 .c_name = "IPVS_CMD_GET_DAEMON",
	 .c_msg_parser = ip_vs_genl_dump_daemons,
	 },
	{
	 .c_id = IPVS_CMD_SET_CONFIG,
	 .c_attr_policy = ip_vs_cmd_policy,
	 .c_msg_parser = ip_vs_genl_set_cmd,
	 },
	{
	 .c_id = IPVS_CMD_GET_CONFIG,
	 .c_msg_parser = ip_vs_genl_get_cmd,
	 },
	{
	 .c_id = IPVS_CMD_GET_INFO,
	 .c_name = "IPVS_CMD_GET_INFO",
	 .c_msg_parser = ip_vs_genl_get_cmd,
	 },
	{
	 .c_id = IPVS_CMD_ZERO,
	 .c_name = "IPVS_CMD_ZERO",
	 .c_attr_policy = ip_vs_cmd_policy,
	 .c_msg_parser = ip_vs_genl_set_cmd,
	 },
	{
	 .c_id = IPVS_CMD_FLUSH,
	 .c_name = "IPVS_CMD_FLUSH",
	 .c_msg_parser = ip_vs_genl_set_cmd,
	 },
	{
	 .c_id = IPVS_CMD_NEW_LADDR,
	 .c_name = "IPVS_CMD_NEW_LADDR",
	 .c_attr_policy = ip_vs_cmd_policy,
	 .c_msg_parser = ip_vs_genl_set_cmd,
	 },
	{
	 .c_id = IPVS_CMD_DEL_LADDR,
	 .c_name = "IPVS_CMD_DEL_LADDR",
	 .c_attr_policy = ip_vs_cmd_policy,
	 .c_msg_parser = ip_vs_genl_set_cmd,
	 },
	{
	 .c_id = IPVS_CMD_GET_LADDR,
	 .c_name = "IPVS_CMD_GET_LADDR",
	 .c_attr_policy = ip_vs_cmd_policy,
	 .c_msg_parser = ip_vs_genl_dump_laddrs,
	 },
};

#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
static struct genl_ops ip_vs_genl_ops = {
	 //.o_id = GENL_ID_GENERATE,
	 .o_cmds = ip_vs_genl_cmds,
	 .o_name = IPVS_GENL_NAME,
	 .o_ncmds = ARRAY_SIZE(ip_vs_genl_cmds),
};

static int ip_vs_genl_register(void)
{
	return genl_register_family(&ip_vs_genl_ops);
}

static void ip_vs_genl_unregister(void)
{
	genl_unregister_family(&ip_vs_genl_ops);
}

static void free_svc_tab(void)
{
	int cpu;
	struct list_head *ip_vs_svc_tab;
	struct list_head *ip_vs_svc_fwm_tab;

	for_each_possible_cpu(cpu) {
		ip_vs_svc_tab = per_cpu(ip_vs_svc_tab_percpu, cpu);
		ip_vs_svc_fwm_tab = per_cpu(ip_vs_svc_fwm_tab_percpu, cpu);

		/* free NULL is OK  */
		rte_free(ip_vs_svc_tab);
		rte_free(ip_vs_svc_fwm_tab);
	}
}

static int alloc_svc_tab(void)
{
	int cpu;
	struct list_head *tmp;

	/* clear percpu svc_tab */
	for_each_possible_cpu(cpu) {
		per_cpu(ip_vs_svc_tab_percpu, cpu) = NULL;
	}

	for_each_possible_cpu(cpu) {
		unsigned socket_id = rte_lcore_to_socket_id(cpu);

		tmp = rte_malloc_socket("ip_vs_svc_tab",
			sizeof(struct list_head) * IP_VS_SVC_TAB_SIZE,
			0, socket_id);

		if (!tmp) {
			OFP_ERR("cannot allocate svc_tab.\n");
			return -ENOMEM;
		}

		per_cpu(ip_vs_svc_tab_percpu, cpu) = tmp;

		tmp = rte_malloc_socket("ip_vs_svc_fwm_tab",
			sizeof(struct list_head) * IP_VS_SVC_TAB_SIZE,
			0, socket_id);

		if (!tmp) {
			OFP_ERR("cannot allocate svc_fwm_tab.\n");
			return -ENOMEM;
		}

		per_cpu(ip_vs_svc_fwm_tab_percpu, cpu) = tmp;
	}

	return 0;
}

static void *ofp_vs_ctl_thread(void *arg)
{
	int err;
	odp_bool_t *is_running = NULL;

	(void)arg;

	is_running = ofp_get_processing_state();
	if (is_running == NULL) {
		OFP_ERR("ofp_get_processing_state failed\n");
		ofp_term_local();
		goto out;	
	}

	if (sock == NULL) {
		OFP_ERR("nl_sock is NULL\n");
		ofp_term_local();
		goto out;
	}
	
	OFP_INFO("ofp_vs_ctl_thread thread is running.\n");
	while (*is_running) {
		if ((err = -nl_recvmsgs_default(sock)) > 0) {
			OFP_ERR("nl_recvmsgs_default return %d\n", err);
		}
		//OFP_DBG("nl recv data\n");
	}

out:

	OFP_INFO("ofp_vs_ctl_thread exiting");
	return NULL;
}

static odph_linux_pthread_t ofp_vs_ctl_pthread;
void ofp_vs_ctl_thread_start(odp_instance_t instance, int core_id)
{
	odp_cpumask_t cpumask;
	odph_linux_thr_params_t thr_params;

	odp_cpumask_zero(&cpumask);
	odp_cpumask_set(&cpumask, core_id);

	thr_params.start = ofp_vs_ctl_thread;
	thr_params.arg = NULL;
	thr_params.thr_type = ODP_THREAD_CONTROL;
	thr_params.instance = instance;
	odph_linux_pthread_create(&ofp_vs_ctl_pthread,
				  &cpumask,
				  &thr_params
				);
}


int ofp_vs_ctl_init(odp_instance_t instance, ofp_init_global_t *app_init_params)
{
	int ret;
	int cpu;

	sock = nl_socket_alloc();
	if (NULL == sock) {
		ret = -ENOMEM;
		OFP_ERR("ip_vs_genl_register failed\n");
		goto cleanup;
	}

	nl_socket_set_nonblocking(sock);
	nl_socket_set_local_port(sock, 101);
	genl_connect(sock);

	if ((ret = ip_vs_genl_register()) < 0) {
		OFP_ERR("ip_vs_genl_register failed\n");
		goto cleanup; 
	}

	if ((ret = genl_ops_resolve(sock, &ip_vs_genl_ops)) < 0) {
		OFP_ERR("genl_osp_resolve return %d\n", ret);
		goto cleanup_genl; 
	}

	if (genl_ctrl_resolve(sock, "nlctrl") != GENL_ID_CTRL) {
		OFP_ERR("Resolving of \"nlctrl\" failed");
		goto cleanup_genl; 
	}

	
	if ((ret = nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM,
			ofp_vs_nl_msg_handler, NULL)) != 0) {
		OFP_ERR("nl_socket_modify_cb failed %s\n", strerror(errno));
		goto cleanup_genl;
	}

	nl_socket_disable_seq_check(sock);

	ret = alloc_svc_tab();
	if (ret) {
		goto cleanup_svctab;
	}

	for_each_possible_cpu(cpu) {
		int idx;
		struct list_head *ip_vs_svc_tab;
		struct list_head *ip_vs_svc_fwm_tab;

		spin_lock_init(&per_cpu(ip_vs_svc_lock, cpu));
		ip_vs_svc_tab = per_cpu(ip_vs_svc_tab_percpu, cpu);
		ip_vs_svc_fwm_tab = per_cpu(ip_vs_svc_fwm_tab_percpu, cpu);

		/* Initialize ip_vs_svc_table, ip_vs_svc_fwm_table */
		for (idx = 0; idx < IP_VS_SVC_TAB_SIZE; idx++) {
			INIT_LIST_HEAD(ip_vs_svc_tab + idx);
			INIT_LIST_HEAD(ip_vs_svc_fwm_tab + idx);
		}

		INIT_LIST_HEAD(&per_cpu(ip_vs_dest_trash_percpu, cpu));
	}

	/* ofp_vs_ctl thread */
	ofp_vs_ctl_thread_start(instance, app_init_params->linux_core_id);

	OFP_INFO("ofp_vs_ctl_init ok\n");
	return ret;
	
cleanup_svctab:
	free_svc_tab();
cleanup_genl:
	ip_vs_genl_unregister(); 
cleanup:
	if (sock) {
		nl_close(sock);
		nl_socket_free(sock);
		sock = NULL;
	}
	return ret;
}

void ofp_vs_ctl_finish(void)
{
	ip_vs_trash_cleanup();
	free_svc_tab();
	ip_vs_genl_unregister();

	if (sock) {
		OFP_DBG("close nl sock\n");
		nl_close(sock);
		nl_socket_free(sock);
	}
	//odph_linux_pthread_join(&ofp_vs_ctl_thread, 1);
}
