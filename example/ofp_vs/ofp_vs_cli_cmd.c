
#include "ofp_vs.h"
#include "ofpi_cli.h"

extern odp_pktio_config_t default_pktio_config;

struct flow_type_info {
	char str[32];
	uint16_t type;
};
static struct flow_type_info flowtype_str_table[] = {
	{"raw", RTE_ETH_FLOW_RAW},
	//{"ipv4", RTE_ETH_FLOW_IPV4},
	{"ipv4-frag", RTE_ETH_FLOW_FRAG_IPV4},
	{"ipv4-tcp", RTE_ETH_FLOW_NONFRAG_IPV4_TCP},
	{"ipv4-udp", RTE_ETH_FLOW_NONFRAG_IPV4_UDP},
	{"ipv4-sctp", RTE_ETH_FLOW_NONFRAG_IPV4_SCTP},
	{"ipv4-other", RTE_ETH_FLOW_NONFRAG_IPV4_OTHER},
	{"ipv6", RTE_ETH_FLOW_IPV6},
	{"ipv6-frag", RTE_ETH_FLOW_FRAG_IPV6},
	{"ipv6-tcp", RTE_ETH_FLOW_NONFRAG_IPV6_TCP},
	{"ipv6-udp", RTE_ETH_FLOW_NONFRAG_IPV6_UDP},
	{"ipv6-sctp", RTE_ETH_FLOW_NONFRAG_IPV6_SCTP},
	{"ipv6-other", RTE_ETH_FLOW_NONFRAG_IPV6_OTHER},
	{"l2-payload", RTE_ETH_FLOW_L2_PAYLOAD},
};

static char *
flowtype_to_str(uint16_t flow_type)
{
	uint8_t i;
	for (i = 0; i < RTE_DIM(flowtype_str_table); i++) {
		if (flowtype_str_table[i].type == flow_type)
			return flowtype_str_table[i].str;
	}

	return NULL;
}

static uint16_t
str2flowtype(char *string)
{
	uint8_t i = 0;
	for (i = 0; i < RTE_DIM(flowtype_str_table); i++) {
		if (!strcmp(flowtype_str_table[i].str, string))
			return flowtype_str_table[i].type;
	}
	return RTE_ETH_FLOW_UNKNOWN;
}

static void __fdir_ctrl(void *handle, const char *args, const char *op)
{
	int ret;
	int sscanf_cnt;
	int fd = ofp_cli_get_fd(handle);
	uint32_t src_ip, dst_ip;
	int a, b, c, d, e, f, g, h, src_port, dst_port, queue_id, port, vlan;
	char dev[16];
	char proto[16];
	struct rte_eth_fdir_filter entry;
	uint8_t flexbytes[RTE_ETH_FDIR_MAX_FLEXLEN];

	if ((sscanf_cnt = sscanf(args,
		"%s %s %d.%d.%d.%d %d %d.%d.%d.%d %d %d",
		dev, proto, &a, &b, &c, &d, &src_port,
		&e, &f, &g, &h, &dst_port, &queue_id)) != 13) {
		ofp_sendf(fd, "sscanf Expect %d args but got %d !\r\n",
			  13, sscanf_cnt);
		sendcrlf((struct cli_conn *)handle);
		return;
	}

	OFP_DBG("args: %s %s %d.%d.%d.%d %d %d.%d.%d.%d %d %d",
		dev, proto, a, b, c, d, src_port,
		e, f, g, h, dst_port, queue_id);
	
	src_ip = odp_cpu_to_be_32((a << 24) | (b << 16) | (c << 8) | d);
	dst_ip = odp_cpu_to_be_32((e << 24) | (f << 16) | (g << 8) | h);

	port = ofp_name_to_port_vlan(dev, &vlan); 
	if (port < 0 || port >= ofp_get_num_ports()) {
		ofp_sendf(fd, "Invalid port!\r\n");
		sendcrlf((struct cli_conn *)handle);
		return;
	}

	if (rte_eth_dev_filter_supported(port, RTE_ETH_FILTER_FDIR) < 0) {
		ofp_sendf(fd, "flow director is not supported"
			  "on port %u.\r\n", port);
		sendcrlf((struct cli_conn *)handle);
		return;		
	}

	memset(flexbytes, 0, sizeof(flexbytes));
	memset(&entry, 0, sizeof(struct rte_eth_fdir_filter));

	entry.input.flow_type = str2flowtype(proto);
	switch (entry.input.flow_type) {
	//case RTE_ETH_FLOW_IPV4:
	case RTE_ETH_FLOW_FRAG_IPV4:
	case RTE_ETH_FLOW_NONFRAG_IPV4_OTHER:
	case RTE_ETH_FLOW_NONFRAG_IPV4_UDP:
	case RTE_ETH_FLOW_NONFRAG_IPV4_TCP:
		entry.input.flow.ip4_flow.dst_ip = dst_ip;
		entry.input.flow.ip4_flow.src_ip = src_ip;
		/* need convert to big endian. */
		entry.input.flow.udp4_flow.dst_port =
				rte_cpu_to_be_16(dst_port);
		entry.input.flow.udp4_flow.src_port =
				rte_cpu_to_be_16(src_port);
		break;
	default:
		ofp_sendf(fd, "Not support flow_type %d\r\n",
		        entry.input.flow_type);
		sendcrlf((struct cli_conn *)handle);
		return;
	}

	
	entry.action.flex_off = 0;  /*use 0 by default */
	entry.action.behavior = RTE_ETH_FDIR_ACCEPT;
	entry.action.report_status = RTE_ETH_FDIR_REPORT_ID;
	entry.action.rx_queue = queue_id;

	if (!strcmp(op, "add")) {
		ret = rte_eth_dev_filter_ctrl(port,
			RTE_ETH_FILTER_FDIR, RTE_ETH_FILTER_ADD, &entry);
	} else if (!strcmp(op, "del")) {
		ret = rte_eth_dev_filter_ctrl(port,
			RTE_ETH_FILTER_FDIR, RTE_ETH_FILTER_DELETE, &entry);
	} else {
		ret = rte_eth_dev_filter_ctrl(port,
			RTE_ETH_FILTER_FDIR, RTE_ETH_FILTER_UPDATE, &entry);
	}

	if (ret < 0) {
		ofp_sendf(fd, "flow director programming error: (%s)\r\n",
			strerror(-ret));
		sendcrlf((struct cli_conn *)handle);
		return;
	}

	ofp_sendf(fd, "%s OK\r\n", op);
	sendcrlf((struct cli_conn *)handle);
}

static void fdir_add(void *handle, const char *args)
{
	__fdir_ctrl(handle, args, "add");
}

static void fdir_del(void *handle, const char *args)
{
	__fdir_ctrl(handle, args, "del");
}

static inline void
print_fdir_flow_type(int fd, uint32_t flow_types_mask)
{
	int i;
	char *p;

	for (i = RTE_ETH_FLOW_UNKNOWN; i < RTE_ETH_FLOW_MAX; i++) {
		if (!(flow_types_mask & (1 << i)))
			continue;
		p = (char *)flowtype_to_str(i);
		if (p)
			ofp_sendf(fd, " %s", p);
		else
			ofp_sendf(fd, " unknown");
	}
	ofp_sendf(fd, "\r\n");
}

static inline void
print_fdir_mask(int fd,
	struct rte_eth_fdir_masks *mask)
{
	ofp_sendf(fd, "\r\n    vlan_tci: 0x%04x, ", mask->vlan_tci_mask);
	
	/*
	if (default_pktio_config.fdir_conf.fdir_mode ==
	    RTE_FDIR_MODE_PERFECT_MAC_VLAN)
		ofp_sendf(fd, "mac_addr: 0x%02x", mask->mac_addr_byte_mask);
	else if (default_pktio_config.fdir_conf.fdir_mode ==
		 RTE_FDIR_MODE_PERFECT_TUNNEL)
		ofp_sendf(fd, "mac_addr: 0x%02x, tunnel_type: 0x%01x, tunnel_id: 0x%08x",
			mask->mac_addr_byte_mask, mask->tunnel_type_mask,
			mask->tunnel_id_mask);
	else
	*/
	{
		ofp_sendf(fd, "src_ipv4: 0x%08x, dst_ipv4: 0x%08x,"
			" src_port: 0x%04x, dst_port: 0x%04x",
			mask->ipv4_mask.src_ip, mask->ipv4_mask.dst_ip,
			mask->src_port_mask, mask->dst_port_mask);

		ofp_sendf(fd, "\r\n    src_ipv6: 0x%08x,0x%08x,0x%08x,0x%08x,"
			" dst_ipv6: 0x%08x,0x%08x,0x%08x,0x%08x",
			mask->ipv6_mask.src_ip[0], mask->ipv6_mask.src_ip[1],
			mask->ipv6_mask.src_ip[2], mask->ipv6_mask.src_ip[3],
			mask->ipv6_mask.dst_ip[0], mask->ipv6_mask.dst_ip[1],
			mask->ipv6_mask.dst_ip[2], mask->ipv6_mask.dst_ip[3]);
	}

	ofp_sendf(fd, "\r\n");
}

static inline void
print_fdir_flex_payload(int fd,
	struct rte_eth_fdir_flex_conf *flex_conf, uint32_t num)
{
	struct rte_eth_flex_payload_cfg *cfg;
	uint32_t i, j;

	for (i = 0; i < flex_conf->nb_payloads; i++) {
		cfg = &flex_conf->flex_set[i];
		if (cfg->type == RTE_ETH_RAW_PAYLOAD)
			ofp_sendf(fd, "\r\n    RAW:  ");
		else if (cfg->type == RTE_ETH_L2_PAYLOAD)
			ofp_sendf(fd, "\r\n    L2_PAYLOAD:  ");
		else if (cfg->type == RTE_ETH_L3_PAYLOAD)
			ofp_sendf(fd, "\r\n    L3_PAYLOAD:  ");
		else if (cfg->type == RTE_ETH_L4_PAYLOAD)
			ofp_sendf(fd, "\r\n    L4_PAYLOAD:  ");
		else
			ofp_sendf(fd, "\r\n    UNKNOWN PAYLOAD(%u):  ", cfg->type);
		for (j = 0; j < num; j++)
			ofp_sendf(fd, "  %-5u", cfg->src_offset[j]);
	}
	ofp_sendf(fd, "\r\n");
}

static inline void
print_fdir_flex_mask(int fd,
		struct rte_eth_fdir_flex_conf *flex_conf, uint32_t num)
{
	struct rte_eth_fdir_flex_mask *mask;
	uint32_t i, j;
	char *p;

	for (i = 0; i < flex_conf->nb_flexmasks; i++) {
		mask = &flex_conf->flex_mask[i];
		p = (char *)flowtype_to_str(mask->flow_type);
		ofp_sendf(fd, "\r\n    %s:\t", p ? p : "unknown");
		for (j = 0; j < num; j++)
			ofp_sendf(fd, " %02x", mask->mask[j]);
	}
	ofp_sendf(fd, "\r\n");
}

static void fdir_get_infos(int fd, int port_id)
{
	struct rte_eth_fdir_stats fdir_stat;
	struct rte_eth_fdir_info fdir_info;
	int ret;

	static const char *fdir_stats_border = "########################";

	if (port_id > RTE_MAX_ETHPORTS)
		return;
	ret = rte_eth_dev_filter_supported(port_id, RTE_ETH_FILTER_FDIR);
	if (ret < 0) {
		ofp_sendf(fd, "\r\n FDIR is not supported on port %-2d\r\n",
			port_id);
		return;
	}

	memset(&fdir_info, 0, sizeof(fdir_info));
	rte_eth_dev_filter_ctrl(port_id, RTE_ETH_FILTER_FDIR,
			       RTE_ETH_FILTER_INFO, &fdir_info);
	memset(&fdir_stat, 0, sizeof(fdir_stat));
	rte_eth_dev_filter_ctrl(port_id, RTE_ETH_FILTER_FDIR,
			       RTE_ETH_FILTER_STATS, &fdir_stat);
	ofp_sendf(fd, "\r\n  %s FDIR infos for port %-2d     %s\r\n",
	       fdir_stats_border, port_id, fdir_stats_border);
	ofp_sendf(fd, "  MODE: ");
	if (fdir_info.mode == RTE_FDIR_MODE_PERFECT)
		ofp_sendf(fd, "  PERFECT\r\n");
	else if (fdir_info.mode == RTE_FDIR_MODE_PERFECT_MAC_VLAN)
		ofp_sendf(fd, "  PERFECT-MAC-VLAN\r\n");
	else if (fdir_info.mode == RTE_FDIR_MODE_PERFECT_TUNNEL)
		ofp_sendf(fd, "  PERFECT-TUNNEL\r\n");
	else if (fdir_info.mode == RTE_FDIR_MODE_SIGNATURE)
		ofp_sendf(fd, "  SIGNATURE\r\n");
	else
		ofp_sendf(fd, "  DISABLE\r\n");
	if (fdir_info.mode != RTE_FDIR_MODE_PERFECT_MAC_VLAN
		&& fdir_info.mode != RTE_FDIR_MODE_PERFECT_TUNNEL) {
		ofp_sendf(fd, "  SUPPORTED FLOW TYPE: ");
		print_fdir_flow_type(fd, fdir_info.flow_types_mask[0]);
	}
	ofp_sendf(fd, "  FLEX PAYLOAD INFO:\r\n");
	ofp_sendf(fd, "  max_len:       %-10"PRIu32"  payload_limit: %-10"PRIu32"\r\n"
	       "  payload_unit:  %-10"PRIu32"  payload_seg:   %-10"PRIu32"\r\n"
	       "  bitmask_unit:  %-10"PRIu32"  bitmask_num:   %-10"PRIu32"\r\n",
		fdir_info.max_flexpayload, fdir_info.flex_payload_limit,
		fdir_info.flex_payload_unit,
		fdir_info.max_flex_payload_segment_num,
		fdir_info.flex_bitmask_unit, fdir_info.max_flex_bitmask_num);
	ofp_sendf(fd, "  MASK: ");
	print_fdir_mask(fd, &fdir_info.mask);
	if (fdir_info.flex_conf.nb_payloads > 0) {
		ofp_sendf(fd, "  FLEX PAYLOAD SRC OFFSET:");
		print_fdir_flex_payload(fd, &fdir_info.flex_conf, fdir_info.max_flexpayload);
	}
	if (fdir_info.flex_conf.nb_flexmasks > 0) {
		ofp_sendf(fd, "  FLEX MASK CFG:");
		print_fdir_flex_mask(fd, &fdir_info.flex_conf, fdir_info.max_flexpayload);
	}
	ofp_sendf(fd, "  guarant_count: %-10"PRIu32"  best_count:    %"PRIu32"\r\n",
	       fdir_stat.guarant_cnt, fdir_stat.best_cnt);
	ofp_sendf(fd, "  guarant_space: %-10"PRIu32"  best_space:    %"PRIu32"\r\n",
	       fdir_info.guarant_spc, fdir_info.best_spc);
	ofp_sendf(fd, "  collision:     %-10"PRIu32"  free:          %"PRIu32"\r\n"
	       "  maxhash:       %-10"PRIu32"  maxlen:        %"PRIu32"\r\n"
	       "  add:	         %-10"PRIu64"  remove:        %"PRIu64"\r\n"
	       "  f_add:         %-10"PRIu64"  f_remove:      %"PRIu64"\r\n",
	       fdir_stat.collision, fdir_stat.free,
	       fdir_stat.maxhash, fdir_stat.maxlen,
	       fdir_stat.add, fdir_stat.remove,
	       fdir_stat.f_add, fdir_stat.f_remove);
	ofp_sendf(fd, "  %s############################%s\r\n",
	       fdir_stats_border, fdir_stats_border);
}

static void fdir_show(void *handle, const char *args)
{
	int vlan;
	int fd = ofp_cli_get_fd(handle);
	int port = ofp_name_to_port_vlan(args, &vlan); 

	if (port < 0 || port >= ofp_get_num_ports()) {
		ofp_sendf(fd, "Invalid port!\r\n");
		sendcrlf((struct cli_conn *)handle);
		return;
	}

	fdir_get_infos(fd, port);

	sendcrlf((struct cli_conn *)handle);
}

static void fdir_flush(void *handle, const char *args)
{
	int ret = 0;
	int vlan;
	int fd = ofp_cli_get_fd(handle);
	int port = ofp_name_to_port_vlan(args, &vlan); 

	if (port < 0 || port >= ofp_get_num_ports()) {
		ofp_sendf(fd, "Invalid port!\r\n");
		sendcrlf((struct cli_conn *)handle);
		return;
	}

	
	ret = rte_eth_dev_filter_supported(port, RTE_ETH_FILTER_FDIR);
	if (ret < 0) {
		ofp_sendf(fd, "flow director table flushing error: (%s)\r\n",
			strerror(-ret));
		sendcrlf((struct cli_conn *)handle);
		return;
	}

	ret = rte_eth_dev_filter_ctrl(port,
			RTE_ETH_FILTER_FDIR, RTE_ETH_FILTER_FLUSH, NULL);

	if (ret < 0)
		ofp_sendf(fd, "flow director table flushing error: (%s)\r\n",
			strerror(-ret));
	else
		ofp_sendf(fd, "OK\r\n");

	sendcrlf((struct cli_conn *)handle);
}


static void snat_enable(void *handle, const char *args)
{
	int fd = ofp_cli_get_fd(handle);
	int ret = 0;
	(void)args;
	
	if ((ret = ofp_vs_snat_enable())) {
		ofp_sendf(fd, "snat enable error: (%s)\r\n", strerror(ret));
	}
	
	sendcrlf((struct cli_conn *)handle);
}

static void snat_del(void *handle, const char *s)
{
	int a, b, c, d, e, f, g, h, smlen, dmlen, ret;
	struct cli_conn *conn = (struct cli_conn *)handle;
	int fd = ofp_cli_get_fd(handle);
	char dev[16];
	struct snat_args args;	

	if (sscanf(s, "%d.%d.%d.%d/%d %d.%d.%d.%d/%d %s",
	           &a, &b, &c, &d, &smlen, &e, &f, &g, &h,
		   &dmlen, dev) != 11)
		return;

	args.saddr = odp_cpu_to_be_32((a << 24) | (b << 16) | (c << 8) | d);
	args.daddr = odp_cpu_to_be_32((e << 24) | (f << 16) | (g << 8) | h);
	args.smask = inet_make_mask(smlen);
	args.dmask = inet_make_mask(dmlen);

	ret = ofp_vs_snat_del_rule(&args);
	if (ret) {
		ofp_sendf(fd, "ofp_vs_snat_add_rule error %s\r\n",
			strerror(ret));
	} else
		ofp_sendf(fd, "OK\r\n");

	sendcrlf(conn);
}

struct snat_algo_str {
	const char *name;
	int algo;
};
static struct snat_algo_str snat_algo_table[] = {
	{"s", IPVS_SNAT_IPS_SH},
	{"sd", IPVS_SNAT_IPS_SDH},
	{"sdfn", IPVS_SNAT_IPS_SDFNH},
};

static int snat_algo_str2int(const char *s)
{
	uint8_t i;
	for (i = 0; i < RTE_DIM(snat_algo_table); i++) {
		if (!strcmp(s, snat_algo_table[i].name))
			return snat_algo_table[i].algo;
	}

	return IPVS_SNAT_IPS_SDH;	
}

static const char *snat_algo_int2str(int algo)
{
	uint8_t i;
	for (i = 0; i < RTE_DIM(snat_algo_table); i++) {
		if (algo == snat_algo_table[i].algo)
			return snat_algo_table[i].name;
	}

	return "sd";
}

static void snat_add(void *handle, const char *s)
{
	struct snat_args args;	
	int a, b, c, d, e, f, g, h, port, smlen, dmlen;
	int i, j, k, l, m, n, o, p, vlan;
	int ret;
	char dev[16], algo_str[16];
	struct cli_conn *conn = (struct cli_conn *)handle;
	int fd = ofp_cli_get_fd(handle);

	if (sscanf(s, "%d.%d.%d.%d/%d "
		   "%d.%d.%d.%d/%d "
		   "%s "
		   "%d.%d.%d.%d "
		   "%d.%d.%d.%d "
		   "%s",
		   &a, &b, &c, &d, &smlen,
		   &e, &f, &g, &h, &dmlen,
		   dev,
		   &i, &j, &k, &l,
		   &m, &n, &o, &p,
		   algo_str) != 20)
		return;

	args.saddr = odp_cpu_to_be_32((a << 24) | (b << 16) | (c << 8) | d);
	args.daddr = odp_cpu_to_be_32((e << 24) | (f << 16) | (g << 8) | h);
	args.minip =
	      	odp_cpu_to_be_32((i << 24) | (j << 16) | (k << 8) | l);
	args.maxip =
		odp_cpu_to_be_32((m << 24) | (n << 16) | (o << 8) | p);

	port = ofp_name_to_port_vlan(dev, &vlan);
	if (port < 0 || port >= ofp_get_num_ports()) {
		ofp_sendf(fd, "Invalid port!\r\n");
		sendcrlf(conn);
		return;
	}

	args.out_port = port;
	args.ip_sel_algo = snat_algo_str2int(algo_str);
	args.smask = inet_make_mask(smlen);
	args.dmask = inet_make_mask(dmlen);

	ret = ofp_vs_snat_add_rule(&args);
	if (ret) {
		ofp_sendf(fd, "ofp_vs_snat_add_rule error %s\r\n",
			strerror(ret));
	} else
		ofp_sendf(fd, "OK\r\n");

	sendcrlf(conn);
}

static void snat_show(void *handle, const char *s)
{
	int fd = ofp_cli_get_fd(handle);
	struct cli_conn *conn = (struct cli_conn *)handle;
	int i, cnt;
	struct snat_args args[MAX_SNAT_RULES];
	(void)s;

	ofp_sendf(fd, "from\tto\tdev\tsource\talgo\r\n");

	cnt = ofp_vs_snat_dump_rules(args, MAX_SNAT_RULES); 
	for (i = 0; i < cnt; i++) {
		ofp_sendf(fd, PRINT_IP_FORMAT"/%d\t"
			PRINT_IP_FORMAT"/%d\t"
			"%s\t"
			PRINT_IP_FORMAT"-"PRINT_IP_FORMAT
			"\t%s\r\n",
			PRINT_NIP(args[i].saddr),
			inet_mask_len(args[i].smask),
			PRINT_NIP(args[i].daddr),
			inet_mask_len(args[i].dmask),
			ofp_port_vlan_to_ifnet_name(args[i].out_port, 0),
			PRINT_NIP(args[i].minip),
			PRINT_NIP(args[i].maxip),
			snat_algo_int2str(args[i].ip_sel_algo));
	}

	sendcrlf(conn);
}

void ofp_vs_cli_cmd_init(void)
{
	ofp_cli_add_command("fdir add DEV proto STRING src_ipv4 IP4ADDR "
			"src_port NUMBER dst_ipv4 IP4ADDR "
			"dst_port NUMBER queue_id NUMBER",
			"Add a flow director entry to network interface",
			fdir_add);
	ofp_cli_add_command("fdir del DEV proto STRING src_ipv4 IP4ADDR "
			"src_port NUMBER dst_ipv4 IP4ADDR "
			"dst_port NUMBER queue_id NUMBER",
			"Add a flow director entry to network interface",
			fdir_del);

	ofp_cli_add_command("fdir show DEV",
			"Show flow director entries of a network interface",
			fdir_show);

	ofp_cli_add_command("fdir flush DEV",
			"Flush flow director entries of a network interface",
			fdir_flush);

	ofp_cli_add_command("snat enable",
			"Enable snat service",
			snat_enable);

	ofp_cli_add_command("snat add from IP4NET to IP4NET "
			"out_dev DEV source IP4ADDR - IP4ADDR algo STRING",
			"Add snat rule",
			snat_add);

	ofp_cli_add_command("snat del from IP4NET to IP4NET out_dev DEV",
			"Del snat rule",
			snat_del);
	ofp_cli_add_command("snat show",
			"Show snat rule",
			snat_show);
}
