/*
 * Copyright (c) 2018 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <odp_api.h>

#include "api/ofp_ipsec.h"
#include "ofpi_cli.h"
#include "ofpi_util.h"
#include "ofpi_log.h"

#define NUM_TEMPLATES 16
#define MAX_STR 80
#define SCNs "79s"
#define MAX_IP_STR 32

struct sa_template {
	char name[MAX_STR];
	int allocated;
	uint16_t vrf;
	int dir;
	int proto;
	int mode;
	int cipher;
	ofp_ipsec_key_t cipher_key;
	int auth;
	ofp_ipsec_key_t auth_key;
	uint32_t window_size;
	uint32_t tun_src;
	uint32_t tun_dst;
};

struct sp_template {
	char name[MAX_STR];
	int allocated;
	uint16_t vrf;
	int dir;
	uint32_t src_start;
	uint32_t src_end;
	uint32_t dst_start;
	uint32_t dst_end;
	uint16_t ip_proto;
	int action;
};

/*
 * It seems that the CLI does not support threads which do not share their
 * memory, so simply store templates here instead of shared memory.
 */
static struct sa_template sa_templates[NUM_TEMPLATES];
static struct sp_template sp_templates[NUM_TEMPLATES];

struct value_str_mapping {
	const char *context;
	const char *str;
	int value;
};

static const struct value_str_mapping value_str_map[] = {
	{"sa-status", "active",    OFP_IPSEC_SA_ACTIVE},
	{"sa-status", "disabled",  OFP_IPSEC_SA_DISABLED},
	{"sa-status", "destroyed", OFP_IPSEC_SA_DESTROYED},
	{"sp-status", "active",    OFP_IPSEC_SP_ACTIVE},
	{"sp-status", "destroyed", OFP_IPSEC_SP_DESTROYED},
	{"direction", "in",        OFP_IPSEC_DIR_INBOUND},
	{"direction", "out",       OFP_IPSEC_DIR_OUTBOUND},
	{"protocol",  "esp",       OFP_IPSEC_PROTO_ESP},
	{"protocol",  "ah",        OFP_IPSEC_PROTO_AH},
	{"mode",      "tunnel",    OFP_IPSEC_MODE_TUNNEL},
	{"mode",      "transport", OFP_IPSEC_MODE_TRANSPORT},
	{"cipher",    "null",      OFP_IPSEC_CIPHER_ALG_NULL},
	{"cipher",    "3des-cbc",  OFP_IPSEC_CIPHER_ALG_3DES_CBC},
	{"cipher",    "aes-cbc",   OFP_IPSEC_CIPHER_ALG_AES_CBC},
	{"cipher",    "aes-gcm",   OFP_IPSEC_CIPHER_ALG_AES_GCM},
	{"auth-alg",  "null",      OFP_IPSEC_AUTH_ALG_NULL},
	{"auth-alg",  "sha-1",     OFP_IPSEC_AUTH_ALG_SHA1_HMAC},
	{"auth-alg",  "sha-256",   OFP_IPSEC_AUTH_ALG_SHA256_HMAC},
	{"auth-alg",  "sha-512",   OFP_IPSEC_AUTH_ALG_SHA512_HMAC},
	{"auth-alg",  "aes-gcm",   OFP_IPSEC_AUTH_ALG_AES_GCM},
	{"auth-alg",  "aes-gmac",  OFP_IPSEC_AUTH_ALG_AES_GMAC},
	{"action",    "discard",   OFP_IPSEC_ACTION_DISCARD},
	{"action",    "bypass",    OFP_IPSEC_ACTION_BYPASS},
	{"action",    "protect",   OFP_IPSEC_ACTION_PROTECT},
	{NULL,        NULL,        0}
};

static int value_str_valid(const char *context, const char *value_str)
{
	int n;

	if (context == NULL)
		return 1;

	for (n = 0; value_str_map[n].context != NULL; n++) {
		if (!strcmp(value_str_map[n].context, context) &&
		    !strcmp(value_str_map[n].str, value_str)) {
			return 1;
		}
	}
	return 0;
}

static int value_str_to_num(const char *context, const char *value_str)
{
	int n;

	if (!value_str)
		return 0;

	for (n = 0; value_str_map[n].context != NULL; n++) {
		if (!strcmp(value_str_map[n].context, context) &&
		    !strcmp(value_str_map[n].str, value_str)) {
				return value_str_map[n].value;
		}
	}
	return 0;
}

static const char *value_str_from_num(const char *context, int num)
{
	int n;

	for (n = 0; value_str_map[n].context != NULL; n++) {
		if (!strcmp(value_str_map[n].context, context) &&
		    value_str_map[n].value == num) {
				return value_str_map[n].str;
		}
	}
	return "(unknown value)";
}

static struct sa_template *sat_alloc(void)
{
	int n;
	struct sa_template *sat;

	for (n = 0; n < NUM_TEMPLATES; n++) {
		sat = &sa_templates[n];
		if (!sat->allocated) {
			sat->allocated = 1;
			return sat;
		}
	}
	return NULL;
}

static struct sp_template *spt_alloc(void)
{
	int n;
	struct sp_template *spt;

	for (n = 0; n < NUM_TEMPLATES; n++) {
		spt = &sp_templates[n];
		if (!spt->allocated) {
			spt->allocated = 1;
			return spt;
		}
	}
	return NULL;
}

static struct sa_template *find_sat(const char *name)
{
	int n;
	struct sa_template *sat;

	for (n = 0; n < NUM_TEMPLATES; n++) {
		sat = &sa_templates[n];
		if (sat->allocated &&
		    name && !strcmp(sat->name, name))
			return sat;
	}
	return NULL;
}

static struct sp_template *find_spt(const char *name)
{
	int n;
	struct sp_template *spt;

	for (n = 0; n < NUM_TEMPLATES; n++) {
		spt = &sp_templates[n];
		if (spt->allocated &&
		    name && !strcmp(spt->name, name))
			return spt;
	}
	return NULL;
}

static void cmd_sat_add(struct cli_conn *conn, const char *s)
{
	struct sa_template *sat;
	char name[MAX_STR];

	sscanf(s, "%"SCNs, name); /* strip whitespace */

	if (find_sat(name)) {
		ofp_sendf(conn->fd, "Template already exists\r\n");
		sendcrlf(conn);
		return;
	}

	sat = sat_alloc();
	if (sat == NULL) {
		ofp_sendf(conn->fd, "Template allocation failed");
		sendcrlf(conn);
		return;
	}
	memset(sat, 0, sizeof(*sat));
	strncpy(sat->name, name, sizeof(sat->name));
	sat->name[sizeof(sat->name) - 1] = 0;
	sat->allocated = 1;
	sendcrlf(conn);
}

static void cmd_spt_add(struct cli_conn *conn, const char *s)
{
	struct sp_template *spt;
	char name[MAX_STR];

	sscanf(s, "%"SCNs, name); /* strip whitespace */

	if (find_spt(name)) {
		ofp_sendf(conn->fd, "Template already exists\r\n");
		sendcrlf(conn);
		return;
	}

	spt = spt_alloc();
	if (spt == NULL) {
		ofp_sendf(conn->fd, "Template allocation failed");
		sendcrlf(conn);
		return;
	}
	memset(spt, 0, sizeof(*spt));
	strncpy(spt->name, name, sizeof(spt->name));
	spt->name[sizeof(spt->name) - 1] = 0;
	spt->allocated = 1;
	sendcrlf(conn);
}

static struct sa_template *sat_from_cmd(struct cli_conn *conn, const char *s)
{
	char name[MAX_STR];
	struct sa_template *sat;

	if (sscanf(s, "%"SCNs, name) != 1) {
		ofp_sendf(conn->fd, "Syntax error\r\n");
		return NULL;
	}
	sat = find_sat(name);

	if (sat == NULL) {
		ofp_sendf(conn->fd, "Template not found\r\n");
	}
	return sat;
}

static struct sp_template *spt_from_cmd(struct cli_conn *conn, const char *s)
{
	char name[MAX_STR];
	struct sp_template *spt;

	if (sscanf(s, "%"SCNs, name) != 1) {
		ofp_sendf(conn->fd, "Syntax error\r\n");
		return NULL;
	}
	spt = find_spt(name);

	if (spt == NULL) {
		ofp_sendf(conn->fd, "Template not found\r\n");
	}
	return spt;
}

static void cmd_sat_del(struct cli_conn *conn, const char *s)
{
	struct sa_template *sat = sat_from_cmd(conn, s);

	if (sat)
		sat->allocated = 0;
	sendcrlf(conn);
}

static void cmd_spt_del(struct cli_conn *conn, const char *s)
{
	struct sp_template *spt = spt_from_cmd(conn, s);

	if (spt)
		spt->allocated = 0;
	sendcrlf(conn);
}

/*
 * Read two hex digits from 's' and return their combined value
 * through 'byte'.
 * Return 0 if 's' is empty, 1 on success and -1 on failure.
 */
static int get_byte(struct cli_conn *conn, const char *s, uint8_t *byte)
{
	char tmp[3];
	char *endptr;

	if (s[0] == 0)
		return 0;
	tmp[0] = s[0];
	tmp[1] = s[1];
	tmp[2] = 0;
	*byte = strtoul(tmp, &endptr, 16);
	if (endptr != &tmp[2]) {
		ofp_sendf(conn->fd, "Invalid key\r\n");
		return -1;
	}
	return 1;
}

static void parse_key(struct cli_conn *conn, const char *s,
		      ofp_ipsec_key_t *key)
{
	char key_str[MAX_STR];
	ofp_ipsec_key_t tmp_key;
	int t;

	if (sscanf(s, "%*s%"SCNs, key_str) != 1) {
		ofp_sendf(conn->fd, "Syntax error\r\n");
		return;
	}
	s = key_str;

	tmp_key.key_len = 0;
	while (1) {
		t = get_byte(conn, s, &tmp_key.key_data[tmp_key.key_len]);
		if (t == -1)
			break;
		if (t == 0) {
			*key = tmp_key;
			break;
		}
		if (tmp_key.key_len >= OFP_IPSEC_MAX_KEY_SZ) {
			ofp_sendf(conn->fd, "Key too long\r\n");
			break;
		}
		tmp_key.key_len++;
		s += 2;
	}
}

static void parse_enum(struct cli_conn *conn, const char *s,
		       const char *context, int *result)
{
	char new_value[MAX_STR];

	if (sscanf(s, "%*s%"SCNs, new_value) != 1) {
		ofp_sendf(conn->fd, "Syntax error\r\n");
		return;
	}
	if (!value_str_valid(context, new_value)) {
		ofp_sendf(conn->fd, "Invalid %s\r\n", context);
		return;
	}
	*result = value_str_to_num(context, new_value);
}

static void cmd_sat_set_vrf(struct cli_conn *conn, const char *s)
{
	struct sa_template *sat = sat_from_cmd(conn, s);
	uint16_t vrf;

	if (sat) {
		if (sscanf(s, "%*s%"SCNu16, &vrf) != 1) {
			ofp_sendf(conn->fd, "Syntax error\r\n");
			sendcrlf(conn);
			return;
		}
		sat->vrf = vrf;
	}
	sendcrlf(conn);
}

static void cmd_sat_set_dir(struct cli_conn *conn, const char *s)
{
	struct sa_template *sat = sat_from_cmd(conn, s);

	if (sat)
		parse_enum(conn, s, "direction", &sat->dir);
	sendcrlf(conn);
}

static void cmd_sat_set_mode(struct cli_conn *conn, const char *s)
{
	struct sa_template *sat = sat_from_cmd(conn, s);

	if (sat)
		parse_enum(conn, s, "mode", &sat->mode);
	sendcrlf(conn);
}

static void cmd_sat_set_proto(struct cli_conn *conn, const char *s)
{
	struct sa_template *sat = sat_from_cmd(conn, s);

	if (sat)
		parse_enum(conn, s, "protocol", &sat->proto);
	sendcrlf(conn);
}

static void cmd_sat_set_cipher(struct cli_conn *conn, const char *s)
{
	struct sa_template *sat = sat_from_cmd(conn, s);

	if (sat)
		parse_enum(conn, s, "cipher", &sat->cipher);
	sendcrlf(conn);
}

static void cmd_sat_set_cipher_key(struct cli_conn *conn, const char *s)
{
	struct sa_template *sat = sat_from_cmd(conn, s);

	if (sat)
		parse_key(conn, s, &sat->cipher_key);
	sendcrlf(conn);
}

static void cmd_sat_set_auth(struct cli_conn *conn, const char *s)
{
	struct sa_template *sat = sat_from_cmd(conn, s);

	if (sat)
		parse_enum(conn, s, "auth-alg", &sat->auth);
	sendcrlf(conn);
}

static void cmd_sat_set_auth_key(struct cli_conn *conn, const char *s)
{
	struct sa_template *sat = sat_from_cmd(conn, s);

	if (sat)
		parse_key(conn, s, &sat->auth_key);
	sendcrlf(conn);
}

static void cmd_sat_set_window_size(struct cli_conn *conn, const char *s)
{
	struct sa_template *sat = sat_from_cmd(conn, s);
	uint32_t size;

	if (sat) {
		if (sscanf(s, "%*s%"SCNu32, &size) != 1) {
			ofp_sendf(conn->fd, "Syntax error\r\n");
			sendcrlf(conn);
			return;
		}
		sat->window_size = size;
	}
	sendcrlf(conn);
}

static void cmd_sat_set_tun_src(struct cli_conn *conn, const char *s)
{
	struct sa_template *sat = sat_from_cmd(conn, s);
	char addr[MAX_STR];

	if (sat) {
		if (sscanf(s, "%*s %"SCNs, addr) != 1) {
			ofp_sendf(conn->fd, "Syntax error\r\n");
		} else if (!ip4addr_get(addr, &sat->tun_src)) {
			ofp_sendf(conn->fd, "Invalid address\r\n");
		}
	}
	sendcrlf(conn);
}

static void cmd_sat_set_tun_dst(struct cli_conn *conn, const char *s)
{
	struct sa_template *sat = sat_from_cmd(conn, s);
	char addr[MAX_STR];

	if (sat) {
		if (sscanf(s, "%*s %"SCNs, addr) != 1) {
			ofp_sendf(conn->fd, "Syntax error\r\n");
		} else if (!ip4addr_get(addr, &sat->tun_dst)) {
			ofp_sendf(conn->fd, "Invalid address\r\n");
		}
	}
	sendcrlf(conn);
}

static void cmd_spt_set_vrf(struct cli_conn *conn, const char *s)
{
	struct sp_template *spt = spt_from_cmd(conn, s);
	uint16_t vrf;

	if (spt) {
		if (sscanf(s, "%*s%"SCNu16, &vrf) != 1) {
			ofp_sendf(conn->fd, "Syntax error\r\n");
			sendcrlf(conn);
			return;
		}
		spt->vrf = vrf;
	}
	sendcrlf(conn);
}

static void cmd_spt_set_dir(struct cli_conn *conn, const char *s)
{
	struct sp_template *spt = spt_from_cmd(conn, s);

	if (spt)
		parse_enum(conn, s, "direction", &spt->dir);
	sendcrlf(conn);
}

static void parse_addr_range(struct cli_conn *conn, const char *s,
			     uint32_t *start, uint32_t *end)
{
	char start_str[MAX_STR], end_str[MAX_STR];
	uint32_t start_bin, end_bin;

	if (sscanf(s, "%*s%"SCNs"%"SCNs, start_str, end_str) != 2) {
		ofp_sendf(conn->fd, "Syntax error\r\n");
	} else if (!ip4addr_get(start_str, &start_bin) ||
		   !ip4addr_get(end_str, &end_bin)) {
		ofp_sendf(conn->fd, "Invalid address\r\n");
	} else {
		*start = start_bin;
		*end = end_bin;
	}
}

static void cmd_spt_set_src(struct cli_conn *conn, const char *s)
{
	struct sp_template *spt = spt_from_cmd(conn, s);

	if (spt)
		parse_addr_range(conn, s, &spt->src_start, &spt->src_end);
	sendcrlf(conn);
}

static void cmd_spt_set_dst(struct cli_conn *conn, const char *s)
{
	struct sp_template *spt = spt_from_cmd(conn, s);

	if (spt)
		parse_addr_range(conn, s, &spt->dst_start, &spt->dst_end);
	sendcrlf(conn);
}

static void cmd_spt_set_proto(struct cli_conn *conn, const char *s)
{
	struct sp_template *spt = spt_from_cmd(conn, s);
	uint16_t proto;

	if (spt) {
		if (sscanf(s, "%*s%"SCNu16, &proto) != 1) {
			ofp_sendf(conn->fd, "Syntax error\r\n");
			sendcrlf(conn);
			return;
		}
		spt->ip_proto = proto;
	}
	sendcrlf(conn);
}

static void cmd_spt_set_action(struct cli_conn *conn, const char *s)
{
	struct sp_template *spt = spt_from_cmd(conn, s);

	if (spt)
		parse_enum(conn, s, "action", &spt->action);
	sendcrlf(conn);
}

static void ip4addr_print(char *buf, int maxlen, uint32_t addr)
{
	addr = odp_be_to_cpu_32(addr);
	snprintf(buf, maxlen, "%d.%d.%d.%d",
		 (addr >> 24) & 0xff,
		 (addr >> 16) & 0xff,
		 (addr >> 8)  & 0xff,
		 (addr)       & 0xff);
}

static void show_sat_params(struct cli_conn *conn, struct sa_template *sat)
{
	char tun_src[MAX_IP_STR], tun_dst[MAX_IP_STR];

	ip4addr_print(tun_src, sizeof(tun_src), sat->tun_src);
	ip4addr_print(tun_dst, sizeof(tun_dst), sat->tun_dst);

	ofp_sendf(conn->fd,
		  "  direction:  %s\r\n"
		  "  protocol:   %s\r\n"
		  "  mode:       %s\r\n"
		  "  cipher:     %s\r\n"
		  "  cipher-key: <%"PRIu16" bytes>\r\n"
		  "  auth:       %s\r\n"
		  "  auth-key:   <%"PRIu16" bytes>\r\n"
		  "  window-size %"PRIu32"\r\n"
		  "  tunnel-src: %s\r\n"
		  "  tunnel-dst: %s\r\n",
		  value_str_from_num("direction", sat->dir),
		  value_str_from_num("protocol", sat->proto),
		  value_str_from_num("mode", sat->mode),
		  value_str_from_num("cipher", sat->cipher),
		  sat->cipher_key.key_len,
		  value_str_from_num("auth-alg", sat->auth),
		  sat->auth_key.key_len,
		  sat->window_size,
		  tun_src,
		  tun_dst);
}

static void show_spt_params(struct cli_conn *conn, struct sp_template *spt)
{
	char src_s[MAX_IP_STR], src_e[MAX_IP_STR];
	char dst_s[MAX_IP_STR], dst_e[MAX_IP_STR];

	ip4addr_print(src_s, sizeof(src_s), spt->src_start);
	ip4addr_print(src_e, sizeof(src_e), spt->src_end);
	ip4addr_print(dst_s, sizeof(dst_s), spt->dst_start);
	ip4addr_print(dst_e, sizeof(dst_e), spt->dst_end);

	ofp_sendf(conn->fd,
		  "  direction:  %s\r\n"
		  "  src_addr:   %s - %s\r\n"
		  "  dst_addr:   %s - %s\r\n"
		  "  protocol:   %"PRIu16"\r\n"
		  "  action:     %s\r\n",
		  value_str_from_num("direction", spt->dir),
		  src_s, src_e,
		  dst_s, dst_e,
		  spt->ip_proto,
		  value_str_from_num("action", spt->action));
}

static void cmd_show_sat(struct cli_conn *conn, const char *s)
{
	(void) s;
	int n;

	for (n = 0; n < NUM_TEMPLATES; n++) {
		if (sa_templates[n].allocated) {
			ofp_sendf(conn->fd, "\r\nSA template name: %s\r\n",
				  sa_templates[n].name);
			show_sat_params(conn, &sa_templates[n]);
		}
	}
	sendcrlf(conn);
}

static void cmd_show_spt(struct cli_conn *conn, const char *s)
{
	(void) s;
	int n;

	for (n = 0; n < NUM_TEMPLATES; n++) {
		if (sp_templates[n].allocated) {
			ofp_sendf(conn->fd, "\r\nSA template name: %s\r\n",
				  sp_templates[n].name);
			show_spt_params(conn, &sp_templates[n]);
		}
	}
	sendcrlf(conn);
}

static void cmd_sa_add(struct cli_conn *conn, const char *s)
{
	char template[MAX_STR];
	uint32_t id;
	uint32_t spi;
	struct sa_template *sat;
	ofp_ipsec_sa_handle sa;
	ofp_ipsec_sa_param_t param;

	if (sscanf(s, "%"SCNu32 "%"SCNu32"%"SCNs, &id, &spi, template) != 3) {
		ofp_sendf(conn->fd, "Syntax error\r\n");
		sendcrlf(conn);
		return;
	}

	sat = find_sat(template);
	if (sat == NULL) {
		ofp_sendf(conn->fd, "Template not found\r\n");
		sendcrlf(conn);
		return;
	}

	ofp_ipsec_sa_param_init(&param);

	param.id    = id;
	param.vrf   = sat->vrf;
	param.dir   = sat->dir;
	param.proto = sat->proto;
	param.mode  = sat->mode;
	param.antireplay_ws = sat->window_size;
	param.crypto.cipher_alg = sat->cipher;
	param.crypto.cipher_key = sat->cipher_key;
	param.crypto.auth_alg   = sat->auth;
	param.crypto.auth_key   = sat->auth_key;
	param.tunnel.type = OFP_IPSEC_TUNNEL_IPV4;
	param.tunnel.ipv4.src_addr.s_addr = sat->tun_src;
	param.tunnel.ipv4.dst_addr.s_addr = sat->tun_dst;
	param.tunnel.ipv4.dscp = 0;
	param.tunnel.ipv4.ttl = UINT8_MAX;

	param.opt.esn = 0;
	param.opt.udp_encap = 0;
	param.opt.copy_dscp = 0;
	param.opt.copy_flabel = 0;

	param.spi = spi;

	sa = ofp_ipsec_sa_create(&param);
	ofp_ipsec_sa_unref(sa); /* forget the returned handle */
	if (sa == NULL)
		ofp_sendf(conn->fd, "SA creation failed\r\n");
	sendcrlf(conn);
}

static void cmd_sp_add(struct cli_conn *conn, const char *s)
{
	uint32_t id;
	char template[MAX_STR];
	uint32_t prio;
	struct sp_template *spt;
	ofp_ipsec_sp_handle sp;
	ofp_ipsec_sp_param_t param;

	if (sscanf(s, "%"SCNu32 "%"SCNu32"%"SCNs, &id, &prio, template) != 3) {
		ofp_sendf(conn->fd, "Syntax error\r\n");
		sendcrlf(conn);
		return;
	}
	spt = find_spt(template);
	if (spt == NULL) {
		ofp_sendf(conn->fd, "Template not found\r\n");
		sendcrlf(conn);
		return;
	}

	ofp_ipsec_sp_param_init(&param);
	param.id = id;
	param.vrf = spt->vrf;
	param.priority = prio;
	param.action = spt->action;
	param.dir = spt->dir;
	param.selectors.type = OFP_IPSEC_SELECTOR_IPV4;
	param.selectors.src_ipv4_range.first_addr.s_addr = spt->src_start;
	param.selectors.src_ipv4_range.last_addr.s_addr = spt->src_end;
	param.selectors.dst_ipv4_range.first_addr.s_addr = spt->dst_start;
	param.selectors.dst_ipv4_range.last_addr.s_addr = spt->dst_end;
	param.selectors.ip_proto = spt->ip_proto;

	sp = ofp_ipsec_sp_create(&param);
	ofp_ipsec_sp_unref(sp); /* forget the returned handle */
	if (sp == NULL)
		ofp_sendf(conn->fd, "SP creation failed\r\n");
	sendcrlf(conn);
}

static void cmd_sa_del(struct cli_conn *conn, const char *s)
{
	uint32_t id;
	ofp_ipsec_sa_handle sa;

	if (sscanf(s, "%"SCNu32, &id) != 1) {
		ofp_sendf(conn->fd, "Syntax error\r\n");
		sendcrlf(conn);
		return;
	}
	sa = ofp_ipsec_sa_find_by_id(id);
	if (!sa) {
		ofp_sendf(conn->fd, "SA not found\r\n");
		sendcrlf(conn);
		return;
	}
	if (ofp_ipsec_sa_destroy(sa))
		ofp_sendf(conn->fd, "SA deletion failed\r\n");
	ofp_ipsec_sa_unref(sa);
	sendcrlf(conn);
}

static void cmd_sp_del(struct cli_conn *conn, const char *s)
{
	uint32_t id;
	ofp_ipsec_sp_handle sp;

	if (sscanf(s, "%"SCNu32, &id) != 1) {
		ofp_sendf(conn->fd, "Syntax error\r\n");
		sendcrlf(conn);
		return;
	}
	sp = ofp_ipsec_sp_find_by_id(id);
	if (!sp) {
		ofp_sendf(conn->fd, "SP not found\r\n");
		sendcrlf(conn);
		return;
	}
	if (ofp_ipsec_sp_destroy(sp))
		ofp_sendf(conn->fd, "SP deletion failed\r\n");
	ofp_ipsec_sp_unref(sp);
	sendcrlf(conn);
}

static void cmd_sp_bind(struct cli_conn *conn, const char *s)
{
	uint32_t sp_id, sa_id;
	ofp_ipsec_sp_handle sp;
	ofp_ipsec_sa_handle sa;

	if (sscanf(s, "%"SCNu32"%"SCNu32, &sp_id, &sa_id) != 2) {
		ofp_sendf(conn->fd, "Syntax error\r\n");
		sendcrlf(conn);
		return;
	}
	sp = ofp_ipsec_sp_find_by_id(sp_id);
	if (sp == NULL) {
		ofp_sendf(conn->fd, "SP not found\r\n");
		sendcrlf(conn);
		return;
	}
	sa = ofp_ipsec_sa_find_by_id(sa_id);
	if (sa == NULL) {
		ofp_sendf(conn->fd, "SA not found\r\n");
		sendcrlf(conn);
		ofp_ipsec_sp_unref(sp);
		return;
	}
	if (ofp_ipsec_sp_bind(sp, sa))
		ofp_sendf(conn->fd, "Binding SA to SP failed\r\n");
	ofp_ipsec_sp_unref(sp);
	ofp_ipsec_sa_unref(sa);
	sendcrlf(conn);
}

static void cmd_sp_unbind(struct cli_conn *conn, const char *s)
{
	uint32_t id;
	ofp_ipsec_sp_handle sp;

	if (sscanf(s, "%"SCNu32, &id) != 1) {
		ofp_sendf(conn->fd, "Syntax error\r\n");
		sendcrlf(conn);
		return;
	}
	sp = ofp_ipsec_sp_find_by_id(id);
	if (sp == NULL) {
		ofp_sendf(conn->fd, "SP not found\r\n");
		sendcrlf(conn);
		return;
	}
	if (ofp_ipsec_sp_bind(sp, OFP_IPSEC_SA_INVALID))
		ofp_sendf(conn->fd, "Unbinding SA from SP failed\r\n");
	ofp_ipsec_sp_unref(sp);
	sendcrlf(conn);
}

static void show_sa(struct cli_conn *conn, ofp_ipsec_sa_handle sa)
{
	ofp_ipsec_sa_info_t info;

	ofp_ipsec_sa_get_info(sa, &info);
	if (info.status == OFP_IPSEC_SA_DESTROYED)
		return;
	ofp_sendf(conn->fd, "\r\nSA ID: %"PRIu32"\r\n", info.param.id);
	ofp_sendf(conn->fd,
		  "   status:     %s\r\n"
		  "   VRF:        %"PRIu16"\r\n"
		  "   SPI:        %"PRIu32"\r\n"
		  "   direction:  %s\r\n"
		  "   protocol:   %s\r\n"
		  "   mode:       %s\r\n"
		  "   cipher:     %s\r\n"
		  "   auth-alg:   %s\r\n"
		  "   window size %"PRIu32"\r\n",
		  value_str_from_num("sa-status", info.status),
		  info.param.vrf,
		  info.param.spi,
		  value_str_from_num("direction", info.param.dir),
		  value_str_from_num("protocol", info.param.proto),
		  value_str_from_num("mode",     info.param.mode),
		  value_str_from_num("cipher",   info.param.crypto.cipher_alg),
		  value_str_from_num("auth-alg", info.param.crypto.auth_alg),
		  info.param.antireplay_ws);

	if (info.param.mode == OFP_IPSEC_MODE_TUNNEL) {
		ofp_ipsec_tunnel_param_t *tun = &info.param.tunnel;
		char src[MAX_IP_STR], dst[MAX_IP_STR];

		ip4addr_print(src, sizeof(src), tun->ipv4.src_addr.s_addr);
		ip4addr_print(dst, sizeof(dst), tun->ipv4.dst_addr.s_addr);
		ofp_sendf(conn->fd,
			  "   tunnel-src: %s\r\n"
			  "   tunnel-dst: %s\r\n",
			  src, dst);
	}
}

static void show_sp(struct cli_conn *conn, ofp_ipsec_sp_handle sp)
{
	ofp_ipsec_sp_info_t info;
	char src_s[MAX_IP_STR], src_e[MAX_IP_STR];
	char dst_s[MAX_IP_STR], dst_e[MAX_IP_STR];

	ofp_ipsec_sp_get_info(sp, &info);
	if (info.status == OFP_IPSEC_SP_DESTROYED)
		return;
	ofp_sendf(conn->fd, "\r\nSP ID: %"PRIu32"\r\n", info.param.id);
	ofp_sendf(conn->fd,
		  "   status:     %s\r\n"
		  "   VRF:        %"PRIu16"\r\n"
		  "   direction:  %s\r\n"
		  "   priority:   %"PRIu32"\r\n"
		  "   action:     %s\r\n"
		  "   selectors:\r\n",
		  value_str_from_num("sp-status", info.status),
		  info.param.vrf,
		  value_str_from_num("direction", info.param.dir),
		  info.param.priority,
		  value_str_from_num("action", info.param.action));

	ip4addr_print(src_s, sizeof(src_s),
		      info.param.selectors.src_ipv4_range.first_addr.s_addr);
	ip4addr_print(src_e, sizeof(src_e),
		      info.param.selectors.src_ipv4_range.last_addr.s_addr);
	ip4addr_print(dst_s, sizeof(dst_s),
		      info.param.selectors.dst_ipv4_range.first_addr.s_addr);
	ip4addr_print(dst_e, sizeof(dst_e),
		      info.param.selectors.dst_ipv4_range.last_addr.s_addr);

	ofp_sendf(conn->fd,
		  "   selectors:\r\n"
		  "      src_addr:   %s - %s\r\n"
		  "      dst_addr:   %s - %s\r\n"
		  "      protocol:   %"PRIu16"\r\n",
		  src_s, src_e,
		  dst_s, dst_e,
		  info.param.selectors.ip_proto);
}

static void cmd_show_sa(struct cli_conn *conn, const char *s)
{
	ofp_ipsec_sa_handle sa;
	(void) s;

	sa = ofp_ipsec_sa_first();
	while (sa != OFP_IPSEC_SA_INVALID) {
		show_sa(conn, sa);
		sa = ofp_ipsec_sa_next(sa);
	}
	sendcrlf(conn);
}

static void cmd_show_sp(struct cli_conn *conn, const char *s)
{
	ofp_ipsec_sp_handle sp;
	(void) s;

	sp = ofp_ipsec_sp_first();
	while (sp != OFP_IPSEC_SP_INVALID) {
		show_sp(conn, sp);
		sp = ofp_ipsec_sp_next(sp);
	}
	sendcrlf(conn);
}

static const char *help_text[] = {
	"Create IPsec security policy (SP) template:",
	"  ipsec sp-template add <name>",
	"Set a parameter in IPsec SP template:",
	"  ipsec sp-template set <name> <parameter> <value>",
	"Delete IPsec SP template:",
	"  ipsec sp-template del <name>",
	"Show IPsec SP templates:",
	"  ipsec show sp-template",
	"",
	"Create IPsec security association (SA) template:",
	"  ipsec sa-template add <name>",
	"Set a parameter in IPsec SA template:",
	"  ipsec sa-template set <name> <parameter> <value>",
	"Delete IPsec SA template:",
	"  ipsec sa-template del <name>",
	"Show IPsec SA templates:",
	"  ipsec show sa-template",
	"",
	"Create IPsec security policy (SP) rule based on template:",
	"  ipsec sp add <id> priority <priority> template <template>",
	"Delete IPsec SP rule:",
	"  ipsec sp del <id>",
	"Show IPsec SP rules:",
	"  ipsec show sp",
	"",
	"Create IPsec security association (SA) based on template:",
	"  ipsec sa add <id> spi <spi> template <template>",
	"Delete IPsec SA:",
	"  ipsec sa del <id>",
	"Show IPsec SAs:",
	"  ipsec show sa",
	"",
	"Bind IPsec SP and SA:",
	"  ipsec sp bind <sp id> sa <sa id>",
	"Unbind an outbound IPsec SA from an outbound SP:",
	"  ipsec sp unbind <sp id> sa <sa id>",
	0};

static void cmd_help(struct cli_conn *conn, const char *s)
{
	const char **line = help_text;
	(void) s;

	while (*line) {
		ofp_sendf(conn->fd, *line);
		ofp_sendf(conn->fd, "\r\n");
		line++;
	}
	sendcrlf(conn);
}

struct cli_command {
	const char *command;
	const char *help;
#if 0
	void (*func)(struct cli_conn *, const char *);
#else
	void *func;
#endif
};

static struct cli_command commands[] = {
	/*
	 * IPsec SA template
	 */
	{
		"ipsec sa-template add STRING",
		"Create a SA template",
		cmd_sat_add
	},
	{
		"ipsec sa-template delete STRING",
		"Delete a SA template",
		cmd_sat_del
	},
	{
		"ipsec sa-template set STRING vrf NUMBER",
		"Set vrf in a SA template",
		cmd_sat_set_vrf
	},
	{
		"ipsec sa-template set STRING dir STRING",
		"Set direction (in, out) in a SA template",
		cmd_sat_set_dir
	},
	{
		"ipsec sa-template set STRING proto STRING",
		"Set protocol (esp, ah) in a SA template",
		cmd_sat_set_proto
	},
	{
		"ipsec sa-template set STRING mode STRING",
		"Set mode (transport, tunnel) in a SA template",
		cmd_sat_set_mode
	},
	{
		"ipsec sa-template set STRING cipher STRING",
		"Set encryption algorithm in a SA template",
		cmd_sat_set_cipher
	},
	{
		"ipsec sa-template set STRING cipher-key STRING",
		"Set encryption key in a SA template",
		cmd_sat_set_cipher_key
	},
	{
		"ipsec sa-template set STRING auth STRING",
		"Set authentication algorithm in a SA template",
		cmd_sat_set_auth
	},
	{
		"ipsec sa-template set STRING auth-key STRING",
		"Set authentication key in a SA template",
		cmd_sat_set_auth_key
	},
	{
		"ipsec sa-template set STRING window-size NUMBER",
		"Set anti-replay window size",
		cmd_sat_set_window_size
	},
	{
		"ipsec sa-template set STRING tun-src IP4ADDR",
		"Set tunnel source address in a SA template",
		cmd_sat_set_tun_src
	},
	{
		"ipsec sa-template set STRING tun-dst IP4ADDR",
		"Set tunnel destination address in a SA template",
		cmd_sat_set_tun_dst
	},

	/*
	 * IPsec SA
	 */
	{
		"ipsec sa add NUMBER spi NUMBER template STRING",
		"Create a SA based on a SA template",
		cmd_sa_add
	},
	{
		"ipsec sa delete NUMBER",
		"Delete a SA",
		cmd_sa_del
	},

	/*
	 * IPsec SP template
	 */
	{
		"ipsec sp-template add STRING",
		"Create a SP template",
		cmd_spt_add
	},
	{
		"ipsec sp-template del STRING",
		"Delete a SP template",
		cmd_spt_del
	},
	{
		"ipsec sp-template set STRING vrf NUMBER",
		"Set vrf in a SP template",
		cmd_spt_set_vrf
	},
	{
		"ipsec sp-template set STRING dir STRING",
		"Set direction in a SP template",
		cmd_spt_set_dir
	},
	{
		"ipsec sp-template set STRING src-range IP4ADDR IP4ADDR",
		"Set source address selector in a SP template",
		cmd_spt_set_src
	},
	{
		"ipsec sp-template set STRING dst-range IP4ADDR IP4ADDR",
		"Set destination address selector in a SP template",
		cmd_spt_set_dst
	},
	{
		"ipsec sp-template set STRING proto NUMBER",
		"Set protocol selector in a SP template",
		cmd_spt_set_proto
	},
	{
		"ipsec sp-template set STRING action STRING",
		"Set action in a SP template",
		cmd_spt_set_action
	},

	/*
	 * IPsec SP
	 */
	{
		"ipsec sp add NUMBER priority NUMBER template STRING",
		"Create a SP based on a SP template",
		cmd_sp_add
	},
	{
		"ipsec sp delete NUMBER",
		"Delete a SP",
		cmd_sp_del
	},
	{
		"ipsec sp bind NUMBER sa NUMBER",
		"Bind a SA to a SP",
		cmd_sp_bind
	},
	{
		"ipsec sp unbind NUMBER",
		"Unbind a SA from a SP",
		cmd_sp_unbind
	},

	/*
	 * IPsec status
	 */
	{
		"ipsec show sa-template",
		"Show IPsec SA templates",
		cmd_show_sat
	},
	{
		"ipsec show sa",
		"Show IPsec SAs",
		cmd_show_sa
	},
	{
		"ipsec show sp-template",
		"Show IPsec SP templates",
		cmd_show_spt
	},
	{
		"ipsec show sp",
		"Show IPsec SPs",
		cmd_show_sp
	},
	/*
	 * Help
	 */
	{
		"ipsec help",
		NULL,
		cmd_help
	},
	{
		"help ipsec",
		NULL,
		cmd_help
	},
	{ NULL, NULL, NULL }
};

void ofpcli_ipsec_init(void);

void ofpcli_ipsec_init(void)
{
	struct cli_command *cmd = commands;
	static int initialized = 0;

	if (initialized)
		return;
	initialized = 1;

	while (cmd->command) {
		ofp_cli_add_command(cmd->command, cmd->help, cmd->func);
		cmd++;
	}
}
