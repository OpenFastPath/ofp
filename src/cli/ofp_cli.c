/*-
 * Copyright (c) 2014 ENEA Software AB
 * Copyright (c) 2014 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <pwd.h>
#include <time.h>
#include <errno.h>

#include <odp_api.h>

#include "ofp_errno.h"

#include "ofpi.h"
#include "ofpi_pkt_processing.h"
#include "ofpi_cli.h"
#include "ofpi_log.h"
#include "ofpi_util.h"
#include "ofpi_portconf.h"

#ifdef CLI
/*
 * Only core 0 runs this.
 */

static int close_cli;

int cli_display_width = 80, cli_display_height = 24;
int cli_curses = 0;
int cli_display_row = 2, cli_display_col = 5;
int cli_display_rows = 10, cli_display_cols = 30;

/** CLI Commands node
 */
struct cli_node {
	void (*func)(struct cli_conn *, const char *);
	struct cli_node *nextword;
	struct cli_node *nextpossibility;
	char *word;
	const char *help;
	char type;
};

/** CLI Command descriptor
 */
struct cli_command {
	const char *command;
	const char *help;
	void (*func)(struct cli_conn *, const char *);
};

/* status bits */
#define CONNECTION_ON		1
#define DO_ECHO			2 /* telnet */
#define DO_SUPPRESS		4 /* telnet */
#define WILL_SUPPRESS		8 /* telnet */
#define WAITING_TELNET_1	16
#define WAITING_TELNET_2	32
#define WAITING_ESC_1		64
#define WAITING_ESC_2		128
#define WAITING_PASSWD		256
#define ENABLED_OK		512

static struct cli_conn connection;

int run_alias = -1;

static void addchars(struct cli_conn *conn, const char *s);
static void parse(struct cli_conn *conn, int extra);

static void close_connection(struct cli_conn *conn)
{
	(void)conn;
	OFP_DBG("Closing connection...\r\n");
	close_cli = 1; /* tell server to close the socket */
}

static int int_ok(char *val)
{
	if ((val[0] == '0') &&
		(val[1] == 'x' || val[1] == 'X')) {
		val += 2;
		while (*val) {
			if (!((*val >= '0' && *val <= '9') ||
				(*val >= 'a' && *val <= 'f') ||
				(*val >= 'A' && *val <= 'F')))
					return 0;
			val++;
		}
		return 1;
	}

	while (*val) {
		if (*val < '0' || *val > '9')
			return 0;
		val++;
	}
	return 1;
}

static int ip4addr_ok(char *val)
{
	char b[100], *p, *octet;
	int i;

	strcpy(b, val);

	p = b;
	for (i = 0; i < 4; i++) {
		octet = strsep(&p, ".");
		if (strlen(octet) > 3)
			return 0;
		if (strlen(octet) == 0)
			return 0;
		if (!int_ok(octet))
			return 0;
		if (i < 3 && p == NULL)
			return 0;
	}
	if (p)
		return 0;
	return 1;
}

static int topname_ok(char *val)
{
	if (!strncmp("parse", val, 3))
		return 1;
	if (!strncmp("resolve", val, 3))
		return 1;
	if (!strncmp("modify", val, 3))
		return 1;
	if (!strncmp("search", val, 3))
		return 1;
	if (!strncmp("learn", val, 3))
		return 1;
	return 0;
}

static int dev_ok(char *val)
{
	int port, vlan;

	port = ofp_name_to_port_vlan(val, &vlan);
	return (port >= 0 && port < ofp_get_num_ports());
}

static int ip4net_ok(char *val)
{
	char b[100], *p, *octet;
	int i;

	strcpy(b, val);

	p = b;
	for (i = 0; i < 5; i++) {
		if (i == 3)
			octet = strsep(&p, "/");
		else
			octet = strsep(&p, ".");
		if (strlen(octet) > 3)
			return 0;
		if (strlen(octet) == 0)
			return 0;
		if (!int_ok(octet))
			return 0;
		if (i < 4 && p == NULL)
			return 0;
	}
	return 1;
}

static int ip6addr_check_ok(char *val, int len)
{
	char *it, *last;
	char *last_colon;
	char *group_start;
	int colon_cnt;
	int group_cnt;
	odp_bool_t short_format;

	it = val;
	last = it + len;
	last_colon = NULL;
	colon_cnt = 0;
	group_cnt = 0;
	short_format = 0;

	while (it < last) {
		if ((*it) == ':') {
			if ((last_colon != NULL) && (it - 1 == last_colon))
				short_format = 1;
			last_colon = it;
			it++;
			colon_cnt++;
		} else if (((*it) >= '0' && (*it) <= '9') ||
			   ((*it) >= 'a' && (*it) <= 'f') ||
			   ((*it) >= 'A' && (*it) <= 'F')) {
			group_start = it;
			while ((it < last) &&
				  (((*it) >= '0' && (*it) <= '9') ||
				   ((*it) >= 'a' && (*it) <= 'f') ||
				   ((*it) >= 'A' && (*it) <= 'F'))) {
					it++;
			}

			if ((it - group_start > 4) ||
				(it - group_start == 0))
				return 0;

			group_cnt++;
		} else
			return 0;

	}

	if (short_format) {
		if (colon_cnt > 7 || group_cnt > 8)
			return 0;
	} else {
		if (colon_cnt != 7 || group_cnt != 8)
			return 0;
	}

	return 1;
}

static int ip6addr_ok(char *val)
{
	return ip6addr_check_ok(val, strlen(val));
}

static int ip6net_ok(char *val)
{
	char *prefix_position;

	prefix_position = strstr(val, "/");
	if (prefix_position == NULL)
		return 0;


	if (ip6addr_check_ok(val, prefix_position - val) == 0)
		return 0;

	prefix_position++;

	if (strlen(prefix_position) > 3)
		return 0;
	if (strlen(prefix_position) == 0)
		return 0;
	if (!int_ok(prefix_position))
		return 0;

	return 1;
}

static uint8_t txt_to_hex(char val)
{
	if (val >= '0' && val <= '9')
		return(val - '0');
	if (val >= 'a' && val <= 'f')
		return(val - 'a' + 10);
	if (val >= 'A' && val <= 'F')
		return(val - 'A' + 10);

	return 255;
}

int ip4addr_get(const char *tk, uint32_t *addr)
{
	int a, b, c, d;

	if (sscanf(tk, "%d.%d.%d.%d", &a, &b, &c, &d) < 4)
		return 0;

	*addr = odp_cpu_to_be_32((a << 24) | (b << 16) | (c << 8) | d);

	return 1;
}

int ip4net_get(const char *tk, uint32_t *addr, int *mask)
{
	int a, b, c, d;

	if (sscanf(tk, "%d.%d.%d.%d/%d", &a, &b, &c, &d, mask) < 5)
		return 0;

	*addr = odp_cpu_to_be_32((a << 24) | (b << 16) | (c << 8) | d);

	return 1;
}

int ip6addr_get(const char *tk, int tk_len, uint8_t *addr)
{
	const char *it, *last;
	const char *last_colon;
	const char *group_start;
	int group_cnt;
	int group_len;
	int dbl_colon_pos;
	int i;

	memset(addr, 0, 16);

	it = tk;
	last = it + tk_len;
	last_colon = NULL;
	group_cnt = 0;
	dbl_colon_pos = -1;

	while (it < last) {
		if ((*it) == ':') {
			if ((last_colon != NULL) &&
				(it - 1 == last_colon)) {
				if (dbl_colon_pos != -1)
					return 0;
				dbl_colon_pos = group_cnt;
			}
			last_colon = it;
			it++;
		} else if (((*it) >= '0' && (*it) <= '9') ||
			((*it) >= 'a' && (*it) <= 'f') ||
			((*it) >= 'A' && (*it) <= 'F')) {
			group_start = it;
			while ((it < last) &&
				(((*it) >= '0' && (*it) <= '9') ||
				((*it) >= 'a' && (*it) <= 'f') ||
				((*it) >= 'A' && (*it) <= 'F'))) {
					it++;
			}
			group_len = it - group_start;
			if ((group_len > 4) ||
				(group_len == 0))
				return 0;

			if (group_len >= 1)
				addr[group_cnt * 2 + 1] =
					txt_to_hex(*(it - 1));
			if (group_len >= 2)
				addr[group_cnt * 2 + 1] |=
					txt_to_hex(*(it - 2)) << 4;
			if (group_len >= 3)
				addr[group_cnt * 2] =
					txt_to_hex(*(it - 3));
			if (group_len == 4)
				addr[group_cnt * 2] |=
					txt_to_hex(*(it - 4)) << 4;

			group_cnt++;
		} else
			return 0;

	}

	if (dbl_colon_pos != -1) {
		for (i = 0; i < 16  - (dbl_colon_pos * 2); i++) {
			if (i < (group_cnt - dbl_colon_pos) * 2)
				addr[15 - i] =
					addr[group_cnt * 2 - 1 - i];
			else
				addr[15 - i] = 0;
		}
	}

	return 1;
}

static void sendstr(struct cli_conn *conn, const char *s)
{
	if (S_ISSOCK(conn->fd))
		send(conn->fd, s, strlen(s), 0);
	else
		(void)(write(conn->fd, s, strlen(s)) + 1);
}

void sendcrlf(struct cli_conn *conn)
{
	if ((conn->status & DO_ECHO) == 0)
		sendstr(conn, "\n"); /* no extra prompts */
	else if (conn->status & ENABLED_OK)
		sendstr(conn, "\r\n# ");
	else
		sendstr(conn, "\r\n> ");
}

static void sendprompt(struct cli_conn *conn)
{
	if (conn->status & ENABLED_OK)
		sendstr(conn, "\r# ");
	else
		sendstr(conn, "\r> ");
}

static void cli_send_welcome_banner(int fd)
{
	struct cli_conn *conn;
	char sendbuf[100];
	(void)fd;

	conn = &connection;

	sprintf(sendbuf,
		"\r\n"
		"--==--==--==--==--==--==--\r\n"
		"-- WELCOME to OFP CLI --\r\n"
		"--==--==--==--==--==--==--\r\n"
		);
	sendstr(conn, sendbuf);
	sendcrlf(conn);
}

static void cli_send_goodbye_banner(struct cli_conn *conn)
{
	sendstr(conn,
		"\r\n"
		"--==--==--==--\r\n"
		"-- Goodbye! --\r\n"
		"--==--==--==--\r\n"
		);
	sendcrlf(conn);
}

/***********************************************
 * Functions to be called.                     *
 ***********************************************/

static void f_exit(struct cli_conn *conn, const char *s)
{
	(void)s;
	if (conn->status & ENABLED_OK) {
		conn->status &= ~ENABLED_OK;
		cli_send_goodbye_banner(conn);
		sendcrlf(conn);
		return;
	}

	cli_send_goodbye_banner(conn);
	close_connection(conn);
}

static void f_help(struct cli_conn *conn, const char *s)
{
	(void)s;
	ofp_sendf(conn->fd, "Display help information for CLI commands:\r\n"
		"  help <command>\r\n"
		"    command: alias, arp, debug, exit, ifconfig, loglevel, address, "
		"route, show, stat\r\n\r\n");
	sendcrlf(conn);
}

static void f_help_exit(struct cli_conn *conn, const char *s)
{
	(void)s;
	sendstr(conn, "Exit closes the current connection.\r\n"
		"You can type ctl-D, too.");
	sendcrlf(conn);
}


static void f_help_show(struct cli_conn *conn, const char *s)
{
	(void)s;
	ofp_sendf(conn->fd, "Display current status:\r\n"
		"  show <command>\r\n"
		"    command: alias, arp, debug, ifconfig, loglevel, route, address, "
		"stat\r\n\r\n");
	sendcrlf(conn);
}

static int authenticate(const char *user, const char *passwd)
{
	(void)user;
	(void)passwd;
#if 0
	struct passwd *pw;
	char *epasswd;

	if ((pw = getpwnam(user)) == NULL) return 0;
	if (pw->pw_passwd == 0) return 1;
	epasswd = crypt(passwd, pw->pw_passwd);
	if (strcmp(epasswd, pw->pw_passwd)) return 0;
#endif
	return 1;
}


/*******************************************/

/**< Special Parameter keywords in commands */
static char NUMBER[]  = "<number>";
static char IP4ADDR[] = "<a.b.c.d>";
static char TOPNAME[] = "<top name>";
static char STRING[]  = "<string>";
static char DEV[] = "<dev>";
static char IP4NET[] = "<a.b.c.d/n>";
static char IP6ADDR[] = "<a:b:c:d:e:f:g:h>";
static char IP6NET[] = "<a:b:c:d:e:f:g:h/n>";

/** Check if the given word is a built-in "Parameter Keyword",
 *  and if so returns the Parameter string address, used as an identifier in the parser;
 *
 * @input str const char*: word to be checked
 * @return char*
 * @return NULL: the input word is not a Parameter
 * @return else the Parameter string address
 *
 */
static char *get_param_string(const char *str)
{
#define IS_PARAM(str, param) (!strncmp(str, #param, strlen(#param)))

	if IS_PARAM(str, NUMBER)
		return NUMBER;
	if IS_PARAM(str, IP4ADDR)
		return IP4ADDR;
	if IS_PARAM(str, TOPNAME)
		return TOPNAME;
	if IS_PARAM(str, STRING)
		return STRING;
	if IS_PARAM(str, DEV)
		return DEV;
	if IS_PARAM(str, IP4NET)
		return IP4NET;
	if IS_PARAM(str, IP6NET)
		return IP6NET;
	if IS_PARAM(str, IP6ADDR)
		return IP6ADDR;

#undef IS_PARAM
	return NULL;
}

static struct cli_node end = {0, 0, 0, 0, 0, 0};
static struct cli_node *start = &end;

/* CLI Commands list */

/* Command Parameters are indicated by the following keywords:
 * NUMBER,IP4ADDR,TOPNAME,STRING,DEV,IP4NET
 */

struct cli_command commands[] = {
	{
		"exit",
		"Quit the connection",
		f_exit
	},
	{
		"show",
		"Display information",
		f_help_show
	},
	{
		"show help",
		"Display information",
		f_help_show
	},
	{
		"show arp",
		NULL,
		f_arp
	},
	{
		"show debug",
		NULL,
		f_debug_show
	},
	{
		"show loglevel",
		NULL,
		f_loglevel_show
	},
	{
		"show route",
		NULL,
		f_route_show
	},
	{
		"show alias",
		NULL,
		f_alias_show
	},
	{
		"show stat",
		NULL,
		f_stat_show
	},
	{
		"show ifconfig",
		NULL,
		f_ifconfig_show
	},
	{
		"debug",
		"Print traffic to file (and console) or to a pcap file",
		f_debug_show
	},
	{
		"debug NUMBER",
		"Bit mask of categories whose traffic to print (15 or 0xf for everything)",
		f_debug
	},
	{
		"debug help",
		"Print help",
		f_help_debug
	},
	{
		"debug show",
		"Show debug settings",
		f_debug_show
	},
	{
		"debug capture NUMBER",
		"Port mask whose traffic to save in pcap format (15 or 0xf for ports 0-3)",
		f_debug_capture
	},
	{
		"debug capture info NUMBER",
		"Non-zero = Include port number info by overwriting the first octet of dest MAC",
		f_debug_info
	},
	{
		"debug capture file STRING",
		"File to save captured packets",
		f_debug_capture_file
	},
	{
		"loglevel",
		"Show or set log level",
		f_loglevel_show
	},
	{
		"loglevel set STRING",
		"Set log level",
		f_loglevel
	},
	{
		"loglevel help",
		"Print help",
		f_help_loglevel
	},
	{
		"loglevel show",
		"Show log level",
		f_loglevel_show
	},
	{
		"help",
		NULL,
		f_help
	},
	{
		"help exit",
		NULL,
		f_help_exit
	},
	{
		"help show",
		NULL,
		f_help_show
	},
	{
		"help debug",
		NULL,
		f_help_debug
	},
	{
		"help loglevel",
		NULL,
		f_help_loglevel
	},
	{
		"help route",
		NULL,
		f_help_route
	},
	{
		"help arp",
		NULL,
		f_help_arp
	},
	{
		"help alias",
		NULL,
		f_help_alias
	},
	{
		"help stat",
		NULL,
		f_help_stat
	},
	{
		"help ifconfig",
		NULL,
		f_help_ifconfig
	},
	{
		"arp",
		"Show arp table",
		f_arp
	},
	{
		"arp flush",
		"Flush arp table",
		f_arp_flush
	},
	{
		"arp cleanup",
		"Clean old entries from arp table",
		f_arp_cleanup
	},
	{
		"arp help",
		NULL,
		f_help_arp
	},
	{
		"route",
		"Show route table",
		f_route_show
	},
	{
		"route show",
		"Show route table",
		f_route_show
	},
	{
		"route add IP4NET gw IP4ADDR dev DEV",
		"Add route",
		f_route_add
	},
	{
		"route -A inet4 add IP4NET gw IP4ADDR dev DEV",
		"Add route",
		f_route_add
	},
#ifdef INET6
	{
		"route -A inet6 add IP6NET gw IP6ADDR dev DEV",
		"Add route",
		f_route_add_v6
	},
#endif /* INET6 */
	{
		"route add vrf NUMBER IP4NET gw IP4ADDR dev DEV",
		"Add route to VRF",
		f_route_add_vrf
	},
	{
		"route -A inet4 add vrf NUMBER IP4NET gw IP4ADDR dev DEV",
		"Add route to VRF",
		f_route_add_vrf
	},
	{
		"route delete IP4NET",
		"Delete route",
		f_route_del
	},
	{
		"route -A inet4 delete IP4NET",
		"Delete route",
		f_route_del
	},
	{
		"route delete vrf NUMBER IP4NET",
		"Delete route",
		f_route_del_vrf
	},
	{
		"route -A inet4 delete vrf NUMBER IP4NET",
		"Delete route",
		f_route_del_vrf
	},
#ifdef INET6
	{
		"route -A inet6 delete IP6NET",
		"Delete route",
		f_route_del_v6
	},
#endif /* INET6 */
	{
		"route add from DEV to DEV",
		"Add route from interface to interface",
		f_route_add_dev_to_dev
	},
	{
		"route help",
		NULL,
		f_help_route
	},
	{
		"ifconfig",
		"Show interfaces",
		f_ifconfig_show
	},
	{
		"ifconfig show",
		NULL,
		f_ifconfig_show
	},
	{
		"ifconfig DEV IP4NET",
		"Create interface",
		f_ifconfig
	},
	{
		"ifconfig -A inet4 DEV IP4NET",
		"Create interface",
		f_ifconfig
	},
#ifdef INET6
	{
		"ifconfig -A inet6 DEV IP6NET",
		"Create interface",
		f_ifconfig_v6
	},
#endif /* INET6 */
	{
		"ifconfig DEV IP4NET vrf NUMBER",
		"Create interface",
		f_ifconfig
	},
	{
		"ifconfig -A inet4 DEV IP4NET vrf NUMBER",
		"Create interface",
		f_ifconfig
	},
	{
		"ifconfig tunnel gre DEV local IP4ADDR remote IP4ADDR peer IP4ADDR IP4ADDR",
		"Create GRE tunnel interface",
		f_ifconfig_tun
	},
	{
		"ifconfig tunnel gre DEV local IP4ADDR remote IP4ADDR peer IP4ADDR IP4ADDR vrf NUMBER",
		"Create GRE tunnel interface",
		f_ifconfig_tun
	},
	{
		"ifconfig vxlan DEV group IP4ADDR dev DEV IP4NET",
		"Create VXLAN interface",
		f_ifconfig_vxlan
	},
	{
		"ifconfig DEV down",
		"Delete interface",
		f_ifconfig_down
	},
	{
		"ifconfig help",
		NULL,
		f_help_ifconfig
	},
	{
		"address add IP4NET DEV",
		"Add IP address to interface",
		f_address_add
	},
	{
		"address del IP4NET DEV",
		"Remove IP address to interface",
		f_address_del
	},
	{
		"address show",
		"Show IP addresses",
		f_address_show
	},
	{
		"help address",
		NULL,
		f_address_help
	},
	{
		"alias",
		NULL,
		f_alias_show
	},
	{
		"alias set STRING STRING",
		"Define an alias",
		f_alias_set
	},
	{
		"alias show",
		NULL,
		f_alias_show
	},
	{
		"alias help",
		NULL,
		f_help_alias
	},
	{
		"stat",
		"Show statistics",
		f_stat_show
	},
	{
		"stat show",
		NULL,
		f_stat_show
	},
	{
		"stat set NUMBER",
		NULL,
		f_stat_set
	},
	{
		"stat perf",
		NULL,
		f_stat_perf
	},
	{
		"stat clear",
		NULL,
		f_stat_clear
	},
	{
		"stat help",
		NULL,
		f_help_stat
	},
	{
		"sysctl dump",
		"Dump sysctl tree",
		f_sysctl_dump
	},
	{
		"sysctl r STRING",
		"Read sysctl variable",
		f_sysctl_read
	},
	{
		"sysctl w STRING STRING",
		"Set sysctl variable",
		f_sysctl_write
	},
	{ NULL, NULL, NULL }
};

static void print_nodes(int fd, struct cli_node *node)
{
	struct cli_node *n;
	static int depth = 0;
	int i;
	int ni = 0;
	struct cli_node *stack[100];

	if (node == &end)
		return;

	for (i = 0; i < depth; i++)
		ofp_sendf(fd, " ");
	for (n = node; n != &end; n = n->nextword) {
		depth += strlen(n->word) + 1;
		stack[ni++] = n;
		ofp_sendf(fd, "%s ", n->word);
	}

	ofp_sendf(fd, "\n");
	while (ni > 0) {
		n = stack[--ni];
		depth -= strlen(n->word) + 1;
		print_nodes(fd, n->nextpossibility);
	}
}

static struct cli_node *add_command(struct cli_node *root, struct cli_command *cc)
{
	struct cli_node *s;
	struct cli_node *cn = root;
	struct cli_node *new;
	struct cli_node *n;
	int nextpossibility = 0;
	int len;
	char *nw;
	char *param;
	const char *str;
	const char *w;

	w = cc->command;

	s = cn;
	while (cn != &end) {
		nw = strchr(w, ' ');

		str = get_param_string(w);
		if (!str) {
			str = w;
			if (nw)
				len = nw - w;
			else
				len = strlen(w);
		} else {
			len = strlen(str);
		}

		while (cn != &end && strncmp(str, cn->word, len)) {
			s = cn;
			cn = cn->nextpossibility;
		}

		if (cn == &end) {
			nextpossibility = 1;
		} else {
			if (!nw)
				ofp_generate_coredump();
			w = nw + 1;
			s = cn;
			cn = cn->nextword;
		}
	}

	new = NULL;
	cn = NULL;
	while (w) {
		n = malloc(sizeof(*cn));
		n->help = NULL;
		n->func = NULL;
		n->nextword = &end;
		n->nextpossibility = &end;

		if (!new)
			new = n;

		if (cn)
			cn->nextword = n;

		cn = n;
		param = get_param_string(w);
		nw = strchr(w, ' ');
		if (!nw) {
			if (param)
				n->word = param;
			else
				n->word = strdup(w);
			break;
		}
		/* else */
		if (param) {
			n->word = param;
		} else {
			n->word = malloc(nw - w + 1);
			memcpy(n->word, w, nw - w);
			n->word[nw - w] = '\0';
		}
		w = nw + 1;
	}

	cn->func = cc->func;
	cn->help = cc->help;

	if (root == &end)
		root = new;
	else if (nextpossibility)
		s->nextpossibility = new;
	else
		s->nextword = new;

	return root;
}

static void f_run_alias(struct cli_conn *conn, const char *s)
{
	(void)s;
	char *line = conn->inbuf;
	int i;

	for (i = 0; i < ALIAS_TABLE_LEN; i++) {
		if (alias_table[i].name == 0 || alias_table[i].cmd == 0)
			continue;
		if (strncmp(line, alias_table[i].name,
			strlen(alias_table[i].name)) == 0) {
			run_alias = i;
			return;
		}
	}
}

void f_add_alias_command(const char *name)
{
	struct cli_command a;

	a.command = name;
	a.help = "Alias command";
	a.func = f_run_alias;
	start = add_command(start, &a);
}

void ofp_cli_add_command(const char *cmd, const char *help,
			 ofp_cli_cb_func func)
{
	struct cli_command a;

	a.command = cmd;
	a.help = help;
	a.func = (void (*)(struct cli_conn *, const char *))func;
	start = add_command(start, &a);
}

int ofp_cli_get_fd(void *handle)
{
	struct cli_conn *conn = handle;
	return conn->fd;
}

static void cli_init_commands(void)
{
	unsigned i = 0;
	static int initialized = 0;
	struct cli_conn conn;

	if (initialized)
		return;

	initialized = 1;

	/* virtual connection */
	memset(&conn, 0, sizeof(conn));
	conn.fd = 1; /* stdout */
	conn.status = CONNECTION_ON; /* no prompt */


	/* Initalize alias table*/
	for (i = 0; i < ALIAS_TABLE_LEN; i++) {
		alias_table[i].name = NULL;
		alias_table[i].cmd = NULL;
	}

	/* Add regular commands */
	for (i = 0; commands[i].command; i++)
		start = add_command(start, &commands[i]);

	/* Print nodes */
	if (ofp_debug_logging_enabled()) {
	    ofp_sendf(conn.fd, "CLI Command nodes:\n");
	    print_nodes(conn.fd, start);
	}
}

static void cli_process_file(char *file_name)
{
	FILE *f;
	struct cli_conn conn;

	/* virtual connection */
	memset(&conn, 0, sizeof(conn));
	conn.fd = 1; /* stdout */
	conn.status = CONNECTION_ON; /* no prompt */

	if (file_name != NULL) {
		f = fopen(file_name, "r");
		if (!f) {
			OFP_ERR("OFP CLI file not found.\n");
			return;
		}

		while (fgets(conn.inbuf, sizeof(conn.inbuf), f)) {
			if (conn.inbuf[0] == '#' || conn.inbuf[0] <= ' ')
				continue;
			ofp_sendf(conn.fd, "CLI: %s\n",
				conn.inbuf);
			parse(&conn, 0);
		}

		fclose(f);
	}
	else {
		OFP_DBG("OFP CLI file not set.\n");
	}
}

static void print_q(struct cli_conn *conn, struct cli_node *s, struct cli_node *ok)
{
	char sendbuf[200];

	if (s == &end || (ok && ok->func)) {
		sendstr(conn, "\r\n <cr>");
		//return;
	}
	while (s != &end) {
		if (s->help)
			sprintf(sendbuf, "\r\n %-20s(%.158s)", s->word, s->help);
		else
			sprintf(sendbuf, "\r\n %.178s", s->word);
		sendstr(conn, sendbuf);
		s = s->nextpossibility;
	}
	sendcrlf(conn);
	return;
}

static struct cli_node *find_next_vertical(struct cli_node *s, char *word)
{
	int foundcnt = 0, len = strlen(word);
	struct cli_node *found = 0;

	while (s != &end) {
		if ((strncmp(s->word, word, len) == 0) ||
			(s->word == NUMBER && int_ok(word)) ||
			(s->word == IP4ADDR && ip4addr_ok(word)) ||
			(s->word == TOPNAME && topname_ok(word)) ||
			(s->word == DEV && dev_ok(word)) ||
			(s->word == IP4NET && ip4net_ok(word)) ||
			(s->word == STRING) ||
			(s->word == IP6ADDR && ip6addr_ok(word)) ||
			(s->word == IP6NET && ip6net_ok(word))) {
			foundcnt++;
			if (foundcnt > 1) return 0;
			found = s;
		}
		s = s->nextpossibility;
	}
	return found;
}

static int is_parameter(struct cli_node *s)
{
	return ((s->word == NUMBER) ||
		(s->word == IP4ADDR) ||
		(s->word == TOPNAME) ||
		(s->word == DEV) ||
		(s->word == IP4NET) ||
		(s->word == STRING) ||
		(s->word == IP6ADDR) ||
		(s->word == IP6NET));
}

/** parse(): parse a Command line
 *
 * @param conn struct cli_conn*
 * @param extra int
 * @return void
 *
 */
static void parse(struct cli_conn *conn, int extra)
{
	char **ap, *argv[50], **token, *msg, *lasttoken = 0;
	char b[sizeof(conn->inbuf)];
	struct cli_node *p = start, *horpos = &end, *lastok = 0;
	int paramlen;
	char paramlist[100];
	char *line = conn->inbuf;
	int linelen = strlen(line);

	if (linelen > 0 && line[linelen-1] == ' ' && extra) extra = '?';
	else if (linelen == 0 && extra) extra = '?';
	else if (extra) extra = '\t';

	if (linelen == 0) {
		print_q(conn, p, 0);
		return;
	}

	strcpy(b, line);
	msg = b;

	for (ap = argv; (*ap = strsep(&msg, " \r\n")) != NULL;) {
		if (**ap != '\0') {
			if (++ap >= &argv[49])
				break;

			if (msg != NULL && *msg == '\"') {
				msg += 1;
				*ap = strsep(&msg, "\"\r\n");
				if (++ap >= &argv[49])
					break;
			}
	    }
	}

	token = argv;

	horpos = p;
	paramlen = 0;
	paramlist[0] = 0;

	while (*token && p != &end) {
		struct cli_node *found;
		found = find_next_vertical(p, *token);
		if (found) {
			lastok = found;
			lasttoken = *token;
			p = found->nextword;
			horpos = p;
			if ((found->word == NUMBER && int_ok(*token)) ||
				(found->word == IP4ADDR && ip4addr_ok(*token)) ||
				(found->word == TOPNAME && topname_ok(*token)) ||
				(found->word == DEV && dev_ok(*token)) ||
				(found->word == IP4NET && ip4net_ok(*token)) ||
				(found->word == STRING) ||
				(found->word == IP6ADDR && ip6addr_ok(*token)) ||
				(found->word == IP6NET && ip6net_ok(*token))) {
				paramlen += sprintf(paramlist + paramlen,
						"%s ", *token);
			}
			token++;
		} else {
			p = &end;
		}
	}

	if (extra && p == &end && *token == 0) {
		if (is_parameter(lastok) ||
			strlen(lastok->word) == strlen(lasttoken)) {
			sendstr(conn, "\r\n <cr>");
			sendcrlf(conn);
			sendstr(conn, line);
		} else {
			addchars(conn, lastok->word + strlen(lasttoken));
			addchars(conn, " ");
			sendstr(conn, lastok->word + strlen(lasttoken));
			sendstr(conn, " ");
		}
		return;
	}

	if (lastok && lastok->func && extra == 0) {
		lastok->func(conn, paramlist);
		return;
	}

	if (extra == '?') {
		print_q(conn, horpos, lastok);
		sendstr(conn, line);
		return;
	}

	if (extra == '\t') {
		struct cli_node *found = 0;

		if (*token == NULL) {
			addchars(conn, lastok->word + strlen(lasttoken));
			addchars(conn, " ");
			sendstr(conn, lastok->word + strlen(lasttoken));
			sendstr(conn, " ");
			return;
		}

		found = find_next_vertical(horpos, *token);

		if (found) {
			addchars(conn, found->word + strlen(*token));
			addchars(conn, " ");
			sendstr(conn, found->word + strlen(*token));
			sendstr(conn, " ");
			return;
		}

		print_q(conn, horpos, lastok);
		sendstr(conn, line);
		return;
	}

	sendstr(conn, "syntax error\r\n");
	sendcrlf(conn);
	return;
}

static char telnet_echo_off[] = {
	0xff, 0xfb, 0x01, /* IAC WILL ECHO */
	0xff, 0xfb, 0x03, /* IAC WILL SUPPRESS_GO_AHEAD */
	0xff, 0xfd, 0x03, /* IAC DO SUPPRESS_GO_AHEAD */
};

static void addchars(struct cli_conn *conn, const char *s)
{
	strcat(conn->inbuf, s);
	conn->pos += strlen(s);
}


static int cli_read(int fd)
{
	struct cli_conn *conn = &connection;
	unsigned char c;

	//receive data from client
	if (recv(fd, &c, 1, 0) <= 0) {
		OFP_ERR("Failed to recive data on socket: %s", strerror(errno));
		close_connection(conn);
		return -1;
	}

	if (conn->status & WAITING_PASSWD) {
		unsigned int plen = strlen(conn->passwd);
		if (c == 10 || c == 13) {
			conn->status &= ~WAITING_PASSWD;
			if (authenticate("admin", conn->passwd)) {
				conn->status |= ENABLED_OK;
				sendcrlf(conn);
			} else {
				sendstr(conn, "Your password fails!");
				sendcrlf(conn);
			}
		} else if (plen < (sizeof(conn->passwd)-1)) {
			conn->passwd[plen] = c;
			conn->passwd[plen+1] = 0;
		}
		return 0;
	} else if (conn->status & WAITING_TELNET_1) {
		conn->ch1 = c;
		conn->status &= ~WAITING_TELNET_1;
		conn->status |= WAITING_TELNET_2;
		return 0;
	} else if (conn->status & WAITING_TELNET_2) {
	static int num_dsp_chars = 0;
	static char dsp_chars[8];

	if (num_dsp_chars) {
		dsp_chars[6 - num_dsp_chars--] = c;
		if (num_dsp_chars == 0) {
			conn->status &= ~WAITING_TELNET_2;
			cli_display_width = dsp_chars[1];
			cli_display_height = dsp_chars[3];
		}
		return 0;
	}

	if      (conn->ch1 == 0xfd && c == 0x01) conn->status |= DO_ECHO;
	else if (conn->ch1 == 0xfd && c == 0x03) conn->status |= DO_SUPPRESS;
	else if (conn->ch1 == 0xfb && c == 0x03) {
		conn->status |= WILL_SUPPRESS;
		// ask for display size
		char com[] = {255, 253, 31};
		send(fd, com, sizeof(com), 0);
	} else if (conn->ch1 == (unsigned char)0x251 && c == 31) {
		// IAC WILL NAWS (display size)
	} else if (conn->ch1 == 250 && c == 31) {  // (display size info)
		num_dsp_chars = 6;
		return 0;
	}
	conn->status &= ~WAITING_TELNET_2;
		return 0;
	} else if (conn->status & WAITING_ESC_1) {
		conn->ch1 = c;
		conn->status &= ~WAITING_ESC_1;
		conn->status |= WAITING_ESC_2;
		return 0;
	} else if (conn->status & WAITING_ESC_2) {
		conn->status &= ~WAITING_ESC_2;
		if (conn->ch1 != 0x5b)
			return 0;

		switch (c) {
		case 0x41: // up
			c = 0x10; /* arrow up = ctl-P */
			break;
		case 0x42: // down
			c = 0x0e; /* arrow down = ctl-N */
			break;
		case 0x44: // left
			c = 8;    /* arrow left = backspace */
			break;
		case 0x31: // home
			cli_curses = !cli_curses;
			return 0;
		case 0x32: // ins
		case 0x33: // delete
		case 0x34: // end
		case 0x35: // pgup
		case 0x36: // pgdn
		case 0x43: // right
		case 0x45: // 5
			return 0;
		}
	}

	if (c == 4) { /* ctl-D */
		close_connection(conn);
		return 0;
	} else if (c == 0x10 || c == 0x0e) { /* ctl-P or ctl-N */
		strcpy(conn->inbuf, conn->oldbuf[conn->old_get_cnt]);
		if (c == 0x10) {
			conn->old_get_cnt--;
			if (conn->old_get_cnt < 0)
				conn->old_get_cnt = NUM_OLD_BUFS - 1;
		} else {
			conn->old_get_cnt++;
			if (conn->old_get_cnt >= NUM_OLD_BUFS)
				conn->old_get_cnt = 0;
		}
		conn->pos = strlen(conn->inbuf);
		sendstr(conn, "\r                                                                   ");
		sendprompt(conn);
		sendstr(conn, conn->inbuf);
	} else if (c == 0x1b) {
		conn->status |= WAITING_ESC_1;
	} else if (c == 0xff) {
		/* telnet commands */
		conn->status |= WAITING_TELNET_1;
		/*
		  unsigned char c1, c2;
		  recv(conn->fd, &c1, 1, 0);
		  recv(conn->fd, &c2, 1, 0);
		  if      (c1 == 0xfd && c2 == 0x01) conn->status |= DO_ECHO;
		  else if (c1 == 0xfd && c2 == 0x03) conn->status |= DO_SUPPRESS;
		  else if (c1 == 0xfb && c2 == 0x03) conn->status |= WILL_SUPPRESS;
		*/
	} else if (c == 13 || c == 10) {
	char nl[] = {13, 10};
	if (conn->status & DO_ECHO)
		send(fd, nl, sizeof(nl), 0);
	conn->inbuf[conn->pos] = 0;
	if (0 && conn->pos == 0) {
		strcpy(conn->inbuf, conn->oldbuf[conn->old_put_cnt]);
		conn->pos = strlen(conn->inbuf);
		sendstr(conn, conn->inbuf);
		send(fd, nl, sizeof(nl), 0);
	} else if (conn->pos > 0 && strcmp(conn->oldbuf[conn->old_put_cnt], conn->inbuf)) {
		conn->old_put_cnt++;
		if (conn->old_put_cnt >= NUM_OLD_BUFS)
			conn->old_put_cnt = 0;
		strcpy(conn->oldbuf[conn->old_put_cnt], conn->inbuf);
	}

	if (conn->pos) {
		parse(conn, 0);

		if (run_alias >= 0) {
			strcpy(conn->inbuf, alias_table[run_alias].cmd);
			run_alias = -1;
			parse(conn, 0);
		}
	} else
		sendcrlf(conn);

	conn->pos = 0;
	conn->inbuf[0] = 0;
	conn->old_get_cnt = conn->old_put_cnt;
	} else if (c == 8 || c == 127) {
		if (conn->pos > 0) {
			char bs[] = {8, ' ', 8};
			if (conn->status & DO_ECHO)
				send(fd, bs, sizeof(bs), 0);
			conn->pos--;
			conn->inbuf[conn->pos] = 0;
		}
	} else if (c == '?' || c == '\t') {
		parse(conn, c);
	} else if (c >= ' ' && c < 127) {
		if (conn->pos < (sizeof(conn->inbuf) - 1)) {
			conn->inbuf[conn->pos++] = c;
			conn->inbuf[conn->pos] = 0;

			if (conn->status & DO_ECHO)
				send(fd, &c, 1, 0);
		}
	}

	return 0;
}

static void cli_sa_accept(int fd)
{
	struct cli_conn *conn;

	conn = &connection;
	bzero(conn, sizeof(*conn));
	conn->fd = fd;
	send(fd, telnet_echo_off, sizeof(telnet_echo_off), 0);

	OFP_DBG("new sock %d opened\r\n", conn->fd);
}

#define OFP_SERVER_PORT 2345

static int cli_serv_fd = -1, cli_tmp_fd = -1;

/** CLI server thread
 *
 * @param arg void*
 * @return void*
 *
 */
static int cli_server(void *arg)
{
	int alen;
	struct sockaddr_in my_addr, caller;
	int reuse = 1;
	fd_set read_fd, fds;
	char *file_name;
	struct ofp_global_config_mem *ofp_global_cfg = NULL;
	int select_nfds;

	close_cli = 0;

	file_name = (char *)arg;

	OFP_INFO("CLI server started on core %i\n", odp_cpu_id());

	if (ofp_init_local()) {
		OFP_ERR("Error: OFP local init failed.\n");
		return -1;
	}

	ofp_global_cfg = ofp_get_global_config();
	if (!ofp_global_cfg) {
		OFP_ERR("Error: Failed to retrieve global configuration.");
		ofp_term_local();
		return -1;
	}

	cli_init_commands();

	cli_process_file(file_name);

	cli_serv_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (cli_serv_fd < 0) {
		OFP_ERR("cli serv socket\n");
		ofp_term_local();
		return -1;
	}

	if (setsockopt(cli_serv_fd, SOL_SOCKET,
		   SO_REUSEADDR, (void *)&reuse, sizeof(reuse)) < 0)
		OFP_ERR("cli setsockopt (SO_REUSEADDR)\n");

	memset(&my_addr, 0, sizeof(my_addr));
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = odp_cpu_to_be_16(OFP_SERVER_PORT);
	my_addr.sin_addr.s_addr = odp_cpu_to_be_32(INADDR_ANY);

	if (bind(cli_serv_fd, (struct sockaddr *)&my_addr,
		 sizeof(struct sockaddr)) < 0) {
		OFP_ERR("serv bind\n");
		ofp_term_local();
		return -1;
	}

	listen(cli_serv_fd, 1);

	FD_ZERO(&read_fd);
	FD_SET(cli_serv_fd, &read_fd);

	while (ofp_global_cfg->is_running) {
		struct timeval timeout;
		int r;

		fds = read_fd;
		select_nfds = cli_serv_fd + 1;

		if (cli_tmp_fd > 0) {
			FD_SET(cli_tmp_fd, &fds);
			if (cli_tmp_fd > select_nfds - 1)
				select_nfds = cli_tmp_fd + 1;
		}

		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		r = select(select_nfds, &fds, NULL, NULL, &timeout);

		if (close_cli) {
			if (cli_tmp_fd > 0)
				close(cli_tmp_fd);
			cli_tmp_fd = -1;
			close_cli = 0;
			OFP_DBG("CLI connection closed\r\n");
		}

		if (r < 0)
			continue;

		if (FD_ISSET(cli_serv_fd, &fds)) {
			close_cli = 0;

			if (cli_tmp_fd > 0)
				close(cli_tmp_fd);

			alen = sizeof(caller);
			cli_tmp_fd = accept(cli_serv_fd,
					(struct sockaddr *)&caller,
					(socklen_t *)&alen);
			if (cli_tmp_fd < 0) {
				OFP_ERR("cli serv accept");
				continue;
			}
			cli_sa_accept(cli_tmp_fd);
			cli_send_welcome_banner(cli_tmp_fd);
			OFP_DBG("CLI connection established\r\n");
		}

	if (cli_tmp_fd > 0 && FD_ISSET(cli_tmp_fd, &fds)) {
			if (cli_read(cli_tmp_fd)) {
				close(cli_tmp_fd);
				cli_tmp_fd = -1;
				OFP_DBG("CLI connection closed\r\n");
			}
		}
	} /* while () */

	if (cli_tmp_fd > 0)
		close(cli_tmp_fd);
	cli_tmp_fd = -1;

	close(cli_serv_fd);
	cli_serv_fd = -1;

	OFP_DBG("CLI server exiting");
	ofp_term_local();
	return 0;
}

int ofp_start_cli_thread(odp_instance_t instance, int core_id, char *cli_file)
{
	odp_cpumask_t cpumask;
	struct ofp_global_config_mem *ofp_global_cfg;
	odph_odpthread_params_t thr_params;

	ofp_global_cfg = ofp_get_global_config();
	if (!ofp_global_cfg) {
		OFP_ERR("Error: Failed to retrieve global configuration.");
		return -1;
	}
	if (ofp_global_cfg->cli_thread_is_running) {
		OFP_ERR("Error: CLI thread is running.");
		return -1;
	}
	odp_cpumask_zero(&cpumask);
	odp_cpumask_set(&cpumask, core_id);

	thr_params.start = cli_server;
	thr_params.arg = cli_file;
	thr_params.thr_type = ODP_THREAD_CONTROL;
	thr_params.instance = instance;

	if (odph_odpthreads_create(&ofp_global_cfg->cli_thread,
				   &cpumask,
				   &thr_params) == 0) {
		OFP_ERR("Failed to start CLI thread.");
		ofp_global_cfg->cli_thread_is_running = 0;
		return -1;
	}
	ofp_global_cfg->cli_thread_is_running = 1;

	return 0;
}

int ofp_stop_cli_thread(void)
{
	struct ofp_global_config_mem *ofp_global_cfg;

	ofp_global_cfg = ofp_get_global_config();
	if (!ofp_global_cfg) {
		OFP_ERR("Error: Failed to retrieve global configuration.");
		return -1;
	}

	if (ofp_global_cfg->cli_thread_is_running) {
		close_connection(NULL);
		odph_odpthreads_join(&ofp_global_cfg->cli_thread);
		ofp_global_cfg->cli_thread_is_running = 0;
	}

	return 0;
}

#else

int ofp_start_cli_thread(odp_instance_t instance, int core_id, char *cli_file)
{
	(void) instance;
	(void) core_id;
	(void) cli_file;

	return OFP_ENOTSUP;
}
int ofp_stop_cli_thread(void)
{
	return OFP_ENOTSUP;
}

#endif


/*end*/
