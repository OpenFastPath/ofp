#include "ofpi_cli.h"
#include "ofpi_socketvar.h"
#include "ofpi_tcp_var.h"
#include "ofpi_udp_var.h"

/* "netstat" */
void f_netstat_all(struct cli_conn *conn, const char *s)
{
	(void)s;

	ofp_tcp_netstat(conn->fd);
	ofp_udp_netstat(conn->fd);

	sendcrlf(conn);
}

/* "netstat -t" */
void f_netstat_tcp(struct cli_conn *conn, const char *s)
{
	(void)s;

	ofp_tcp_netstat(conn->fd);

	sendcrlf(conn);
}

/* "netstat -u" */
void f_netstat_udp(struct cli_conn *conn, const char *s)
{
	(void)s;

	ofp_udp_netstat(conn->fd);

	sendcrlf(conn);
}

/* "help netstat" */
void f_help_netstat(struct cli_conn *conn, const char *s)
{
	(void)s;
	ofp_sendf(conn->fd,
		"Show all open ports:\r\n"
		"  netstat\r\n\r\n");

	ofp_sendf(conn->fd,
		"Show TCP open ports:\r\n"
		"  netstat -t\r\n\r\n");

	ofp_sendf(conn->fd,
		"Show UDP open ports:\r\n"
		"  netstat -u\r\n\r\n");

	ofp_sendf(conn->fd,
		"Show (this) help:\r\n"
		"  netstat help\r\n\r\n");

	sendcrlf(conn);
}
