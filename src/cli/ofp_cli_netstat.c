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
