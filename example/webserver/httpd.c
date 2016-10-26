#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#include "ofp.h"
#include "httpd.h"

int sigreceived = 0;
static uint32_t myaddr;

/* Table of concurrent connections */
#define NUM_CONNECTIONS 16
static struct {
	int fd;
	uint32_t addr;
	int closed;
	FILE *post;
} connections[NUM_CONNECTIONS];

/* Sending function with some debugging. */
static int mysend(int s, char *p, int len)
{
	int n;

	while (len > 0) {
		n = ofp_send(s, p, len, 0);
		if (n < 0) {
			OFP_ERR("ofp_send failed n=%d, err='%s'",
				  n, ofp_strerror(ofp_errno));
			return n;
		}
		len -= n;
		p += n;
		if (len) {
			OFP_WARN("Only %d bytes sent", n);
		}
	}
	return len;
}

static int sendf(int fd, const char *fmt, ...)
{
	char buf[1024];
	int ret;
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	ret = mysend(fd, buf, n);
	return ret;
}

/* Send one file. */
static void get_file(int s, char *url)
{
	/* Set www_dir to point to your web directory. */
	char *www_dir = NULL;
	char bufo[512];
	int n, w;

	const char *mime = NULL;
	const char *p = url + 1;

	if (*p == 0)
		p = "index.html";

	char *p2 = strrchr(p, '.');
	if (p2) {
		p2++;
		if (!strcmp(p2, "html")) mime = "text/html";
		else if (!strcmp(p2, "htm")) mime = "text/html";
		else if (!strcmp(p2, "css")) mime = "text/css";
		else if (!strcmp(p2, "txt")) mime = "text/plain";
		else if (!strcmp(p2, "png")) mime = "image/png";
		else if (!strcmp(p2, "jpg")) mime = "image/jpg";
		else if (!strcmp(p2, "class")) mime = "application/x-java-applet";
		else if (!strcmp(p2, "jar")) mime = "application/java-archive";
		else if (!strcmp(p2, "pdf")) mime = "application/pdf";
		else if (!strcmp(p2, "swf")) mime = "application/x-shockwave-flash";
		else if (!strcmp(p2, "ico")) mime = "image/vnd.microsoft.icon";
		else if (!strcmp(p2, "js")) mime = "text/javascript";
	}

	www_dir = getenv("www_dir");

	snprintf(bufo, sizeof(bufo), "%s/%s", www_dir, p);
	FILE *f = fopen(bufo, "rb");

	if (!f) {
		sendf(s, "HTTP/1.0 404 NOK\r\n\r\n");
		return;
	}

	sendf(s, "HTTP/1.0 200 OK\r\n");
	if (mime)
		sendf(s, "Content-Type: %s\r\n\r\n", mime);
	else
		sendf(s, "\r\n");

	while ((n = fread(bufo, 1, sizeof(bufo), f)) > 0)
		if ((w = mysend(s, bufo, n)) < 0)
			break;
	fclose(f);
}

static int analyze_http(char *http, int s) {
	char *url;

	if (!strncmp(http, "GET ", 4)) {
		url = http + 4;
		while (*url == ' ')
			url++;
		char *p = strchr(url, ' ');
		if (p)
			*p = 0;
		else
			return -1;
		OFP_INFO("GET %s (fd=%d)", url, s);
		get_file(s, url);
	} else if (!strncmp(http, "POST ", 5)) {
		/* Post is not supported. */
		OFP_INFO("%s", http);
	}

	return 0;
}

#ifndef USE_EPOLL
static void monitor_connections(ofp_fd_set *fd_set)
{
	int i;

	for (i = 0; i < NUM_CONNECTIONS; ++i)
		if (connections[i].fd)
			OFP_FD_SET(connections[i].fd, fd_set);
}
#endif

static inline int accept_connection(int serv_fd)
{
	int tmp_fd, i;
	struct ofp_sockaddr_in caller;
	unsigned int alen = sizeof(caller);

	if ((tmp_fd = ofp_accept(serv_fd, (struct ofp_sockaddr *)&caller, &alen)) > 0) {
		OFP_INFO("accept fd=%d", tmp_fd);

		for (i = 0; i < NUM_CONNECTIONS; i++)
			if (connections[i].fd == 0)
				break;

		if (i >= NUM_CONNECTIONS) {
			OFP_ERR("Node cannot accept new connections!");
			ofp_close(tmp_fd);
			return -1;
		}

#if 0
		struct ofp_linger so_linger;
		so_linger.l_onoff = 1;
		so_linger.l_linger = 0;
		int r1 = ofp_setsockopt(tmp_fd,
					  OFP_SOL_SOCKET,
					  OFP_SO_LINGER,
					  &so_linger,
					  sizeof so_linger);
		if (r1) OFP_ERR("SO_LINGER failed!");
#endif
		struct ofp_timeval tv;
		tv.tv_sec = 3;
		tv.tv_usec = 0;
		int r2 = ofp_setsockopt(tmp_fd,
					  OFP_SOL_SOCKET,
					  OFP_SO_SNDTIMEO,
					  &tv,
					  sizeof tv);
		if (r2) OFP_ERR("SO_SNDTIMEO failed!");

		connections[i].fd = tmp_fd;
		connections[i].addr = caller.sin_addr.s_addr;
		connections[i].closed = FALSE;
	}

	return tmp_fd;
}

static int handle_connection(int i)
{
	int fd, r;
	static char buf[1024];

	if (connections[i].fd == 0)
		return 0;

	fd = connections[i].fd;
	r = ofp_recv(connections[i].fd, buf, sizeof(buf)-1, 0);

	if (r < 0)
		return 0;

	if (r > 0) {
		buf[r] = 0;
		OFP_INFO("recv data: %s", buf);

		if (!strncmp(buf, "GET", 3))
			analyze_http(buf, connections[i].fd);
		else
			OFP_INFO("Not an HTTP GET request");

		OFP_INFO("closing %d\n", connections[i].fd);

		while (ofp_close(connections[i].fd) < 0) {
			OFP_ERR("ofp_close failed, fd=%d err='%s'",
				connections[i].fd,
				ofp_strerror(ofp_errno));
			sleep(1);
		}
		OFP_INFO("closed fd=%d", connections[i].fd);
		connections[i].fd = 0;
	} else if (r == 0) {
		if (connections[i].post) {
			OFP_INFO("File download finished");
			fclose(connections[i].post);
			connections[i].post = NULL;
		}
		ofp_close(connections[i].fd);
		connections[i].fd = 0;
	}

	return fd;
}

static void *webserver(void *arg)
{
	int serv_fd, tmp_fd;
	struct ofp_sockaddr_in my_addr;

	(void)arg;

	OFP_INFO("HTTP thread started");

	if (ofp_init_local()) {
		OFP_ERR("Error: OFP local init failed.\n");
		return NULL;
	}
	sleep(1);

	myaddr = ofp_port_get_ipv4_addr(0, 0, OFP_PORTCONF_IP_TYPE_IP_ADDR);

	if ((serv_fd = ofp_socket(OFP_AF_INET, OFP_SOCK_STREAM, OFP_IPPROTO_TCP)) < 0) {
		OFP_ERR("ofp_socket failed");
		perror("serv socket");
		return NULL;
	}

	memset(&my_addr, 0, sizeof(my_addr));
	my_addr.sin_family = OFP_AF_INET;
	my_addr.sin_port = odp_cpu_to_be_16(2048);
	my_addr.sin_addr.s_addr = myaddr;
	my_addr.sin_len = sizeof(my_addr);

	if (ofp_bind(serv_fd, (struct ofp_sockaddr *)&my_addr,
		       sizeof(struct ofp_sockaddr)) < 0) {
		OFP_ERR("Cannot bind http socket (%s)!", ofp_strerror(ofp_errno));
		return 0;
	}

	ofp_listen(serv_fd, 10);

#ifndef USE_EPOLL
	OFP_INFO("Using ofp_select");
	ofp_fd_set read_fd;
	OFP_FD_ZERO(&read_fd);
	int nfds = serv_fd;
#else
	OFP_INFO("Using ofp_epoll");
	int epfd = ofp_epoll_create(1);
	struct ofp_epoll_event e = { OFP_EPOLLIN, { .fd = serv_fd } };
	ofp_epoll_ctl(epfd, OFP_EPOLL_CTL_ADD, serv_fd, &e);
#endif

	for ( ; ; )
	{
#ifndef USE_EPOLL
		int r, i;
		struct ofp_timeval timeout;

		timeout.tv_sec = 0;
		timeout.tv_usec = 200000;

		OFP_FD_SET(serv_fd, &read_fd);
		monitor_connections(&read_fd);
		r = ofp_select(nfds + 1, &read_fd, NULL, NULL, &timeout);

		if (r <= 0)
			continue;

		if (OFP_FD_ISSET(serv_fd, &read_fd))
			if ((tmp_fd = accept_connection(serv_fd)) > nfds)
				nfds = tmp_fd;

		for (i = 0; i < NUM_CONNECTIONS; i++)
			if (OFP_FD_ISSET(connections[i].fd, &read_fd) &&
			   (tmp_fd = handle_connection(i)))
				OFP_FD_CLR(tmp_fd, &read_fd);
#else
		int r, i;
		struct ofp_epoll_event events[10];

		r = ofp_epoll_wait(epfd, events, 10, 200);

		for (i = 0; i < r; ++i) {
			if (events[i].data.fd == serv_fd) {
				tmp_fd = accept_connection(serv_fd);
				struct ofp_epoll_event e = { OFP_EPOLLIN, { .u32 = i } };
				ofp_epoll_ctl(epfd, OFP_EPOLL_CTL_ADD, tmp_fd, &e);
			}
			else if ((tmp_fd = handle_connection(events[i].data.u32)))
				ofp_epoll_ctl(epfd, OFP_EPOLL_CTL_DEL, tmp_fd, NULL);
		}
#endif
	}

	OFP_INFO("httpd exiting");
	return NULL;
}

void ofp_start_webserver_thread(odp_instance_t instance, int core_id)
{
	static odph_linux_pthread_t test_linux_webserver_pthread;
	odp_cpumask_t cpumask;
	odph_linux_thr_params_t thr_params;

	odp_cpumask_zero(&cpumask);
	odp_cpumask_set(&cpumask, core_id);

	thr_params.start = webserver;
	thr_params.arg = NULL;
	thr_params.thr_type = ODP_THREAD_CONTROL;
	thr_params.instance = instance;
	odph_linux_pthread_create(&test_linux_webserver_pthread,
				  &cpumask,
				  &thr_params);
}
