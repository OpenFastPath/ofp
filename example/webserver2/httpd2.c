#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#include "ofp.h"

#include "httpd.h"

void httpd_main(uint32_t addr);

int sigreceived = 0;
static uint32_t myaddr;

/* Set www_dir to point to your web directory. */
static const char *www_dir = "/home/hjokinen/Dropbox/kolumbus-web";

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

static void notify(union ofp_sigval sv)
{
	struct ofp_sock_sigval *ss = sv.sival_ptr;
	int s = ss->sockfd;
	int event = ss->event;
	odp_packet_t pkt = ss->pkt;
	int r;
	char *buf, *tail;

	if (event == OFP_EVENT_ACCEPT) {
		struct ofp_sockaddr_in caller;
		ofp_socklen_t alen = sizeof(caller);
		/*
		 * ss->sockfd is the original listened socket.
		 * ss->sockfd2 is the new socket that is returned by accept.
		 * We don't need the returned socket, but accept
		 * must be called to set the data structures.
		 */
		int new = ofp_accept(ss->sockfd,
				       (struct ofp_sockaddr *)&caller,
				       &alen);
		(void)new;
		/* new == ss->sockfd2 */
		return;
	}

	if (event != OFP_EVENT_RECV)
		return;

	r = odp_packet_len(pkt);

	if (r > 0) {
		buf = odp_packet_data(pkt);
		/* Add 0 to the end */
		tail = odp_packet_push_tail(pkt, 1);
		*tail = 0;

		analyze_http(buf, s);

		if (ofp_close(s) < 0)
			OFP_ERR("ofp_close failed fd=%d err='%s'",
				s, ofp_strerror(ofp_errno));
	} else if (r == 0) {
		ofp_close(s);
	}

	odp_packet_free(pkt);
	/*
	 * Mark ss->pkt invalid to indicate it was released by us.
	 */
	ss->pkt = ODP_PACKET_INVALID;
}

static void *webserver(void *arg)
{
	int serv_fd;
	struct ofp_sockaddr_in my_addr;
	ofp_fd_set read_fd;

	(void)arg;

	OFP_INFO("HTTP thread started");

	if (odp_init_local(ODP_THREAD_CONTROL)) {
		OFP_ERR("Error: ODP local init failed.\n");
		return NULL;
	}
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
		OFP_ERR("ofp_bind failed, err='%s'", ofp_strerror(ofp_errno));
		return 0;
	}

	ofp_listen(serv_fd, 10);

	struct ofp_sigevent ev;
	struct ofp_sock_sigval ss;
	ss.sockfd = serv_fd;
	ss.event = 0;
	ss.pkt = ODP_PACKET_INVALID;
	ev.ofp_sigev_notify = 1;
	ev.ofp_sigev_notify_function = notify;
	ev.ofp_sigev_value.sival_ptr = &ss;
	ofp_socket_sigevent(&ev);

	OFP_FD_ZERO(&read_fd);
	OFP_FD_SET(serv_fd, &read_fd);

	while (1) {
		sleep(1);
	}

	OFP_INFO("httpd exiting");
	return NULL;
}

void ofp_start_webserver_thread(int core_id)
{
	odph_linux_pthread_t test_linux_pthread;
	odp_cpumask_t cpumask;

	odp_cpumask_zero(&cpumask);
	odp_cpumask_set(&cpumask, core_id);

	odph_linux_pthread_create(&test_linux_pthread,
				  &cpumask,
				  webserver,
				  NULL);
}
