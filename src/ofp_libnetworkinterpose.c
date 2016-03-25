#ifndef RTLD_NEXT
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "ofp.h"

static int (*libc_socket)(int, int, int);
static int (*libc_bind)(int, const struct sockaddr*, socklen_t);
static int (*libc_accept)(int, struct sockaddr*, socklen_t*);
static int (*libc_connect)(int, const struct sockaddr*, socklen_t);
static int (*libc_listen)(int, int);
static int (*libc_shutdown)(int, int);
static int (*libc_setsockopt)(int, int, int, const void*, socklen_t);
static ssize_t (*libc_read)(int, void*, size_t);
static ssize_t (*libc_recv)(int, void*, size_t, int);
static ssize_t (*libc_write)(int, void*, size_t);
static ssize_t (*libc_send)(int, const void*, size_t, int);

int socket(int domain, int type, int protocol);
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int listen(int sockfd, int backlog);
int shutdown(int sockfd, int how);
int setsockopt(int sockfd, int level, int opt_name,
	const void *opt_val, socklen_t opt_len);
ssize_t read(int sockfd, void *buf, size_t len);
ssize_t recv(int sockfd, void *buf, size_t len, int flags);
ssize_t write(int sockfd, void *buf, size_t len);
ssize_t send(int sockfd, const void *buf, size_t len, int flags);

static int ofp_libc_init(void)
{
#define LIBC_FUNCTION(func) \
	libc_##func = dlsym(RTLD_NEXT, #func);\
	if(dlerror()) { \
		errno = EACCES; \
		return EXIT_FAILURE; \
	}

	LIBC_FUNCTION(socket);
	LIBC_FUNCTION(bind);
	LIBC_FUNCTION(accept);
	LIBC_FUNCTION(connect);
	LIBC_FUNCTION(listen);
	LIBC_FUNCTION(shutdown);
	LIBC_FUNCTION(setsockopt);
	LIBC_FUNCTION(read);
	LIBC_FUNCTION(recv);
	LIBC_FUNCTION(write);
	LIBC_FUNCTION(send);

	return EXIT_SUCCESS;
}

int socket(int domain, int type, int protocol)
{
	int sockfd = -1, ret_val;
	static int init_socket = 0;

	switch (init_socket) {
	case 0:
		init_socket++; /* = 1 */

		ret_val = ofp_libc_init();
		if (ret_val == EXIT_FAILURE)
			return sockfd;
	case 1:
		sockfd = (*libc_socket)(domain, type, protocol);
		break;
	}

	OFP_DBG("Created socket '%d' with domain:%d, type:%d, protocol:%d.",
		sockfd, domain, type, protocol);

	return sockfd;
}


int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	int bind_value = -1;

	if (sockfd < OFP_SOCK_NUM_OFFSET) {
		bind_value = (*libc_bind)(sockfd, addr, addrlen);
	} else if (addr->sa_family == AF_INET) {
		struct ofp_sockaddr_in ofp_addr;

		bzero((char *) &ofp_addr, sizeof(ofp_addr));
		ofp_addr.sin_family = AF_INET;
		ofp_addr.sin_addr.s_addr =
			((const struct sockaddr_in *)addr)->sin_addr.s_addr;
		ofp_addr.sin_port =
			((const struct sockaddr_in *)addr)->sin_port;
		ofp_addr.sin_len = sizeof(struct ofp_sockaddr_in);

		bind_value = ofp_bind(sockfd,
				(const struct ofp_sockaddr *)&ofp_addr,
				addrlen);
	}

	OFP_DBG("Binding socket '%d' to the address '%x:%d' returns:%d",
		sockfd,	((const struct sockaddr_in *)addr)->sin_addr.s_addr,
		ntohs(((const struct sockaddr_in *)addr)->sin_port),
		bind_value);

	return bind_value;
}


int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	int accept_value = -1;

	if (sockfd < OFP_SOCK_NUM_OFFSET)
		accept_value = (*libc_accept)(sockfd, addr, addrlen);
	else
		accept_value = ofp_accept(sockfd,
			(struct ofp_sockaddr *)addr, addrlen);

	OFP_DBG("Accepting socket '%d' to the address '%x:%d' returns:'%d'",
		sockfd, ((struct sockaddr_in *)addr)->sin_addr.s_addr,
		ntohs(((struct sockaddr_in *)addr)->sin_port), accept_value);

	return accept_value;
}



int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	int connect_value;

	if (sockfd < OFP_SOCK_NUM_OFFSET)
		connect_value = (*libc_connect)(sockfd, addr, addrlen);
	else
		connect_value = ofp_connect(sockfd,
			(const struct ofp_sockaddr *)addr,
			addrlen);

	OFP_DBG("Connecting socket '%d' to the address '%x:%d' returns:'%d'",
		sockfd, ((const struct sockaddr_in *)addr)->sin_addr.s_addr,
		ntohs(((const struct sockaddr_in *)addr)->sin_port),
		connect_value);

	return connect_value;
}


int listen(int sockfd, int backlog)
{
	int listen_value;

	if (sockfd < OFP_SOCK_NUM_OFFSET)
		listen_value = (*libc_listen)(sockfd, backlog);
	else
		listen_value = ofp_listen(sockfd, backlog);

	OFP_DBG("Listen called on socket '%d' returns:'%d'",
		sockfd, listen_value);

	return listen_value;
}



int shutdown(int sockfd, int how)
{
	int shutdown_value;

	if (sockfd < OFP_SOCK_NUM_OFFSET)
		shutdown_value = (*libc_shutdown)(sockfd, how);
	else
		shutdown_value = ofp_shutdown(sockfd, how);

	OFP_DBG("Socket '%d' closed with option '%d' returns:'%d'",
		sockfd, how, shutdown_value);

	return shutdown_value;
}



int setsockopt(int sockfd, int level, int opt_name, const void *opt_val,
	socklen_t opt_len)
{
	int setsockopt_value;

	if (sockfd < OFP_SOCK_NUM_OFFSET)
		setsockopt_value = (*libc_setsockopt)(sockfd, level, opt_name,
			opt_val, opt_len);
	else
		setsockopt_value = ofp_setsockopt(sockfd, level, opt_name,
			opt_val, opt_len);

	OFP_DBG("Setsockopt on sock:'%d',level:'%d',opt_name:'%d'",
		sockfd, level, opt_name);

	return setsockopt_value;
}


ssize_t read(int sockfd, void *buf, size_t len)
{
	ssize_t read_value;

	if (sockfd < OFP_SOCK_NUM_OFFSET)
		read_value = (*libc_read)(sockfd, buf, len);
	else
		read_value = ofp_recv(sockfd, buf, len, 0);

	OFP_DBG("Read called on socket '%d'", sockfd);

	return read_value;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
	ssize_t recv_value;

	if (sockfd < OFP_SOCK_NUM_OFFSET)
		recv_value = (*libc_recv)(sockfd, buf, len, flags);
	else
		recv_value = ofp_recv(sockfd, buf, len, flags);

	OFP_DBG("Recv called on socket '%d'", sockfd);

	return recv_value;
}


ssize_t write(int sockfd, void *buf, size_t len)
{
	ssize_t write_value;

	if (sockfd < OFP_SOCK_NUM_OFFSET)
		write_value = (*libc_write)(sockfd, buf, len);
	else
		write_value = ofp_send(sockfd, buf, len, 0);

	OFP_DBG("Write called on socket '%d'", sockfd);

	return write_value;
}


ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
	ssize_t send_value;

	if (sockfd < OFP_SOCK_NUM_OFFSET)
		send_value = (*libc_send)(sockfd, buf, len, flags);
	else
		send_value = ofp_send(sockfd, buf, len, flags);

	OFP_DBG("Send called on socket '%d'", sockfd);

	return send_value;
}
