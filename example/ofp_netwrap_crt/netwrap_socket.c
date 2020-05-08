/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "netwrap_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include "ofp.h"
#include "netwrap_socket.h"
#include "netwrap_errno.h"

union _ofp_sockaddr_storage {
	struct ofp_sockaddr_in addr_in;
	struct ofp_sockaddr_in6 addr_in6;
};

static int (*libc_socket)(int, int, int);
static int (*libc_shutdown)(int, int);
static int (*libc_close)(int);
static int (*libc_bind)(int, const struct sockaddr*, socklen_t);
static int (*libc_accept)(int, struct sockaddr*, socklen_t*);
static int (*libc_accept4)(int, struct sockaddr*, socklen_t*, int);
static int (*libc_listen)(int, int);
static int (*libc_connect)(int, const struct sockaddr*, socklen_t);
static ssize_t (*libc_read)(int, void*, size_t);
static ssize_t (*libc_write)(int, const void*, size_t);
static ssize_t (*libc_recv)(int, void*, size_t, int);
static ssize_t (*libc_send)(int, const void*, size_t, int);

void setup_socket_wrappers(void)
{
	LIBC_FUNCTION(socket);
	LIBC_FUNCTION(shutdown);
	LIBC_FUNCTION(close);
	LIBC_FUNCTION(bind);
	LIBC_FUNCTION(accept);
	LIBC_FUNCTION(accept4);
	LIBC_FUNCTION(listen);
	LIBC_FUNCTION(connect);
	LIBC_FUNCTION(read);
	LIBC_FUNCTION(write);
	LIBC_FUNCTION(recv);
	LIBC_FUNCTION(send);
}

int socket(int domain, int type, int protocol)
{
	int sockfd = -1;

	if (netwrap_constructor_called) {
		if (domain != AF_INET)
			sockfd = (*libc_socket)(domain, type, protocol);
		else {
			int ofp_domain = OFP_AF_INET;
			int ofp_type, ofp_protocol;

			switch (type) {
			case SOCK_STREAM:
				ofp_type = OFP_SOCK_STREAM;
				break;
			case SOCK_DGRAM:
				ofp_type = OFP_SOCK_DGRAM;
				break;
			default:
				ofp_type = type;
			}

			switch (protocol) {
			case IPPROTO_UDP:
				ofp_protocol = OFP_IPPROTO_UDP;
				break;
			case IPPROTO_TCP:
				ofp_protocol = OFP_IPPROTO_TCP;
				break;
			default:
				ofp_protocol = protocol;
			}

			sockfd = ofp_socket(ofp_domain, ofp_type, ofp_protocol);
			errno = NETWRAP_ERRNO(ofp_errno);
		}
	} else { /* pre init*/
		LIBC_FUNCTION(socket);

		if (libc_socket)
			sockfd = (*libc_socket)(domain, type, protocol);
		else {
			sockfd = -1;
			errno = EACCES;
		}
	}

	/*printf("socket wrapper return: %d\n", sockfd);*/
	return sockfd;
}

int shutdown(int sockfd, int how)
{
	int shutdown_value;

	if (IS_OFP_SOCKET(sockfd)) {
		int ofp_how;

		switch (how) {
		case SHUT_RD:
			ofp_how = OFP_SHUT_RD;
			break;
		case SHUT_WR:
			ofp_how = OFP_SHUT_WR;
			break;
		case SHUT_RDWR:
			ofp_how = OFP_SHUT_RDWR;
			break;
		default:
			ofp_how = how;
		}
		shutdown_value = ofp_shutdown(sockfd, ofp_how);
		errno = NETWRAP_ERRNO(ofp_errno);
	} else if (libc_shutdown) {
		shutdown_value = (*libc_shutdown)(sockfd, how);
	} else {
		LIBC_FUNCTION(shutdown);

		if (libc_shutdown)
			shutdown_value = (*libc_shutdown)(sockfd, how);
		else {
			shutdown_value = -1;
			errno = EACCES;
		}
	}

	return shutdown_value;
}
int close(int sockfd)
{
	int close_value;

	if (IS_OFP_SOCKET(sockfd)) {
		close_value = ofp_close(sockfd);
		errno = NETWRAP_ERRNO(ofp_errno);
	} else if (libc_close)
		close_value = (*libc_close)(sockfd);
	else { /* pre init*/
		LIBC_FUNCTION(close);

		if (libc_close)
			close_value = (*libc_close)(sockfd);
		else {
			close_value = -1;
			errno = EACCES;
		}
	}

	/*printf("Socket '%d' closed returns:'%d'\n",
		sockfd, close_value);*/
	return close_value;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	int bind_value = -1;

	if (IS_OFP_SOCKET(sockfd)) {
		struct ofp_sockaddr_in ofp_addr;
		ofp_socklen_t ofp_addrlen;

		if (!addr) {
			errno = EFAULT;
			return -1;
		}
		if (addrlen != sizeof(struct sockaddr_in)) {
			errno = EINVAL;
			return -1;
		}

		bzero((char *) &ofp_addr, sizeof(ofp_addr));
		ofp_addr.sin_family = OFP_AF_INET;
		ofp_addr.sin_addr.s_addr =
			((const struct sockaddr_in *)addr)->sin_addr.s_addr;
		ofp_addr.sin_port =
			((const struct sockaddr_in *)addr)->sin_port;
		ofp_addr.sin_len = sizeof(struct ofp_sockaddr_in);

		ofp_addrlen = sizeof(ofp_addr);

		bind_value = ofp_bind(sockfd,
				(const struct ofp_sockaddr *)&ofp_addr,
				ofp_addrlen);
		errno = NETWRAP_ERRNO(ofp_errno);
	} else if (libc_bind)
		bind_value = (*libc_bind)(sockfd, addr, addrlen);
	else { /* pre init*/
		LIBC_FUNCTION(bind);

		if (libc_bind)
			bind_value = (*libc_bind)(sockfd, addr, addrlen);
		else {
			bind_value = -1;
			errno = EACCES;
		}
	}

	/*printf("Binding socket '%d' to the address '%x:%d' returns:%d\n",
		sockfd,	((const struct sockaddr_in *)addr)->sin_addr.s_addr,
		odp_be_to_cpu_16(((const struct sockaddr_in *)addr)->sin_port),
		bind_value);*/
	return bind_value;
}


int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	int accept_value = -1;

	if (IS_OFP_SOCKET(sockfd)) {
		union _ofp_sockaddr_storage ofp_addr_local;
		struct ofp_sockaddr *ofp_addr;
		ofp_socklen_t ofp_addrlen_local;
		ofp_socklen_t *ofp_addrlen;

		if (addr) {
			ofp_addr = (struct ofp_sockaddr *)&ofp_addr_local;

			if (!addrlen) {
				errno = EINVAL;
				return -1;
			}
			ofp_addrlen = &ofp_addrlen_local;
			ofp_addrlen_local = sizeof(ofp_addr_local);
		} else {
			ofp_addr = NULL;
			ofp_addrlen = NULL;
		}


		accept_value = ofp_accept(sockfd, ofp_addr, ofp_addrlen);
		errno = NETWRAP_ERRNO(ofp_errno);

		if (accept_value != -1 && addr) {
			switch (ofp_addr->sa_family) {
			case OFP_AF_INET:
			{
				struct sockaddr_in addr_in_tmp;
				struct ofp_sockaddr_in *ofp_addr_in_tmp =
					(struct ofp_sockaddr_in *)ofp_addr;

				addr_in_tmp.sin_family = AF_INET;
				addr_in_tmp.sin_port =
					ofp_addr_in_tmp->sin_port;
				addr_in_tmp.sin_addr.s_addr =
					ofp_addr_in_tmp->sin_addr.s_addr;

				if (*addrlen > sizeof(addr_in_tmp))
					*addrlen = sizeof(addr_in_tmp);

				memcpy(addr, &addr_in_tmp, *addrlen);
				break;
			}
			case OFP_AF_INET6:
			{
				struct sockaddr_in6 addr_in6_tmp;
				struct ofp_sockaddr_in6 *ofp_addr_in6_tmp =
					(struct ofp_sockaddr_in6 *)ofp_addr;

				addr_in6_tmp.sin6_family = AF_INET6;
				addr_in6_tmp.sin6_port =
					ofp_addr_in6_tmp->sin6_port;

				addr_in6_tmp.sin6_flowinfo =
					ofp_addr_in6_tmp->sin6_flowinfo;
				addr_in6_tmp.sin6_scope_id =
					ofp_addr_in6_tmp->sin6_scope_id;
				memcpy((unsigned char *)addr_in6_tmp.sin6_addr.s6_addr,
					(unsigned char *)ofp_addr_in6_tmp->sin6_addr.__u6_addr.__u6_addr16,
					16);

				if (*addrlen > sizeof(addr_in6_tmp))
					*addrlen = sizeof(addr_in6_tmp);

				memcpy(addr, &addr_in6_tmp, *addrlen);
				break;
			}
			default:
				return -1;
			}
		}

	} else if (libc_accept)
		accept_value = (*libc_accept)(sockfd, addr, addrlen);
	else { /* pre init*/
		LIBC_FUNCTION(accept);

		if (libc_accept)
			accept_value = (*libc_accept)(sockfd, addr, addrlen);
		else {
			accept_value = -1;
			errno = EACCES;
		}
	}

	/*printf("Accept called on socket '%d' returned:'%d'\n",
		sockfd, accept_value);*/
	return accept_value;
}

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
	int accept_value = -1;

	if (IS_OFP_SOCKET(sockfd)) {
		union _ofp_sockaddr_storage ofp_addr_local;
		struct ofp_sockaddr *ofp_addr;
		ofp_socklen_t ofp_addrlen_local;
		ofp_socklen_t *ofp_addrlen;

		if (addr) {
			ofp_addr = (struct ofp_sockaddr *)&ofp_addr_local;

			if (!addrlen) {
				errno = EINVAL;
				return -1;
			}
			ofp_addrlen = &ofp_addrlen_local;
			ofp_addrlen_local = sizeof(ofp_addr_local);
		} else {
			ofp_addr = NULL;
			ofp_addrlen = NULL;
		}


		accept_value = ofp_accept(sockfd, ofp_addr, ofp_addrlen);
		errno = NETWRAP_ERRNO(ofp_errno);

		if (accept_value != -1 && addr) {
			switch (ofp_addr->sa_family) {
			case OFP_AF_INET:
			{
				struct sockaddr_in addr_in_tmp;
				struct ofp_sockaddr_in *ofp_addr_in_tmp =
					(struct ofp_sockaddr_in *)ofp_addr;

				addr_in_tmp.sin_family = AF_INET;
				addr_in_tmp.sin_port =
					ofp_addr_in_tmp->sin_port;
				addr_in_tmp.sin_addr.s_addr =
					ofp_addr_in_tmp->sin_addr.s_addr;

				if (*addrlen > sizeof(addr_in_tmp))
					*addrlen = sizeof(addr_in_tmp);

				memcpy(addr, &addr_in_tmp, *addrlen);
				break;
			}
			case OFP_AF_INET6:
			{
				struct sockaddr_in6 addr_in6_tmp;
				struct ofp_sockaddr_in6 *ofp_addr_in6_tmp =
					(struct ofp_sockaddr_in6 *)ofp_addr;

				addr_in6_tmp.sin6_family = AF_INET6;
				addr_in6_tmp.sin6_port =
					ofp_addr_in6_tmp->sin6_port;

				addr_in6_tmp.sin6_flowinfo =
					ofp_addr_in6_tmp->sin6_flowinfo;
				addr_in6_tmp.sin6_scope_id =
					ofp_addr_in6_tmp->sin6_scope_id;
				memcpy((unsigned char *)addr_in6_tmp.sin6_addr.s6_addr,
					(unsigned char *)ofp_addr_in6_tmp->sin6_addr.__u6_addr.__u6_addr16,
					16);

				if (*addrlen > sizeof(addr_in6_tmp))
					*addrlen = sizeof(addr_in6_tmp);

				memcpy(addr, &addr_in6_tmp, *addrlen);
				break;
			}
			default:
				return -1;
			}
		}

		if ((accept_value != -1) && (flags & SOCK_NONBLOCK)) {
			int p = 1;

			if (ofp_ioctl(accept_value, OFP_FIONBIO, &p)) {
				errno = NETWRAP_ERRNO(ofp_errno);
				ofp_close(accept_value);
				accept_value = -1;
			}
		}
	} else if (libc_accept4)
		accept_value = (*libc_accept4)(sockfd, addr, addrlen, flags);
	else { /* pre init*/
		LIBC_FUNCTION(accept4);

		if (libc_accept4)
			accept_value = (*libc_accept4)(sockfd, addr,
					addrlen, flags);
		else {
			accept_value = -1;
			errno = EACCES;
		}
	}

	/*printf("Accept4 called on socket '%d' returned:'%d'\n",
		sockfd, accept_value);*/
	return accept_value;
}

int listen(int sockfd, int backlog)
{
	int listen_value = -1;

	if (IS_OFP_SOCKET(sockfd)) {
		listen_value = ofp_listen(sockfd, backlog);
		errno = NETWRAP_ERRNO(ofp_errno);
	} else if (libc_listen)
		listen_value = (*libc_listen)(sockfd, backlog);
	else { /* pre init*/
		LIBC_FUNCTION(listen);

		if (libc_listen)
			listen_value = (*libc_listen)(sockfd, backlog);
		else {
			listen_value = -1;
			errno = EACCES;
		}
	}

	/*printf("Listen called on socket '%d' returns:'%d'\n",
		sockfd, listen_value);*/
	return listen_value;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	int connect_value;

	if (IS_OFP_SOCKET(sockfd)) {
		union _ofp_sockaddr_storage ofp_addr_local;
		struct ofp_sockaddr *ofp_addr;
		ofp_socklen_t ofp_addrlen;

		if (!addr || addrlen < sizeof(short)) {
			errno = EINVAL;
			return -1;
		}

		ofp_addr = (struct ofp_sockaddr *)&ofp_addr_local;

		switch (addr->sa_family) {
		case AF_INET:
		{
			const struct sockaddr_in *addr_in_tmp;
			struct ofp_sockaddr_in *ofp_addr_in_tmp;

			if (addrlen < sizeof(struct sockaddr_in)) {
				errno = EINVAL;
				return -1;
			}
			addr_in_tmp = (const struct sockaddr_in *)addr;
			ofp_addr_in_tmp = (struct ofp_sockaddr_in *)ofp_addr;

			ofp_addr_in_tmp->sin_family = OFP_AF_INET;
			ofp_addr_in_tmp->sin_port = addr_in_tmp->sin_port;
			ofp_addr_in_tmp->sin_len =
				sizeof(struct ofp_sockaddr_in);
			ofp_addr_in_tmp->sin_addr.s_addr =
				addr_in_tmp->sin_addr.s_addr;

			ofp_addrlen = sizeof(struct ofp_sockaddr_in);
			break;
		}
		case AF_INET6:
		{
			const struct sockaddr_in6 *addr_in6_tmp;
			struct ofp_sockaddr_in6 *ofp_addr_in6_tmp;

			if (addrlen < sizeof(struct sockaddr_in6)) {
				errno = EINVAL;
				return -1;
			}
			addr_in6_tmp = (const struct sockaddr_in6 *)addr;
			ofp_addr_in6_tmp = (struct ofp_sockaddr_in6 *)ofp_addr;

			ofp_addr_in6_tmp->sin6_family = OFP_AF_INET6;
			ofp_addr_in6_tmp->sin6_port = addr_in6_tmp->sin6_port;
			ofp_addr_in6_tmp->sin6_flowinfo =
				addr_in6_tmp->sin6_flowinfo;
			ofp_addr_in6_tmp->sin6_scope_id =
				addr_in6_tmp->sin6_scope_id;
			ofp_addr_in6_tmp->sin6_len =
				sizeof(struct ofp_sockaddr_in6);

			memcpy((unsigned char *)ofp_addr_in6_tmp->sin6_addr.__u6_addr.__u6_addr16,
				(const unsigned char *)addr_in6_tmp->sin6_addr.s6_addr,
				16);

			ofp_addrlen = sizeof(struct ofp_sockaddr_in6);
			break;
		}

		default:
			errno = EAFNOSUPPORT;
			return -1;
		};

		connect_value = ofp_connect(sockfd,
			ofp_addr,
			ofp_addrlen);
		errno = NETWRAP_ERRNO(ofp_errno);
	} else if (libc_connect)
		connect_value = (*libc_connect)(sockfd, addr, addrlen);
	else {
		LIBC_FUNCTION(connect);

		if (libc_connect)
			connect_value = (*libc_connect)(sockfd, addr, addrlen);
		else {
			connect_value = -1;
			errno = EACCES;
		}
	}

	/*printf("Connect called on socket '%d' returns:'%d'\n",
		sockfd, connect_value);*/
	return connect_value;
}

ssize_t read(int sockfd, void *buf, size_t len)
{
	ssize_t read_value;

	if (IS_OFP_SOCKET(sockfd)) {
		read_value = ofp_recv(sockfd, buf, len, 0);
		errno = NETWRAP_ERRNO(ofp_errno);
	} else if (libc_read)
		read_value = (*libc_read)(sockfd, buf, len);
	else {
		LIBC_FUNCTION(read);

		if (libc_read)
			read_value = (*libc_read)(sockfd, buf, len);
		else {
			read_value = -1;
			errno = EACCES;
		}
	}

	return read_value;
}

ssize_t write(int sockfd, const void *buf, size_t len)
{
	ssize_t write_value;

	if (IS_OFP_SOCKET(sockfd)) {
		write_value = ofp_send(sockfd, buf, len, 0);
		errno = NETWRAP_ERRNO(ofp_errno);
	} else if (libc_write)
		write_value = (*libc_write)(sockfd, buf, len);
	else {
		LIBC_FUNCTION(write);
		if (libc_write)
			write_value = (*libc_write)(sockfd, buf, len);
		else {
			write_value = -1;
			errno = EACCES;
		}
	}

	return write_value;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
	ssize_t recv_value;

	if (IS_OFP_SOCKET(sockfd)) {
		int ofp_flags = 0;

		if (flags) {
			/*if (flags & MSG_CMSG_CLOEXEC)
				ofp_flags |= MSG_CMSG_CLOEXEC;*/
			if (flags & MSG_DONTWAIT)
				ofp_flags |= OFP_MSG_DONTWAIT;
			/*if (flags & MSG_ERRQUEUE)
				ofp_flags |= MSG_ERRQUEUE;*/
			if (flags & MSG_OOB)
				ofp_flags |= OFP_MSG_OOB;
			if (flags & MSG_PEEK)
				ofp_flags |= OFP_MSG_PEEK;
			if (flags & MSG_TRUNC)
				ofp_flags |= OFP_MSG_TRUNC;
			if (flags & MSG_WAITALL)
				ofp_flags |= OFP_MSG_WAITALL;
		}

		recv_value = ofp_recv(sockfd, buf, len, ofp_flags);
		errno = NETWRAP_ERRNO(ofp_errno);
	} else if (libc_recv)
		recv_value = (*libc_recv)(sockfd, buf, len, flags);
	else { /* pre init*/
		LIBC_FUNCTION(recv);

		if (libc_recv)
			recv_value = (*libc_recv)(sockfd, buf, len, flags);
		else {
			recv_value = -1;
			errno = EACCES;
		}
	}

	return recv_value;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
	ssize_t send_value;

	if (IS_OFP_SOCKET(sockfd)) {
		int ofp_flags = 0;

		if (flags) {
			/*if (flags & MSG_CONFIRM)
				ofp_flags |= OFP_MSG_CONFIRM;*/
			if (flags & MSG_DONTROUTE)
				ofp_flags |= OFP_MSG_DONTROUTE;
			if (flags & MSG_DONTWAIT)
				ofp_flags |= OFP_MSG_DONTWAIT;
			if (flags & MSG_DONTWAIT)
				ofp_flags |= OFP_MSG_DONTWAIT;
			if (flags & MSG_EOR)
				ofp_flags |= OFP_MSG_EOR;
			/*if (flags & MSG_MORE)
				ofp_flags |= OFP_MSG_MORE;*/
			if (flags & MSG_NOSIGNAL)
				ofp_flags |= OFP_MSG_NOSIGNAL;
			if (flags & MSG_OOB)
				ofp_flags |= OFP_MSG_OOB;
		}

		send_value = ofp_send(sockfd, buf, len, ofp_flags);
		errno = NETWRAP_ERRNO(ofp_errno);
	} else if (libc_send)
		send_value = (*libc_send)(sockfd, buf, len, flags);
	else {
		LIBC_FUNCTION(send);

		if (libc_send)
			send_value = (*libc_send)(sockfd, buf, len, flags);
		else {
			send_value = -1;
			errno = EACCES;
		}
	}

	return send_value;
}


