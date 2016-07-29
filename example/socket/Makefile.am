include $(top_srcdir)/example/Makefile.inc

noinst_PROGRAMS = socket
socket_LDFLAGS = $(AM_LDFLAGS) -static

dist_socket_SOURCES = \
suite_framework.c \
socket_create_close.c \
socket_bind.c \
socket_shutdown.c \
socket_connect_udp.c \
socket_send_sendto_udp.c \
socket_send_recv_udp.c \
socket_listen_tcp.c \
socket_connect_accept_tcp.c \
socket_send_recv_tcp.c \
socket_select.c \
socket_sigevent.c \
socket_main.c

noinst_HEADERS = \
		${srcdir}/socket_bind.h \
		${srcdir}/socket_send_recv_udp.h \
		${srcdir}/socket_connect_accept_tcp.h \
		${srcdir}/socket_send_sendto_udp.h \
		${srcdir}/socket_connect_udp.h \
		${srcdir}/socket_shutdown.h \
		${srcdir}/socket_create_close.h \
		${srcdir}/socket_sigevent.h \
		${srcdir}/socket_listen_tcp.h \
		${srcdir}/socket_util.h \
		${srcdir}/socket_select.h \
		${srcdir}/suite_framework.h \
		${srcdir}/socket_send_recv_tcp.h
if OFP_IPv6
socket_CFLAGS =  -DINET6
endif
