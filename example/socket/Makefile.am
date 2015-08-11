include $(top_srcdir)/example/Makefile.inc

noinst_PROGRAMS = socket
socket_LDFLAGS = $(AM_LDFLAGS) -static
socket_CFLAGS = $(AM_CFLAGS)

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

if OFP_IPv6
socket_CFLAGS +=  -DINET6
endif
