include $(top_srcdir)/example/Makefile.inc

noinst_PROGRAMS = udp_fwd_socket

AM_CFLAGS +=  -I$(top_srcdir)/include
AM_CFLAGS +=  -I$(top_srcdir)/include/api

udp_fwd_socket_LDFLAGS = $(AM_LDFLAGS) -static
udp_fwd_socket_CFLAGS = $(AM_CFLAGS)

dist_udp_fwd_socket_SOURCES = app_main.c udp_fwd_socket.c

noinst_HEADERS = ${srcdir}/udp_fwd_socket.h
