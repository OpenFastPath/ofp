include $(top_srcdir)/example/Makefile.inc

noinst_PROGRAMS = udpecho

AM_CFLAGS +=  -I$(top_srcdir)/include
AM_CFLAGS +=  -I$(top_srcdir)/include/api

udpecho_LDFLAGS = $(AM_LDFLAGS) -static
udpecho_CFLAGS = $(AM_CFLAGS)

dist_udpecho_SOURCES = app_main.c udp_server.c
