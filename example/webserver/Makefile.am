include $(top_srcdir)/example/Makefile.inc

bin_PROGRAMS = webserver

AM_CFLAGS +=  -I$(top_srcdir)/include
AM_CFLAGS +=  -I$(top_srcdir)/include/api

webserver_LDFLAGS = $(AM_LDFLAGS) -static
webserver_CFLAGS = $(AM_CFLAGS)

dist_webserver_SOURCES = app_main.c httpd.c
