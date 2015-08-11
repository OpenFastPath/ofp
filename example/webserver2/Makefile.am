include $(top_srcdir)/example/Makefile.inc

noinst_PROGRAMS = webserver2

AM_CFLAGS +=  -I$(top_srcdir)/include
AM_CFLAGS +=  -I$(top_srcdir)/include/api

webserver2_LDFLAGS = $(AM_LDFLAGS) -static
webserver2_CFLAGS = $(AM_CFLAGS)

dist_webserver2_SOURCES = app_main.c httpd2.c
