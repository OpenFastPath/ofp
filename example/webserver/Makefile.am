include $(top_srcdir)/example/Makefile.inc

noinst_PROGRAMS = webserver

webserver_LDFLAGS = $(AM_LDFLAGS) -static

dist_webserver_SOURCES = app_main.c httpd.c

noinst_HEADERS = ${srcdir}/httpd.h
