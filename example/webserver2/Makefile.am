include $(top_srcdir)/example/Makefile.inc

noinst_PROGRAMS = webserver2

webserver2_LDFLAGS = $(AM_LDFLAGS) -static

dist_webserver2_SOURCES = app_main.c httpd2.c

noinst_HEADERS = ${srcdir}/httpd.h
