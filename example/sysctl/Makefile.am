include $(top_srcdir)/example/Makefile.inc

noinst_PROGRAMS = sysctl

AM_CFLAGS +=  -I$(top_srcdir)/include
AM_CFLAGS +=  -I$(top_srcdir)/include/api

sysctl_LDFLAGS = $(AM_LDFLAGS) -static
sysctl_CFLAGS = $(AM_CFLAGS)

dist_sysctl_SOURCES = app_main.c sysctl.c

noinst_HEADERS = ${srcdir}/sysctl.h
