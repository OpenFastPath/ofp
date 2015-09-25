include $(top_srcdir)/example/Makefile.inc

noinst_PROGRAMS = mcast

AM_CFLAGS +=  -I$(top_srcdir)/include
AM_CFLAGS +=  -I$(top_srcdir)/include/api

mcast_LDFLAGS = $(AM_LDFLAGS) -static
mcast_CFLAGS = $(AM_CFLAGS)

dist_mcast_SOURCES = app_main.c mcast.c
