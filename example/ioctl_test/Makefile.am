include $(top_srcdir)/example/Makefile.inc

noinst_PROGRAMS = ioctl_test

AM_CFLAGS +=  -I$(top_srcdir)/include
AM_CFLAGS +=  -I$(top_srcdir)/include/api

ioctl_test_LDFLAGS = $(AM_LDFLAGS) -static
ioctl_test_CFLAGS = $(AM_CFLAGS)

dist_ioctl_test_SOURCES = app_main.c ioctl_test.c
