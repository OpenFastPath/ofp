LIB   = $(top_builddir)/lib

AM_CPPFLAGS +=  -I.
AM_CPPFLAGS +=  -I$(top_srcdir)/include/api

lib_LTLIBRARIES = $(LIB)/libofp_netwrap_crt.la

noinst_HEADERS = \
		 $(srcdir)/netwrap_common.h \
		 $(srcdir)/netwrap_errno.h \
		 $(srcdir)/netwrap_fork.h \
		 $(srcdir)/netwrap_ioctl.h \
		 $(srcdir)/netwrap_select.h \
		 $(srcdir)/netwrap_sendfile.h \
		 $(srcdir)/netwrap_socket.h \
		 $(srcdir)/netwrap_sockopt.h \
		 $(srcdir)/netwrap_uio.h \
		 $(srcdir)/netwrap_epoll.h

__LIB__libofp_netwrap_crt_la_SOURCES = netwrap.c \
				netwrap_socket.c \
				netwrap_sockopt.c \
				netwrap_ioctl.c \
				netwrap_fork.c \
				netwrap_select.c \
				netwrap_uio.c \
				netwrap_sendfile.c \
				netwrap_epoll.c
