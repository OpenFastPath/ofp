LIB   = $(top_builddir)/lib

AM_CFLAGS =  -I.
AM_CFLAGS +=  -I$(top_srcdir)/include/api \
	     -DODP_VERSION=$(ODP_VERSION) 

lib_LTLIBRARIES = $(LIB)/libofp_netwrap_crt.la

__LIB__libofp_netwrap_crt_la_SOURCES = netwrap.c \
				netwrap_socket.c \
				netwrap_sockopt.c \
				netwrap_ioctl.c \
				netwrap_fork.c \
				netwrap_select.c \
				netwrap_uio.c \
				netwrap_sendfile.c
