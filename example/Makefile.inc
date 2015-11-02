LIB   = $(top_builddir)/lib
LDADD = $(LIB)/libofp.la

DEFAULT_INCLUDES=-I.

AM_CFLAGS += \
	     -I$(srcdir) \
	     -DODP_VERSION=$(ODP_VERSION) \
	     -I$(top_srcdir)/include/api

AM_LDFLAGS += -L$(LIB)
