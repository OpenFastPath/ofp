LIB   = $(top_builddir)/lib
LDADD = $(LIB)/libofp.la

DEFAULT_INCLUDES=-I.

AM_CPPFLAGS += \
	     $(DEFAULT_INCLUDES) \
	     -I$(srcdir) \
	     -I$(top_srcdir)/include/api \
	     -I$(top_srcdir)/example/common

AM_LDFLAGS += -L$(LIB)
