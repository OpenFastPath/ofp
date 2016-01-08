SUBDIRS = .

if OFP_CUNIT_ENABLED
SUBDIRS += cunit
endif

AM_CPPFLAGS += -DODP_VERSION=$(ODP_VERSION) -I$(top_srcdir)/include/api

LDADD = $(top_builddir)/lib/libofp.la

bin_PROGRAMS = cpp_test redefinitions_posix_test

TESTS = ${bin_PROGRAMS}

cpp_test_SOURCES = cpp_test.cpp
