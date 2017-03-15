SUBDIRS = .

if OFP_CUNIT_ENABLED
SUBDIRS += cunit
endif

AM_CPPFLAGS += -I$(top_srcdir)/include/api

LDADD = $(top_builddir)/lib/libofp.la

bin_PROGRAMS = cpp_test redefinitions_posix_test
cpp_test_LDFLAGS = $(AM_LDFLAGS) -static
redefinitions_posix_test_LDFLAGS = $(AM_LDFLAGS) -static

TESTS = ${bin_PROGRAMS}

cpp_test_SOURCES = cpp_test.cpp
