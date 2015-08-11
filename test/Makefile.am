SUBDIRS = . cunit

AM_CPPFLAGS += -I$(top_srcdir)/include/api

check_PROGRAMS = cpp_test

TESTS = ${check_PROGRAMS}

cpp_test_SOURCES = cpp_test.cpp
cpp_test_LDADD = $(top_builddir)/lib/libofp.la
