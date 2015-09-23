DEFAULT_INCLUDES=-I.

AM_CFLAGS += -DINET

if OFP_IPv6
AM_CFLAGS += -DINET6
endif

if OFP_SP
AM_CFLAGS +=  -DSP
endif

if OFP_MTRIE
AM_CFLAGS +=  -DMTRIE
endif

AM_CPPFLAGS += -I$(top_srcdir)/include -I$(top_srcdir)/include/api
AM_LDFLAGS += -L$(top_builddir)/lib

if HAVE_CUNIT_PATH
AM_CPPFLAGS += -I$(CUNIT_PATH)/include
AM_LDFLAGS += -L$(CUNIT_PATH)/lib
endif

AM_LDFLAGS += -static -lcunit

LDADD = $(top_builddir)/lib/libofp.la

check_PROGRAMS = \
	ofp_test_arp \
	ofp_test_debug_pcap \
	ofp_test_debug_print \
	ofp_test_errno \
	ofp_test_fragmentation \
	ofp_test_packet_input \
	ofp_test_packet_output \
	ofp_test_port_conf \
	ofp_test_stat \
	ofp_test_util \
	ofp_test_in_cksum

TESTS = ${check_PROGRAMS}

CLEANFILES = $(wildcard *.xml) packets.txt testbuf.txt test.pcap
