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

bin_PROGRAMS = \
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
	ofp_test_in_cksum \
	ofp_test_init \
	ofp_test_in_var \
	ofp_test_tcp_seq \
	ofp_test_rt_lookup \
	ofp_test_syscalls \
	ofp_test_epoll \
	ofp_test_icmp

if OFP_MTRIE
bin_PROGRAMS += ofp_test_rt_mtrie_lookup
endif

TESTS = ${bin_PROGRAMS}

EXTRA_DIST = cksum_packets.h fragmented_packet.h test_raw_frames.h

CLEANFILES = $(wildcard *.xml) packets.txt testbuf.txt test.pcap
