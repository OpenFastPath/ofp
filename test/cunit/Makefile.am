LIB   = $(top_builddir)/lib
LDADD = $(LIB)/libofp.la

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

AM_CFLAGS += \
	     -I$(srcdir) \
	     -I$(top_srcdir)/include \
	     -I$(top_srcdir)/include/api \
	     -I$(CUNIT_PATH)/include

AM_LDFLAGS += \
	      -L$(LIB) \
	      -L$(CUNIT_PATH)/lib

if OFP_CUNIT_ENABLED
TESTS = ${check_PROGRAMS}
check_PROGRAMS = ofp_test_util ofp_test_stat ofp_test_packet_input \
		 ofp_test_packet_output ofp_test_debug_pcap \
		 ofp_test_debug_print ofp_test_fragmentation \
		 ofp_test_port_conf

ofp_test_util_LDFLAGS = $(AM_LDFLAGS) -static -lcunit
ofp_test_stat_LDFLAGS = $(AM_LDFLAGS) -static -lcunit
ofp_test_packet_input_LDFLAGS = $(AM_LDFLAGS) -static -lcunit
ofp_test_packet_output_LDFLAGS = $(AM_LDFLAGS) -static -lcunit
ofp_test_debug_pcap_LDFLAGS = $(AM_LDFLAGS) -static -lcunit
ofp_test_debug_print_LDFLAGS = $(AM_LDFLAGS) -static -lcunit
ofp_test_fragmentation_LDFLAGS = $(AM_LDFLAGS) -static -lcunit
ofp_test_port_conf_LDFLAGS = $(AM_LDFLAGS) -static -lcunit
endif
