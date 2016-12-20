include $(top_srcdir)/example/Makefile.inc

noinst_PROGRAMS = ofp_vs

AM_CFLAGS +=  -I$(top_srcdir)/include
AM_CFLAGS +=  -I$(top_srcdir)/include/api
AM_CFLAGS +=  -I/usr/local/include/libnl3
AM_CFLAGS +=  -I$(RTE_SDK)/$(RTE_TARGET)/include
AM_CFLAGS +=  -I./include
AM_CFLAGS +=  -msse4.2

ofp_vs_LDFLAGS = $(AM_LDFLAGS) -static -L/usr/local/lib -lnl-3 -lnl-genl-3 -lnl-cli-3
ofp_vs_CFLAGS = $(AM_CFLAGS) -Woverride-init 
ofp_vs_CFLAGS += -DCONFIG_IP_VS_DEBUG
ofp_vs_CFLAGS += -DCONFIG_IP_VS_PROTO_TCP
ofp_vs_CFLAGS += -DCONFIG_IP_VS_PROTO_UDP 
ofp_vs_CFLAGS += -DCONFIG_OFP_VS_RTE_TIMER

dist_ofp_vs_SOURCES = main.c ofp_vs_core.c ofp_vs_ctl.c ofp_vs_proto_tcp.c \
		ofp_vs_proto_udp.c ofp_vs_sched.c ofp_vs_rr.c ofp_vs_conn.c \
		ofp_vs_proto.c ofp_vs_xmit.c ofp_vs_stats.c ofp_vs_timer.c \
		#ofp_vs_cli_cmd.c
