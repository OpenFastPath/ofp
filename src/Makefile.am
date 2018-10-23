LIB   = $(top_builddir)/lib

VPATH = $(srcdir) $(builddir)

lib_LTLIBRARIES = $(LIB)/libofp.la

.PHONY: pkgconfig/libofp.pc

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = $(top_builddir)/pkgconfig/libofp.pc

AM_LDFLAGS += -version-number '$(LIBOFP_VERSION)'

AM_CFLAGS +=  -I$(top_srcdir)/include
AM_CFLAGS +=  -I$(top_srcdir)/include/api
AM_CFLAGS +=  $(VISIBILITY_CFLAGS)

__LIB__libofp_la_SOURCES = \
ofp_pkt_processing.c \
ofp_pkt_send_burst.c \
ofp_avl.c \
ofp_log.c \
ofp_debug.c \
ofp_debug_pcap.c \
ofp_debug_print.c \
cli/ofp_cli.c \
ofp_hash.c \
ofp_icmp.c \
ofp_ifnet.c \
ofp_init.c \
ofp_inet.c \
ofp_in_pcb.c \
ofp_in_proto.c \
ofp_in_cksum.c \
ofp_ip_init.c \
ofp_portconf.c \
ofp_route.c \
ofp_subr_hash.c \
ofp_syscalls.c \
ofp_timer.c \
ofp_udp_usrreq.c \
ofp_uipc_sockbuf.c \
ofp_uipc_socket.c \
ofp_uipc_domain.c \
ofp_tcp_usrreq.c \
ofp_tcp_subr.c \
ofp_tcp_timer.c \
ofp_tcp_output.c \
ofp_tcp_input.c \
ofp_tcp_sack.c \
ofp_tcp_timewait.c \
ofp_tcp_syncache.c \
ofp_tcp_reass.c \
ofp_gre.c \
ofp_md5c.c \
ofp_errno.c \
ofp_stat.c \
ofp_hook.c \
ofp_util.c \
ofp_reass.c \
ofp_sys_socket.c \
ofp_in.c \
ofp_sysctl.c \
ofp_igmp.c \
ofp_in_mcast.c \
ofp_vxlan.c \
ofp_shared_mem.c \
ofp_uma.c \
ofp_epoll.c \
ofp_ipsec.c \
ofp_ipsec_spd.c \
ofp_ipsec_sad.c

if OFP_USE_LIBCK
__LIB__libofp_la_SOURCES += \
ofp_arp_ck.c
else
__LIB__libofp_la_SOURCES += \
ofp_arp.c
endif

if OFP_USE_LIBCONFIG
AM_CFLAGS += -DOFP_DEFAULT_CONF_FILE="\"$(sysconfdir)/ofp.conf\""
endif

if OFP_SP
__LIB__libofp_la_SOURCES += \
ofp_netlink.c \
ofp_quagga.c \
ofp_tunthread.c
endif

if OFP_IPv6
__LIB__libofp_la_SOURCES += \
ofp_ip6_init.c \
ofp_in6_proto.c \
ofp_in6.c \
ofp_in6_pcb.c \
ofp_in6_cksum.c \
ofp_udp6_usrreq.c \
ofp_icmp6.c \
ofp_nd6.c
endif

if OFP_MTRIE
__LIB__libofp_la_SOURCES += \
ofp_rt_mtrie_lookup.c
else
__LIB__libofp_la_SOURCES += \
ofp_rt_lookup.c
endif

if OFP_CLI

__LIB__libofp_la_SOURCES += \
cli/ofp_cli_route.c \
cli/ofp_cli_debug.c \
cli/ofp_cli_log.c \
cli/ofp_cli_arp.c \
cli/ofp_cli_alias.c \
cli/ofp_cli_stat.c \
cli/ofp_cli_ifconfig.c \
cli/ofp_cli_address.c \
cli/ofp_cli_sysctl.c \
cli/ofp_cli_ipsec.c
endif
