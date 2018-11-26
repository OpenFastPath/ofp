# OpenFastPath Bumblebee 3.0.0

Repository                          | Branch    | Tag
------------------------------------|-----------|------
https://github.com/OpenFastPath/ofp | bumblebee | 3.0.0

## Dependencies

OpenDataPlane v1.18.0.0 or later.

## Highlights

* Basic epoll implementation.
* Various TCP fixes and performance improvements.
* More efficient route insertion and deletion.
* Configurability improvements.
* Configuration file support.
* Basic IPsec implementation using ODP IPsec API.
* IPv4/UDP/TCP checksum offloading.
* Routing speedup by caching a reference to ARP entry in the nexthop entry.
* Multiple IP addresses per interface.

## Changes since 2.0.1

### Resolved Issues

* #60 "loglevel" is broken after commit 2073b2b1
* #61 "Loglevel" description is missing
* #85 Adding new rules is inefficient
* #86 DNS address hard-coded in reset scripts
* #92 the misleading return code of ofp_connect() function
* #93 Data corruption - tcp packets dropped in the receive path
* #98 TCP timers problems
* #101 Wrong netmask when configuring interface address through CLI
* #106 Implement epoll() in ofp_netwrap_crt example
* #111 Dubious piece of dead code in add_link()
* #112 OFP TCP crash with sigevent
* #114 ofp_rt_rule_find_prefix_match mix use of big-endian data
* #115 ofp_rt_rule_find_prefix_match use incorrect masklen to
* #116 ofp_rtl_remove will re-insert the route it just
* #118 NODEALLOC does not reset next pointer and lead to
* #119 Left bit shift result in UB
* #120 Nexthops may be used after freed and while being modified
* #123 Missing locking around the avl_tree used for VLANs
* #142 fpm command line option -c doesn't work
* #144 Hard coded TCP MSS value to 960 bytes
* #146 mcasttest thread terminate once startup
* #149 ofp_create_ns_socket creates unnecessary children
* #152 Premature closure of TCP connection
* #153 unknown type name 'fd_set'
* #158 ODP pool parameters not always fully initialized
* #162 Fragmentation does not work with IP options
* #163 MTUs of GRE interfaces are ignored
* #164 MTUs of VxLAN interfaces are ignored
* #169 Incorrect IP header checksum in locally originated tunneled packets
* #170 Duplicate values in IPv4 identification field
* #178 OFP crashes during output link congestion.
* #179 ICMP packet is malformed if triggering packet contains IP options.
* #182 Outdated packets are not always properly freed from the packet pools
* #183 CLI command "stat" doesn't always output CPU core
* #189 Outgoing TCP RST contains bad TCP header fields.
* #192 ofp_mtu_set() function doesn't set interface MTU value properly
* #196 Packets corrupted at output
* #197 Sent Ethernet frames may have extra octets at the end
* #203 Segmentation fault in default_event_dispatcher
* #204 TCP src and dst ports mixed up in IPv6 RST
* #205 Seg fault after changing IP address running fpm in ofp_arp_save_ipv4_pkt (ofp_arp.c:585)
* #209 Arp entries become invalid after 2s.
* #215 IPv6 broken

### Library Version Changes

* libofp.so: 2.0.1 -> 3.0.0

### API Changes

Changes to data types, typedefs and preprocessor macros are not listed.

#### Added Header Files

* ofp_epoll.h
* ofp_ipsec.h
* ofp_ipsec_init.h

#### Added Functions

Added functions in new header files are not listed.

##### ofp_in.h
* uint16_t ofp_cksum_iph(const void *addr, int ip_hl)

##### ofp_init.h
* void ofp_init_global_param(ofp_global_param_t *params)
* void ofp_init_global_param_from_file(ofp_global_param_t *params, const char *filename)

##### ofp_pkt_processing.h
* enum ofp_return_code ofp_ip6_send(odp_packet_t pkt, struct ofp_nh6_entry* nh_param)
* enum ofp_return_code ofp_ip_send(odp_packet_t pkt, struct ofp_nh_entry* nh_param)
* uint32_t ofp_packet_min_user_area(void)

##### ofp_portconf.h
* const char *ofp_config_interface_add_ip_v4(int port, uint16_t vlan, uint16_t vrf, uint32_t addr, int masklen)
* const char *ofp_config_interface_del_ip_v4(int port, uint16_t vlan, int vrf, uint32_t addr, int masklen)
* void ofp_show_ifnet_ip_addrs(int fd)
* struct ofp_ifnet *ofp_vlan_alloc()

#### Removed Functions

##### ofp_pkt_processing.h
* enum ofp_return_code ofp_ip6_output(odp_packet_t pkt, struct ofp_nh6_entry* nh_param)
* enum ofp_return_code ofp_ip_output(odp_packet_t pkt, struct ofp_nh_entry* nh_param)
* enum ofp_return_code ofp_ip_output_opt(odp_packet_t pkt, odp_packet_t opt, struct ofp_nh_entry* nh_param, int flags, struct ofp_ip_moptions* imo, struct inpcb* inp)
* enum ofp_return_code ofp_sp_input(odp_packet_t pkt, struct ofp_ifnet* ifnet)

##### ofp_route_arp.h
* int ofp_del_mac(struct ofp_ifnet* dev, uint32_t addr, uint8_t* mac)
* uint16_t ofp_get_probable_vlan(int port, uint32_t addr)

#### Changed Functions

##### ofp_pkt_processing.h
* enum ofp_return_code ofp_arp_processing(odp_packet_t pkt) -> enum ofp_return_code ofp_arp_processing(odp_packet_t* pkt)
* enum ofp_return_code ofp_eth_vlan_processing(odp_packet_t pkt) -> enum ofp_return_code ofp_eth_vlan_processing(odp_packet_t* pkt)
* enum ofp_return_code ofp_gre_processing(odp_packet_t pkt) -> enum ofp_return_code ofp_gre_processing(odp_packet_t* pkt)
* enum ofp_return_code ofp_ipv4_processing(odp_packet_t pkt) -> enum ofp_return_code ofp_ipv4_processing(odp_packet_t* pkt)
* enum ofp_return_code ofp_ipv6_processing(odp_packet_t pkt) -> enum ofp_return_code ofp_ipv6_processing(odp_packet_t* pkt)
* enum ofp_return_code ofp_tcp4_processing(odp_packet_t pkt) -> enum ofp_return_code ofp_tcp4_processing(odp_packet_t* pkt)
* enum ofp_return_code ofp_udp4_processing(odp_packet_t pkt) -> enum ofp_return_code ofp_udp4_processing(odp_packet_t* pkt)

##### ofp_route_arp.h
* int ofp_get_mac(struct ofp_ifnet* dev, uint32_t addr, uint8_t* mac_out) -> int ofp_get_mac(struct ofp_ifnet* dev, struct ofp_nh_entry* nh_data, uint32_t addr, uint32_t is_link_local, uint8_t* mac_out)

##### ofp_in.h
* uint16_t ofp_cksum_buffer(register uint16_t *addr, register int len) -> uint16_t ofp_cksum_buffer(const void *addr, int len);
* int ofp_cksum(const odp_packet_t pkt, unsigned int off, unsigned int len) -> uint16_t ofp_cksum(const odp_packet_t pkt, unsigned int off, unsigned int len);
* int ofp_in4_cksum(const odp_packet_t pkt) -> uint16_t ofp_in4_cksum(const odp_packet_t pkt);

##### ofp_init.h
* int ofp_init_global(odp_instance_t instance, ofp_init_global_t *params) -> int ofp_init_global(odp_instance_t instance, ofp_global_param_t *params)

##### ofp_pkt_processing.h
* void *default_event_dispatcher(void *arg) -> int default_event_dispatcher(void *arg)

#### Added CLI Commands

* `address add <address/mask> <interface>`
* `address del <address/mask> <interface>`
* `address show`
* `help address`
* `help ipsec`
* `ipsec help`
* `ipsec sa add <id> spi <spi> template <template>`
* `ipsec sa add NUMBER spi NUMBER template STRING`
* `ipsec sa del <id>`
* `ipsec sa delete NUMBER`
* `ipsec sa-template add <name>`
* `ipsec sa-template add STRING`
* `ipsec sa-template del <name>`
* `ipsec sa-template delete STRING`
* `ipsec sa-template set <name> <parameter> <value>`
* `ipsec sa-template set STRING auth STRING`
* `ipsec sa-template set STRING auth-key STRING`
* `ipsec sa-template set STRING cipher STRING`
* `ipsec sa-template set STRING cipher-key STRING`
* `ipsec sa-template set STRING dir STRING`
* `ipsec sa-template set STRING mode STRING`
* `ipsec sa-template set STRING proto STRING`
* `ipsec sa-template set STRING tun-dst IP4ADDR`
* `ipsec sa-template set STRING tun-src IP4ADDR`
* `ipsec sa-template set STRING vrf NUMBER`
* `ipsec sa-template set STRING window-size NUMBER`
* `ipsec show sa-template`
* `ipsec show sa-template`
* `ipsec show sa`
* `ipsec show sa`
* `ipsec show sp-template`
* `ipsec show sp-template`
* `ipsec show sp`
* `ipsec show sp`
* `ipsec sp add <id> priority <priority> template <template>`
* `ipsec sp add NUMBER priority NUMBER template STRING`
* `ipsec sp bind <sp id> sa <sa id>`
* `ipsec sp bind NUMBER sa NUMBER`
* `ipsec sp del <id>`
* `ipsec sp delete NUMBER`
* `ipsec sp unbind <sp id> sa <sa id>`
* `ipsec sp unbind NUMBER`
* `ipsec sp-template add <name>`
* `ipsec sp-template add STRING`
* `ipsec sp-template del <name>`
* `ipsec sp-template del STRING`
* `ipsec sp-template set <name> <parameter> <value>`
* `ipsec sp-template set STRING action STRING`
* `ipsec sp-template set STRING dir STRING`
* `ipsec sp-template set STRING dst-range IP4ADDR IP4ADDR`
* `ipsec sp-template set STRING proto NUMBER`
* `ipsec sp-template set STRING src-range IP4ADDR IP4ADDR`
* `ipsec sp-template set STRING vrf NUMBER`
* `netstat -t`
* `netstat -u`
* `netstat`

## Unit Testing

Environment | ODP Variant | Test Cases Total | Pass | Fail
------------|-------------|------------------|------|-----
x86-64      | odp-linux   | 130              | 130  | 0

## For More Information

See project home page http://www.openfastpath.org
