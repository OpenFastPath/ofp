/* Copyright (c) 2015, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 *
 */
#ifndef __OFPI_VXLAN_H__
#define __OFPI_VXLAN_H__

struct vxlan_user_data {
	uint32_t hdrlen;
	uint32_t vni;
};

struct ofp_ifnet;
struct ofp_nh_entry;
struct ofp_arphdr;
struct ip_out;
enum ofp_return_code ofp_vxlan_input(odp_packet_t pkt);
enum ofp_return_code ofp_vxlan_prepend_hdr(odp_packet_t pkt, struct ofp_ifnet *vxdev,
			  struct ofp_nh_entry *nh);
int ofp_vxlan_init_global(void);
int ofp_vxlan_term_global(void);
void ofp_vxlan_init_local(void);
void ofp_vxlan_term_local(void);
int ofp_vxlan_lookup_shared_memory(void);
void ofp_vxlan_set_mac_dst(uint8_t *mac, uint32_t dst);
uint32_t ofp_vxlan_get_mac_dst(uint8_t *mac);
int ofp_set_vxlan_interface_queue(void);
int ofp_clean_vxlan_interface_queue(void);
void ofp_vxlan_update_devices(odp_packet_t pkt, struct ofp_arphdr *arp, uint16_t *vlan,
			      struct ofp_ifnet **dev, struct ofp_ifnet **outdev,
			      uint8_t *save_space);
void ofp_vxlan_restore_and_update_header(odp_packet_t pkt,
					 struct ofp_ifnet *outdev,
					 uint8_t *saved_mac);
void ofp_vxlan_send_arp_request(odp_packet_t pkt, struct ofp_ifnet *dev);
enum ofp_return_code ofp_ip_output_vxlan(odp_packet_t pkt, struct ip_out *xxx);


#endif /*__OFPI_VXLAN_H__*/
