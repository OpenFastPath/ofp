/* Copyright (c) 2015, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 *
 */

#include <odp_api.h>
#include "api/ofp_types.h"
#include "api/ofp_pkt_processing.h"
#include "ofpi_in.h"
#include "ofpi_ip.h"
#include "ofpi_udp.h"
#include "ofpi_if_vxlan.h"
#include "ofpi_if_vlan.h"
#include "ofpi_ethernet.h"
#include "ofpi_portconf.h"
#include "ofpi_log.h"
#include "ofpi_hook.h"
#include "ofpi_util.h"
#include "ofpi_vxlan.h"
#include "ofpi_if_arp.h"
#include "ofpi_pkt_processing.h"
#include "ofpi_ipsec.h"

#define SHM_NAME_VXLAN "OfpVxlanShMem"

/* MAC address to IP address hash table is an array of key/value pairs,
 * where the key is a MAC address and value is an IP address.
 * Hash value is the two least significant bytes of a MAC address. No extra hash
 * function is needed.
 *
 * There are no linked lists to resolve hash collisions outside the table;
 * there is only the array itself. A zero or one key in the array designates a free
 * entry, and the array is initially all zeros. Items in the table are inserted
 * and located by performing a linear search. Search begins each linear search
 * at an index determined by the hash. Search stops when a key value zero is seen.
 *
 * After entry deletion the new key value will be 'recycled' to indicate a free
 * place that is not the end of the search.
 *
 * Table is 8k long, which is an overkill. Most probably there will be at most
 * a few hundred entries in the table and since the used hash distributes well
 * a shorter table should be adequate.
 */

#define NUM_MAC_DST_ENTRIES 0x2000
#define KEY_FREE            0
#define KEY_RECYCLED        0x0100000000000001

#define VXLAN_TICK             20000UL /* Timer resolution */
#define VXLAN_MAC_IP_AGE       (3600UL*1000000UL) /* 1 hour */
#define VXLAN_MAC_IP_AGE_TICKS (VXLAN_MAC_IP_AGE/VXLAN_TICK)

struct mac_dst {
	odp_atomic_u64_t mac;	/* MAC + 2 bytes padding */
	odp_atomic_u32_t addr;	/* IPv4 address of the destination */
	odp_atomic_u32_t tmo;	/* Last update time */
};

struct ofp_vxlan_mem {
	struct mac_dst mac_to_dst[NUM_MAC_DST_ENTRIES];
	uint32_t       next_check;	/* Index of entry to check */
	uint32_t       tick;		/* Time now */
};

odp_timer_t ofp_vxlan_timer = ODP_TIMER_INVALID;

static __thread struct ofp_vxlan_mem *shm;

void ofp_vxlan_set_mac_dst(uint8_t *mac, uint32_t dst)
{
	int i;
	/* "hash" is the two least significant bytes of the mac */
	uint16_t hash = (*((uint16_t *)(&mac[4]))) & (NUM_MAC_DST_ENTRIES - 1);
	uint64_t key = 0, old_key = KEY_FREE;

	memcpy((uint8_t *)&key, mac, OFP_ETHER_ADDR_LEN);

	for (i = hash; ; ) {
		/* Change this to an odp function. */
		__atomic_compare_exchange_n(&shm->mac_to_dst[i].mac.v,
					    &old_key, key,
					    0/*strong*/,
					    __ATOMIC_RELAXED, __ATOMIC_RELAXED);
		if (old_key == KEY_FREE || old_key == key) {
			odp_atomic_store_u32(&shm->mac_to_dst[i].addr, dst);
			odp_atomic_store_u32(&shm->mac_to_dst[i].tmo,
					     shm->tick + VXLAN_MAC_IP_AGE_TICKS);
			OFP_DBG("VXLAN: set mac-dst %s->%s to pos 0x%x",
				ofp_print_mac(mac),
				ofp_print_ip_addr(dst), i);
			return;
		}

		/* Check for recycled place */
		old_key = KEY_RECYCLED;
		__atomic_compare_exchange_n(&shm->mac_to_dst[i].mac.v,
					    &old_key, key,
					    0/*strong*/,
					    __ATOMIC_RELAXED, __ATOMIC_RELAXED);
		if (old_key == KEY_RECYCLED || old_key == key) {
			odp_atomic_store_u32(&shm->mac_to_dst[i].addr, dst);
			odp_atomic_store_u32(&shm->mac_to_dst[i].tmo,
					     shm->tick + VXLAN_MAC_IP_AGE_TICKS);
			OFP_DBG("VXLAN: recyc set mac-dst %s->%s to pos 0x%x",
				ofp_print_mac(mac),
				ofp_print_ip_addr(dst), i);
			return;
		}

		i = (i + 1) & (NUM_MAC_DST_ENTRIES - 1);
		if (i == hash) {
			OFP_ERR("VXLAN: No more space in the table");
			return;
		}
        }
}

uint32_t ofp_vxlan_get_mac_dst(uint8_t *mac)
{
	int i;
	/* "hash" is the two least significant bytes of the mac */
	uint16_t hash = (*((uint16_t *)(&mac[4]))) & (NUM_MAC_DST_ENTRIES - 1);
	uint64_t key = 0, probed_key;

	memcpy((uint8_t *)&key, mac, OFP_ETHER_ADDR_LEN);

	for (i = hash; ; ) {
		probed_key = odp_atomic_load_u64(&shm->mac_to_dst[i].mac);
		if (probed_key == key) {
			OFP_DBG("VXLAN: get mac-dst %s->%s from pos 0x%x",
				ofp_print_mac(mac),
				ofp_print_ip_addr(shm->mac_to_dst[i].addr.v), i);
			return odp_atomic_load_u32(&shm->mac_to_dst[i].addr);
		}
		if (probed_key == KEY_FREE)
			return 0;
		i = (i + 1) & (NUM_MAC_DST_ENTRIES - 1);
		if (i == hash)
			return 0;
        }
}

static void ofp_vxlan_tmo(void *arg)
{
	int i = shm->next_check;
	uint32_t tmo = odp_atomic_load_u32(&shm->mac_to_dst[i].tmo);
	uint64_t mac = odp_atomic_load_u64(&shm->mac_to_dst[i].mac);
	(void)arg;

	if (mac != KEY_FREE &&
	    mac != KEY_RECYCLED &&
	    tmo + VXLAN_MAC_IP_AGE_TICKS < shm->tick) {
		OFP_DBG("VXLAN: tick=%d delete mac-dst %s->%s from pos 0x%x",
			shm->tick,
			ofp_print_mac((uint8_t *)(uintptr_t)mac),
			ofp_print_ip_addr(shm->mac_to_dst[i].addr.v), i);
		odp_atomic_store_u64(&shm->mac_to_dst[i].mac, KEY_RECYCLED);
	}

	shm->tick++;
	shm->next_check = (shm->next_check + 1) & (NUM_MAC_DST_ENTRIES - 1);
	ofp_vxlan_timer = ofp_timer_start(VXLAN_TICK, ofp_vxlan_tmo, NULL, 0);
	if (ODP_TIMER_INVALID == ofp_vxlan_timer)
		OFP_ERR("Failed to restart VXLAN timer.");
}

enum ofp_return_code ofp_vxlan_input(odp_packet_t pkt)
{
	struct ofp_ip *ip = (struct ofp_ip *)odp_packet_l3_ptr(pkt, NULL);
	struct ofp_udphdr *udp;
	struct ofp_vxlan_h *vxlan;
	struct ofp_ifnet *dev, *dev0;
	struct ofp_ether_header *eth;
	uint32_t vni;
	int vxlen;

	if (ip->ip_p != OFP_IPPROTO_UDP)
		return OFP_PKT_CONTINUE;

	udp = (struct ofp_udphdr *)((char *)ip + (ip->ip_hl<<2));
	if (odp_be_to_cpu_16(udp->uh_dport) != VXLAN_PORT)
		return OFP_PKT_CONTINUE;

	vxlan = (struct ofp_vxlan_h *)(udp + 1);
	vni = odp_be_to_cpu_32(vxlan->vni) >> 8;
	dev = ofp_get_ifnet(VXLAN_PORTS, vni);
	if (!dev)
		return OFP_PKT_CONTINUE;

	/* outer header from address */
	uint32_t from = ip->ip_src.s_addr;

	vxlen = odp_packet_l3_offset(pkt) + (ip->ip_hl<<2) +
		sizeof(struct ofp_udphdr) +
		sizeof(struct ofp_vxlan_h);
	if (!odp_packet_pull_head(pkt, vxlen))
		return OFP_PKT_DROP;

	odp_packet_l2_offset_set(pkt, 0);

	eth = (struct ofp_ether_header *)odp_packet_data(pkt);
	if (odp_be_to_cpu_16(eth->ether_type) == OFP_ETHERTYPE_VLAN)
		odp_packet_l3_offset_set(pkt, sizeof(struct ofp_ether_vlan_header));
	else
		odp_packet_l3_offset_set(pkt, sizeof(struct ofp_ether_header));

	/* save data to user area */
	struct vxlan_user_data *saved = &ofp_packet_user_area(pkt)->vxlan;
	saved->hdrlen = vxlen;
	saved->vni = vni;

	/* learn mac to dst addr association */
	ofp_vxlan_set_mac_dst(eth->ether_shost, from);
	odp_packet_user_ptr_set(pkt, dev);
	ofp_ipsec_flags_set(pkt, 0);
	dev0 = ofp_get_ifnet(VXLAN_PORTS, 0);
	odp_event_t ev = odp_packet_to_event(pkt);
	if (odp_queue_enq(dev0->loopq_def, ev) < 0) {
		OFP_ERR("odp_queue_enq");
		return OFP_PKT_DROP;
	}

	return OFP_PKT_PROCESSED;
}

enum ofp_return_code ofp_vxlan_prepend_hdr(odp_packet_t pkt, struct ofp_ifnet *vxdev,
			  struct ofp_nh_entry *nh)
{
	struct ofp_vxlan_udp_ip *ip_udp_vxlan;
	size_t size;

	if (nh)
		nh->gw = 0;

	/* Find next hop based on inner packet's dest mac */
	struct ofp_ether_header *eth = odp_packet_data(pkt);
	uint32_t gw = ofp_vxlan_get_mac_dst(eth->ether_dhost);
	if (gw == 0) {
		/* No entry found, use multicast group */
		struct ofp_ifnet *outdev = ofp_get_ifnet(vxdev->physport,
							 vxdev->physvlan);
		gw = vxdev->ip_p2p;
		if (nh) {
			nh->gw = gw;
			nh->port = outdev->port;
			nh->vlan = outdev->vlan;
		}
	}

	size = odp_packet_len(pkt);
	ip_udp_vxlan = odp_packet_push_head(pkt, sizeof(*ip_udp_vxlan));
	if (!ip_udp_vxlan) {
		OFP_ERR("odp_packet_push_head failed");
		return OFP_PKT_DROP;
	}

	ip_udp_vxlan->vxlan.flags = odp_cpu_to_be_32(0x08000000);
	ip_udp_vxlan->vxlan.vni = odp_cpu_to_be_32(vxdev->vlan << 8);

	ip_udp_vxlan->udp.uh_sport = odp_cpu_to_be_16(17777);
	ip_udp_vxlan->udp.uh_dport = odp_cpu_to_be_16(VXLAN_PORT);
	ip_udp_vxlan->udp.uh_ulen = odp_cpu_to_be_16(
		size + sizeof(struct ofp_vxlan_h) + sizeof(struct ofp_udphdr));
	ip_udp_vxlan->udp.uh_sum = 0;

	ip_udp_vxlan->ip.ip_hl = 5;
	ip_udp_vxlan->ip.ip_v = OFP_IPVERSION;
	ip_udp_vxlan->ip.ip_tos = 0;
	ip_udp_vxlan->ip.ip_len = odp_cpu_to_be_16(
		size + sizeof(struct ofp_vxlan_udp_ip));
	ip_udp_vxlan->ip.ip_off = 0;
	ip_udp_vxlan->ip.ip_ttl = 2;
	ip_udp_vxlan->ip.ip_p = OFP_IPPROTO_UDP;

	ip_udp_vxlan->ip.ip_src.s_addr = 0;
	ip_udp_vxlan->ip.ip_dst.s_addr = gw;
	ip_udp_vxlan->ip.ip_sum = 0;

	odp_packet_l2_offset_set(pkt, 0);
	odp_packet_l3_offset_set(pkt, 0);

	return OFP_PKT_CONTINUE;
}

static int ofp_vxlan_alloc_shared_memory(void)
{
	shm = ofp_shared_memory_alloc(SHM_NAME_VXLAN, sizeof(*shm));
	if (shm == NULL) {
		OFP_ERR("Error: %s shared mem alloc failed on core: %u.\n",
			SHM_NAME_VXLAN, odp_cpu_id());
		return -1;
	}
	return 0;
}

static int ofp_vxlan_free_shared_memory(void)
{
	int rc = 0;

	if (ofp_shared_memory_free(SHM_NAME_VXLAN) == -1) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}

	shm = NULL;
	return rc;
}

void ofp_vxlan_init_prepare(void)
{
	ofp_shared_memory_prealloc(SHM_NAME_VXLAN, sizeof(*shm));
}

int ofp_vxlan_init_global(void)
{
	HANDLE_ERROR(ofp_vxlan_alloc_shared_memory());

	memset(shm, 0, sizeof(*shm));

	ofp_vxlan_timer = ofp_timer_start(VXLAN_TICK, ofp_vxlan_tmo, NULL, 0);
	if (ODP_TIMER_INVALID == ofp_vxlan_timer) {
		OFP_ERR("Failed to start VXLAN timer.");
		return -1;
	}
	return 0;
}

int ofp_vxlan_term_global(void)
{
	int rc = 0;

	if (ofp_vxlan_lookup_shared_memory())
		return -1;

	if (ofp_vxlan_timer != ODP_TIMER_INVALID) {
		if (ofp_timer_cancel(ofp_vxlan_timer)) {
			OFP_ERR("Failed to cancel VXLAN timer.");
			rc = -1;
		}
		ofp_vxlan_timer = ODP_TIMER_INVALID;
	}

	CHECK_ERROR(ofp_vxlan_free_shared_memory(), rc);

	return rc;
}

void ofp_vxlan_init_local(void)
{
}

void ofp_vxlan_term_local(void)
{
}

int ofp_vxlan_lookup_shared_memory(void)
{
	shm = ofp_shared_memory_lookup(SHM_NAME_VXLAN);
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}
	return 0;
}

int ofp_set_vxlan_interface_queue(void)
{
	odp_queue_param_t qparam;
	struct ofp_ifnet *ifnet = ofp_get_ifnet(VXLAN_PORTS, 0);

	/* VXLAN interface queue */
	odp_queue_param_init(&qparam);
	qparam.type = ODP_QUEUE_TYPE_SCHED;
	qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;

	ifnet->loopq_def = odp_queue_create("vxlan_loopq", &qparam);
	if (ifnet->loopq_def == ODP_QUEUE_INVALID) {
		OFP_ERR("odp_queue_create failed");
		return -1;
	}

	/* Set device loopq queue context */
	odp_queue_context_set(ifnet->loopq_def, ifnet, sizeof(ifnet));

	return 0;
}

int ofp_clean_vxlan_interface_queue(void)
{
	struct ofp_ifnet *ifnet = ofp_get_ifnet(VXLAN_PORTS, 0);

	if (ifnet == NULL) {
		OFP_ERR("Error: Failed to locate VXLAN port");
		return -1;
	}

	if (ifnet->loopq_def == ODP_QUEUE_INVALID) {
		OFP_ERR("Error: VXLAN port queue not initialized");
		return -1;
	}

	if (odp_queue_destroy(ifnet->loopq_def)) {
		OFP_ERR("Error: Failed to destroi VXLAN port queue");
		return -1;
	}

	return 0;
}

/*
 * Arp request to a vxlan interface comes from a physical interface.
 * After vxlan header removal it is put to vxlan input queue.
 * Vxlan device must be looked up while the output
 * device must be a physical interface. Vxlan doesn't use vlans.
 * Arp request's source mac address is saved to be used as a key
 * in MAC address to IP address hash table.
 */
void ofp_vxlan_update_devices(odp_packet_t pkt, struct ofp_arphdr *arp, uint16_t *vlan,
			      struct ofp_ifnet **dev, struct ofp_ifnet **outdev,
			      uint8_t *save_space)
{
	/* Find the vxlan device this message is destined to. */
	struct vxlan_user_data *saved = &ofp_packet_user_area(pkt)->vxlan;
	struct ofp_ifnet *vxdev = ofp_get_ifnet(VXLAN_PORTS, saved->vni);

	/* Sanity check. */
	if (vxdev && ofp_if_type(vxdev) == OFP_IFT_VXLAN) {
		*dev = vxdev;
		*outdev = ofp_get_ifnet(vxdev->physport, vxdev->physvlan);
		*vlan = 0;
		memcpy(save_space, arp->eth_src, OFP_ETHER_ADDR_LEN);
	}
}

/*
 * After vxlan header has been pulled out it is still in the buffer untouched.
 * Restore the header and update the addresses. Original destination can be
 * a multicast address that is not suitable for a source address.
 */
void ofp_vxlan_restore_and_update_header(odp_packet_t pkt,
					 struct ofp_ifnet *outdev,
					 uint8_t *saved_mac)
{
	struct ofp_ether_header *eth;
	struct ofp_ip *ip;

	/* Vxlan header pull length is saved in packet's user area. */
	struct vxlan_user_data *saved = &ofp_packet_user_area(pkt)->vxlan;
	/* Restore the original header. */
	eth = odp_packet_push_head(pkt, saved->hdrlen);

	/* Original dst mac can be a multicast address. Use valid addresses. */
	memcpy(eth->ether_dhost, eth->ether_shost, OFP_ETHER_ADDR_LEN);
	memcpy(eth->ether_shost, outdev->mac, OFP_ETHER_ADDR_LEN);

	/* Find ip header based on eth hdr type. */
	if (odp_be_to_cpu_16(eth->ether_type) == OFP_ETHERTYPE_VLAN)
		ip = (struct ofp_ip *)
			(((char *)eth) +
			 sizeof(struct ofp_ether_vlan_header));
	else
		ip = (struct ofp_ip *)
			(((char *)eth) +
			 sizeof(struct ofp_ether_header));

	ip->ip_dst.s_addr = ip->ip_src.s_addr;
	ip->ip_src.s_addr = outdev->ip_addr_info[0].ip_addr;
	ip->ip_sum = 0;
	ip->ip_sum = ofp_cksum_iph(ip, sizeof(*ip)>>2);

	/* Save MAC address to IP address information. */
	ofp_vxlan_set_mac_dst(saved_mac, ip->ip_dst.s_addr);
}

void ofp_vxlan_send_arp_request(odp_packet_t pkt, struct ofp_ifnet *dev)
{
	struct ofp_nh_entry nh;
	ofp_vxlan_prepend_hdr(pkt, dev, &nh);
	odp_packet_l2_offset_set(pkt, 0);
	odp_packet_l3_offset_set(pkt, 0);
	if (ofp_ip_output(pkt, nh.gw ? &nh : NULL) == OFP_PKT_DROP)
		odp_packet_free(pkt);
}

enum ofp_return_code ofp_ip_output_vxlan(odp_packet_t pkt,
					 struct ofp_ifnet *dev_out)
{
	struct ofp_nh_entry nh;
	struct ofp_nh_entry *nhp = NULL;

	/* Prepend packet with vxlan header */
	if (ofp_vxlan_prepend_hdr(pkt, dev_out, &nh) == OFP_PKT_DROP) {
		OFP_ERR("VXLAN: cannot prepend!");
		return OFP_PKT_DROP;
	}

	if (nh.gw)
		nhp = &nh;

	return ofp_ip_output_recurse(pkt, nhp);
}
