/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#include "ofpi_pkt_processing.h"

#ifndef _OFPI_RT_LOOKUP_H
#define _OFPI_RT_LOOKUP_H

#define OFP_RTL_ENOMEM ((void *) ofp_rtl_init)

#define OFP_RTL_MAXDEPTH   32
#define OFP_RTL64_MAXDEPTH 64

#define OFP_RTL_FLAGS_VALID_DATA      1
#define OFP_RTL_FLAGS_GATEWAY         2
#define OFP_RTL_FLAGS_MAC_ADDR        4
#define OFP_RTL_FLAGS_LOCAL_INTERFACE 8

#ifdef MTRIE
#define IPV4_LENGTH      32
#define IPV4_FIRST_LEVEL 16
#define IPV4_LEVEL       8

struct ofp_rt_rule {
	uint8_t used;
	union {
		struct {
			uint32_t addr;
			uint16_t vrf;
			uint8_t masklen;
			struct ofp_nh_entry data[1];
		} s1;
		struct ofp_rt_rule *next;
	} u1;
};

#endif


struct __attribute__((aligned (32))) ofp_rtl_node {
	uint32_t flags;
	struct ofp_nh_entry data[1];
#ifdef MTRIE
	uint8_t masklen;
	uint8_t root;
	uint16_t ref;
	struct ofp_rtl_node *next;
#else
	struct ofp_rtl_node *left;
	struct ofp_rtl_node *right;
#endif
};

struct ofp_rtl_tree {
	uint16_t vrf;
	struct ofp_rtl_node *root;
};

struct ofp_rtl_tailq {
	struct ofp_rtl_node *first;
	struct ofp_rtl_node *last;
};

struct ofp_rtl6_node {
	uint32_t flags;
	struct ofp_nh6_entry data;

	struct ofp_rtl6_node *left;
	struct ofp_rtl6_node *right;
};

struct ofp_rtl6_tree {
		struct ofp_rtl6_node *root;
};

extern int ofp_rtl_init(struct ofp_rtl_tree *tree);
extern int ofp_rtl_root_init(struct ofp_rtl_tree *tree, uint16_t vrf);
extern struct ofp_nh_entry *ofp_rtl_insert(struct ofp_rtl_tree *tree, uint32_t addr,
										   uint32_t masklen, struct ofp_nh_entry *data);
extern struct ofp_nh_entry *ofp_rtl_remove(struct ofp_rtl_tree *tree, uint32_t addr,
										   uint32_t masklen);
#ifdef MTRIE
extern int ofp_rt_rule_add(uint16_t vrf, uint32_t addr, uint32_t masklen, struct ofp_nh_entry *data);
extern int ofp_rt_rule_remove(uint16_t vrf, uint32_t addr, uint32_t masklen);
extern void ofp_rt_rule_print(int fd, uint16_t vrf,
					 void (*func)(int fd, uint32_t key, int level, struct ofp_nh_entry *data));
#else
extern struct ofp_nh_entry *ofp_rtl_search_exact(struct ofp_rtl_tree *tree,
								 uint32_t addr, uint32_t masklen);
extern void ofp_rtl_destroy(struct ofp_rtl_tree *tree,
							void (*func)(void *data));
extern void ofp_rtl_traverse(int fd, struct ofp_rtl_tree *tree,
							 void (*func)(int fd, uint32_t key, int level, struct ofp_nh_entry *data));
#endif
extern int ofp_rtl6_init(struct ofp_rtl6_tree *tree);
extern struct ofp_nh6_entry *ofp_rtl_insert6(struct ofp_rtl6_tree *tree, uint8_t *addr,
											uint32_t masklen, struct ofp_nh6_entry *data);
extern struct ofp_nh6_entry *ofp_rtl_remove6(struct ofp_rtl6_tree *tree, uint8_t *addr,
											uint32_t masklen);
extern void ofp_rtl_traverse6(int fd, struct ofp_rtl6_tree *tree,
							  void (*func)(int fd, uint8_t *key, int level, struct ofp_nh6_entry *data));
extern void ofp_print_rt_stat(int fd);
#ifndef MTRIE
static __inline struct ofp_nh_entry *ofp_rtl_search(struct ofp_rtl_tree *tree, uint32_t addr_be)
{
	struct ofp_rtl_node *node;
	uint32_t             mask = 0x80000000;
	uint32_t             addr = odp_be_to_cpu_32(addr_be);
	struct ofp_rtl_node *match_table[65];
	int                  matches;

	matches = 0;
	node = tree->root;
	while (node) {
		if (node->flags & OFP_RTL_FLAGS_VALID_DATA) {
			match_table[matches++] = node;
		}

		if (addr & mask) {
				node = node->right;
		} else {
				node = node->left;
		}
		mask >>= 1;
	}
	if (!matches)
		return NULL;

	return &(match_table[--matches]->data[0]);
}
#else
struct ofp_nh_entry *ofp_rtl_search(struct ofp_rtl_tree *tree, uint32_t addr_be);
struct ofp_rt_rule *ofp_rt_rule_find_prefix_match(uint16_t vrf, uint32_t addr,
						  uint8_t masklen, uint8_t low);
#endif

static inline int ofp_rt_bit_set(uint8_t *p, int bit)
{
	uint8_t r = 7 - (bit & 7);
	int i = bit >> 3;
	return p[i] & (1 << r);
}

static inline void ofp_rt_set_bit(uint8_t *p, int bit)
{
	uint8_t r = 7 - (bit & 7);
	int i = bit >> 3;
	p[i] |= (1 << r);
}

static inline void ofp_rt_reset_bit(uint8_t *p, int bit)
{
	uint8_t r = 7 - (bit & 7);
	int i = bit >> 3;
	p[i] &= ~(1 << r);
}

static inline struct ofp_rtl6_node*
ofp_rt_traverse_tree(struct ofp_rtl6_node *node, uint8_t *addr, uint32_t bit)
{
	return ofp_rt_bit_set(addr, bit) ? node->right : node->left;
}

static __inline struct ofp_nh6_entry *ofp_rtl_search6(struct ofp_rtl6_tree *tree, uint8_t *addr)
{
	struct ofp_rtl6_node *node;
	struct ofp_rtl6_node *match = NULL;
	uint32_t             bit = 0;

	for (node = tree->root; node; node = ofp_rt_traverse_tree(node, addr, bit++))
		if (node->flags & OFP_RTL_FLAGS_VALID_DATA)
			match = node;

	return match ? &match->data : NULL;
}

int ofp_rt_lookup_lookup_shared_memory(void);
void ofp_rt_lookup_init_prepare(void);
int ofp_rt_lookup_init_global(void);
int ofp_rt_lookup_term_global(void);

#endif /* _OFPI_RT_LOOKUP_H */
