/* Copyright (c) 2015, ENEA Software AB
 * Copyright (c) 2015, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

/*
 *
 * MTRIE data structure contains forwarding information.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "ofpi_util.h"
#include "ofpi.h"
#include "odp.h"
#include "ofpi_rt_lookup.h"
#include "ofpi_log.h"

#define SHM_NAME_RT_LOOKUP_MTRIE	"OfpRtlookupMtrieShMem"

#define ROUTE_LIST_SIZE			ROUTE4_RULE_LIST_SIZE
#define NUM_NODES			ROUTE4_MTRIE8_TABLE_NODES
#define NUM_NODES_LARGE			ROUTE4_MTRIE16_TABLE_NODES

#define NUM_NODES_6			ROUTE6_NODES

/*
 * Shared data
 */
struct ofp_rt_lookup_mem {
	struct ofp_rtl_node small_list[NUM_NODES][1<<IPV4_LEVEL];
	struct ofp_rtl_node large_list[NUM_NODES_LARGE][1<<IPV4_FIRST_LEVEL];
	struct ofp_rtl_node *free_small;
	struct ofp_rtl_node *free_large;

	struct ofp_rt_rule rules[ROUTE_LIST_SIZE];
	int nodes_allocated, max_nodes_allocated;

	struct ofp_rtl6_node *global_stack6[129];
	struct ofp_rtl6_node node_list6[NUM_NODES_6];
	struct ofp_rtl6_node *free_nodes6;
	int nodes_allocated6, max_nodes_allocated6;
};

/*
 * Data per core
 */
static __thread struct ofp_rt_lookup_mem *shm;

static void NODEFREE(struct ofp_rtl_node *node)
{
	if (node->root == 0) {
		node->next = shm->free_small;
		shm->free_small = node;
		shm->nodes_allocated--;
	}
}

static struct ofp_rtl_node *NODEALLOC(void)
{
	if (!shm)
		return NULL;

	struct ofp_rtl_node *rtl_node = shm->free_small;

	if (rtl_node) {
		shm->free_small = rtl_node->next;
		shm->nodes_allocated++;

		if (shm->nodes_allocated > shm->max_nodes_allocated)
			shm->max_nodes_allocated = shm->nodes_allocated;

		rtl_node->root = 0;
		rtl_node->ref = 0;
	}

	return rtl_node;
}

int ofp_rtl_init(struct ofp_rtl_tree *tree)
{
	return ofp_rtl_root_init(tree, 0);
}

int ofp_rtl_root_init(struct ofp_rtl_tree *tree, uint16_t vrf)
{
	tree->root = shm->free_large;
	if (shm->free_large)
		shm->free_large = shm->free_large->next;

	if (!tree->root) {
		OFP_ERR("Allocation failed");
		return -1;
	}

	tree->root->flags = 0;
	tree->root->next = NULL;
	tree->root->root = 1;
	tree->root->ref = 0;
	tree->vrf = vrf;

	return 0;
}

static void NODEFREE6(struct ofp_rtl6_node *node)
{
	node->left = NULL;
	node->right = shm->free_nodes6;
	if (shm->free_nodes6) shm->free_nodes6->left = node;
	shm->free_nodes6 = node;
	shm->nodes_allocated6--;
}

static struct ofp_rtl6_node *NODEALLOC6(void)
{
	struct ofp_rtl6_node *p = shm->free_nodes6;
	if (shm->free_nodes6) {
		shm->free_nodes6->left = NULL;
		shm->free_nodes6 = shm->free_nodes6->right;
		shm->nodes_allocated6++;
		if (shm->nodes_allocated6 > shm->max_nodes_allocated6)
			shm->max_nodes_allocated6 = shm->nodes_allocated6;
	}
	return p;
}

int ofp_rtl6_init(struct ofp_rtl6_tree *tree)
{
	tree->root = NODEALLOC6();
	if (!tree->root) {
		OFP_ERR("Allocation failed");
		return -1;
	}

	tree->root->flags = 0;
	tree->root->left = NULL;
	tree->root->right = NULL;

	return 0;
}


static int16_t ofp_rt_rule_search(uint16_t vrf, uint32_t addr, uint32_t masklen)
{
	uint32_t index;

	for (index = 0; index < ROUTE_LIST_SIZE; index++)
		if (shm->rules[index].used &&
		    shm->rules[index].vrf == vrf &&
		    shm->rules[index].addr == addr &&
		    shm->rules[index].masklen == masklen)
			return index;

	return -1;
}

static int32_t find_first_unused_rule(void)
{
	uint32_t index;

	for (index = 0; index < ROUTE_LIST_SIZE; ++index)
		if (shm->rules[index].used == 0)
			return index;

	return -1;
}

void ofp_rt_rule_add(uint16_t vrf, uint32_t addr, uint32_t masklen, struct ofp_nh_entry *data)
{
	int32_t reserved;

	if ((reserved = ofp_rt_rule_search(vrf, addr, masklen)) == -1 &&
	    (reserved = find_first_unused_rule()) == -1) {
		OFP_ERR("ofp_rt_rule_search failed");
		return;
	}

	shm->rules[reserved].used = 1;
	shm->rules[reserved].masklen = masklen;
	shm->rules[reserved].addr = addr;
	shm->rules[reserved].vrf = vrf;
	shm->rules[reserved].data[0] = *data;
}

void ofp_rt_rule_remove(uint16_t vrf, uint32_t addr, uint32_t masklen)
{
	int32_t reserved = ofp_rt_rule_search(vrf, addr, masklen);

	if (reserved == -1) {
		OFP_ERR("ofp_rt_rule_search failed");
		return;
	}

	shm->rules[reserved].used = 0;
}

void ofp_rt_rule_print(int fd, uint16_t vrf,
		       void (*func)(int fd, uint32_t key, int level, struct ofp_nh_entry *data))
{
	uint32_t index;

	for (index = 0; index < ROUTE_LIST_SIZE; index++)
		if (shm->rules[index].used && shm->rules[index].vrf == vrf)
			func(fd, odp_be_to_cpu_32(shm->rules[index].addr),
			     shm->rules[index].masklen,
			     &shm->rules[index].data[0]);
}

static inline uint32_t
shift_least_significant_bits(uint32_t addr, uint32_t masklen)
{
	return (addr >> (IPV4_LENGTH - masklen));
}

static inline int
equal_most_significant_bits(uint32_t addr_lhs, uint32_t addr_rhs, uint32_t masklen)
{
	return shift_least_significant_bits(addr_lhs, masklen) ==
	       shift_least_significant_bits(addr_rhs, masklen);
}

int32_t ofp_rt_rule_find_prefix_match(uint16_t vrf, uint32_t addr, uint8_t masklen, uint8_t low)
{
	uint32_t index;
	uint8_t low_int = low + 1;
	int32_t reserved = -1;
	struct ofp_rt_rule *rule;

	for (index = 0; index < ROUTE_LIST_SIZE; index++) {
		rule = &shm->rules[index];

		if (rule->vrf == vrf &&
		    rule->masklen >= low_int &&
		    rule->masklen <= masklen &&
		    equal_most_significant_bits(rule->addr, addr, masklen))
		{
		/* search route rule with prefix_len in the same interval,
		 * largest prefix_len that is smaller or equal than what we
		 * removed, same route ipv4 address prefix */
			low_int = rule->masklen;
			reserved = index;
		}
	}
	return reserved;
}


static inline uint32_t get_use_reference(struct ofp_rtl_node *node)
{
	return node->ref;
}

static inline void inc_use_reference(struct ofp_rtl_node *node)
{
	node->ref++;
}

static inline void dec_use_reference(struct ofp_rtl_node *node)
{
	if (--node->ref == 0)
		NODEFREE(node);
}

static inline uint32_t to_network_prefix(uint32_t addr_be, uint32_t masklen)
{
	return (odp_be_to_cpu_32(addr_be)) & ((~0) << (32 - masklen));
}

static inline uint32_t
ip_range_helper(uint32_t addr, uint32_t masklen, uint32_t low, uint32_t high)
{
	return (addr << (IPV4_LENGTH - masklen + low)
		     >> (low + IPV4_LENGTH - high));
}

static inline uint32_t
ip_range_begin(uint32_t addr, uint32_t masklen, uint32_t low, uint32_t high)
{
	return ip_range_helper(shift_least_significant_bits(addr, masklen),
			       masklen, low, high);
}

static inline uint32_t
ip_range_end(uint32_t addr, uint32_t masklen, uint32_t low, uint32_t high)
{
	const uint32_t end = ip_range_helper(
		shift_least_significant_bits(addr, masklen) + 1,
		masklen, low, high);
	return end ? end : 1U << (high - low);
}

static inline struct ofp_rtl_node *
find_node(struct ofp_rtl_node *node, uint32_t addr, uint32_t low, uint32_t high)
{
	return &node[(addr << low) >> (low + IPV4_LENGTH - high)];
}

struct ofp_nh_entry *
ofp_rtl_insert(struct ofp_rtl_tree *tree, uint32_t addr_be,
			   uint32_t masklen, struct ofp_nh_entry *data)
{
	struct ofp_rtl_node *node = tree->root;
	uint32_t addr = to_network_prefix(addr_be, masklen);
	uint32_t low = 0, high = IPV4_FIRST_LEVEL;

	for (; high <= IPV4_LENGTH; low = high, high += IPV4_LEVEL) {
		inc_use_reference(node);

		if (masklen <= high) {
			uint32_t index = ip_range_begin(addr, masklen, low, high);
			uint32_t index_end = ip_range_end(addr, masklen, low, high);

			for (; index < index_end; index++) {
				if (node[index].masklen <= masklen || node[index].masklen > high) {
					node[index].data[0] = *data;
					node[index].masklen = masklen;
				}
			}
			break;
		}

		node = find_node(node, addr, low, high);

		if (node->next == NULL && !(node->next = NODEALLOC())) {
			OFP_ERR("NODEALLOC failed!");
			return data;
		}

		if (node->masklen == 0)
			node->masklen = masklen;

		node = node->next;
	}

	return NULL;
}

static inline struct ofp_nh_entry *
find_data(uint16_t vrf, uint32_t addr_be, uint32_t masklen)
{
	int32_t reserved = ofp_rt_rule_search(vrf, addr_be, masklen);

	if (reserved == -1)
		return NULL;

	return &shm->rules[reserved].data[0];
}

struct ofp_nh_entry *
ofp_rtl_remove(struct ofp_rtl_tree *tree, uint32_t addr_be, uint32_t masklen)
{
	struct ofp_rtl_node *elem, *node = tree->root;
	const uint32_t addr = to_network_prefix(addr_be, masklen);
	struct ofp_nh_entry *data = find_data(tree->vrf, addr_be, masklen);
	uint32_t low = 0, high = IPV4_FIRST_LEVEL;
	int32_t insert = -1;

	if (!data)
		return NULL;

	for (; high <= IPV4_LENGTH ; low = high, high += IPV4_LEVEL) {
		dec_use_reference(node);

		if (masklen <= high) {
			uint32_t index = ip_range_begin(addr, masklen, low, high);
			uint32_t index_end = ip_range_end(addr, masklen, low, high);

			for (; index < index_end; index++) {
				if (node[index].masklen == masklen &&
				    !memcmp(&node[index].data, data,
					    sizeof(struct ofp_nh_entry))) {
					if (node[index].next == NULL)
						node[index].masklen = 0;
					else
						node[index].masklen = high + 1;
				}
			}
			/* if exists, re-insert previous route that was overwritten, after cleanup*/
			insert = ofp_rt_rule_find_prefix_match(tree->vrf, addr, masklen, low);
			break;
		}

		elem = find_node(node, addr, low, high);

		if (elem->masklen == 0)
			return NULL;

		node = elem->next;

		if (get_use_reference(node) == 1 && elem->masklen > high) {
			/* next level will be freed so we update prefix_len to 0,
			 * if there is no leaf stored on the current elem */
			elem->masklen = 0;
			elem->next = NULL;
		}
	}
	odp_mb_release();

	if (insert != -1)
		ofp_rtl_insert(tree,
				shm->rules[insert].addr,
				shm->rules[insert].masklen,
				&shm->rules[insert].data[0]);

	return data;
}


struct ofp_nh_entry *ofp_rtl_search(struct ofp_rtl_tree *tree, uint32_t addr_be)
{
	struct ofp_nh_entry *nh = NULL;
	struct ofp_rtl_node *elem, *node = tree->root;
	uint32_t addr = odp_be_to_cpu_32(addr_be);
	uint32_t low = 0, high = IPV4_FIRST_LEVEL;

	for (; high <= IPV4_LENGTH ; low = high, high += IPV4_LEVEL) {
		elem = find_node(node, addr, low, high);

		if (elem->masklen == 0)
			return nh;
		else if (elem->masklen <= high)
			nh = &elem->data[0];

		if ((node = elem->next) == NULL)
			return nh;
	}

	return nh;
}

struct ofp_nh6_entry *
ofp_rtl_insert6(struct ofp_rtl6_tree *tree, uint8_t *addr,
				uint32_t masklen, struct ofp_nh6_entry *data)
{
	struct ofp_rtl6_node  *node;
	struct ofp_rtl6_node  *last = NULL;
	uint32_t	      depth;
	uint32_t	      bit = 0;

	depth = 0;
	node = tree->root;
	while (depth < masklen && node) {
		last = node;
		if (ofp_rt_bit_set(addr, bit)) {
			node = node->right;
		} else {
			node = node->left;
		}
		depth++;
		bit++;
	}

	if (node)
		return &node->data;

	node = NODEALLOC6();
	if (!node) {
		OFP_ERR("NODEALLOC6 failed!");
		return data;
	}

	memset(node, 0, sizeof(*node));

	node->left = NULL;
	node->right = NULL;
	node->flags = OFP_RTL_FLAGS_VALID_DATA;
	node->data = *data;

	bit = masklen - 1;
	while (depth < masklen) {
		struct ofp_rtl6_node *tmp;

		tmp = NODEALLOC6();
		if (!tmp)
			goto nomem;
		memset(tmp, 0, sizeof(*tmp));

		if (ofp_rt_bit_set(addr, bit)) {
			tmp->right = node;
			tmp->left = NULL;
		} else {
			tmp->left = node;
			tmp->right = NULL;
		}
		node = tmp;
		bit--;
		depth++;
	}

	if (!last) {
		OFP_ERR("!last");
		return data;
	}

	if (ofp_rt_bit_set(addr, bit)) {
		last->right = node;
	} else {
		last->left = node;
	}

	return NULL;

 nomem:
	while(node) {
		struct ofp_rtl6_node *tmp;

		bit++;
		if (ofp_rt_bit_set(addr, bit)) {
			tmp = node->right;
			NODEFREE6(node);
		} else {
			tmp = node->left;
			NODEFREE6(node);
		}
		node = tmp;
	}

	return data;
}

struct ofp_nh6_entry *
ofp_rtl_remove6(struct ofp_rtl6_tree *tree, uint8_t *addr, uint32_t masklen)
{
	struct ofp_rtl6_node  *node;
	struct ofp_rtl6_node **stack = shm->global_stack6;
	uint32_t	       depth;
	void		  *data;
	int		    bit = 0;

	depth = 0;
	node = tree->root;
	while (depth < masklen && node) {
		stack[depth] = node;
		if (ofp_rt_bit_set(addr, bit)) {
			node = node->right;
		} else {
			node = node->left;
		}
		depth++;
		bit++;
	}

	if (!node || !(node->flags & OFP_RTL_FLAGS_VALID_DATA))
		return NULL;

	data = &node->data;
	node->flags = 0;

	if (node->left || node->right) {
		return data;
	}

	if (!depth)
		return data;

	NODEFREE6(node);

	bit = masklen - 1;
	depth--;
	do {
		if (ofp_rt_bit_set(addr, bit)) {
			stack[depth]->right = NULL;
			if (stack[depth]->left || (stack[depth]->flags & OFP_RTL_FLAGS_VALID_DATA)) {
				break;
			}
		} else {
			stack[depth]->left = NULL;
			if (stack[depth]->right || (stack[depth]->flags & OFP_RTL_FLAGS_VALID_DATA)) {
				break;
			}
		}

		if (depth == 0)
			break;

		NODEFREE6(stack[depth]);
		depth--;
		bit--;
	} while (1);

	return data;
}

void ofp_rtl_traverse6(int fd, struct ofp_rtl6_tree *tree,
					   void (*func)(int fd, uint8_t *key, int level, struct ofp_nh6_entry *data))
{
	char key[16];
	memset(key, 0, sizeof(key));
#define VISITED_LEFT  1
#define VISITED_RIGHT 2
	char visited[129];
	struct ofp_rtl6_node *stack[129];
	struct ofp_rtl6_node *node = tree->root;
	int depth = 0;

	memset(key, 0, sizeof(key));
	memset(visited, 0, sizeof(visited));

	for (;;) {
		if (func && (node->flags & OFP_RTL_FLAGS_VALID_DATA) && visited[depth] == 0) {
			func(fd, (uint8_t*)key, depth, &(node->data));
		}

		stack[depth] = node;
		if (node->left && (visited[depth] & VISITED_LEFT) == 0) {
			node = node->left;
			ofp_rt_reset_bit((uint8_t*)key, depth);
			visited[depth++] = VISITED_LEFT;
		} else if (node->right && (visited[depth] & VISITED_RIGHT) == 0) {
			node = node->right;
			ofp_rt_set_bit((uint8_t*)key, depth);
			visited[depth++] |= VISITED_RIGHT;
		} else {
			visited[depth] = 0;
			ofp_rt_reset_bit((uint8_t*)key, depth);
			depth--;
			if (depth < 0)
				break;
			node = stack[depth];
		}
	}
}

void ofp_print_rt_stat(int fd)
{
	ofp_sendf(fd, "rt tree alloc now=%d max=%d total=%d\r\n",
			  shm->nodes_allocated, shm->max_nodes_allocated, NUM_NODES);
	ofp_sendf(fd, "rt6 tree alloc now=%d max=%d total=%d\r\n",
			  shm->nodes_allocated6, shm->max_nodes_allocated6, NUM_NODES_6);
}

static int ofp_rt_lookup_alloc_shared_memory(void)
{
	shm = ofp_shared_memory_alloc(SHM_NAME_RT_LOOKUP_MTRIE, sizeof(*shm));
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}
	return 0;
}

static int ofp_rt_lookup_free_shared_memory(void)
{
	int rc = 0;

	if (ofp_shared_memory_free(SHM_NAME_RT_LOOKUP_MTRIE) == -1) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}
	shm = NULL;
	return rc;
}

int ofp_rt_lookup_lookup_shared_memory(void)
{
	shm = ofp_shared_memory_lookup(SHM_NAME_RT_LOOKUP_MTRIE);
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}

	return 0;
}

int ofp_rt_lookup_init_global(void)
{
	int i;

	HANDLE_ERROR(ofp_rt_lookup_alloc_shared_memory());

	memset(shm, 0, sizeof(*shm));

	for (i = 0; i < NUM_NODES; i++)
		shm->small_list[i][0].next = (i == NUM_NODES - 1) ?
			NULL : &(shm->small_list[i+1][0]);
	shm->free_small = shm->small_list[0];

	for (i = 0; i < NUM_NODES_LARGE; i++)
		shm->large_list[i][0].next = (i == NUM_NODES_LARGE - 1) ?
			NULL : &(shm->large_list[i+1][0]);
	shm->free_large = shm->large_list[0];

	for (i = 0; i < NUM_NODES_6; i++) {
		shm->node_list6[i].left = (i == 0) ?
			NULL : &(shm->node_list6[i-1]);
		shm->node_list6[i].right = (i == NUM_NODES_6 - 1) ?
			NULL : &(shm->node_list6[i+1]);
	}
	shm->free_nodes6 = &(shm->node_list6[0]);

	return 0;
}

int ofp_rt_lookup_term_global(void)
{
	int rc = 0;

	if (ofp_rt_lookup_lookup_shared_memory())
		return -1;

	CHECK_ERROR(ofp_rt_lookup_free_shared_memory(), rc);

	return rc;
}
