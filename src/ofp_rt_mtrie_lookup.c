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
#include <odp_api.h>
#include "ofpi_rt_lookup.h"
#include "ofpi_log.h"
#include "ofpi_avl.h"

#define SHM_NAME_RT_LOOKUP_MTRIE	"OfpRtlookupMtrieShMem"

#define NUM_RT_RULES			global_param->mtrie.routes
#define NUM_NODES			global_param->mtrie.table8_nodes
#define NUM_NODES_LARGE			global_param->num_vrf

#define NUM_NODES_6			ROUTE6_NODES

#define SMALL_NODE (1<<IPV4_LEVEL)
#define LARGE_NODE (1<<IPV4_FIRST_LEVEL)
#define SIZEOF_SMALL_LIST (sizeof(struct ofp_rtl_node)*NUM_NODES*SMALL_NODE)
#define SIZEOF_LARGE_LIST (sizeof(struct ofp_rtl_node)*NUM_NODES_LARGE*LARGE_NODE)
#define SHM_SIZE_RT_LOOKUP_MTRIE					\
	(sizeof(*shm) +	SIZEOF_SMALL_LIST + SIZEOF_LARGE_LIST +		\
	 sizeof(struct ofp_rt_rule)*NUM_RT_RULES)

/*
 * Shared data
 */

struct ofp_rt_rule_table {
	struct ofp_rt_rule *rules;
	struct ofp_rt_rule *free_rule;
	uint32_t rule_allocated;
	uint32_t max_rule_allocated;
	avl_tree *rule_tree;
};

struct ofp_rt_lookup_mem {
	struct ofp_rtl_node *small_list;
	struct ofp_rtl_node *large_list;
	struct ofp_rtl_tailq free_small;
	struct ofp_rtl_node *free_large;

	struct ofp_rt_rule_table rt_rule_table;
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
		node->next = NULL;
		if (shm->free_small.last)
			shm->free_small.last->next = node;
		else
			shm->free_small.first = node;
		shm->free_small.last = node;
		shm->nodes_allocated--;
	}
}

static inline uint32_t to_network_prefix(uint32_t addr_be, uint32_t masklen);

static struct ofp_rtl_node *NODEALLOC(void)
{
	if (!shm)
		return NULL;

	struct ofp_rtl_node *rtl_node = shm->free_small.first;

	if (rtl_node) {
		shm->free_small.first = rtl_node->next;
		if (shm->free_small.first == NULL)
			shm->free_small.last = NULL;
		shm->nodes_allocated++;

		if (shm->nodes_allocated > shm->max_nodes_allocated)
			shm->max_nodes_allocated = shm->nodes_allocated;

		rtl_node->root = 0;
		rtl_node->ref = 0;
		rtl_node->next = NULL;
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

static int rt_rules_avl_compare(void *compare_arg, void *a, void *b)
{
	(void) compare_arg;
	struct ofp_rt_rule *a1 = a;
	struct ofp_rt_rule *b1 = b;

	/*
	 * vrf is most significant factor so that rules with the same
	 * vrf appear together in the avl inorder traversal
	 * thus more efficient when walking through all rules given a vrf
	 */
	if (a1->u1.s1.vrf > b1->u1.s1.vrf)
		return 1;
	else if (a1->u1.s1.vrf < b1->u1.s1.vrf)
		return -1;
	else if (a1->u1.s1.addr > b1->u1.s1.addr)
		return 1;
	else if (a1->u1.s1.addr < b1->u1.s1.addr)
		return -1;
	else if (a1->u1.s1.masklen > b1->u1.s1.masklen)
		return 1;
	else if (a1->u1.s1.masklen < b1->u1.s1.masklen)
		return -1;
	else
		return 0;
}

static struct ofp_rt_rule*
ofp_rt_rule_search(uint16_t vrf, uint32_t addr_be, uint32_t masklen)
{
	struct ofp_rt_rule key, *rule = NULL;

	key.u1.s1.vrf = vrf;
	key.u1.s1.addr = to_network_prefix(addr_be, masklen);
	key.u1.s1.masklen = masklen;
	avl_get_by_key(shm->rt_rule_table.rule_tree, &key, (void **)&rule);

	return rule;
}

static void rt_rule_free(struct ofp_rt_rule *rule)
{
	rule->used = 0;
	rule->u1.next = shm->rt_rule_table.free_rule;
	shm->rt_rule_table.free_rule = rule;
	shm->rt_rule_table.rule_allocated--;
}

static struct ofp_rt_rule *rt_rule_alloc(void)
{
	if (!shm)
		return NULL;

	struct ofp_rt_rule *rule = shm->rt_rule_table.free_rule;

	if (rule) {
		shm->rt_rule_table.free_rule = rule->u1.next;
		shm->rt_rule_table.rule_allocated++;
		rule->used = 1;

		if (shm->rt_rule_table.rule_allocated >
		    shm->rt_rule_table.max_rule_allocated) {
			shm->rt_rule_table.max_rule_allocated =
				shm->rt_rule_table.rule_allocated;
		}
	}

	return rule;
}

int ofp_rt_rule_add(uint16_t vrf, uint32_t addr_be, uint32_t masklen, struct ofp_nh_entry *data)
{
	struct ofp_rt_rule *rule = NULL;

	if ((rule = ofp_rt_rule_search(vrf, addr_be, masklen)) != NULL) {
		rule->u1.s1.data[0] = *data;
		OFP_INFO("ofp_rt_rule_add updated existing rule vrf %u %s/%u",
			rule->u1.s1.vrf,
			ofp_print_ip_addr(odp_cpu_to_be_32(rule->u1.s1.addr)),
			rule->u1.s1.masklen);
		return -1;
	}

	if ((rule = rt_rule_alloc()) == NULL) {
		OFP_ERR("ofp_rt_rule_add allocation failed rule allocated %u/%u",
			shm->rt_rule_table.rule_allocated, NUM_RT_RULES);
		return -1;
	}

	/*
	 * note that the incoming addr_be is masked and we store cpu-endian
	 * in the rule table
	 */
	rule->u1.s1.masklen = masklen;
	rule->u1.s1.addr = to_network_prefix(addr_be, masklen);
	rule->u1.s1.vrf = vrf;
	rule->u1.s1.data[0] = *data;

	if (avl_insert(shm->rt_rule_table.rule_tree, rule) != 0) {
		rt_rule_free(rule);
		OFP_ERR("ofp_rt_rule_add avl insertion failed");
		return -1;
	}

	OFP_INFO("ofp_rt_rule_add inserted new rule vrf %u prefix %s/%u",
		 rule->u1.s1.vrf,
		 ofp_print_ip_addr(odp_cpu_to_be_32(rule->u1.s1.addr)),
		 rule->u1.s1.masklen);

	return 0;
}

int ofp_rt_rule_remove(uint16_t vrf, uint32_t addr_be, uint32_t masklen)
{
	struct ofp_rt_rule *rule = NULL;

	if ((rule = ofp_rt_rule_search(vrf, addr_be, masklen)) == NULL) {
		OFP_ERR("ofp_rt_rule_remove rule vrf %u %s/%u not exist", vrf,
			ofp_print_ip_addr(addr_be), masklen);
		return -1;
	}

	avl_delete(shm->rt_rule_table.rule_tree, rule, NULL);

	OFP_INFO("ofp_rt_rule_remove removed rule vrf %u %s/%u", rule->u1.s1.vrf,
		 ofp_print_ip_addr(odp_cpu_to_be_32(rule->u1.s1.addr)),
		 rule->u1.s1.masklen);

	rt_rule_free(rule);

	return 0;
}


struct ofp_rt_rule_vrf_iter_arg_st {
	int (*func)(void *key, void *iter_arg);
	void *iter_arg;
};

static int ofp_rt_rule_iter_helper(unsigned long index, void *key, void *iter_arg)
{
	(void)index;
	struct ofp_rt_rule_vrf_iter_arg_st *vrf_iter = iter_arg;

	return vrf_iter->func(key, vrf_iter->iter_arg);
}

static void ofp_rt_rule_vrf_iter(uint16_t vrf,
				 int (*func)(void *key, void *iter_arg),
				 void *iter_arg)
{
	struct ofp_rt_rule_vrf_iter_arg_st vrf_iter = {func, iter_arg};
	struct ofp_rt_rule key, *rule;
	unsigned long low_index, high_index, tmp_index;

	/*
	 * we iterate the section corresponding to the given vrf
	 * instead of whole tree
	 */

	/* get the low index and high index of the section to be iterated */
	key.u1.s1.vrf = vrf;
	key.u1.s1.addr = 0;
	key.u1.s1.masklen = 0;
	if (avl_get_item_by_key_least(shm->rt_rule_table.rule_tree,
				     &key, (void **)&rule) == -1) {
		OFP_WARN("1 ofp_rt_rule_print no rule for vrf %u", vrf);
		return;
	}
	if (rule->u1.s1.vrf != vrf) {
		OFP_WARN("2 ofp_rt_rule_print no rule for vrf %u", vrf);
		return;
	}
	avl_get_span_by_key(shm->rt_rule_table.rule_tree, rule, &low_index, &tmp_index);

	key.u1.s1.vrf = vrf;
	key.u1.s1.addr = 0xFFFFFFFF;
	key.u1.s1.masklen = 32;
	if (avl_get_item_by_key_most(shm->rt_rule_table.rule_tree,
				    &key, (void **)&rule) == -1) {
		OFP_WARN("3 ofp_rt_rule_print no rule for vrf %u", vrf);
		return;
	}
	if (rule->u1.s1.vrf != vrf) {
		/* would never be in this branch */
		OFP_WARN("ofp_rt_rule_print no rule for vrf %u", vrf);
		return;
	}
	avl_get_span_by_key(shm->rt_rule_table.rule_tree, rule,
			    &high_index, &tmp_index);

	/*
	 * do the iteration over the particular section, note the argument high of
	 * the API is the one following the last iterated elements
	 */
	OFP_DBG("ofp_rt_rule_print iterate from index %lu to %lu for vrf %u",
		low_index, high_index, vrf);
	avl_iterate_index_range(shm->rt_rule_table.rule_tree, ofp_rt_rule_iter_helper,
				low_index, high_index+1, &vrf_iter);

}

struct ofp_rt_rule_print_iter_arg_st {
	void (*func)(int fd, uint32_t key, int level, struct ofp_nh_entry *data);
	int32_t fd;
};

static int ofp_rt_rule_print_iter(void *key, void *iter_arg)
{
	struct ofp_rt_rule_print_iter_arg_st *print_iter_arg = iter_arg;
	struct ofp_rt_rule *rule = key;

	print_iter_arg->func(print_iter_arg->fd, rule->u1.s1.addr,
			     rule->u1.s1.masklen, &rule->u1.s1.data[0]);
	/*return 0 to continue with the iteration*/
	return 0;
}

void ofp_rt_rule_print(int fd, uint16_t vrf,
		       void (*func)(int fd, uint32_t key, int level, struct ofp_nh_entry *data))
{
	struct ofp_rt_rule_print_iter_arg_st print_arg = {func, fd};

	ofp_rt_rule_vrf_iter(vrf, ofp_rt_rule_print_iter, (void *)&print_arg);
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

struct ofp_rt_rule*
ofp_rt_rule_find_prefix_match(uint16_t vrf, uint32_t addr,
			      uint8_t masklen, uint8_t low)
{
	uint8_t mask = masklen - 1;
	struct ofp_rt_rule *rule = NULL;
	uint32_t addr_be;

	addr_be = odp_cpu_to_be_32(addr);
	while (rule == NULL && mask > low) {
		rule = ofp_rt_rule_search(vrf, addr_be, mask);
		mask--;
	}

	return rule;
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
	return (odp_be_to_cpu_32(addr_be)) & (0xFFFFFFFFULL << (32 - masklen));
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

struct ofp_nh_entry *
ofp_rtl_remove(struct ofp_rtl_tree *tree, uint32_t addr_be, uint32_t masklen)
{
	struct ofp_rtl_node *elem, *node = tree->root;
	const uint32_t addr = to_network_prefix(addr_be, masklen);
	struct ofp_nh_entry *data;
	struct ofp_rt_rule *removing_rule;
	struct ofp_rt_rule *insert_rule = NULL;
	uint32_t low = 0, high = IPV4_FIRST_LEVEL;

	removing_rule = ofp_rt_rule_search(tree->vrf, addr_be, masklen);
	if (removing_rule == NULL) {
		OFP_WARN("ofp_rtl_remove no rule found for vrf %u addr %s masklen %u",
			 tree->vrf, ofp_print_ip_addr(addr_be), masklen);
		return NULL;
	}
	data = &removing_rule->u1.s1.data[0];

	for (; high <= IPV4_LENGTH ; low = high, high += IPV4_LEVEL) {
		dec_use_reference(node);

		if (masklen <= high) {
			uint32_t index = ip_range_begin(addr, masklen, low, high);
			uint32_t index_end = ip_range_end(addr, masklen, low, high);

			for (; index < index_end; index++) {
				if (node[index].masklen == masklen &&
				    !memcmp(&node[index].data, data,
					    sizeof(struct ofp_nh_entry))) {
					if (node[index].next == NULL &&
						&node[index] != shm->free_small.last)
						node[index].masklen = 0;
					else
						node[index].masklen = high + 1;
				}
			}
			/* if exists, re-insert previous route that was overwritten, after cleanup*/
			insert_rule = ofp_rt_rule_find_prefix_match(tree->vrf, addr,
														masklen, low);
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

	if (insert_rule != NULL)
		ofp_rtl_insert(tree,
			       odp_cpu_to_be_32(insert_rule->u1.s1.addr),
			       insert_rule->u1.s1.masklen,
			       &insert_rule->u1.s1.data[0]);

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

	if (node) {
		if (node->flags == OFP_RTL_FLAGS_VALID_DATA) {
			return &node->data;
		} else {
			node->flags = OFP_RTL_FLAGS_VALID_DATA;
			node->data = *data;
			return NULL;
		}
	}

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
	ofp_sendf(fd, "rt rule alloc now=%d max=%d total=%d\r\n",
			  shm->rt_rule_table.rule_allocated,
			  shm->rt_rule_table.max_rule_allocated, NUM_RT_RULES);
}

static int ofp_rt_lookup_alloc_shared_memory(void)
{
	shm = ofp_shared_memory_alloc(SHM_NAME_RT_LOOKUP_MTRIE, SHM_SIZE_RT_LOOKUP_MTRIE);
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

void ofp_rt_lookup_init_prepare(void)
{
	ofp_shared_memory_prealloc(SHM_NAME_RT_LOOKUP_MTRIE, SHM_SIZE_RT_LOOKUP_MTRIE);
}

int ofp_rt_lookup_init_global(void)
{
	int i;

	HANDLE_ERROR(ofp_rt_lookup_alloc_shared_memory());

	memset(shm, 0, SHM_SIZE_RT_LOOKUP_MTRIE);

	shm->small_list = (struct ofp_rtl_node *)((char *)shm+sizeof(*shm));
	shm->large_list = (struct ofp_rtl_node *)((char *)shm->small_list+SIZEOF_SMALL_LIST);
	shm->rt_rule_table.rules = (struct ofp_rt_rule *)((char *)shm->large_list+SIZEOF_LARGE_LIST);

	for (i = 0; i < NUM_NODES; i++)
		shm->small_list[i * SMALL_NODE].next = (i == NUM_NODES - 1) ?
			NULL : &(shm->small_list[(i + 1) * SMALL_NODE]);
	shm->free_small.first = &shm->small_list[0];
	shm->free_small.last = &shm->small_list[(NUM_NODES - 1) * SMALL_NODE];

	for (i = 0; i < NUM_NODES_LARGE; i++)
		shm->large_list[i * LARGE_NODE].next = (i == NUM_NODES_LARGE - 1) ?
			NULL : &(shm->large_list[(i + 1) * LARGE_NODE]);
	shm->free_large = shm->large_list;

	for (i = 0; i < NUM_NODES_6; i++) {
		shm->node_list6[i].left = (i == 0) ?
			NULL : &(shm->node_list6[i-1]);
		shm->node_list6[i].right = (i == NUM_NODES_6 - 1) ?
			NULL : &(shm->node_list6[i+1]);
	}
	shm->free_nodes6 = &(shm->node_list6[0]);

	for (i = 0; i < NUM_RT_RULES; i++)
		shm->rt_rule_table.rules[i].u1.next = (i == NUM_RT_RULES - 1) ?
			NULL : &(shm->rt_rule_table.rules[i+1]);
	shm->rt_rule_table.free_rule = &(shm->rt_rule_table.rules[0]);
	shm->rt_rule_table.rule_tree = avl_tree_new(rt_rules_avl_compare, NULL);

	return 0;
}

int ofp_rt_lookup_term_global(void)
{
	int rc = 0;

	if (ofp_rt_lookup_lookup_shared_memory())
		return -1;

	avl_tree_free(shm->rt_rule_table.rule_tree, NULL);
	CHECK_ERROR(ofp_rt_lookup_free_shared_memory(), rc);

	return rc;
}
