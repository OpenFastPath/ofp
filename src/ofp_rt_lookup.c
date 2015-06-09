/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

/** \file
 * \anchor rt_lookup
 *
 * Radix tree contains all the routing data for the simple executive.
 * Data has two types:
 * - MAC addresses
 * - Gateway addresses
 *
 * For a given address the first hit may be a gateway address, whose
 * MAC address is looked up using a second lookup.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "ofpi_util.h"
#include "ofpi.h"
#include "odp/rwlock.h"
#include "ofpi_rt_lookup.h"
#include "ofpi_log.h"

/*
 * Shared data
 */
struct ofp_rt_lookup_mem {
	struct ofp_rtl_node *global_stack[65];
#define NUM_NODES 65536
	struct ofp_rtl_node node_list[NUM_NODES];
	struct ofp_rtl_node *free_nodes;
	int nodes_allocated, max_nodes_allocated;

	struct ofp_rtl6_node *global_stack6[129];
#define NUM_NODES_6 65536
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
	node->left = NULL;
	node->right = shm->free_nodes;
	if (shm->free_nodes) shm->free_nodes->left = node;
	shm->free_nodes = node;
	shm->nodes_allocated--;
}

static struct ofp_rtl_node *NODEALLOC(void)
{
	struct ofp_rtl_node *p = shm->free_nodes;
	if (shm->free_nodes) {
		shm->free_nodes->left = NULL;
		shm->free_nodes = shm->free_nodes->right;
		shm->nodes_allocated++;
		if (shm->nodes_allocated > shm->max_nodes_allocated)
			shm->max_nodes_allocated = shm->nodes_allocated;
	}
	return p;
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

#define OFP_OOPS(_s) printf(_s)

int ofp_rtl_init(struct ofp_rtl_tree *tree)
{
	int i;

	for (i = 0; i < NUM_NODES; i++) {
		shm->node_list[i].left = (i == 0) ? NULL : &(shm->node_list[i-1]);
		shm->node_list[i].right = (i == NUM_NODES - 1) ? NULL : &(shm->node_list[i+1]);
	}
	shm->free_nodes = shm->node_list;

	return ofp_rtl_root_init(tree, 0);
}

int ofp_rtl6_init(struct ofp_rtl6_tree *tree)
{
	int i;

	for (i = 0; i < NUM_NODES_6; i++) {
		shm->node_list6[i].left = (i == 0) ? NULL : &(shm->node_list6[i-1]);
		shm->node_list6[i].right = (i == NUM_NODES_6 - 1) ? NULL : &(shm->node_list6[i+1]);
	}
	shm->free_nodes6 = &(shm->node_list6[0]);

	tree->root = NODEALLOC6();
	if (!tree->root) {
		printf("%s(): allocation failed!\n", __FUNCTION__);
		return -1;
	}

	tree->root->flags = 0;
	tree->root->left = NULL;
	tree->root->right = NULL;

	return 0;
}

int ofp_rtl_root_init(struct ofp_rtl_tree *tree, uint16_t vrf)
{
	tree->root = NODEALLOC();
	if (!tree->root) {
		printf("%s(): allocation failed!\n", __FUNCTION__);
		return -1;
	}

	tree->root->flags = 0;
	tree->root->left = NULL;
	tree->root->right = NULL;
	tree->vrf = vrf;

	return 0;
}


/* __attribute__((optimize("O0"))) */
struct ofp_nh_entry *
ofp_rtl_insert(struct ofp_rtl_tree *tree, uint32_t addr_be,
			   uint32_t masklen, struct ofp_nh_entry *data)
{
	struct ofp_rtl_node  *node;
	struct ofp_rtl_node  *last = NULL;
	uint32_t              depth;
	uint32_t              mask = 0x80000000;
	uint32_t              addr = (odp_be_to_cpu_32(addr_be)) & ((~0)<<(32-masklen));

	depth = 0;
	node = tree->root;
	while (depth < masklen && node) {
		last = node;
		if (addr & mask) {
			node = node->right;
		} else {
			node = node->left;
		}
		depth++;
		mask >>= 1;
	}

	if (node) {
		node->data[0] = *data;
		node->flags = OFP_RTL_FLAGS_VALID_DATA;
		return NULL;
	}

	node = NODEALLOC();
	if (!node)
		return NULL;//tree;
	memset(node, 0, sizeof(*node));

	node->left = NULL;
	node->right = NULL;
	node->flags = OFP_RTL_FLAGS_VALID_DATA;
	node->data[0] = *data;

	mask = (1 << (32 - masklen));
	while (depth < masklen) {
		struct ofp_rtl_node *tmp;

		tmp = NODEALLOC();
		if (!tmp)
			goto nomem;
		memset(tmp, 0, sizeof(*tmp));

		if (addr & mask) {
			tmp->right = node;
			tmp->left = NULL;
		} else {
			tmp->left = node;
			tmp->right = NULL;
		}
		node = tmp;
		mask <<= 1;
		depth++;
	}

	if (!last) OFP_OOPS("!last");
	if (addr & mask) {
		last->right = node;
	} else {
		last->left = node;
	}

	return NULL;

 nomem:
	while(node) {
		struct ofp_rtl_node *tmp;

		mask >>= 1;
		if (addr & mask) {
			tmp = node->right;
			NODEFREE(node);
		} else {
			tmp = node->left;
			NODEFREE(node);
		}
		node = tmp;
	}

	return NULL; //tree;
}


struct ofp_nh_entry *
ofp_rtl_search_exact(struct ofp_rtl_tree *tree, uint32_t addr_be, uint32_t masklen)
{
	struct ofp_rtl_node  *node;
	uint32_t              depth;
	uint32_t              mask = 0x80000000;
	uint32_t              addr = odp_be_to_cpu_32(addr_be);

	depth = 0;
	node = tree->root;
	while (depth < masklen && node) {
		shm->global_stack[depth] = node;
		if (addr & mask) {
			node = node->right;
		} else {
			node = node->left;
		}
		depth++;
		mask >>= 1;
	}

	if (!node)
		return NULL;

	return &node->data[0];
}

struct ofp_nh_entry *
ofp_rtl_remove(struct ofp_rtl_tree *tree, uint32_t addr_be, uint32_t masklen)
{
	struct ofp_rtl_node  *node;
	struct ofp_rtl_node **stack = shm->global_stack;
	uint32_t              depth;
	uint32_t              mask = 0x80000000;
	void                 *data;
	uint32_t              addr = odp_be_to_cpu_32(addr_be);

	depth = 0;
	node = tree->root;
	while (depth < masklen && node) {
		stack[depth] = node;
		if (addr & mask) {
			node = node->right;
		} else {
			node = node->left;
		}
		depth++;
		mask >>= 1;
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

	NODEFREE(node);

	mask = 1 << (32 - depth);
	depth--;
	do {
		if (addr & mask) {
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

		NODEFREE(stack[depth]);
		depth--;
		mask <<= 1;
	} while (1);

	return data;
}

void ofp_rtl_destroy(struct ofp_rtl_tree *tree, void (*func)(void *data))
{
	struct ofp_rtl_node *stack[OFP_RTL_MAXDEPTH + 1];
	struct ofp_rtl_node *node;
	int depth = 0;

	node = tree->root;

	for (;;) {
		if (depth == OFP_RTL_MAXDEPTH + 1) OFP_OOPS("rtl maxdetph exceeded");

		if (!node->left && !node->right) {
			if (func && (node->flags & OFP_RTL_FLAGS_VALID_DATA))
				func(&node->data);
			NODEFREE(node);
			depth--;
			if (depth < 0) break;

			if (stack[depth]->left == node)
				stack[depth]->left = NULL;
			else if (stack[depth]->right == node)
				stack[depth]->right = NULL;

			node = stack[depth];
		} else {
			stack[depth++] = node;

			if (node->left)
				node = node->left;
			else
				node = node->right;
		}
	}

	tree->root = NULL;
}

static void traverse(int fd, struct ofp_rtl_node *node,
					 void (*func)(int fd, uint32_t key, int level, struct ofp_nh_entry *data),
					 uint32_t key, int level)
{
	if (!node)
		return;

	//printf("leaf=%p flags=0x%x\n", node, node->flags);
	if (func && (node->flags & OFP_RTL_FLAGS_VALID_DATA))
			func(fd, key, level, &(node->data[0]));

	//printf("left=%p right=%p\n", node->left, node->right);
	traverse(fd, node->left, func, key, level+1);
	if (node->right) key |= 0x80000000 >> level;
	traverse(fd, node->right, func, key, level+1);
}

void ofp_rtl_traverse(int fd, struct ofp_rtl_tree *tree,
					  void (*func)(int fd, uint32_t key, int level, struct ofp_nh_entry *data))
{
	traverse(fd, tree->root, func, 0, 0);
}

struct ofp_nh6_entry *
ofp_rtl_insert6(struct ofp_rtl6_tree *tree, uint8_t *addr,
				uint32_t masklen, struct ofp_nh6_entry *data)
{
	struct ofp_rtl6_node  *node;
	struct ofp_rtl6_node  *last = NULL;
	uint32_t              depth;
	uint32_t              bit = 0;

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
	if (!node)
		return NULL;//tree;
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

	if (!last) OFP_OOPS("!last");
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

	return NULL; //tree;
}

struct ofp_nh6_entry *
ofp_rtl_remove6(struct ofp_rtl6_tree *tree, uint8_t *addr, uint32_t masklen)
{
	struct ofp_rtl6_node  *node;
	struct ofp_rtl6_node **stack = shm->global_stack6;
	uint32_t               depth;
	void                  *data;
	int                    bit = 0;

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

#if 0
static void tr(int fd, struct ofp_rtl6_node *n, int level)
{
	ofp_sendf(fd, "level=%d node=%d left=%d right=%d flags=%d\r\n", level, NUM(n),
			  NUM(n->left), NUM(n->right), n->flags);
	if (n->left) {
		tr(fd, n->left, level+1);
	}
	if (n->right) {
		tr(fd, n->right, level+1);
	}
}
#endif

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

void ofp_rt_lookup_alloc_shared_memory(void)
{
	odp_shm_t shm_h;

	/* Reserve memory for args from shared mem */
	shm_h = odp_shm_reserve("OfpRtlookupShMem",
					sizeof(*shm), ODP_CACHE_LINE_SIZE, 0);
	shm = odp_shm_addr(shm_h);

	if (shm == NULL) {
		OFP_ABORT("Error: OfpRtlookupShMem shared mem alloc failed on core: %u.\n",
							odp_cpu_id());
		exit(EXIT_FAILURE);
	}

	memset(shm, 0, sizeof(*shm));
}

void ofp_rt_lookup_lookup_shared_memory(void)
{
	odp_shm_t shm_h;

	shm_h = odp_shm_lookup("OfpRtlookupShMem");
	shm = odp_shm_addr(shm_h);

	if (shm == NULL) {
		OFP_ABORT("Error: OfpRtlookupShMem shared mem lookup failed on core: %u.\n",
							odp_cpu_id());
		exit(EXIT_FAILURE);
	}
}
