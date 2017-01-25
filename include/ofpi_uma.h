/*-
 * Copyright (c) 2014 Nokia
 * Copyright (c) 2014 ENEA Software AB
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#ifndef __OFPI_UMA_H__
#define __OFPI_UMA_H__

/*
 * Universal Memory allocator via ODP pools
 *
 * uma zones are implemented as ODP pools, which means static allocation.
 *
 * uma_zcreate() takes an additional parameter 'nitems' to specify the
 * max number of objects. uma_zone_set_max() does nothing.
 *
 */

#define	OFP_M_NOWAIT	0x0001		/* do not block */
#define	OFP_M_WAITOK	0x0002		/* ok to block */
#define	OFP_M_ZERO		0x0100		/* bzero the allocation */
#define	OFP_M_NOVM		0x0200		/* don't ask VM for pages */
#define	OFP_M_USE_RESERVE	0x0400		/* can alloc out of reserve memory */
#define	OFP_M_NODUMP	0x0800		/* don't dump pages in this allocation */

typedef int uma_zone_t;

#define OFP_UMA_ZONE_INVALID (-1)

#define OFP_NUM_UMA_POOLS 32

#define uma_zcreate(name, nitems, size, ctor, dtor, uminit, fini, align, flags) \
	ofp_uma_pool_create(name, nitems, size)

#define uma_zdestroy(zone) \
	ofp_uma_pool_destroy(zone)

#define uma_zalloc(zone, flags) \
	ofp_uma_pool_alloc(zone, flags)

#define uma_zfree(zone, item) \
	ofp_uma_pool_free(item)

#define uma_zone_set_max(zone, nitems)

uma_zone_t ofp_uma_pool_create(const char *name, int nitems, int size);
int ofp_uma_pool_destroy(uma_zone_t zone);
void *ofp_uma_pool_alloc(uma_zone_t zone, int flags);
void ofp_uma_pool_free(void *item);


int ofp_uma_lookup_shared_memory(void);
int ofp_uma_init_global(void);
int ofp_uma_term_global(void);

#endif /* __OFPI_UMA_H__ */

