/*
 * Copyright (c) 2018, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#ifndef OFPI_BRLOCK_H
#define OFPI_BRLOCK_H

#include <odp_api.h>

/*
 * Big reader lock
 *
 * ofp_brlock is a read-write lock optimized for very frequent reading and rare
 * writing. The implementation uses thread specific spinlocks to avoid cache
 * line sharing between readers.
 */

struct ofp_brlock_s {
        struct ODP_ALIGNED_CACHE {
                odp_spinlock_t lock;
        } per_thread[ODP_THREAD_COUNT_MAX];
};

typedef struct ofp_brlock_s ofp_brlock_t;

static inline void ofp_brlock_init(ofp_brlock_t *lock)
{
        for (int n = 0; n < ODP_THREAD_COUNT_MAX; n++) {
                odp_spinlock_init(&lock->per_thread[n].lock);
        }
}

static inline void ofp_brlock_read_lock(ofp_brlock_t *lock)
{
        odp_spinlock_lock(&lock->per_thread[odp_thread_id()].lock);
}

static inline void ofp_brlock_read_unlock(ofp_brlock_t *lock)
{
        odp_spinlock_unlock(&lock->per_thread[odp_thread_id()].lock);
}

static inline void ofp_brlock_write_lock(ofp_brlock_t *lock)
{
        for (int n = 0; n < ODP_THREAD_COUNT_MAX; n++) {
                odp_spinlock_lock(&lock->per_thread[n].lock);
        }
}

static inline void ofp_brlock_write_unlock(ofp_brlock_t *lock)
{
        for (int n = 0; n < ODP_THREAD_COUNT_MAX; n++) {
                odp_spinlock_unlock(&lock->per_thread[n].lock);
        }
}

#endif /* OFPI_BRLOCK_H */
