/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

uint32_t ofp_hashword(const uint32_t *k, size_t length, uint32_t initval);
void ofp_hashword2(const uint32_t *k, size_t length, uint32_t *pc, uint32_t *pb);
uint32_t ofp_hashlittle(const void *key, size_t length, uint32_t initval);
void ofp_hashlittle2(const void *key, size_t length, uint32_t *pc, uint32_t *pb);
uint32_t ofp_hashbig(const void *key, size_t length, uint32_t initval);
