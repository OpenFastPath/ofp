/* Copyright (c) 2017, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 *
 */

#ifndef OFPI_ODP_COMPAT_H
#define OFPI_ODP_COMPAT_H

#include <odp_api.h>

/*
 * This file enables OFP build with both the latest LTS release of ODP
 * and the latest tagged release.
 */

/*
 * ODP 1.13.0.0 introduced ODP_SHM_SINGLE_VA flag for requesting
 * an SHM block to have the same virtual address in all threads.
 */
#ifdef ODP_SHM_SINGLE_VA
#define OFP_SHM_SINGLE_VA ODP_SHM_SINGLE_VA
#else
#define OFP_SHM_SINGLE_VA 0
#endif

#endif /* OFPI_ODP_COMPAT_H */
