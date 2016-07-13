/* Copyright (c) 2015, ENEA Software AB
 * Copyright (c) 2015, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * Create an OFP interface with ODP ifname and packet input mode
 *
 * Open an ODP interface using its name and access type after global
 * initialization. The coresponding OFP object, ofp_ifnet is created.
 *
 * This function can be used anytime to open ODP interfaces that were not opened
 * during ofp_init_global(). One can specify no interface in ofp_init_global
 * and open one by one using this functionality.
 *
 * @param if_name Interface name to open
 * @param pktio_param Specify packet access mode for this
 *        interface
 * @param pktin_param Specify packet input queue parameters for
 *        this interface
 *
 * @retval 0 on success
 * @retval -1 on failure
 *
 * @see ofp_init_global() can init interfaces.
 * @see ofp_init_local() which is required per thread before use.
 */
#ifndef __OFP_IFNET_H__
#define __OFP_IFNET_H__

#if __GNUC__ >= 4
#pragma GCC visibility push(default)
#endif

int ofp_ifnet_create(odp_instance_t instance, char *if_name,
	odp_pktio_param_t *pktio_param,
	odp_pktin_queue_param_t *pktin_param,
	odp_pktout_queue_param_t *pktout_param);
#if __GNUC__ >= 4
#pragma GCC visibility pop
#endif

#endif /* __OFP_IFNET_H__ */
