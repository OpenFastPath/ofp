/* Copyright (c) 2015, ENEA Software AB
 * Copyright (c) 2015, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef __OFP_CONFIG_H__
#define __OFP_CONFIG_H__

/**
 * @file
 *
 * @brief Configuration file for OFP
 *
 */

/* Enable features */

/**Enable PERFORMANCE measurements mode. Some validations are skipped.*/
#define OFP_PERFORMANCE



/* Configure values */

/**Value of burst size used in default_event_dispatcher.*/
#define OFP_EVENT_BURST_SIZE 16

#endif
