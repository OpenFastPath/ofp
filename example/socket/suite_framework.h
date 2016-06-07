/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */
#ifndef __SUITE_FRAMEWORK_H__
#define __SUITE_FRAMEWORK_H__
#include "odp.h"

typedef int (*init_function)(int *pfd_thread1, int *pfd_thread2);
typedef int (*run_function)(int fd);

int config_suite_framework(uint16_t linux_core_id);

int init_suite(init_function init_func);
void run_suite(odp_instance_t instance,
	run_function run_func1, run_function run_func2);
void end_suite(void);

#endif /* __SUITE_FRAMEWORK_H__ */

