/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include "ofp.h"
#include "suite_framework.h"

static int suite_thread1(void *arg);
static int suite_thread2(void *arg);

int fd_thread1 = -1;
int fd_thread2 = -1;
int core_id = -1;

int config_suite_framework(uint16_t linux_core_id)
{
	core_id = linux_core_id;

	return 0;
}

int init_suite(init_function init_func)
{
	fd_thread1 = -1;
	fd_thread2 = -1;

	if (init_func)
		return init_func(&fd_thread1, &fd_thread2);
	else
		return 0;
}

void run_suite(odp_instance_t instance,
	run_function run_func1, run_function run_func2)
{
	odph_thread_t sock_pthread1;
	odph_thread_t sock_pthread2;
	odp_cpumask_t sock_cpumask;
	odph_thread_param_t thr_params;
	odph_thread_common_param_t thr_common;

	odp_cpumask_zero(&sock_cpumask);
	odp_cpumask_set(&sock_cpumask, core_id);

	odph_thread_param_init(&thr_params);
	thr_params.start = suite_thread1;
	thr_params.arg = run_func1;
	thr_params.thr_type = ODP_THREAD_CONTROL;
	odph_thread_common_param_init(&thr_common);
	thr_common.instance = instance;
	thr_common.cpumask = &sock_cpumask;
	thr_common.share_param = 1;

	if (odph_thread_create(&sock_pthread1, &thr_common, &thr_params, 1) != 1) {
		OFP_ERR("Error: odph_thread_create() failed.\n");
		exit(EXIT_FAILURE);
	}

	thr_params.start = suite_thread2;
	thr_params.arg = run_func2;

	if (odph_thread_create(&sock_pthread2, &thr_common, &thr_params, 1) != 1) {
		OFP_ERR("Error: odph_thread_create() failed.\n");
		exit(EXIT_FAILURE);
	}

	odph_thread_join(&sock_pthread1, 1);
	odph_thread_join(&sock_pthread2, 1);
}

void end_suite(void)
{
	if (fd_thread1 != -1) {
		if (ofp_close(fd_thread1) == -1)
			OFP_ERR("Faild to close socket 1 (errno = %d)\n",
				ofp_errno);
		fd_thread1 = -1;
	}

	if (fd_thread2 != -1) {
		if (ofp_close(fd_thread2) == -1)
			OFP_ERR("Faild to close socket 1 (errno = %d)\n",
				ofp_errno);
		fd_thread2 = -1;
	}
}

static int suite_thread1(void *arg)
{
	run_function run_func = (run_function)arg;

	if (ofp_init_local()) {
		OFP_ERR("Error: OFP local init failed.\n");
		return -1;
	}

	(void)run_func(fd_thread1);

	return 0;
}

static int suite_thread2(void *arg)
{
	run_function run_func = (run_function)arg;

	if (ofp_init_local()) {
		OFP_ERR("Error: OFP local init failed.\n");
		return -1;
	}

	(void)run_func(fd_thread2);

	return 0;
}
