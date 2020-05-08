/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __NETWRAP_COMMON_H__
#define __NETWRAP_COMMON_H__

#ifndef RTLD_NEXT
#define _GNU_SOURCE
#endif
#include <dlfcn.h>

#include <ofp.h>

int setup_common_vars(void);
extern ofp_global_param_t ofp_global_params;
extern odp_bool_t netwrap_constructor_called;

#define LIBC_FUNCTION(func) do {			\
		libc_##func = dlsym(RTLD_NEXT, #func);	\
		if (dlerror()) {			\
			errno = EACCES;			\
			exit(1);			\
		}					\
	} while (0)

#define IS_OFP_SOCKET(_fd) (netwrap_constructor_called && \
	(_fd >= (int)ofp_global_params.socket.sd_offset))

#endif /* __NETWRAP_COMMON_H__ */


