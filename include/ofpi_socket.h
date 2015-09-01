/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 * Copyright (c) 2014, Nokia
 * Copyright (c) 2014, Enea Software AB
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFPI_SOCKET_H__
#define __OFPI_SOCKET_H__

#include "api/ofp_socket.h"
#include "ofpi_queue.h"

OFP_LIST_HEAD(ofp_fdset, selinfo);
#define OFP_GET_FD_SET(_set) (struct ofp_fdset *)(_set)->fd_set_buf

void ofp_socket_alloc_shared_memory(void);
void ofp_socket_free_shared_memory(void);
void ofp_socket_lookup_shared_memory(void);
void ofp_socket_init_global(odp_pool_t);
void ofp_socket_term_global(void);

#endif /* __OFPI_SOCKET_H__ */
