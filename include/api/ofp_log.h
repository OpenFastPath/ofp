/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 * Copyright (c) 2014, Nokia
 * Copyright (c) 2014, Enea Software AB
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
/**
 * @file
 *
 * ofp log
 */

#ifndef __OFP_LOG_H__
#define __OFP_LOG_H__

#include <odp.h>
#include "ofp_timer.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * These logging macros can be used to send a message to the logging
 * destination. Currently, this is stderr.
 *
 * Log line format:
 *
 *   L t coreid:threadid file:line] msg...
 *
 * where the fields are defined as:
 *
 *   L        - A single character, representing the log level
 *   t        - ODP tick count
 *   coreid   - ODP core id
 *   threadid - pthread thread id
 *   file     - The file name
 *   line     - The line number
 *   msg      - The user-supplied message
 *
 * Example:
 *
 *   I 1595 7:2172776256 ofp_pkt_processing.c:48] Bad checksum, dropping packet
 *   D 1596 7:2172776256 ofp_pkt_processing.c:49] Begin ofp_tcp_input()
 */
#define OFP_LOG(fmt, ...) \
	_ODP_FP_LOG(OFP_LOG_INFO, fmt, ##__VA_ARGS__)
#define OFP_INFO(fmt, ...) \
	_ODP_FP_LOG(OFP_LOG_INFO, fmt, ##__VA_ARGS__)
#define OFP_ERR(fmt, ...) \
	_ODP_FP_LOG(OFP_LOG_ERR, fmt, ##__VA_ARGS__)
#define OFP_ABORT(fmt, ...) \
	_ODP_FP_LOG(OFP_LOG_ABORT, fmt, ##__VA_ARGS__)

/*
 * Debug macros which will be compiled out when --enable-debug is not used.
 */
#if defined(OFP_DEBUG)
#define OFP_DBG(fmt, ...) \
	_ODP_FP_LOG(OFP_LOG_DBG, fmt, ##__VA_ARGS__)
#define OFP_IS_LOGLEVEL_DEBUG() \
	(ofp_loglevel == OFP_LOG_DBG ? 1 : 0)
#else
#define OFP_DBG(fmt, ...)
#define OFP_IS_LOGLEVEL_DEBUG() 0
#endif

/**
 * Print output to stderr
 */
#define OFP_LOG_NO_CTX(level, fmt, ...) do {	\
		if (level > ofp_loglevel)	\
			break;			\
		fprintf(stderr, fmt, ##__VA_ARGS__);	\
	} while (0)


#define __FILENAME__ \
	(strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

/* Internal macro, do not use. */
#define _ODP_FP_LOG(level, fmt, ...) do {				\
		if (level > ofp_loglevel)				\
			break;						\
		fprintf(stderr, "%s %d %d:%u %s:%d] " fmt "\n",		\
			(level == OFP_LOG_ABORT) ? "A" :		\
			(level == OFP_LOG_ERR)   ? "E" :		\
			(level == OFP_LOG_INFO)  ? "I" :		\
			(level == OFP_LOG_DBG)   ? "D" : "?",		\
			ofp_timer_ticks(0),				\
			odp_cpu_id(), (unsigned int) pthread_self(),	\
			__FILENAME__, __LINE__,				\
			##__VA_ARGS__);					\
		if (level == OFP_LOG_ABORT)				\
			abort();					\
	} while (0)

enum ofp_log_level_s {
	OFP_LOG_ABORT = 1,
	OFP_LOG_ERR,
	OFP_LOG_INFO,
	OFP_LOG_DBG
};

extern enum ofp_log_level_s ofp_loglevel;

#endif /*__OFP_LOG_H__*/
