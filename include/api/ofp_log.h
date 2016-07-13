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

#if __GNUC__ >= 4
#pragma GCC visibility push(default)
#endif

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
 *   D 186 3:3098175232 ofp_pkt_processing.c:280] Device IP: 0.0.0.0, Packet Dest IP: 192.168.146.130
 */
#define OFP_INFO(fmt, ...) \
	_OFP_LOG(OFP_LOG_INFO, fmt, ##__VA_ARGS__)
#define OFP_WARN(fmt, ...) \
	_OFP_LOG(OFP_LOG_WARNING, fmt, ##__VA_ARGS__)
#define OFP_ERR(fmt, ...) \
	_OFP_LOG(OFP_LOG_ERROR, fmt, ##__VA_ARGS__)

/*
 * Debug macros which will be compiled out when --enable-debug is not used.
 */
#if defined(OFP_DEBUG)
#define OFP_DBG(fmt, ...) \
	_OFP_LOG(OFP_LOG_DEBUG, fmt, ##__VA_ARGS__)
#else
#define OFP_DBG(fmt, ...) do {} while (0)
#endif

#define OFP_LOG_NO_CTX(level, fmt, ...) do {		\
		if (level > ofp_loglevel)		\
			break;				\
		fprintf(stderr, fmt, ##__VA_ARGS__);	\
	} while (0)

#define OFP_LOG_NO_CTX_NO_LEVEL(fmt, ...) \
		fprintf(stderr, fmt, ##__VA_ARGS__)

enum ofp_log_level_s {
	OFP_LOG_DISABLED = -1,
	OFP_LOG_ERROR = 0,
	OFP_LOG_WARNING,
	OFP_LOG_INFO,
	OFP_LOG_DEBUG,
	OFP_LOG_MAX_LEVEL
};

extern enum ofp_log_level_s ofp_loglevel;

static inline int ofp_debug_logging_enabled(void)
{
	return (ofp_loglevel == OFP_LOG_DEBUG);
}

/*
 * Do not use these macros.
 */
#define __FILENAME__ \
	(strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#define _OFP_LOG(level, fmt, ...) do {					\
		if (level > ofp_loglevel)				\
			break;						\
		fprintf(stderr, "%s %d %d:%u %s:%d] " fmt "\n",		\
			(level == OFP_LOG_ERROR)   ? "E" :		\
			(level == OFP_LOG_WARNING) ? "W" :		\
			(level == OFP_LOG_INFO)    ? "I" :		\
			(level == OFP_LOG_DEBUG)   ? "D" : "?",		\
			ofp_timer_ticks(0),				\
			odp_cpu_id(), (unsigned int) pthread_self(),	\
			__FILENAME__, __LINE__,				\
			##__VA_ARGS__);					\
	} while (0)

#if __GNUC__ >= 4
#pragma GCC visibility pop
#endif

#endif /*__OFP_LOG_H__*/
