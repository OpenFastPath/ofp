/* Copyright (c) 2016, Nokia
 * Copyright (c) 2016, ENEA Software AB
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFP_CUNIT_VERSION_H__
#define __OFP_CUNIT_VERSION_H__

/* http://stackoverflow.com/questions/2124339/c-preprocessor-va-args-number-of-arguments */
#define COUNT_ARGS(...) COUNT_ARGS_(__VA_ARGS__, 6, 5, 4, 3, 2, 1, 0)
#define COUNT_ARGS_(_1, _2, _3, _4, _5, _6, N, ...) N

/* The CUnit 2.1-3 version supports per test setup and teardown functions while
 * the older versions don't. The CUnit header only has a string type of version
 * number which cannot be used with preprocessor conditionals. The main
 * difference of interest between the CUnit versions is within the definition of
 * 'CU_SuiteInfo' structure. This is also visible in the 'CU_SUITE_INFO_NULL'
 * macro that has a different 'size' between the versions. This 'size'
 * difference can be checked by the preprocessor and used to set up the
 * compilation environment.
 */
#if COUNT_ARGS(CU_SUITE_INFO_NULL) > 4
#define CU_HAS_TEST_SETUP_AND_TEARDOWN
#endif

#endif
