/*-
 * Copyright (c) 2014 ENEA Software AB
 * Copyright (c) 2014 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#ifndef __OFPI_VNET_H__
#define __OFPI_VNET_H__

/*
 * Versions of the VNET macros that compile to normal global variables and
 * standard sysctl definitions.
 */
#define	VNET_NAME(n)		n
#define	VNET_DECLARE(t, n)	extern t n
#define	VNET_DEFINE(t, n)	t n

/*
 * Virtualized global variable accessor macros.
 */
#define	VNET_VNET_PTR(vnet, n)		(&(n))
#define	VNET_VNET(vnet, n)		(n)

#define	VNET_PTR(n)		(&(n))
#define	VNET(n)			(n)

#endif /*__OFPI_VNET_H__*/
