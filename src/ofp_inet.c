/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <odp.h>

#include "ofpi_inet.h"
#include "ofpi_domain.h"
#include "ofpi_protosw.h"
#include "ofpi_ip6protosw.h"
#include "ofpi_sysctl.h"
#include "ofpi_igmp_var.h"

int ofp_inet_init(void)
{
#ifdef INET
	domain_init(&ofp_inetdomain);
#endif /* INET */

#ifdef INET6
	domain_init(&ofp_inet6domain);
#endif /* INET6 */

	return 0;
}

int ofp_inet_term(void)
{
#ifdef INET
	domain_uninit(&ofp_inetdomain);
#endif /* INET */

#ifdef INET6
	domain_uninit(&ofp_inet6domain);
#endif /* INET6 */

	return 0;
}
