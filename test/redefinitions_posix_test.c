/* Copyright (c) 2014, ENEA Software AB
 * Copyrighy (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:    BSD-3-Clause
 */
#include "ofp.h"

/* Note that gcc does not emit a warning for macros that are redefined
 * where the definitions are effectively the same. See:
 * https://gcc.gnu.org/onlinedocs/cpp/Undefining-and-Redefining-Macros.html
 */

/* Test for definition collisions against posix headers. */

#include <aio.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <nl_types.h>
#include <poll.h>
#include <sched.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <time.h>

#if defined(__linux__)
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <net/if_packet.h>
#include <net/if_ppp.h>
#include <net/if_shaper.h>
#include <net/if_slip.h>
#include <net/ppp-comp.h>
#include <net/ppp_defs.h>
#include <net/route.h>
#include <netinet/ether.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <netinet/if_fddi.h>
#include <netinet/if_tr.h>
#include <netinet/igmp.h>
#include <netinet/in_systm.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#endif

int main(void)
{
	static ofp_init_global_t oig;

	if (odp_init_global(NULL, NULL)) {
		OFP_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}
	odp_init_local();

	ofp_init_global(&oig);

	OFP_INFO("Init successful.\n");
	return 0;
}
