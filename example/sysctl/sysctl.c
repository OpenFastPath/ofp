 /*
  * Copyright (c) 2015, Nokia Solutions and Networks
  * Copyright (c) 2015, ENEA Software AB
  * All rights reserved.
  *
  * SPDX-License-Identifier:	BSD-3-Clause
  */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#include "ofp.h"

#include "sysctl.h"

/*
 * Management Information Base (MIB) is a hierarchical database that
 * describes an application. Object Identifiers (OID) are used to
 * read and write the variables. In IETF notation OIDs are composed of digits
 * and dots.
 *
 * For example in this library 'net' branch has OID number 4,
 * 'inet' has number 4.2, 'udp' 4.2.17, and udp's checksum variable 4.2.17.1.
 * The checksum variable can be expressed as a sequence of integers:
 *   4.2.17.1
 * or as a string:
 *   net.inet.udp.checksum
 *
 * When you create a new OID it is possible to allocate new static numbers, but
 * you have to be careful not to use reserved numbers. Recommended way is to use
 * automatic allocation and access the variables using the string notation.
 *
 * Example of a hierarcy tree:
 * 4 net RW Node
 *   2 inet RW Node
 *     0 ip RW Node
 *     1 icmp RW Node
 *     2 igmp RW Node
 *     6 tcp RW Node
 *     17 udp RW Node
 *       1 checksum RW Int
 *       256 blackhole RW Int
 *       257 log_in_vain RW Int
 *
 * OIDs are created at compile time. Create a new branch at root level using
 * static OID number 73:
 */

OFP_SYSCTL_NODE(, 73, mybranch, OFP_CTLFLAG_RW, 0, "My test branch");

/*
 * Create two child branches 'telnet' and 'ssh'. Use automatic OID allocation.
 * Note the underscore before mybranch:
 */

OFP_SYSCTL_NODE(_mybranch, OFP_OID_AUTO, telnet, OFP_CTLFLAG_RW, 0, "Telnet control");
OFP_SYSCTL_NODE(_mybranch, OFP_OID_AUTO, ssh,    OFP_CTLFLAG_RW, 0, "Ssh control");

/*
 * If you want to use the branches in other files use the following
 * declarations in relevant include file:
 *
 * SYSCTL_DECL(_mybranch_telnet);
 * SYSCTL_DECL(_mybranch_ssh);
 */

/*
 * For an integer rw variable useful syntax is:
 * OFP_SYSCTL_INT(_parent, OFP_OID_AUTO, name, OFP_CTLFLAG_RW,
 *                  &variable, value, "Description");
 * There are many other types than integer available, too.
 *
 * Create four variables, two for enabling the protocols and two for statistics.
 * Statistical variables are 64 bit read only.
 */

static int enable_telnet = 1;
static int enable_ssh = 0;
static uint64_t telnet_bytes;
static uint64_t ssh_bytes;

OFP_SYSCTL_INT(_mybranch_telnet, OFP_OID_AUTO, enabled, OFP_CTLFLAG_RW,
	   &enable_telnet, 0, "Enable telnet protocol");
OFP_SYSCTL_INT(_mybranch_ssh, OFP_OID_AUTO, enabled, OFP_CTLFLAG_RW,
	   &enable_ssh, 0, "Enable ssh protocol");
OFP_SYSCTL_QUAD(_mybranch_telnet, OFP_OID_AUTO, counter, OFP_CTLFLAG_RD,
	   &telnet_bytes, 0, "Telnet counter");
OFP_SYSCTL_QUAD(_mybranch_ssh, OFP_OID_AUTO, counter, OFP_CTLFLAG_RD,
	   &ssh_bytes, 0, "Ssh counter");

/*
 * Hello message for clients. If 6th value (length) is zero
 * the string cannot be changed.
 */
static char hello_msg[32];

OFP_SYSCTL_STRING(_mybranch, OFP_OID_AUTO, hello, OFP_CTLFLAG_RW,
	      hello_msg, sizeof(hello_msg), "Hello message");

/*
 * End of compile time definitions. Our branch looks like this:
 *
 * 73 mybranch RW Node
 *   256 hello RW String
 *   261 ssh RW Node
 *     257 counter R  int64_t
 *     259 enabled RW int
 *   262 telnet RW Node
 *     258 counter R  int64_t
 *     260 enabled RW int
 *
 * OID values > 255 are dynamically allocated.
 */

static void *
sysctl(void *arg)
{
	(void)arg;

	if (odp_init_local(ODP_THREAD_CONTROL)) {
		OFP_ERR("Error: ODP local init failed.\n");
		return NULL;
	}
	if (ofp_init_local()) {
		OFP_ERR("Error: OFP local init failed.\n");
		return NULL;
	}
	sleep(2);

	/*
	 * Variables may be visible per thread. Addresses of the shared
	 * variables are not known at compile time. Also sometimes it may be
	 * necessary to create OIDs dynamically.
	 *
	 * Add an OID dynamically to the existing compile time
	 * created branch:
	 */
	static int created;

	OFP_SYSCTL_ADD_INT(NULL, SYSCTL_STATIC_CHILDREN(_mybranch), OFP_OID_AUTO,
			     "created", OFP_CTLFLAG_RW, &created, 0,
			     "Dynamically created");

	/*
	 * Create a branch dynamically:
	 */
	struct ofp_sysctl_oid *dyn_root;

	dyn_root = OFP_SYSCTL_ADD_NODE
		(NULL,
		 SYSCTL_STATIC_CHILDREN(_mybranch), OFP_OID_AUTO, "subbranch",
		 OFP_CTLFLAG_RW, 0, "Dynamically created branch");

	/*
	 * Add a variable to that, for example one from the shared memory.
	 * Here we use a static integer.
	 */
	static int shared;

	OFP_SYSCTL_ADD_INT(NULL, SYSCTL_CHILDREN(dyn_root), OFP_OID_AUTO,
			     "shared", OFP_CTLFLAG_RW, &shared, 0,
			     "Shared memory variable");
	/*
	 * Our branch is complete:
	 *
	 * 73 mybranch RW Node  (My test branch)
	 *   256 hello RW string  (Hello message)
	 *   261 ssh RW Node  (Ssh control)
	 *     257 counter R  int64_t  (Ssh counter)
	 *     259 enabled RW int  (Enable ssh protocol)
	 *   262 telnet RW Node  (Telnet control)
	 *     258 counter R  int64_t  (Telnet counter)
	 *     260 enabled RW int  (Enable telnet protocol)
	 *   328 created RW int  (Dynamically created)
	 *   329 subbranch RW Node  (Dynamically created branch)
	 *     330 shared RW int  (Shared memory variable)
	 */

	/*
	 * Use created variables. First set some meaningful values:
	 */
	telnet_bytes = 123456;
	ssh_bytes = 567890;
	strcpy(hello_msg, "Hello, world!");

	/*
	 * There are several functions to access MIB data. Simplest one
	 * is the following:
	 *
	 *   ofp_sysctl(const char *name, void *old, size_t *oldlenp,
	 *                const void *new, size_t newlen, size_t *retval)
	 *
	 *   name:    OID using string notation (like "net.inet.udp.checksum").
	 *   old:     Pointer to memory where old value will be saved.
	 *            Can be NULL.
	 *   oldlenp: Pointer to variable whose value is the result space
	 *            in bytes. Will be updated to the real space.
	 *   new:     Pointer to the new value. Can be NULL.
	 *   newlen:  Size of the new value in bytes or zero.
	 *   retval:  Pointer to a variable that will be set to
	 *            response's length.
	 */

	/*
	 * Read the telnet bytes:
	 */
	uint64_t counter;
	size_t counterlen = sizeof(counter);
	size_t retval;
	ofp_sysctl("mybranch.telnet.counter", &counter, &counterlen,
		     NULL, 0, &retval);
	OFP_INFO("mybranch.telnet.counter=%"PRIu64" len=%zu retval=%zu\n",
		  counter, counterlen, retval);
	/*
	 * Read the ssh bytes:
	 */
	ofp_sysctl("mybranch.ssh.counter", &counter, &counterlen,
		     NULL, 0, &retval);
	OFP_INFO("mybranch.ssh.counter=%"PRIu64" len=%zu retval=%zu\n",
		  counter, counterlen, retval);

	/*
	 * Check if telnet is enabled:
	 */
	int enabled;
	size_t enalen = sizeof(enabled);
	ofp_sysctl("mybranch.telnet.enabled", &enabled, &enalen,
		     NULL, 0, &retval);
	OFP_INFO("mybranch.telnet.enabled=%d\n", enabled);
	/*
	 * Disable telnet:
	 */
	enabled = 0;
	ofp_sysctl("mybranch.telnet.enabled", NULL, 0,
		     &enabled, sizeof(enabled), &retval);
	/*
	 * Check if that worked. Init variable with something to ensure it is
	 * really changed:
	 */
	enabled = 123;
	enalen = sizeof(enabled);
	ofp_sysctl("mybranch.telnet.enabled", &enabled, &enalen,
		     NULL, 0, &retval);
	OFP_INFO("After disabling: mybranch.telnet.enabled=%d, real value=%d\n",
		  enabled, enable_telnet);

	/*
	 * Read and change the hello message:
	 */
	char msg[32];
	size_t msglen = sizeof(msg);
	ofp_sysctl("mybranch.hello", msg, &msglen,
		     "Server is down.", 16, &retval);
	OFP_INFO("mybranch.hello: old value=%s, new value=%s\n",
		  msg, hello_msg);

	/*
	 * Make telnet connection to local address port 2345.
	 * Try commands:
	 *   sysctl dump
	 *   sysctl r mybranch.ssh.counter
	 *   sysctl w mybranch.ssh.enabled 1
	 *   sysctl w mybranch.ssh.counter 777
	 */

	while (1)
		sleep(1);

	return NULL;
}

void ofp_start_sysctl_thread(int core_id)
{
	odph_linux_pthread_t test_linux_pthread;
	odp_cpumask_t cpumask;

	odp_cpumask_zero(&cpumask);
	odp_cpumask_set(&cpumask, core_id);

	ofp_linux_pthread_create(&test_linux_pthread,
				  &cpumask,
				  sysctl,
				  NULL,
				  ODP_THREAD_WORKER
				);
}
