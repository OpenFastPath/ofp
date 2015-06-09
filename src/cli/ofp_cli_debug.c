/*-
 * Copyright (c) 2014 ENEA Software AB
 * Copyright (c) 2014 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ofpi_debug.h"
#include "ofpi_cli.h"
#include "ofpi_util.h"

/* debug NUMBER */
void f_debug(struct cli_conn *conn, const char *s)
{
	(void)s;
	ofp_debug_flags = (ofp_debug_flags &
		(~OFP_DEBUG_PCAP_PORT_MASK)) |
		strtol(s, NULL, 0);

	if ((ofp_debug_flags & OFP_DEBUG_CAPTURE) &&
		(ofp_debug_capture_ports == 0)) {

		/*enable capture on first port*/
		ofp_debug_capture_ports = 0x1;
	}
	sendcrlf(conn);
}

/* debug show */
void f_debug_show(struct cli_conn *conn, const char *s)
{
	int i;
	char filename[128];

	(void)s;

	if (ofp_debug_flags & (OFP_DEBUG_PRINT_RECV_NIC |
				 OFP_DEBUG_PRINT_SEND_NIC |
				 OFP_DEBUG_PRINT_RECV_KNI |
				 OFP_DEBUG_PRINT_SEND_KNI)) {
		ofp_sendf(conn->fd,
			"Printing traffic on file%s:%s%s%s%s\r\n",
			ofp_debug_flags & OFP_DEBUG_PRINT_CONSOLE ?
			" (and console)" : "",
			ofp_debug_flags & OFP_DEBUG_PRINT_RECV_NIC ?
			" ODP-to-FP" : "",
			ofp_debug_flags & OFP_DEBUG_PRINT_SEND_NIC ?
			" FP-to-ODP" : "",
			ofp_debug_flags & OFP_DEBUG_PRINT_RECV_KNI ?
			" FP-to-SP" : "",
			ofp_debug_flags & OFP_DEBUG_PRINT_SEND_KNI ?
			" SP-to-ODP" : "");
		ofp_sendf(conn->fd, "  Printing file: "
			DEFAULT_DEBUG_TXT_FILE_NAME"\r\n");
	} else {
		ofp_sendf(conn->fd, "Printing NO traffic.\r\n");
	}

	if (ofp_debug_flags & OFP_DEBUG_CAPTURE) {
		ofp_sendf(conn->fd,
			    "Capturing traffic from ports%s:",
			    ofp_debug_capture_ports &
			    OFP_DEBUG_PCAP_CONF_ADD_INFO ?
			    " (with info)" : "");

		for (i = 0; i < 30; i++)
			if (ofp_debug_capture_ports & (1 << i))
				ofp_sendf(conn->fd, " %d", i);

		ofp_sendf(conn->fd, "\r\n");

		ofp_get_capture_file(filename, sizeof(filename));

		ofp_sendf(conn->fd, "  Capturing file: %s\r\n", filename);
	} else {
		ofp_sendf(conn->fd, "Capturing NO traffic.\r\n");
	}

	sendcrlf(conn);
}

/* debug capture NUMBER */
void f_debug_capture(struct cli_conn *conn, const char *s)
{
	ofp_debug_capture_ports = strtol(s, NULL, 0);

	if (ofp_debug_capture_ports)
		ofp_debug_flags |= OFP_DEBUG_CAPTURE;
	else
		ofp_debug_flags &= ~OFP_DEBUG_CAPTURE;

	sendcrlf(conn);
}

/* debug capture info NUMBER */
void f_debug_info(struct cli_conn *conn, const char *s)
{
	if (atoi(s))
		ofp_debug_capture_ports |= OFP_DEBUG_PCAP_CONF_ADD_INFO;
	else
		ofp_debug_capture_ports &= ~OFP_DEBUG_PCAP_CONF_ADD_INFO;

	sendcrlf(conn);
}

 /* debug capture file STRING */
void f_debug_capture_file(struct cli_conn *conn, const char *s)
{
	(void)s;
	ofp_set_capture_file(s);
	sendcrlf(conn);
}

/* debug */
/* debug help */
/* help debug*/
void f_help_debug(struct cli_conn *conn, const char *s)
{
	(void)s;
	ofp_sendf(conn->fd,
		"Show debug settings\r\n"
		"  debug show\r\n\r\n");

	ofp_sendf(conn->fd,
		"Set options for printing traffic on file"
		" (and console) in text format and capturing traffic"
		" on file in pcap format\r\n"
		"  debug <bit mask of traffic categories>\r\n"
		"    bit 0: print packets from ODP to FP\r\n"
		"    bit 1: print packets from FP to ODP\r\n"
		"    bit 2: print packets from FP to SP\r\n"
		"    bit 3: print packets from SP to ODP\r\n"
		"    bit 4: print packets to console\r\n"
		"    bit 6: capture packets to pcap file\r\n"
		"           - set/reset automatically by capture function\r\n"
		"  Default text file name: '"
		DEFAULT_DEBUG_TXT_FILE_NAME"'\r\n"
		"  Default capture file name: '"
		DEFAULT_DEBUG_PCAP_FILE_NAME"'\r\n"
		"  Example: Print SP traffic:\r\n"
		"    debug 0xc\r\n"
		"    (numbers can be in decimal or hex format)\r\n\r\n");

	ofp_sendf(conn->fd,
		"Set packet capture port(s).\r\n"
		"  debug capture <bit mask of ports whose traffic to save>\r\n"
		"    bit 0: port 0\r\n"
		"    bit 1: port 1\r\n"
		"    etc.\r\n"
		"  Note: \r\n"
		"    A zero value will disable packet capture.\r\n"
		"    A non-zero value will enable packet capture.\r\n"
		"  Default capture file is '"DEFAULT_DEBUG_PCAP_FILE_NAME"'\r\n"
		"    Old file is overwritten when the fastpath starts.\r\n"
		"  Example: Save traffic of ports 0, 2, and 3:\r\n"
		"    debug capture 0xd\r\n\r\n");

	ofp_sendf(conn->fd,
	  "Set packet capture file or fifo\r\n"
	  "  debug capture file <filename>\r\n"
	  "  Example:\r\n"
	  "    debug capture file /root/my-fifo\r\n\r\n");

	ofp_sendf(conn->fd,
	  "Set the first octet of the destination MAC address "
	  "of captured packet to 'port info' value.\r\n"
	  "  debug capture info <1 or 0>\r\n"
	  "    1: overwrite MAC address octet\r\n"
	  "    0: no overwriting\r\n"
	  "  Port info format:\r\n"
	  "    bits 0-5: port number\r\n"
	  "    bit 6: 1 = SP traffic\r\n"
	  "    bit 7: 0 = received, 1 = transmitted packet\r\n"
	  "  Example: tcpdump line:\r\n"
	  "    '11:36:56.851469 b4:b5:2f:63:05:e5 > c0:9d:67:1a:97:7e, ethe...'\r\n"
	  "    1st octet of dst = 0xc0 -> port = 0, tx via KNI\r\n\r\n");
	sendcrlf(conn);
}
