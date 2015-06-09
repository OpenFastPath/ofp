/*-
 * Copyright (c) 2014 ENEA Software AB
 * Copyright (c) 2014 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

int main(void)
{
	char *buffer = "test_udp";
	struct sockaddr_in dest_addr = {0};
	int sd = -1;

	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sd == -1) {
		printf("Error: failed to create socket\n");
		exit(0);
	}

	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(54321);
	inet_aton("192.168.100.1", &dest_addr.sin_addr.s_addr);

	sendto(sd, buffer, strlen(buffer) + 1, 0,
		(const struct sockaddr *)&dest_addr, sizeof(dest_addr));

	close (sd);
	return 0;
}
