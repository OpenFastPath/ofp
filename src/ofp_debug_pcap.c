/*-
 * Copyright (c) 2014 ENEA Software AB
 * Copyright (c) 2014 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ofpi_debug.h"
#include "ofpi_log.h"
#include "ofpi_util.h"

#define SHM_NAME_PCAP "OfpPcapShMem"
#define PCAP_FILE_NAME_MAX_SIZE 128

struct ofp_pcap_mem {
	odp_rwlock_t lock_pcap_rw;
	FILE *pcap_fd;
	int   pcap_first;
	int   pcap_is_fifo;
	char  pcap_file_name[PCAP_FILE_NAME_MAX_SIZE];
};
static __thread struct ofp_pcap_mem *shm;

#define IS_KNI(flag) \
	(flag == OFP_DEBUG_PRINT_RECV_KNI || \
	flag == OFP_DEBUG_PRINT_SEND_KNI)

#define IS_TX(flag) \
	(flag == OFP_DEBUG_PRINT_SEND_NIC || \
	flag == OFP_DEBUG_PRINT_SEND_KNI)

#define GET_PCAP_CONF_ADD_INFO(port, flag) \
	(port | \
	(IS_KNI(flag) ? OFP_DEBUG_PCAP_KNI : 0) | \
	(IS_TX(flag) ? OFP_DEBUG_PCAP_TX : 0))

/* PCAP */
void ofp_save_packet_to_pcap_file(uint32_t flag, odp_packet_t pkt, int port)
{
#define PUT16(x) do {					\
uint16_t val16 = x; fwrite(&val16, 2, 1, shm->pcap_fd);	\
} while (0)
#define PUT32(x) do {					\
uint32_t val32 = x; fwrite(&val32, 4, 1, shm->pcap_fd);	\
} while (0)
	struct timeval t;

	if ((ofp_debug_capture_ports &
	     (1 << (port & OFP_DEBUG_PCAP_PORT_MASK))) == 0)
		return;

	odp_rwlock_write_lock(&shm->lock_pcap_rw);

	if (shm->pcap_first) {
		/*int n = ufp_get_num_ports(), i;*/
		struct stat st;

		shm->pcap_is_fifo = 0;
		if (stat(shm->pcap_file_name, &st) == 0)
			shm->pcap_is_fifo = (st.st_mode & S_IFIFO) != 0;

		shm->pcap_fd = fopen(shm->pcap_file_name, "w");
		if (!shm->pcap_fd)
			goto out;

		/* Global header */
		PUT32(0xa1b2c3d4); /* Byte order magic */
		PUT16(2); PUT16(4); /* Version major & minor */
		PUT32(0); /* Timezone */
		PUT32(0); /* Accuracy */
		PUT32(0xffff); /* Snaplen */
		PUT32(1); /* Ethernet */

		shm->pcap_first = 0;
	} else if (shm->pcap_fd == NULL) {
		shm->pcap_fd = fopen(shm->pcap_file_name, "a");
		if (!shm->pcap_fd)
			goto out;
	}

	/* Header */
	/* Timestamp */
	gettimeofday(&t, NULL);
	PUT32(t.tv_sec);
	PUT32(t.tv_usec);

	PUT32(odp_packet_len(pkt)); /* Saved packet len -- segment len */
	PUT32(odp_packet_len(pkt)); /* Captured packet len -- packet len */

	/* Data */
	if (ofp_debug_capture_ports & OFP_DEBUG_PCAP_CONF_ADD_INFO) {
		fputc(GET_PCAP_CONF_ADD_INFO(port, flag), shm->pcap_fd);
		/* Packet data */
		fwrite((uint8_t *) odp_packet_data(pkt) + 1, 1,
		       odp_packet_len(pkt) - 1, shm->pcap_fd);
	} else {
		/* Packet data */
		fwrite(odp_packet_data(pkt), 1,
		       odp_packet_len(pkt), shm->pcap_fd);
	}

	if (!shm->pcap_is_fifo) {
		fclose(shm->pcap_fd);
		shm->pcap_fd = NULL;
	} else {
		fflush(shm->pcap_fd);
	}
out:
	odp_rwlock_write_unlock(&shm->lock_pcap_rw);
}

void ofp_set_capture_file(const char *filename)
{
	char *p;

	odp_rwlock_write_lock(&shm->lock_pcap_rw);

	strncpy(shm->pcap_file_name, filename, sizeof(shm->pcap_file_name)-1);
	shm->pcap_file_name[sizeof(shm->pcap_file_name)-1] = 0;

	/* There may be trailing spaces. Remove. */
	for (p = shm->pcap_file_name; *p; p++)
		if (*p == ' ') {
			*p = 0;
			break;
		}

	if (shm->pcap_fd) {
		fclose(shm->pcap_fd);
		shm->pcap_fd = NULL;
	}
	shm->pcap_first = 1;

	odp_rwlock_write_unlock(&shm->lock_pcap_rw);
}

void ofp_get_capture_file(char *filename, int max_size)
{
	odp_rwlock_write_lock(&shm->lock_pcap_rw);

	strncpy(filename, shm->pcap_file_name, max_size - 1);
	filename[max_size - 1] = 0;

	odp_rwlock_write_unlock(&shm->lock_pcap_rw);
}

static void sigpipe_handler(int s)
{
	(void) s;
	if (shm->pcap_fd) {
		fclose(shm->pcap_fd);
		shm->pcap_fd = NULL;
		shm->pcap_first = 1;
	}
}

static int ofp_pcap_alloc_shared_memory(void)
{
	shm = ofp_shared_memory_alloc(SHM_NAME_PCAP, sizeof(*shm));
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}

	return 0;
}

static int ofp_pcap_free_shared_memory(void)
{
	int rc = 0;

	if (ofp_shared_memory_free(SHM_NAME_PCAP)) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}

	shm = NULL;
	return rc;
}

int ofp_pcap_lookup_shared_memory(void)
{
	shm = ofp_shared_memory_lookup(SHM_NAME_PCAP);
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}
	return 0;
}

int ofp_pcap_init_global(void)
{
	HANDLE_ERROR(ofp_pcap_alloc_shared_memory());

	memset(shm, 0, sizeof(*shm));
	odp_rwlock_init(&shm->lock_pcap_rw);
	strncpy(shm->pcap_file_name, DEFAULT_DEBUG_PCAP_FILE_NAME,
		PCAP_FILE_NAME_MAX_SIZE);
	shm->pcap_file_name[PCAP_FILE_NAME_MAX_SIZE - 1] = 0;
	shm->pcap_first = 1;
	shm->pcap_fd = NULL;

	if (signal(SIGPIPE, sigpipe_handler) == SIG_ERR) {
		OFP_ERR("Failed to set SIGPIPE handler.");
		return -1;
	}

	return 0;
}

int ofp_pcap_term_global(void)
{
	int rc = 0;

	if (ofp_pcap_lookup_shared_memory())
		return -1;

	if (signal(SIGPIPE, SIG_DFL) == SIG_ERR) {
		OFP_ERR("Failed to reset SIGPIPE handler.");
		rc = -1;
	}

	if (shm->pcap_fd) {
		fclose(shm->pcap_fd);
		shm->pcap_fd = NULL;
		shm->pcap_first = 1;
	}

	CHECK_ERROR(ofp_pcap_free_shared_memory(), rc);

	return rc;
}
