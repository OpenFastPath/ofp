/*
 * Copyright (c) 2018, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <inttypes.h>
#include <odp_api.h>
#include "api/ofp_types.h"
#include "api/ofp_ip6.h"
#include "api/ofp_log.h"
#include "ofpi_pkt_processing.h"
#include "ofpi_in.h"
#include "ofpi_ip.h"
#include "ofpi_ip_var.h"
#include "ofpi_ipsec.h"
#include "ofpi_ipsec_spd.h"
#include "ofpi_ipsec_sad.h"

#define SHM_NAME_IPSEC "ofp_ipsec"
__thread struct ofp_ipsec *ofp_ipsec_shm;

static int ipsec_sa_flush(int check_vrf, uint16_t vrf);
static int ipsec_sp_flush(int check_vrf, uint16_t vrf);

static enum ofp_return_code ipsec_output(odp_packet_t pkt,
					 ofp_ipsec_sa_handle sa,
					 int *lock_held);

static enum ofp_return_code ipsec_output_continue(odp_packet_t pkt);

static enum ofp_return_code ipsec_input_continue(odp_packet_t *pktp,
						 const ofp_ipsec_sa_param_t *sa_param,
						 int *lock_held);

static void process_result_packet(odp_packet_t pkt, int *lock_held);

static enum ofp_return_code process_result(odp_packet_t *pkt,
					   odp_ipsec_packet_result_t *res,
					   int *lock_held);

static void handle_sa_disable_completion(const odp_ipsec_status_t *status,
					 odp_queue_t queue);

void ofp_ipsec_flags_set(odp_packet_t pkt, uint8_t flags)
{
	struct ofp_packet_user_area *ua = ofp_packet_user_area(pkt);
	if (ua)
		ua->ipsec_flags = flags;
}

uint8_t ofp_ipsec_flags(const odp_packet_t pkt)
{
	struct ofp_packet_user_area *ua = ofp_packet_user_area(pkt);
	return ua ? ua->ipsec_flags : 0;
}

void ofp_ipsec_param_init(struct ofp_ipsec_param *param)
{
	memset(param, 0, sizeof(*param));
	param->inbound_op_mode = ODP_IPSEC_OP_MODE_SYNC;
	param->outbound_op_mode = ODP_IPSEC_OP_MODE_SYNC;
	param->max_num_sp = OFP_IPSEC_MAX_NUM_SP;
	param->max_num_sa = OFP_IPSEC_MAX_NUM_SA;
	param->max_inbound_spi = OFP_IPSEC_MAX_INBOUND_SPI;
	param->inbound_queue = ODP_QUEUE_INVALID;
	param->outbound_queue = ODP_QUEUE_INVALID;
}

void ofp_ipsec_init_prepare(const struct ofp_ipsec_param *param)
{
	ofp_ipsec_sad_init_prepare(param->max_num_sa);
	ofp_ipsec_spd_init_prepare(param->max_num_sp);
	ofp_shared_memory_prealloc(SHM_NAME_IPSEC, sizeof(*ofp_ipsec_shm));
}

static int op_mode_supported_by_odp(odp_ipsec_op_mode_t op_mode,
				    odp_ipsec_capability_t *capa,
				    int outbound)
{
	odp_support_t inline_capa = capa->op_mode_inline_in;
	const char *dir = "inbound";

	if (outbound) {
		inline_capa = capa->op_mode_inline_out;
		dir = "outbound";
	}
	if ((op_mode == ODP_IPSEC_OP_MODE_SYNC   && capa->op_mode_sync) ||
	    (op_mode == ODP_IPSEC_OP_MODE_ASYNC  && capa->op_mode_async) ||
	    (op_mode == ODP_IPSEC_OP_MODE_INLINE && inline_capa) ||
	    (op_mode == ODP_IPSEC_OP_MODE_DISABLED))
		return 1;

	OFP_ERR("Requested %s IPsec operation mode is not supported by ODP",
		dir);
	return 0;
}

static int create_ev_queues(const struct ofp_ipsec_param *param,
			    odp_queue_t *in_queue,
			    odp_queue_t *out_queue)
{
	odp_queue_param_t queue_param;

	*in_queue = ODP_QUEUE_INVALID;
	*out_queue = ODP_QUEUE_INVALID;

	odp_queue_param_init(&queue_param);
	queue_param.type = ODP_QUEUE_TYPE_SCHED;
	queue_param.enq_mode = ODP_QUEUE_OP_DISABLED;
	queue_param.deq_mode = ODP_QUEUE_OP_DISABLED;
	queue_param.sched.sync = ODP_SCHED_SYNC_ORDERED;
	queue_param.sched.lock_count = 1;

	if (param->inbound_op_mode != ODP_IPSEC_OP_MODE_SYNC) {
		*in_queue = odp_queue_create("IPsec inbound", &queue_param);
		if (*in_queue == ODP_QUEUE_INVALID) {
			OFP_ERR("Failed to create inbound IPsec event queue");
			return -1;
		}
	}
	if (param->outbound_op_mode != ODP_IPSEC_OP_MODE_SYNC) {
		*out_queue = odp_queue_create("IPsec outbound", &queue_param);
		if (*out_queue == ODP_QUEUE_INVALID) {
			OFP_ERR("Failed to create outbound IPsec event queue");
			if (*in_queue != ODP_QUEUE_INVALID)
				odp_queue_destroy(*in_queue);
			return -1;
		}
	}
	return 0;
}

static int check_ev_queue(odp_ipsec_op_mode_t op_mode, odp_queue_t queue)
{
	if (op_mode == ODP_IPSEC_OP_MODE_SYNC)
		return 0;
	if (queue == ODP_QUEUE_INVALID)
		return -1;
	if (odp_queue_type(queue) != ODP_QUEUE_TYPE_SCHED)
		return 0;

	switch (odp_queue_sched_type(queue)) {
	case ODP_SCHED_SYNC_ORDERED:
		if (odp_queue_lock_count(queue) < 1) {
			OFP_ERR("No ordered locks in IPsec event queue");
			return -1;
		}
		break;
	case ODP_SCHED_SYNC_PARALLEL:
		OFP_WARN("Parallel IPsec event queue may not preserve packet order");
		break;
	default:
		break;
	}
	return 0;
}

static void destroy_ev_queues(odp_queue_t in_queue, odp_queue_t out_queue)
{
	if (in_queue != ODP_QUEUE_INVALID)
		odp_queue_destroy(in_queue);
	if (out_queue != ODP_QUEUE_INVALID &&
	    out_queue != in_queue)
		odp_queue_destroy(out_queue);
}

int ofp_ipsec_init_global(const struct ofp_ipsec_param *param)
{
	odp_ipsec_config_t config;
	odp_ipsec_capability_t capa;
	odp_queue_t in_queue = param->inbound_queue;
	odp_queue_t out_queue = param->outbound_queue;
	uint32_t max_num_sa = param->max_num_sa;
	uint32_t max_num_sp = param->max_num_sp;

	if (odp_ipsec_capability(&capa)) {
		OFP_ERR("odp_ipsec_capability failed");
		return -1;
	}

#ifdef SP
	if (max_num_sa > 0 || max_num_sp > 0) {
		OFP_INFO("IPsec not supported with SP. Disabling IPsec.");
		max_num_sa = 0;
		max_num_sp = 0;
	}
#endif

	if (max_num_sa > 0 &&
	    (param->inbound_op_mode == ODP_IPSEC_OP_MODE_INLINE ||
	     param->outbound_op_mode == ODP_IPSEC_OP_MODE_INLINE)) {
		OFP_ERR("Inline IPsec operation mode is not supported");
		return -1;
	}

	if (max_num_sa > 0 &&
	    (!op_mode_supported_by_odp(param->inbound_op_mode, &capa, 0) ||
	     !op_mode_supported_by_odp(param->outbound_op_mode, &capa, 1))) {
		OFP_ERR("Setting maximum number of IPsec SAs to zero");
		max_num_sa = 0;
	}

	/* Don't bother supporting asymmetrically disabled IPsec */
	if (max_num_sa > 0 &&
	    (param->inbound_op_mode == ODP_IPSEC_OP_MODE_DISABLED ||
	     param->outbound_op_mode == ODP_IPSEC_OP_MODE_DISABLED)) {
		OFP_INFO("IPsec inbound or outbound op mode is disabled.");
		OFP_INFO("Setting maximum number of IPsec SAs to zero.");
		max_num_sa = 0;
	}

	if (capa.max_num_sa < max_num_sa) {
		OFP_ERR("Used ODP does not support enough IPsec SAs "
			"(%" PRIu32 " requested, %" PRIu32 " supported)",
			max_num_sa, capa.max_num_sa);
		max_num_sa = capa.max_num_sa;
		OFP_ERR("Setting maximum number of SAs to %" PRIu32,
			max_num_sa);
	}

	if (max_num_sa > 0) {
		if (create_ev_queues(param, &in_queue, &out_queue) != 0)
			return -1;
		if (check_ev_queue(param->inbound_op_mode, in_queue) ||
		    check_ev_queue(param->outbound_op_mode, out_queue)) {
			destroy_ev_queues(in_queue, out_queue);
			return -1;
		}

		odp_ipsec_config_init(&config);
		config.inbound_mode = param->inbound_op_mode;
		config.outbound_mode = param->outbound_op_mode;
		config.max_num_sa = max_num_sa;
		config.inbound.default_queue = in_queue;
		config.inbound.lookup.min_spi = 0;
		config.inbound.lookup.max_spi = param->max_inbound_spi;
		config.inbound.lookup.spi_overlap = 0;
		config.inbound.retain_outer = ODP_PROTO_LAYER_NONE;
		config.inbound.parse_level = ODP_PROTO_LAYER_ALL;
		config.inbound.chksums.all_chksum = 0;
		config.outbound.all_chksum = 0;

		if (odp_ipsec_config(&config)) {
			OFP_ERR("odp_ipsec_config failed");
			destroy_ev_queues(in_queue, out_queue);
			return -1;
		}
	}

	if (ofp_ipsec_sad_init_global(max_num_sa, in_queue, out_queue)) {
		destroy_ev_queues(in_queue, out_queue);
		return -1;
	}
	if (ofp_ipsec_spd_init_global(max_num_sp)) {
		destroy_ev_queues(in_queue, out_queue);
		(void) ofp_ipsec_sad_term_global();
		return -1;
	}

	ofp_ipsec_shm = ofp_shared_memory_alloc(SHM_NAME_IPSEC,
						sizeof(*ofp_ipsec_shm));
	if (!ofp_ipsec_shm) {
		OFP_ERR("Failed to allocate IPsec shared memory");
		destroy_ev_queues(in_queue, out_queue);
		(void) ofp_ipsec_sad_term_global();
		(void) ofp_ipsec_spd_term_global();
		return -1;
	}
	odp_atomic_init_u32(&ofp_ipsec_shm->ipsec_active, 0);
	ofp_brlock_init(&ofp_ipsec_shm->processing_lock);
	ofp_ipsec_shm->max_num_sa = max_num_sa;
	ofp_ipsec_shm->inbound_op_mode = param->inbound_op_mode;
	ofp_ipsec_shm->outbound_op_mode = param->outbound_op_mode;
	ofp_ipsec_shm->in_queue = in_queue;
	ofp_ipsec_shm->out_queue = out_queue;

	/*
	 * Prevent protoswitch from calling us if we have not initialized
	 * ODP IPsec and cannot process ESP and AH packets.
	 */
	if (max_num_sa == 0) {
		ofp_ip_protox[OFP_IPPROTO_AH] = 0;
		ofp_ip_protox[OFP_IPPROTO_ESP] = 0;
	}

	return 0;
}

int ofp_ipsec_init_local(void)
{
	if (ofp_ipsec_sad_init_local())
		return -1;
	if (ofp_ipsec_spd_init_local())
		return -1;

	ofp_ipsec_shm = ofp_shared_memory_lookup(SHM_NAME_IPSEC);
	if (!ofp_ipsec_shm) {
		OFP_ERR("Failed to lookup IPsec shared memory");
		return -1;
	}
	return 0;
}

int ofp_ipsec_stop_global(void)
{
	(void) ipsec_sp_flush(0, 0);
	(void) ipsec_sa_flush(0, 0);
	return 0;
}

int ofp_ipsec_term_global_ok(void)
{
	ofp_ipsec_sa_handle sa;

	sa = ofp_ipsec_sa_first();
	if (sa == OFP_IPSEC_SA_INVALID)
		return 1;
	ofp_ipsec_sa_unref(sa);
	return 0;
}

int ofp_ipsec_term_global(void)
{
	ofp_ipsec_spd_term_global();
	ofp_ipsec_sad_term_global();
	destroy_ev_queues(ofp_ipsec_shm->in_queue,
			  ofp_ipsec_shm->out_queue);
	ofp_shared_memory_free(SHM_NAME_IPSEC);
	return 0;
}

enum ofp_return_code ofp_ipsec_output(odp_packet_t pkt,
				      ofp_ipsec_sa_handle sa)
{
	int lock_held;
	enum ofp_return_code ret;

	/*
	 * Outbound processing lock must have been taken by the
	 * caller through ofp_ipsec_out_lookup().
	 */
	lock_held = 1;

	ret = ipsec_output(pkt, sa, &lock_held);

	if (lock_held) {
		ofp_brlock_read_unlock(&ofp_ipsec_shm->processing_lock);
	}
	return ret;
}

enum ofp_return_code ofp_ipsec_input(odp_packet_t *pkt, int off)
{
	odp_ipsec_in_param_t param = {.num_sa = 0}; /* offload SA lookup */
	odp_packet_t pkt_out;
	int lock_held;
	int num_out = 1;
	int ret;
	(void) off;

	if (odp_unlikely(ofp_ipsec_shm->inbound_op_mode
			 == ODP_IPSEC_OP_MODE_DISABLED))
		return OFP_PKT_DROP;

	/*
	 * Async processing in async and inline mode
	 */
	if (ofp_ipsec_shm->inbound_op_mode != ODP_IPSEC_OP_MODE_SYNC) {
		ret = odp_ipsec_in_enq(pkt, 1, &param);
		if (odp_unlikely(ret <= 0)) {
			OFP_ERR("odp_ipsec_in_enq() failed: %d", ret);
			return OFP_PKT_DROP;
		}
		return OFP_PKT_PROCESSED;
	}

	/*
	 * Sync mode processing
	 */
	ofp_brlock_read_lock(&ofp_ipsec_shm->processing_lock);

	ret = odp_ipsec_in(pkt, 1, &pkt_out, &num_out, &param);
	if (odp_unlikely(ret <= 0)) {
		OFP_ERR("odp_ipsec_in() failed: %d", ret);
		ofp_brlock_read_unlock(&ofp_ipsec_shm->processing_lock);
		return OFP_PKT_DROP;
	}
	lock_held = 1;
	process_result_packet(pkt_out, &lock_held);
	if (lock_held) {
		ofp_brlock_read_unlock(&ofp_ipsec_shm->processing_lock);
	}
	return OFP_PKT_PROCESSED;
}

/*
 * Continue IPsec input after ODP IPsec processing
 */
static enum ofp_return_code ipsec_input_continue(odp_packet_t *pktp,
						 const ofp_ipsec_sa_param_t *sa_param,
						 int *lock_held)
{
	odp_packet_t pkt = *pktp;
	ofp_ipsec_mode_t  mode = sa_param->mode;

	ofp_ipsec_flags_set(pkt, OFP_IPSEC_INBOUND_DONE);

	if (*lock_held) {
		ofp_brlock_read_unlock(&ofp_ipsec_shm->processing_lock);
		*lock_held = 0;
	}

	if (mode == OFP_IPSEC_MODE_TRANSPORT) {
		if (odp_packet_has_ipv4(pkt)) {
			struct ofp_ip *ip;
			ip = odp_packet_l3_ptr(pkt, NULL);
			return ipv4_transport_classifier(pktp, ip->ip_p);
		} else {
			OFP_ERR("Non-IPv4 packet after IPsec decapsulation");
		}
	} else {
		if (odp_packet_has_ipv4(pkt))
			return ofp_ipv4_processing(pktp);
		else {
			OFP_ERR("Non-IPv4 packet after IPsec decapsulation");
		}
	}
	return OFP_PKT_DROP;
}

static enum ofp_return_code ipsec_output(odp_packet_t pkt,
					 ofp_ipsec_sa_handle sa,
					 int *lock_held)
{
	odp_ipsec_out_param_t param = {0};
	const ofp_ipsec_sa_param_t *sa_param = ofp_ipsec_sa_get_param(sa);
	odp_ipsec_sa_t odp_sa = ofp_ipsec_sa_get_odp_sa(sa);
	odp_packet_t pkt_out;
	int num_out = 1;
	int ret;

	if (sa_param->mode == OFP_IPSEC_MODE_TRANSPORT) {
		/* TODO: check that this is not a forwarded packet */
	}

	param.num_sa = 1;
	param.sa = &odp_sa;

	/*
	 * Async and inline processing
	 */
	if (ofp_ipsec_shm->outbound_op_mode != ODP_IPSEC_OP_MODE_SYNC) {
		ret = odp_ipsec_out_enq(&pkt, 1, &param);
		if (odp_unlikely(ret <= 0)) {
			OFP_ERR("odp_ipsec_out_enq() failed: %d", ret);
			return OFP_PKT_DROP;
		}
		return OFP_PKT_PROCESSED;
	}

	/*
	 * Sync processing
	 */
	ret = odp_ipsec_out(&pkt, 1, &pkt_out, &num_out, &param);
	if (odp_unlikely(ret <= 0)) {
		OFP_ERR("odp_ipsec_out() failed: %d", ret);
		return OFP_PKT_DROP;
	}
	process_result_packet(pkt_out, lock_held);
	return OFP_PKT_PROCESSED;
}

/*
 * Continue IPsec output after ODP IPsec processing
 */
static enum ofp_return_code ipsec_output_continue(odp_packet_t pkt)
{
	if (odp_packet_has_ipv4(pkt)) {
		/*
		 * IP ID and header checksum have now been set by ODP.
		 * Output the packet without rewriting them.
		 */
		return ofp_ip_output_common(pkt, NULL, 0, OFP_IPSEC_SA_INVALID);
	} else
		OFP_ERR("Non-IPv4 packet after IPsec encapsulation");

	return OFP_PKT_DROP;
}

void ofp_ipsec_packet_event(odp_event_t ev, odp_queue_t queue)
{
	odp_packet_t pkt;
	int lock_held = 0;

	(void) queue;
	pkt = odp_ipsec_packet_from_event(ev);
	process_result_packet(pkt, &lock_held);
}

static void process_result_packet(odp_packet_t pkt, int *lock_held)
{
	odp_ipsec_packet_result_t result;

	if (odp_ipsec_result(&result, pkt)) {
		OFP_ERR("odp_ipsec_result() failed");
		odp_packet_free(pkt);
		return;
	}

	switch (process_result(&pkt, &result, lock_held)) {
	case OFP_PKT_DROP:
		odp_packet_free(pkt);
		break;
	case OFP_PKT_CONTINUE:
		/*
		 * IPsec not supported with SP
		 */
		odp_packet_free(pkt);
		break;
	case OFP_PKT_PROCESSED:
	default:
		break;
	}
}

static enum ofp_return_code process_result(odp_packet_t *pkt_ptr,
					   odp_ipsec_packet_result_t *res,
					   int *lock_held)
{
	odp_packet_t pkt = *pkt_ptr;
	const ofp_ipsec_sa_param_t *sa_param;
	enum ofp_return_code ret = OFP_PKT_CONTINUE;
	odp_ipsec_op_status_t status = res->status;
	ofp_ipsec_sa_handle sa;
	uint32_t garbage_len;

	if (odp_unlikely(status.error.all))
		return OFP_PKT_DROP;

	sa = odp_ipsec_sa_context(res->sa);

	garbage_len = odp_packet_l3_offset(pkt);
	if (garbage_len > 0) {
		uint32_t l4_offset = odp_packet_l4_offset(pkt);
		void *data = odp_packet_pull_head(pkt, garbage_len);

		if (odp_unlikely(data == NULL)) {
			if (odp_packet_trunc_head(&pkt, garbage_len,
						  NULL, NULL) < 0) {
				return OFP_PKT_DROP;
			}
			*pkt_ptr = pkt;
		}
		odp_packet_l3_offset_set(pkt, 0);
		odp_packet_l4_offset_set(pkt, l4_offset - garbage_len);
	}
	odp_packet_l2_offset_set(pkt, 0);

	/*
	 * OFP does not support segmented packets
	 */
	if (odp_unlikely(odp_packet_is_segmented(pkt))) {
		OFP_ERR("Got segmented packet from ODP IPsec, giving up\n");
		return OFP_PKT_DROP;
	}

	if (ret == OFP_PKT_CONTINUE) {
		sa_param = ofp_ipsec_sa_get_param(sa);
		if (sa_param->dir == OFP_IPSEC_DIR_OUTBOUND) {
			if (*lock_held) {
				ofp_brlock_read_unlock(&ofp_ipsec_shm->processing_lock);
				*lock_held = 0;
			}
			ret = ipsec_output_continue(pkt);
		} else {
			ret = ipsec_input_continue(pkt_ptr, sa_param,
						   lock_held);
		}
	}
	return ret;
}

ofp_ipsec_sp_handle ofp_ipsec_sp_create(const ofp_ipsec_sp_param_t *param)
{
	ofp_ipsec_sa_handle *sa_ptr;
	ofp_ipsec_sp_handle sp;
	uint32_t active;

	sp = ofp_ipsec_sp_add(param);
	if (sp != OFP_IPSEC_SP_INVALID) {
		sa_ptr = ofp_ipsec_sp_get_sa_area(sp);
		*sa_ptr = OFP_IPSEC_SA_INVALID;

		ofp_brlock_write_lock(&ofp_ipsec_shm->processing_lock);
		ofp_ipsec_sp_lookup_add_sp(sp);

		active = odp_atomic_load_u32(&ofp_ipsec_shm->ipsec_active);
		if (!active)
			odp_atomic_store_u32(&ofp_ipsec_shm->ipsec_active, 1);

		ofp_brlock_write_unlock(&ofp_ipsec_shm->processing_lock);
	}
	return sp;
}

int ofp_ipsec_sp_destroy(ofp_ipsec_sp_handle sp)
{
	ofp_ipsec_sa_handle *sa_ptr;
	ofp_ipsec_sa_handle sa;
	int empty;

	/*
	 * First delete from lookup to avoid race with SP creation
	 */
	sa_ptr = ofp_ipsec_sp_get_sa_area(sp);
	ofp_brlock_write_lock(&ofp_ipsec_shm->processing_lock);
	sa = *sa_ptr;
	*sa_ptr = OFP_IPSEC_SA_INVALID;
	if (ofp_ipsec_sp_lookup_del_sp(sp, &empty)) {
		/*
		 * SP was not found in lookup. Either the it has already been
		 * deleted or its creation has not yet completed.
		 */
		ofp_brlock_write_unlock(&ofp_ipsec_shm->processing_lock);
		return -1;
	}
	if (empty)
		odp_atomic_store_u32(&ofp_ipsec_shm->ipsec_active, 0);

	ofp_brlock_write_unlock(&ofp_ipsec_shm->processing_lock);
	ofp_ipsec_sa_unref(sa);

	/*
	 * Delete from SPD
	 */
	if (ofp_ipsec_sp_del(sp))
		return -1;

	return 0;
}

static int ipsec_sp_flush(int check_vrf, uint16_t vrf)
{
	ofp_ipsec_sp_handle sp;
	int ret = 0;

	sp = ofp_ipsec_sp_first();
	while (sp != OFP_IPSEC_SP_INVALID) {
		const ofp_ipsec_sp_param_t *param = ofp_ipsec_sp_get_param(sp);
		if (!check_vrf || param->vrf == vrf)
			ret |= ofp_ipsec_sp_destroy(sp);

		sp = ofp_ipsec_sp_next(sp);
	}
	return ret;
}

int ofp_ipsec_sp_flush(uint16_t vrf)
{
	return ipsec_sp_flush(1, vrf);
}

int ofp_ipsec_sp_bind(ofp_ipsec_sp_handle sp, ofp_ipsec_sa_handle sa)
{
	ofp_ipsec_sa_handle *sa_ptr;
	ofp_ipsec_sa_handle old_sa;
	const ofp_ipsec_sp_param_t *sp_param = ofp_ipsec_sp_get_param(sp);
	const ofp_ipsec_sa_param_t *sa_param = ofp_ipsec_sa_get_param(sa);

	if (sp_param->dir != sa_param->dir) {
		OFP_ERR("Cannot bind IPsec SP and SA: "
			"directions do not match");
		return -1;
	}
	if (sp_param->dir == OFP_IPSEC_DIR_INBOUND) {
		OFP_ERR("Post-decapsulation policy check not yet implemented.");
		return -1;
	}

	sa_ptr = ofp_ipsec_sp_get_sa_area(sp);
	ofp_brlock_write_lock(&ofp_ipsec_shm->processing_lock);
	old_sa = *sa_ptr;
	*sa_ptr = sa;
	ofp_brlock_write_unlock(&ofp_ipsec_shm->processing_lock);
	ofp_ipsec_sa_unref(old_sa);
	ofp_ipsec_sa_ref(sa);
	return 0;
}

ofp_ipsec_action_t ofp_ipsec_in_lookup(uint16_t vrf, odp_packet_t pkt)
{
	ofp_ipsec_action_t action;

	ofp_brlock_read_lock(&ofp_ipsec_shm->processing_lock);
	action = ofp_ipsec_sp_in_lookup(vrf, pkt);
	ofp_brlock_read_unlock(&ofp_ipsec_shm->processing_lock);
	return action;
}

ofp_ipsec_action_t ofp_ipsec_out_lookup_priv(uint16_t vrf,
					     odp_packet_t pkt,
					     ofp_ipsec_sa_handle *sa)
{
	ofp_ipsec_action_t action;

	ofp_brlock_read_lock(&ofp_ipsec_shm->processing_lock);
	action = ofp_ipsec_sp_out_lookup(vrf, pkt, sa);
	if (*sa == OFP_IPSEC_SA_INVALID)
		ofp_brlock_read_unlock(&ofp_ipsec_shm->processing_lock);
	return action;
}

int ofp_ipsec_sa_destroy(ofp_ipsec_sa_handle sa)
{
	const ofp_ipsec_sa_param_t *param = ofp_ipsec_sa_get_param(sa);
	odp_ipsec_op_mode_t op_mode;

	if (ofp_ipsec_sa_disable(sa))
		return -1;

	/* Wait that other threads stop using the SA. */
	ofp_brlock_write_lock(&ofp_ipsec_shm->processing_lock);
	ofp_brlock_write_unlock(&ofp_ipsec_shm->processing_lock);

	if (ofp_ipsec_sa_disable_finish(sa))
		return -1;

	if (param->dir == OFP_IPSEC_DIR_INBOUND)
		op_mode = ofp_ipsec_shm->inbound_op_mode;
	else
		op_mode = ofp_ipsec_shm->outbound_op_mode;
	/*
	 * Sync mode SAs can now be destroyed for good as no other thread
	 * is using them. Async and inline mode SAs may have packets in
	 * flight and will be fully destroyed in the event handler for the
	 * disable completion event after all packet events for the SA
	 * have been processed.
	 */
	if (op_mode == ODP_IPSEC_OP_MODE_SYNC)
		return ofp_ipsec_sa_destroy_finish(sa);

	return 0;
}

static int ipsec_sa_flush(int check_vrf, uint16_t vrf)
{
	ofp_ipsec_sa_handle sa;
	int ret = 0;

	sa = ofp_ipsec_sa_first();
	while (sa != OFP_IPSEC_SA_INVALID) {
		const ofp_ipsec_sa_param_t *param = ofp_ipsec_sa_get_param(sa);
		if (!check_vrf || param->vrf == vrf)
			ret |= ofp_ipsec_sa_destroy(sa);

		sa = ofp_ipsec_sa_next(sa);
	}
	return ret;
}

int ofp_ipsec_sa_flush(uint16_t vrf)
{
	return ipsec_sa_flush(1, vrf);
}

void ofp_ipsec_status_event(odp_event_t ev, odp_queue_t queue)
{
	odp_ipsec_status_t status;

	if (odp_ipsec_status(&status, ev) < 0) {
		OFP_ERR("Error parsing IPsec status event");
		odp_event_free(ev);
		return;
	}
	odp_event_free(ev);

	switch (status.id) {
	case ODP_IPSEC_STATUS_SA_DISABLE:
		handle_sa_disable_completion(&status, queue);
		break;
	default:
		OFP_ERR("Unknown IPsec status event (id = %d)",
			(int) status.id);
		break;
	}
}

static void handle_sa_disable_completion(const odp_ipsec_status_t *status,
					 odp_queue_t queue)
{
	ofp_ipsec_sa_handle sa = odp_ipsec_sa_context(status->sa);

	if (status->result < 0) {
		OFP_ERR("Failed to finish disabling ODP SA (%"PRIu64")",
			odp_ipsec_sa_to_u64(status->sa));
		return;
	}

	/*
	 * Make sure other threads complete the processing of preceding
	 * packet completion events for this SA.
	 *
	 * - If the event queue is atomic, other threads have already
	 *   stopped processing all packet events for this SA.
	 * - If the event queue is ordered, we use an ordered lock to
	 *   ensure the other threads are done.
	 * - If the event queue is parallel or not scheduled at all,
	 *   we assume that the OFP application somehow ensures that
	 *   the SA is no longer in
	 */
	if (odp_queue_type(queue) == ODP_QUEUE_TYPE_SCHED &&
	    odp_queue_sched_type(queue) == ODP_SCHED_SYNC_ORDERED) {
		odp_schedule_order_lock(0);
		/* At this point other threads are done with this SA. */
		odp_schedule_order_unlock(0);
	}

	ofp_ipsec_sa_destroy_finish(sa);
}
