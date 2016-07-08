/*-
 * Copyright (c) 2016 Nokia
 * Copyright (c) 2016 ENEA Software AB
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <string.h>
#include <inttypes.h>

#include "odp.h"
#include "api/ofp_config.h"
#include "ofpi_util.h"
#include "ofpi_log.h"


#include "ofpi_timer.h"

#define SHM_NAME_TIMER "OfpTimerShMem"

struct ofp_timer_internal {
	struct ofp_timer_internal *next;
	odp_buffer_t buf;
	odp_event_t t_ev;
	uintptr_t id;
	ofp_timer_callback callback;
	char arg[OFP_TIMER_ARG_LEN];
};

struct ofp_timer_long_internal {
	struct ofp_timer_internal tmo;
};

#define TIMER_POOL_SIZE	 (1024*1024) /* Timer pool size */
#define TIMER_NUM_TIMERS	10000
#define TIMER_LONG_SHIFT	13
#define TIMER_NUM_LONG_SLOTS    (1<<TIMER_LONG_SHIFT)
#define TIMER_LONG_MASK	 (TIMER_NUM_LONG_SLOTS-1)

/* MASK applied over odp_timer_t value when OFP handles the timer internally */
#define OFP_TIMER_MASK (1UL << (sizeof(odp_timer_t) * 8 - 1))

struct ofp_timer_mem {
	char pool_space[TIMER_POOL_SIZE];
	odp_pool_t pool;
	odp_pool_t buf_pool;
	odp_queue_t queue;
	odp_queue_t queue_per_cpu[OFP_MAX_NUM_CPU];
	odp_timer_pool_t socket_timer_pool;
	struct ofp_timer_internal *long_table[TIMER_NUM_LONG_SLOTS];
	int sec_counter;
	size_t id;
	odp_spinlock_t lock;
	odp_timer_t timer_1s;
};

/*
 * Data per core
 */

static __thread struct ofp_timer_mem *shm;

static void ofp_timer_shm_init(void)
{
	uint32_t cpu_id;
	memset(shm, 0, sizeof(*shm));
	shm->pool = ODP_POOL_INVALID;
	shm->buf_pool = ODP_POOL_INVALID;
	shm->queue = ODP_QUEUE_INVALID;
	for (cpu_id = 0; cpu_id < OFP_MAX_NUM_CPU; cpu_id++)
		shm->queue_per_cpu[cpu_id] = ODP_QUEUE_INVALID;
	shm->socket_timer_pool = ODP_TIMER_POOL_INVALID;
	shm->timer_1s = ODP_TIMER_INVALID;
}

static void one_sec(void *arg)
{
	struct ofp_timer_internal *bufdata;
	(void)arg;

	odp_spinlock_lock(&shm->lock);
	shm->sec_counter = (shm->sec_counter + 1) & TIMER_LONG_MASK;
	bufdata = shm->long_table[shm->sec_counter];
	shm->long_table[shm->sec_counter] = NULL;
	odp_spinlock_unlock(&shm->lock);

	while (bufdata) {
		struct ofp_timer_internal *next = bufdata->next;
		bufdata->callback(&bufdata->arg);
		odp_buffer_free(bufdata->buf);
		bufdata = next;
	}

	/* Start one second timeout */
	shm->timer_1s = ofp_timer_start(1000000UL, one_sec, NULL, 0);
}

static int ofp_timer_alloc_shared_memory(void)
{
	shm = ofp_shared_memory_alloc(SHM_NAME_TIMER, sizeof(*shm));
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}

	return 0;
}

static int ofp_timer_free_shared_memory(void)
{
	int rc = 0;

	if (ofp_shared_memory_free(SHM_NAME_TIMER) == -1) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}
	shm = NULL;
	return rc;
}

static int ofp_timer_create_queues(void)
{
	odp_queue_param_t param;
	uint32_t cpu_id = 0;

	odp_queue_param_init(&param);
	param.type = ODP_QUEUE_TYPE_SCHED;
	param.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	param.sched.sync  = ODP_SCHED_SYNC_PARALLEL;
	param.sched.group = ODP_SCHED_GROUP_ALL;

	shm->queue = odp_queue_create("TimerQueue", &param);
	if (shm->queue == ODP_QUEUE_INVALID) {
		OFP_ERR("odp_queue_create failed");
		return -1;
	}

	for (cpu_id = 0; cpu_id < OFP_MAX_NUM_CPU; cpu_id++) {
		char queue_name_cpu[32];
		odp_queue_param_init(&param);

		param.type = ODP_QUEUE_TYPE_PLAIN;
		param.enq_mode = ODP_QUEUE_OP_MT_UNSAFE;
		param.deq_mode = ODP_QUEUE_OP_MT_UNSAFE;

		sprintf(queue_name_cpu,"TimerQueue_cpu_%u", cpu_id);

		shm->queue_per_cpu[cpu_id] = odp_queue_create(queue_name_cpu,
				&param);

		if (shm->queue_per_cpu[cpu_id] == ODP_QUEUE_INVALID) {
			OFP_ERR("ofp_queue_create failed");
			return -1;
		}
	}

	return 0;
}


int ofp_timer_init_global(int resolution_us,
		int min_us, int max_us,
		int tmo_count)
{
	odp_pool_param_t pool_params;
	odp_timer_pool_param_t timer_params;

	/* For later tuning. */
	(void)tmo_count;

	HANDLE_ERROR(ofp_timer_alloc_shared_memory());

	ofp_timer_shm_init();

	/* Timout pool */
	memset(&pool_params, 0, sizeof(pool_params));
	pool_params.tmo.num  = TIMER_NUM_TIMERS;
	pool_params.type  = ODP_POOL_TIMEOUT;

	shm->pool = ofp_pool_create("TimeoutPool", &pool_params);

	if (shm->pool == ODP_POOL_INVALID) {
		OFP_ERR("odp_pool_create failed");
		return -1;
	}

	/* Buffer pool */
	memset(&pool_params, 0, sizeof(pool_params));
	pool_params.buf.size  = sizeof(struct ofp_timer_internal);
	pool_params.buf.align = 0;
	pool_params.buf.num  = TIMER_NUM_TIMERS;
	pool_params.type  = ODP_POOL_BUFFER;

	shm->buf_pool = ofp_pool_create("TimeoutBufferPool", &pool_params);

	if (shm->buf_pool == ODP_POOL_INVALID) {
		OFP_ERR("odp_pool_create failed");
		return -1;
	}

	/* Timer pool */
	memset(&timer_params, 0, sizeof(timer_params));
	timer_params.res_ns = resolution_us*ODP_TIME_USEC_IN_NS;
	timer_params.min_tmo = min_us*ODP_TIME_USEC_IN_NS;
	timer_params.max_tmo = max_us*ODP_TIME_USEC_IN_NS;
	timer_params.num_timers = TIMER_NUM_TIMERS;
	timer_params.priv = 0; /* Shared */
	timer_params.clk_src = ODP_CLOCK_CPU;
	shm->socket_timer_pool = odp_timer_pool_create("TmrPool",
						       &timer_params);

	if (shm->socket_timer_pool == ODP_TIMER_POOL_INVALID) {
		OFP_ERR("odp_timer_pool_create");
		return -1;
	}

	odp_timer_pool_start();

	HANDLE_ERROR(ofp_timer_create_queues());

	odp_spinlock_init(&shm->lock);

	/* Start one second timeouts */
	shm->timer_1s = ofp_timer_start(1000000UL, one_sec, NULL, 0);

	return 0;
}

int ofp_timer_stop_global(void)
{
	int rc = 0;

	if (shm->timer_1s != ODP_TIMER_INVALID) {
		CHECK_ERROR(ofp_timer_cancel(shm->timer_1s), rc);
		shm->timer_1s = ODP_TIMER_INVALID;
	}

	return rc;
}

static int ofp_timer_term_queue(odp_queue_t *queue)
{
	int rc = 0;

	if (*queue != ODP_QUEUE_INVALID) {
		CHECK_ERROR(odp_queue_destroy(*queue), rc);
		*queue = ODP_QUEUE_INVALID;
	}

	return rc;
}

static int ofp_timer_term_queues(void)
{
	int rc;
	int i;

	rc = ofp_timer_term_queue(&shm->queue);

	for (i = 0; i < OFP_MAX_NUM_CPU; i++)
		rc = ofp_timer_term_queue(&shm->queue_per_cpu[i]);

	return rc;
}


int ofp_timer_term_global(void)
{
	int i;
	struct ofp_timer_internal *bufdata, *next;
	int rc = 0;

	if (ofp_timer_lookup_shared_memory())
		return -1;

	CHECK_ERROR(ofp_timer_stop_global(), rc);

/* Cleanup long timers*/
	for (i = 0; i < TIMER_NUM_LONG_SLOTS; i++) {
		bufdata = shm->long_table[i];
		if (!bufdata)
			continue;

		while (bufdata) {
			next = bufdata->next;
			odp_buffer_free(bufdata->buf);
			bufdata = next;
		}
	}

/* Cleanup timer related ODP objects*/
	CHECK_ERROR(ofp_timer_term_queues(), rc);

	if (shm->socket_timer_pool != ODP_TIMER_POOL_INVALID) {
		odp_timer_pool_destroy(shm->socket_timer_pool);
		shm->socket_timer_pool = ODP_TIMER_POOL_INVALID;
	}

	if (shm->buf_pool != ODP_POOL_INVALID) {
		CHECK_ERROR(odp_pool_destroy(shm->buf_pool), rc);
		shm->buf_pool = ODP_POOL_INVALID;
	}

	if (shm->pool != ODP_POOL_INVALID) {
		CHECK_ERROR(odp_pool_destroy(shm->pool), rc);
		shm->pool = ODP_POOL_INVALID;
	}

	CHECK_ERROR(ofp_timer_free_shared_memory(), rc);

	return rc;
}


int ofp_timer_lookup_shared_memory(void)
{
	shm = ofp_shared_memory_lookup(SHM_NAME_TIMER);
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}
	return 0;
}

static odp_timer_t ofp_timer_alloc(int cpu_id, struct ofp_timer_internal *buf)
{
	if (cpu_id == -1)
		return odp_timer_alloc(shm->socket_timer_pool, shm->queue, buf);

	return odp_timer_alloc(shm->socket_timer_pool,
			shm->queue_per_cpu[cpu_id], buf);
}

odp_timer_t ofp_timer_start(uint64_t tmo_us, ofp_timer_callback callback,
			void *arg, int arglen)
{
	return ofp_timer_start_cpu_id(tmo_us, callback, arg, arglen, -1);
}

odp_timer_t ofp_timer_start_cpu_id(uint64_t tmo_us, ofp_timer_callback callback,
		       void *arg, int arglen, int cpu_id)
{
	uint64_t tick;
	uint64_t period;
	uint64_t period_ns;
	struct ofp_timer_internal *bufdata;
	odp_buffer_t buf;
	odp_timer_set_t t;
	odp_timeout_t tmo;

	/* Init shm if not done yet. */
	if ((shm == NULL) && ofp_timer_lookup_shared_memory()) {
		OFP_ERR("ofp_timer_lookup_shared_memory failed");
		return ODP_TIMER_INVALID;
	}

	/* Alloc user buffer */
	buf = odp_buffer_alloc(shm->buf_pool);
	if (buf == ODP_BUFFER_INVALID) {
		OFP_ERR("odp_buffer_alloc failed");
		return ODP_TIMER_INVALID;
	}

	bufdata = (struct ofp_timer_internal *)odp_buffer_addr(buf);
	bufdata->callback = callback;
	bufdata->buf = buf;
	bufdata->t_ev = ODP_EVENT_INVALID;
	bufdata->next = NULL;
	bufdata->id = 0;
	if (arg && arglen)
		memcpy(bufdata->arg, arg, arglen);

	if (tmo_us >= OFP_TIMER_MAX_US) {
		/* Long 1 s resolution timeout */
		uint64_t sec = tmo_us/1000000UL;
		if (sec > TIMER_NUM_LONG_SLOTS) {
			OFP_ERR("Timeout too long = %"PRIu64"s", sec);
		}

		odp_spinlock_lock(&shm->lock);
		size_t ix = (shm->sec_counter + sec) & TIMER_LONG_MASK;
		bufdata->id = ((shm->id++)<<TIMER_LONG_SHIFT) | ix | OFP_TIMER_MASK;
		bufdata->next = shm->long_table[ix];
		shm->long_table[ix] = bufdata;
		odp_spinlock_unlock(&shm->lock);

		return (odp_timer_t) bufdata->id;
	} else {
		/* Short 10 ms resolution timeout */
		odp_timer_t timer;

		/* Alloc timout event */
		tmo = odp_timeout_alloc(shm->pool);
		if (tmo == ODP_TIMEOUT_INVALID) {
			odp_buffer_free(buf);
			OFP_ERR("odp_timeout_alloc failed");
			return ODP_TIMER_INVALID;
		}
		bufdata->t_ev = odp_timeout_to_event(tmo);

		period_ns = tmo_us*ODP_TIME_USEC_IN_NS;
		period    = odp_timer_ns_to_tick(shm->socket_timer_pool, period_ns);
		tick      = odp_timer_current_tick(shm->socket_timer_pool);
		tick     += period;

		timer = ofp_timer_alloc(cpu_id, bufdata);

		if (timer == ODP_TIMER_INVALID) {
			odp_timeout_free(tmo);
			odp_buffer_free(buf);
			OFP_ERR("odp_timer_alloc failed");
			return ODP_TIMER_INVALID;
		}

		t = odp_timer_set_abs(timer, tick, &bufdata->t_ev);

		if (t != ODP_TIMER_SUCCESS) {
			odp_timeout_free(tmo);
			odp_buffer_free(buf);
			OFP_ERR("odp_timer_set_abs failed");
			return ODP_TIMER_INVALID;
		}

		return timer;
	}
	return ODP_TIMER_INVALID;
}

int ofp_timer_cancel(odp_timer_t tim)
{
	odp_event_t timeout_event = ODP_EVENT_INVALID;
	odp_timeout_t tmo;
	uintptr_t t = (uintptr_t) tim;
	struct ofp_timer_internal *bufdata;
	struct ofp_timer_internal *prev = NULL;

	if (tim == ODP_TIMER_INVALID)
		return 0;

	if (t & OFP_TIMER_MASK) {
		/* long timeout */
		odp_spinlock_lock(&shm->lock);
		bufdata = shm->long_table[t & TIMER_LONG_MASK];

		while (bufdata) {
			struct ofp_timer_internal *next = bufdata->next;
			if (bufdata->id == t) {
				if (prev == NULL)
					shm->long_table[t & TIMER_LONG_MASK] = next;
				else
					prev->next = next;
				odp_buffer_free(bufdata->buf);
				odp_spinlock_unlock(&shm->lock);
				return 0;
			}
			prev = bufdata;
			bufdata = next;
		}
		odp_spinlock_unlock(&shm->lock);
		return -1;
	}
	else {
		if (odp_timer_cancel(tim, &timeout_event) < 0)
		{
			OFP_WARN("Timeout already expired or inactive");
			return 0;
		}

		if (timeout_event != ODP_EVENT_INVALID) {
			tmo = odp_timeout_from_event(timeout_event);
			bufdata = odp_timeout_user_ptr(tmo);
			odp_buffer_free(bufdata->buf);
			odp_timeout_free(tmo);
		} else {
			OFP_WARN("Lost timeout buffer at timer cancel");
			return -1;
		}

		if (odp_timer_free(tim) != ODP_EVENT_INVALID) {
			OFP_ERR("odp_timer_free failed");
			return -1;
		}
	}

	return 0;
}

void ofp_timer_handle(odp_event_t ev)
{
	struct ofp_timer_internal *bufdata;
	odp_timeout_t tmo = odp_timeout_from_event(ev);
	odp_timer_t tim = odp_timeout_timer(tmo);

	bufdata = (struct ofp_timer_internal *)odp_timeout_user_ptr(tmo);
	fflush(NULL);
	bufdata->callback(&bufdata->arg);

	odp_buffer_free(bufdata->buf);
	odp_timeout_free(tmo);
	odp_timer_free(tim);
}

/*
 * During shutdown process, all OFP submodules cancel their timers. However, it
 * is possible that the timer is cancelled (thus preventing further expiration),
 * but a timeout event for a previous expiration of this timer is sitting in a
 * queue waiting to be scheduled. schedule_shutdown() calls this function to
 * cleanup these events.
 */
void ofp_timer_evt_cleanup(odp_event_t ev)
{
	odp_timeout_t tmo;
	odp_timer_t tim;
	struct ofp_timer_internal *bufdata;

	tmo = odp_timeout_from_event(ev);
	tim = odp_timeout_timer(tmo);
	bufdata = (struct ofp_timer_internal *) odp_timeout_user_ptr(tmo);

	odp_buffer_free(bufdata->buf);
	odp_timeout_free(tmo);
	odp_timer_free(tim);
}

/* timer_num defines the timer type. At the moment
   there is only one timer. */
int ofp_timer_ticks(int timer_num)
{
	(void)timer_num;
	if (!shm)
		return 0;
	return odp_timer_current_tick(shm->socket_timer_pool);
}

odp_timer_pool_t ofp_timer(int timer_num)
{
	(void)timer_num;
	return shm->socket_timer_pool;
}

odp_queue_t ofp_timer_queue_cpu(int cpu_id)
{
	if (!shm || cpu_id > OFP_MAX_NUM_CPU)
		return ODP_QUEUE_INVALID;
	return shm->queue_per_cpu[cpu_id];
}
