#include "ofp_vs.h"

#define OFP_VS_MAX_TIMEOUT_TICKS (7200*HZ)
#define OFP_VS_US_PER_TICK (1000000UL/HZ)

DEFINE_PER_CPU(struct list_head *, ofp_vs_timer_list);
//DEFINE_PER_CPU(odp_timer_t, odp_timer);
DEFINE_PER_CPU(struct rte_timer, rte_timer);

RTE_DEFINE_PER_LCORE(volatile uint64_t, ofp_vs_timer_cursor) = 0;
RTE_DEFINE_PER_LCORE(volatile uint64_t, ofp_vs_ticks) = 0;
RTE_DEFINE_PER_LCORE(volatile uint64_t, ofp_vs_ticks_per_loop) = 1;

uint64_t ofp_vs_us_per_tick;
static uint64_t rte_cycles_per_ofp_tick; 

static inline struct list_head *ofp_vs_get_timer_list(uint64_t ticks,
						      int cpuid)
{
	struct list_head *timer_list = per_cpu(ofp_vs_timer_list, cpuid);

	assert(ticks <= OFP_VS_MAX_TIMEOUT_TICKS);

	return &timer_list[ticks];
}


static inline void __ofp_vs_del_timer(struct ofp_vs_timer *timer)
{
	
	if (timer->state)
		list_del(&timer->list);
	timer->state = 0;
}

void ofp_vs_timer_setup(struct ofp_vs_timer *timer,
			void (*cb)(void *arg),
			void *arg) {
	if (!timer)
		return;

	timer->expires = 0;
	timer->state = 0;
	timer->cb = cb;
	timer->arg = arg;
}

void ofp_vs_del_timer(struct ofp_vs_timer *timer)
{
	__ofp_vs_del_timer(timer);
}


void ofp_vs_mod_timer(struct ofp_vs_timer *timer, uint64_t expires)
{
	uint32_t cursor;
	struct list_head *timer_list;
	uint64_t ticks = ofp_timer_ticks(0);
	uint64_t timeout_ticks;

	if (expires < ticks) {
		timeout_ticks = 0;
	} else {
		timeout_ticks =
			(expires - ticks)/RTE_PER_LCORE(ofp_vs_ticks_per_loop);
	}

	
#ifdef OFP_DEBUG
	IP_VS_DBG(12, "expires:%lu timer.expires:%lu"
		" ticks:%lu to_ticks:%lu loopticks:%lu cpu:%d\n",
		expires, timer->expires, ticks,
		timeout_ticks, RTE_PER_LCORE(ofp_vs_ticks_per_loop),
		rte_lcore_id());
#endif

	assert(timeout_ticks <= OFP_VS_MAX_TIMEOUT_TICKS);

	timer->expires = expires;

	__ofp_vs_del_timer(timer);
	cursor = (RTE_PER_LCORE(ofp_vs_timer_cursor) + timeout_ticks) %
			OFP_VS_MAX_TIMEOUT_TICKS;
	timer_list = ofp_vs_get_timer_list(cursor, rte_lcore_id());
	list_add_tail(&timer->list, timer_list);
	timer->state = 1;
}

static void ofp_vs_timer_run(void *arg);

static void ofp_vs_rte_timer_cb(struct rte_timer *timer, void *arg)
{
	(void)timer;
	ofp_vs_timer_run(arg);
}

static void ofp_vs_timer_run(void *arg)
{
	uint64_t ticks = ofp_timer_ticks(0);
	uint32_t cursor = RTE_PER_LCORE(ofp_vs_timer_cursor);
	struct list_head *timer_list = per_cpu(ofp_vs_timer_list, rte_lcore_id());
	struct ofp_vs_timer *timer, *timer_next; 
	//int cpu = odp_cpu_id();	
	(void)arg;
	
	RTE_PER_LCORE(ofp_vs_ticks_per_loop) =
		ticks - RTE_PER_LCORE(ofp_vs_ticks);	
	if (RTE_PER_LCORE(ofp_vs_ticks_per_loop) <= 0)
		RTE_PER_LCORE(ofp_vs_ticks_per_loop) = 1;
	/*
	OFP_DBG("us per tick:%d last ticks:%d cur ticks:%d diff:%d\n",
		ofp_vs_us_per_tick, RTE_PER_LCORE(ofp_vs_ticks), ticks,
		RTE_PER_LCORE(ofp_vs_ticks_per_loop));
	*/
	RTE_PER_LCORE(ofp_vs_ticks) = ticks;
	
	if (cursor > OFP_VS_MAX_TIMEOUT_TICKS)
		cursor = 0;
	
	list_for_each_entry_safe(timer, timer_next,
				 &timer_list[cursor], list) {
		list_del(&timer->list);
		timer->expires = ticks;
		timer->state = 0;
		timer->cb(timer->arg);
	}

	if (!list_empty(&timer_list[cursor])) {
		uint32_t next_cursor = cursor + 1;

		if (next_cursor > OFP_VS_MAX_TIMEOUT_TICKS)
			next_cursor = 0;

		list_splice(&timer_list[cursor], &timer_list[next_cursor]);
	}

	RTE_PER_LCORE(ofp_vs_timer_cursor) = cursor + 1;	

	/*
	per_cpu(ofp_timer_handle, cpu) = ofp_timer_start_cpu_id(
				ofp_vs_us_per_tick, ofp_vs_timer_run, NULL,
				0, cpu);
	*/
}


int ofp_vs_timer_init(void)
{
	
	unsigned i; 
	int ret = 0;
	int cpu;

	ofp_vs_us_per_tick = odp_timer_tick_to_ns(ofp_timer(0), 1)/NS_PER_US;
	rte_cycles_per_ofp_tick = rte_get_timer_hz()*ofp_vs_us_per_tick/US_PER_SEC;

	for_each_possible_cpu(cpu) {
		struct list_head *timer_list = rte_malloc_socket(
				"conn_timer",
				sizeof(struct list_head) *
				(OFP_VS_MAX_TIMEOUT_TICKS + 1),
				0, rte_lcore_to_socket_id(cpu));

		if (timer_list == NULL) {
			for (i = 0; i < (unsigned)cpu; i++) {
				rte_free(per_cpu(ofp_vs_timer_list, i));
			}
			ret = -ENOMEM;
			break;
		}

		per_cpu(ofp_vs_timer_list, cpu) = timer_list;

		for (i = 0; i <= OFP_VS_MAX_TIMEOUT_TICKS; i++) {
			INIT_LIST_HEAD(&timer_list[i]);
		}
	}

	
	for_each_odp_cpumask(cpu, &ofp_vs_worker_cpumask) {
		/*
		per_cpu(odp_timer, cpu) =
			ofp_timer_start_cpu_id(ofp_vs_us_per_tick,
				ofp_vs_timer_run, NULL, 0, cpu);
		if (per_cpu(odp_timer, cpu) == ODP_TIMER_INVALID) {
			ret = -EINVAL;
			break;
		}
		*/
		rte_timer_init(&per_cpu(rte_timer, cpu));
		ret = rte_timer_reset(&per_cpu(rte_timer, cpu),
			rte_cycles_per_ofp_tick, PERIODICAL,
			cpu, ofp_vs_rte_timer_cb, NULL);
		if (ret < 0)
			break;
	}

	return ret;
}

void ofp_vs_timer_finish(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		rte_free(per_cpu(ofp_vs_timer_list, cpu));
	}
}

