#ifndef __OFP_VS_TIMER_H__
#define __OFP_VS_TIMER_H__

#include "kern_list.h"
#include "ofpi_timer.h"

struct ofp_vs_timer {
	struct list_head list;
	int state;
	uint64_t expires;
	void (*cb)(void *arg);
	void *arg;
};


void ofp_vs_mod_timer(struct ofp_vs_timer *timer, uint64_t expires);
void ofp_vs_del_timer(struct ofp_vs_timer *timer);
void ofp_vs_timer_setup(struct ofp_vs_timer *timer,
			void (*cb)(void *arg),
			void *arg);

int ofp_vs_timer_init(void);
void ofp_vs_timer_finish(void);

#endif
