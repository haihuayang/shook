
#ifndef __timerq__h__
#define __timerq__h__

#ifndef __cplusplus
#error Must C++
#endif

#include "timer.h"
#include <vector>

struct ya_timerq_t
{
	ya_timerq_t() : timers{nullptr} { }

	void schedule(ya_timer_t *timer, ya_tick_t now, ya_tick_diff_t intval);
	void cancel(ya_timer_t *timer);
	bool run(ya_tick_t now, ya_tick_t *next);

	std::vector<ya_timer_t *> timers;
	std::vector<ya_timer_t *> temp_timers;
};

#endif /* __timerq__h__ */

