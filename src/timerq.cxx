
#include "timerq.h"
#include <vector>
#include <assert.h>
#include <stdlib.h>

static inline size_t left(size_t index)
{
	assert(index > 0);
	return index << 1;
}

static inline size_t parent(size_t index)
{
	assert(index > 1);
	return index >> 1;
}

static inline void unschedule(ya_timer_t *timer)
{
	timer->internal = 0;
}

static inline bool is_dirty(ya_timerq_t const *timerq)
{
	return timerq->timers[0] != NULL;
}

static inline void mark_dirty(ya_timerq_t *timerq)
{
	timerq->timers[0] = (ya_timer_t *)1;
}

static inline void mark_clean(ya_timerq_t *timerq)
{
	timerq->timers[0] = NULL;
}

static inline size_t get_count(const ya_timerq_t *timerq)
{
	return timerq->timers.size() - 1;
}

static inline ya_timer_t * const *get_timers(const ya_timerq_t *timerq)
{
	return timerq->timers.data();
}

static inline bool index_is_valid(const ya_timerq_t *timerq, size_t index)
{
	assert(index > 0);
	assert(index <= get_count(timerq));
	return index > 0 && index <= get_count(timerq);
}

static inline bool timer_is_valid(const ya_timerq_t *timerq, ya_timer_t const *timer)
{
	assert(index_is_valid(timerq, timer->internal));
	assert(timer == timerq->timers[timer->internal]);
	return index_is_valid(timerq, timer->internal) &&
		timer == timerq->timers[timer->internal];
}

#define YA_TIMERQ_CHECK 1
#ifdef YA_TIMERQ_CHECK
static inline void check_heap(const ya_timerq_t *timerq)
{
	if (is_dirty(timerq))
		return;
	ya_timer_t * const * timers = get_timers(timerq);
	assert(get_count(timerq) == 0 || (timers[1] != NULL && timers[1]->internal == 1));
	for (size_t i = 2; i <= get_count(timerq); ++i) {
		assert((size_t)timers[i]->internal == i);
		assert(ya_tick_cmp(timers[parent(i)]->timeout, timers[i]->timeout) <= 0);
	}
}

#define CHECK_HEAP check_heap
#else
#define CHECK_HEAP(x)
#endif

static inline ya_timer_t *get_timer(ya_timerq_t *timerq, size_t index)
{
	assert(index_is_valid(timerq, index));
	return timerq->timers[index];
}

static inline void set_timer(ya_timerq_t *timerq, size_t index, ya_timer_t *timer)
{
	assert(index_is_valid(timerq, index));
	timerq->timers[index] = timer;
	timer->internal = index;
}

static void swap(ya_timerq_t *timerq, size_t index1, size_t index2)
{
	assert(index1 != index2);
	ya_timer_t *timer1 = get_timer(timerq, index1);
	ya_timer_t *timer2 = get_timer(timerq, index2);
	set_timer(timerq, index1, timer2);
	set_timer(timerq, index2, timer1);
}

static void trickle_down(ya_timerq_t *timerq, size_t index)
{
	for (;;) {
		assert(index_is_valid(timerq, index));

		size_t l_index = left(index);
		if (l_index > get_count(timerq)) {
			// both left-node and right-node empty
			break;
		}

		ya_timer_t *timer = get_timer(timerq, index);
		ya_timer_t *l_timer = get_timer(timerq, l_index);
		long l_delta = ya_tick_cmp(l_timer->timeout, timer->timeout);

		if (l_index == get_count(timerq)) {
			// the left child is the last one
			if (l_delta < 0) {
				swap(timerq, index, l_index);
			}
			break;
		}

		// both left-node and right-node valid 
		size_t r_index = l_index + 1;
		ya_timer_t *r_timer = get_timer(timerq, r_index);
		long r_delta = ya_tick_cmp(r_timer->timeout, timer->timeout);
		if (l_delta >= 0 && r_delta >= 0) {
			break;
		}
	
		size_t swap_index;
		if (l_delta < r_delta) {
			swap_index = l_index;
		} else {
			swap_index = r_index;
		}
		swap(timerq, index, swap_index);
		index = swap_index;
	}
}

static void trickle_up(ya_timerq_t *timerq, size_t index)
{
	assert(index_is_valid(timerq, index));
	while (index != 1) {
		size_t p_index = parent(index);
		ya_timer_t *timer = get_timer(timerq, index);
		ya_timer_t *p_timer = get_timer(timerq, p_index);
		if (ya_tick_cmp(p_timer->timeout, timer->timeout) <= 0) {
			break;
		}
		swap(timerq, index, p_index);
		index = p_index;
	}
}

static void trickle(ya_timerq_t *timerq, size_t index)
{
	assert(index_is_valid(timerq, index));
	if (index > 1) {
		size_t p_index = parent(index);
		assert(index_is_valid(timerq, p_index));

		ya_timer_t *timer = get_timer(timerq, index);
		ya_timer_t *p_timer = get_timer(timerq, p_index);
		if (ya_tick_cmp(timer->timeout, p_timer->timeout) <= 0) {
			swap(timerq, index, p_index);
			trickle_up(timerq, p_index);
			return;
		}
	}
	trickle_down(timerq, index);
}

static inline void check_dirty(ya_timerq_t *timerq)
{
	if (is_dirty(timerq)) {
		set_timer(timerq, 1, timerq->timers.back());
		timerq->timers.pop_back();

		trickle_down(timerq, 1);
		mark_clean(timerq);
	}
	CHECK_HEAP(timerq);
}

static void timerq_insert(ya_timerq_t *timerq, ya_timer_t *timer)
{
	if (is_dirty(timerq)) {
		set_timer(timerq, 1, timer);
		trickle_down(timerq, 1);
		mark_clean(timerq);
	} else {
		timer->internal = timerq->timers.size();
		timerq->timers.push_back(timer);
		trickle_up(timerq, timer->internal);
	}
	CHECK_HEAP(timerq);
}

static void timerq_schedule__(ya_timerq_t *timerq, ya_timer_t *timer,
		ya_tick_t now, long intval)
{
	assert(!ya_timer_is_scheduled(timer));
	timer->timeout = now + intval;
	// if intval is 0 and timerq is running, store the timer other place to avoid run the timer forever
	if (intval == 0 && !timerq->temp_timers.empty()) {
		timer->internal = -(long)timerq->temp_timers.size();
		timerq->temp_timers.push_back(timer);
	} else {
		timerq_insert(timerq, timer);
	}
}

static bool timerq_run__(ya_timerq_t *timerq, ya_tick_t now, ya_tick_t *next)
{
	assert(timerq->temp_timers.empty());
	timerq->temp_timers.push_back(nullptr);
	for (;;) {
		check_dirty(timerq);
		size_t count = get_count(timerq);
		if (count == 0) {
			break;
		}
		ya_timer_t *timer = timerq->timers[1];
		if (ya_tick_cmp(timer->timeout, now) > 0) {
			break;
		}
		if (count == 1) {
			timerq->timers.pop_back();
		} else {
			mark_dirty(timerq);
		}
		unschedule(timer);

		long intval = timer->fn(timer, now);
		if (intval >= 0) {
			timerq_schedule__(timerq, timer, now, intval);
		}
	}

	for (size_t i = 1; i < timerq->temp_timers.size(); ++i) {
		ya_timer_t *timer = timerq->temp_timers[i];
		if (timer) {
			assert(timer->internal + i == 0);
			timerq_insert(timerq, timer);
		}
	}

	timerq->temp_timers.clear();
	if (get_count(timerq) == 0) {
		return false;
	} else {
		*next = timerq->timers[1]->timeout;
		return true;
	}
}

static void timerq_cancel__(ya_timerq_t *timerq, ya_timer_t *timer)
{
	if (timer->internal >= 0) {
		assert(timer_is_valid(timerq, timer));
		check_dirty(timerq);
		assert(timer_is_valid(timerq, timer));
		if ((size_t)timer->internal == get_count(timerq)) {
			timerq->timers.pop_back();
		} else {
			set_timer(timerq, timer->internal, timerq->timers.back());
			timerq->timers.pop_back();
			trickle(timerq, timer->internal);
		}
		unschedule(timer);
		CHECK_HEAP(timerq);
	} else {
		assert(timer->internal + timerq->temp_timers.size() > 0);
		assert(timer == timerq->temp_timers[-timer->internal]);
		timerq->temp_timers[-timer->internal] = nullptr;
	}
}

bool ya_timerq_t::run(ya_tick_t now, ya_tick_t *next)
{
	return timerq_run__(this, now, next);
}

void ya_timerq_t::cancel(ya_timer_t *timer)
{
	timerq_cancel__(this, timer);
}

void ya_timerq_t::schedule(ya_timer_t *timer, ya_tick_t now, long intval)
{
	return timerq_schedule__(this, timer, now, intval);
}



