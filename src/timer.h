
#ifndef __timer__h__
#define __timer__h__

#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#define container_of(ptr, type, member) ((type *)((char *)ptr - offsetof(type, member)))
	
typedef unsigned long ya_tick_t;
typedef long ya_tick_diff_t;

#define YA_TICK_FROM_SEC(s) ((s) * 1000)
#define YA_TICK_FROM_MSEC(s) (s)

static inline ya_tick_t ya_get_tick(void)
{
#ifdef _WIN32
	return GetTickCount();
#else
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	return ((unsigned long)now.tv_sec) * 1000 + now.tv_nsec / 1000000;
	// return ((unsigned long)times(NULL)) * 10;
#endif
}

static inline ya_tick_diff_t ya_tick_cmp(ya_tick_t t1, ya_tick_t t2)
{
	return (ya_tick_diff_t)(t1 - t2);
}

typedef struct ya_timer_st ya_timer_t;
typedef ya_tick_diff_t (*ya_timer_fn_t)(ya_timer_t *timer, ya_tick_t now);

struct ya_timer_st
{
	long internal;
	ya_tick_t timeout;
	ya_timer_fn_t fn;
};

static inline void ya_timer_init(ya_timer_t *timer, ya_timer_fn_t fn)
{
	timer->internal = 0;
	timer->fn = fn;
}

static inline int ya_timer_is_scheduled(const ya_timer_t *timer)
{
	return timer->internal != 0;
}

#endif /* __timer__h__ */

