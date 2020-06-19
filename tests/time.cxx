
#include <time.h>
#include <sys/time.h>
#include <stdio.h>

static void test_gettimeofday()
{
	struct timeval tv;
	int err = gettimeofday(&tv, NULL);
	printf("gettimeofday ret %d, %ld:%ld\n", err, tv.tv_sec, tv.tv_usec);
}

static void test_realtime()
{
	struct timespec ts;
	int err = clock_gettime(CLOCK_REALTIME, &ts);
	printf("realtime ret %d, %ld:%ld\n", err, ts.tv_sec, ts.tv_nsec);
}

static void test_time()
{
	time_t t = time(NULL);
	printf("time ret %ld\n", t);
}

int main()
{
	test_gettimeofday();
	test_realtime();
	test_time();
	return 0;
}

