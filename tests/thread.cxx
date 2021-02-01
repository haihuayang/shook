
#include <assert.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

static void *thread_func(void *arg)
{
	sleep(1000);
	return nullptr;
}

int main(int argc, char **argv)
{
	int i, count = atoi(argv[1]);
	pthread_t th[count];
	for (i = 0; i < count; ++i) {
		int err = pthread_create(&th[i], NULL, thread_func, NULL);
		assert(err == 0);
	}

	for (i = 0; i < count; ++i) {
		int err = pthread_join(th[i], NULL);
		assert(err == 0);
	}
	return 0;
}
