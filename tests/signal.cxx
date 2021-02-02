
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

static void signal_handler(int signo)
{
	printf("catch signal %d\n", signo);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		signal(SIGHUP, signal_handler);
	} else {
		for (int i = 1; i < argc; ++i) {
			int signo = atoi(argv[i]);
			signal(signo, signal_handler);
		}
	}

	for (;;) {
		pause();
	}
	return 0;
}

