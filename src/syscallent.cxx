
#include "globals.hxx"

const char *g_syscall_name[] = {
#define X(s, argc, r, p) #s,
#include "syscallent.h"
#undef X
};

unsigned int get_scno_by_name(const char *name)
{
	for (unsigned int scno = 0; scno < SCNO_MAX; ++scno) {
		if (strcmp(name, g_syscall_name[scno]) == 0) {
			return scno;
		}
	}
	return SCNO_INVALID;
}
