
#ifndef __globals__hxx__
#define __globals__hxx__

#define PY_SSIZE_T_CLEAN

#include <Python.h>

#define _GNU_SOURCE 1
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

#include <libunwind-ptrace.h>
#include <string>
#include <vector>
#include <memory>

#include "timer.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}

#define TODO_assert assert

int py_init(const char *mod_name,
		int script_argc, char **script_argv);

int shook_set_syscall(pid_t pid, int syscall);
int shook_set_gdb(pid_t pid);
long shook_get_return(pid_t pid);
int shook_set_return(pid_t pid, long ret_val);
int shook_suspend(pid_t pid, unsigned int seconds);
int shook_resume(pid_t pid);
int shook_detach(pid_t pid);
void shook_write(int stream, const char *str);
long shook_alloc_stack(pid_t pid, size_t len);
long shook_alloc_copy(pid_t pid, const void *data, size_t len);

void shook_set_timer(ya_timer_t *timer, ya_tick_diff_t milli_seconds);
void shook_cancel_timer(ya_timer_t *timer);

#define SHOOK_PROCESS_ENUM \
	SHOOK_PROCESS_DECL(UNKNOWN) \
	SHOOK_PROCESS_DECL(CREATED) \
	SHOOK_PROCESS_DECL(ATTACHED) \
	SHOOK_PROCESS_DECL(DETACHED) \
	SHOOK_PROCESS_DECL(FORK) \
	SHOOK_PROCESS_DECL(VFORK) \
	SHOOK_PROCESS_DECL(CLONE) \

enum {
#define SHOOK_PROCESS_DECL(x) SHOOK_PROCESS_##x,
	SHOOK_PROCESS_ENUM
#undef SHOOK_PROCESS_DECL
	SHOOK_PROCESS_MAX
};

#define SHOOK_ACTION_ENUM \
	SHOOK_ACTION_DECL(NONE) \
	SHOOK_ACTION_DECL(BYPASS) \
	SHOOK_ACTION_DECL(REDIRECT) \
	SHOOK_ACTION_DECL(RETURN) \
	SHOOK_ACTION_DECL(KILL) \
	SHOOK_ACTION_DECL(SUSPEND) \
	SHOOK_ACTION_DECL(DETACH) \
	SHOOK_ACTION_DECL(GDB)

enum {
#define SHOOK_ACTION_DECL(x) SHOOK_ACTION_##x,
	SHOOK_ACTION_ENUM
#undef SHOOK_ACTION_DECL
	SHOOK_ACTION_MAX,
};

struct pyobj_t
{
	explicit pyobj_t(PyObject *o = nullptr) : obj(o) {
	}

	pyobj_t(const pyobj_t &o): obj(o.obj) {
		Py_XINCREF(obj);
	}

	~pyobj_t() {
		Py_XDECREF(obj);
	}

	pyobj_t &operator=(PyObject *o) {
		if (obj != o) {
			Py_XDECREF(obj);
			obj = o;
		}
		return *this;
	}

	pyobj_t &operator=(const pyobj_t &o) {
		if (obj != o.obj) {
			Py_XDECREF(obj);
			obj = o.obj;
			Py_XINCREF(obj);
		}
		return *this;
	}

	operator PyObject *() const {
		return obj;
	}

	bool is_null() const {
		return obj == nullptr;
	}

private:
	PyObject *obj;
};

struct context_t
{
	unsigned int action;
	unsigned int scno;
	unsigned int argc;
	unsigned long suspend_time; // in milliseconds
	unsigned int signo;
	long retval;
	long args[6];

	int state;
	int signal_depth = 0;
	bool modified = false;
	pyobj_t last_retval, last_args;
	std::vector<pyobj_t> stack;
};

int shook_py_emit_enter_signal(bool abort_on_error, pid_t pid, context_t &context);
int shook_py_emit_enter_syscall(bool abort_on_error, pid_t pid, context_t &context);
int shook_py_emit_leave_syscall(bool abort_on_error, pid_t pid, context_t &context);
int shook_py_emit_process(bool abort_on_error, pid_t pid, unsigned int process_type, int ppid);
int shook_py_emit_finish(bool abort_on_error);

struct stackframe_t
{
	stackframe_t(unw_word_t ip_, unw_word_t offset_, const char *s) : ip(ip_), offset(offset_), symbol(s) { }
	stackframe_t(unw_word_t ip_) : ip(ip_), offset(0), symbol("<unknown>") { }
	unw_word_t ip;
	unw_word_t offset;
	std::string symbol;
};

int shook_backtrace(std::vector<stackframe_t> &stacks, pid_t pid, unsigned int depth);

#endif

#endif /* __globals__hxx__ */

