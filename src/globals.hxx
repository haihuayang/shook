
#ifndef __globals__hxx__
#define __globals__hxx__

#include "pycomp.hxx"

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

#define SHOOK_MAJOR_VERSION 0
#define SHOOK_MINOR_VERSION 2
#define SHOOK_PATCH_VERSION 1

#define STR_1(x) #x
#define STR(x) STR_1(x)

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}

#define TODO_assert assert

#define XSTR(s) #s
#define XSTR2(s) XSTR(s)

#ifndef __location__
#define __location__ __FILE__ ":" XSTR2(__LINE__)
#endif


enum {
	LOG_FATAL,
	LOG_ERROR,
	LOG_WARN,
	LOG_INFO,
	LOG_DEBUG,
	LOG_VERB,
	LOG_MAX,
};

#define LOG(level, ...) do { \
	if (level <= loglevel) { \
		shook_log(level, __VA_ARGS__); \
	} \
} while (0)

#define DBG(fmt, ...) LOG(LOG_DEBUG, "at %s:%d " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define VERB(fmt, ...) LOG(LOG_VERB, "at %s:%d:%s " fmt, __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)
#define WARN(fmt, ...) LOG(LOG_WARN, "at %s:%d " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define FATAL(fmt, ...) do { \
	LOG(LOG_FATAL, "at %s:%d " fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
	abort(); \
} while (0)

extern const char *g_build_date;
extern const char *g_git_commit;

extern unsigned int loglevel;
void shook_log(int level, const char *fmt, ...) __attribute__((format (printf, 2, 3)));
void shook_write(int stream, const char *str);
bool shook_output_init(const char *file, unsigned int level);

int py_init(const char *mod_name,
		int script_argc, char **script_argv);

int shook_set_syscall(pid_t pid, int syscall);
int shook_set_gdb(pid_t pid);
long shook_get_return(pid_t pid);
int shook_set_return(pid_t pid, long ret_val);
int shook_suspend(pid_t pid, unsigned int seconds);
int shook_resume(pid_t pid);
int shook_detach(pid_t pid);
long shook_alloc_stack(pid_t pid, size_t len);
long shook_alloc_copy(pid_t pid, const void *data, size_t len);

void shook_set_timer(ya_timer_t *timer, ya_tick_diff_t milli_seconds);
void shook_cancel_timer(ya_timer_t *timer);

enum {
	SHOOK_ABORT = -1,
};

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

static inline PyObject *py_incref(PyObject *o)
{
	assert(o->ob_refcnt > 0);
	Py_INCREF(o);
	return o;
}

static inline void py_decref(PyObject *o)
{
	assert(o->ob_refcnt > 0);
	Py_DECREF(o);
}

static inline PyObject *py_xincref(PyObject *o)
{
	return o ? py_incref(o) : o;
}

static inline void py_xdecref(PyObject *o)
{
	if (o) {
		py_decref(o);
	}
}

#define py_xcheckref(obj) assert(!(obj) || (obj)->ob_refcnt > 0)

struct pyobj_t
{
	explicit pyobj_t(PyObject *o = nullptr) : obj(o) {
		py_xcheckref(obj);
	}

	pyobj_t(pyobj_t &&o): obj(o.obj) {
		o.obj = nullptr;
	}

	pyobj_t(const pyobj_t &o): obj(py_xincref(o.obj)) {
	}

	~pyobj_t() {
		py_xdecref(obj);
	}

	pyobj_t &operator=(PyObject *o) {
		py_xcheckref(o);
		if (obj != o) {
			py_xdecref(obj);
			obj = o;
		}
		return *this;
	}

	pyobj_t &operator=(const pyobj_t &o) {
		if (obj != o.obj) {
			py_xdecref(obj);
			obj = py_xincref(o.obj);
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
	PyObject *obj = nullptr;
};

struct context_t
{
	unsigned int action;
	unsigned int scno;
	unsigned int argc;
	unsigned long suspend_time; // in milliseconds
	unsigned int signo{};
	long retval;
	long args[6];

	int state{};
	int signal_depth = 0;
	bool modified = false;
	pyobj_t last_retval, last_args;
	std::vector<pyobj_t> stack;
};

int shook_py_emit_leave_signal(bool abort_on_error, pid_t pid, context_t &context);
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

int shook_disable_vdso(pid_t pid, unsigned long rsp);

#define SCNO_INVALID ((unsigned int)-1)
enum {
#define X(s, argc, r, p) SCNO_##s,
#include "syscallent.h"
#undef X
	SCNO_MAX
};

extern const char *g_syscall_name[];
unsigned int get_scno_by_name(const char *name);

#endif

#endif /* __globals__hxx__ */

