
#include "globals.hxx"

#include <unordered_map>
#include <sstream>
#include <initializer_list>

#include <stdarg.h>
#include <fcntl.h>
#include <dirent.h>

#include <syscall.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/socket.h>
#include <sys/signalfd.h>
#include <sys/poll.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>

#include "timerq.h"
#include "utils.h"

static const struct {
	const char *name;
	int argc;
} g_syscalls[] = {
#define X(s, argc, r, p) { #s, argc, },
#include "syscallent.h"
#undef X
};

static const char *syscall_name(unsigned long scno)
{
	if (scno < sizeof(g_syscalls) / sizeof(g_syscalls[0])) {
		return g_syscalls[scno].name;
	} else {
		return "INVALID";
	}
}

static const char * const action_name[] = {
#define SHOOK_ACTION_DECL(x) #x,
	SHOOK_ACTION_ENUM
#undef SHOOK_ACTION_DECL
};

enum {
	FLAG_STARTUP = 1,
	FLAG_ENTERING = 2,
	FLAG_IGNORE_ONE_SIGSTOP = 4,
	FLAG_SUSPEND = 8,
	FLAG_BYPASS = 0x10,
	FLAG_GDB = 0x20,
	FLAG_DETACHING = 0x40,
	FLAG_CREATED = 0x80, // process is created by shook or child of process created by shook
};

enum class tcb_trace_state_t : uint8_t {
	S_NONE,
	S_ENTER_SYSCALL,
	S_LEAVE_SYSCALL,
	S_LEAVE_SIGNAL,
};

enum class tcb_life_state_t : uint8_t {
	S_0, // initialized
	S_1, // parent get process event (S_0->)
	S_2, // parent return from syscall (S_1->)
	S_3, // detached from S_1, wait for parent return from system
	S_4, // dead (S_2,S_3 ->)
};

struct unw_t
{
	~unw_t() {
		if (unw_addr_space) {
			unw_destroy_addr_space(unw_addr_space);
		}
	}

	unw_addr_space_t unw_addr_space = nullptr;
};

struct tcb_t
{
	tcb_t(pid_t pid_, unsigned int pt, unsigned ppid, uint32_t flags)
		: pid(pid_)
		, flags(flags | FLAG_STARTUP | FLAG_ENTERING | FLAG_IGNORE_ONE_SIGSTOP)
		, process_type(pt), create_pid(ppid) {
	}

	const pid_t pid;
	tcb_life_state_t life_state = tcb_life_state_t::S_0;
	tcb_trace_state_t trace_state = tcb_trace_state_t::S_NONE;
	uint32_t flags = FLAG_STARTUP | FLAG_ENTERING | FLAG_IGNORE_ONE_SIGSTOP;
	unsigned int process_type, create_pid;
	int save_status = 0;
	unsigned int last_syscall;
	unsigned int restart_signo = 0;
	// long next_retval;
	long tmp_mem_addr;

	/* TODO should reflesh addr space cache after execve? */
	std::shared_ptr<unw_t> uas;
	struct UPT_info *unw_info = nullptr;

	struct user_regs_struct regs;

	context_t context;
};

static int init_unw_cursor(unw_cursor_t &cursor, tcb_t &tcb)
{
	if (!tcb.unw_info) {
		if (!tcb.uas->unw_addr_space) {
			tcb.uas->unw_addr_space = unw_create_addr_space(&_UPT_accessors, 0);
			assert(tcb.uas->unw_addr_space);
			unw_set_caching_policy(tcb.uas->unw_addr_space, UNW_CACHE_GLOBAL);
		}
		tcb.unw_info = (struct UPT_info *)_UPT_create(tcb.pid);
		TODO_assert(tcb.unw_info);
	}

	return unw_init_remote(&cursor, tcb.uas->unw_addr_space, tcb.unw_info);
}

static const unsigned int syscall_trap_sig = SIGTRAP | 0x80;

enum {
	ABORT_STATE_NONE,
	ABORT_STATE_STARTED,
};

struct gstate_t
{
	std::unordered_map<pid_t, tcb_t> tcbs;
	ya_timerq_t timerq;
	ya_tick_t now;
	int signalfd = -1;
	bool enable_vdso = false;
	bool aborted = false;
	bool exiting = false;
	pid_t start_pid = -1;
	unsigned int exit_code = 0;
	unsigned int exit_timeout_ms = 5000;

	ya_timer_t exiting_timer;
};

static gstate_t gstate;
static bool abort_on_python_exception = false;

static void detached(tcb_t &tcb, unsigned int exit_code);

static int detach(pid_t pid)
{
	auto it = gstate.tcbs.find(pid);
	if (it == gstate.tcbs.end()) {
		return -2;
	} else if (it->second.flags & FLAG_DETACHING) {
		LOG(LOG_WARN, "pid %d is already in detaching", pid);
	} else {
		DBG("detaching %d", pid);
		auto &tcb = it->second;
		tcb.flags |= FLAG_DETACHING;
		int err = ptrace(PTRACE_DETACH, pid, 0, 0);
		if (err == 0) {
			detached(tcb, 0);
			return err;
		}
		assert(errno == ESRCH);
		err = ptrace(PTRACE_INTERRUPT, pid, 0, 0);
		if (err < 0) {
			FATAL("PTRACE_INTERRUPT %d errno %d", pid, errno);
		}
	}
	return 0;
}

static void exit_detach(tcb_t &tcb, int signo)
{
	uint32_t flags = tcb.flags & (FLAG_DETACHING | FLAG_CREATED);
	if (flags == FLAG_CREATED) {
		LOG(LOG_INFO, "killing %d %d", tcb.pid, signo);
		kill(tcb.pid, signo);
	} else if (flags == 0) {
		detach(tcb.pid);
	}
}

static ya_tick_diff_t exiting_timer_func(ya_timer_t *timer, ya_tick_t now)
{
	assert(timer == &gstate.exiting_timer);
	assert(gstate.exiting);

	LOG(LOG_ERROR, "exiting timeout, send SIGKILL to tracee");
	for (auto &it: gstate.tcbs) {
		exit_detach(it.second, SIGKILL);
	}

	return -1;
}

static void exiting()
{
	if (gstate.exiting) {
		return;
	}
	gstate.exiting = true;
	for (auto &it: gstate.tcbs) {
		exit_detach(it.second, SIGTERM);
	}
	ya_timer_init(&gstate.exiting_timer, exiting_timer_func);
	shook_set_timer(&gstate.exiting_timer, YA_TICK_FROM_MSEC(gstate.exit_timeout_ms));
}

static void shook_abort()
{
	LOG(LOG_INFO, "abort");
	if (!gstate.aborted) {
		gstate.aborted = true;
		exiting();
	}
}

#define CHECK_ABORT(action) do { \
	if (action == SHOOK_ABORT) { \
		shook_abort(); \
		return; \
	} \
} while (0)

static void emit_process(pid_t pid, unsigned int process_type, int ppid)
{
	if (gstate.aborted) {
		return;
	}

	int action = shook_py_emit_process(abort_on_python_exception, pid, process_type, ppid);
	CHECK_ABORT(action);
}

static void detached(tcb_t &tcb, unsigned int exit_code)
{
	if (tcb.pid == gstate.start_pid) {
		gstate.exit_code = exit_code;
	}

	emit_process(tcb.pid, SHOOK_PROCESS_DETACHED, 0);

	if (tcb.unw_info) {
		_UPT_destroy(tcb.unw_info);
		tcb.unw_info = nullptr;
	}

	if (tcb.life_state == tcb_life_state_t::S_2) {
		gstate.tcbs.erase(tcb.pid);
	} else if (tcb.life_state == tcb_life_state_t::S_1) {
		tcb.life_state = tcb_life_state_t::S_3;
	}
}

static void check_pid_changed(tcb_t &tcb, pid_t pid)
{
	unsigned long old_pid = 0;

	if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, (long)&old_pid) < 0)
		return;
	if (old_pid == (unsigned long)pid || old_pid > UINT_MAX)
		return;

	auto it_tcb = gstate.tcbs.find(old_pid);
	assert(it_tcb != gstate.tcbs.end());

	DBG("pid change from %ld to %d", old_pid, pid);
	// TODO terminal current syscall in pid's tcb

	tcb.flags = it_tcb->second.flags;
	// we do not have exit_code, just use 0
	detached(tcb, 0);
}

static const int arg_offsets[] = {
	long(&((struct user_regs_struct *)0)->rdi),
	long(&((struct user_regs_struct *)0)->rsi),
	long(&((struct user_regs_struct *)0)->rdx),
	long(&((struct user_regs_struct *)0)->r10),
	long(&((struct user_regs_struct *)0)->r8),
	long(&((struct user_regs_struct *)0)->r9),
};

static long get_argument(const struct user_regs_struct *regs, unsigned int index)
{
	return *(long *)((const char *)regs + arg_offsets[index]);
}

static void set_argument(const struct user_regs_struct *regs, unsigned int index, long val)
{
	*(long *)((const char *)regs + arg_offsets[index]) = val;
}

static void gdb(pid_t pid)
{
	// TODO should send CONT to other process?
	char str_pid[16];
	snprintf(str_pid, sizeof(str_pid), "%d", pid);
	int err = ptrace(PTRACE_DETACH, pid, (char *)1, SIGSTOP);
	LOG(LOG_INFO, "PTRACE_DETACH %d = %d, %d\n", pid, err, errno);
	unsetenv("PYTHONHOME");

        sigset_t mask;
        /* We will handle SIGTERM and SIGINT. */
        sigemptyset(&mask);
	err = sigprocmask(SIG_SETMASK, &mask, NULL);
	if (err < 0) {
		LOG(LOG_ERROR, "sigprocmask errno=%d\n", errno);
	}

	const char *gdbpath = getenv("GDB");
	if (!gdbpath) {
		gdbpath = "gdb";
	}
	execlp(gdbpath, "gdb", "-p", str_pid, NULL);
	LOG(LOG_ERROR, "Never be here\n");
	assert(0);
}

static tcb_t &tcb_create(pid_t pid, unsigned int type, pid_t create_pid,
		uint32_t flags)
{
	const auto &ret = gstate.tcbs.emplace(pid, tcb_t(pid, type, create_pid, flags));
	assert(ret.second);
	return ret.first->second;
}

static void trace_new_proc(const char *location, pid_t pid, unsigned int type,
		tcb_t &create_tcb)
{
	LOG(LOG_INFO, "%s trace_new_proc pid=%d, type=%d, creator=%d, flags=0x%x",
			location,
			pid, type, create_tcb.pid,
			create_tcb.flags & FLAG_CREATED);
	auto &tcb = tcb_create(pid, type, create_tcb.pid, create_tcb.flags & FLAG_CREATED);
	tcb.life_state = tcb_life_state_t::S_1;

	if (gstate.aborted) {
		exit_detach(tcb, SIGTERM);
	} else {
		if (type == SHOOK_PROCESS_CLONE) {
			tcb.uas = create_tcb.uas;
		} else {
			tcb.uas = std::make_shared<unw_t>();
		}
		emit_process(pid, type, create_tcb.pid);
	}
}

static tcb_t &trace_exist_proc(const char *location, pid_t pid,
		uint32_t type, pid_t create_pid, uint32_t flags,
		const std::shared_ptr<unw_t> &unw)
{
	LOG(LOG_INFO, "%s trace_exist_proc pid=%d, type=%d, creator=%d, flags=0x%x",
			location,
			pid, type, create_pid,
			flags);
	auto &tcb = tcb_create(pid, type, create_pid, flags);
	tcb.life_state = tcb_life_state_t::S_2;
	tcb.uas = unw;
	emit_process(pid, type, create_pid);
	return tcb;
}

static void update_proc(const char *location, tcb_t &tcb, pid_t pid, unsigned int type,
		tcb_t &create_tcb)
{
	if (tcb.process_type == SHOOK_PROCESS_UNKNOWN) {
		LOG(LOG_INFO, "%s update_proc pid=%d, old_type=%d, type=%d, creator=%d",
				location, pid, tcb.process_type, type, create_tcb.pid);
		tcb.process_type = type;
		tcb.create_pid = create_tcb.pid;
		tcb.flags |= (create_tcb.flags & FLAG_CREATED);
		if (type == SHOOK_PROCESS_CLONE) {
			tcb.uas = create_tcb.uas;
		} else {
			tcb.uas = std::make_shared<unw_t>();
		}
		emit_process(pid, type, create_tcb.pid);
	} else if (tcb.process_type != type) {
		LOG(LOG_ERROR, "%s update_proc pid=%d, old_type=%d, type=%d, creator=%d",
				location, pid, tcb.process_type, type, create_tcb.pid);
	}
}

#define TRACE_NEW_PROC(...) trace_new_proc(__location__, __VA_ARGS__)
#define TRACE_EXIST_PROC(...) trace_exist_proc(__location__, __VA_ARGS__)
#define UPDATE_PROC(...) update_proc(__location__, __VA_ARGS__)

/*
 * TODO, suppose script never modify syscall fork/vfork/clone
 */
static void check_new_process_return(pid_t pid, tcb_t &tcb, context_t &ctx)
{
	uint32_t new_proc_type = SHOOK_PROCESS_UNKNOWN;
	if (ctx.scno == SYS_clone) {
		/* is it enough just checking CLONE_THREAD? */
		if (ctx.args[0] & CLONE_THREAD) {
			new_proc_type = SHOOK_PROCESS_CLONE;
		} else {
			new_proc_type = SHOOK_PROCESS_FORK;
		}
	} else if (ctx.scno == SYS_fork) {
		new_proc_type = SHOOK_PROCESS_FORK;
	} else if (ctx.scno == SYS_vfork) {
		new_proc_type = SHOOK_PROCESS_VFORK;
	}

	if (new_proc_type != SHOOK_PROCESS_UNKNOWN && ctx.retval > 0) {
		pid_t new_pid = ctx.retval;
		auto new_it_tcb = gstate.tcbs.find(new_pid);
		assert (new_it_tcb != gstate.tcbs.end());

		auto &new_tcb = new_it_tcb->second;
		DBG("process_return %d new_pid %d, life_state %d", pid, new_pid,
				int(new_tcb.life_state));
		if (new_tcb.life_state == tcb_life_state_t::S_1) {
			new_tcb.life_state = tcb_life_state_t::S_2;
		} else if (new_tcb.life_state == tcb_life_state_t::S_3) {
			gstate.tcbs.erase(new_it_tcb);
		} else {
			assert(false);
		}
	}
}

static void emit_leave_signal(pid_t pid, tcb_t &tcb)
{
	if (gstate.aborted) {
		return;
	}

	int action = shook_py_emit_leave_signal(abort_on_python_exception, pid, tcb.context);
	CHECK_ABORT(action);

	if (action == SHOOK_ACTION_SUSPEND) {
		VERB("<- suspend pid=%d", pid);
		return;
	}

	if (tcb.context.modified) {
		tcb.restart_signo = tcb.context.signo;
	}

	if (action == SHOOK_ACTION_NONE) {
	} else if (action == SHOOK_ACTION_DETACH) {
		DBG("<- Action detach pid=%d", pid);
		detach(pid);
	} else if (action == SHOOK_ACTION_GDB) {
		DBG("<- Action gdb pid=%d", pid);
		gdb(pid);
	} else {
		assert(0);
	}
}

static void emit_enter_syscall(pid_t pid, tcb_t &tcb)
{
	if (gstate.aborted) {
		return;
	}

	int action = shook_py_emit_enter_syscall(abort_on_python_exception, pid, tcb.context);
	CHECK_ABORT(action);

	VERB("-> pid=%d %s", pid, action_name[action]);

	if (action == SHOOK_ACTION_SUSPEND) {
		return;
	}

	if (action == SHOOK_ACTION_NONE) {
	} else if (action == SHOOK_ACTION_BYPASS) {
		tcb.flags |= FLAG_BYPASS;
		// tcb.next_retval = tcb.context.retval;
		// -1 is not valid syscall
		ptrace(PTRACE_POKEUSER, pid, ORIG_RAX * 8, -1);
		tcb.context.modified = false;

	} else if (action == SHOOK_ACTION_KILL) {
		tcb.restart_signo = tcb.context.signo;
	} else if (action == SHOOK_ACTION_DETACH) {
		detach(pid);
		return;
	} else if (action == SHOOK_ACTION_GDB) {
		gdb(pid);
		return;
	} else {
		assert(0);
	}

	if (tcb.context.modified) {
		if (tcb.context.argc == 0) {
			ptrace(PTRACE_POKEUSER, pid, ORIG_RAX * 8, tcb.context.scno);
		} else {
			tcb.regs.orig_rax = tcb.context.scno;
			for (unsigned int i = 0; i < tcb.context.argc; ++i) {
				set_argument(&tcb.regs, i, tcb.context.args[i]);
			}
			ptrace(PTRACE_SETREGS, pid, 0, &tcb.regs);
		}
	}
	if (false && tcb.flags & FLAG_GDB) {
		gdb(pid);
	}
	tcb.trace_state = tcb_trace_state_t::S_NONE;
}

static void emit_leave_syscall(pid_t pid, tcb_t &tcb)
{
	if (gstate.aborted) {
		return;
	}

	if (!gstate.enable_vdso && tcb.context.scno == SYS_execve && tcb.context.retval == 0) {
		shook_disable_vdso(pid, tcb.regs.rsp);
	}

	int action = shook_py_emit_leave_syscall(abort_on_python_exception, pid, tcb.context);
	CHECK_ABORT(action);

	VERB("<- pid=%d %s", pid, action_name[action]);
	if (action == SHOOK_ACTION_SUSPEND) {
		DBG("<- Action suspend pid=%d", pid);
		return;
	}
	if (tcb.context.modified) {
		ptrace(PTRACE_POKEUSER, pid, RAX * 8, tcb.context.retval);
	}

	check_new_process_return(pid, tcb, tcb.context);

	if (action == SHOOK_ACTION_NONE) {
	} else if (action == SHOOK_ACTION_KILL) {
		tcb.restart_signo = tcb.context.signo;
	} else if (action == SHOOK_ACTION_DETACH) {
		detach(pid);
	} else if (action == SHOOK_ACTION_GDB) {
		gdb(pid);
	}
	if (tcb.context.modified) {
		int err = ptrace(PTRACE_POKEUSER, pid, RAX * 8, tcb.context.retval);
		assert(err == 0);
	}
	if (tcb.flags & FLAG_GDB) {
		gdb(pid);
	}
	tcb.trace_state = tcb_trace_state_t::S_NONE;
}

static void terminate(void)
{
	exit(gstate.exit_code);
}

static void resume(tcb_t &tcb)
{
	if (tcb.trace_state == tcb_trace_state_t::S_ENTER_SYSCALL) {
		emit_enter_syscall(tcb.pid, tcb);
	} else if (tcb.trace_state == tcb_trace_state_t::S_LEAVE_SYSCALL) {
		emit_leave_syscall(tcb.pid, tcb);
	} else if (tcb.trace_state == tcb_trace_state_t::S_LEAVE_SIGNAL) {
		emit_leave_signal(tcb.pid, tcb);
	} else {
		assert(0);
	}

	if (tcb.trace_state == tcb_trace_state_t::S_NONE) {
		/* Enter next system call */
		if (ptrace(PTRACE_SYSCALL, tcb.pid, 0, tcb.restart_signo) == -1)
			FATAL("%s", strerror(errno));
	}
}

static void on_syscall(pid_t pid, tcb_t &tcb, ya_tick_t now)
{
	VERB("pid %d flags x%x orig_rax %lld %s rax %lld, %ld %ld %ld %ld %ld %ld",
			pid, tcb.flags, tcb.regs.orig_rax,
			syscall_name(tcb.regs.orig_rax),
			tcb.regs.rax,
			get_argument(&tcb.regs, 0),
			get_argument(&tcb.regs, 1),
			get_argument(&tcb.regs, 2),
			get_argument(&tcb.regs, 3),
			get_argument(&tcb.regs, 4),
			get_argument(&tcb.regs, 5));

	tcb.context.modified = false;

	if ((tcb.flags & FLAG_ENTERING) != 0) {
		assert((tcb.flags & FLAG_BYPASS) == 0);
		if (long(tcb.regs.orig_rax) < 0) {
			LOG(LOG_WARN, "Invalid orig_rax %lld pid %d",
					tcb.regs.orig_rax, pid);
			return;
		}
		tcb.last_syscall = tcb.regs.orig_rax;
		tcb.context.action = SHOOK_ACTION_NONE;
		tcb.context.scno = tcb.regs.orig_rax;
		tcb.context.argc = g_syscalls[tcb.regs.orig_rax].argc;
		for (unsigned int i = 0; i < tcb.context.argc; ++i) {
			tcb.context.args[i] = get_argument(&tcb.regs, i);
		}

		tcb.trace_state = tcb_trace_state_t::S_ENTER_SYSCALL;
		emit_enter_syscall(pid, tcb);
	} else {
		if ((tcb.flags & FLAG_BYPASS) != 0) {
			tcb.flags &= ~FLAG_BYPASS;
			tcb.context.modified = true;
			// tcb.context.retval = tcb.next_retval;
		} else {
			tcb.context.retval = tcb.regs.rax;
		}
		tcb.trace_state = tcb_trace_state_t::S_LEAVE_SYSCALL;
		emit_leave_syscall(pid, tcb);
	}
}

static const uint32_t g_trace_flags = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC |
PTRACE_O_TRACECLONE |
PTRACE_O_TRACEFORK |
PTRACE_O_TRACEVFORK;

static void trace(pid_t pid, unsigned int status, tcb_t &tcb, ya_tick_t now)
{
	unsigned int sig = 0;
	unsigned int event;

	tcb.restart_signo = 0;

	event = (unsigned int)status >> 16;
	if (event == PTRACE_EVENT_EXEC) {
		/* ptrace(2)
		 * If the execing thread is not a thread group leader, the
		 * thread ID is reset to thread group leader's ID before
		 * this stop.  Since Linux 3.0, the former thread ID can
		 * be retrieved with PTRACE_GETEVENTMSG.
		 */
		check_pid_changed(tcb, pid);
		// TODO handle thread do exec
		goto restart_tracee;
	}

	if (WIFSIGNALED(status)) {
		DBG("pid %d killed %d", pid, status);
		detached(tcb, 128 + WTERMSIG(status));
		return;
	}

	if (WIFEXITED(status)) {
		DBG("pid %d exited %d", pid, status);
		detached(tcb, WEXITSTATUS(status));
		return;
	}

	if (event == PTRACE_EVENT_CLONE || event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK) {
		long new_pid;
		if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &new_pid) < 0) {
			assert(0);
		}
		unsigned int type = (event == PTRACE_EVENT_CLONE) ? SHOOK_PROCESS_CLONE : 
			(event == PTRACE_EVENT_FORK) ? SHOOK_PROCESS_FORK : SHOOK_PROCESS_VFORK;
		DBG("event %d pid %d new_pid %ld", event, pid, new_pid);
		auto new_it_tcb = gstate.tcbs.find(new_pid);
		if (new_it_tcb == gstate.tcbs.end()) {
			TRACE_NEW_PROC(new_pid, type, tcb);
		} else {
			auto &new_tcb = new_it_tcb->second;
			assert(new_tcb.life_state == tcb_life_state_t::S_0);
			new_tcb.life_state = tcb_life_state_t::S_1;

			UPDATE_PROC(new_tcb, new_pid, type, tcb);
			if (new_tcb.save_status != 0) {
				/* trigger the saved event for new_pid */
				trace(new_pid, new_tcb.save_status, new_it_tcb->second, now);
				new_tcb.save_status = 0;
			}
		}
	}

	if (tcb.flags & FLAG_STARTUP) {
		tcb.flags &= ~FLAG_STARTUP;
		ptrace(PTRACE_SETOPTIONS, pid, 0, g_trace_flags);
	}

	if (event != 0) {
		DBG("pid %d event %d event", pid, event);
		goto restart_tracee;
	}

	sig = WSTOPSIG(status);
	if (sig == SIGSTOP && tcb.flags & FLAG_IGNORE_ONE_SIGSTOP) {
		tcb.flags &= ~FLAG_IGNORE_ONE_SIGSTOP;
		goto restart_tracee;
	}

	if (sig != syscall_trap_sig) {
		siginfo_t si;
		int stopped = ptrace(PTRACE_GETSIGINFO, pid, 0, (long)&si) < 0;
		DBG("pid %d %d, %d %d %d %d %p", pid, stopped, si.si_signo, si.si_code,
				si.si_pid, si.si_uid, si.si_addr);
		if (sig == SIGTRAP) {
			long new_pid;
			event = (si.si_code >> 8);
			if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK || event == PTRACE_EVENT_CLONE) {
				ptrace(PTRACE_GETEVENTMSG, pid, NULL, &new_pid);
				DBG("%d getnewpid %ld when %d", pid, new_pid, event);
			}
			tcb.restart_signo = 0;
			goto restart_tracee;
			LOG(LOG_WARN, "Unexpected SIGTRAP");
		}
		tcb.trace_state = tcb_trace_state_t::S_LEAVE_SIGNAL;
		tcb.restart_signo = sig;
		tcb.context.signo = sig;
		tcb.context.signal_depth = -1;
		emit_leave_signal(pid, tcb);
		goto restart_tracee;
	}

	/* Gather system call arguments or result */
	if (ptrace(PTRACE_GETREGS, pid, 0, &tcb.regs) == -1) {
		if (errno != ESRCH) {
			FATAL("%s", strerror(errno));
		}

		DBG("pid %d exit %lld", pid, tcb.regs.rdi);
		detached(tcb, tcb.regs.rdi);
		if (gstate.tcbs.empty()) {
			terminate();
		}
		return;
	}

#define ABI_RED_ZONE_SIZE	128
	/* 128 for x86_64, TODO other platform? */
	tcb.tmp_mem_addr = tcb.regs.rsp - ABI_RED_ZONE_SIZE;
	on_syscall(pid, tcb, now);
	tcb.flags ^= FLAG_ENTERING;
restart_tracee:
	if (tcb.flags & FLAG_DETACHING) {
		int err = ptrace(PTRACE_DETACH, pid, 0, 0);
		assert(err == 0);
		detached(tcb, 0);
	} else if ((tcb.flags & FLAG_SUSPEND) == 0) {
		/* Enter next system call */
		if (ptrace(PTRACE_SYSCALL, pid, 0, tcb.restart_signo) == -1)
			FATAL("%s", strerror(errno));
	}
}

static int create_signalfd()
{
        sigset_t mask;

        sigemptyset(&mask);
        sigaddset(&mask, SIGTERM);
        sigaddset(&mask, SIGINT);
        sigaddset(&mask, SIGCHLD);

        if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		FATAL("sigprocmask, errno=%d", errno);
        }

        return signalfd(-1, &mask, SFD_CLOEXEC);
}

static int run_shook(int start_pid, const std::vector<int> &pid_attach,
		int argc, char **argv)
{
        gstate.signalfd = create_signalfd();
        if (gstate.signalfd < 0) {
		FATAL("signalfd, errno=%d", errno);
        }

	if (argc) {
		DBG("py_init, argc = %d, argv[0] = %s", argc, argv[0]);
		if (py_init("shook", argc, argv) != 0) {
		}
	}

	if (start_pid > 0) {
		TRACE_EXIST_PROC(start_pid, SHOOK_PROCESS_CREATED, 0, FLAG_CREATED,
				std::make_shared<unw_t>());
	}

	for (auto pid: pid_attach) {
		DBG("attaching %d", pid);
		/* in detaching, it requires PTRACE_INTERRUPT to stop tracee,
		 * have to use PTRACE_SEIZE becauase PTRACE_ATTACK does not allow
		 * PTRACE_INTERRUPT
		 */
		int err = ptrace(PTRACE_SEIZE, pid, 0, 0);
		assert(err == 0);
		err = ptrace(PTRACE_INTERRUPT, pid, 0, 0);
		assert(err == 0);
		if (!gstate.enable_vdso) {
			shook_disable_vdso(pid, 0);
		}
		auto &tcb = TRACE_EXIST_PROC(pid, SHOOK_PROCESS_ATTACHED, 0, 0, std::make_shared<unw_t>());

		char proc_buf[80];
		snprintf(proc_buf, sizeof proc_buf, "/proc/%d/task", pid);
		DIR *dir = opendir(proc_buf);
		if (!dir) {
			continue;
		}
		struct dirent *de;
		while ((de = readdir(dir)) != NULL) {
			char *end;
			pid_t tpid = strtoul(de->d_name, &end, 0);
			if (*end) {
				continue;
			}
			if (tpid == pid || tpid <= 0) {
				continue;
			}
			err = ptrace(PTRACE_SEIZE, tpid, 0, 0);
			if (err != 0) {
				LOG(LOG_WARN, "failed to seize thread %d of %d, errno = %d",
						tpid, pid, errno);
				continue;
			}
			err = ptrace(PTRACE_INTERRUPT, tpid, 0, 0);
			assert(err == 0);
			TRACE_EXIST_PROC(tpid, SHOOK_PROCESS_CLONE, pid, 0, tcb.uas);
		}
		closedir(dir);
	}
	gstate.now = ya_get_tick();
#define MAX_POLL_WAIT_TIME (0xfffffff)
	while (!gstate.tcbs.empty()) {
		int status;
		pid_t pid = wait4(-1, &status, WNOHANG | __WALL, NULL);
		if (pid == -1) {
			if (errno == EINTR) {
				continue;
			}
			FATAL("%s", strerror(errno));
		} else if (pid != 0) {
			VERB("pid %d status=%d,0x%x, signal=%d", pid, status, status, WSTOPSIG(status));

			// tcb_t &tcb = find_or_create_tcb(pid);
			auto it_tcb = gstate.tcbs.find(pid);
			if (it_tcb == gstate.tcbs.end()) {
				// Child process signaled before the parent process,
				// suspend the process until the event about how it is created
				if (WIFEXITED(status)) {
					LOG(LOG_WARN, "pid %d already detached, status=0x%x,%d", pid, status, status);
					continue;
				}
				DBG("create tcb for new pid %d, status=0x%x,%d", pid, status, status);
				auto &new_tcb = tcb_create(pid, SHOOK_PROCESS_UNKNOWN, -1, 0);
				new_tcb.save_status = status;
				continue;
			}

			trace(pid, status, it_tcb->second, gstate.now);
		} else {
			ya_tick_t next_wakeup;
			int timeout;
			if (gstate.timerq.run(gstate.now, &next_wakeup)) {
				timeout = ya_tick_cmp(next_wakeup, gstate.now);
			} else {
				timeout = MAX_POLL_WAIT_TIME;
			}
			VERB("poll timeout %d", timeout);

			struct pollfd pollfd;
			pollfd.fd = gstate.signalfd;
			pollfd.events = POLLIN;
			pollfd.revents = 0;
			int ret = poll(&pollfd, 1, timeout);
			gstate.now = ya_get_tick();

			if (ret > 0) {
				struct signalfd_siginfo si;
				ssize_t res = read(gstate.signalfd, &si, sizeof(si));
				if (res < 0) {
					perror("read");
					return 1;
				}
				if (res != sizeof(si)) {
					fprintf (stderr, "Something wrong\n");
					return 1;
				}
				if (si.ssi_signo == SIGCHLD) {
					continue;
				} else if (si.ssi_signo == SIGTERM || si.ssi_signo == SIGINT) {
					LOG(LOG_INFO, "catch signal %d, exiting...", si.ssi_signo);
					exiting();
				} else {
					fprintf (stderr, "Got some unhandled signal\n");
					return 1;
				}
			}
		}
	}

	shook_py_emit_finish(abort_on_python_exception);
	terminate();
	return 0;
}

static void usage()
{
	fprintf(stderr, R"EOF(
Usage: shook [-o output] [-bg] [-enable-vdso] [-p pid] -x script ... [-- command ...]
	-version	report version and exit
	-o file		output to file, default stderr
	-bg		run shook in background
	-enable-vdso	not intercept vdso functions
	-p pid		attach the process
	-x script ...	python script and the optional arguments
	command ...	the trace command and its arguments
)EOF");
	exit(1);
}

#define USAGE(fmt, ...) do { \
	fprintf(stderr, fmt, ##__VA_ARGS__); \
	usage(); \
} while (0)

#define NEXT_ARG(a) ({ \
	const char *option = *a; \
	++(a); \
	if (*(a) == NULL) { \
		USAGE("Error: Option %s requires value.", option); \
	} \
	*(a); \
})

static unsigned int parse_loglevel(const char *arg)
{
	static const struct {
		const char *name;
		int val;
	} pairs[] = {
		{ "warn", LOG_WARN, },
		{ "info", LOG_INFO, },
		{ "debug", LOG_DEBUG, },
		{ "verb", LOG_VERB, },
	};

	for (auto &pair: pairs) {
		if (strcmp(arg, pair.name) == 0) {
			return pair.val;
		}
	}

	char *end;
	unsigned long ret = strtoul(arg, &end, 0);
	if (*end) {
		USAGE("Error: Invalid loglevel value %s.", arg);
	}
	return ret;
}

static void init_gstate()
{
	const char *env;
	char *end;

	env = getenv("SHOOK_EXIT_TIMEOUT");
	if (env && *env) {
		unsigned long val = strtoul(env, &end, 0);
		gstate.exit_timeout_ms = val;
	}
}

int main(int argc, char **argv)
{
	// const char *progname = argv[0];
	++argv;
	int script_argc = 0;
	char **script_argv = nullptr;

	const char *output = nullptr;
	unsigned int loglevel = LOG_INFO;
	std::vector<int> pid_attach;
	bool background = false;
	bool dosleep = false;

	init_gstate();

	for ( ; *argv; ++argv) {
		if (false) {
			/* placeholder */
		} else if (strcmp(*argv, "-version") == 0) {
			printf("shook %d.%d.%d %s %s\n",
					SHOOK_MAJOR_VERSION, SHOOK_MINOR_VERSION, SHOOK_PATCH_VERSION,
					g_git_commit, g_build_date);
			return 0;
		} else if (strcmp(*argv, "-x") == 0) {
			NEXT_ARG(argv);
			script_argv = argv;
			++argv;
			for ( ; ; ++argv) {
				if (!*argv || strcmp(*argv, "--") == 0) {
					break;
				}
			}
			script_argc = argv - script_argv;
			if (!*argv) {
				break;
			}
		} else if (strcmp(*argv, "-o") == 0) {
			output = NEXT_ARG(argv);
		} else if (strcmp(*argv, "-loglevel") == 0) {
			loglevel = parse_loglevel(NEXT_ARG(argv));
		} else if (strcmp(*argv, "-exit-timeout") == 0) {
			gstate.exit_timeout_ms = atoi(NEXT_ARG(argv));
		} else if (strcmp(*argv, "-p") == 0) {
			int pid = atoi(NEXT_ARG(argv));
			if (pid <= 0) {
				USAGE("Error: Invalid attach pid %d.", pid);
			}
			bool exists = false;
			for (auto _pid: pid_attach) {
				if (_pid == pid) {
					exists = true;
					break;
				}
			}
			if (exists) {
				fprintf(stderr, "Warning: attach pid %d exists, ignore", pid);
			} else {
				pid_attach.push_back(pid);
			}
		} else if (strcmp(*argv, "-bg") == 0) {
			background = true;
		} else if (strcmp(*argv, "-enable-vdso") == 0) {
			gstate.enable_vdso = true;
		} else if (strcmp(*argv, "-abort") == 0) {
			abort_on_python_exception = true;
		} else if (strcmp(*argv, "-sleep") == 0) {
			dosleep = true;
		} else if (**argv == '-') {
			USAGE("Unknown option %s.", *argv);
		} else {
			break;
		}
	}

	if (!*argv && pid_attach.empty()) {
		USAGE("Error: must attach or start new process.");
	}

	if (!shook_output_init(output, loglevel)) {
		fprintf(stderr, "Failed open log file \"%s\", errno=%d\n", output, errno);
		exit(1);
	}

	int this_pid = getpid();
	if (background) {
		if (!*argv) {
			USAGE("Error: background requires command line to start new process");
		}
		int sockets[2];
		int err = socketpair(AF_LOCAL, SOCK_SEQPACKET, 0, sockets);
		assert(err == 0);

		int pid = fork();
		assert(pid >= 0);
		if (pid == 0) {
			close(sockets[1]);
			pid = fork();
			assert(pid >= 0);
			if (pid > 0) {
				exit(0);
			}

			while (dosleep) {
				sleep(3);
			}

			setsid();
			close(0);
			open("/dev/null", O_RDWR);
			close(1);
			dup(0);
			if (output) {
				close(2);
				dup(0);
			}

			pid = getpid();
			write(sockets[0], &pid, sizeof(pid));
			int unused;
			read(sockets[0], &unused, sizeof(unused));

			LOG(LOG_INFO, "%d attach to tracee %d", pid, this_pid);
			ptrace(PTRACE_ATTACH, this_pid, 0, 0);

			// TODO should delay close, use it to notify tracee
			// in case there are something wrong
			close(sockets[0]);

			run_shook(this_pid, pid_attach, script_argc, script_argv);
			exit(0);
		}

		int status;
		err = waitpid(pid, &status, 0);
		fprintf(stderr, "%d exit 0x%x\n", pid, status);
		close(sockets[0]);
		err = read(sockets[1], &pid, sizeof(pid));
		if (err != 4) {
			fprintf(stderr, "Failed to get tracer's pid\n");
			exit(1);
		}
		prctl(PR_SET_PTRACER, pid, 0, 0, 0);
		write(sockets[1], &this_pid, sizeof(this_pid));
		int unused;
		// wait for tracer, should get EOF
		read(sockets[1], &unused, sizeof(unused));
		close(sockets[1]);

		execvp(argv[0], argv);
		exit(2);
	} else {
		pid_t start_pid = -1;
		if (*argv) {
			start_pid = fork();
			if (start_pid < 0) {
				FATAL("%s", strerror(errno));
			}
			if (start_pid == 0) {
				ptrace(PTRACE_TRACEME, 0, 0, 0);
				kill(getpid(), SIGSTOP);
				execvp(argv[0], argv);
				FATAL("%s", strerror(errno));
			}
			gstate.start_pid = start_pid;
		}
		return run_shook(start_pid, pid_attach, script_argc, script_argv);
	}
}

int shook_detach(pid_t pid)
{
	return detach(pid);
}

void shook_cancel_timer(ya_timer_t *timer)
{
	gstate.timerq.cancel(timer);
}

void shook_set_timer(ya_timer_t *timer, ya_tick_diff_t intval)
{
	DBG("intval=%ld", intval);
	gstate.timerq.schedule(timer, gstate.now, intval);
}

int shook_resume(pid_t pid)
{
	auto it = gstate.tcbs.find(pid);
	if (it == gstate.tcbs.end()) {
		return -2;
	} else {
		resume(it->second);
		return 0;
	}
}

/* expand tracee's stack and copy data to stack, NOTE, len should not be large */
long shook_alloc_stack(pid_t pid, size_t len)
{
	auto it = gstate.tcbs.find(pid);
	TODO_assert(it != gstate.tcbs.end());

	tcb_t &tcb = it->second;
	tcb.tmp_mem_addr -= ((len + 15) & ~15);
	return tcb.tmp_mem_addr;
}

/* expand tracee's stack and copy data to stack, NOTE, len should not be large */
long shook_alloc_copy(pid_t pid, const void *data, size_t len)
{
	long stack_space = shook_alloc_stack(pid, len);
	vm_poke_mem(pid, data, stack_space, len);
	return stack_space;
}

int shook_backtrace(std::vector<stackframe_t> &stacks, pid_t pid, unsigned int depth)
{
	auto it = gstate.tcbs.find(pid);
	TODO_assert(it != gstate.tcbs.end());

	unw_cursor_t cursor;
	int err = init_unw_cursor(cursor, it->second);

	TODO_assert(err >= 0);
	for (unsigned int d = 0; depth == 0 || d < depth; ++d) {
		unw_word_t ip;
		err = unw_get_reg(&cursor, UNW_REG_IP, &ip);
		TODO_assert(err >= 0);

		char symbol_name[256];
		unw_word_t offset;
		err = unw_get_proc_name(&cursor, symbol_name, sizeof(symbol_name) - 1, &offset);
		if (err == 0) {
			stacks.emplace_back(ip, offset, symbol_name);
		} else {
			stacks.emplace_back(ip);
		}

		if (unw_step(&cursor) <= 0) {
			break;
		}
	}
	return 0;
}

int shook_set_gdb(pid_t pid)
{
	auto it = gstate.tcbs.find(pid);
	TODO_assert(it != gstate.tcbs.end());
	if (it == gstate.tcbs.end()) {
		return -ENOENT;
	}
	tcb_t &tcb = it->second;
	tcb.flags |= FLAG_GDB;
	return 0;
}

#ifdef __SANITIZE_ADDRESS__
const char* __asan_default_options() { return "detect_leaks=0"; }
#endif
