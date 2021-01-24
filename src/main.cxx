
#include "globals.hxx"

#include <unordered_map>
#include <sstream>
#include <initializer_list>

#include <stdarg.h>
#include <fcntl.h>

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

static unsigned int g_syscall_argc[] = {
#define X(s, argc, r, p) argc,
#include "syscallent.h"
#undef X
};


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
};

enum tcb_state_t {
	STATE_NONE,
	STATE_ENTER_SYSCALL,
	STATE_LEAVE_SYSCALL,
	STATE_ENTER_SIGNAL,
};

struct tcb_t
{
	tcb_t(pid_t pid_, unsigned int pt, unsigned ppid) : pid(pid_),
			process_type(pt), create_pid(ppid) {
	}

	pid_t pid;
	tcb_state_t state = STATE_NONE;
	uint32_t flags = FLAG_STARTUP | FLAG_ENTERING | FLAG_IGNORE_ONE_SIGSTOP;
	unsigned int process_type, create_pid;
	unsigned int new_proc_type;
	int save_status = 0;
	unsigned int last_syscall;
	unsigned int restart_signo = 0;
	// long next_retval;
	long tmp_mem_addr;

	struct UPT_info *unw_info = nullptr;
	// unsigned long wakeup_time;
	struct user_regs_struct regs;

	context_t context;
};

static const unsigned int syscall_trap_sig = SIGTRAP | 0x80;

enum {
	ABORT_STATE_NONE,
	ABORT_STATE_STARTED,
};

struct gstate_t
{
	std::unordered_map<pid_t, tcb_t> tcb;
	ya_timerq_t timerq;
	ya_tick_t now;
	int signalfd = -1;
	bool enable_vdso = false;
	bool aborted = false;
	pid_t start_pid = -1;
	unsigned int exit_code = 0;

	unw_addr_space_t unw_addr_space;
};

static gstate_t gstate;
static bool abort_on_python_exception = false;

static void shook_abort()
{
	LOG(LOG_INFO, "abort");
	if (!gstate.aborted) {
		gstate.aborted = true;
		for (auto &it: gstate.tcb) {
			kill(it.second.pid, SIGTERM);
		}
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
	}
	gstate.tcb.erase(tcb.pid);
}

static void check_pid_changed(tcb_t &tcb, pid_t pid)
{
	unsigned long old_pid = 0;

	if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, (long)&old_pid) < 0)
		return;
	if (old_pid == (unsigned long)pid || old_pid > UINT_MAX)
		return;

	auto it_tcb = gstate.tcb.find(old_pid);
	assert(it_tcb != gstate.tcb.end());

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

static int detach(pid_t pid)
{
	auto it = gstate.tcb.find(pid);
	if (it == gstate.tcb.end()) {
		return -2;
	} else {
		int err = ptrace(PTRACE_DETACH, pid, 0, 0);
		assert(err == 0);
		return err;
	}
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

static void trace_new_proc(pid_t pid, unsigned int type, pid_t create_pid)
{
	DBG("trace_new_proc pid=%d, type=%d, creator=%d", pid, type, create_pid);
	gstate.tcb.emplace(pid, tcb_t(pid, type, create_pid));
	if (gstate.aborted) {
		kill(pid, SIGTERM);
		return;
	}
	emit_process(pid, type, create_pid);
}

static void update_proc(tcb_t &tcb, pid_t pid, unsigned int type, pid_t create_pid)
{
	if (tcb.process_type == SHOOK_PROCESS_UNKNOWN) {
		tcb.process_type = type;
		tcb.create_pid = pid;
		emit_process(pid, type, create_pid);
	} else if (tcb.process_type != type) {
		LOG(LOG_WARN, "update_proc pid=%d, old_type=%d, type=%d, creator=%d",
				pid, tcb.process_type, type, create_pid);
	}
}

/*
 * TODO, suppose script never modify syscall fork/vfork/clone
 */
static void check_new_process(pid_t pid, tcb_t &tcb, context_t &ctx)
{
	if (ctx.scno == SYS_clone) {
		/* is it enough just checking CLONE_THREAD? */
		if (ctx.args[0] & CLONE_THREAD) {
			tcb.new_proc_type = SHOOK_PROCESS_CLONE;
		} else {
			tcb.new_proc_type = SHOOK_PROCESS_FORK;
		}
	} else if (ctx.scno == SYS_fork) {
		tcb.new_proc_type = SHOOK_PROCESS_FORK;
	} else if (ctx.scno == SYS_vfork) {
		tcb.new_proc_type = SHOOK_PROCESS_VFORK;
	} else {
		tcb.new_proc_type = SHOOK_PROCESS_UNKNOWN;
	}
}

static void check_new_process_return(pid_t pid, tcb_t &tcb, context_t &ctx)
{
	if (tcb.new_proc_type != SHOOK_PROCESS_UNKNOWN) {
		if (ctx.retval > 0) {
			pid_t new_pid = ctx.retval;
			auto new_it_tcb = gstate.tcb.find(new_pid);
			if (new_it_tcb == gstate.tcb.end()) {
				trace_new_proc(new_pid, tcb.new_proc_type, pid);
			} else {
				update_proc(new_it_tcb->second, new_pid, tcb.new_proc_type, pid);
			}
		}
		tcb.new_proc_type = SHOOK_PROCESS_UNKNOWN;
	}
}

static void emit_enter_signal(pid_t pid, tcb_t &tcb)
{
	if (gstate.aborted) {
		return;
	}

	int action = shook_py_emit_enter_signal(abort_on_python_exception, pid, tcb.context);
	CHECK_ABORT(action);

	if (action == SHOOK_ACTION_SUSPEND) {
		VERB("<- suspend pid=%d", pid);
		return;
	}

	if (action == SHOOK_ACTION_NONE) {
	} else if (action == SHOOK_ACTION_REDIRECT) {
		DBG("<- Action redirect pid=%d, signo=%d", pid, tcb.context.signo);
		tcb.restart_signo = tcb.context.signo;
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
	tcb.state = STATE_NONE;
	check_new_process(pid, tcb, tcb.context);
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
	tcb.state = STATE_NONE;
}

static void terminate(void)
{
	exit(gstate.exit_code);
}

static void resume(tcb_t &tcb)
{
	if (tcb.state == STATE_ENTER_SYSCALL) {
		emit_enter_syscall(tcb.pid, tcb);
	} else if (tcb.state == STATE_LEAVE_SYSCALL) {
		emit_leave_syscall(tcb.pid, tcb);
	} else if (tcb.state == STATE_ENTER_SIGNAL) {
		emit_enter_signal(tcb.pid, tcb);
	} else {
		assert(0);
	}

	if (tcb.state == STATE_NONE) {
		/* Enter next system call */
		if (ptrace(PTRACE_SYSCALL, tcb.pid, 0, tcb.restart_signo) == -1)
			FATAL("%s", strerror(errno));
	}
}

static void on_syscall(pid_t pid, tcb_t &tcb, ya_tick_t now)
{
	tcb.context.modified = false;

	if ((tcb.flags & FLAG_ENTERING) != 0) {
		assert((tcb.flags & FLAG_BYPASS) == 0);
		tcb.last_syscall = tcb.regs.orig_rax;
		tcb.context.action = SHOOK_ACTION_NONE;
		tcb.context.scno = tcb.regs.orig_rax;
		tcb.context.argc = g_syscall_argc[tcb.regs.orig_rax];
		for (unsigned int i = 0; i < tcb.context.argc; ++i) {
			tcb.context.args[i] = get_argument(&tcb.regs, i);
		}

		tcb.state = STATE_ENTER_SYSCALL;
		emit_enter_syscall(pid, tcb);
	} else {
		if ((tcb.flags & FLAG_BYPASS) != 0) {
			tcb.flags &= ~FLAG_BYPASS;
			tcb.context.modified = true;
			// tcb.context.retval = tcb.next_retval;
		} else {
			tcb.context.retval = tcb.regs.rax;
		}
		tcb.state = STATE_LEAVE_SYSCALL;
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
		auto new_it_tcb = gstate.tcb.find(new_pid);
		if (new_it_tcb == gstate.tcb.end()) {
			trace_new_proc(new_pid, type, pid);
		} else {
			update_proc(new_it_tcb->second, new_pid, type, pid);
			if (new_it_tcb->second.save_status != 0) {
				/* trigger the saved event for new_pid */
				trace(new_pid, new_it_tcb->second.save_status, new_it_tcb->second, now);
				new_it_tcb->second.save_status = 0;
			}
		}
	}

	if (event != 0) {
		DBG("pid %d event %d event", pid, event);
		goto restart_tracee;
	}

	if (tcb.flags & FLAG_STARTUP) {
		tcb.flags &= ~FLAG_STARTUP;
		ptrace(PTRACE_SETOPTIONS, pid, 0, g_trace_flags);
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
		tcb.state = STATE_ENTER_SIGNAL;
		tcb.restart_signo = sig;
		tcb.context.signo = sig;
		tcb.context.signal_depth = 0;
		emit_enter_signal(pid, tcb);
		goto restart_tracee;
	}

	/* Gather system call arguments or result */
	if (ptrace(PTRACE_GETREGS, pid, 0, &tcb.regs) == -1) {
		if (errno == ESRCH) {
			DBG("pid %d exit %lld", pid, tcb.regs.rdi);
			detached(tcb, tcb.regs.rdi);
			if (gstate.tcb.empty()) {
				terminate();
			}
		} else {
			FATAL("%s", strerror(errno));
		}
	}

#define ABI_RED_ZONE_SIZE	128
	/* 128 for x86_64, TODO other platform? */
	tcb.tmp_mem_addr = tcb.regs.rsp - ABI_RED_ZONE_SIZE;
	on_syscall(pid, tcb, now);
	tcb.flags ^= FLAG_ENTERING;
restart_tracee:
	if ((tcb.flags & FLAG_SUSPEND) == 0) {
		/* Enter next system call */
		if (ptrace(PTRACE_SYSCALL, pid, 0, tcb.restart_signo) == -1)
			FATAL("%s", strerror(errno));
	}
}

static void init_unwind(void)
{
	gstate.unw_addr_space = unw_create_addr_space(&_UPT_accessors, 0);
	assert(gstate.unw_addr_space);
	unw_set_caching_policy(gstate.unw_addr_space, UNW_CACHE_GLOBAL);
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
	init_unwind();

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
		trace_new_proc(start_pid, SHOOK_PROCESS_CREATED, 0);
	}

	for (auto pid: pid_attach) {
		int err = ptrace(PTRACE_ATTACH, pid, 0, 0);
		assert(err == 0);
		if (!gstate.enable_vdso) {
			shook_disable_vdso(pid, 0);
		}
		trace_new_proc(pid, SHOOK_PROCESS_ATTACHED, 0);
	}
	gstate.now = ya_get_tick();
#define MAX_POLL_WAIT_TIME (0xfffffff)
	while (!gstate.tcb.empty()) {
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
			auto it_tcb = gstate.tcb.find(pid);
			if (it_tcb == gstate.tcb.end()) {
				// Child process signaled before the parent process,
				// suspend the process until the event about how it is created
				DBG("pid %d not found", pid);
				auto ret = gstate.tcb.emplace(pid, tcb_t(pid, SHOOK_PROCESS_UNKNOWN, -1));
				assert(ret.second);
				ret.first->second.save_status = status;
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
					for (auto &it: gstate.tcb) {
						kill(it.first, SIGTERM);
					}
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
	for ( ; *argv; ++argv) {
		if (false) {
			/* placeholder */
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
			loglevel = atoi(NEXT_ARG(argv));
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
	auto it = gstate.tcb.find(pid);
	if (it == gstate.tcb.end()) {
		return -2;
	} else {
		resume(it->second);
		return 0;
	}
}

/* expand tracee's stack and copy data to stack, NOTE, len should not be large */
long shook_alloc_stack(pid_t pid, size_t len)
{
	auto it = gstate.tcb.find(pid);
	TODO_assert(it != gstate.tcb.end());

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
	auto it = gstate.tcb.find(pid);
	TODO_assert(it != gstate.tcb.end());

	tcb_t &tcb = it->second;
	if (!tcb.unw_info) {
		tcb.unw_info = (struct UPT_info *)_UPT_create(pid);
		TODO_assert(tcb.unw_info);
	}

	unw_cursor_t cursor;
	int err = unw_init_remote(&cursor, gstate.unw_addr_space, tcb.unw_info);
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
	auto it = gstate.tcb.find(pid);
	TODO_assert(it != gstate.tcb.end());
	if (it == gstate.tcb.end()) {
		return -ENOENT;
	}
	tcb_t &tcb = it->second;
	tcb.flags |= FLAG_GDB;
	return 0;
}


