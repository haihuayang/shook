
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

#include <elf.h>

static unsigned int g_syscall_argc[] = {
#define X(s, argc, r, p) argc,
#include "syscallent.h"
#undef X
};


enum {
	LOG_FATAL,
	LOG_ERROR,
	LOG_WARN,
	LOG_INFO,
	LOG_DEBUG,
	LOG_VERB,
	LOG_MAX,
};

static const char * const level_name[] = {
	"Fatal",
	"Error",
	"Warn",
	"Info",
	"Debug",
	"Verb",
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

struct gstate_t
{
	std::unordered_map<pid_t, tcb_t> tcb;
	ya_timerq_t timerq;
	ya_tick_t now;
	int signalfd = -1;
	int logfd = 2;
	unsigned int loglevel = LOG_INFO;
	bool disable_vdso = false;

	unw_addr_space_t unw_addr_space;
};

static gstate_t gstate;
static bool abort_on_python_exception = false;

#if 0
#define OUTPUT_LOG(...) do { \
	fprintf(g_logfp, __VA_ARGS__); \
} while (0)
#else
#define OUTPUT_LOG(...) do { \
	char __buf[1024]; \
	int __len = snprintf(__buf, sizeof __buf, __VA_ARGS__); \
	write(gstate.logfd, __buf, __len); \
} while (0)
#endif

#define FATAL(...) do { \
	OUTPUT_LOG("FATAL at %d, errno %d: ", __LINE__, errno); \
	OUTPUT_LOG(__VA_ARGS__); \
	OUTPUT_LOG("\n"); \
	exit(EXIT_FAILURE); \
} while (0)

static void dolog(int level, const char *fmt, ...) __attribute__((format (printf, 2, 3)));
static void dolog(int level, const char *fmt, ...)
{
	char buff[1024], *p = buff, *end = p + sizeof(buff) - 1; // 1 byte for \n
	struct tm tm_now;
	struct timeval tv_now;
	gettimeofday(&tv_now, NULL);
	time_t t = tv_now.tv_sec;
	localtime_r(&t, &tm_now);
	int l = strftime(p, end - p, "%T", &tm_now);
	if (l == 0) {
		goto truncated;
	}
	p += l;
	l = snprintf(p, end - p, ":%03d %s ", (unsigned int)tv_now.tv_usec / 1000, level_name[level]);
	if (p + l >= end) {
		goto truncated;
	}
	p += l;

	va_list va;
	va_start(va, fmt);
	l = vsnprintf(p, end - p, fmt, va);
	assert(l >= 0);
	if (p + l >= end) {
		goto truncated;
	}
	p += l;

output:
	*p++ = '\n';
	write(gstate.logfd, buff, p - buff);
	return;

truncated:
	p = end - 2;
	*p++ = '>';
	*p++ = '>';
	goto output;
}

#define LOG(level, ...) do { \
	if (level <= gstate.loglevel) { \
		dolog(level, __VA_ARGS__); \
	} \
} while (0)

#define DBG(fmt, ...) LOG(LOG_DEBUG, "at %s:%d " fmt, __FILE__, __LINE__, __VA_ARGS__)
#define VERB(fmt, ...) LOG(LOG_VERB, "at %s:%d " fmt, __FILE__, __LINE__, __VA_ARGS__)

static void detached(tcb_t &tcb)
{
	shook_py_emit_process(abort_on_python_exception, tcb.pid, SHOOK_PROCESS_DETACHED, 0);
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
	detached(tcb);
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
	fprintf(stderr, "PTRACE_DETACH %d = %d, %d\n", pid, err, errno);
	unsetenv("PYTHONHOME");

        sigset_t mask;
        /* We will handle SIGTERM and SIGINT. */
        sigemptyset(&mask);
	err = sigprocmask(SIG_SETMASK, &mask, NULL);
	if (err < 0) {
		fprintf(stderr, "sigprocmask errno=%d\n", errno);
	}

	const char *gdbpath = getenv("GDB");
	if (!gdbpath) {
		gdbpath = "gdb";
	}
	execlp(gdbpath, "gdb", "-p", str_pid, NULL);
	fprintf(stderr, "Never be here\n");
	assert(0);
}

static void trace_new_proc(pid_t pid, unsigned int type, pid_t create_pid)
{
	DBG("trace_new_proc pid=%d, type=%d, creator=%d", pid, type, create_pid);
	gstate.tcb.emplace(pid, tcb_t(pid, type, create_pid));
	shook_py_emit_process(abort_on_python_exception, pid, type, create_pid);
}

static void update_proc(tcb_t &tcb, pid_t pid, unsigned int type, pid_t create_pid)
{
	if (tcb.process_type == SHOOK_PROCESS_UNKNOWN) {
		tcb.process_type = type;
		tcb.create_pid = pid;
		shook_py_emit_process(abort_on_python_exception, pid, type, create_pid);
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
	int action = shook_py_emit_enter_signal(abort_on_python_exception, pid, tcb.context);
	if (action == SHOOK_ACTION_SUSPEND) {
		DBG("<- Action suspend pid=%d", pid);
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
	int action = shook_py_emit_enter_syscall(abort_on_python_exception, pid, tcb.context);
	DBG("-> Action pid=%d %s", pid, action_name[action]);

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
	if (gstate.disable_vdso && tcb.context.scno == SYS_execve && tcb.context.retval == 0) {
		DBG("%d disable vdso", pid);
		unsigned long base = tcb.regs.rsp;
		unsigned long argc = ptrace(PTRACE_PEEKDATA, pid, base, NULL);
		/* skip the argv */
		base += (argc + 2) * sizeof(unsigned long);
		/* skip the environment */
		DBG("pid %d env at 0x%lx, rsp 0x%lx", pid, base, tcb.regs.rsp);
		for (;;) {
			unsigned long env = ptrace(PTRACE_PEEKDATA, pid, base, NULL);
			base += sizeof(long);
			if (!env) {
				break;
			}
		}
		/* find AT_SYSINFO_EHDR, and overwrite it to 0 */
		for (;;) {
			unsigned long type = ptrace(PTRACE_PEEKDATA, pid, base, NULL);
			if (type == AT_NULL) {
				LOG(LOG_WARN, "Cannot found AT_SYSINFO_EHDR pid=%d, rsp=0x%lx", pid, tcb.regs.rsp);
				break;
			} else if (type == AT_SYSINFO_EHDR) {
				unsigned long origval = ptrace(PTRACE_PEEKDATA, pid, base + sizeof(long), NULL);
				DBG("AT_SYSINFO_EHDR at 0x%lx", origval);
				ptrace(PTRACE_POKEDATA, pid, base + sizeof(long), 0);
				break;
			}
			base += 2 * sizeof(long);
		}
	}

	int action = shook_py_emit_leave_syscall(abort_on_python_exception, pid, tcb.context);
	DBG("<- Action pid=%d %s", pid, action_name[action]);
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

static uint32_t g_trace_flags = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC |
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
		detached(tcb);
		return;
	}

	if (WIFEXITED(status)) {
		DBG("pid %d exited", pid);
		detached(tcb);
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
			detached(tcb);
			if (gstate.tcb.empty()) {
				exit(0);
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

static int run_shook(int start_pid, int pid_attach,
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

	trace_new_proc(start_pid, SHOOK_PROCESS_CREATED, 0);
	if (pid_attach != -1) {
		int err = ptrace(PTRACE_ATTACH, pid_attach, 0, 0);
		assert(err == 0);
		trace_new_proc(pid_attach, SHOOK_PROCESS_ATTACHED, 0);
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
	return 0;
}


static void usage()
{
	fprintf(stderr, "Usage: shook [-o output] [-x script] [-bg] [-p pid] command ...\n");
	exit(1);
}

#define NEXT_ARG(a) ({ \
	++(a); \
	if (*(a) == NULL) { \
		usage(); \
	} \
	*(a); \
})

int main(int argc, char **argv)
{
	// const char *progname = argv[0];
	++argv;
	int script_argc = 0;
	char **script_argv = nullptr;

	const char *output = "shook.out";
	int pid_attach = -1;
	bool background = false;
	bool dosleep = false;
	while (*argv) {
		if (false) {
			/* placeholder */
		} else if (strcmp(*argv, "-x") == 0) {
			NEXT_ARG(argv);
			script_argv = argv;
			++argv;
			for ( ; ; ++argv) {
				if (!*argv) {
					usage();
				}
				if (strcmp(*argv, "--") == 0) {
					break;
				}
			}
			script_argc = argv - script_argv;
		} else if (strcmp(*argv, "-o") == 0) {
			output = NEXT_ARG(argv);
		} else if (strcmp(*argv, "-loglevel") == 0) {
			gstate.loglevel = atoi(NEXT_ARG(argv));
		} else if (strcmp(*argv, "-p") == 0) {
			pid_attach = atoi(NEXT_ARG(argv));
		} else if (strcmp(*argv, "-bg") == 0) {
			background = true;
		} else if (strcmp(*argv, "-disable-vdso") == 0) {
			gstate.disable_vdso = true;
		} else if (strcmp(*argv, "-abort") == 0) {
			abort_on_python_exception = true;
		} else if (strcmp(*argv, "-sleep") == 0) {
			dosleep = true;
		} else if (**argv == '-') {
			usage();
		} else {
			break;
		}
		++argv;
	}

	if (!*argv && pid_attach == -1) {
		usage();
	}

	int this_pid = getpid();
	if (background) {
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

			int fd = open(output, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
			if (fd < 0) {
				fprintf(stderr, "Failed open log file \"%s\", errno=%d\n", output, errno);
				exit(1);
			}

			setsid();
			close(0);
			close(1);
			close(2);
			open("/dev/null", O_RDWR);
			dup(0);
			dup(fd);
			close(fd);

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
		}
		int fd = open(output, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		if (fd < 0) {
			fprintf(stderr, "Failed open log file \"%s\", errno=%d\n", output, errno);
			exit(1);
		}
		gstate.logfd = fd;
		return run_shook(start_pid, pid_attach, script_argc, script_argv);
	}
}

static char g_logbuf[8192];
static int g_loglen = 0;
void shook_write(int stream, const char *str)
{
	const char *eol = strrchr(str, '\n');
	if (eol) {
		if (g_loglen > 0) {
			write(gstate.logfd, g_logbuf, g_loglen);
			g_loglen = 0;
		}
		write(gstate.logfd, str, eol + 1 - str);
		size_t len = strlen(eol + 1);
		if (len < sizeof(g_logbuf)) {
			strcpy(g_logbuf, eol + 1);
			g_loglen = len;
		} else {
			write(gstate.logfd, eol + 1, len);
		}
	} else {
		size_t len = strlen(str);
		if (len + g_loglen < sizeof(g_logbuf)) {
			strcpy(g_logbuf + g_loglen, str);
			g_loglen += len;
		} else {
			write(gstate.logfd, g_logbuf, g_loglen);
			g_loglen = 0;
			write(gstate.logfd, str, len);
		}
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

