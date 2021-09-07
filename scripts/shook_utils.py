#!/usr/bin/env python

from __future__ import print_function
import sys, os, errno, socket, select, struct, fcntl, copy
import shook
from datetime import datetime

def str_time(now = None):
	if now is None:
		now = datetime.now()
	return "%02d:%02d:%02d.%06d" % (now.hour, now.minute, now.second, now.microsecond)

def report(*args):
	print(str_time(), *args)
	sys.stdout.flush()

FIONREAD = 0x541B
FIONBIO  = 0x5421
class FD(object):
	def on_getsockname(self, pid, retval, fd, sa, salen):
		return None
	def on_getpeername(self, pid, retval, fd, sa, salen):
		return None
	def on_ioctl(self, pid, fd, op, val):
		return None
	def on_fionread(self, pid):
		raise NotImplementedError('on_fionread')
	def on_read(self, pid, retval, fd, addr, length):
		raise NotImplementedError('on_read')
	def on_readv(self, pid, retval, fd, iov, iovcnt):
		raise NotImplementedError('on_readv')
	def on_recvfrom(self, pid, retval, fd, addr, length, flags, src_addr, addrlen):
		raise NotImplementedError('on_recvfrom')
	def on_write(self, pid, retval, fd, addr, length):
		raise NotImplementedError('on_write')
	def on_writev(self, pid, retval, fd, iov, iovcnt):
		raise NotImplementedError('on_writev')
	def on_sendto(self, pid, retval, fd, addr, length, flags, src_addr, addrlen):
		raise NotImplementedError('on_sendto')
	def on_close(self, pid, fd):
		pass

class Pollable(object):
	def want_recv(self, fd):
		raise NotImplementedError('want_recv')
	def want_send(self, fd):
		raise NotImplementedError('want_send')

class RMemIO:
	def __init__(self, pid, iovec):
		self.pid, self.iovec = pid, iovec
	def send(self, data):
		length = shook.poke_datav(self.pid, data, *self.iovec)	
		return length
	def recv(self, length):
		ret = shook.peek_datav(self.pid, length, *self.iovec)
		return ret

class Epoll(object):
	def __init__(self):
		self.fd_table = {}

	def add(self, fd, epoll_event):
		if fd in self.fd_table:
			return -errno.EEXIST
		else:
			self.fd_table[fd] = epoll_event
			return 0
		
	def mod(self, fd, epoll_event):
		if fd in self.fd_table:
			self.fd_table[fd] = epoll_event
			return 0
		else:
			return -errno.ENOENT

	def remove(self, fd):
		try:
			del self.fd_table[fd]
			return 0
		except KeyError:
			return -errno.ENOENT

class TraceeMgmt__:
	class Tracee:
		def __init__(self, pid, main_pid, fd_table):
			self.pid, self.main_pid, self.fd_table = pid, main_pid, fd_table
			self.cwd = None
			self.data = []

	def __init__(self, **kwargs):
		self.tracee_tbl = { }
		self.strict = kwargs.pop('strick', False)
		self.debug = kwargs.pop('debug', False)
		if kwargs:
			raise TypeError('Unexpected **kwargs: %r' % kwargs)

	def dprint(self, *args):
		if self.debug:
			report(*args)

	def register_handlers(self, *handlers):
		syscall_hooks = [ ]
		for handler in handlers:
			hook = getattr(handler, "syscall_hook", None)
			if hook:
				syscall_hooks.append(hook)
		syscall_hooks.append(self.syscall_hook)
		shook.register(shook.EVENT_SYSCALL, *syscall_hooks)

		process_hooks = [ ]
		for handler in handlers:
			hook = getattr(handler, "process_hook", None)
			if hook:
				process_hooks.append(hook)
		process_hooks.append(self.process_hook)
		shook.register(shook.EVENT_PROCESS, *process_hooks)
		
		signal_hooks = [ ]
		for handler in handlers:
			hook = getattr(handler, "signal_hook", None)
			if hook:
				signal_hooks.append(hook)
		if signal_hooks:
			shook.register(shook.EVENT_SIGNAL, *signal_hooks)

		finish_hooks = [ ]
		for handler in handlers:
			hook = getattr(handler, "finish_hook", None)
			if hook:
				finish_hooks.append(hook)
		if finish_hooks:
			shook.register(shook.EVENT_FINISH, *finish_hooks)

	def attached(self, pid):
		# not fd table is empty
		self.tracee_tbl[pid] = self.Tracee(pid, pid, {})

	def forked(self, pid_from, pid_to):
		self.tracee_tbl[pid_to] = self.Tracee(pid_to, pid_to, copy.deepcopy(self.tracee_tbl[pid_from].fd_table))

	def cloned(self, pid_from, pid_to):
		tracee_from = self.tracee_tbl[pid_from]
		self.tracee_tbl[pid_to] = self.Tracee(pid_to, tracee_from.main_pid, tracee_from.fd_table)
		
	def get_main_pid(self, pid):
		return self.tracee_tbl[pid].main_pid

	def set_cwd(self, pid, path):
		self.tracee_tbl[pid].cwd = path

	def get_cwd(self, pid):
		return self.tracee_tbl[pid].cwd

	def push(self, pid, *data):
		self.tracee_tbl[pid].data.append(data)

	def pop(self, pid):
		return self.tracee_tbl[pid].data.pop()

	# flags, fdobj and userdata, among them, fd and userdata shared by dup fd
	def get_fd(self, pid, fd):
		try:
			return self.tracee_tbl[pid].fd_table[fd]
		except:
			return 0, None, None
		
	def put_fd_obj(self, pid, fd, t):
		fd_table = self.tracee_tbl[pid].fd_table
		if fd in fd_table:
			fd_table[fd][1] = t
		else:
			fd_table[fd] = [0, t, None]
		
	# Note, flags is 32 bits
	F_NONBLOCKING = 1
	F_CLOEXEC = 2
	F_SOCKBOUND = 4
	O_NONBLOCKING = 0x800
	O_CLOEXEC = 0x80000
	def mod_fd_flags(self, pid, fd, flags, enable):
		fd_table = self.tracee_tbl[pid].fd_table
		if fd in fd_table:
			if enable:
				fd_table[fd][0] |= flags
			else:
				fd_table[fd][0] &= (0xffffffff ^ flags)
		else:
			if enable:
				fd_table[fd] = [flags, None, None]
			else:
				fd_table[fd] = [0, None, None]

	def set_fd_userdata(self, pid, fd, userdata):
		fd_table = self.tracee_tbl[pid].fd_table
		try:
			fd_table[fd][2] = userdata
		except KeyError:
			fd_table[fd] = [0, None, userdata]

	def get_fd_userdata(self, pid, fd):
		fd_table = self.tracee_tbl[pid].fd_table
		return fd_table[fd][2]
	
	def close_fd(self, pid, fd):
		try:
			del self.tracee_tbl[pid].fd_table[fd]
		except:
			pass
	
	def dup_fd(self, pid, fd_src, fd_dst, flags = 0):
		fd_table = self.tracee_tbl[pid].fd_table
		try:
			_, fd_obj, userdata = self.get_fd(pid, fd_src)
			fd_table[fd_dst] = [flags, fd_obj, userdata]
		except KeyError:
			pass

	def process_hook(self, pid, event, ppid):
		if event == shook.PROCESS_CREATED:
			report('PID', pid, 'created')
			self.attached(pid)
		elif event == shook.PROCESS_ATTACHED:
			report('PID', pid, 'attached')
			self.attached(pid)
		elif event == shook.PROCESS_DETACHED:
			report('PID', pid, 'detached')
			del self.tracee_tbl[pid]
		elif event == shook.PROCESS_FORK:
			report('PID', pid, 'forked by', ppid)
			self.forked(ppid, pid)
		elif event == shook.PROCESS_VFORK:
			report('PID', pid, 'vforked by', ppid)
			self.forked(ppid, pid)
		elif event == shook.PROCESS_CLONE:
			report('PID', pid, 'cloned by', ppid)
			self.cloned(ppid, pid)
		else:
			assert False, f"invalid event {event}"

	def syscall_hook(self, pid, retval, scno, *args):
		if scno == shook.SYS_close:
			if retval is not None:
				fd, = args
				if retval >= 0:
					_, fd_obj, _ = self.get_fd(pid, fd)
					if isinstance(fd_obj, FD):
						fd_obj.on_close(pid, fd)
					self.close_fd(pid, fd)
				elif self.strict:
					return shook.ACTION_GDB,
		elif scno == shook.SYS_execve:
			if retval == 0:
				# remove all fd with F_CLOEXEC after execve succeed
				new_fd_tbl = { }
				tracee = self.tracee_tbl[pid]
				for fd, fd_data in tracee.fd_table.items():
					flags, fd_obj, user_data = fd_data
					if (flags & self.F_CLOEXEC) == 0:
						new_fd_tbl[fd] = [flags, fd_obj, user_data]
				tracee.fd_table = new_fd_tbl
				
		elif scno == shook.SYS_ioctl:
			fd, op, val = args
			if retval is None:
				_, fd_obj, _ = self.get_fd(pid, fd)
				if isinstance(fd_obj, FD):
					if op == FIONREAD:
						nread = fd_obj.on_fionread(pid)
						if nread is not None:
							shook.poke_uint32(pid, val, nread)
							return shook.ACTION_BYPASS, 0
					else:
						ret = fd_obj.on_ioctl(pid, fd, op, val)
						if ret is not None:
							return shook.ACTION_BYPASS, ret
			elif retval is not None:
				if retval >= 0 and op == 0x5421:
					opt = shook.peek_uint32(pid, val, 1)[0]
					self.mod_fd_flags(pid, fd, self.F_NONBLOCKING, opt != 0)
		elif scno == shook.SYS_fcntl:
			if retval is not None:
				fd, op, val = args
				if retval >= 0:
					if op == fcntl.F_SETFL:
						self.mod_fd_flags(pid, fd, self.F_NONBLOCKING, (val & self.O_NONBLOCKING) != 0)
					elif op == fcntl.F_DUPFD:
						self.dup_fd(pid, fd, retval)
		elif scno == shook.SYS_dup:
			fd, = args
			if retval is not None:
				if retval >= 0:
					self.dup_fd(pid, fd, retval)
		elif scno == shook.SYS_dup2:
			fdold, fdnew = args
			if retval is not None:
				if retval >= 0 and retval != fdold:
					self.close_fd(pid, fdnew)
					self.dup_fd(pid, fdold, retval)
		elif scno == shook.SYS_dup3:
			fdold, fdnew, flags = args
			if retval is not None:
				if retval >= 0:
					self.close_fd(pid, fdnew)
					self.dup_fd(pid, fdold, retval, self.F_CLOEXEC if flags & self.O_CLOEXEC else 0)
		elif scno == shook.SYS_socket:
			if retval is not None and retval >= 0:
				domain, type, protocol = args
				flags = 0
				if type & shook.SOCK_NONBLOCK:
					flags |= self.F_NONBLOCKING
				if type & shook.SOCK_CLOEXEC:
					flags |= self.F_CLOEXEC
				if flags:
					self.mod_fd_flags(pid, retval, flags, True)
		elif scno == shook.SYS_getsockname:
			fd, sa, slen = args
			_, fd_obj, _ = self.get_fd(pid, fd)
			if isinstance(fd_obj, FD):
				return fd_obj.on_getsockname(pid, retval, fd, sa, slen)
		elif scno == shook.SYS_getpeername:
			fd, sa, slen = args
			_, fd_obj, _ = self.get_fd(pid, fd)
			if isinstance(fd_obj, FD):
				return fd_obj.on_getpeername(pid, retval, fd, sa, slen)
		elif scno == shook.SYS_read:
			fd, addr, length = args
			_, fd_obj, _ = self.get_fd(pid, fd)
			if isinstance(fd_obj, FD):
				return fd_obj.on_read(pid, retval, fd, addr, length)
		elif scno == shook.SYS_readv:
			fd, iov, iovcnt = args
			_, fd_obj, _ = self.get_fd(pid, fd)
			if isinstance(fd_obj, FD):
				return fd_obj.on_readv(pid, retval, fd, iov, iovcnt)
		elif scno == shook.SYS_recvfrom:
			fd, addr, length, flags, src_addr, addrlen = args
			_, fd_obj, _ = self.get_fd(pid, fd)
			if isinstance(fd_obj, FD):
				return fd_obj.on_recvfrom(pid, retval, fd, addr, length, flags, src_addr, addrlen)
		elif scno == shook.SYS_recvmsg:
			fd, msg, flags = args
			_, fd_obj, _ = self.get_fd(pid, fd)
			if isinstance(fd_obj, FD):
				return fd_obj.on_recvmsg(pid, retval, fd, msg, flags)
		elif scno == shook.SYS_write:
			fd, addr, length = args
			_, fd_obj, _ = self.get_fd(pid, fd)
			if isinstance(fd_obj, FD):
				return fd_obj.on_write(pid, retval, fd, addr, length)
		elif scno == shook.SYS_writev:
			fd, iov, iovcnt = args
			_, fd_obj, _ = self.get_fd(pid, fd)
			if isinstance(fd_obj, FD):
				return fd_obj.on_writev(pid, retval, fd, iov, iovcnt)
		elif scno == shook.SYS_sendto:
			fd, addr, length, flags, dest_addr, addrlen = args
			_, fd_obj, _ = self.get_fd(pid, fd)
			if isinstance(fd_obj, FD):
				return fd_obj.on_sendto(pid, retval, fd, addr, length, flags, dest_addr, addrlen)
		elif scno == shook.SYS_sendmsg:
			fd, msg, flags = args
			_, fd_obj, _ = self.get_fd(pid, fd)
			if isinstance(fd_obj, FD):
				return fd_obj.on_sendmsg(pid, retval, fd, msg, flags);
		elif scno == shook.SYS_sendmmsg:
			fd, msgvec, vlen, flags = args
			_, fd_obj, _ = self.get_fd(pid, fd)
			if isinstance(fd_obj, FD):
				return fd_obj.on_sendmmsg(pid, retval, fd, msgvec, vlen, flags);
		elif scno == shook.SYS_epoll_ctl:
			#define EPOLL_CTL_ADD 1
			#define EPOLL_CTL_DEL 2
			#define EPOLL_CTL_MOD 3
			if retval is None:
				epfd, op, fd, epevt = args
				_, epfd_obj, _ = self.get_fd(pid, epfd)
				if not isinstance(epfd_obj, Epoll):
					return None
				_, fd_obj, _ = self.get_fd(pid, fd)
				if not isinstance(fd_obj, Pollable):
					return None
				if op == 1:
					ret = epfd_obj.add(fd, shook.peek_epoll_event(pid, epevt, 1)[0])
					if ret != 0 and self.strict:
						return shook.ACTION_GDB,
					return shook.ACTION_BYPASS, ret
				elif op == 2:
					return shook.ACTION_BYPASS, epfd_obj.remove(fd)
				elif op == 3:
					return shook.ACTION_BYPASS, epfd_obj.mod(fd, shook.peek_epoll_event(pid, epevt, 1)[0])
		elif scno == shook.SYS_epoll_wait:
			if retval is None:
				epfd, events, maxevents, timeout = args
				_, epfd_obj, _ = self.get_fd(pid, epfd)
				if not isinstance(epfd_obj, Epoll):
					return None
				# TODO make it fair
				ready = []
				for fd, epoll_event in epfd_obj.fd_table.items():
					_, fd_obj, _ = self.get_fd(pid, fd)
					if not isinstance(fd_obj, Pollable):
						report('Warning %d is not intercepted' % fd)
					else:
						revents = 0
						if epoll_event[0] & select.POLLOUT and fd_obj.want_send(fd):
							revents |= select.POLLOUT
						if epoll_event[0] & select.POLLIN and fd_obj.want_recv(fd):
							revents |= select.POLLIN
						if revents != 0:
							if epoll_event[0] & select.EPOLLONESHOT:
								report('Reset fd event to 0 for ONESHOT', fd)
								epoll_event[0] = 0
							ready.append((revents, epoll_event[1]))
							if len(ready) == maxevents:
								break
				if len(ready) > 0:
					report('epoll_wait', *ready)
					shook.poke_epoll_event(pid, events, *ready)
					return shook.ACTION_BYPASS, len(ready)
		elif scno == shook.SYS_ppoll:
			# TODO kernel modify arg_tmo_p 
			arg_fds, arg_nfds, arg_tmo_p, arg_sigmask, arg_sigsetsize = args
			if retval is None:
				ready, ret_nfds = self.rewrite_pollfd_enter(pid, arg_fds, arg_nfds)
				if ret_nfds != arg_nfds:
					if ready:
						# make it return immediately
						arg_tmo_p = shook.alloc_copy(pid, struct.pack('QQ', 0, 0))
					return shook.ACTION_REDIRECT, scno, arg_fds, ret_nfds, arg_tmo_p, arg_sigmask, arg_sigsetsize
			else:
				return self.rewrite_pollfd_leave(pid, retval, arg_fds, arg_nfds)

		elif scno == shook.SYS_poll:
			arg_fds, arg_nfds, arg_timeout = args
			if retval is None:
				ready, ret_nfds = self.rewrite_pollfd_enter(pid, arg_fds, arg_nfds)
				if ret_nfds != arg_nfds:
					return shook.ACTION_REDIRECT, scno, arg_fds, ret_nfds, 0 if ready else arg_timeout
			else:
				return self.rewrite_pollfd_leave(pid, retval, arg_fds, arg_nfds)
					
	def rewrite_pollfd_enter(self, pid, arg_fds, arg_nfds):
		pollfd = shook.peek_pollfd(pid, arg_fds, arg_nfds)
		new_pollfd, ret_pollfd = [], []
		ready_count = 0
		index = 0
		for pfd in pollfd:
			_, fd_obj, _ = self.get_fd(pid, pfd[0])
			if isinstance(fd_obj, Pollable):
				revents = 0
				if pfd[1] & select.POLLOUT and fd_obj.want_send(pfd[0]):
					revents |= select.POLLOUT
				if pfd[1] & select.POLLIN and fd_obj.want_recv(pfd[0]):
					revents |= select.POLLIN
				ret_pollfd.append((pfd[0], pfd[1], revents, index))
				if revents != 0:
					ready_count += 1
			else:
				new_pollfd.append(pfd)
			index += 1
		# TODO can avoid save the ret_pollfd?
		self.dprint('pollfd', pollfd, new_pollfd, ret_pollfd)
		self.push(pid, arg_fds, arg_nfds, ret_pollfd)
		if len(ret_pollfd) > 0:
			shook.poke_pollfd(pid, arg_fds, *new_pollfd)
		return ready_count, len(new_pollfd)
		
	def rewrite_pollfd_leave(self, pid, retval, arg_fds, arg_nfds):
		fds, nfds, ret_pollfd = self.pop(pid)
		if retval < 0:
			return None
		elif len(ret_pollfd) > 0:
			pollfd = shook.peek_pollfd(pid, fds, nfds - len(ret_pollfd))
			new_pollfd = list(pollfd)
			for fd, events, revents, index in ret_pollfd:
				new_pollfd.insert(index, (fd, events, revents))
				if revents != 0:
					retval += 1
			self.dprint('rewrite ret pollfds', pollfd, ret_pollfd, new_pollfd, retval)
			assert len(new_pollfd) == nfds, "len(%s) != %d" % (new_pollfd, nfds)
			shook.poke_pollfd(pid, fds, *new_pollfd)
			return shook.ACTION_RETURN, retval
		else:
			pollfd = shook.peek_pollfd(pid, fds, nfds)
			self.dprint('not modified', retval, pollfd)

# TODO TraceeMgmt__ is singleton
the_tracee_manager = TraceeMgmt__()
def get_tracee_manager():
	return the_tracee_manager

