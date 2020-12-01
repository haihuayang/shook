#!/usr/bin/env python

from __future__ import print_function
import sys, os, socket
from datetime import datetime
import shook
import shook_utils

def dissect_execve(stracer, pid, retval, scno, *args):
	if retval is None:
		path, argv, envp = args
		return '"%s", 0x%x, 0x%x' % (shook.peek_path(pid, path), argv, envp)
	else:
		return ''

def open_flags_mode_to_string(flags, mode):
	open_flags = (
		( os.O_APPEND, 'O_APPEND' ),
		( os.O_ASYNC, 'O_ASYNC' ),
		( os.O_CLOEXEC, 'O_CLOEXEC' ),
		( os.O_CREAT, 'O_CREAT' ),
		( os.O_DIRECT, 'O_DIRECT' ),
		( os.O_DSYNC, 'O_DSYNC' ),
		( os.O_EXCL, 'O_EXCL' ),
		( os.O_LARGEFILE, 'O_LARGEFILE' ),
		( os.O_NOATIME, 'O_NOATIME' ),
		( os.O_NOCTTY, 'O_NOCTTY' ),
		( os.O_NOFOLLOW, 'O_NOFOLLOW' ),
		( os.O_NONBLOCK, 'O_NONBLOCK' ),
		( os.O_PATH, 'O_PATH' ),
		( os.O_SYNC, 'O_SYNC' ),
		( os.O_TMPFILE, 'O_TMPFILE' ),
		( os.O_TRUNC, 'O_TRUNC' ),
	)
	flags_str = []
	wr, flags = flags & 3, flags & ~3
	if wr == 0:
		flags_str = [ 'O_RDONLY' ]
	elif wr == 1:
		flags_str = [ 'O_WRONLY' ]
	elif wr == 2:
		flags_str = [ 'O_RDWR' ]
	else:
		flags_str = [ 'O_3' ]
	if flags & (os.O_CREAT | os.O_TMPFILE):
		mode_str = ', 0%o' % mode
	else:
		mode_str = ''

	for f, n in open_flags:
		if flags & f:
			flags_str.append(n)
			flags &= ~f
	if flags:
		flags_str.append('0x%x' % flags)
	return '|'.join(flags_str) + mode_str;

def dissect_open(stracer, pid, retval, scno, *args):
	if retval is None:
		path, flags, mode = args
		return '"%s", %s' % (shook.peek_path(pid, path), open_flags_mode_to_string(flags, mode))
	else:
		return ''

def dissect_openat(stracer, pid, retval, scno, *args):
	if retval is None:
		dirfd, path, flags, mode = args
		return '%d, "%s", %s' % (dirfd, shook.peek_path(pid, path), open_flags_mode_to_string(flags, mode))
	else:
		return ''

def dissect_mkdir(stracer, pid, retval, scno, *args):
	if retval is None:
		path, mode = args
		return '"%s", 0%o' % (shook.peek_path(pid, path), mode)
	else:
		return ''

def dissect_stat(stracer, pid, retval, scno, *args):
	if retval is None:
		path, statbuf = args
		return '"%s", 0x%x' % (shook.peek_path(pid, path), statbuf)
	else:
		return ''

def dissect_access(stracer, pid, retval, scno, *args):
	if retval is None:
		path, mode = args
		return '"%s", %d' % (shook.peek_path(pid, path), mode)
	else:
		return ''

def dissect_faccessat(stracer, pid, retval, scno, *args):
	if retval is None:
		dirfd, path, mode = args
		return '%d, "%s", %d' % (dirfd, shook.peek_path(pid, path), mode)
	else:
		return ''

def dissect_unlink(stracer, pid, retval, scno, *args):
	if retval is None:
		path, = args
		return '"%s"' % shook.peek_path(pid, path)
	else:
		return ''

def dissect_readlink(stracer, pid, retval, scno, *args):
	if retval is None:
		path, buf, bufsize = args
		return '"%s", 0x%x, %d' % (shook.peek_path(pid, path), buf, bufsize)
	elif retval > 0:
		path, buf, bufsize = args
		return ' "%s"' % shook.peek_data(buf, retval)
		
	else:
		return ''

def dissect_socket(stracer, pid, retval, scno, *args):
	if retval is None:
		domain, socktype, protocol = args
		domain_names = (
			( socket.AF_UNIX, 'AF_UNIX' ),
			( socket.AF_INET, 'AF_INET' ),
			( socket.AF_INET6, 'AF_INET6' ),
			( socket.AF_NETLINK, 'AF_NETLINK' ),
			( socket.AF_PACKET, 'AF_PACKET' ),
		)
		socktype_names = (
			( socket.SOCK_STREAM, 'SOCK_STREAM' ),
			( socket.SOCK_DGRAM, 'SOCK_DGRAM' ),
			( socket.SOCK_SEQPACKET, 'SOCK_SEQPACKET' ),
			( socket.SOCK_RAW, 'SOCK_RAW' ),
			# ( socket.SOCK_PACKET, 'SOCK_PACKET' ),
		)
		for v, n in domain_names:
			if domain == v:
				domain_name = n
				break
		else:
			domain_name = 'AF_%d' % domain

		for v, n in socktype_names:
			if socktype == v:
				socktype_name = n
				break
		else:
			socktype_name = 'SOCK_%d' % socktype

		return '%s, %s, %d' % (domain_name, socktype_name, protocol)
	else:
		return ''

def dissect_connect_bind(stracer, pid, retval, scno, *args):
	if retval is None:
		sockfd, sa, slen = args
		sockaddr = shook.peek_sockaddr(pid, sa, slen)
		return '%d, %s, %d' % (sockfd, sockaddr, slen)
	else:
		return ''

def dissect_sendto(stracer, pid, retval, scno, *args):
	if retval is None:
		sockfd, buf, length, flags, dest_addr, addrlen = args
		sockaddr = shook.peek_sockaddr(pid, dest_addr, addrlen)
		return '%d, 0x%x, %d, 0x%x, %s, %d' % (sockfd, buf, length, flags, sockaddr, addrlen)
	else:
		return ''

def dissect_sendmsg(stracer, pid, retval, scno, *args):
	if retval is None:
		sockfd, msghdr, flags = args
		msg_name, msg_namelen, msg_iov, msg_iovlen, msg_control, msg_controllen, msg_flags = shook.peek_msghdr(pid, msghdr, 1)[0]
		if msg_name != 0:
			sockaddr = shook.peek_sockaddr(pid, msg_name, msg_namelen)
		else:
			sockaddr = '0x0'
		return '%d, [%s, %d, 0x%x, %d, 0x%x, %d, 0x%x], 0x%x' % (sockfd,
			sockaddr, msg_namelen, msg_iov, msg_iovlen, msg_control, msg_controllen, msg_flags, flags)
	else:
		return ''

def dissect_recvfrom(stracer, pid, retval, scno, *args):
	if retval is None:
		sockfd, buf, length, flags, src_addr, paddrlen = args
		return '%d, 0x%x, %d, 0x%x, 0x%x, 0x%x' % (sockfd, buf, length, flags, src_addr, paddrlen)
	elif retval >= 0:
		sockfd, buf, length, flags, src_addr, paddrlen = args
		if src_addr != 0:
			addrlen = shook.peek_uint32(pid, paddrlen, 1)[0]
			sockaddr = shook.peek_sockaddr(pid, src_addr, addrlen)
			return '%s, %d' % (sockaddr, addrlen)
		return ''
	else:
		return ''

def dissect_recvmsg(stracer, pid, retval, scno, *args):
	if retval is None:
		sockfd, msghdr, flags = args
		return '%d, 0x%x, 0x%x' % (sockfd, msghdr, flags)
	elif retval >= 0:
		sockfd, msghdr, flags = args
		msg_name, msg_namelen, msg_iov, msg_iovlen, msg_control, msg_controllen, msg_flags = shook.peek_msghdr(pid, msghdr, 1)[0]
		if msg_name != 0:
			sockaddr = shook.peek_sockaddr(pid, msg_name, msg_namelen)
		else:
			sockaddr = '0x0'
		return '[%s, %d, 0x%x, %d, 0x%x, %d, 0x%x]' % (sockaddr, msg_namelen, msg_iov, msg_iovlen, msg_control, msg_controllen, msg_flags)
	else:
		return ''

def dissect_getxattr(stracer, pid, retval, scno, *args):
	if retval is None:
		path, name, value, size = args
		return '"%s", "%s", 0x%x, %d' % (shook.peek_path(pid, path), shook.peek_path(pid, name), value, size)
	else:
		return ''

def dissect_setxattr(stracer, pid, retval, scno, *args):
	if retval is None:
		path, name, value, size, flags = args
		return '"%s", "%s", 0x%x, %d, 0x%x' % (shook.peek_path(pid, path), shook.peek_path(pid, name), value, size, flags)
	else:
		return ''

def dissect_default(stracer, pid, retval, scno, *args):
	if retval is None:
		return ', '.join(['%d' % arg for arg in args])
	else:
		return ''

def str_time(now):
	return "%02d:%02d:%02d.%06d" % (now.hour, now.minute, now.second, now.microsecond)

def str_timespan(d):
	return "<%d.%06d>" % (d.seconds, d.microseconds)

class Stracer(object):
	dissects = {
		shook.SYS_execve: dissect_execve,
		shook.SYS_open: dissect_open,
		shook.SYS_mkdir: dissect_mkdir,
		shook.SYS_unlink: dissect_unlink,
		shook.SYS_stat: dissect_stat,
		shook.SYS_statfs: dissect_stat, # TODO
		shook.SYS_access: dissect_access,
		shook.SYS_faccessat: dissect_faccessat,
		shook.SYS_getxattr: dissect_getxattr,
		shook.SYS_setxattr: dissect_setxattr,
		shook.SYS_readlink: dissect_readlink,
		shook.SYS_socket: dissect_socket,
		shook.SYS_connect: dissect_connect_bind,
		shook.SYS_bind: dissect_connect_bind,
		shook.SYS_sendto: dissect_sendto,
		shook.SYS_sendmsg: dissect_sendmsg,
		shook.SYS_recvfrom: dissect_recvfrom,
		shook.SYS_recvmsg: dissect_recvmsg,
	}

	def __init__(self, output):
		self.output = output
		self.last_pid = None

	def syscall_hook(self, pid, retval, scno, *args):
		if self.last_pid is not None and self.last_pid != pid:
			self.output(" <unfinished ...>\n")
		
		now = datetime.now()
		try:
			dissect = self.dissects[scno]
		except:
			dissect = dissect_default

		data = dissect(self, pid, retval, scno, *args)
		if retval is None: 
			self.output(str_time(now), pid, shook.syscall_name(scno), "(%s" % data)
			self.last_pid = pid
			shook_utils.the_tracee_manager.push(pid, now)
		else:
			enter_time, = shook_utils.the_tracee_manager.pop(pid)
			if self.last_pid != pid:
				self.output(str_time(now), pid, "... resume ")
			self.output("%s) =" % data, retval, str_timespan(now - enter_time), '\n')
			self.last_pid = None

	def process_hook(self, pid, event, ppid):
		if self.last_pid is not None:
			self.output("<unfinished ...>\n")
			self.last_pid = None
	
		if event == shook.PROCESS_CREATED:
			self.output(pid, "CREATED")
		elif event == shook.PROCESS_ATTACHED:
			self.output(pid, "ATTACHED")
		elif event == shook.PROCESS_DETACHED:
			self.output(pid, "DETACHED")
		elif event == shook.PROCESS_FORK:
			self.output(pid, "FORK", 'by', ppid)
		elif event == shook.PROCESS_VFORK:
			self.output(pid, "VFORK", 'by', ppid)
		elif event == shook.PROCESS_CLONE:
			self.output(pid, "CLONE", 'by', ppid)
		else:
			self.output(pid, "UNKNOWN", 'ppid', ppid)

	def signal_hook(self, pid, signo):
		if self.last_pid is not None:
			self.output("<unfinished ...>\n")
			self.last_pid = None
	
		self.output(pid, '+++  killed by', shook.signal_name(signo), ' +++')

	def finish_hook(self):
		if self.last_pid is not None:
			self.output("<unfinished ...>\n")
			self.last_pid = None
	
		self.output("finished")
