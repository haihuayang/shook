#!/usr/bin/env python

from __future__ import print_function
import sys, errno, socket

def report(*args):
	print(*args)

class Global(object):
	sockaddr_orig, sockaddr_new = None, None
	count = 0
	failure = 0

def syscall_handler(pid, retval, scno, *args):
	if scno == shook.SYS_write and retval is None:
		arg_fd, arg_data, arg_size = args
		if arg_fd == 9999:
			Global.count += 1
			if Global.count == 1:
				sockaddr = shook.peek_sockaddr(pid, arg_data, arg_size)
				if sockaddr == Global.sockaddr_orig:
					report('CHECKPOINT: PASSED peek_sockaddr')
				else:
					report('CHECKPOINT: FAILED peek_sockaddr', sockaddr, 'expect', Global.sockaddr_orig)
					Global.failure += 1
				shook.poke_sockaddr(pid, arg_data, arg_size, *Global.sockaddr_new)
				return shook.ACTION_BYPASS, arg_size
			elif Global.count == 2:
				sockaddr = shook.peek_sockaddr(pid, arg_data, arg_size)
				if sockaddr == Global.sockaddr_new:
					report('CHECKPOINT: PASSED poke_sockaddr')
				else:
					report('CHECKPOINT: FAILED poke_sockaddr', sockaddr, 'expect', Global.sockaddr_new)
					Global.failure += 1
			else:
				report('CHECKPOINT: FAILED unexpected')
				Global.failure += 1

def finish_handler():
	if Global.failure:
		report('FAIL:', Global.failure)
	

def parse_sockaddr(s):
	arr = s.split(',')
	if arr[0] == 'unix':
		return (socket.AF_UNIX, arr[1])
	elif arr[0] == 'inet':
		ip = socket.inet_ntop(socket.AF_INET, socket.inet_pton(socket.AF_INET, arr[1]))
		return (socket.AF_INET, ip, int(arr[2], 0))
	elif arr[0] == 'inet6':
		ip = socket.inet_ntop(socket.AF_INET6, socket.inet_pton(socket.AF_INET6, arr[1]))
		flowinfo = int(arr[3], 0) if len(arr) > 3 else 0
		scope_id = int(arr[4], 0) if len(arr) > 4 else 0
		return (socket.AF_INET6, ip, int(arr[2], 0), flowinfo, scope_id)
	else:
		assert False

Global.sockaddr_orig = parse_sockaddr(sys.argv[1])
Global.sockaddr_new = parse_sockaddr(sys.argv[2])

shook.register(shook.EVENT_SYSCALL, syscall_handler)
shook.register(shook.EVENT_FINISH, finish_handler)

