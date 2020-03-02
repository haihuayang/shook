#!/usr/bin/env python

from __future__ import print_function
import sys, os
from datetime import datetime

def str_time(now = None):
	if now is None:
		now = datetime.now()
	return "%02d:%02d:%02d.%06d" % (now.hour, now.minute, now.second, now.microsecond)

def report(*args):
	print(str_time(), *args)
	sys.stdout.flush()

class Globals:
	pass

def syscall_handler(pid, retval, scno, *args):
	if scno in [ shook.SYS_getuid, shook.SYS_geteuid ]:
		if retval is not None:
			report(pid, shook.syscall_name(scno), "fake to 0")
			return shook.ACTION_RETURN, 0
	elif scno in [ shook.SYS_getgid, shook.SYS_getegid ]:
		if retval is not None:
			report(pid, shook.syscall_name(scno), "fake to 0")
			return shook.ACTION_RETURN, 0
	elif scno == shook.SYS_getgroups:
		if retval is None:
			if args[0] != 0:
				shook.poke_uint32(pid, args[1], 0)
			return shook.ACTION_BYPASS, 1
	elif scno in [ shook.SYS_stat, shook.SYS_lstat, shook.SYS_fstat ]:
		if retval == 0:
			uid, gid = shook.peek_uint32(pid, args[1] + 0x1c, 2)
			report(pid, shook.syscall_name(scno), uid, gid)
			modified = False
			if uid == Globals.uid:
				uid = 0
				modified = True
			if gid == Globals.gid:
				gid = 0
				modified = True
			if modified:
				shook.poke_uint32(pid, args[1] + 0x1c, uid, gid)
	


Globals.uid = os.getuid()
Globals.gid = os.getgid()

shook.register(shook.EVENT_SYSCALL, syscall_handler)

