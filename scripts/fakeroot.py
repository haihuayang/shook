#!/usr/bin/env python

from __future__ import print_function
import sys, os
from datetime import datetime
sys.path.append(os.path.dirname(__file__)); import shook_utils

def str_time(now = None):
	if now is None:
		now = datetime.now()
	return "%02d:%02d:%02d.%06d" % (now.hour, now.minute, now.second, now.microsecond)

def report(*args):
	print(str_time(), *args)
	sys.stdout.flush()

class Globals:
	tracee_mgmt = shook_utils.TraceeMgmt()
	mknod_created = { }
	pass

DBG = report

AT_FDCWD = -100
AT_SYMLINK_NOFOLLOW = 0x100
AT_EMPTY_PATH = 0x1000

def get_abspath(pid, fd, path_addr, flags):
	if fd == AT_FDCWD:
		fdcwd = '/proc/%d/cwd' % Globals.tracee_mgmt.get_main_pid(pid)
		fdcwd = os.path.realpath(fdcwd)
	else:
		_, _, fdcwd = Globals.tracee_mgmt.get_fd(pid, fd)

	if path_addr != 0:
		path = shook.peek_path(pid, path_addr)
		ret_path = os.path.join(fdcwd, path)
	elif flags & AT_EMPTY_PATH:
		ret_path = fdcwd
	else:
		assert False, "get_abspath"

	if (flags & AT_SYMLINK_NOFOLLOW) == 0:
		return os.path.realpath(ret_path)
	return ret_path

def rewrite_stat(pid, scno, abspath, stat_arg):
	uid, gid = shook.peek_uint32(pid, stat_arg + 0x1c, 2)
	try:
		nod_info = Globals.mknod_created[abspath]
	except:
		nod_info = None

	report(pid, shook.syscall_name(scno), "rewrite_stat", abspath, uid, gid, nod_info)
	modified = False
	if uid == Globals.uid:
		uid = 0
		modified = True
	if gid == Globals.gid:
		gid = 0
		modified = True
	if modified:
		shook.poke_uint32(pid, stat_arg + 0x1c, uid, gid)

	if nod_info:
		mode, rdev = nod_info
		report(pid, 'mode 0x%x, rdev 0x%x' % (mode, rdev))
		shook.poke_uint32(pid, stat_arg + 0x18, mode)
		shook.poke_uint64(pid, stat_arg + 0x28, rdev)

def unlink(pid, scno, retval, fdcwd, path_addr, flags):
	abspath = get_abspath(pid, fdcwd, path_addr, flags)
	DBG(pid, shook.syscall_name(scno), retval, abspath)
	if retval is None:
		if abspath in Globals.mknod_created:
			if fdcwd != AT_FDCWD:
				path_addr = shook.alloc_copy(pid, abspath)
			return shook.ACTION_REDIRECT, shook.SYS_rmdir, path_addr
	elif retval == 0:
		try:
			del Globals.mknod_created[abspath]
		except KeyError:
			report(pid, "path %s not in table" % abspath)

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
	elif scno == shook.SYS_mknod:
		if retval is None:
			Globals.tracee_mgmt.push(pid, args[1], args[2])
			# creaet a normal file instead device
			return shook.ACTION_REDIRECT, shook.SYS_mkdir, args[0], (args[1] & 0777)
		else:
			mode, rdev = Globals.tracee_mgmt.pop(pid)
			report(pid, 'mknod', retval, 'mode 0x%x, rdev 0x%x' % (mode, rdev))
			if retval == 0:
				path = shook.peek_path(pid, args[0])
				abspath = os.path.realpath(os.path.join('/proc/%d/cwd' % Globals.tracee_mgmt.get_main_pid(pid), path))
				report(pid, 'mknod', path, abspath, 'mode 0x%x, rdev 0x%x' % (mode, rdev))
				Globals.mknod_created[abspath] = (mode, rdev)
	elif scno in [ shook.SYS_unlink ]:
		return unlink(pid, scno, retval, AT_FDCWD, args[1], AT_SYMLINK_NOFOLLOW)
	elif scno in [ shook.SYS_unlinkat ]:
		return unlink(pid, scno, retval, args[0], args[1], args[2])
	elif scno in [ shook.SYS_open ]:
		report(pid, shook.syscall_name(scno), shook.peek_path(pid, args[0]))
		if retval is not None and retval >= 0:
			Globals.tracee_mgmt.set_fd_userdata(pid, retval,
				get_abspath(pid, AT_FDCWD, args[0], 0))
	elif scno in [ shook.SYS_openat ]:
		if retval is not None and retval >= 0:
			Globals.tracee_mgmt.set_fd_userdata(pid, retval,
				get_abspath(pid, args[0], args[1], args[2]))
	elif scno == shook.SYS_stat:
		if retval == 0:
			abspath = get_abspath(pid, AT_FDCWD, args[0], 0)
			rewrite_stat(pid, scno, abspath, args[1])
	elif scno == shook.SYS_lstat:
		if retval == 0:
			abspath = get_abspath(pid, AT_FDCWD, args[0], AT_SYMLINK_NOFOLLOW)
			rewrite_stat(pid, scno, abspath, args[1])
	elif scno == shook.SYS_fstat:
		report(pid, shook.syscall_name(scno), *args)
		if retval == 0:
			_, _, abspath = Globals.tracee_mgmt.get_fd(pid, args[0])
			rewrite_stat(pid, scno, abspath, args[1])
	elif scno == shook.SYS_newfstatat:
		if retval == 0:
			abspath = get_abspath(pid, args[0], args[1], args[3])
			rewrite_stat(pid, scno, abspath, args[2])
			
			
Globals.uid = os.getuid()
Globals.gid = os.getgid()
Globals.tracee_mgmt.register_handlers((syscall_handler,))

