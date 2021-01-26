#!/usr/bin/env python

from __future__ import print_function
import sys, errno
from datetime import datetime

def str_time(now = None):
	if now is None:
		now = datetime.now()
	return "%02d:%02d:%02d.%06d" % (now.hour, now.minute, now.second, now.microsecond)

def report(*args):
	print(str_time(), *args)
	sys.stdout.flush()

reject_pattern = sys.argv[1]

def syscall_handler(pid, retval, scno, *args):
	if scno == shook.SYS_mkdir and retval is None:
		path = shook.peek_path(pid, args[0])
		if path.find(reject_pattern) >= 0:
			report("bypass mkdir(%s), return ENOSPC" % path)
			return shook.ACTION_BYPASS, -errno.ENOSPC

shook.register(shook.EVENT_SYSCALL, syscall_handler)

