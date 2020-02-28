#!/usr/bin/env python

from __future__ import print_function
import sys, errno, time
from datetime import datetime

def str_time(now = None):
	if now is None:
		now = datetime.now()
	return "%02d:%02d:%02d.%06d" % (now.hour, now.minute, now.second, now.microsecond)

def report(*args):
	print(str_time(), *args)
	sys.stdout.flush()

def output_backtrace(pid):
	stacks = shook.backtrace(pid)
	for ip, offset, symbol in stacks:
		print('    0x%x %s+%d' % (ip, symbol, offset))

class Globals:
	shift_seconds = 0

CLOCK_REALTIME = 0 # no definition in python 2.7 

def syscall_handler(pid, retval, scno, *args):
	# shift wall-clock time
	if scno == shook.SYS_clock_gettime:
		if retval == 0 and args[0] == CLOCK_REALTIME:
			sec, nsec = shook.peek_timespec(pid, args[1], 1)[0]
			report(pid, "shift realtime (%d, %d)" % (sec, nsec))
			output_backtrace(pid)
			shook.poke_timespec(pid, args[1], (sec + Globals.shift_seconds, nsec))
	elif scno == shook.SYS_gettimeofday:
		if retval == 0:
			sec, usec = shook.peek_timeval(pid, args[0], 1)[0]
			report(pid, "shift gettimeofday (%d, %d)" % (sec, usec))
			output_backtrace(pid)
			shook.poke_timeval(pid, args[0], (sec + Globals.shift_seconds, usec))
	elif scno == shook.SYS_time:
		if not retval in [ None, -1 ]:
			report(pid, "shift time %d" % retval)
			output_backtrace(pid)
			return shook.ACTION_RETURN, retval + Globals.shift_seconds


if len(sys.argv) == 2:
	Globals.shift_seconds = int(sys.argv[1])

report("time_shift %d seconds" % Globals.shift_seconds)
shook.register(shook.EVENT_SYSCALL, syscall_handler)

