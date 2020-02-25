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

class Globals:
	shift_seconds = 600

CLOCK_REALTIME = 0 # no definition in python 2.7 

def syscall_handler(pid, retval, scno, *args):
	# shift wall-clock time
	if scno == shook.SYS_clock_gettime and retval == 0 and args[0] == CLOCK_REALTIME:
		sec, nsec = shook.peek_timespec(pid, args[1], 1)[0]
		report("shift time (%d, %d) +600" % (sec, nsec))
		shook.poke_timespec(pid, args[1], (sec + Globals.shift_seconds, nsec))

if len(sys.argv) == 2:
	Globals.shift_seconds = int(sys.argv[1])

shook.register(shook.EVENT_SYSCALL, syscall_handler)

