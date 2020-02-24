#!/usr/bin/env python

from __future__ import print_function
import sys
from datetime import datetime

def str_time(now = None):
	if now is None:
		now = datetime.now()
	return "%02d:%02d:%02d.%06d" % (now.hour, now.minute, now.second, now.microsecond)

def report(*args):
	print(str_time(), *args)
	sys.stdout.flush()

def syscall_handler(pid, retval, scno, *args):
	if retval is None: 
		report(pid, '->', shook.syscall_name(scno), *args)
	else:
		report(pid, '<-', shook.syscall_name(scno), retval)

def process_handler(pid, event, ppid):
	if event == shook.PROCESS_CREATED:
		report(pid, "CREATED")
	elif event == shook.PROCESS_ATTACHED:
		report(pid, "ATTACHED")
	elif event == shook.PROCESS_DETACHED:
		report(pid, "DETACHED")
	elif event == shook.PROCESS_FORK:
		report(pid, "FORK", 'by', ppid)
	elif event == shook.PROCESS_VFORK:
		report(pid, "VFORK", 'by', ppid)
	elif event == shook.PROCESS_CLONE:
		report(pid, "CLONE", 'by', ppid)
	else:
		report(pid, "UNKNOWN", 'ppid', ppid)

def signal_handler(pid, signo, coredump):
	report(pid, '+++  killed by', shook.signal_name(signo), '(core dumped)' if coredump else '', '+++')

def finish_handler():
	report("finished")

shook.register(shook.EVENT_PROCESS, process_handler)
shook.register(shook.EVENT_SYSCALL, syscall_handler)
shook.register(shook.EVENT_SIGNAL, signal_handler)
shook.register(shook.EVENT_FINISH, finish_handler)

