#!/usr/bin/env python

from __future__ import print_function
import sys, os

sys.path.append(os.path.dirname(__file__))
import shook_utils, stracer

def output(*args):
	print(*args, end='')

gstate = shook_utils.get_tracee_manager()
gstate.register_handlers(stracer.Stracer(output))

