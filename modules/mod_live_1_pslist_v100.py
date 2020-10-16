#!/usr/bin/env python

'''

@ purpose:

A module intended to record the current process listing when run on a
live system.

'''

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from .common.functions import stats2

# IMPORT STATIC VARIABLES FROM MAIN
from __main__ import inputdir
from __main__ import outputdir
from __main__ import forensic_mode
from __main__ import no_tarball
from __main__ import quiet

from __main__ import archive
from __main__ import startTime
from __main__ import full_prefix
from __main__ import data_writer

import os
import csv
import subprocess
import logging
from .common.dateutil import parser

_modName = __name__.split('_')[-2]
_modVers = '.'.join(list(__name__.split('_')[-1][1:]))
log = logging.getLogger(_modName)

def module():
	if ("Volumes" not in inputdir and forensic_mode is False):
		
		headers = ['pid','ppid','user','state','proc_start','runtime','cmd']
		output = data_writer(_modName, headers)

		os.environ['TZ'] = 'UTC0'
		ps_out, e = subprocess.Popen(["ps","-Ao","pid,ppid,user,stat,lstart,time,command"], stdout=subprocess.PIPE).communicate()

		if e:
			pass
		else:
			pslist = ps_out.decode('utf-8').split('\n')
			for l in pslist:
				if "PID" not in l and len(l) > 0:
					item =  [x.lstrip(' ') for x in filter(None,l.split(' '))]
					pid = item[0]
					ppid = item[1]
					user = item[2]
					state = item[3]
					proc_start = parser.parse(' '.join(item[5:9])).replace(tzinfo=None).isoformat()+'Z'
					runtime = item[9]
					cmd = ' '.join(item[10:])
					
					line = [pid,ppid,user,state,proc_start,runtime,cmd]
					output.write_entry(line)

	else:
		log.error("Module did not run: input is not a live system!")

if __name__ == "__main__":
    print("This is an AutoMacTC module, and is not meant to be run stand-alone.")
    print("Exiting.")
    sys.exit(0)
else:
	module()