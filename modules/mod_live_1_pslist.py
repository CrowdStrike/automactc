"""A module intended to record the current process listing when run on a
live system.
"""

import logging
import os
import subprocess
import sys

# IMPORT STATIC VARIABLES FROM MAIN
from __main__ import (archive, data_writer, forensic_mode, full_prefix,
						inputdir, no_tarball, outputdir, quiet, startTime)

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from .common.dateutil import parser
from .common.functions import stats2

_modName = __name__.split('_')[-1]
_modVers = '1.1.0'
log = logging.getLogger(_modName)


def module():
	if ("Volumes" not in inputdir and forensic_mode is False):
		headers = ['pid', 'ppid', 'user', 'state', 'proc_start', 'runtime', 'cmd']
		output = data_writer(_modName, headers)

		os.environ['TZ'] = 'UTC0'
		ps_out, e = subprocess.Popen(["ps", "-Ao", "pid,ppid,user,stat,lstart,time,command"], stdout=subprocess.PIPE).communicate()

		if e:
			pass
		else:
			pslist = ps_out.decode('utf-8').split('\n')
			for p in pslist:
				if "PID" not in p and len(p) > 0:
					item = [x.lstrip(' ') for x in filter(None, p.split(' '))]
					pid = item[0]
					ppid = item[1]
					user = item[2]
					state = item[3]
					proc_start = parser.parse(' '.join(item[5:9])).replace(tzinfo=None).isoformat() + 'Z'
					runtime = item[9]
					cmd = ' '.join(item[10:])

					line = [pid, ppid, user, state, proc_start, runtime, cmd]
					output.write_record(line)

	else:
		log.error("Module did not run: input is not a live system!")
	output.flush_record()

if __name__ == "__main__":
	print("This is an AutoMacTC module, and is not meant to be run stand-alone.")
	print("Exiting.")
	sys.exit(0)
else:
	module()
