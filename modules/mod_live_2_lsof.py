"""A module intended to record current file handles open, when run on a
live system.
"""

import logging
import sys
from collections import OrderedDict
from subprocess import PIPE, Popen

# IMPORT STATIC VARIABLES FROM MAIN
from __main__ import (archive, data_writer, forensic_mode, full_prefix,
						inputdir, no_tarball, outputdir, quiet, startTime)

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from .common.functions import stats2

_modName = __name__.split('_')[-1]
_modVers = '1.1.0'
log = logging.getLogger(_modName)


def module():
	if ("Volumes" not in inputdir and forensic_mode is False):
		headers = ['cmd', 'pid', 'ppid', 'user', 'file_descriptor', 'type', 'device', 'size', 'node', 'access', 'name']
		output = data_writer(_modName, headers)

		# encoding = locale.getpreferredencoding(True)
		names = OrderedDict(zip('cpRLftDsian', 'command pid ppid user fd type device_no size inode access name'.split()))

		lsof = Popen(["lsof", "-n", "-P", "-F{}0".format(''.join(names))], stdout=PIPE, bufsize=-1)

		for line in lsof.stdout:
			try:
				fields = {f[:1].decode('ascii', 'strict'): f[1:].decode() for f in line.split(b'\0') if f.rstrip(b'\n')}
			except UnicodeDecodeError:
				fields = {f[:1].decode('ascii', 'strict'): f[1:] for f in line.split(b'\0') if f.rstrip(b'\n')}
			if 'p' in fields:
				process_info = fields
			elif 'f' in fields:
				fields.update(process_info)
				result = OrderedDict((name, fields.get(id)) for id, name in names.items())
				line = [v for k, v in result.items()]

				output.write_record(line)

		lsof.communicate()
	else:
		log.error("Module did not run: input is not a live system!")
	output.flush_record()

if __name__ == "__main__":
	print("This is an AutoMacTC module, and is not meant to be run stand-alone.")
	print("Exiting.")
	sys.exit(0)
else:
	module()
