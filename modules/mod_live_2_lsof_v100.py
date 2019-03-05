#!/usr/bin/env python

'''
@ author: Kshitij Kumar
@ email: kshitijkumar14@gmail.com, kshitij.kumar@crowdstrike.com

@ purpose:

A module intended to record current file handles open, when run on a
live system.

'''

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from common.functions import stats2

# IMPORT STATIC VARIABLES FROM MACXTR
from __main__ import inputdir
from __main__ import outputdir
from __main__ import forensic_mode
from __main__ import no_tarball
from __main__ import quiet

from __main__ import archive
from __main__ import startTime
from __main__ import full_prefix
from __main__ import data_writer

import csv
import locale
import logging

from collections import OrderedDict
from subprocess import Popen, PIPE

_modName = __name__.split('_')[-2]
_modVers = '.'.join(list(__name__.split('_')[-1][1:]))
log = logging.getLogger(_modName)

def module():
	if ("Volumes" not in inputdir and forensic_mode is False):
		
		headers = ['cmd','pid','ppid','user','file_descriptor','type','device','size','node','access','name']
		output = data_writer(_modName, headers)

		#encoding = locale.getpreferredencoding(True)
		names = OrderedDict(zip('cpRLftDsian', 'command pid ppid user fd type device_no size inode access name'.split()))

		lsof = Popen(["lsof","-n","-P","-F{}0".format(''.join(names))], stdout=PIPE, bufsize=-1)

		for line in lsof.stdout:
		   
		    fields = {f[:1].decode('ascii', 'strict'): f[1:] for f in line.split(b'\0') if f.rstrip(b'\n')}
		    if 'p' in fields:
		        process_info = fields
		    elif 'f' in fields:
		        fields.update(process_info)
		        result = OrderedDict((name, fields.get(id)) for id, name in names.items())
		        line = [v for k,v in result.items()]

		        output.write_entry(line)

		lsof.communicate()


	else:
		log.error("Module did not run: input is not a live system!")

if __name__ == "__main__":
	print "This is an AutoMacTC module, and is not meant to be run stand-alone."
	print "Exiting."
	sys.exit(0)
else:
	module()