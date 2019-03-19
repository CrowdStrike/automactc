#!/usr/bin/env python

'''
@ author: Kshitij Kumar
@ email: kshitijkumar14@gmail.com, kshitij.kumar@crowdstrike.com

@ purpose:

A module intended to record current and past network connections, when
run on a live system.

'''

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from common.functions import stats2

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

import csv
import subprocess
import logging

_modName = __name__.split('_')[-2]
_modVers = '.'.join(list(__name__.split('_')[-1][1:]))
log = logging.getLogger(_modName)

def module():
	if ("Volumes" not in inputdir and forensic_mode is False):
		
		headers = ['protocol','recv_q','send_q','src_ip','src_port','dst_ip','dst_port','state']
		output = data_writer(_modName, headers)

		netstat_out, e = subprocess.Popen(["netstat","-f","inet","-n"], stdout=subprocess.PIPE).communicate()

		if e:
			pass
		else:
			netstat=netstat_out.encode('utf-8').split('\n')
			for l in netstat:
				if not (l.startswith("Active") or l.startswith("Proto") or len(l) == 0):
					item =  [x.lstrip(' ') for x in filter(None,l.split(' '))]
					protocol = item[0]
					recv_q = item[1]
					send_q = item[2]
					
					try:
						src_ip = '.'.join(item[3].split('.')[0:4])
					except:
						src_ip = "ERROR"
					try:
						src_port = item[3].split('.')[-1]
					except:
						src_port = "ERROR"

					try:
						dst_ip = '.'.join(item[4].split('.')[0:4])
					except:
						dst_ip = "ERROR"
					try:
						dst_port = item[4].split('.')[-1]
					except:
						dst_port = "ERROR"

					if len(item) == 6:
						state = item[5]
					else:
						state = ""

					line = [protocol,recv_q,send_q,src_ip,src_port,dst_ip,dst_port,state]
					output.write_entry(line)

	else:
		log.error("Module did not run: input is not a live system!")


if __name__ == "__main__":
	print "This is an AutoMacTC module, and is not meant to be run stand-alone."
	print "Exiting."
	sys.exit(0)
else:
	module()