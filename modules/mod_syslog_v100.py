#!/usr/bin/env python

'''
@ author: Jai Musunuri
@ email: jai.musunuri@crowdstrike.com

@ purpose:

A module intended to read and parse system.log files on disk.

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

import glob
import csv
import gzip
import os
import re
import logging
from itertools import groupby
from operator import itemgetter
from collections import OrderedDict
from datetime import datetime, timedelta
import dateutil.parser as parser

_modName = __name__.split('_')[-2]
_modVers = '.'.join(list(__name__.split('_')[-1][1:]))
log = logging.getLogger(_modName)

def syslog_parse(logfile, logdata, headers, output):
    x = 0
    data = []
    singlelines = {}
    multilines = {}
    for i in logdata:
        x+=1
        if re.search('^[A-Za-z]{3}',i):
            singlelines[x] = i.rstrip()
        else:
            data.append(x)
            data.append(x-1)
            data.append(x+1)
            multilines[x] = i.rstrip()

    data = list(OrderedDict.fromkeys(sorted(data)))
    ranges = []
    for key, group in groupby(enumerate(data), lambda (index, item): index - item):
        group = map(itemgetter(1), group)
        if len(group) > 1:
            ranges.append(xrange(group[0], group[-1]))
        else:
            ranges.append(group[0])

    for u in ranges:
        chain = []
        for z in u:
            if multilines.get(z) is None:
                lno = z
                anchor = singlelines.get(z)
            else:
                val = multilines.get(z).replace('\t','').replace('  ','')
                chain.append(val)

        singlelines[lno] = anchor+' '+''.join(chain)

    for k,v in singlelines.items():
        line = v
        if not 'last message repeated' in line:
            record = OrderedDict((h, '') for h in headers)
            m = re.match(r"(?P<month>\w\w\w)\s{1,2}(?P<day>\d{1,2}) (?P<time>\w\w:\w\w:\w\w) (?P<systemname>.*?) (?P<processName>.*?)\[(?P<PID>[0-9]+)\].*?:\s{0,1}(?P<message>.*)", line)
            record['src_file'] = logfile
            record['timestamp'] = str(m.group('month') + " " + m.group('day') + " " + m.group('time'))
            record['log_systemname'] = m.group('systemname')
            record['processname'] = m.group('processName')
            record['pid'] = m.group('PID')
            record['message'] = m.group('message')

            output.write_entry(record.values())


def module():

    headers = ['src_file','timestamp','log_systemname','processname','pid','message']
    output = data_writer(_modName, headers)

    syslog_loc = os.path.join(inputdir,'private/var/log/system.log*')
    varlog_inputdir = glob.glob(syslog_loc)

    if len(varlog_inputdir) == 0:
        log.debug("Files not found in: {0}".format(syslog_loc))

    for c_syslog in varlog_inputdir:
        if not c_syslog.endswith('.gz'):
            with open(c_syslog, 'r') as co_syslog:
                syslog_parse(c_syslog, co_syslog, headers, output)
        else:
            with gzip.open(c_syslog, 'r') as go_syslog:
                syslog_parse(c_syslog, go_syslog, headers, output)

if __name__ == "__main__":
    print "This is an AutoMacTC module, and is not meant to be run stand-alone."
    print "Exiting."
    sys.exit(0)
else:
    module()


