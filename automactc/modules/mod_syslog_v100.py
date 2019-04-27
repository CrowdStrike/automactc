#!/usr/bin/env python

'''
@ author: Jai Musunuri
@ email: jai.musunuri@crowdstrike.com

@ purpose:

A module intended to read and parse system.log files on disk.

'''
import glob
import gzip
import os
import re
from itertools import groupby
from operator import itemgetter
from collections import OrderedDict

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from automactc.modules.common.base import AutoMacTCModule
from automactc.utils.output import DataWriter


class SyslogModule(AutoMacTCModule):
    _mod_filename = __name__

    _headers = ['src_file', 'timestamp', 'log_systemname', 'processname', 'pid', 'message']

    def _syslog_parse(self, logfile, logdata, output):
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

        for k, v in singlelines.items():
            line = v
            if not 'last message repeated' in line:
                record = OrderedDict((h, '') for h in self._headers)
                m = re.match(r"(?P<month>\w\w\w)\s{1,2}(?P<day>\d{1,2}) (?P<time>\w\w:\w\w:\w\w) (?P<systemname>.*?) (?P<processName>.*?)\[(?P<PID>[0-9]+)\].*?:\s{0,1}(?P<message>.*)", line)
                record['src_file'] = logfile
                record['timestamp'] = str(m.group('month') + " " + m.group('day') + " " + m.group('time'))
                record['log_systemname'] = m.group('systemname')
                record['processname'] = m.group('processName')
                record['pid'] = m.group('PID')
                record['message'] = m.group('message')

                output.write_entry(record.values())

    def run(self):
        output = DataWriter(self.module_name(), self._headers, self.log, self.run_id, self.options)

        syslog_loc = os.path.join(self.options.inputdir,'private/var/log/system.log*')
        varlog_inputdir = glob.glob(syslog_loc)

        if len(varlog_inputdir) == 0:
            self.log.debug("Files not found in: {0}".format(syslog_loc))

        for c_syslog in varlog_inputdir:
            if not c_syslog.endswith('.gz'):
                with open(c_syslog, 'r') as co_syslog:
                    self._syslog_parse(c_syslog, co_syslog, output)
            else:
                with gzip.open(c_syslog, 'r') as go_syslog:
                    self._syslog_parse(c_syslog, go_syslog, output)
