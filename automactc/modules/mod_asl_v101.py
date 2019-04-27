#!/usr/bin/env python

'''
@ author: Jai Musunuri
@ email: jai.musunuri@crowdstrike.com

@ purpose:

A module intended to read and parse .asl files on disk.

'''
import os
import subprocess
import glob
import re
from collections import OrderedDict
from itertools import groupby
from operator import itemgetter

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from automactc.modules.common.base import AutoMacTCModule
from automactc.utils.output import DataWriter


class ASLModule(AutoMacTCModule):
    _mod_filename = __name__

    _headers = ['src_file', 'timestamp', 'log_systemname', 'processname', 'pid', 'message']

    def _asl_parse(self, logfile, logdata, output):
        x = 0
        data = []
        singlelines = {}
        multilines = {}

        for i in logdata:
            x += 1
            if re.search(r'^\d{4}\-\d{2}\-\d{2}', i):
                singlelines[x] = i.rstrip()
            else:
                data.append(x)
                data.append(x - 1)
                data.append(x + 1)
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
                    val = multilines.get(z).replace('\t', '').replace('  ', '')
                    chain.append(val)

            try:
                singlelines[lno] = anchor + ' ' + ''.join(chain)
            except TypeError:
                if not "NOTE:Most system logs have moved" in ''.join(chain):
                    self.log.debug("Line does not resemble an ASL entry: {0}.".format(chain))

        for k, v in singlelines.items():
            line = v
            if not 'last message repeated' in line:
                record = OrderedDict((h, '') for h in self._headers)
                m = re.match(
                    r"^(?P<datetime>\d{4}\-\d{2}\-\d{2} \w\w:\w\w:\w\w\.\d{3}Z) (?P<systemname>.*?) (?P<processName>.*?)\[(?P<PID>[0-9]+)\].*?:\s{0,1}(?P<message>.*)", line)
                record['src_file'] = logfile
                record['timestamp'] = m.group('datetime').replace(' ', 'T')
                record['log_systemname'] = m.group('systemname')
                record['processname'] = m.group('processName')
                record['pid'] = m.group('PID')
                record['message'] = m.group('message')

                output.write_entry(record.values())

    def run(self):
        output = DataWriter(self.module_name(), self._headers, self.log, self.run_id, self.options)

        os.environ['TZ'] = 'UTC0'
        asl_loc = os.path.join(self.options.inputdir,'private/var/log/asl/*.asl')
        varlogasl_inputdir = glob.glob(asl_loc)

        if len(varlogasl_inputdir) == 0:
            self.log.debug("Files not found in: {0}".format(asl_loc))


        for asllog in varlogasl_inputdir:
            FNULL = open(os.devnull, 'w')
            asl_out, e = subprocess.Popen(
                ["syslog", "-f", asllog, '-T', 'utc.3'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()
            if "Invalid Data Store" in asl_out:
                self.log.debug("Could not parse {0}. Invalid Data Store error reported - file may be corrupted.".format(asllog))
            if not e:
                oasllog = asl_out.split('\n')
                self._asl_parse(asllog, oasllog, output)
            else:
                self.log.error("Could not parse ASL logs.")
