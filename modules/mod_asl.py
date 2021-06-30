"""A module intended to read and parse .asl files on disk.
"""

import glob
import logging
import os
import plistlib
import re
import subprocess
import sys
from collections import OrderedDict

# IMPORT STATIC VARIABLES FROM MAIN
from __main__ import data_writer, forensic_mode, inputdir, quiet

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from .common.functions import stats2
from .common.xmltodict import xmltodict

try:
    from past.builtins import range as xrange
except Exception:
    pass

_modName = __name__.split('_')[-1]
_modVers = "1.0.4"
log = logging.getLogger(_modName)

def asl_raw_parse(logfile, logdata, output, headers):
    for entry in logdata:
        record = OrderedDict((h, '') for h in headers)
        for h in headers:
            try:
                record[h] = entry.get(h)
            except IndexError:
                record[h] = ""
        output.write_record(record)
    output.flush_record()    


def asl_parse(logfile, logdata, headers, output):
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
    # for key, group in groupby(enumerate(data), lambda (index, item): index - item):
    for group in enumerate(data):
        # group = map(itemgetter(1), group)
        if len(group) > 1:
            ranges.append(range(group[0], group[-1]))
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
            if "NOTE:Most system logs have moved" not in ''.join(chain):
                log.debug("Line does not resemble an ASL entry: {0}.".format(chain))
        except UnboundLocalError:
            if len(u) > 0:
                log.debug("No ASL data? {0}".format(u))

    for k, v in singlelines.items():
        line = v
        if 'last message repeated' not in line:
            record = OrderedDict((h, '') for h in headers)
            m = re.match(
                r"^(?P<datetime>\d{4}\-\d{2}\-\d{2} \w\w:\w\w:\w\w\.\d{3}Z) (?P<systemname>.*?) (?P<processName>.*?)\[(?P<PID>[0-9]+)\].*?:\s{0,1}(?P<message>.*)", line)
            record['src_file'] = logfile
            record['timestamp'] = m.group('datetime').replace(' ', 'T')
            record['log_systemname'] = m.group('systemname')
            record['processname'] = m.group('processName')
            record['pid'] = m.group('PID')
            record['message'] = m.group('message')

            output.write_record(record)


def module():
    os.environ['TZ'] = 'UTC0'

    headers = ["ASLMessageID", "Time", "TimeNanoSec", "Level", "PID", "UID", 
        "GID", "ReadGID", "Host", "Sender", "Facility", "Message", "ut_user", "ut_id"
        "ut_line", "ut_pid", "ut_type", "ut_tv.tv_sec", "ut_tv.tv_usec"
        "SenderMachUUID", "ASLExpireTime"]
    output = data_writer(_modName, headers)

    asl_loc = os.path.join(inputdir, 'private/var/log/asl/*.asl')
    varlogasl_inputdir = glob.glob(asl_loc)

    if len(varlogasl_inputdir) == 0:
        log.debug("Files not found in: {0}".format(asl_loc))

    for asllog in varlogasl_inputdir:
        FNULL = open(os.devnull, 'w')
        asl_out, e = subprocess.Popen(
            ["syslog", "-f", asllog, '-T', 'utc.3', '-F', 'xml'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()
        if "Invalid Data Store" in asl_out.decode('utf-8'):
            log.debug("Could not parse {0}. Invalid Data Store error reported - file may be corrupted.".format(asllog))
            continue
        if not e:
            if b"NOTE:  Most system logs have moved to a new logging system.  See log(1) for more information." in asl_out:
                if sys.version_info[0] < 3:
                    p = plistlib.readPlistFromString("\n".join(asl_out.split('\n')[1:]))
                else:
                    p = plistlib.loads(b"\n".join(asl_out.split(b'\n')[1:]))
            else:
                if sys.version_info[0] < 3:
                    p = plistlib.readPlistFromString(asl_out.split('\n'))
                else:
                    p = plistlib.loads(b"\n".join(asl_out.split('\n')))

            asl_raw_parse(asllog, p, output, headers)

        else:
            log.error("Could not parse ASL logs.")
    output.flush_record()


if __name__ == "__main__":
    print("This is an AutoMacTC module, and is not meant to be run stand-alone.")
    print("Exiting.")
    sys.exit(0)
else:
    module()
