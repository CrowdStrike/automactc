#!/usr/bin/env python

'''

@ purpose:

A module intended to read and parse the utmpx file located in
/private/var/run/utmpx.


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

import sys
import os
import csv
import glob
import datetime
import logging

from collections import OrderedDict
from struct import Struct, calcsize, unpack_from
from string import printable

_modName = __name__.split('_')[-2]
_modVers = '.'.join(list(__name__.split('_')[-1][1:]))
log = logging.getLogger(_modName)

# Setting up a function to decode the logon types


def decode_logon(int_code):
    if int_code == 2:
        logon_type = "BOOT_TIME"
    elif int_code == 7:
        logon_type = "USER_PROCESS"
    else:
        logon_type = "UNKNOWN"
    return logon_type


def module():
    headers = ['user', 'id', 'terminal_type', 'pid', 'logon_type', 'timestamp', 'hostname']
    output = data_writer(_modName, headers)

    utmpx_path = glob.glob(os.path.join(inputdir,'private/var/run/utmpx'))

    # This is a string version of the struct format
    # https://opensource.apple.com/source/Libc/Libc-1158.50.2/include/NetBSD/utmpx.h.auto.html
    # https://github.com/libyal/dtformats/blob/master/documentation/Utmp%20login%20records%20format.asciidoc
    # https://stackoverflow.com/questions/17244488/reading-struct-in-python-from-created-struct-in-c

    UTMPX_STR = "256s4s32sih2xii256s64x"
    UTMPX_STR_SIZE = calcsize(UTMPX_STR)
    UTMPX_BUFFER_SIZE = 628

    if len(utmpx_path) == 0:
        log.debug("File not found: {0}".format(utmpx_path))

    for path in utmpx_path:
        with open(path, 'rb') as file:
            # set the headers and write it out.
            record = OrderedDict((h, '') for h in headers)
            # Read out header section, but we'll discard it for now.
            header = file.read(UTMPX_BUFFER_SIZE)
            # print header
            # Loop through the rest of the records.
            # First record is always boot time.
            while True:
                buf = file.read(UTMPX_BUFFER_SIZE)
                if len(buf) != UTMPX_STR_SIZE:
                    break
                # Write out the fields
                user, id, terminal_type, pid, logon_code, epoch, usec, host_id = unpack_from(UTMPX_STR, buf)
                # Combine the timestamp fields
                combo_time = datetime.datetime.utcfromtimestamp(epoch) + datetime.timedelta(microseconds=usec)
                timestamp_formatted = combo_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

                if host_id.decode('utf-8').rstrip('\x00') == '':
                    host = "localhost"
                else:
                    host = host_id.decode('utf-8').rstrip('\x00')

                # Convert them to an OrderedDict and then create Values View
                record['user'] = user.decode('utf-8').rstrip('\x00')
                record['id'] = "".join(filter(lambda char: char in printable, id.decode('utf-8')))
                record['terminal_type'] = terminal_type.decode('utf-8').rstrip('\x00')
                record['pid'] = pid
                record['logon_type'] = decode_logon(logon_code)
                record['timestamp'] = timestamp_formatted
                record['hostname'] = host
                line = record.values()
                # print values
                output.write_entry(line)


if __name__ == "__main__":
    print("This is an AutoMacTC module, and is not meant to be run stand-alone.")
    print("Exiting.")
    sys.exit(0)
else:
    module()
