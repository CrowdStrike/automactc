#!/usr/bin/env python

'''
@ author: Eric John
@ email: eric.john@crowdstrike.com

@ purpose:

A module intended to read and parse the utmpx file located in
/private/var/run/utmpx.


'''
import os
import glob
import datetime
from collections import OrderedDict
from struct import calcsize, unpack_from

import pytz

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from automactc.modules.common.base import AutoMacTCModule
from automactc.utils.output import DataWriter


class UTMPXModule(AutoMacTCModule):
    _mod_filename = __name__

    _headers = ['user', 'id', 'terminal_type', 'pid', 'logon_type', 'timestamp', 'hostname']

    # Setting up a function to decode the logon types
    @classmethod
    def _decode_logon(cls, int_code):
        if int_code == 2:
            logon_type = "BOOT_TIME"
        elif int_code == 7:
            logon_type = "USER_PROCESS"
        else:
            logon_type = "UNKNOWN"
        return logon_type


    def run(self):

        output = DataWriter(self.module_name(), self._headers, self.log, self.run_id, self.options)

        utmpx_path = glob.glob(os.path.join(self.options.inputdir,'private/var/run/utmpx'))

        # This is a string version of the struct format
        # https://opensource.apple.com/source/Libc/Libc-1158.50.2/include/NetBSD/utmpx.h.auto.html
        # https://github.com/libyal/dtformats/blob/master/documentation/Utmp%20login%20records%20format.asciidoc
        # https://stackoverflow.com/questions/17244488/reading-struct-in-python-from-created-struct-in-c

        UTMPX_STR = "256s4s32sih2xii256s64x"
        UTMPX_STR_SIZE = calcsize(UTMPX_STR)
        UTMPX_BUFFER_SIZE = 628

        if len(utmpx_path) == 0:
            self.log.debug("File not found: {0}".format(utmpx_path))

        for path in utmpx_path:
            with open(path, 'rb') as file:
                # set the headers and write it out.
                record = OrderedDict((h, '') for h in self._headers)
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
                    utc_combo = pytz.utc.localize(combo_time)
                    timestamp_formatted = utc_combo.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

                    if host_id.rstrip('\x00') == '':
                        host = "localhost"
                    else:
                        host = host_id.rstrip('\x00')

                    # Convert them to an OrderedDict and then create Values View
                    record['user'] = user.rstrip('\x00')
                    record['id'] = id
                    record['terminal_type'] = terminal_type.rstrip('\x00')
                    record['pid'] = pid
                    record['logon_type'] = self._decode_logon(logon_code)
                    record['timestamp'] = timestamp_formatted
                    record['hostname'] = host
                    line = record.values()
                    # print values
                    output.write_entry(line)
