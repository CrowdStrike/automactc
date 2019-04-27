#!/usr/bin/env python

'''
@ author: Kshitij Kumar
@ email: kshitijkumar14@gmail.com, kshitij.kumar@crowdstrike.com

@ purpose:

A module intended to record current file handles open, when run on a
live system.

'''
from collections import OrderedDict
from subprocess import Popen, PIPE

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from automactc.modules.common.base import AutoMacTCModule
from automactc.utils.output import DataWriter


class LSOFModule(AutoMacTCModule):
    _mod_filename = __name__

    _headers = [
        'cmd', 'pid', 'ppid', 'user', 'file_descriptor',
        'type', 'device', 'size', 'node', 'access', 'name'
    ]

    def run(self):
        if ("Volumes" not in self.options.inputdir and self.options.forensic_mode is False):
            output = DataWriter(self.module_name(), self._headers, self.log, self.run_id, self.options)

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
                    line = [v for k, v in result.items()]

                    output.write_entry(line)

            lsof.communicate()

        else:
            self.log.error("Module did not run: input is not a live system!")
