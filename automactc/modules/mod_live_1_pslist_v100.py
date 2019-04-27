#!/usr/bin/env python

'''
@ author: Kshitij Kumar
@ email: kshitijkumar14@gmail.com, kshitij.kumar@crowdstrike.com

@ purpose:

A module intended to record the current process listing when run on a
live system.

'''
import os
import subprocess
import dateutil.parser as parser

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from automactc.modules.common.base import AutoMacTCModule
from automactc.utils.output import DataWriter


class PsListModule(AutoMacTCModule):
    _mod_filename = __name__

    _headers = [
        'pid', 'ppid', 'user', 'state', 'proc_start', 'runtime', 'cmd'
    ]

    def run(self):
        if ("Volumes" not in self.options.inputdir and self.options.forensic_mode is False):
            output = DataWriter(self.module_name(), self._headers, self.log, self.run_id, self.options)

            os.environ['TZ'] = 'UTC0'
            ps_out, e = subprocess.Popen(["ps","-Ao","pid,ppid,user,stat,lstart,time,command"], stdout=subprocess.PIPE).communicate()

            if e:
                pass
            else:
                pslist = ps_out.decode('utf-8').split('\n')
                for l in pslist:
                    if "PID" not in l and len(l) > 0:
                        item =  [x.lstrip(' ') for x in filter(None,l.split(' '))]
                        pid = item[0]
                        ppid = item[1]
                        user = item[2]
                        state = item[3]
                        proc_start = parser.parse(' '.join(item[5:9])).replace(tzinfo=None).isoformat()+'Z'
                        runtime = item[9]
                        cmd = ' '.join(item[10:]).encode("utf-8")

                        line = [pid,ppid,user,state,proc_start,runtime,cmd]
                        output.write_entry(line)

        else:
            self.log.error("Module did not run: input is not a live system!")
