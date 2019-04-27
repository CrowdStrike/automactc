#!/usr/bin/env python

'''
@ author: Kshitij Kumar
@ email: kshitijkumar14@gmail.com, kshitij.kumar@crowdstrike.com

@ purpose:

A module intended to record current and past network connections, when
run on a live system.

'''
import subprocess

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from automactc.modules.common.base import AutoMacTCModule
from automactc.utils.output import DataWriter


class NetstatModule(AutoMacTCModule):
    _mod_filename = __name__

    _headers = [
        'protocol', 'recv_q', 'send_q', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'state'
    ]

    def run(self):
        if ("Volumes" not in self.options.inputdir and self.options.forensic_mode is False):
            output = DataWriter(self.module_name(), self._headers, self.log, self.run_id, self.options)
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
            self.log.error("Module did not run: input is not a live system!")
