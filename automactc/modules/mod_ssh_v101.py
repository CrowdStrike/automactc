#!/usr/bin/env python

'''
@ author: Kshitij Kumar
@ email: kshitijkumar14@gmail.com, kshitij.kumar@crowdstrike.com

@ purpose:

A module intended to read and parse SSH known_hosts and authorized_keys
files for each user on disk.

'''
import os
import subprocess
import glob
from collections import OrderedDict

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from automactc.modules.common.base import AutoMacTCModule
from automactc.utils.output import DataWriter


class SpotlightModule(AutoMacTCModule):
    _mod_filename = __name__

    _headers = ['src_name', 'user', 'bits', 'fingerprint', 'host', 'keytype']

    def run(self):
        output = DataWriter(self.module_name(), self._headers, self.log, self.run_id, self.options)

        user_inputdir = glob.glob(os.path.join(self.options.inputdir, "Users/*"))
        user_inputdir.append(os.path.join(self.options.inputdir, "var/root"))

        record = OrderedDict((h, '') for h in self._headers)

        for user_home in user_inputdir:
            record['user'] = os.path.basename(user_home)

            # Gather known_hosts and authorized_users files for the user.
            kh_path = os.path.join(user_home, '.ssh/known_hosts')
            u_knownhosts = glob.glob(kh_path)

            ak_path = os.path.join(user_home, '.ssh/authorized_keys')
            u_authorizedkeys = glob.glob(ak_path)

            # Combine all files found into one list per user.
            u_ssh_all = u_knownhosts + u_authorizedkeys

            # Define the directory checked for use in debug messages.
            user_ssh_dir = os.path.join(user_home, '.ssh/')

            # Generate debug messages for files not found.
            if len(u_knownhosts) == 0:
                self.log.debug("File not found: {0}".format(kh_path))
            if len(u_authorizedkeys) == 0:
                self.log.debug("File not found: {0}".format(ak_path))

            # Iterate over files found and parse them using ssh-keygen.
            for item in u_ssh_all:
                p, e = subprocess.Popen(["ssh-keygen", "-l", "-f", item], stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()
                record['src_name'] = os.path.basename(item)

                if not e and not "is not a public key file" in p:
                    p = p.split('\n')
                    p = [x for x in p if len(x) > 0]
                    for i in p:
                        data = i.split(' ')
                        record['bits'] = data[0]
                        record['fingerprint'] = data[1]
                        record['host'] = data[2]
                        record['keytype'] = data[3]

                        line = record.values()
                        output.write_entry(line)

                elif "is not a public key file" in p:
                    self.log.debug("Could not parse {0}: {1}".format(file, p))
