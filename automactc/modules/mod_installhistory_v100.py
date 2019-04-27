#!/usr/bin/env python

'''
@ author: Kshitij Kumar
@ email: kshitijkumar14@gmail.com, kshitij.kumar@crowdstrike.com

@ purpose:

A module intended to parse the InstallHistory.plist file.

'''
import plistlib
import os
import glob
from collections import OrderedDict

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from automactc.modules.common.base import AutoMacTCModule
from automactc.utils.output import DataWriter


class PsListModule(AutoMacTCModule):
    _mod_filename = __name__

    _headers = [
        'src_name', 'timestamp', 'display_name', 'display_version',
        'package_identifiers', 'process_name'
    ]

    def run(self):
        output = DataWriter(self.module_name(), self._headers, self.log, self.run_id, self.options)

        installhistory_loc = os.path.join(self.options.inputdir, 'Library/Receipts/InstallHistory.plist')
        installhistory_list = glob.glob(installhistory_loc)

        if len(installhistory_list) == 0:
            self.log.debug("File not found: {0}".format(installhistory_loc))

        for item in installhistory_list:
            installhistory = plistlib.readPlist(item)

            for i in range(len(installhistory)):
                record = OrderedDict((h, '') for h in self._headers)
                record['src_name'] = os.path.basename(item)
                record['timestamp'] = installhistory[i]['date'].strftime('%Y-%m-%dT%H:%M:%SZ')
                record['display_version'] = installhistory[i]['displayVersion']
                record['display_name'] = installhistory[i]['displayName']
                record['package_identifiers'] = installhistory[i]['packageIdentifiers']
                record['process_name'] = installhistory[i]['processName']

                line = [x.encode('utf-8') if isinstance(x, unicode) else x for x in record.values()]
                output.write_entry(line)
