#!/usr/bin/env python

'''
@ author: Kshitij Kumar
@ email: kshitijkumar14@gmail.com, kshitij.kumar@crowdstrike.com

@ purpose:

A module intended gather basic system information that can be used
to identify the host.

'''
import plistlib
import sqlite3
import subprocess
import glob
import os
import traceback
from collections import OrderedDict

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from automactc.modules.common.base import AutoMacTCModule
from automactc.modules.common.functions import stats2
from automactc.modules.common.functions import finditem
from automactc.modules.common.functions import read_bplist
from automactc.utils.output import DataWriter


class SystemInfoModule(AutoMacTCModule):
    _mod_filename = __name__

    _headers = [
        'local_hostname', 'computer_name', 'hostname', 'model',
        'product_version', 'product_build_version', 'serial_no', 'volume_created',
        'system_tz', 'amtc_runtime', 'ipaddress', 'fvde_status'
    ]

    def run(self):
        output = DataWriter(self.module_name(), self._headers, self.log, self.run_id, self.options)

        # -------------BEGIN MODULE-SPECIFIC LOGIC------------- #
        globalpreferences = read_bplist(os.path.join(self.options.inputdir, 'Library/Preferences/.GlobalPreferences.plist'))
        preferences = plistlib.readPlist(os.path.join(self.options.inputdir, 'Library/Preferences/SystemConfiguration/preferences.plist'))
        systemversion = plistlib.readPlist(os.path.join(self.options.inputdir, 'System/Library/CoreServices/SystemVersion.plist'))

        # KEEP THE LINE BELOW TO GENERATE AN ORDEREDDICT BASED ON THE HEADERS
        record = OrderedDict((h, '') for h in self._headers)

        record['local_hostname'] = finditem(preferences, 'LocalHostName')
        record['ipaddress'] = self.options.full_prefix.split(',')[2]

        computer_name = finditem(preferences, 'ComputerName')
        if computer_name is not None:
            record['computer_name'] = computer_name.encode('utf-8')
        record['hostname'] = finditem(preferences, 'HostName')
        record['model'] = finditem(preferences, 'Model')
        record['product_version'] = self.options.os_version
        record['product_build_version'] = finditem(systemversion, 'ProductBuildVersion')

        g = glob.glob(os.path.join(self.options.inputdir, 'private/var/folders/zz/zyxvpxvq6csfxvn_n00000sm00006d/C/*'))
        check_dbs = ['consolidated.db', 'cache_encryptedA.db', 'lockCache_encryptedA.db']
        serial_dbs = [loc for loc in g if any(loc.endswith(db) for db in check_dbs)]
        serial_query = 'SELECT SerialNumber FROM TableInfo;'

        for db in serial_dbs:
            try:
                cursor = sqlite3.connect(db).cursor()
                record['serial_no'] = cursor.execute(serial_query).fetchone()[0]
                break

            except Exception:
                record['serial_no'] = 'ERROR'

        record['volume_created'] = stats2(self.options.inputdir + "/", oMACB=True)['btime']
        record['amtc_runtime'] = str(self.options.start_time).replace(' ', 'T').replace('+00:00', 'Z')

        if 'Volumes' not in self.options.inputdir and self.options.forensic_mode is not True:

            tz, e = subprocess.Popen(["systemsetup", "-gettimezone"], stdout=subprocess.PIPE).communicate()
            record['system_tz'] = tz.rstrip().replace('Time Zone: ', '')

            _fdestatus, e = subprocess.Popen(["fdesetup", "status"], stdout=subprocess.PIPE).communicate()
            if 'On' in _fdestatus:
                record['fvde_status'] = "On"
            else:
                record['fvde_status'] = "Off"
        else:
            try:
                record['system_tz'] = globalpreferences[0]['com.apple.TimeZonePref.Last_Selected_City'][3]
            except Exception:
                self.log.error("Could not get system timezone: {0}".format([traceback.format_exc()]))
                record['system_tz'] = "ERROR"

            record['fvde_status'] = "NA"

        # PROVIDE OUTPUT LINE, AND WRITE TO OUTFILE
        line = record.values()
        output.write_entry(line)

        # ------------- END MODULE-SPECIFIC LOGIC ------------- #
