#!/usr/bin/env python

'''
@ author: Kshitij Kumar
@ email: kshitijkumar14@gmail.com, kshitij.kumar@crowdstrike.com

@ purpose:

A module intended gather basic system information that can be used
to identify the host.

'''

# KEEP THIS - IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from common.functions import stats2
from common.functions import finditem
from common.functions import read_bplist

# KEEP THIS - IMPORT STATIC VARIABLES FROM MAIN
from __main__ import inputdir
from __main__ import outputdir
from __main__ import forensic_mode
from __main__ import quiet

from __main__ import archive
from __main__ import startTime
from __main__ import full_prefix
from __main__ import OSVersion
from __main__ import data_writer

# MODULE-SPECIFIC IMPORTS, UPDATE AS NEEDED
import plistlib
import sqlite3
import csv
import subprocess
import logging
import glob
import os
import traceback
from collections import OrderedDict

# KEEP THESE - DEFINES MODULE NAME AND VERSION (BASED ON MODULE FILENAME) AND ESTABLISHES LOGGING.
_modName = __name__.split('_')[-2]
_modVers = '.'.join(list(__name__.split('_')[-1][1:]))
log = logging.getLogger(_modName)

# PUT YOUR OUTPUT HEADERS HERE. USE THESE HEADERS AS THE VARIABLE NAMES 
# IN YOUR CODE LOGIC, AND PUT THEM IN THE ORDER (IN THE LIST BELOW) 
# THAT YOU WANT THEM TO APPEAR 
# IN THE OUTPUT.

_headers = ['local_hostname', 'computer_name', 'hostname', 'model',
            'product_version', 'product_build_version', 'serial_no', 'volume_created',
            'system_tz', 'amtc_runtime', 'ipaddress', 'fvde_status']


def module():
    # KEEP THIS - ENABLES WRITING OUTPUT FILE.
    _output = data_writer(_modName, _headers)

    # -------------BEGIN MODULE-SPECIFIC LOGIC------------- #
    globalpreferences = read_bplist(os.path.join(inputdir, 'Library/Preferences/.GlobalPreferences.plist'))
    preferences = plistlib.readPlist(os.path.join(inputdir, 'Library/Preferences/SystemConfiguration/preferences.plist'))
    systemversion = plistlib.readPlist(os.path.join(inputdir, 'System/Library/CoreServices/SystemVersion.plist'))

    # KEEP THE LINE BELOW TO GENERATE AN ORDEREDDICT BASED ON THE HEADERS
    record = OrderedDict((h, '') for h in _headers)

    record['local_hostname'] = finditem(preferences, 'LocalHostName')
    record['ipaddress'] = full_prefix.split(',')[2]

    computer_name = finditem(preferences, 'ComputerName')
    if computer_name is not None:
        record['computer_name'] = computer_name.encode('utf-8')
    record['hostname'] = finditem(preferences, 'HostName')
    record['model'] = finditem(preferences, 'Model')
    record['product_version'] = OSVersion
    record['product_build_version'] = finditem(systemversion, 'ProductBuildVersion')

    g = glob.glob(os.path.join(inputdir, 'private/var/folders/zz/zyxvpxvq6csfxvn_n00000sm00006d/C/*'))
    check_dbs = ['consolidated.db', 'cache_encryptedA.db', 'lockCache_encryptedA.db']
    serial_dbs = [loc for loc in g if any(loc.endswith(db) for db in check_dbs)]
    serial_query = 'SELECT SerialNumber FROM TableInfo;'

    for db in serial_dbs:
        try:
            cursor = sqlite3.connect(db).cursor()
            record['serial_no'] = cursor.execute(serial_query).fetchone()[0]
            break

        except Exception, e:
            record['serial_no'] = 'ERROR'

    record['volume_created'] = stats2(inputdir + "/", oMACB=True)['btime']
    record['amtc_runtime'] = str(startTime).replace(' ', 'T').replace('+00:00', 'Z')

    if 'Volumes' not in inputdir and forensic_mode is not True:

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
        except Exception, e:
            log.error("Could not get system timezone: {0}".format([traceback.format_exc()]))
            record['system_tz'] = "ERROR"

        record['fvde_status'] = "NA"

    # PROVIDE OUTPUT LINE, AND WRITE TO OUTFILE
    line = record.values()
    _output.write_entry(line)

    # ------------- END MODULE-SPECIFIC LOGIC ------------- #


# KEEP THIS - ESTABLISHES THAT THIS SCRIPT CAN'T BE RUN WITHOUT THE FRAMEWORK.
if __name__ == "__main__":
    print "This is an AutoMacTC module, and is not meant to be run stand-alone."
    print "Exiting."
    sys.exit(0)
else:
    module()
