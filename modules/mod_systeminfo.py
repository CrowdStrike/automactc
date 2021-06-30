"""A module intended gather basic system information that can be used
to identify the host.
"""

# MODULE-SPECIFIC IMPORTS, UPDATE AS NEEDED
import logging
import os
import plistlib
import subprocess
import sys
from collections import OrderedDict

# KEEP THIS - IMPORT STATIC VARIABLES FROM MAIN
from __main__ import (OSVersion, archive, data_writer, forensic_mode,
                      full_prefix, inputdir, inputsysdir, outputdir, quiet,
                      serial, startTime)

# KEEP THIS - IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from .common.functions import finditem, read_bplist, stats2

# KEEP THESE - DEFINES MODULE NAME AND VERSION (BASED ON MODULE FILENAME) AND ESTABLISHES LOGGING.
_modName = __name__.split('_')[-1]
_modVers = '1.0.4'
log = logging.getLogger(_modName)

# PUT YOUR OUTPUT HEADERS HERE. USE THESE HEADERS AS THE VARIABLE NAMES
# IN YOUR CODE LOGIC, AND PUT THEM IN THE ORDER (IN THE LIST BELOW)
# THAT YOU WANT THEM TO APPEAR
# IN THE OUTPUT.

_headers = ['local_hostname', 'computer_name', 'hostname', 'model',
            'product_version', 'product_build_version', 'serial_no', 'volume_created',
            'system_tz', 'amtc_runtime', 'ipaddress', 'fvde_status', 'gatekeeper_status',
            'sip_status']


def module():
    # KEEP THIS - ENABLES WRITING OUTPUT FILE.
    _output = data_writer(_modName, _headers)

    # -------------BEGIN MODULE-SPECIFIC LOGIC------------- #
    try:
        globalpreferences = read_bplist(os.path.join(inputdir, 'Library/Preferences/.GlobalPreferences.plist'))
    except FileNotFoundError:
        globalpreferences = read_bplist(os.path.join(inputsysdir, 'Library/Preferences/.GlobalPreferences.plist'))
    if sys.version_info[0] < 3:
        try:
            preferences = plistlib.readPlist(os.path.join(inputdir, 'Library/Preferences/SystemConfiguration/preferences.plist'))
        except FileNotFoundError:
            preferences = plistlib.readPlist(os.path.join(inputsysdir, 'Library/Preferences/SystemConfiguration/preferences.plist'))
    else:
        try:
            with open(os.path.join(inputdir, 'Library/Preferences/SystemConfiguration/preferences.plist'), 'rb') as fp:
                preferences = plistlib.load(fp)
        except FileNotFoundError:
            with open(os.path.join(inputsysdir, 'Library/Preferences/SystemConfiguration/preferences.plist'), 'rb') as fp:
                preferences = plistlib.load(fp)
    if sys.version_info[0] < 3:
        try:
            systemversion = plistlib.readPlist(os.path.join(inputdir, 'System/Library/CoreServices/SystemVersion.plist'))
        except FileNotFoundError:
            systemversion = plistlib.readPlist(os.path.join(inputsysdir, 'System/Library/CoreServices/SystemVersion.plist'))
    else:
        try:
            with open(os.path.join(inputdir, 'System/Library/CoreServices/SystemVersion.plist'), 'rb') as fp:
                systemversion = plistlib.load(fp)
        except FileNotFoundError:
            with open(os.path.join(inputsysdir, 'System/Library/CoreServices/SystemVersion.plist'), 'rb') as fp:
                systemversion = plistlib.load(fp)

    # KEEP THE LINE BELOW TO GENERATE AN ORDEREDDICT BASED ON THE HEADERS
    record = OrderedDict((h, '') for h in _headers)

    record['local_hostname'] = finditem(preferences, 'LocalHostName')
    record['ipaddress'] = full_prefix.split(',')[2]

    computer_name = finditem(preferences, 'ComputerName')
    if computer_name is not None:
        try:
            record['computer_name'] = computer_name.encode('utf-8').decode()
        except UnicodeDecodeError:
            record['computer_name'] = computer_name.encode('utf-8')
    record['hostname'] = finditem(preferences, 'HostName')
    record['model'] = finditem(preferences, 'Model')
    record['product_version'] = OSVersion
    record['product_build_version'] = finditem(systemversion, 'ProductBuildVersion')
    record['serial_no'] = serial
    record['volume_created'] = stats2(inputdir + "/", oMACB=True)['btime']
    record['amtc_runtime'] = str(startTime).replace(' ', 'T').replace('+00:00', 'Z')

    if 'Volumes' not in inputdir and forensic_mode is not True:

        tz, e = subprocess.Popen(["systemsetup", "-gettimezone"], stdout=subprocess.PIPE).communicate()
        record['system_tz'] = tz.decode().rstrip().replace('Time Zone: ', '')

        _fdestatus, e = subprocess.Popen(["fdesetup", "status"], stdout=subprocess.PIPE).communicate()
        if 'On' in _fdestatus.decode():
            record['fvde_status'] = "On"
        else:
            record['fvde_status'] = "Off"

        gatekeeper = subprocess.Popen(["spctl", "--status"], stdout=subprocess.PIPE).communicate()
        record['gatekeeper_status'] = gatekeeper[0].decode()

        sip = subprocess.Popen(["csrutil", "status"], stdout=subprocess.PIPE).communicate()
        record['sip_status'] = sip[0][36:].decode()

    else:
        try:
            record['system_tz'] = globalpreferences[0]['com.apple.TimeZonePref.Last_Selected_City'][3]
        except Exception:
            try:
                record['system_tz'] = os.readlink(os.path.join(inputdir, 'etc/localtime'))[26:]
            except Exception:
                log.error("Could not get system timezone")
                record['system_tz'] = "ERROR"

        record['fvde_status'] = "NA"
        record['gatekeeper_status'] = "NA"
        record['sip_status'] = "NA"

    # PROVIDE OUTPUT LINE, AND WRITE TO OUTFILE
    _output.write_record(record)
    _output.flush_record()
    # ------------- END MODULE-SPECIFIC LOGIC ------------- #


# KEEP THIS - ESTABLISHES THAT THIS SCRIPT CAN'T BE RUN WITHOUT THE FRAMEWORK.
if __name__ == "__main__":
    print("This is an AutoMacTC module, and is not meant to be run stand-alone.")
    print("Exiting.")
    sys.exit(0)
else:
    module()
