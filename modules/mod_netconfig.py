"""A module intended parse network config plists
"""

import logging
import os
import plistlib
import re
import sys
from collections import OrderedDict

# IMPORT STATIC VARIABLES FROM MAIN
from __main__ import (OSVersion, archive, data_writer, forensic_mode,
                      full_prefix, inputdir, outputdir, quiet, startTime)

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from .common.functions import finditem

_modName = __name__.split('_')[-1]
_modVers = '1.0.1'
log = logging.getLogger(_modName)


def module():
    _headers = ['type', 'name', 'last_connected', 'security', 'hotspot']
    _output = data_writer(_modName, _headers)

    if sys.version_info[0] < 3:
        airport = plistlib.readPlist(os.path.join(inputdir, 'Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist'))
        interface = plistlib.readPlist(os.path.join(inputdir, 'Library/Preferences/SystemConfiguration/NetworkInterfaces.plist'))
    else:
        with open(os.path.join(inputdir, 'Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist'), 'rb') as fp:
            airport = plistlib.load(fp)
        with open(os.path.join(inputdir, 'Library/Preferences/SystemConfiguration/NetworkInterfaces.plist'), 'rb') as fp:
            interface = plistlib.load(fp)

    # KEEP THE LINE BELOW TO GENERATE AN ORDEREDDICT BASED ON THE HEADERS
    record = OrderedDict((h, '') for h in _headers)

    if 'KnownNetworks' in airport:
        for i in airport['KnownNetworks']:
            record['type'] = "Airport"
            record['name'] = finditem(airport['KnownNetworks'][i], 'SSIDString')
            record['last_connected'] = finditem(airport['KnownNetworks'][i], 'LastConnected')
            record['security'] = finditem(airport['KnownNetworks'][i], 'SecurityType')
            record['hotspot'] = finditem(airport['KnownNetworks'][i], 'PersonalHotspot')

            _output.write_record(record)
    else:
        log.debug("No KnownNetworks found")

    if 'Interfaces' in interface:
        for i in interface['Interfaces']:
            record['type'] = finditem(i, 'BSD Name')
            record['name'] = finditem(i['SCNetworkInterfaceInfo'], 'UserDefinedName')
            record['last_connected'] = ''
            record['security'] = ''
            record['hotspot'] = ''

            _output.write_record(record)
    else:
        log.debug("No Interfaces found")
    _output.flush_record()


if __name__ == "__main__":
    print("This is an AutoMacTC module, and is not meant to be run stand-alone.")
    print("Exiting.")
    sys.exit(0)
else:
    module()
