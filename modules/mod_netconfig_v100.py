#!/usr/bin/env python

'''

@ purpose:

A module intended parse network config plists

'''

# KEEP THIS - IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from .common.functions import finditem

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
import os
import logging
from collections import OrderedDict

_modName = __name__.split('_')[-2]
_modVers = '.'.join(list(__name__.split('_')[-1][1:]))
log = logging.getLogger(_modName)

 
def module():
    _headers = ['type', 'name', 'last_connected', 'security', 'hotspot']
    _output = data_writer(_modName, _headers)

    airport = plistlib.readPlist(os.path.join(inputdir, 'Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist'))
    interface = plistlib.readPlist(os.path.join(inputdir, 'Library/Preferences/SystemConfiguration/NetworkInterfaces.plist'))
    
    # KEEP THE LINE BELOW TO GENERATE AN ORDEREDDICT BASED ON THE HEADERS
    record = OrderedDict((h, '') for h in _headers)


    for i in airport['KnownNetworks']:
    	record['type'] = "Airport"
    	record['name'] = finditem(airport['KnownNetworks'][i], 'SSIDString')
    	record['last_connected'] = finditem(airport['KnownNetworks'][i], 'LastConnected')
    	record['security'] = finditem(airport['KnownNetworks'][i], 'SecurityType')
    	record['hotspot'] = finditem(airport['KnownNetworks'][i], 'PersonalHotspot')

    	line = record.values()
    	_output.write_entry(line)

    for i in interface['Interfaces']:
        record['type'] = finditem(i, 'BSD Name')
        record['name'] = finditem(i['SCNetworkInterfaceInfo'], 'UserDefinedName')
        record['last_connected'] = ''
        record['security'] = ''
        record['hotspot'] = ''

        line = record.values()
        _output.write_entry(line)


if __name__ == "__main__":
    print("This is an AutoMacTC module, and is not meant to be run stand-alone.")
    print("Exiting.")
    sys.exit(0)
else:
    module()