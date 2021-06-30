"""A module intended to parse the InstallHistory.plist file.
"""

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from .common.functions import stats2

# IMPORT STATIC VARIABLES FROM MAIN
from __main__ import inputdir
from __main__ import outputdir
from __main__ import forensic_mode
from __main__ import no_tarball
from __main__ import quiet

from __main__ import archive
from __main__ import startTime
from __main__ import full_prefix
from __main__ import data_writer

import plistlib
import logging
import os
import glob
import sys
from collections import OrderedDict

_modName = __name__.split('_')[-1]
_modVers = '1.0.2'
log = logging.getLogger(_modName)


def module():
    headers = ['src_name', 'timestamp', 'display_name', 'display_version',
               'package_identifiers', 'process_name']
    output = data_writer(_modName, headers)

    installhistory_loc = os.path.join(inputdir, 'Library/Receipts/InstallHistory.plist')
    installhistory_list = glob.glob(installhistory_loc)

    if len(installhistory_list) == 0:
        log.debug("File not found: {0}".format(installhistory_loc))

    for file in installhistory_list:
        installhistoryfile = open(file, 'rb')
        try:
            installhistory = plistlib.load(installhistoryfile)
        except AttributeError as e:
            log.debug(e)
            log.debug("Running python 2 code for this.")
            installhistory = plistlib.readPlist(installhistoryfile)

        for i in range(len(installhistory)):
            record = OrderedDict((h, '') for h in headers)
            record['src_name'] = os.path.basename(file)
            if 'date' in installhistory[i]:
                record['timestamp'] = installhistory[i]['date'].strftime('%Y-%m-%dT%H:%M:%SZ')
            else:
                record['timestamp'] = ""
            if 'displayVersion' in installhistory[i]:
                record['display_version'] = installhistory[i]['displayVersion']
            else:
                record['display_version'] = ""
            if 'displayName' in installhistory[i]:
                record['display_name'] = installhistory[i]['displayName']
            else:
                record['display_name'] = ""
            if 'packageIdentifiers' in installhistory[i]:
                record['package_identifiers'] = installhistory[i]['packageIdentifiers']
            else:
                record['package_idenfifiers'] = ""
            if 'processName' in installhistory[i]:
                record['process_name'] = installhistory[i]['processName']
            else:
                record['process_name'] = ""

            output.write_record(record)
    output.flush_record()


if __name__ == "__main__":
    print("This is an AutoMacTC module, and is not meant to be run stand-alone.")
    print("Exiting.")
    sys.exit(0)
else:
    module()
