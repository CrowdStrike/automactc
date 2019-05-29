#!/usr/bin/env python

'''
@ author: Kshitij Kumar
@ email: kshitijkumar14@gmail.com, kshitij.kumar@crowdstrike.com

@ purpose:

A module intended to parse the com.apple.spotlight.Shortcuts plist file,
which contains a record of every application opened with Spotlight, as
well as the timestamp that it was last opened.

'''

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from common.functions import stats2

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

import os
import csv
import plistlib
import logging
import glob

_modName = __name__.split('_')[-2]
_modVers = '.'.join(list(__name__.split('_')[-1][1:]))
log = logging.getLogger(_modName)


def module():
    headers = ['user', 'shortcut', 'display_name', 'last_used', 'url']
    output = data_writer(_modName, headers)

    user_inputdir = glob.glob(os.path.join(inputdir, "Users/*"))
    user_inputdir += glob.glob(os.path.join(inputdir, "var/*"))

    spotlight_path = 'Library/Application Support/com.apple.spotlight.Shortcuts'
    
    for user_home in user_inputdir:
        sl_path = os.path.join(user_home, spotlight_path)
        u_spotlight = glob.glob(sl_path)
        if len(u_spotlight) == 0:
            log.debug("File not found: {0}".format(sl_path))

        for file in u_spotlight:
            try:
                spotlight_data = plistlib.readPlist(file)
                for k, v in spotlight_data.items():
                    user = os.path.basename(user_home)
                    log.debug("Going to parse Spotlight shortcuts under {0} user.".format(user))
                    shortcut = k
                    display_name = spotlight_data[k]['DISPLAY_NAME']
                    last_used = spotlight_data[k]['LAST_USED'].isoformat() + "Z"
                    url = spotlight_data[k]['URL']

                    line_raw = [user, shortcut, display_name, last_used, url]
                    line = [x.encode('utf-8') for x in line_raw]

                    output.write_entry(line)

            except Exception, e:
                log.error("Could not parse: {0}".format(file))


if __name__ == "__main__":
    print "This is an AutoMacTC module, and is not meant to be run stand-alone."
    print "Exiting."
    sys.exit(0)
else:
    module()
