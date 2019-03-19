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

# KEEP THIS - IMPORT STATIC VARIABLES FROM MAIN
from __main__ import inputdir
from __main__ import outputdir
from __main__ import forensic_mode
from __main__ import quiet

from __main__ import archive
from __main__ import startTime
from __main__ import runID
from __main__ import full_prefix
from __main__ import OSVersion
from __main__ import data_writer

# MODULE-SPECIFIC IMPORTS, UPDATE AS NEEDED
import os
import shutil
import logging
from distutils.dir_util import copy_tree

_modName = __name__.split('_')[-2]
_modVers = '.'.join(list(__name__.split('_')[-1][1:]))
log = logging.getLogger(_modName)


def getLogArchive():

    persist = os.path.join(inputdir,'/private/var/db/diagnostics/Persist')
    persistent = os.path.join(inputdir,'private/var/db/diagnostics/Persistent')
    
    if os.path.exists(persist) or os.path.exists(persistent):
        tracev3_diaginputdir = os.path.join(inputdir,'private/var/db/diagnostics/')
    else:
        tracev3_diaginputdir = None
        log.error("Did not find .tracev3 files to parse.")

    if tracev3_diaginputdir:
        tracev3_uuidinputdir = os.path.join(inputdir,'private/var/db/uuidtext/')

        odirectory = os.path.join(outputdir,"tracev3tmp"+runID)
        if not os.path.exists(odirectory):
            os.makedirs(odirectory)

        copy_tree(tracev3_diaginputdir, odirectory)
        log.debug("Copying Persistent data to tmpdir.")
        copy_tree(tracev3_uuidinputdir, odirectory)
        log.debug("Copying UUIDText data to tmpdir.")

        logarchive_name = os.path.join(outputdir,full_prefix+',unifiedlog'+runID+'.logarchive')
        shutil.move(odirectory, logarchive_name)
        log.debug("Renamed tmpdir to logarchive.")


if __name__ == "__main__":
    print "This is an AutoMacTC module, and is not meant to be run stand-alone."
    print "Exiting."
    sys.exit(0)
else:
    getLogArchive()

