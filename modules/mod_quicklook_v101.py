#!/usr/bin/env python

'''
@ author: Kshitij Kumar
@ email: kshitijkumar14@gmail.com, kshitij.kumar@crowdstrike.com

@ purpose:

A module intended to parse the Quicklooks database for each user. 

'''

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from common.functions import stats2
from common.functions import cocoa_time
from common.functions import read_stream_bplist
from common.functions import query_db

# IMPORT STATIC VARIABLES FROM MAIN
from __main__ import inputdir
from __main__ import outputdir
from __main__ import forensic_mode
from __main__ import no_tarball
from __main__ import quiet

from __main__ import archive
from __main__ import startTime
from __main__ import full_prefix
from __main__ import OSVersion
from __main__ import data_writer


import plistlib
import sqlite3
import traceback
import csv
import os
import glob
import logging
import shutil
from collections import OrderedDict
import time

_modName = __name__.split('_')[-2]
_modVers = '.'.join(list(__name__.split('_')[-1][1:]))
log = logging.getLogger(_modName)


def module():
    headers = ['uid', 'path', 'name', 'last_hit_date', 'hit_count',
               'file_last_modified', 'generator', 'file_size']
    output = data_writer(_modName, headers)

    q_loc = os.path.join(inputdir, 'private/var/folders/*/*/C/com.apple.QuickLook.thumbnailcache/index.sqlite')
    qlist = glob.glob(q_loc)

    if OSVersion is not None:
        ver = float('.'.join(OSVersion.split('.')[1:]))
        if ver > 14.0 and ver is not None and forensic_mode is not True:
            log.error("Artifacts are inaccessible on and above OS version 10.14 on live systems.")
            return
    else:
        if forensic_mode is not True:
            log.debug("OSVersion not detected, but going to try to parse anyway.")
        else:
            log.error("OSVersion not detected, so will not risk parsing as artifacts are inaccessible on and above OS version 10.14 on live systems.")
            return


    if len(qlist) == 0:
        log.debug("Files not found in: {0}".format(q_loc))

    ql_sql = 'SELECT distinct k.folder, k.file_name, t.hit_count, t.last_hit_date, k.version \
              FROM (SELECT rowid AS f_rowid,folder,file_name,version FROM files) k \
              LEFT JOIN thumbnails t ON t.file_id = k.f_rowid ORDER BY t.hit_count DESC'

    for qfile in qlist:

        uid = stats2(qfile)['uid']
        
        data = query_db(qfile, ql_sql, outputdir)

        for item in data:
            item = list(item)
            record = OrderedDict((h, '') for h in headers)
            record['uid'] = uid
            record['path'] = item[0].encode('utf-8')
            record['name'] = item[1].encode('utf-8')

            if item[3]:
                record['last_hit_date'] = cocoa_time(item[3])
            else:
                record['last_hit_date'] = ''

            if item[2]:
                record['hit_count'] = item[2]
            else:
                record['hit_count'] = ''

            try:
                plist_array = read_stream_bplist(item[4])
                record['file_last_modified'] = cocoa_time(plist_array['date'])
                record['generator'] = plist_array['gen']
                try:
                    record['file_size'] = int(plist_array['size'])
                except KeyError:
                    record['file_size'] = 'Error'
            except Exception, e:
                log.error("Could not parse: embedded binary plist for record {0}".format(record['name']))

            output.write_entry(record.values())


if __name__ == "__main__":
    print "This is an AutoMacTC module, and is not meant to be run stand-alone."
    print "Exiting."
    sys.exit(0)
else:
    module()
