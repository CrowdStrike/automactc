"""A module intended to parse the Quicklooks database for each user.
"""

import glob
import io
import logging
import os
import sys
import traceback
from collections import OrderedDict

# IMPORT STATIC VARIABLES FROM MAIN
from __main__ import (OSVersion, archive, data_writer, forensic_mode,
                      full_prefix, inputdir, no_tarball, outputdir, quiet,
                      startTime)

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from .common import ccl_bplist as bplist
from .common.functions import cocoa_time, query_db, read_stream_bplist, stats2

_modName = __name__.split('_')[-1]
_modVers = '1.0.2'
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
            record['path'] = item[0]
            record['name'] = item[1]

            if item[3]:
                record['last_hit_date'] = cocoa_time(item[3])
            else:
                record['last_hit_date'] = ''

            if item[2]:
                record['hit_count'] = item[2]
            else:
                record['hit_count'] = ''

            try:
                try:
                    plist_array = read_stream_bplist(item[4])
                except Exception:
                    plist_array = bplist.load(io.BytesIO(item[4]))
                record['file_last_modified'] = cocoa_time(plist_array['date'])
                record['generator'] = plist_array['gen']
                try:
                    record['file_size'] = int(plist_array['size'])
                except KeyError:
                    record['file_size'] = 'Error'
            except Exception:
                log.error("Could not parse: embedded binary plist for record {0}".format(record['name']))

            output.write_record(record)
    output.flush_record()

if __name__ == "__main__":
    print("This is an AutoMacTC module, and is not meant to be run stand-alone.")
    print("Exiting.")
    sys.exit(0)
else:
    module()
