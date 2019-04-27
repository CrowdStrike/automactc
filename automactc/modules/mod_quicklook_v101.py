#!/usr/bin/env python

'''
@ author: Kshitij Kumar
@ email: kshitijkumar14@gmail.com, kshitij.kumar@crowdstrike.com

@ purpose:

A module intended to parse the Quicklooks database for each user.

'''
import os
import glob
from collections import OrderedDict

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from automactc.modules.common.base import AutoMacTCModule
from automactc.modules.common.functions import stats2
from automactc.modules.common.functions import cocoa_time
from automactc.modules.common.functions import read_stream_bplist
from automactc.modules.common.functions import query_db
from automactc.utils.output import DataWriter


class QuickLookModule(AutoMacTCModule):
    _mod_filename = __name__

    _headers = [
        'uid', 'path', 'name', 'last_hit_date', 'hit_count',
        'file_last_modified', 'generator', 'file_size'
    ]

    def run(self):
        output = DataWriter(self.module_name(), self._headers, self.log, self.run_id, self.options)

        q_loc = os.path.join(self.options.inputdir, 'private/var/folders/*/*/C/com.apple.QuickLook.thumbnailcache/index.sqlite')
        qlist = glob.glob(q_loc)

        if self.options.os_version is not None:
            ver = float('.'.join(self.options.os_version.split('.')[1:]))
            if ver > 14.0 and ver is not None and self.options.forensic_mode is not True:
                self.log.error("Artifacts are inaccessible on and above OS version 10.14 on live systems.")
                return
        else:
            if self.options.forensic_mode is not True:
                self.log.debug("OSVersion not detected, but going to try to parse anyway.")
            else:
                self.log.error("OSVersion not detected, so will not risk parsing as artifacts are inaccessible on and above OS version 10.14 on live systems.")
                return


        if len(qlist) == 0:
            self.log.debug("Files not found in: {0}".format(q_loc))

        ql_sql = 'SELECT distinct k.folder, k.file_name, t.hit_count, t.last_hit_date, k.version \
                  FROM (SELECT rowid AS f_rowid,folder,file_name,version FROM files) k \
                  LEFT JOIN thumbnails t ON t.file_id = k.f_rowid ORDER BY t.hit_count DESC'

        for qfile in qlist:

            uid = stats2(qfile)['uid']

            data = query_db(qfile, ql_sql, self.options.outputdir)

            for item in data:
                item = list(item)
                record = OrderedDict((h, '') for h in self._headers)
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
                except Exception:
                    self.log.error("Could not parse: embedded binary plist for record {0}".format(record['name']))

                output.write_entry(record.values())
