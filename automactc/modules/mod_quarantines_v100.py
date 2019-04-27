#!/usr/bin/env python

'''
@ author: Kshitij Kumar
@ email: kshitijkumar14@gmail.com, kshitij.kumar@crowdstrike.com

@ purpose:

A module intended to parse the QuarantineEventsV2 database.

'''
import os
import glob
from collections import OrderedDict

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from automactc.modules.common.base import AutoMacTCModule
from automactc.modules.common.functions import cocoa_time
from automactc.modules.common.functions import query_db
from automactc.utils.output import DataWriter


class QuarantinesModule(AutoMacTCModule):
    _mod_filename = __name__

    _headers = [
        'user', 'timestamp', 'bundle_id', 'quarantine_agent', 'download_url', 'sender_name',
        'sender_address', 'typeno', 'origin_title', 'origin_title', 'origin_url', 'origin_alias'
    ]

    def run(self):
        output = DataWriter(self.module_name(), self._headers, self.log, self.run_id, self.options)

        qevents_loc = os.path.join(self.options.inputdir, 'Users/*/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2')
        qevents_list = glob.glob(qevents_loc)
        qry = 'SELECT * FROM LSQuarantineEvent'

        if len(qevents_list) == 0:
            self.log.debug("Files not found in: {0}".format(qevents_loc))

        for i in qevents_list:
            data = query_db(i, qry, self.options.outputdir)

            userpath = i.split('/')
            userindex = userpath.index('Users') + 1
            user = userpath[userindex]

            for item in data:
                item = list(item)
                record = OrderedDict((h, '') for h in self._headers)
                record['user'] = user
                record['timestamp'] = cocoa_time(item[1])
                record['bundle_id'] = item[2]
                record['quarantine_agent'] = item[3]
                record['download_url'] = item[4]
                record['sender_name'] = item[5]
                record['sender_address'] = item[6]
                record['typeno'] = str(item[7])
                record['origin_title'] = item[8]
                record['origin_url'] = item[9]
                record['origin_alias'] = item[10]

                line = [x.encode('utf-8') if isinstance(x, unicode) else x for x in record.values()]
                output.write_entry(line)
