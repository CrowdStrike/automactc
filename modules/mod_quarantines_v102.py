#!/usr/bin/env python

'''
@ author: Kshitij Kumar
@ email: kshitijkumar14@gmail.com, kshitij.kumar@crowdstrike.com

@ purpose:

A module intended to parse the QuarantineEventsV2 database.

'''

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from common.functions import cocoa_time
from common.functions import query_db
from common.functions import multiglob

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


import sqlite3
import csv
import os
import glob
import logging
from collections import OrderedDict

_modName = __name__.split('_')[-2]
_modVers = '.'.join(list(__name__.split('_')[-1][1:]))
log = logging.getLogger(_modName)


def module():
    headers = ['user', 'timestamp', 'bundle_id', 'quarantine_agent', 'download_url', 'sender_name',
               'sender_address', 'typeno', 'origin_title', 'origin_title', 'origin_url', 'origin_alias']
    output = data_writer(_modName, headers)

    qevents_list = multiglob(inputdir, ['Users/*/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2', 
                                        'private/var/*/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2'])
    qry = 'SELECT * FROM LSQuarantineEvent'

    if len(qevents_list) == 0:
        log.debug("Files not found in: {0}".format(qevents_loc))

    for i in qevents_list:
        data = query_db(i, qry, outputdir)

        userpath = i.split('/')
        if 'Users' in userpath:
            userindex = len(userpath) - 1 - userpath[::-1].index('Users') + 1
        else:
            userindex = len(userpath) - 1 - userpath[::-1].index('var') + 1
        user = userpath[userindex]

        for item in data:
            item = list(item)
            record = OrderedDict((h, '') for h in headers)
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


if __name__ == "__main__":
    print "This is an AutoMacTC module, and is not meant to be run stand-alone."
    print "Exiting."
    sys.exit(0)
else:
    module()
