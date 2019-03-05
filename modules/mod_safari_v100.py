#!/usr/bin/env python

'''
@ author: Kshitij Kumar
@ email: kshitijkumar14@gmail.com, kshitij.kumar@crowdstrike.com

@ purpose:

A module intended to read and parse the Safari history database and 
Downloads.plist for each user on disk.

'''

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from common.functions import stats2
from common.functions import read_bplist
from common.functions import cocoa_time

# IMPORT STATIC VARIABLES FROM MACXTR
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

import os
import csv
import glob
import sqlite3
import logging
import traceback
import dateutil.parser as parser
from collections import OrderedDict


_modName = __name__.split('_')[-2]
_modVers = '.'.join(list(__name__.split('_')[-1][1:]))
log = logging.getLogger(_modName)


def get_column_headers(db, column):
    col_headers = sqlite3.connect(db).cursor().execute('SELECT * from {0}'.format(column))
    names = list(map(lambda x: x[0], col_headers.description))
    return names

def connect_to_db(db_location, main_table):
    try:
        log.debug("Trying to connect to {0} directly...".format(db_location))
        history_db = db_location
        test = get_column_headers(history_db, main_table)
        log.debug("Successfully connected.")
    except sqlite3.OperationalError:
        error = [x for x in traceback.format_exc().split('\n') if x.startswith("OperationalError")]
        log.debug("Could not connect [{0}].".format(error[0]))

        if "database is locked" in error[0]:
            tmpdb = os.path.basename(db_location)+'-tmp'
            log.debug("Trying to connect to db copied to temp location...")

            shutil.copyfile(history_db, os.path.join(outputdir, tmpdb))
            history_db = os.path.join(outputdir, tmpdb)
            try:
                test = get_column_headers(history_db, main_table)
                log.debug("Successfully connected.")
            except sqlite3.OperationalError:
                error = [x for x in traceback.format_exc().split('\n') if x.startswith("OperationalError")]
                log.debug("Could not connect [{0}].".format(error[0]))

                if "no such table" in error[0]:
                    log.error("Module fatal error: necessary table doesn't exist in database.")
                    history_db = None
        elif "no such table" in error[0]:
            log.error("Module fatal error: necessary table doesn't exist in database.")
            history_db = None

        else:
            log.error("Module fatal error: cannot parse database.")
            history_db = None

    return history_db


def pull_download_history(downloads_plist, user, downloads_output, downloads_headers):

    log.debug("Trying to access Downloads.plist...")

    if not os.path.exists(downloads_plist):
        log.debug("File not found: {0}".format(downloads_plist))
        return

    try:
        downloads = read_bplist(downloads_plist)[0]['DownloadHistory']
        log.debug("Success. Found {0} lines of data.".format(len(downloads)))
    except IOError:
        log.error("File not found: {0}".format(downloads_plist))
        downloads = []

    log.debug("Parsing and writing downloads data...")
    for i in downloads:
        for k,v in i.items():
            if k not in ['DownloadEntryPostBookmarkBlob','DownloadEntryBookmarkBlob']:
                record = OrderedDict((h, '') for h in downloads_headers)
                record['user'] = user
                record['download_url'] = i['DownloadEntryURL']
                record['download_path'] = i['DownloadEntryPath']
                record['download_started'] = str(i['DownloadEntryDateAddedKey'])
                record['download_finished'] = str(i['DownloadEntryDateFinishedKey'])
                record['download_totalbytes'] = int(i['DownloadEntryProgressTotalToLoad'])
                record['download_bytes_received'] = int(i['DownloadEntryProgressBytesSoFar'])

        downloads_output.write_entry(record.values())

    log.debug("Done.")


def pull_visit_history(recently_closed_plist, history_db, user, history_output, history_headers):

    try:
        log.debug("Trying to access RecentlyClosedTabs.plist...")
        recently_closed = read_bplist(recently_closed_plist)[0]['ClosedTabOrWindowPersistentStates']     
        d = {}
        log.debug("Success. Found {0} lines of data.".format(len(recently_closed)))
        for i in recently_closed:
            for k,v in i['PersistentState'].items():
                if k == 'TabURL':
                    tab_title = i['PersistentState']['TabTitle'].encode('utf-8')
                    date_closed = parser.parse(str(i['PersistentState']['DateClosed'])).replace(tzinfo=None).isoformat()+'Z'
                    try:
                        last_visit_time = i['PersistentState']['LastVisitTime']
                        last_visit_time = cocoa_time(last_visit_time)
                    except KeyError:
                        last_visit_time = ''
                    d[i['PersistentState']['TabURL']] = [tab_title,date_closed,last_visit_time]
    except IOError:
        log.debug("File not found: {0}".format(recently_closed_plist))
        d = {}
        pass


    desired_columns = ['visit_time', 'title', 'url', 'visit_count']
    available_columns = get_column_headers(history_db,'history_visits') + get_column_headers(history_db,'history_items')
    query_columns_list = [i for i in desired_columns if i in available_columns]
    query_columns = ', '.join([i for i in desired_columns if i in available_columns])

    unavailable = ','.join(list(set(desired_columns) - set(query_columns_list)))
    if len(unavailable) > 0:
        log.debug('The following desired columns are not available in the database: {0}'.format(unavailable))

    log.debug("Executing sqlite query for visit history...")
    
    try:
        history_data = sqlite3.connect(history_db).cursor().execute(

            'SELECT {0} from history_visits \
            left join history_items on history_items.id = history_visits.history_item'.format(query_columns)

            ).fetchall()

        log.debug("Success. Found {0} lines of data.".format(len(history_data)))

    except sqlite3.OperationalError:
        error = [x for x in traceback.format_exc().split('\n') if x.startswith("OperationalError")]
        log.error('Failed to run query. [{0}]'.format(error[0]))

        return

    log.debug("Parsing and writing visits data...")

    nondict = dict.fromkeys(desired_columns)
    for item in history_data:
        record = OrderedDict((h, '') for h in history_headers)
        item_dict = dict(zip(query_columns_list,item))
        nondict.update(item_dict)

        record['user'] = user
        record['visit_time'] = cocoa_time(nondict['visit_time'])
        if nondict['title'] is not None:
            record['title'] = nondict['title'].encode('utf-8')
        record['url'] = nondict['url']
        record['visit_count'] = nondict['visit_count']


        if nondict['url'] in d.keys():

            record['recently_closed'] = 'Yes'
            record['tab_title'] = d[nondict['url']][0]
            record['date_closed'] = d[nondict['url']][1]
            record['last_visit_time'] = d[nondict['url']][2]


        history_output.write_entry(record.values())


def module(safari_location):
    ver = float('.'.join(OSVersion.split('.')[1:]))
    
    if ver > 14.0 and forensic_mode is not True:
        log.error("Artifacts are inaccessible on and above OS version 10.14.")
        return

    history_headers = ['user','visit_time','title','url','visit_count','last_visit_time','recently_closed','tab_title','date_closed']
    history_output = data_writer('browser_safari_history',history_headers)

    downloads_headers = ['user','download_url','download_path','download_started','download_finished','download_totalbytes','download_bytes_received']
    downloads_output = data_writer('browser_safari_downloads',downloads_headers)

    for c in safari_location:
        userpath = c.split('/')
        userindex = userpath.index('Users') + 1
        user = userpath[userindex]

        log.debug("Starting parsing for Safari under {0} user.".format(user))

        history_db = connect_to_db(os.path.join(c, 'History.db'),'history_visits')
        recently_closed_plist = os.path.join(c, 'RecentlyClosedTabs.plist')
        if history_db:
            pull_visit_history(recently_closed_plist, history_db, user, history_output, history_headers)

        downloads_plist = os.path.join(c, 'Downloads.plist')
        pull_download_history(downloads_plist, user, downloads_output, downloads_headers)
    
        try:
            os.remove(os.path.join(outputdir, 'History.db-tmp'))
            os.remove(os.path.join(outputdir, 'History.db-tmp-shm'))
            os.remove(os.path.join(outputdir, 'History.db-tmp-wal'))
        except OSError:
            pass


if __name__ == "__main__":
    print "This is an AutoMacTC module, and is not meant to be run stand-alone."
    print "Exiting."
    sys.exit(0)
else:
    safari_location = glob.glob(
        os.path.join(inputdir, 'Users/*/Library/Safari/'))
    module(safari_location)