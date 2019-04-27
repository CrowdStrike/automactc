#!/usr/bin/env python

'''
@ author: Kshitij Kumar
@ email: kshitijkumar14@gmail.com, kshitij.kumar@crowdstrike.com

@ purpose:

A module intended to read and parse the Safari history database and
Downloads.plist for each user on disk.

'''
import os
import glob
import shutil
import sqlite3
import traceback
from collections import OrderedDict
import dateutil.parser as parser

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from automactc.modules.common.base import AutoMacTCModule
from automactc.modules.common.functions import read_bplist
from automactc.modules.common.functions import cocoa_time
from automactc.utils.output import DataWriter


class SafariModule(AutoMacTCModule):
    _mod_filename = __name__

    _headers = [
        'uid', 'path', 'name', 'last_hit_date', 'hit_count',
        'file_last_modified', 'generator', 'file_size'
    ]

    @classmethod
    def _get_column_headers(cls, db, column):
        col_headers = sqlite3.connect(db).cursor().execute('SELECT * from {0}'.format(column))
        names = list(map(lambda x: x[0], col_headers.description))
        return names

    def _connect_to_db(self, db_location, main_table):
        try:
            self.log.debug("Trying to connect to {0} directly...".format(db_location))
            history_db = db_location
            test = self._get_column_headers(history_db, main_table)
            self.log.debug("Successfully connected.")
        except sqlite3.OperationalError:
            error = [x for x in traceback.format_exc().split('\n') if x.startswith("OperationalError")]
            self.log.debug("Could not connect [{0}].".format(error[0]))

            if "database is locked" in error[0]:
                tmpdb = os.path.basename(db_location)+'-tmp'
                self.log.debug("Trying to connect to db copied to temp location...")

                shutil.copyfile(history_db, os.path.join(self.options.outputdir, tmpdb))
                history_db = os.path.join(self.options.outputdir, tmpdb)
                try:
                    test = self._self._get_column_headers(history_db, main_table)
                    self.log.debug("Successfully connected.")
                except sqlite3.OperationalError:
                    error = [x for x in traceback.format_exc().split('\n') if x.startswith("OperationalError")]
                    self.log.debug("Could not connect [{0}].".format(error[0]))

                    if "no such table" in error[0]:
                        self.log.error("Module fatal error: necessary table doesn't exist in database | {0}".format([traceback.format_exc()]))
                        history_db = None
            elif "no such table" in error[0]:
                self.log.error("Module fatal error: necessary table doesn't exist in database | {0}".format([traceback.format_exc()]))
                history_db = None

            else:
                self.log.error("Module fatal error: cannot parse database | {0}".format([traceback.format_exc()]))
                history_db = None

        return history_db


    def _pull_download_history(self, downloads_plist, user, downloads_output, downloads_headers):

        self.log.debug("Trying to access Downloads.plist...")

        if not os.path.exists(downloads_plist):
            self.log.debug("File not found: {0}".format(downloads_plist))
            return

        try:
            downloads = read_bplist(downloads_plist)[0]['DownloadHistory']
            self.log.debug("Success. Found {0} lines of data.".format(len(downloads)))
        except IOError:
            self.log.error("File not found: {0}".format(downloads_plist))
            downloads = []

        self.log.debug("Parsing and writing downloads data...")
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

        self.log.debug("Done.")


    def _pull_visit_history(self, recently_closed_plist, history_db, user, history_output, history_headers):

        try:
            self.log.debug("Trying to access RecentlyClosedTabs.plist...")
            recently_closed = read_bplist(recently_closed_plist)[0]['ClosedTabOrWindowPersistentStates']
            d = {}
            self.log.debug("Success. Found {0} lines of data.".format(len(recently_closed)))
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
            self.log.debug("File not found: {0}".format(recently_closed_plist))
            d = {}
            pass


        desired_columns = ['visit_time', 'title', 'url', 'visit_count']
        available_columns = self._get_column_headers(history_db,'history_visits') + self._get_column_headers(history_db,'history_items')
        query_columns_list = [i for i in desired_columns if i in available_columns]
        query_columns = ', '.join([i for i in desired_columns if i in available_columns])

        unavailable = ','.join(list(set(desired_columns) - set(query_columns_list)))
        if len(unavailable) > 0:
            self.log.debug('The following desired columns are not available in the database: {0}'.format(unavailable))

        self.log.debug("Executing sqlite query for visit history...")

        try:
            history_data = sqlite3.connect(history_db).cursor().execute(

                'SELECT {0} from history_visits \
                left join history_items on history_items.id = history_visits.history_item'.format(query_columns)

                ).fetchall()

            self.log.debug("Success. Found {0} lines of data.".format(len(history_data)))

        except sqlite3.OperationalError:
            error = [x for x in traceback.format_exc().split('\n') if x.startswith("OperationalError")]
            self.log.error('Failed to run query. [{0}]'.format(error[0]))

            return

        self.log.debug("Parsing and writing visits data...")

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

    def run(self):
        safari_location = glob.glob(os.path.join(self.options.inputdir, 'Users/*/Library/Safari/'))

        if self.options.os_version is not None:
            ver = float('.'.join(self.options.os_version.split('.')[1:]))
            if ver > 14.0 and self.options.forensic_mode is not True:
                self.log.error("Artifacts are inaccessible on and above OS version 10.14 on live systems.")
                return
        else:
            if self.options.forensic_mode is not True:
                self.log.debug("OSVersion not detected, but going to try to parse anyway.")
            else:
                self.log.error("OSVersion not detected, so will not risk parsing as artifacts are inaccessible on and above OS version 10.14 on live systems.")
                return

        history_headers = ['user','visit_time','title','url','visit_count','last_visit_time','recently_closed','tab_title','date_closed']
        history_output = DataWriter('browser_safari_history', history_headers, self.log, self.run_id, self.options)

        downloads_headers = ['user','download_url','download_path','download_started','download_finished','download_totalbytes','download_bytes_received']
        downloads_output = DataWriter('browser_safari_downloads', history_headers, self.log, self.run_id, self.options)

        for c in safari_location:
            userpath = c.split('/')
            userindex = len(userpath) - 1 - userpath[::-1].index('Users') + 1
            user = userpath[userindex]

            self.log.debug("Starting parsing for Safari under {0} user.".format(user))

            history_db = self._connect_to_db(os.path.join(c, 'History.db'),'history_visits')
            recently_closed_plist = os.path.join(c, 'RecentlyClosedTabs.plist')
            if history_db:
                self._pull_visit_history(recently_closed_plist, history_db, user, history_output, history_headers)

            downloads_plist = os.path.join(c, 'Downloads.plist')
            self._pull_download_history(downloads_plist, user, downloads_output, downloads_headers)

            try:
                os.remove(os.path.join(self.options.outputdir, 'History.db-tmp'))
                os.remove(os.path.join(self.options.outputdir, 'History.db-tmp-shm'))
                os.remove(os.path.join(self.options.outputdir, 'History.db-tmp-wal'))
            except OSError:
                pass
