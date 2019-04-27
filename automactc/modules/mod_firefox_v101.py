#!/usr/bin/env python

'''
@ author: Kshitij Kumar
@ email: kshitijkumar14@gmail.com, kshitij.kumar@crowdstrike.com

@ purpose:

A module intended to read and parse the Firefox history database for each
user on disk.

'''
import os
import glob
import sqlite3
import shutil
import traceback
from collections import OrderedDict
from ConfigParser import ConfigParser

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from automactc.modules.common.base import AutoMacTCModule
from automactc.modules.common.functions import firefox_time
from automactc.utils.output import DataWriter


class FirefoxModule(AutoMacTCModule):
    _mod_filename = __name__

    _downloads_headers = [
        'user', 'profile', 'download_url', 'download_path', 'download_started',
        'download_finished', 'download_totalbytes'
    ]

    _urls_headers = [
        'user', 'profile', 'visit_time', 'title', 'url',
        'visit_count', 'last_visit_time', 'typed', 'description'
    ]

    def __init__(self, *args, **kwargs):
        super(FirefoxModule, self).__init__(*args, **kwargs)
        self.firefox_location = glob.glob(
            os.path.join(self.options.inputdir, 'Users/*/Library/Application Support/Firefox/Profiles/*.*'))

        self._downloads_output = DataWriter('browser_firefox_downloads', self._downloads_headers, self.log, self.run_id, self.options)
        self._urls_output = DataWriter('browser_firefox_history', self._urls_headers, self.log, self.run_id, self.options)

    def _get_column_headers(self, conn, table):
        col_headers = conn.cursor().execute('SELECT * from {0}'.format(table))
        names = list(map(lambda x: x[0], col_headers.description))
        return names

    def _get_firefox_version(self, firefox_file):
        verfile = os.path.join(firefox_file, 'compatibility.ini')
        config = ConfigParser()
        config.read(verfile)
        ver = config.get('Compatibility','lastversion')
        self.log.debug("Firefox Version {0} identified.".format(ver))
        return ver

    def _connect_to_db(self, db_location, main_table):
        try:
            self.log.debug("Trying to connect to {0} directly...".format(db_location))
            history_db = db_location
            conn = sqlite3.connect(history_db)
            test = self._get_column_headers(conn, main_table)
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
                    conn = sqlite3.connect(history_db)
                    test = self._get_column_headers(history_db, main_table)
                    self.log.debug("Successfully connected.")
                except sqlite3.OperationalError:
                    error = [x for x in traceback.format_exc().split('\n') if x.startswith("OperationalError")]
                    self.log.debug("Could not connect [{0}].".format(error[0]))

                    if "no such table" in error[0]:
                        self.log.error("Module fatal error: necessary table doesn't exist in database.")
                        history_db = None
            elif "no such table" in error[0]:
                self.log.error("Module fatal error: necessary table doesn't exist in database.")
                history_db = None

            else:
                self.log.error("Module fatal error: cannot parse database.")
                history_db = None

        return history_db

    def _pull_download_history(self, conn, user, profile):
        desired_columns = ['url', 'content', 'dateAdded']
        available_columns = self._get_column_headers(conn, 'moz_annos') + self._get_column_headers(conn, 'moz_places')
        query_columns_list = [i for i in desired_columns if i in available_columns]
        query_columns = ', '.join([i for i in desired_columns if i in available_columns])

        unavailable = ','.join(list(set(desired_columns) - set(query_columns_list)))
        if len(unavailable) > 0:
            self.log.debug('The following desired columns are not available in the database: {0}'.format(unavailable))

        self.log.debug("Executing sqlite query for download history...")
        try:
            downloads_data = conn.cursor().execute(

                'SELECT url,group_concat(content),dateAdded FROM moz_annos \
                LEFT JOIN moz_places ON moz_places.id = moz_annos.place_id \
                GROUP BY place_id'

            ).fetchall()

            self.log.debug("Success. Found {0} lines of data.".format(len(downloads_data)))

        except sqlite3.OperationalError:
            error = [x for x in traceback.format_exc().split('\n') if x.startswith("OperationalError")]
            self.log.error('Failed to run query. [{0}]'.format(error[0]))

            return

        self.log.debug("Parsing and writing downloads data...")
        for item in downloads_data:
            record = OrderedDict((h, '') for h in self._downloads_headers)
            record['user'] = user
            record['profile'] = profile
            record['download_url'] = item[0]
            record['download_path'] = item[1].split(',')[0]
            record['download_started'] = firefox_time(item[2]).split('.')[0]+'Z'
            record['download_finished'] = firefox_time(int(item[1].split(',')[2].split(':')[1])*1000).split('.')[0]+'Z'
            record['download_totalbytes'] = item[1].split(',')[3].split(':')[1].replace('}','')

            self._downloads_output.write_entry(record.values())

        self.log.debug("Done.")

    def _pull_visit_history(self, conn, user, profile):
        desired_columns = ['visit_date','title','url','visit_count','typed','last_visit_date','description']
        available_columns = self._get_column_headers(conn, 'moz_places') + self._get_column_headers(conn, 'moz_historyvisits')
        query_columns_list = [i for i in desired_columns if i in available_columns]
        query_columns = ', '.join([i for i in desired_columns if i in available_columns])

        unavailable = ','.join(list(set(desired_columns) - set(query_columns_list)))
        if len(unavailable) > 0:
            self.log.debug('The following desired columns are not available in the database: {0}'.format(unavailable))

        self.log.debug("Executing sqlite query for visit history...")

        try:
            urls_data = conn.cursor().execute(

                'SELECT {0} FROM moz_historyvisits left join moz_places \
                on moz_places.id = moz_historyvisits.place_id'.format(query_columns)

            ).fetchall()
            self.log.debug("Success. Found {0} lines of data.".format(len(urls_data)))

        except sqlite3.OperationalError:
            error = [x for x in traceback.format_exc().split('\n') if x.startswith("OperationalError")]
            self.log.error('Failed to run query. [{0}]'.format(error[0]))

            return


        self.log.debug("Parsing and writing visits data...")
        nondict = dict.fromkeys(desired_columns)
        for item in urls_data:
            record = OrderedDict((h, '') for h in self._urls_headers)
            item_dict = dict(zip(query_columns_list,item))

            nondict.update(item_dict)

            record['user'] = user
            record['profile'] = profile
            record['visit_time'] = firefox_time(nondict['visit_date']).split('.')[0]+'Z'
            if nondict['title']:
                record['title'] = nondict['title'].encode('utf-8')
            record['url'] = nondict['url']
            record['visit_count'] = nondict['visit_count']
            record['typed'] = nondict['typed']
            record['last_visit_time'] = firefox_time(nondict['last_visit_date']).split('.')[0]+'Z'
            if nondict['description']:
                record['description'] = nondict['description'].encode('utf-8')

            self._urls_output.write_entry(record.values())

        self.log.debug("Done.")


    def run(self):
        for c in self.firefox_location:
            userpath = c.split('/')
            userindex = len(userpath) - 1 - userpath[::-1].index('Users') + 1
            user = userpath[userindex]

            profileindex = userpath.index('Profiles') + 1
            profile = userpath[profileindex]

            self.log.debug("Starting parsing for Firefox under {0} user.".format(user))

            self._get_firefox_version(c)

            history_db = self._connect_to_db(os.path.join(c, 'places.sqlite'),'moz_places')

            # If the database cannot be accessed, or if the main table necessary
            # for parsing (moz_places) is unavailable,
            # fail gracefully.
            if history_db:
                conn = sqlite3.connect(history_db)
                self._pull_download_history(conn, user, profile)
                self._pull_visit_history(conn, user, profile)

            try:
                os.remove(os.path.join(self.options.outputdir, 'places.sqlite-tmp'))
                os.remove(os.path.join(self.options.outputdir, 'places.sqlite-tmp-shm'))
                os.remove(os.path.join(self.options.outputdir, 'places.sqlite-tmp-wal'))
            except OSError:
                pass
