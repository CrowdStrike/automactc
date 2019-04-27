#!/usr/bin/env python

'''
@ author: Kshitij Kumar
@ email: kshitijkumar14@gmail.com, kshitij.kumar@crowdstrike.com

@ purpose:

A module intended to read and parse the Chrome history database for each
user on disk.

'''
import os
import itertools
import json
import glob
import sqlite3
import shutil
import time
import traceback
from collections import OrderedDict
import dateutil.parser as parser

import pytz

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from automactc.modules.common.base import AutoMacTCModule
from automactc.modules.common.functions import chrome_time
from automactc.modules.common.functions import firefox_time
from automactc.modules.common.functions import multiglob
from automactc.modules.common.functions import finditem
from automactc.utils.output import DataWriter


class ChromeModule(AutoMacTCModule):
    _mod_filename = __name__

    _profile_headers = [
        'user', 'profile', 'active_time', 'is_using_default_avatar', 'is_omitted_from_profile_list',
        'name', 'gaia_picture_file_name', 'user_name', 'managed_user_id', 'gaia_name',
        'avatar_icon', 'gaia_id', 'local_auth_credentials', 'gaia_given_name',
        'is_using_default_name', 'background_apps', 'is_ephemeral'
    ]

    _downloads_headers = [
        'user', 'profile', 'download_path', 'current_path', 'download_started', 'download_finished',
        'danger_type', 'opened', 'last_modified', 'referrer', 'tab_url', 'tab_referrer_url',
        'download_url', 'url'
    ]

    _urls_headers = [
        'user', 'profile', 'visit_time', 'title', 'url', 'visit_count', 'last_visit_time',
        'typed_count', 'visit_duration', 'search_term'
    ]

    def __init__(self, *args, **kwargs):
        super(ChromeModule, self).__init__(*args, **kwargs)
        self.chrome_location = glob.glob(
            os.path.join(self.options.inputdir, 'Users/*/Library/Application Support/Google/Chrome/'))
        self._profiles_output = DataWriter('browser_chrome_profiles', self._profile_headers, self.log, self.run_id, self.options)
        self._downloads_output = DataWriter('browser_chrome_downloads', self._downloads_headers, self.log, self.run_id, self.options)
        self._urls_output = DataWriter('browser_chrome_history', self._urls_headers, self.log, self.run_id, self.options)

    def _parse_profiles(self, profile_data, user):
        self.log.debug("Success. Found metadata for {0} profiles.".format(len(profile_data.items())))
        for k,v in profile_data.items():
            record = OrderedDict((h, '') for h in self._profile_headers)
            record['user'] = user
            record['profile'] = k

            for key, val in v.items():
                if key in self._profile_headers:
                    record[key] = val

            record['active_time'] = firefox_time(record['active_time']*1000000)

            self._profiles_output.write_entry(record.values())

    def _process_profiles(self):
        for c in self.chrome_location:
            userpath = c.split('/')
            userindex = userpath.index('Users') + 1
            user = userpath[userindex]

            self.log.debug("Parsing Chrome Local State data under {0} user.".format(user))
            localstate_file = os.path.join(c, 'Local State')
            if os.path.exists(localstate_file):
                with open(localstate_file, 'r') as data:
                    jdata = json.loads(data.read())
                    chrome_ver = finditem(jdata, "stats_version")
                    self.log.debug("Chrome version {0} identified.".format(chrome_ver))

                    profile_data = finditem(jdata, "info_cache")
                    self._parse_profiles(profile_data, user)

            else:
                self.log.debug("File not found: {0}".format(localstate_file))

    def _pull_visit_history(self, conn, user, prof):

        self.log.debug("Executing sqlite query for visit history...")

        try:
            urls_data = conn.cursor().execute(

                'SELECT visit_time, urls.url, title, visit_duration, visit_count, \
                typed_count, urls.last_visit_time, term \
                from visits left join urls on visits.url = urls.id \
                            left join keyword_search_terms on keyword_search_terms.url_id = urls.id'

            ).fetchall()
            self.log.debug("Success. Found {0} lines of data.".format(len(urls_data)))

        except Exception:
            self.log.debug('Failed to run query: {0}'.format([traceback.format_exc()]))

            u_cnames = self._get_column_headers(conn, 'urls')
            self.log.debug('Columns available: {0}'.format(str(u_cnames)))

            v_cnames = self._get_column_headers(conn, 'visits')
            self.log.debug('Columns available: {0}'.format(str(v_cnames)))

            k_cnames = self._get_column_headers(conn, 'keyword_search_terms')
            self.log.debug('Columns available: {0}'.format(str(k_cnames)))

            return

        self.log.debug("Parsing and writing visits data...")
        for item in urls_data:
            record = OrderedDict((h, '') for h in self._urls_headers)
            item = list(item)

            record['user'] = user
            record['profile'] = prof
            record['visit_time'] = chrome_time(item[0])
            record['url'] = item[1]
            record['title'] = item[2].encode('utf-8')
            record['visit_duration'] = time.strftime("%H:%M:%S", time.gmtime(item[3] / 1000000))
            record['visit_count'] = item[4]
            record['typed_count'] = item[5]
            record['last_visit_time'] = chrome_time(item[6])
            search_term = item[7]

            if search_term is not None:
                record['search_term'] = item[7].encode('utf-8')
            else:
                record['search_term'] = ''

            self._urls_output.write_entry(record.values())
        self.log.debug("Done.")

    def _pull_download_history(self, conn, user, prof):

        self.log.debug("Executing sqlite query for download history...")

        try:
            downloads_data = conn.cursor().execute(

                'SELECT current_path, target_path, start_time, end_time, danger_type, opened, \
                last_modified, referrer, tab_url, tab_referrer_url, site_url, url from downloads \
                left join downloads_url_chains on downloads_url_chains.id = downloads.id'

            ).fetchall()

            self.log.debug("Success. Found {0} lines of data.".format(len(downloads_data)))

        except Exception:
            self.log.debug('Failed to run query: {0}'.format([traceback.format_exc()]))

            duc_cnames = self._get_column_headers(conn, 'downloads_url_chains')
            self.log.debug('Columns available: {0}'.format(str(duc_cnames)))

            d_cnames = self._get_column_headers(conn, 'downloads')
            self.log.debug('Columns available: {0}'.format(str(d_cnames)))

            return

        self.log.debug("Parsing and writing downloads data...")
        for item in downloads_data:
            record = OrderedDict((h, '') for h in self._downloads_headers)
            item = list(item)

            record['user'] = user
            record['profile'] = prof
            record['current_path'] = item[0].encode('utf-8')
            record['download_path'] = item[1].encode('utf-8')
            record['download_started'] = chrome_time(item[2])
            record['download_finished'] = chrome_time(item[3])
            record['danger_type'] = item[4]
            record['opened'] = item[5]

            if item[6] != '':
                last_modified = parser.parse(item[6]).replace(tzinfo=pytz.UTC)
                record['last_modified'] = last_modified.isoformat().replace('+00:00', 'Z')
            else:
                record['last_modified'] = ''

            record['referrer'] = item[7]
            record['tab_url'] = item[8]
            record['tab_referrer_url'] = item[9]
            record['download_url'] = item[10]
            record['url'] = item[11]

            self._downloads_output.write_entry(record.values())

        self.log.debug("Done.")

    def _get_column_headers(self, conn, column):
        col_headers = conn.cursor().execute('SELECT * from {0}'.format(column))
        names = list(map(lambda x: x[0], col_headers.description))
        return names

    def _get_chrome_version(self, history_db):
        version = sqlite3.connect(history_db).cursor().execute(
            'SELECT key, value FROM meta where key="version"').fetchall()
        ver = OrderedDict(version)['version']
        self.log.debug("Chrome History database meta version {0} identified.".format(ver))
        return ver

    def _connect_to_db(self, chrome_file):
        try:
            self.log.debug("Trying to connect to {0} directly...".format(chrome_file))
            history_db = chrome_file
            ver = self._get_chrome_version(history_db)
            self.log.debug("Successfully connected.")
        except sqlite3.OperationalError:
            error = [x for x in traceback.format_exc().split('\n') if x.startswith("OperationalError")]
            self.log.debug("Could not connect [{0}].".format(error[0]))

            if "database is locked" in error[0]:
                tmpdb = os.path.basename(chrome_file)+'-tmp'
                self.log.debug("Trying to connect to db copied to temp location...")

                shutil.copyfile(history_db, os.path.join(self.options.outputdir, tmpdb))
                history_db = os.path.join(self.options.outputdir, tmpdb)

                try:
                    ver = self._get_chrome_version(history_db)
                    self.log.debug("Successfully connected.")
                except:
                    error = [x for x in traceback.format_exc().split('\n') if x.startswith("OperationalError")]
                    self.log.debug("Could not connect [{0}].".format(error[0]))

                    self.log.error("Module fatal error: cannot parse database.")
                    history_db = None

        return history_db

    def run(self):

        self._process_profiles()

        # make a full list of all chrome profiles under all chrome dirs
        full_list_raw = [multiglob(c, ['Default', 'Profile *', 'Guest Profile']) for c in self.chrome_location]
        full_list = list(itertools.chain.from_iterable(full_list_raw))

        for prof in full_list:

            userpath = prof.split('/')
            userindex = len(userpath) - 1 - userpath[::-1].index('Users') + 1
            user = userpath[userindex]

            chromeindex = userpath.index('Chrome') + 1
            profile = userpath[chromeindex]

            self.log.debug("Starting parsing for Chrome history under {0} user.".format(user))

            history_db = self._connect_to_db(os.path.join(prof, 'History'))

            if history_db:
                conn = sqlite3.connect(history_db)
                self._pull_visit_history(conn, user, profile)
                self._pull_download_history(conn, user, profile)

            try:
                os.remove(os.path.join(self.options.outputdir, 'History-tmp'))
            except OSError:
                pass
