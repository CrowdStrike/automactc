#!/usr/bin/env python

'''
@ author: Kshitij Kumar
@ email: kshitijkumar14@gmail.com, kshitij.kumar@crowdstrike.com

@ purpose:

A module intended to read and parse the Chrome history database for each
user on disk.

'''

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from common.functions import stats2
from common.functions import chrome_time
from common.functions import firefox_time
from common.functions import multiglob
from common.functions import finditem

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

import os
import itertools
import json
import ast
import glob
import sqlite3
import shutil
import logging
import pytz
import time
import traceback
import dateutil.parser as parser
from collections import OrderedDict

_modName = __name__.split('_')[-2]
_modVers = '.'.join(list(__name__.split('_')[-1][1:]))
log = logging.getLogger(_modName)


def get_column_headers(db, column):
    try:
        col_headers = sqlite3.connect(db).cursor().execute('SELECT * from {0}'.format(column))
        names = list(map(lambda x: x[0], col_headers.description))
    except sqlite3.OperationalError:
        log.debug("Column '{0}' was not found in database.".format(column))
        names = []
    return names


def get_chrome_version(history_db):
    version = sqlite3.connect(history_db).cursor().execute(
        'SELECT key, value FROM meta where key="version"').fetchall()
    ver = OrderedDict(version)['version']
    log.debug("Chrome History database meta version {0} identified.".format(ver))
    return ver


def connect_to_db(chrome_location):
    try:
        log.debug("Trying to connect to {0} directly...".format(chrome_location))
        history_db = chrome_location
        ver = get_chrome_version(history_db)
        log.debug("Successfully connected.")
    except sqlite3.OperationalError:
        error = [x for x in traceback.format_exc().split('\n') if x.startswith("OperationalError")]
        log.debug("Could not connect [{0}].".format(error[0]))

        if "database is locked" in error[0]:
            tmpdb = os.path.basename(chrome_location)+'-tmp'
            log.debug("Trying to connect to db copied to temp location...")

            shutil.copyfile(history_db, os.path.join(outputdir, tmpdb))
            history_db = os.path.join(outputdir, tmpdb)

            try:
                ver = get_chrome_version(history_db)
                log.debug("Successfully connected.")
            except:
                error = [x for x in traceback.format_exc().split('\n') if x.startswith("OperationalError")]
                log.debug("Could not connect [{0}].".format(error[0]))

                log.error("Module fatal error: cannot parse database.")
                history_db = None

    return history_db


def pull_visit_history(history_db, user, prof, urls_output, urls_headers):

    log.debug("Executing sqlite query for visit history...")

    try:
        urls_data = sqlite3.connect(history_db).cursor().execute(

            'SELECT visit_time, urls.url, title, visit_duration, visit_count, \
            typed_count, urls.last_visit_time, term \
            from visits left join urls on visits.url = urls.id \
                        left join keyword_search_terms on keyword_search_terms.url_id = urls.id'

        ).fetchall()
        log.debug("Success. Found {0} lines of data.".format(len(urls_data)))

    except Exception, e:
        log.debug('Failed to run query: {0}'.format([traceback.format_exc()]))

        u_cnames = get_column_headers(history_db, 'urls')
        log.debug('Columns available in "{0}" table: {1}'.format('urls2', str(u_cnames)))

        v_cnames = get_column_headers(history_db, 'visits')
        log.debug('Columns available in "{0}" table: {1}'.format('visits', str(v_cnames)))

        k_cnames = get_column_headers(history_db, 'keyword_search_terms')
        log.debug('Columns available in "{0}" table: {1}'.format('keyword_search_terms', str(k_cnames)))

        return

    log.debug("Parsing and writing visits data...")
    for item in urls_data:
        record = OrderedDict((h, '') for h in urls_headers)
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

        urls_output.write_entry(record.values())
    log.debug("Done.")


def pull_download_history(history_db, user, prof, downloads_output, downloads_headers):

    log.debug("Executing sqlite query for download history...")

    try:
        downloads_data = sqlite3.connect(history_db).cursor().execute(

            'SELECT current_path, target_path, start_time, end_time, danger_type, opened, \
            last_modified, referrer, tab_url, tab_referrer_url, site_url, url from downloads \
            left join downloads_url_chains on downloads_url_chains.id = downloads.id'

        ).fetchall()

        log.debug("Success. Found {0} lines of data.".format(len(downloads_data)))

    except Exception, e:
        log.debug('Failed to run query: {0}'.format([traceback.format_exc()]))

        duc_cnames = get_column_headers(history_db, 'downloads_url_chains')
        log.debug('Columns available: {0}'.format(str(duc_cnames)))

        d_cnames = get_column_headers(history_db, 'downloads')
        log.debug('Columns available: {0}'.format(str(d_cnames)))

        return

    log.debug("Parsing and writing downloads data...")
    for item in downloads_data:
        record = OrderedDict((h, '') for h in downloads_headers)
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

        downloads_output.write_entry(record.values())

    log.debug("Done.")


def parse_profiles(profile_data, user, profile_output, profile_headers):
    log.debug("Success. Found metadata for {0} profiles.".format(len(profile_data.items())))
    for k,v in profile_data.items():
        record = OrderedDict((h, '') for h in profile_headers)
        record['user'] = user
        record['profile'] = k

        for key, val in v.items():
            if key in profile_headers:
                record[key] = val

        record['active_time'] = firefox_time(record['active_time']*1000000)

        profile_output.write_entry(record.values())



def module(chrome_location):

    # for all chrome dirs on disk, parse their local state files

    profile_headers = ['user','profile','active_time','is_using_default_avatar','is_omitted_from_profile_list',
                       'name','gaia_picture_file_name','user_name','managed_user_id','gaia_name',
                       'avatar_icon','gaia_id','local_auth_credentials','gaia_given_name',
                       'is_using_default_name','background_apps','is_ephemeral']
    profile_output = data_writer('browser_chrome_profiles', profile_headers)

    for c in chrome_location:

        userpath = c.split('/')
        userindex = len(userpath) - 1 - userpath[::-1].index('Users') + 1
        user = userpath[userindex]

        log.debug("Parsing Chrome Local State data under {0} user.".format(user))
        localstate_file = os.path.join(c, 'Local State')
        if os.path.exists(localstate_file):
            with open(localstate_file, 'r') as data:
                jdata = json.loads(data.read())
                chrome_ver = finditem(jdata, "stats_version")
                log.debug("Chrome version {0} identified.".format(chrome_ver))
            
                profile_data = finditem(jdata, "info_cache")
                parse_profiles(profile_data, user, profile_output, profile_headers)

        else:
            log.debug("File not found: {0}".format(localstate_file))

    # make a full list of all chrome profiles under all chrome dirs
    full_list_raw = [multiglob(c, ['Default', 'Profile *', 'Guest Profile']) for c in chrome_location]
    full_list = list(itertools.chain.from_iterable(full_list_raw))

    urls_headers = ['user','profile','visit_time','title','url','visit_count','last_visit_time',
                    'typed_count','visit_duration','search_term']
    urls_output = data_writer('browser_chrome_history', urls_headers)

    downloads_headers = ['user','profile','download_path','current_path','download_started','download_finished',
                         'danger_type','opened','last_modified','referrer','tab_url','tab_referrer_url',
                         'download_url','url']
    downloads_output = data_writer('browser_chrome_downloads', downloads_headers)

    for prof in full_list:

        userpath = prof.split('/')
        userindex = len(userpath) - 1 - userpath[::-1].index('Users') + 1
        user = userpath[userindex]

        chromeindex = userpath.index('Chrome') + 1
        profile = userpath[chromeindex]

        log.debug("Starting parsing for Chrome history under {0} user.".format(user))

        history_db = connect_to_db(os.path.join(prof, 'History'))

        if history_db:      

            pull_visit_history(history_db, user, profile, urls_output, urls_headers)
            pull_download_history(history_db, user, profile, downloads_output, downloads_headers)

        try:
            os.remove(os.path.join(outputdir, 'History-tmp'))
        except OSError:
            pass


if __name__ == "__main__":
    print "This is an AutoMacTC module, and is not meant to be run stand-alone."
    print "Exiting."
    sys.exit(0)
else:
    chrome_location = glob.glob(
        os.path.join(inputdir, 'Users/*/Library/Application Support/Google/Chrome/'))
    module(chrome_location)