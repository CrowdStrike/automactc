"""A module intended to read and parse the Chrome history database for each
user on disk.
"""

import glob
import itertools
import json
import logging
import os
import sqlite3
import sys
import time
import traceback
from collections import OrderedDict
from string import printable

# IMPORT STATIC VARIABLES FROM MAIN
from __main__ import (archive, data_writer, forensic_mode, full_prefix,
                      inputdir, no_tarball, outputdir, quiet, startTime)

from .common.dateutil import parser
# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from .common.functions import (SQLiteDB, chrome_time, finditem, firefox_time, multiglob,
                               stats2, get_db_column_headers)

try:
    from datetime import timezone
except Exception:
    import pytz as timezone

_modName = __name__.split('_')[-1]
_modVers = '1.2.0'
log = logging.getLogger(_modName)


def get_chrome_version(history_db):
    version = sqlite3.connect(history_db).cursor().execute(
        'SELECT key, value FROM meta where key="version"').fetchall()
    ver = OrderedDict(version)['version']
    log.debug("Chrome History database meta version {0} identified.".format(ver))
    return ver


def parse_visit_history(db_filepath, user, profile, urls_output, urls_headers):
    # instantiate db wrapper
    db_wrapper = SQLiteDB()
    if db_wrapper.open(db_filepath, outputdir) is False:
        log.debug('Unable to open db {0}'.format(db_filepath))
        return

    # Check for required tables
    if db_wrapper.table_exists('visits') is False:
        log.debug("Visit History required table 'visits' not found.")
        return
    if db_wrapper.table_exists('keyword_search_terms') is False:
        log.debug("Visit History required table 'keyword_search_terms' not found.")
        return
    if db_wrapper.table_exists('urls') is False:
        log.debug("Visit History required table 'urls' not found.")
        return

    log.debug('[Start] Executing Visit History query against {0} for user {1}'.format(db_filepath, user))

    try:
        urls_data = db_wrapper.query_db(db_filepath,

            'SELECT visit_time, urls.url, title, visit_duration, visit_count, \
            typed_count, urls.last_visit_time, term \
            from visits left join urls on visits.url = urls.id \
                        left join keyword_search_terms on keyword_search_terms.url_id = urls.id', outputdir)

        log.debug("[Chrome visit history for - {0}] Found {1} lines of data.".format(profile, len(urls_data)))

    except Exception:
        log.error("Unable to query {0}: {1}".format(db_filepath, [traceback.format_exc()]))

        # u_cnames = get_db_column_headers(history_db, 'urls')
        # log.debug('Columns available in "{0}" table: {1}'.format('urls', str(u_cnames)))

        # v_cnames = get_db_column_headers(history_db, 'visits')
        # log.debug('Columns available in "{0}" table: {1}'.format('visits', str(v_cnames)))

        # k_cnames = get_db_column_headers(history_db, 'keyword_search_terms')
        # log.debug('Columns available in "{0}" table: {1}'.format('keyword_search_terms', str(k_cnames)))

        return

    log.debug("Parsing and writing visits data...")

    for item in urls_data:
        record = OrderedDict((h, '') for h in urls_headers)
        item = list(item)
        record['user'] = user
        record['profile'] = profile
        record['visit_time'] = chrome_time(item[0])
        record['url'] = item[1]
        record['title'] = "".join(filter(lambda char: char in printable, item[2]))
        record['visit_duration'] = time.strftime("%H:%M:%S", time.gmtime(item[3] / 1000000))
        record['visit_count'] = item[4]
        record['typed_count'] = item[5]
        record['last_visit_time'] = chrome_time(item[6])
        search_term = item[7]

        if search_term is not None:
            record['search_term'] = item[7]
        else:
            record['search_term'] = ''

        urls_output.write_record(record)
    log.debug('[End] Finished executing Visit History query against {0} for user {1}'.format(db_filepath, user))


def parse_download_history(db_filepath, user, profile, downloads_output, downloads_headers):
    # instantiate db wrapper
    db_wrapper = SQLiteDB()
    if db_wrapper.open(db_filepath, outputdir) is False:
        log.debug('Unable to open db {0}'.format(db_filepath))
        return

    # Check for required tables
    if db_wrapper.table_exists('downloads') is False:
        log.debug("Download History required table 'downloads' not found.")
        return
    if db_wrapper.table_exists('downloads_url_chains') is False:
        log.debug("Download History required table 'downloads_url_chains' not found.")
        return

    log.debug('[Start] Executing Download History query against {0} for user {1}'.format(db_filepath, user))
    try:
        downloads_data = db_wrapper.query_db(db_filepath,
            'SELECT current_path, target_path, start_time, end_time, danger_type, opened, \
            last_modified, referrer, tab_url, tab_referrer_url, site_url, url from downloads \
            left join downloads_url_chains on downloads_url_chains.id = downloads.id', outputdir)

        log.debug("[Chrome download history for - {0}] Found {1} lines of data.".format(profile, len(downloads_data)))

    except Exception:
        log.error("Unable to query {0}: {1}".format(db_filepath, [traceback.format_exc()]))

        # duc_cnames = get_db_column_headers(db_filepath, 'downloads_url_chains')
        # log.debug('Columns available: {0}'.format(str(duc_cnames)))

        # d_cnames = get_db_column_headers(db_filepath, 'downloads')
        # log.debug('Columns available: {0}'.format(str(d_cnames)))

        return

    log.debug("Parsing and writing downloads data...")

    for item in downloads_data:
        record = OrderedDict((h, '') for h in downloads_headers)
        item = list(item)

        record['user'] = user
        record['profile'] = profile
        record['current_path'] = item[0]
        record['download_path'] = item[1]
        record['download_started'] = chrome_time(item[2])
        record['download_finished'] = chrome_time(item[3])
        record['danger_type'] = item[4]
        record['opened'] = item[5]

        if item[6] != '':
            last_modified = parser.parse(item[6]).replace(tzinfo=timezone.utc)
            record['last_modified'] = last_modified.isoformat().replace('+00:00', 'Z')
        else:
            record['last_modified'] = ''

        record['referrer'] = item[7]
        record['tab_url'] = item[8]
        record['tab_referrer_url'] = item[9]
        record['download_url'] = item[10]
        record['url'] = item[11]

        downloads_output.write_record(record)

    log.debug('[End] Finished executing Download History query against {0} for user {1}'.format(db_filepath, user))


def parse_profiles(profile_data, user, profile_output, profile_headers):
    log.debug("Success. Found metadata for {0} profiles.".format(len(profile_data.items())))
    for k, v in profile_data.items():
        record = OrderedDict((h, '') for h in profile_headers)
        record['user'] = user
        record['profile'] = k

        for key, val in v.items():
            if key in profile_headers:
                record[key] = val

        record['active_time'] = firefox_time(record['active_time'] * 1000000)

        profile_output.write_record(record)


def get_extensions(extlist, user, prof, extensions_output, extensions_headers):
    log.debug("Writing extension data...")

    for ext in extlist:
        with open(ext) as file:
            data = json.loads(file.read())

        # these json files have various different keys depending on the author

        record = OrderedDict((h, '') for h in extensions_headers)
        record['user'] = user
        record['profile'] = prof
        record['name'] = finditem(data, "name")
        record['author'] = finditem(data, "author")
        record['permissions'] = finditem(data, "permissions")
        record['description'] = finditem(data, "description")
        record['scripts'] = finditem(data, "scripts")
        record['persistent'] = finditem(data, "persistent")
        record['version'] = finditem(data, "version")

        extensions_output.write_record(record)

    log.debug("Completed writing extension data.")


def module():
    chrome_locations = glob.glob(
        os.path.join(inputdir, 'Users/*/Library/Application Support/Google/Chrome/'))

    # for all chrome dirs on disk, parse their local state files

    profile_headers = ['user', 'profile', 'active_time', 'is_using_default_avatar', 'is_omitted_from_profile_list',
                       'name', 'gaia_picture_file_name', 'user_name', 'managed_user_id', 'gaia_name',
                       'avatar_icon', 'gaia_id', 'local_auth_credentials', 'gaia_given_name',
                       'is_using_default_name', 'background_apps', 'is_ephemeral']
    profile_output = data_writer('browser_chrome_profiles', profile_headers)

    for location in chrome_locations:

        user_path = location.split('/')
        user_index = len(user_path) - 1 - user_path[::-1].index('Users') + 1
        user = user_path[user_index]

        log.debug("Parsing Chrome Local State data under {0} user.".format(user))
        localstate_file = os.path.join(location, 'Local State')
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
    full_list_raw = [multiglob(location, ['Default', 'Profile *', 'Guest Profile']) for location in chrome_locations]
    full_list = list(itertools.chain.from_iterable(full_list_raw))

    urls_headers = ['user', 'profile', 'visit_time', 'title', 'url', 'visit_count', 'last_visit_time',
                    'typed_count', 'visit_duration', 'search_term']
    urls_output = data_writer('browser_chrome_history', urls_headers)

    downloads_headers = ['user', 'profile', 'download_path', 'current_path', 'download_started', 'download_finished',
                         'danger_type', 'opened', 'last_modified', 'referrer', 'tab_url', 'tab_referrer_url',
                         'download_url', 'url']
    downloads_output = data_writer('browser_chrome_downloads', downloads_headers)

    extensions_headers = ['user', 'profile', 'name', 'permissions', 'author', 'description', 'scripts', 'persistent', 'version']
    extensions_output = data_writer('browser_chrome_extensions', extensions_headers)

    for prof in full_list:

        user_path = prof.split('/')
        user_index = len(user_path) - 1 - user_path[::-1].index('Users') + 1
        user = user_path[user_index]

        chromeindex = user_path.index('Chrome') + 1
        profile = user_path[chromeindex]

        log.debug("Starting parsing for Chrome history under {0} user.".format(user))

        history_db_filepath = os.path.join(prof, 'History')
        if SQLiteDB.db_exists(history_db_filepath):
            try:
                parse_visit_history(history_db_filepath, user, profile, urls_output, urls_headers)
            except Exception:
                log.error('Unable to parse visit history for user {0}, profile {1}: {2}'.format(user, profile, [traceback.format_exc()]))
            try:
                parse_download_history(history_db_filepath, user, profile, downloads_output, downloads_headers)
            except Exception:
                log.error('Unable to parse download history for user {0}, profile {1}: {2}'.format(user, profile, [traceback.format_exc()]))

        extension_path = os.path.join(prof, 'Extensions/*/*/Manifest.json')
        extension_list = glob.glob(extension_path)
        get_extensions(extension_list, user, profile, extensions_output, extensions_headers)

    extensions_output.flush_record()
    downloads_output.flush_record()
    urls_output.flush_record()

    # clean up
    if os.path.exists(os.path.join(outputdir, 'History-tmp_amtc')):
        try:
            os.remove(os.path.join(outputdir, 'History-tmp_amtc'))
        except OSError as e:
            log.debug('Unable to clean up temp file {0}: '.format(os.path.join(outputdir, 'History-tmp_amtc')) + str(e))


if __name__ == "__main__":
    print("This is an AutoMacTC module, and is not meant to be run stand-alone.")
    print("Exiting.")
    sys.exit(0)
else:
    module()
