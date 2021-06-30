"""A module intended to read and parse the Safari history database and
Downloads.plist for each user on disk.
"""

import logging
import os
import plistlib
import shutil
import sqlite3
import sys
import traceback
from collections import OrderedDict

# IMPORT STATIC VARIABLES FROM MAIN
from __main__ import (OSVersion, archive, data_writer, forensic_mode,
                      full_prefix, inputdir, no_tarball, outputdir, quiet,
                      startTime)

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from .common.dateutil import parser
from .common.functions import cocoa_time, multiglob, read_bplist, stats2, get_db_column_headers

_modName = __name__.split('_')[-1]
_modVers = '1.0.5'
log = logging.getLogger(_modName)


# create_temp_sqlite_file returns the string name of the main sqlite file created
def create_temp_sqlite_file(db_location):
    tmp_db = os.path.basename(db_location) + '-tmp'
    tmp_shm_db = os.path.basename(db_location) + '-tmp-shm'
    tmp_wal_db = os.path.basename(db_location) + '-tmp-wal'
    tmp_wal_db = os.path.basename(db_location) + '-tmp-lock'

    log.debug("Trying to copy {0} temp location".format(db_location))
    try:
        shutil.copyfile(db_location, os.path.join(outputdir, tmp_db))
        shutil.copyfile(db_location + "-shm", os.path.join(outputdir, tmp_shm_db))
        shutil.copyfile(db_location + "-wal", os.path.join(outputdir, tmp_wal_db))
    except Exception as e:
        log.error("Could not copy {0} to temp location: {1}".format(db_location, e))
        try:
            os.remove(os.path.join(outputdir, 'History.db-tmp'))
            os.remove(os.path.join(outputdir, 'History.db-tmp-shm'))
            os.remove(os.path.join(outputdir, 'History.db-tmp-wal'))
        except OSError:
            pass
        return None
    return tmp_db


def connect_to_db(db_location, main_table):
    try:
        log.debug("Trying to connect to {0} directly...".format(db_location))
        history_db = db_location
        get_db_column_headers(history_db, main_table)
        log.debug("Successfully connected.")
    except sqlite3.OperationalError:
        error = [x for x in traceback.format_exc().split('\n') if "OperationalError" in x]
        log.debug("Could not connect to {0} [{1}].".format(db_location, error[0]))

        if "database is locked" or "unable to open" in error[0]:
            tmpdb = create_temp_sqlite_file(db_location)
            if tmpdb is None:
                return None
            history_db = os.path.join(outputdir, tmpdb)

            try:
                get_db_column_headers(history_db, main_table)
                log.debug("Successfully connected.")
            except sqlite3.OperationalError:
                error = [x for x in traceback.format_exc().split('\n') if "OperationalError" in x]
                log.debug("Could not connect [{0}].".format(error[0]))

                if "no such table" in error[0]:
                    log.error("Module fatal error: necessary table doesn't exist in database | {0}".format([traceback.format_exc()]))
                    history_db = None
        elif "no such table" in error[0]:
            log.error("Module fatal error: necessary table doesn't exist in database | {0}".format([traceback.format_exc()]))
            history_db = None

        else:
            log.error("Module fatal error: cannot parse database | {0}".format([traceback.format_exc()]))
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
        for k, v in i.items():
            if k not in ['DownloadEntryPostBookmarkBlob', 'DownloadEntryBookmarkBlob']:
                record = OrderedDict((h, '') for h in downloads_headers)
                record['user'] = user
                record['download_url'] = i['DownloadEntryURL']
                record['download_path'] = i['DownloadEntryPath']
                record['download_started'] = str(i['DownloadEntryDateAddedKey'])
                record['download_finished'] = str(i['DownloadEntryDateFinishedKey'])
                record['download_totalbytes'] = int(i['DownloadEntryProgressTotalToLoad'])
                record['download_bytes_received'] = int(i['DownloadEntryProgressBytesSoFar'])

        downloads_output.write_record(record)

    log.debug("Done.")


def pull_extensions(extensions, user, extensions_output, extensions_headers):
    log.debug("Trying to access extensions.")
    extensions_plist = os.path.join(extensions, 'Extensions.plist')
    file = open(extensions_plist, 'rb')

    if sys.version_info[0] < 3:
        p = plistlib.readPlist(file)
    else:
        p = plistlib.load(file)

    for item in p['Installed Extensions']:
        record = OrderedDict((h, '') for h in extensions_headers)
        record['user'] = user
        record['name'] = item['Archive File Name']
        record['bundle_directory'] = item['Bundle Directory Name']
        record['enabled'] = item['Enabled']
        record['apple_signed'] = item['Apple-signed']
        record['developer_id'] = item['Developer Identifier']
        record['bundle_id'] = item['Bundle Identifier']
        extension_file = os.path.join(extensions, item['Archive File Name'])
        if os.path.exists(extension_file):
            metadata = stats2(extension_file)
            print(metadata)
            record['ctime'] = metadata['ctime']
            record['mtime'] = metadata['mtime']
            record['atime'] = metadata['mtime']
            record['size'] = metadata['size']

        extensions_output.write_record(record)
    log.debug("Finished writing extension data.")


def pull_visit_history(recently_closed_plist, history_db, user, history_output, history_headers):

    try:
        log.debug("Trying to access RecentlyClosedTabs.plist...")
        recently_closed = read_bplist(recently_closed_plist)[0]['ClosedTabOrWindowPersistentStates']
        d = {}
        log.debug("Success. Found {0} lines of data.".format(len(recently_closed)))
        for i in recently_closed:
            for k, v in i['PersistentState'].items():
                if k == 'TabURL':
                    tab_title = i['PersistentState']['TabTitle'].encode('utf-8')
                    date_closed = parser.parse(str(i['PersistentState']['DateClosed'])).replace(tzinfo=None).isoformat() + 'Z'
                    try:
                        last_visit_time = i['PersistentState']['LastVisitTime']
                        last_visit_time = cocoa_time(last_visit_time)
                    except KeyError:
                        last_visit_time = ''
                    d[i['PersistentState']['TabURL']] = [tab_title, date_closed, last_visit_time]
    except IOError:
        log.debug("File not found: {0}".format(recently_closed_plist))
        d = {}
        pass

    desired_columns = ['visit_time', 'title', 'url', 'visit_count']
    available_columns = get_db_column_headers(history_db, 'history_visits') + get_db_column_headers(history_db, 'history_items')
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
        error = [x for x in traceback.format_exc().split('\n') if "OperationalError" in x]
        log.error('Failed to run query. [{0}]'.format(error[0]))

        return

    log.debug("Parsing and writing visits data...")

    nondict = dict.fromkeys(desired_columns)
    for item in history_data:
        record = OrderedDict((h, '') for h in history_headers)
        item_dict = dict(zip(query_columns_list, item))
        nondict.update(item_dict)

        record['user'] = user
        record['visit_time'] = cocoa_time(nondict['visit_time'])
        if nondict['title'] is not None:
            record['title'] = nondict['title']
        record['url'] = nondict['url']
        record['visit_count'] = nondict['visit_count']

        if nondict['url'] in d.keys():

            record['recently_closed'] = 'Yes'
            record['tab_title'] = d[nondict['url']][0]
            record['date_closed'] = d[nondict['url']][1]
            record['last_visit_time'] = d[nondict['url']][2]

        history_output.write_record(record)


def module(safari_location):
    if OSVersion is not None:
        ver = float('.'.join(OSVersion.split('.')[1:]))
        if ver > 14.0 and forensic_mode is not True:
            log.error("Artifacts are inaccessible on and above OS version 10.14 on live systems.")
            return
    else:
        if forensic_mode is not True:
            log.debug("OSVersion not detected, but going to try to parse anyway.")
        else:
            log.error("OSVersion not detected, so will not risk parsing as artifacts are inaccessible on and above OS version 10.14 on live systems.")
            return

    history_headers = ['user', 'visit_time', 'title', 'url', 'visit_count', 'last_visit_time', 'recently_closed', 'tab_title', 'date_closed']
    history_output = data_writer('browser_safari_history', history_headers)

    downloads_headers = ['user', 'download_url', 'download_path', 'download_started', 'download_finished', 'download_totalbytes', 'download_bytes_received']
    downloads_output = data_writer('browser_safari_downloads', downloads_headers)

    extensions_headers = ['user', 'name', 'bundle_directory', 'enabled', 'apple_signed', 'developer_id', 'bundle_id', 'ctime', 'mtime', 'atime', 'size']
    extensions_output = data_writer('browser_safari_extensions', extensions_headers)

    for c in safari_location:
        userpath = c.split('/')
        if 'Users' in userpath:
            userindex = len(userpath) - 1 - userpath[::-1].index('Users') + 1
        else:
            userindex = len(userpath) - 1 - userpath[::-1].index('var') + 1
        user = userpath[userindex]

        log.debug("Starting parsing for Safari under {0} user.".format(user))

        if not os.path.exists(os.path.join(c, 'History.db')):
            log.debug("Did not find History.db under {0} user.".format(user))
            continue

        history_db = connect_to_db(os.path.join(c, 'History.db'), 'history_visits')
        recently_closed_plist = os.path.join(c, 'RecentlyClosedTabs.plist')
        if history_db:
            pull_visit_history(recently_closed_plist, history_db, user, history_output, history_headers)

        downloads_plist = os.path.join(c, 'Downloads.plist')
        pull_download_history(downloads_plist, user, downloads_output, downloads_headers)

        extensions = os.path.join(c, 'Extensions')
        if os.path.exists(extensions):
            pull_extensions(extensions, user, extensions_output, extensions_headers)
        else:
            log.debug("No extensions folder found. Skipping.")

        try:
            os.remove(os.path.join(outputdir, 'History.db-tmp'))
            os.remove(os.path.join(outputdir, 'History.db-tmp-shm'))
            os.remove(os.path.join(outputdir, 'History.db-tmp-wal'))
        except OSError:
            pass
    history_output.flush_record()
    downloads_output.flush_record()
    extensions_output.flush_record()


if __name__ == "__main__":
    print("This is an AutoMacTC module, and is not meant to be run stand-alone.")
    print("Exiting.")
    sys.exit(0)
else:
    safari_location = multiglob(inputdir, ['Users/*/Library/Safari/', 'private/var/*/Library/Safari'])
    module(safari_location)
