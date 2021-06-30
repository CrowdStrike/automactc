"""A module intended to read and parse the Firefox history database for each
user on disk.
"""

import glob
import json
import logging
import os
import sys
import traceback
from collections import OrderedDict
from datetime import datetime
from string import printable

# IMPORT STATIC VARIABLES FROM MAIN
from __main__ import (archive, data_writer, forensic_mode, full_prefix,
                      inputdir, no_tarball, outputdir, quiet, startTime)

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from .common.dateutil import parser
from .common.dep.six.moves import configparser
from .common.functions import (SQLiteDB, db_table_exists, finditem,
                               firefox_time, get_db_column_headers, query_db,
                               stats2)

_modName = __name__.split('_')[-1]
_modVers = '1.2.0'
log = logging.getLogger(_modName)


def get_firefox_version(firefox_location, user, profile):
    """
    Returns the firefox version from the compatibility.ini file or an empty string otherwise.
    """
    ver = ""
    try:
        verfile = os.path.join(firefox_location, 'compatibility.ini')
        if os.path.exists(verfile):
            config = configparser.ConfigParser()
            config.read(verfile)
            try:
                ver = config.get('Compatibility', 'lastversion')
            except Exception:
                ver = config.get('Compatibility', 'LastVersion')
            log.debug("Firefox Version {0} identified for {1} user at {2}.".format(ver, user, profile))
        else:
            log.debug("Could not grab Firefox version for {0} user at {1}, file {2} does not exist".format(user, profile, verfile))
    except Exception as e:
        log.debug("Could not grab FireFox version for {0} user at {1} from {2}: ".format(user, profile, verfile) + str(e))
        return
    return ver


def parse_download_history(firefox_location, user, profile, downloads_output, downloads_headers):
    """
    Parses the Firefox download history form the places.sqlite sqlite3 db file
    Requires the moz_places table and the moz_annos table
    """
    db_filepath = os.path.join(firefox_location, 'places.sqlite')
    db_wrapper = SQLiteDB()
    db_wrapper.open(db_filepath, outputdir)

    if db_wrapper.table_exists('moz_places') is False:
        log.debug("Visit History required table 'moz_places' not found.")
        return
    if db_wrapper.table_exists('moz_annos') is False:
        log.debug("Visit History required table 'moz_annos' not found.")
        return

    # construct query
    desired_columns = ['url', 'content', 'dateAdded']
    available_columns = db_wrapper.column_headers('moz_annos') + db_wrapper.column_headers('moz_places')
    query_columns_list = [i for i in desired_columns if i in available_columns]
    query_columns = ', '.join([i for i in desired_columns if i in available_columns])

    unavailable = ','.join(list(set(desired_columns) - set(query_columns_list)))
    if len(unavailable) > 0:
        log.debug('The following desired columns are not available in the database: {0}'.format(unavailable))
    if len(unavailable) == len(desired_columns):
        log.debug('No desired columns found in db {0} for profile {1}'.format(db_filepath, profile))
        return

    query = 'SELECT url,group_concat(content),dateAdded FROM moz_annos LEFT JOIN moz_places ON moz_places.id = moz_annos.place_id GROUP BY place_id'

    log.debug("[Start] Finished executing SQLite query for Firefox download history.")
    try:
        downloads_data = db_wrapper.query_db(db_filepath, query, outputdir)
        log.debug("[Firefox download history for - {0}] Found {1} lines of data.".format(profile, len(downloads_data)))
    except Exception:
        log.error("Unable to query {0}: {1}".format(db_filepath, [traceback.format_exc()]))
        return

    log.debug("Parsing and writing downloads data...")

    for item in downloads_data:
        record = OrderedDict((h, '') for h in downloads_headers)
        record['user'] = user
        record['profile'] = profile
        record['download_url'] = item[0]
        record['download_path'] = item[1].split(',')[0]
        record['download_started'] = firefox_time(item[2]).split('.')[0] + 'Z'
        record['download_finished'] = firefox_time(int(item[1].split(',')[2].split(':')[1]) * 1000).split('.')[0] + 'Z'
        record['download_totalbytes'] = item[1].split(',')[3].split(':')[1].replace('}', '')

        downloads_output.write_record(record)
    log.debug("[End] Finished executing SQLite query for Firefox download history.")

    # clean up
    if db_wrapper.close():
        log.debug("Successfully closed {0}".format(db_filepath))


def parse_visit_history(firefox_location, user, profile, urls_output, urls_headers):
    """
    Parses the Firefox visit history form the places.sqlite sqlite3 db file
    Requires the moz_places table and the moz_historyvisits table
    """

    db_filepath = os.path.join(firefox_location, 'places.sqlite')
    db_wrapper = SQLiteDB()
    db_wrapper.open(db_filepath, outputdir)

    if db_wrapper.table_exists('moz_places') is False:
        log.debug("Visit History required table 'moz_places' not found.")
        return
    if db_wrapper.table_exists('moz_historyvisits') is False:
        log.debug("Visit History required table 'moz_historyvisits' not found.")
        return



    # construct query
    desired_columns = ['visit_date', 'title', 'url', 'visit_count', 'typed', 'last_visit_date', 'description']
    available_columns = db_wrapper.column_headers('moz_places') + db_wrapper.column_headers('moz_historyvisits')
    query_columns_list = [i for i in desired_columns if i in available_columns]
    query_columns = ', '.join([i for i in desired_columns if i in available_columns])
    unavailable = ','.join(list(set(desired_columns) - set(query_columns_list)))
    if len(unavailable) > 0:
        log.debug('The following desired columns are not available in the database {0}: {1}'.format(db_filepath, unavailable))
    if len(unavailable) == len(desired_columns):
        log.debug('No desired columns found in db {0} for profile {1}'.format(db_filepath, profile))
        return
    query = 'SELECT {0} FROM moz_historyvisits left join moz_places on moz_places.id = moz_historyvisits.place_id'.format(query_columns)

    log.debug("[Start] Executing SQLite query for Firefox visit history.")
    try:
        urls_data = db_wrapper.query_db(db_filepath, query, outputdir)
        log.debug("[Firefox visit history for - {0}] Found {1} lines of data.".format(profile, len(urls_data)))
    except Exception:
        log.error("Unable to query {0}: {1}".format(db_filepath, [traceback.format_exc()]))
        return

    nondict = dict.fromkeys(desired_columns)

    for item in urls_data:
        record = OrderedDict((h, '') for h in urls_headers)
        item_dict = dict(zip(query_columns_list, item))

        nondict.update(item_dict)

        record['user'] = user
        record['profile'] = profile
        record['visit_time'] = firefox_time(nondict['visit_date']).split('.')[0] + 'Z'
        if nondict['title']:
            record['title'] = "".join(filter(lambda char: char in printable, nondict['title']))
        record['url'] = nondict['url']
        record['visit_count'] = nondict['visit_count']
        record['typed'] = nondict['typed']
        record['last_visit_time'] = firefox_time(nondict['last_visit_date']).split('.')[0] + 'Z'
        if nondict['description']:
            record['description'] = nondict['description']

        urls_output.write_record(record)

    log.debug("[End] Finished executing SQLite query for Firefox visit history.")

    # clean up
    if db_wrapper.close():
        log.debug("Successfully closed {0}".format(db_filepath))


def get_extensions(extfile, user, prof, extensions_output, extensions_headers):
    log.debug("Writing extension data...")

    with open(extfile) as file:
        data = json.loads(file.read())

    for field in data.get("addons"):
        record = OrderedDict((h, '') for h in extensions_headers)
        record['user'] = user
        record['profile'] = prof
        record['name'] = finditem(finditem(field, "defaultLocale"), "name")
        record['id'] = finditem(field, "id")
        record['creator'] = finditem(finditem(field, "defaultLocale"), "creator")
        record['description'] = finditem(finditem(field, "defaultLocale"), "description")
        record['update_url'] = finditem(field, "updateURL")
        installDateVal = finditem(field, "installDate")
        if installDateVal is not None:
            record['install_date'] = datetime.utcfromtimestamp(installDateVal / 1000).isoformat()
        else:
            record['install_date'] = ""
        updateDateVal = finditem(field, "updateDate")
        if updateDateVal is not None:
            record['last_updated'] = datetime.utcfromtimestamp(updateDateVal / 1000).isoformat()
        else:
            record['last_updated'] = ""
        record['source_uri'] = finditem(field, "sourceURI")
        record['homepage_url'] = finditem(finditem(field, "defaultLocale"), "homepageURL")

        extensions_output.write_record(record)

    log.debug("Completed writing extension data.")


def module():
    firefox_locations = glob.glob(
        os.path.join(inputdir, 'Users/*/Library/Application Support/Firefox/Profiles/*.*'))

    urls_headers = ['user', 'profile', 'visit_time', 'title', 'url', 'visit_count', 'last_visit_time', 'typed', 'description']
    urls_output = data_writer('browser_firefox_history', urls_headers)

    downloads_headers = ['user', 'profile', 'download_url', 'download_path', 'download_started', 'download_finished', 'download_totalbytes']
    downloads_output = data_writer('browser_firefox_downloads', downloads_headers)

    extensions_headers = ['user', 'profile', 'name', 'id', 'creator', 'description', 'update_url', 'install_date', 'last_updated', 'source_uri', 'homepage_url']
    extensions_output = data_writer('browser_firefox_extensions', extensions_headers)

    for location in firefox_locations:
        user_path = location.split('/')
        user_index = len(user_path) - 1 - user_path[::-1].index('Users') + 1
        user = user_path[user_index]

        profile_index = user_path.index('Profiles') + 1
        profile = user_path[profile_index]

        log.debug("Starting parsing for Firefox under {0} user at {1}.".format(user, profile))

        get_firefox_version(location, user, profile)

        history_db_filepath = os.path.join(location, 'places.sqlite')
        if SQLiteDB.db_table_exists(history_db_filepath, 'moz_places'):
            try:
                parse_visit_history(location, user, profile, urls_output, urls_headers)
                parse_download_history(location, user, profile, downloads_output, downloads_headers)
            except Exception:
                log.error([traceback.format_exc()])
        else:
            log.debug("Did not find visit or download history for Firefox under {0} user at {1}.".format(user, profile))

        # Firefox Extensions
        extension_db_filepath = os.path.join(location, 'extensions.json')
        if os.path.exists(extension_db_filepath):
            try:
                get_extensions(extension_db_filepath, user, profile, extensions_output, extensions_headers)
            except Exception:
                log.error([traceback.format_exc()])
        else:
            log.debug("Did not find any Firefox extensions for Firefox under {0} user at {1}.".format(user, profile))

        # clean up
        for file in glob.glob(os.path.join(outputdir, '*places.sqlite*')):
            try:
                os.remove(file)
            except OSError as e:
                log.debug('Unable to clean up temp file {0}: '.format(file) + str(e))
                continue

    urls_output.flush_record()
    downloads_output.flush_record()
    extensions_output.flush_record()

if __name__ == "__main__":
    print("This is an AutoMacTC module, and is not meant to be run stand-alone.")
    print("Exiting.")
    sys.exit(0)
else:
    module()
