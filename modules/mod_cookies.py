"""A module intended to read and parse the cookies database for each
user for each browser on disk.
"""

import glob
import itertools
import logging
import os
import shutil
import sqlite3
import sys
import traceback
from collections import OrderedDict
from datetime import datetime

if sys.version_info[0] < 3:
    from .common.dep.six.moves import configparser
else:
    import configparser

# IMPORT STATIC VARIABLES FROM MAIN
from __main__ import data_writer, inputdir, outputdir

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from .common.dateutil import parser
from .common.functions import SQLiteDB, chrome_time, firefox_time, multiglob

_modName = __name__.split('_')[-1]
_modVers = '1.2.0'
log = logging.getLogger(_modName)


def get_chrome_version(db):
    """Returns the chrome version from the meta table or an emptry string otherwise
    """
    ver = ""
    try:
        version = sqlite3.connect(db).cursor().execute(
            'SELECT key, value FROM meta where key="version"').fetchall()
        ver = OrderedDict(version)['version']
        log.debug("[Cookies - Chrome] Chrome Cookie database meta version {0} identified.".format(ver))
    except Exception as e:
        log.debug("[Cookies - Chrome] Failed to query for Chrome Cookie database meta version: {0} - {1}.".format(str(e), traceback.format_exc()))
    return ver


def get_firefox_version(firefox_location, user, profile):
    """Returns the firefox version from the compatibility.ini file or an empty string otherwise.
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


def pull_chrome_cookies(db_wrapper, db_filepath, user, profile, cookies_output, cookies_headers):
    log.debug("[START] querying chrome cookies for user {0} profile {1}.".format(user, profile))

    cookies_data = []
    query = 'SELECT host_key, name, value, path, creation_utc, expires_utc, last_access_utc, is_secure,\
            is_httponly, has_expires, is_persistent, priority, encrypted_value, samesite, source_scheme \
            from cookies'
    try:
        cookies_data = db_wrapper.query_db(db_filepath, query, outputdir)
        log.debug("[Cookies - Chrome for {0}] Found {1} lines of data.".format(user, len(cookies_data)))
    except Exception:
        log.error("[Cookies - Chrome for {0}] Unable to query {1}: {2}".format(user, db_filepath, [traceback.format_exc()]))
        return

    log.debug("[Cookies - Chrome for {0}] Parsing and writing cookies data.".format(user))
    for item in cookies_data:
        record = OrderedDict((h, '') for h in cookies_headers)
        item = list(item)

        record['user'] = user
        record['profile'] = profile
        record['host_key'] = item[0]
        record['name'] = item[1]
        record['value'] = item[2]
        record['path'] = item[3]
        record['creation_utc'] = chrome_time(item[4])
        try:
            record['expires_utc'] = chrome_time(item[5])
        except OverflowError:
            record['expires_utc'] = "ERROR"
        try:
            record['last_access_utc'] = chrome_time(item[6])
        except OverflowError:
            record['last_access_utc'] = "ERROR"
        record['is_secure'] = item[7]
        record['is_httponly'] = item[8]
        record['has_expires'] = item[9]
        record['is_persistent'] = item[10]
        record['priority'] = item[11]
        if item[12] != '':
            record['encrypted_value'] = "BLOB exists"
        else:
            record['encrypted_value'] = "NO RECORD"
        record['samesite'] = item[13]
        record['source_scheme'] = item[14]

        cookies_output.write_record(record)
    log.debug("[END] querying chrome cookies for user {0} profile {1}.".format(user, profile))


def pull_firefox_cookies(db_wrapper, db_filepath, user, profile, cookies_output, cookies_headers):
    log.debug("[START] querying firefox cookies for user {0} profile {1}.".format(user, profile))

    cookies_data = []
    query = 'SELECT host, name, value, path, creationTime, expiry, lastAccessed, isSecure,\
            isHttpOnly, inBrowserElement, sameSite \
            from moz_cookies'
    try:
        cookies_data = db_wrapper.query_db(db_filepath, query, outputdir)
        log.debug("[Cookies - Firefox for {0}] Found {1} lines of data.".format(user, len(cookies_data)))
    except Exception:
        log.error("[Cookies - Firefox for {0}] Unable to query {1}: {2}".format(user, db_filepath, [traceback.format_exc()]))
        return

    log.debug("[Cookies - Firefox for {0}] Parsing and writing cookies data.".format(user))
    for item in cookies_data:
        record = OrderedDict((h, '') for h in cookies_headers)
        item = list(item)

        record['user'] = user
        record['profile'] = profile
        record['host_key'] = item[0]
        record['name'] = item[1]
        record['value'] = item[2]
        record['path'] = item[3]
        record['creation_utc'] = firefox_time(item[4])
        record['expires_utc'] = datetime.utcfromtimestamp(item[5]).isoformat() + 'Z'
        record['last_access_utc'] = firefox_time(item[6])
        record['is_secure'] = item[7]
        record['is_httponly'] = item[8]
        record['browser_element'] = item[9]
        record['same_site'] = item[10]

        cookies_output.write_record(record)

    log.debug("[END] querying firefox cookies for user {0} profile {1}.".format(user, profile))


def moduleFirefox(firefox_cookies_location):
    log.debug("[START] Firefox cookies parsing")

    cookies_headers = ['user', 'profile', 'host_key', 'name', 'value', 'path',
                       'creation_utc', 'expires_utc', 'last_access_utc', 'is_secure',
                       'is_httponly', 'browser_element', "same_site"]
    cookies_output = data_writer('browser_firefox_cookies', cookies_headers)

    for c in firefox_cookies_location:
        userpath = c.split('/')
        userindex = len(userpath) - 1 - userpath[::-1].index('Users') + 1
        user = userpath[userindex]

        profileindex = userpath.index('Profiles') + 1
        profile = userpath[profileindex]

        log.debug("Starting parsing for Firefox cookies for profile {0} under user {1}.".format(profile, user))

        # cookies_db = connect_to_db(os.path.join(c, 'cookies.sqlite'))
        db_filepath = os.path.join(c, 'cookies.sqlite')
        db_wrapper = SQLiteDB()
        db_wrapper.open(db_filepath, outputdir)

        if db_wrapper.table_exists('moz_cookies') is False:
            log.debug("Firefox cookies required table 'moz_cookies' not found.")
        else:
            pull_firefox_cookies(db_wrapper, db_filepath, user, profile, cookies_output, cookies_headers)

        for file in glob.glob(os.path.join(outputdir, '*cookies.sqlite*')):
            try:
                os.remove(file)
            except OSError as e:
                log.debug('Unable to clean up temp file {0}: '.format(file) + str(e))
                continue

    # flush output
    cookies_output.flush_record()

    log.debug("[END] Firefox cookies parsing")


def moduleChrome(chrome_cookies_location):
    log.debug("[START] Chrome cookies parsing")

    # Generate list of all chrome profiles under all chrome directories
    full_list_raw = [multiglob(c, ['Default', 'Profile *', 'Guest Profile']) for c in chrome_cookies_location]
    full_list = list(itertools.chain.from_iterable(full_list_raw))

    # headers from db
    cookies_headers = ['user', 'profile', 'host_key', 'name', 'value', 'path',
                       'creation_utc', 'expires_utc', 'last_access_utc', 'is_secure',
                       'is_httponly', 'has_expires', 'is_persistent', 'priority',
                       'encrypted_value', 'samesite', 'source_scheme']
    cookies_output = data_writer('browser_cookies_chrome', cookies_headers)

    for profile in full_list:
        userpath = profile.split('/')
        userindex = len(userpath) - 1 - userpath[::-1].index('Users') + 1
        user = userpath[userindex]

        chromeindex = userpath.index('Chrome') + 1
        prof = userpath[chromeindex]

        log.debug("Starting parsing for Chrome cookies for profile {0} under user {1}.".format(prof, user))

        db_filepath = os.path.join(profile, 'Cookies')
        db_wrapper = SQLiteDB()
        db_wrapper.open(db_filepath, outputdir)

        # Check if required table exists
        if db_wrapper.table_exists('cookies') is False:
            log.debug("Chrome Cookies required table '{0}' not found.".format('cookies'))
        else:
            get_chrome_version(db_filepath)
            pull_chrome_cookies(db_wrapper, db_filepath, user, profile, cookies_output, cookies_headers)

    # flush output
    cookies_output.flush_record()

    # clean files
    # for file in glob.glob(os.path.join(outputdir, '*Cookies*')):
    #     try:
    #         os.remove(file)
    #     except OSError as e:
    #         log.debug('Unable to clean up temp file {0}: '.format(file) + str(e))
    #         continue

    log.debug("[END] Chrome cookies parsing")


def module():
    chrome_cookies_location = glob.glob(
        os.path.join(inputdir, 'Users/*/Library/Application Support/Google/Chrome/')
    )
    firefox_cookies_location = glob.glob(
        os.path.join(inputdir, 'Users/*/Library/Application Support/Firefox/Profiles/*.*')
    )
    moduleChrome(chrome_cookies_location)
    moduleFirefox(firefox_cookies_location)


if __name__ == "__main__":
    print("This is an AutoMacTC module, and is not meant to be run stand-alone.")
    print("Exiting.")
    sys.exit(0)
else:
    module()
