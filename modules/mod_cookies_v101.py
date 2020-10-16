#!/usr/bin/env python

'''

@ purpose:

A module intended to read and parse the cookies database for each
user for each browser on disk.

'''

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from .common.functions import multiglob
from .common.functions import chrome_time
from .common.functions import firefox_time

# IMPORT STATIC VARIABLES FROM MAIN
from __main__ import inputdir
from __main__ import outputdir
from __main__ import data_writer

import os
import glob
import sqlite3
import logging
import itertools
import traceback
from collections import OrderedDict
from .common.dateutil import parser
from datetime import datetime

_modName = __name__.split('_')[-2]
_modVers = '.'.join(list(__name__.split('_')[-1][1:]))
log = logging.getLogger(_modName)


def get_chrome_version(db):
    version = sqlite3.connect(db).cursor().execute(
        'SELECT key, value FROM meta where key="version"').fetchall()
    ver = OrderedDict(version)['version']
    log.debug("Chrome Cookie database meta version {0} identified.".format(ver))
    return ver

def get_firefox_version(firefox_location):
    try :
        verfile = os.path.join(firefox_location, 'compatibility.ini')
        config = configparser.ConfigParser()
        config.read(verfile)
        ver = config.get('Compatibility','lastversion')
        log.debug("Firefox Version {0} identified.".format(ver))
    except Exception as e:
        log.debug("Could not grab FireFox version.")
        return
    return ver

def connect_to_db(location):
    try:
        log.debug("Trying to connect to {0} directly...".format(location))
        db = location
        # ver = get_chrome_version(db)
        log.debug("Successfully connected.")
    except sqlite3.OperationalError:
        error = [x for x in traceback.format_exc().split('\n') if "OperationalError" in x]
        log.debug("Could not connect [{0}].".format(error[0]))

        if "database is locked" in error[0]:
            tmpdb = os.path.basename(location)+'-tmp'
            log.debug("Trying to connect to db copied to temp location...")

            shutil.copyfile(db, os.path.join(outputdir, tmpdb))
            db = os.path.join(outputdir, tmpdb)

            try:
                # ver = get_chrome_version(db)
                log.debug("Successfully connected.")
            except:
                log.error("Module fatal error: cannot parse database.")
                db = None
                error = [x for x in traceback.format_exc().split('\n') if "OperationalError" in x]
                log.debug("Could not connect [{0}].".format(error[0]))
    return db

def pull_chrome_cookies(cookies_db, user, profile, cookies_output, cookies_headers):
    log.debug("Executing sqlite query for cookies...")

    cookies_data = []
    try:
        cookies_data = sqlite3.connect(cookies_db).cursor().execute(

            'SELECT host_key, name, value, path, creation_utc, expires_utc, last_access_utc, is_secure,\
            is_httponly, has_expires, is_persistent, priority, encrypted_value, samesite, source_scheme \
            from cookies'
        ).fetchall()
        log.debug("Success. Found {0} lines of data.".format(len(cookies_data)))
    except Exception as e:
        log.debug("Exception occurred executing sqlite query for cookies: {0}".format([traceback.format_exc()]))
        if ("unable to open" in [traceback.format_exc()][0]):
            log.debug("Unable to open: {0}".format(cookies_db))
            log.debug("CWD: {0}".format(os.getcwd()))

    log.debug("Parsing and writing cookies data")
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
        if item[12] is not '':
            record['encrypted_value'] = "BLOB exists"
        else:
            record['encrypted_value'] = "NO RECORD"
        record['samesite'] = item[13]
        record['source_scheme'] = item[14]

        cookies_output.write_entry(record.values())
    log.debug("Done.")

def pull_firefox_cookies(cookies_db, user, profile, cookies_output, cookies_headers):
    log.debug("Executing sqlite query for cookies...")

    cookies_data = []
    try:
        cookies_data = sqlite3.connect(cookies_db).cursor().execute(

            'SELECT host, name, value, path, creationTime, expiry, lastAccessed, isSecure,\
            isHttpOnly, inBrowserElement, sameSite \
            from moz_cookies'
        ).fetchall()
        log.debug("Success. Found {0} lines of data.".format(len(cookies_data)))
    except Exception as e:
        log.debug("Exception occurred executing sqlite query for cookies: {0}".format([traceback.format_exc()]))
        if ("unable to open" in [traceback.format_exc()][0]):
            log.debug("Unable to open: {0}".format(cookies_db))
            log.debug("CWD: {0}".format(os.getcwd()))

    log.debug("Parsing and writing cookies data")
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

        cookies_output.write_entry(record.values())



def moduleFirefox(firefox_cookies_location):
    log.debug("Parsing Firefox cookies...")

    cookies_headers = ['user','profile','host_key','name','value','path',
                        'creation_utc','expires_utc','last_access_utc','is_secure',
                        'is_httponly','browser_element',"same_site"]
    cookies_output = data_writer('browser_firefox_cookies', cookies_headers)

    for c in firefox_cookies_location:
        userpath = c.split('/')
        userindex = len(userpath) - 1 - userpath[::-1].index('Users') + 1
        user = userpath[userindex]

        profileindex = userpath.index('Profiles') + 1
        profile = userpath[profileindex]

        log.debug("Starting parsing for Firefox cookies under {0} user.".format(user))

        cookies_db = connect_to_db(os.path.join(c, 'cookies.sqlite'))

        if cookies_db:
            pull_firefox_cookies(cookies_db, user, profile, cookies_output, cookies_headers)
        try:
            os.remove(os.path.join(outputdir, 'cookies.sqlite-tmp'))
            os.remove(os.path.join(outputdir, 'cookies.sqlite-tmp-shm'))
            os.remove(os.path.join(outputdir, 'cookies.sqlite-tmp-wal'))
        except OSError:
            pass

    log.debug("Finished parsing Firefox cookies.")

def moduleChrome(chrome_cookies_location):
    log.debug("Parsing Chrome cookies...")

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


        log.debug("Starting parsing for Chrome cookies under {0} user.".format(user))

        get_chrome_version(os.path.join(profile, 'Cookies'))
        cookies_db = connect_to_db(os.path.join(profile, 'Cookies'))

        if cookies_db:
            pull_chrome_cookies(cookies_db, user, profile, cookies_output, cookies_headers)
        try:
            os.remove(os.path.join(outputdir, 'Cookies-tmp'))
        except OSError:
            pass
    log.debug("Finished parsing Chrome cookies.")

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
