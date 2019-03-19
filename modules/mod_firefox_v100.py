#!/usr/bin/env python

'''
@ author: Kshitij Kumar
@ email: kshitijkumar14@gmail.com, kshitij.kumar@crowdstrike.com

@ purpose:

A module intended to read and parse the Firefox history database for each
user on disk.

'''

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from common.functions import stats2
from common.functions import firefox_time

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
import csv
import glob
import sqlite3
import shutil
import logging
import traceback
import dateutil.parser as parser
from collections import OrderedDict
from ConfigParser import ConfigParser

_modName = __name__.split('_')[-2]
_modVers = '.'.join(list(__name__.split('_')[-1][1:]))
log = logging.getLogger(_modName)


def get_column_headers(db, table):
    col_headers = sqlite3.connect(db).cursor().execute('SELECT * from {0}'.format(table))
    names = list(map(lambda x: x[0], col_headers.description))
    return names


def get_firefox_version(firefox_location):
    verfile = os.path.join(firefox_location, 'compatibility.ini')
    config = ConfigParser()
    config.read(verfile)
    ver = config.get('Compatibility','lastversion')
    log.debug("Firefox Version {0} identified.".format(ver))
    return ver


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


def pull_download_history(history_db, user, profile, downloads_output, downloads_headers):

    desired_columns = ['url', 'content', 'dateAdded']
    available_columns = get_column_headers(history_db,'moz_annos') + get_column_headers(history_db,'moz_places')
    query_columns_list = [i for i in desired_columns if i in available_columns]
    query_columns = ', '.join([i for i in desired_columns if i in available_columns])

    unavailable = ','.join(list(set(desired_columns) - set(query_columns_list)))
    if len(unavailable) > 0:
        log.debug('The following desired columns are not available in the database: {0}'.format(unavailable))

    log.debug("Executing sqlite query for download history...")
    try:
        downloads_data = sqlite3.connect(history_db).cursor().execute(

            'SELECT url,group_concat(content),dateAdded FROM moz_annos \
            LEFT JOIN moz_places ON moz_places.id = moz_annos.place_id \
            GROUP BY place_id'

        ).fetchall()

        log.debug("Success. Found {0} lines of data.".format(len(downloads_data)))

    except sqlite3.OperationalError:
        error = [x for x in traceback.format_exc().split('\n') if x.startswith("OperationalError")]
        log.error('Failed to run query. [{0}]'.format(error[0]))

        return

    log.debug("Parsing and writing downloads data...")
    for item in downloads_data:
        record = OrderedDict((h, '') for h in downloads_headers)
        record['user'] = user
        record['profile'] = profile
        record['download_url'] = item[0]
        record['download_path'] = item[1].split(',')[0]
        record['download_started'] = firefox_time(item[2]).split('.')[0]+'Z'
        record['download_finished'] = firefox_time(int(item[1].split(',')[2].split(':')[1])*1000).split('.')[0]+'Z'
        record['download_totalbytes'] = item[1].split(',')[3].split(':')[1].replace('}','')

        downloads_output.write_entry(record.values())

    log.debug("Done.")


def pull_visit_history(history_db, user, profile, urls_output, urls_headers):

    desired_columns = ['visit_date','title','url','visit_count','typed','last_visit_date','description']
    available_columns = get_column_headers(history_db,'moz_places') + get_column_headers(history_db,'moz_historyvisits')
    query_columns_list = [i for i in desired_columns if i in available_columns]
    query_columns = ', '.join([i for i in desired_columns if i in available_columns])

    unavailable = ','.join(list(set(desired_columns) - set(query_columns_list)))
    if len(unavailable) > 0:
        log.debug('The following desired columns are not available in the database: {0}'.format(unavailable))

    log.debug("Executing sqlite query for visit history...")

    try:
        urls_data = sqlite3.connect(history_db).cursor().execute(

            'SELECT {0} FROM moz_historyvisits left join moz_places \
            on moz_places.id = moz_historyvisits.place_id'.format(query_columns)

        ).fetchall()
        log.debug("Success. Found {0} lines of data.".format(len(urls_data)))

    except sqlite3.OperationalError:
        error = [x for x in traceback.format_exc().split('\n') if x.startswith("OperationalError")]
        log.error('Failed to run query. [{0}]'.format(error[0]))

        return


    log.debug("Parsing and writing visits data...")
    nondict = dict.fromkeys(desired_columns)
    for item in urls_data:
        record = OrderedDict((h, '') for h in urls_headers)
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

        urls_output.write_entry(record.values())

    log.debug("Done.")


def module(firefox_location):

    urls_headers = ['user','profile','visit_time','title','url','visit_count','last_visit_time','typed','description']
    urls_output = data_writer('browser_firefox_history', urls_headers)

    downloads_headers = ['user','profile','download_url','download_path','download_started','download_finished','download_totalbytes']
    downloads_output = data_writer('browser_firefox_downloads', downloads_headers)

    for c in firefox_location:
        userpath = c.split('/')
        userindex = userpath.index('Users') + 1
        user = userpath[userindex]

        profileindex = userpath.index('Profiles') + 1
        profile = userpath[profileindex]

        log.debug("Starting parsing for Firefox under {0} user.".format(user))

        get_firefox_version(c)

        history_db = connect_to_db(os.path.join(c, 'places.sqlite'),'moz_places')

        # If the database cannot be accessed, or if the main table necessary 
        # for parsing (moz_places) is unavailable,
        # fail gracefully. 
        if history_db:
            pull_visit_history(history_db, user, profile, urls_output, urls_headers)
            pull_download_history(history_db, user, profile, downloads_output, downloads_headers)

        try:
            os.remove(os.path.join(outputdir, 'places.sqlite-tmp'))
            os.remove(os.path.join(outputdir, 'places.sqlite-tmp-shm'))
            os.remove(os.path.join(outputdir, 'places.sqlite-tmp-wal'))
        except OSError:
            pass


if __name__ == "__main__":
    print "This is an AutoMacTC module, and is not meant to be run stand-alone."
    print "Exiting."
    sys.exit(0)
else:
    firefox_location = glob.glob(
        os.path.join(inputdir, 'Users/*/Library/Application Support/Firefox/Profiles/*.*'))
    module(firefox_location)