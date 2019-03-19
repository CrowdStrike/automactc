#!/usr/bin/env python

'''
@ author: Kshitij Kumar
@ email: kshitijkumar14@gmail.com, kshitij.kumar@crowdstrike.com

@ purpose:

A module intended to enumerate both deleted and current user profiles on
the system. This module will also determine the last logged in user, 
and identify administrative users.

'''

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from common.functions import stats2
from common.functions import read_bplist

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


import csv
import os
import logging
import glob
import traceback
import subprocess
from dateutil import parser
from collections import OrderedDict

_modName = __name__.split('_')[-2]
_modVers = '.'.join(list(__name__.split('_')[-1][1:]))

_modNameVer = '{0}_v{1}'.format(_modName, _modVers.replace('.', ''))
log = logging.getLogger(_modNameVer)

# TODO: Investigate if additional data is in /Users/DeletedUsers? folder,
# 		or the deleted users may remain in the Users folder but be deleted as an account


def module():
    headers = ['mtime', 'atime', 'ctime', 'btime', 'date_deleted', 'uniq_id', 'user', 'real_name', 'admin', 'lastloggedin_user']
    output = data_writer(_modName, headers)

    # Parse the com.apple.preferences.accounts.plist to identify deleted accounts.
    _deletedusers_plist = os.path.join(inputdir, 'Library/Preferences/com.apple.preferences.accounts.plist')
    if not os.path.exists(_deletedusers_plist):
        log.debug("File not found: {0}".format(_deletedusers_plist))
        _deletedusers = []
    else:
        try:
            _deletedusers = read_bplist(_deletedusers_plist)[0]['deletedUsers']
        except Exception, e:
            log.debug("Could not parse: {0}".format(_deletedusers_plist))
            _deletedusers = []

    for i in range(len(_deletedusers)):
        record = OrderedDict((h, '') for h in headers)
        record['date_deleted'] = parser.parse(str(_deletedusers[i]['date'])).strftime('%Y-%m-%dT%H:%M:%SZ')
        record['uniq_id'] = _deletedusers[i]['dsAttrTypeStandard:UniqueID']
        record['user'] = _deletedusers[i]['name']
        record['real_name'] = _deletedusers[i]['dsAttrTypeStandard:RealName']

        output.write_entry(record.values())

    # Enumerate users still active on disk.
    _liveusers_plists = os.path.join(inputdir, 'private/var/db/dslocal/nodes/Default/users/')
    try:
        _liveplists = [i for i in os.listdir(_liveusers_plists) if not i.startswith("_") and i not in ['daemon.plist', 'nobody.plist']]
    except OSError:
        log.debug("Could not connect [{0}].".format([traceback.format_exc()]))
        _liveplists = []

    _liveusers = glob.glob((os.path.join(inputdir, 'Users/*')))
    _liveusers.append(os.path.join(inputdir, "var/root"))

    _admins = os.path.join(inputdir, 'private/var/db/dslocal/nodes/Default/groups/admin.plist')
    if not os.path.exists(_admins):
        log.debug("File not found: {0}".format(_admins))
    else:
        try:
            admins = list(read_bplist(_admins)[0]['users'])
            foo
        except Exception, e:
            try:
                # dscl . -read /Groups/admin GroupMembership
                admin_users, e = subprocess.Popen(["dscl", ".", "-read", "/Groups/admin", "GroupMembership"], stdout=subprocess.PIPE).communicate()
                admins = admin_users.split()[1:]
            except:
                admins = []
                log.debug("Could not parse: {0}".format(_admins))

    _loginwindow = os.path.join(inputdir, 'Library/Preferences/com.apple.loginwindow.plist')
    if not os.path.exists(_loginwindow):
        log.debug("File not found: {0}".format(_loginwindow))
    else:
        try:
            lastuser = read_bplist(_loginwindow)[0]['lastUserName']
        except Exception, e:
            lastuser = ""
            log.debug("Could not parse: {0}".format(_loginwindow))

    for user_path in _liveusers:
        user_home = os.path.basename(user_path)
        if user_home not in ['.localized', 'Shared']:
            record = OrderedDict((h, '') for h in headers)
            oMACB = stats2(user_path, oMACB=True)
            record.update(oMACB)
            if user_home in admins:
                record['admin'] = 'Yes'
            if user_home == lastuser:
                record['lastloggedin_user'] = 'Yes'

            _liveplists = []
            record['user'] = user_home
            if len(_liveplists) > 0:
                i_plist = user_home + '.plist'
                if i_plist in _liveplists:
                    i_plist_array = read_bplist(os.path.join(_liveusers_plists, i_plist))[0]
                    record['uniq_id'] = i_plist_array['uid'][0]
                    record['real_name'] = i_plist_array['realname'][0]
            elif 'Volumes' not in inputdir and forensic_mode != 'True':
                user_ids, e = subprocess.Popen(["dscl", ".", "-list", "Users", "UniqueID"], stdout=subprocess.PIPE).communicate()
                for i in user_ids.split('\n'):
                    data = i.split(' ')
                    if record['user'] == data[0]:
                        record['uniq_id'] = data[-1]

                real_name, e = subprocess.Popen(["finger", record['user']], stdout=subprocess.PIPE, stderr=open(os.devnull, 'w')).communicate()
                names = [i for i in real_name.split('\n') if i.startswith("Login: ")]
                for i in names:
                    if ' '+record['user'] in i:
                        r_name =[i for i in i.split('\t') if i.startswith('Name: ')][0].split()[1:]
                        record['real_name'] = ' '.join(r_name)
            
            output.write_entry(record.values())


if __name__ == "__main__":
    print "This is an AutoMacTC module, and is not meant to be run stand-alone."
    print "Exiting."
    sys.exit(0)
else:
    module()
