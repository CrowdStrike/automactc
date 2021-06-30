"""A module intended to enumerate both deleted and current user profiles on
the system.

This module will also determine the last logged in user, and identify
administrative users.
"""

import glob
import logging
import os
import subprocess
import sys
import traceback
from collections import OrderedDict

# IMPORT STATIC VARIABLES FROM MAIN
from __main__ import (archive, data_writer, forensic_mode, full_prefix,
                      inputdir, no_tarball, outputdir, quiet, startTime)

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from .common.dateutil import parser
from .common.functions import read_bplist, stats2

_modName = __name__.split('_')[-1]
_modVers = '1.1.1'

_modNameVer = '{0}_v{1}'.format(_modName, _modVers.replace('.', ''))
log = logging.getLogger(_modNameVer)

# TODO: Investigate if additional data is in /Users/DeletedUsers? folder,
# 		or the deleted users may remain in the Users folder but be deleted as an account


def module():
    headers = ['mtime', 'atime', 'ctime', 'btime', 'date_deleted', 'uniq_id', 'user', 'real_name', 'admin', 'lastloggedin_user']
    output = data_writer(_modName, headers)

    # Parse the com.apple.preferences.accounts.plist to identify deleted accounts.
    _deletedusers_plist = os.path.join(inputdir, 'Library/Preferences/com.apple.preferences.accounts.plist')
    log.debug("Getting deleted users metadata.")
    if not os.path.exists(_deletedusers_plist):
        log.debug("File not found: {0}".format(_deletedusers_plist))
        _deletedusers = []
    else:
        try:
            _deletedusers = read_bplist(_deletedusers_plist)[0]['deletedUsers']
        except Exception:
            log.debug("Could not parse: {0}".format(_deletedusers_plist))
            _deletedusers = []

    for i in range(len(_deletedusers)):
        record = OrderedDict((h, '') for h in headers)
        record['date_deleted'] = parser.parse(str(_deletedusers[i]['date'])).strftime('%Y-%m-%dT%H:%M:%SZ')
        record['uniq_id'] = _deletedusers[i]['dsAttrTypeStandard:UniqueID']
        record['user'] = _deletedusers[i]['name']
        record['real_name'] = _deletedusers[i]['dsAttrTypeStandard:RealName']

        output.write_record(record)

    # Try to determine admin users on the system.
    _admins = os.path.join(inputdir, 'private/var/db/dslocal/nodes/Default/groups/admin.plist')
    log.debug("Getting admin users metadata.")
    try:
        # Should work on forensic images and live systems under Mojave.
        admins = list(read_bplist(_admins)[0]['users'])
    except Exception:
        log.debug("Could not access dslocal: [{0}].".format([traceback.format_exc()]))
        if not forensic_mode:
            try:
                log.debug("Trying DSCL to obtain admin users as input is live system.")
                admin_users, e = subprocess.Popen(["dscl", ".", "-read", "/Groups/admin", "GroupMembership"], stdout=subprocess.PIPE).communicate()
                admins = admin_users.split()[1:]
            except Exception:
                admins = []
                log.debug("Could not parse: {0}".format(_admins))
                log.error("Could not determine admin users.")
        else:
            log.error('Could not determine admin users from forensic image.')
            admins = []

    # Enumerate users still active on disk in /Users and /private/var off live/dead disks.
    log.debug("Enumerating user directories on disk.")
    _liveusers = glob.glob((os.path.join(inputdir, 'Users/*')))
    _privateusers = glob.glob((os.path.join(inputdir, 'private/var/*')))

    not_users = ['.localized', 'Shared', 'agentx', 'at', 'audit', 'backups', 'db', 'empty',
                 'folders', 'install', 'jabberd', 'lib', 'log', 'mail', 'msgs', 'netboot',
                 'networkd', 'rpc', 'run', 'rwho', 'spool', 'tmp', 'vm', 'yp', 'ma']

    _allpossibleusers = [i for i in _liveusers + _privateusers if os.path.basename(i) not in not_users]

    # Enumerate all user plists in from either /private/var/db/dslocal/nodes or via dscl command.
    log.debug("Enumerating user profiles.")
    only_user_dirs = False
    try:
        # This should work on forensic images and live systems under Mojave.
        _userplists = glob.glob(os.path.join(inputdir, 'private/var/db/dslocal/nodes/Default/users/*'))
        users_dict = {}
        for plist in _userplists:
            i_plist_array = read_bplist(plist)[0]
            users_dict[i_plist_array['name'][0]] = {'uid': i_plist_array['uid'][0], 'real_name': i_plist_array['realname'][0]}
    except OSError:
        log.debug("Could not access dslocal: [{0}].".format([traceback.format_exc()]))
        users_dict = {}
    except Exception:
        log.debug("Could not access dslocal [{0}].".format([traceback.format_exc()]))
        users_dict = {}

    # For live systems Mojave and above, use dscl to get the same dict.
    if not forensic_mode and len(users_dict) == 0:
        user_ids, e = subprocess.Popen(["dscl", ".", "-list", "Users", "UniqueID"], stdout=subprocess.PIPE).communicate()
        for i in user_ids.decode('utf-8').split('\n'):
            data = i.split(' ')
            users_dict[data[0]] = {'uid': data[-1], 'real_name': ''}

        user_names, e = subprocess.Popen(["dscl", ".", "-list", "Users", "RealName"], stdout=subprocess.PIPE).communicate()
        for i in user_names.decode('utf-8').split('\n'):
            data = i.split(' ')
            users_dict[data[0]]['real_name'] = ' '.join(filter(None, data[1:]))
    elif forensic_mode and len(users_dict) == 0:
        # If running in forensic mode and there was still an error accessing dslocal, operate only with the paths for each user.
        users_dict = {}
        only_user_dirs = True

    users_dict.pop('', None)

    # Get last logged in user on system.
    log.debug("Getting last logged in user metadata.")
    _loginwindow = os.path.join(inputdir, 'Library/Preferences/com.apple.loginwindow.plist')
    if not os.path.exists(_loginwindow):
        log.debug("File not found: {0}".format(_loginwindow))
    else:
        try:
            lastuser = read_bplist(_loginwindow)[0]['lastUserName']
        except Exception:
            lastuser = ""
            log.debug("Could not parse: {0}".format(_loginwindow))
            log.error("Could not determine last logged in user.")

    # Iterate through all users identified with folders on disk and output their records.
    log.debug("Iterating through user directories on disk for metadata.")
    for user_path in _allpossibleusers:
        username = os.path.basename(user_path)
        if username not in users_dict:
            continue

        record = OrderedDict((h, '') for h in headers)
        oMACB = stats2(user_path, oMACB=True)
        record.update(oMACB)
        record['user'] = username

        try:
            record['uniq_id'] = users_dict[username]['uid']
            record['real_name'] = users_dict[username]['real_name']
        except KeyError:
            log.debug("Found path {0} for possible user {1}, but no record found associated with this user.".format(user_path, username))

        if username in admins:
            record['admin'] = 'Yes'

        if username == lastuser:
            record['lastloggedin_user'] = 'Yes'

        # Remove users from the broader dict that have already been parsed because they had folders on disk.
        users_dict.pop(username, None)

        output.write_record(record)

    if only_user_dirs:
        log.debug("Iterating only through /User directories on disk for metadata due to dslocal errors in forensic mode.")
        for user_path in _allpossibleusers:
            username = os.path.basename(user_path)

            record = OrderedDict((h, '') for h in headers)
            oMACB = stats2(user_path, oMACB=True)
            record.update(oMACB)
            record['user'] = username

            users_dict.pop(username, None)
            output.write_record(record)

    # Iterate through any remaining users identified with DSCL or the plist files that did not have directories found on disk.
    log.debug("Iterating through users with no directories on disk.")
    for username, userdata in users_dict.items():
        record = OrderedDict((h, '') for h in headers)
        record['user'] = username
        record['uniq_id'] = userdata['uid']
        record['real_name'] = userdata['real_name']

        output.write_record(record)
    output.flush_record()


if __name__ == "__main__":
    print("This is an AutoMacTC module, and is not meant to be run stand-alone.")
    print("Exiting.")
    sys.exit(0)
else:
    module()
