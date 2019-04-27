#!/usr/bin/env python

'''
@ author: Kshitij Kumar
@ email: kshitijkumar14@gmail.com, kshitij.kumar@crowdstrike.com

@ purpose:

A module intended to enumerate both deleted and current user profiles on
the system. This module will also determine the last logged in user,
and identify administrative users.

'''
import os
import glob
import traceback
import subprocess
from collections import OrderedDict
from dateutil import parser

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from automactc.modules.common.base import AutoMacTCModule
from automactc.modules.common.functions import stats2
from automactc.modules.common.functions import read_bplist
from automactc.utils.output import DataWriter


class UsersModule(AutoMacTCModule):
    # TODO: Investigate if additional data is in /Users/DeletedUsers? folder,
    # 		or the deleted users may remain in the Users folder but be deleted as an account
    _mod_filename = __name__

    _headers = [
        'mtime', 'atime', 'ctime', 'btime', 'date_deleted', 'uniq_id',
        'user', 'real_name', 'admin', 'lastloggedin_user'
    ]

    def run(self):
        output = DataWriter(self.module_name(), self._headers, self.log, self.run_id, self.options)

        # Parse the com.apple.preferences.accounts.plist to identify deleted accounts.
        _deletedusers_plist = os.path.join(self.options.inputdir, 'Library/Preferences/com.apple.preferences.accounts.plist')
        if not os.path.exists(_deletedusers_plist):
            self.log.debug("File not found: {0}".format(_deletedusers_plist))
            _deletedusers = []
        else:
            try:
                _deletedusers = read_bplist(_deletedusers_plist)[0]['deletedUsers']
            except Exception:
                self.log.debug("Could not parse: {0}".format(_deletedusers_plist))
                _deletedusers = []

        for i in range(len(_deletedusers)):
            record = OrderedDict((h, '') for h in self._headers)
            record['date_deleted'] = parser.parse(str(_deletedusers[i]['date'])).strftime('%Y-%m-%dT%H:%M:%SZ')
            record['uniq_id'] = _deletedusers[i]['dsAttrTypeStandard:UniqueID']
            record['user'] = _deletedusers[i]['name']
            record['real_name'] = _deletedusers[i]['dsAttrTypeStandard:RealName']

        # Enumerate users still active on disk.
        _liveusers_plists = os.path.join(self.options.inputdir, 'private/var/db/dslocal/nodes/Default/users/')
        try:
            _liveplists = [i for i in os.listdir(_liveusers_plists) if not i.startswith("_") and i not in ['daemon.plist', 'nobody.plist']]
        except OSError:
            self.log.debug("Could not connect [{0}].".format([traceback.format_exc()]))
            _liveplists = []

        _liveusers = glob.glob((os.path.join(self.options.inputdir, 'Users/*')))
        _liveusers.append(os.path.join(self.options.inputdir, "var/root"))

        _admins = os.path.join(self.options.inputdir, 'private/var/db/dslocal/nodes/Default/groups/admin.plist')
        if not os.path.exists(_admins):
            self.log.debug("File not found: {0}".format(_admins))
            self.log.error("Could not determine admin users.")
            admins = []
        else:
            try:
                admins = list(read_bplist(_admins)[0]['users'])
            except Exception:
                try:
                    # dscl . -read /Groups/admin GroupMembership
                    admin_users, e = subprocess.Popen(["dscl", ".", "-read", "/Groups/admin", "GroupMembership"], stdout=subprocess.PIPE).communicate()
                    admins = admin_users.split()[1:]
                except:
                    admins = []
                    self.log.debug("Could not parse: {0}".format(_admins))
                    self.log.error("Could not determine admin users.")

        _loginwindow = os.path.join(self.options.inputdir, 'Library/Preferences/com.apple.loginwindow.plist')
        if not os.path.exists(_loginwindow):
            self.log.debug("File not found: {0}".format(_loginwindow))
        else:
            try:
                lastuser = read_bplist(_loginwindow)[0]['lastUserName']
            except Exception:
                lastuser = ""
                self.log.debug("Could not parse: {0}".format(_loginwindow))
                self.log.error("Could not determine last logged in user.")

        for user_path in _liveusers:
            user_home = os.path.basename(user_path)
            if user_home not in ['.localized', 'Shared']:
                record = OrderedDict((h, '') for h in self._headers)
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
                elif 'Volumes' not in self.options.inputdir and self.options.forensic_mode != 'True':
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
