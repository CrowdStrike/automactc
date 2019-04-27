#!/usr/bin/env python

'''
@ author: Kshitij Kumar
@ email: kshitijkumar14@gmail.com, kshitij.kumar@crowdstrike.com

@ purpose:

A module intended to read and parse .*_history and .bash_sessions
files for each user on the machine, including the root user.

'''
import os
import glob
from collections import OrderedDict

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from automactc.modules.common.base import AutoMacTCModule
from automactc.modules.common.functions import stats2
from automactc.utils.output import DataWriter


class BashModule(AutoMacTCModule):
    _mod_filename = __name__

    _headers = [
        'mtime', 'atime', 'ctime', 'btime',
        'src_file', 'user', 'item_index', 'cmd'
    ]

    def run(self):
        output = DataWriter(self.module_name(), self._headers, self.log, self.run_id, self.options)

        user_inputdir = glob.glob(os.path.join(self.options.inputdir, "Users/*"))
        user_inputdir.append(os.path.join(self.options.inputdir, "var/root"))

        for user_home in user_inputdir:
            # Get username from path.
            user = os.path.basename(user_home)

            # Get all _history files in root of user directory.
            bash_loc = os.path.join(user_home, '.*_history')
            u_bash = glob.glob(bash_loc)
            if len(u_bash) == 0:
                self.log.debug("Files not found in: {0}".format(bash_loc))


            # Get all bash_sessions files .bash_sessions directory.
            bash_sess_loc = os.path.join(user_home, '.bash_sessions/*')
            u_bash_sess = glob.glob(bash_sess_loc)
            if len(u_bash_sess) == 0:
                self.log.debug("Files not found in: {0}".format(bash_sess_loc))


            # Combine all files into a list and parse them iteratively.
            if len(u_bash) != 0 or len(u_bash_sess) != 0:
                u_bash_all = u_bash + u_bash_sess

                for sess in u_bash_all:
                    out = stats2(sess)
                    sess = open(sess, 'r').readlines()
                    indexer = 0
                    for line in sess:
                        record = OrderedDict((h, '') for h in self._headers)

                        for i in self._headers:
                            if i in out:
                                record[i] = out[i]
                                record['src_file'] = out['name']

                        record['user'] = user
                        record['cmd'] = line.rstrip()
                        indexer += 1
                        record['item_index'] = indexer
                        output.write_entry(record.values())
