#!/usr/bin/env python

'''
@ author: Kshitij Kumar
@ email: kshitijkumar14@gmail.com, kshitij.kumar@crowdstrike.com

@ purpose:

A module intended to read and parse .*_history and .bash_sessions
files for each user on the machine, including the root user.

'''

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from common.functions import stats2

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

import sys
import os
import csv
import glob
import logging
from collections import OrderedDict

_modName = __name__.split('_')[-2]
_modVers = '.'.join(list(__name__.split('_')[-1][1:]))
log = logging.getLogger(_modName)


def module():
    _headers = ['mtime', 'atime', 'ctime', 'btime',
                'src_file', 'user', 'item_index', 'cmd']
    output = data_writer(_modName, _headers)

    user_inputdir = glob.glob(os.path.join(inputdir, "Users/*"))
    user_inputdir.append(os.path.join(inputdir, "var/root"))

    for user_home in user_inputdir:
        # Get username from path.
        user = os.path.basename(user_home)

        # Get all _history files in root of user directory.
        bash_loc = os.path.join(user_home, '.*_history')
        u_bash = glob.glob(bash_loc)
        if len(u_bash) == 0:
            log.debug("Files not found in: {0}".format(bash_loc))
            

        # Get all bash_sessions files .bash_sessions directory.
        bash_sess_loc = os.path.join(user_home, '.bash_sessions/*')
        u_bash_sess = glob.glob(bash_sess_loc)
        if len(u_bash_sess) == 0:
            log.debug("Files not found in: {0}".format(bash_sess_loc))
            

        # Combine all files into a list and parse them iteratively.
        if len(u_bash) != 0 or len(u_bash_sess) != 0:
            u_bash_all = u_bash + u_bash_sess

            for sess in u_bash_all:
                out = stats2(sess)
                sess = open(sess, 'r').readlines()
                indexer = 0
                for line in sess:
                    record = OrderedDict((h, '') for h in _headers)

                    for i in _headers:
                        if i in out:
                            record[i] = out[i]
                            record['src_file'] = out['name']

                    record['user'] = user
                    record['cmd'] = line.rstrip()
                    indexer += 1
                    record['item_index'] = indexer
                    output.write_entry(record.values())


if __name__ == "__main__":
    print "This is an AutoMacTC module, and cannot be run stand-alone."
    print "Exiting."
    sys.exit(0)
else:
    module()