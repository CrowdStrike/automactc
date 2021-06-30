"""A module intended to read and parse .*_history and .bash_sessions
files for each user on the machine, including the root user.
"""

import logging
import io
import sys
from collections import OrderedDict

# IMPORT STATIC VARIABLES FROM MAIN
from __main__ import (archive, data_writer, forensic_mode, full_prefix,
                      inputdir, no_tarball, outputdir, quiet, startTime)

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from .common.functions import multiglob, stats2

_modName = __name__.split('_')[-1]
_modVers = '1.0.3'
log = logging.getLogger(_modName)


def module():
    _headers = ['mtime', 'atime', 'ctime', 'btime',
                'src_file', 'user', 'item_index', 'cmd']
    output = data_writer(_modName, _headers)

    user_inputdir = multiglob(inputdir, ['Users/*/.*_history', 'Users/*/.bash_sessions/*',
                               'private/var/*/.*_history', 'private/var/*/.bash_sessions/*',])

    # Generate debug messages indicating users with history files to be parsed.
    userlist = []
    for file in user_inputdir:
        userpath = file.split('/')
        if 'Users' in userpath:
            userindex = len(userpath) - 1 - userpath[::-1].index('Users') + 1
        else:
            userindex = len(userpath) - 1 - userpath[::-1].index('var') + 1
        user = userpath[userindex]

        userlist.append(user)

    for u in list(set(userlist)):
        log.debug("Going to parse bash and other history under {0} user.".format(u))

    # Parse history files found.
    for file in user_inputdir:
        # Get username from path.
        userpath = file.split('/')
        if 'Users' in userpath:
            userindex = len(userpath) - 1 - userpath[::-1].index('Users') + 1
        else:
            userindex = len(userpath) - 1 - userpath[::-1].index('var') + 1
        user = userpath[userindex]

        # Parse the files.
        out = stats2(file)
        if sys.version_info[0] < 3:
            sess = io.open(file, 'r', encoding='ascii', errors='ignore').readlines()
        else:
            sess = open(file, 'r', encoding='ascii', errors="surrogateescape").readlines()
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
            output.write_record(record)
        output.flush_record()

if __name__ == "__main__":
    print("This is an AutoMacTC module, and is not meant to be run stand-alone.")
    print("Exiting.")
    sys.exit(0)
else:
    module()
