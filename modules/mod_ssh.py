"""A module intended to read and parse SSH known_hosts and authorized_keys
files for each user on disk.
"""

import glob
import logging
import os
import subprocess
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
    known_hosts_headers = ['src_name', 'user', 'bits', 'fingerprint', 'host', 'keytype']
    output = data_writer(_modName, known_hosts_headers)

    user_inputdir = multiglob(inputdir, ["Users/*/.ssh", "private/var/*/.ssh"])

    record = OrderedDict((h, '') for h in known_hosts_headers)

    for user_home in user_inputdir:
        record['user'] = user_home.split('/')[-2]

        # Gather known_hosts and authorized_users files for the user.
        kh_path = os.path.join(user_home, 'known_hosts')
        u_knownhosts = glob.glob(kh_path)

        ak_path = os.path.join(user_home, 'authorized_keys')
        u_authorizedkeys = glob.glob(ak_path)

        # Combine all files found into one list per user.
        u_ssh_all = u_knownhosts + u_authorizedkeys

        # Define the directory checked for use in debug messages.
        user_ssh_dir = os.path.join(user_home, '.ssh/')

        # Generate debug messages for files not found.
        if len(u_knownhosts) == 0:
            log.debug("File not found: {0}".format(kh_path))
        if len(u_authorizedkeys) == 0:
            log.debug("File not found: {0}".format(ak_path))

        # Iterate over files found and parse them using ssh-keygen.
        for file in u_ssh_all:
            p, e = subprocess.Popen(["ssh-keygen", "-l", "-f", file], stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()
            record['src_name'] = os.path.basename(file)

            if not e and not "is not a public key file" in p.decode('utf-8'):
                p = p.decode('utf-8').split('\n')
                p = [x for x in p if len(x) > 0]
                for i in p:
                    data = i.split(' ')
                    record['bits'] = data[0]
                    record['fingerprint'] = data[1]
                    record['host'] = data[2]
                    record['keytype'] = data[3]

                    output.write_record(record)

            elif "is not a public key file" in p:
                log.debug("Could not parse {0}: {1}".format(file, p))

    output.flush_record()


if __name__ == "__main__":
    print("This is an AutoMacTC module, and is not meant to be run stand-alone.")
    print("Exiting.")
    sys.exit(0)
else:
    module()
