"""A module intended to enumerate a variety of autostart locations for
plist configuration files, parse them, and check code signatures on the
programs that are ultimate run on login or system startup.
"""

import ast
import hashlib
import logging
import os
import plistlib
import sys
import traceback
from collections import OrderedDict

# IMPORT STATIC VARIABLES FROM MAIN
from __main__ import (archive, data_writer, forensic_mode, full_prefix,
                      hash_alg, hash_size_limit, inputdir, no_code_signatures,
                      no_tarball, outputdir, quiet, startTime)

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from .common.functions import (get_codesignatures, multiglob, read_bplist,
                               stats2)
from .common.mac_alias import Bookmark

_modName = __name__.split('_')[-1]
_modVers = '1.0.3'
log = logging.getLogger(_modName)

ncs = no_code_signatures

# determine which hashing algorithms to run
if type(hash_alg) is list:
    hash_alg = [''.join([x.lower() for x in i]) for i in hash_alg]
elif type(hash_alg) is str:
    hash_alg = [hash_alg]


class BplistError(Exception):
    pass

def shasum(filename, filesize, block_size=65536):
    """
    Returns the string representation of the sha256 of a file. Assumes file exists.
    """
    if filesize <= hash_size_limit and filesize > 0:
        sha256 = hashlib.sha256()
        try:
            with open(filename, 'rb') as f:
                for block in iter(lambda: f.read(block_size), b''):
                    sha256.update(block)
            sha256 = sha256.hexdigest()
        except Exception:
            sha256 = 'ERROR'
    else:
        sha256 = ''
    return sha256


def md5sum(filename, filesize, block_size=65536):
    """
    Returns the string representation of the md5 of a file. Assumes file exists.
    """
    if filesize <= hash_size_limit and filesize > 0:
        md5 = hashlib.md5()
        try:
            with open(filename, 'rb') as f:
                for block in iter(lambda: f.read(block_size), b''):
                    md5.update(block)
            md5 = md5.hexdigest()
        except Exception:
            md5 = 'ERROR'
    else:
        md5 = ''
    return md5

def get_hashes(filepath, hash_alg):
    """
    Returns the hashes specified in the list hash_alg for the file at filepath.
    """
    hashes = {'sha256': '', 'md5': ''}
    if "none" not in hash_alg:
        size = stats2(filepath)['size']
        if size == "ERROR":
            return hashes
        if 'sha256' in hash_alg:
            try:
                hashes['sha256'] = shasum(filepath, size)
            except Exception:
                log.debug("Could not hash {0}: {1}".format(filepath, [traceback.format_exc()]))
                hashes['sha256'] = 'ERROR'
        if 'md5' in hash_alg:
            try:
                hashes['md5'] = md5sum(filepath, size)
            except Exception:
                log.debug("Could not hash {0}: {1}".format(filepath, [traceback.format_exc()]))
                hashes['md5'] = 'ERROR'
    return hashes

def parse_sandboxed_loginitems(headers, output):
    sandboxed_loginitems = multiglob(inputdir, ['var/db/com.apple.xpc.launchd/disabled.*.plist'])

    for i in sandboxed_loginitems:
        record = OrderedDict((h, '') for h in headers)
        metadata = stats2(i, oMACB=True)
        record.update(metadata)
        record['src_file'] = i
        record['src_name'] = "sandboxed_loginitems"

        try:
            if sys.version_info[0] < 3:
                p = plistlib.readPlist(i)
            else:
                with open(i, 'rb') as f:
                    p = plistlib.load(f)
        except Exception:
            try:
                p = read_bplist(i)
            except Exception:
                log.debug('Could not read plist {0}: {1}'.format(i, [traceback.format_exc()]))
                p = 'ERROR'

        if p != 'ERROR':
            for k, v in p.items():
                if v is False:
                    record['prog_name'] = k
                    output.write_record(record)
        else:
            errors = {k: 'ERROR-CNR-PLIST' for k, v in record.items() if v == ''}
            record.update(errors)


def parse_cron(headers, output):
    cron = multiglob(inputdir, ['private/var/at/tabs/*'])

    for i in cron:
        record = OrderedDict((h, '') for h in headers)
        metadata = stats2(i, oMACB=True)
        record.update(metadata)
        record['src_file'] = i
        record['src_name'] = "cron"

        with open(i, 'r') as crontab:
            jobs = [c.rstrip() for c in crontab.readlines() if not c.startswith("# ")]
            for job in jobs:
                record['program'] = job
                output.write_record(record)


def parse_LaunchAgentsDaemons(headers, output):
    LaunchAgents = multiglob(inputdir, ['System/Library/LaunchAgents/*.plist', 'Library/LaunchAgents/*.plist', 'Users/*/Library/LaunchAgents/*.plist', 'private/var/*/Library/LaunchAgents/*.plist',
                                        'System/Library/LaunchAgents/.*.plist', 'Library/LaunchAgents/.*.plist', 'Users/*/Library/LaunchAgents/.*.plist', 'private/var/*/Library/LaunchAgents/.*.plist'])
    LaunchDaemons = multiglob(inputdir, ['System/Library/LaunchDaemons/*.plist', 'Library/LaunchDaemons/*.plist',
                                         'System/Library/LaunchDaemons/.*.plist', 'Library/LaunchDaemons/.*.plist'])

    for i in LaunchDaemons + LaunchAgents:

        record = OrderedDict((h, '') for h in headers)
        metadata = stats2(i, oMACB=True)
        record.update(metadata)
        record['src_file'] = i
        record['src_name'] = "launch_items"

        try:
            if sys.version_info[0] < 3:
                p = plistlib.readPlist(i)
            else:
                with open(i, 'rb') as f:
                    p = plistlib.load(f)
        except Exception:
            try:
                p = read_bplist(i)
            except Exception:
                log.debug('Could not read plist {0}: {1}'.format(i, [traceback.format_exc()]))
                p = 'ERROR'

        if p != 'ERROR':
            if type(p) is list and len(p) > 0:
                p = p[0]

            # Try to get Label from each plist.
            try:
                record['prog_name'] = p['Label']
            except KeyError:
                log.debug("Cannot extract 'Label' from plist: {0}".format(i))
                record['prog_name'] = 'ERROR'

            # Try to get ProgramArguments if present, or Program, from each plist.
            if 'Program' in p and 'ProgramArguments' in p:
                prog_args = p['ProgramArguments']
                program = p['Program']
                record['program'] = program

                if len(prog_args) > 1:
                    record['args'] = ' '.join(p['ProgramArguments'][1:])
            else:
                try:
                    prog_args = p['ProgramArguments']
                    program = p['ProgramArguments'][0]
                    record['program'] = program

                    if len(prog_args) > 1:
                        record['args'] = ' '.join(p['ProgramArguments'][1:])
                except (KeyError, IndexError):
                    try:
                        program = p['Program']
                        record['program'] = program
                    except Exception:
                        log.debug("Cannot extract 'Program' or 'ProgramArguments' from plist: {0}".format(i))
                        program = None
                        record['program'] = 'ERROR'
                        record['args'] = 'ERROR'
                except Exception:
                    log.debug('Could not parse plist {0}: {1}'.format(i, [traceback.format_exc()]))
                    program = None

            # If program is ID'd, run additional checks.
            if program:
                cs_check_path = os.path.join(inputdir, program.lstrip('/'))
                record['code_signatures'] = str(get_codesignatures(cs_check_path, ncs))

                hashset = get_hashes(program, hash_alg)
                record['sha256'] = hashset['sha256']
                record['md5'] = hashset['md5']

        else:
            errors = {k: 'ERROR-CNR-PLIST' for k, v in record.items() if v == ''}
            record.update(errors)

        output.write_record(record)


def parse_ScriptingAdditions(headers, output):
    ScriptingAdditions = multiglob(inputdir, ['System/Library/ScriptingAdditions/*.osax', 'Library/ScriptingAdditions/*.osax',
                                              'System/Library/ScriptingAdditions/.*.osax', 'Library/ScriptingAdditions/.*.osax'])

    for i in ScriptingAdditions:
        record = OrderedDict((h, '') for h in headers)
        metadata = stats2(i, oMACB=True)
        record.update(metadata)
        record['src_file'] = i
        record['src_name'] = "scripting_additions"
        record['code_signatures'] = str(get_codesignatures(i, ncs))
        output.write_record(record)


def parse_StartupItems(headers, output):
    StartupItems = multiglob(inputdir, ['System/Library/StartupItems/*/*', 'Library/StartupItems/*/*'])

    for i in StartupItems:
        record = OrderedDict((h, '') for h in headers)
        metadata = stats2(i, oMACB=True)
        record.update(metadata)
        record['src_file'] = i
        record['src_name'] = "startup_items"

        output.write_record(record)


def parse_PeriodicItems_rcItems_emondItems(headers, output):
    PeriodicItems = multiglob(inputdir, ['private/etc/periodic.conf', 'private/etc/periodic/*/*', 'private/etc/*.local'])
    rcItems = multiglob(inputdir, ['private/etc/rc.common'])
    emondItems = multiglob(inputdir, ['private/etc/emond.d/*', 'private/etc/emond.d/*/*'])

    for i in PeriodicItems + rcItems + emondItems:
        record = OrderedDict((h, '') for h in headers)
        metadata = stats2(i, oMACB=True)
        record.update(metadata)
        record['src_file'] = i
        record['src_name'] = "periodic_rules_items"

        output.write_record(record)


def parse_loginitems(headers, output):
    user_loginitems_plist = multiglob(inputdir, ['Users/*/Library/Preferences/com.apple.loginitems.plist', 'private/var/*/Library/Preferences/com.apple.loginitems.plist'])

    for i in user_loginitems_plist:
        record = OrderedDict((h, '') for h in headers)
        metadata = stats2(i, oMACB=True)
        record.update(metadata)
        record['src_file'] = i
        record['src_name'] = "login_items"

        try:
            if sys.version_info[0] < 3:
                p = plistlib.readPlist(i)
            else:
                with open(i, 'rb') as f:
                    p = plistlib.load(f)
        except Exception:
            try:
                p = read_bplist(i)
            except Exception:
                log.debug('Could not read plist {0}: {1}'.format(i, [traceback.format_exc()]))
                p = 'ERROR'

        if p != 'ERROR':
            items = p[0]['SessionItems']['CustomListItems']
            for i in items:
                record['prog_name'] = i['Name']
                if 'Alias' in i:
                    try:
                        alias_bin = i['Alias']
                    except Exception:
                        alias_bin = 'ERROR'

                    if alias_bin != 'ERROR':
                        c = [i.encode('hex') for i in alias_bin]
                        for i in range(len(c)):
                            l = int(c[i], 16)
                            if l < len(c) and l > 2:
                                test = os.path.join(inputdir, (''.join(c[i + 1:i + l + 1])).decode('hex'))
                                try:
                                    if not os.path.exists(test):
                                        continue
                                    else:
                                        record['program'] = test
                                        cs_check_path = os.path.join(inputdir, test.lstrip('/'))
                                        record['code_signatures'] = str(get_codesignatures(cs_check_path, ncs))

                                except Exception:
                                    record['program'] = 'ERROR'
                                    record['code_signatures'] = 'ERROR'
                                    continue

                elif 'Bookmark' in i:
                    try:
                        bookmark_bin = i['Bookmark']
                    except Exception:
                        bookmark_bin = 'ERROR'

                    if bookmark_bin != 'ERROR':
                        program = [i.encode('hex') for i in bookmark_bin]
                        data = Bookmark.from_bytes(''.join(program).decode('hex'))
                        d = data.get(0xf081, default=None)
                        d = ast.literal_eval(str(d).replace('Data', ''))
                        if d is not None:
                            prog = d.split(';')[-1].replace('\x00', '')
                            record['program'] = prog
                            cs_check_path = os.path.join(inputdir, prog.lstrip('/'))
                            record['code_signatures'] = str(get_codesignatures(cs_check_path, ncs))

                output.write_record(record)
        else:
            errors = {k: 'ERROR-CNR-PLIST' for k, v in record.items() if v == ''}
            record.update(errors)


def module():
    headers = ['mtime', 'atime', 'ctime', 'btime', 'src_name', 'src_file', 'prog_name', 'program', 'args', 'code_signatures', 'sha256', 'md5']
    output = data_writer(_modName, headers)

    parse_sandboxed_loginitems(headers, output)
    parse_loginitems(headers, output)
    parse_cron(headers, output)
    parse_LaunchAgentsDaemons(headers, output)
    parse_StartupItems(headers, output)
    parse_ScriptingAdditions(headers, output)
    parse_PeriodicItems_rcItems_emondItems(headers, output)
    output.flush_record()

if __name__ == "__main__":
    print("This is an AutoMacTC module, and is not meant to be run stand-alone.")
    print("Exiting.")
    sys.exit(0)
else:
    module()
