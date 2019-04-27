#!/usr/bin/env python

'''
@ author: Kshitij Kumar
@ email: kshitijkumar14@gmail.com, kshitij.kumar@crowdstrike.com

@ purpose:

A module intended to enumerate a variety of autostart locations for
plist configuration files, parse them, and check code signatures on the
programs that are ultimate run on login or system startup.

'''
import plistlib
import os
import ast
import traceback
import hashlib
from collections import OrderedDict

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from automactc.modules.common.base import AutoMacTCModule
from automactc.modules.common.functions import stats2
from automactc.modules.common.functions import read_bplist
from automactc.modules.common.functions import get_codesignatures
from automactc.modules.common.functions import multiglob
from automactc.modules.common.mac_alias import Bookmark
from automactc.utils.output import DataWriter


class AutoRunsModule(AutoMacTCModule):
    _mod_filename = __name__

    _headers = [
        'mtime', 'atime', 'ctime', 'btime', 'src_name', 'src_file',
        'prog_name', 'program', 'args', 'code_signatures', 'sha256', 'md5'
    ]

    def __init__(self, *args, **kwargs):
        super(AutoRunsModule, self).__init__(*args, **kwargs)
        self._output = DataWriter(self.module_name(), self._headers, self.log, self.run_id, self.options)

    def _shasum(self, filename, filesize, block_size=65536):
        if os.path.isfile(filename) is False:
            sha256 = 'ERROR-FILE-DNE'
            return sha256

        if filesize <= self.options.dir_hash_size_limit and filesize > 0:
            sha256 = hashlib.sha256()
            try:
                with open(filename, 'rb') as f:
                    for block in iter(lambda: f.read(block_size), b''):
                        sha256.update(block)
                sha256 = sha256.hexdigest()
            except IOError:
                sha256 = 'ERROR'
        else:
            sha256 = ''
        return sha256

    def _md5sum(self, filename, filesize, block_size=65536):
        if os.path.isfile(filename) is False:
            sha256 = 'ERROR-FILE-DNE'
            return sha256

        if filesize <= self.options.dir_hash_size_limit and filesize > 0:
            md5 = hashlib.md5()
            try:
                with open(filename, 'rb') as f:
                    for block in iter(lambda: f.read(block_size), b''):
                        md5.update(block)
                md5 = md5.hexdigest()
            except:
                md5 = 'ERROR'
        else:
            md5 = ''
        return md5

    def _get_hashes(self, program):
        hashes = {'sha256' : '', 'md5': ''}
        if "none" not in self.options.dir_hash_alg:
            size = stats2(program)['size']
            if 'sha256' in self.options.dir_hash_alg:
                try:
                    hashes['sha256'] = self._shasum(program, size)
                except:
                    self.log.debug("Could not hash {0}: {1}".format(program, [traceback.format_exc()]))
                    hashes['sha256'] = 'ERROR'
            if 'md5' in self.options.dir_hash_alg:
                try:
                    hashes['md5'] = self._md5sum(program, size)
                except:
                    self.log.debug("Could not hash {0}: {1}".format(program, [traceback.format_exc()]))
                    hashes['md5'] = 'ERROR'
        return hashes


    def _parse_sandboxed_loginitems(self):
        sandboxed_loginitems = multiglob(self.options.inputdir, ['var/db/com.apple.xpc.launchd/disabled.*.plist'])

        for i in sandboxed_loginitems:
            record = OrderedDict((h, '') for h in self._headers)
            metadata = stats2(i,oMACB=True)
            record.update(metadata)
            record['src_file'] = i
            record['src_name'] = "sandboxed_loginitems"

            try:
                p = plistlib.readPlist(i)
            except:
                try:
                    p = read_bplist(i)
                except:
                    self.log.debug('Could not read plist {0}: {1}'.format(i, [traceback.format_exc()]))
                    p = 'ERROR'

            if p != 'ERROR':
                for k,v in p.items():
                    if v is False:
                        record['prog_name'] = k
                        self._output.write_entry(record.values())
            else:
                errors = {k:'ERROR-CNR-PLIST' for k,v in record.items() if v  == ''}
                record.update(errors)


    def _parse_cron(self):
        cron = multiglob(self.options.inputdir, ['private/var/at/tabs/*'])

        for i in cron:
            record = OrderedDict((h, '') for h in self._headers)
            metadata = stats2(i,oMACB=True)
            record.update(metadata)
            record['src_file'] = i
            record['src_name'] = "cron"

            with open(i,'r') as crontab:
                jobs = [c.rstrip() for c in crontab.readlines() if not c.startswith("# ")]
                for job in jobs:
                    record['program'] = job
                    self._output.write_entry(record.values())


    def _parse_LaunchAgentsDaemons(self):
        LaunchAgents = multiglob(self.options.inputdir, ['System/Library/LaunchAgents/*.plist','Library/LaunchAgents/*.plist','Users/*/Library/LaunchAgents/*.plist',
                                            'System/Library/LaunchAgents/.*.plist','Library/LaunchAgents/.*.plist','Users/*/Library/LaunchAgents/.*.plist'])
        LaunchDaemons = multiglob(self.options.inputdir, ['System/Library/LaunchDaemons/*.plist','Library/LaunchDaemons/*.plist',
                                             'System/Library/LaunchDaemons/.*.plist','Library/LaunchDaemons/.*.plist'])

        for i in LaunchDaemons+LaunchAgents:

            record = OrderedDict((h, '') for h in self._headers)
            metadata = stats2(i,oMACB=True)
            record.update(metadata)
            record['src_file'] = i
            record['src_name'] = "launch_items"

            try:
                p = plistlib.readPlist(i)
            except:
                try:
                    p = read_bplist(i)
                except:
                    self.log.debug('Could not read plist {0}: {1}'.format(i, [traceback.format_exc()]))
                    p = 'ERROR'

            if p != 'ERROR':
                if type(p) is list and len(p) > 0:
                    p = p[0]

                # Try to get Label from each plist.
                try:
                    record['prog_name'] = p['Label']
                except KeyError:
                    self.log.debug("Cannot extract 'Label' from plist: {0}".format(i))
                    record['prog_name'] = 'ERROR'

                # Try to get ProgramArguments if present, or Program, from each plist.
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
                    except:
                        self.log.debug("Cannot extract 'Program' or 'ProgramArguments' from plist: {0}".format(i))
                        program = None
                        record['program'] = 'ERROR'
                        record['args'] = 'ERROR'
                except Exception:
                    self.log.debug('Could not parse plist {0}: {1}'.format(i, [traceback.format_exc()]))
                    program = None

                # If program is ID'd, run additional checks.
                if program:
                    cs_check_path = os.path.join(self.options.inputdir, program.lstrip('/'))
                    record['code_signatures'] = str(get_codesignatures(cs_check_path, self.options.dir_no_code_signatures))

                    hashset = self._get_hashes(program)
                    record['sha256'] = hashset['sha256']
                    record['md5'] = hashset['md5']

            else:
                errors = {k:'ERROR-CNR-PLIST' for k,v in record.items() if v  == ''}
                record.update(errors)

            self._output.write_entry(record.values())

    def _parse_ScriptingAdditions(self):
        ScriptingAdditions = multiglob(self.options.inputdir, ['System/Library/ScriptingAdditions/*.osax','Library/ScriptingAdditions/*.osax',
                                                  'System/Library/ScriptingAdditions/.*.osax','Library/ScriptingAdditions/.*.osax'])

        for i in ScriptingAdditions:
            record = OrderedDict((h, '') for h in self._headers)
            metadata = stats2(i,oMACB=True)
            record.update(metadata)
            record['src_file'] = i
            record['src_name'] = "scripting_additions"
            record['code_signatures'] = str(get_codesignatures(i, self.options.dir_no_code_signatures))
            self._output.write_entry(record.values())

    def _parse_StartupItems(self):
        StartupItems = multiglob(self.options.inputdir, ['System/Library/StartupItems/*/*','Library/StartupItems/*/*'])

        for i in StartupItems:
            record = OrderedDict((h, '') for h in self._headers)
            metadata = stats2(i,oMACB=True)
            record.update(metadata)
            record['src_file'] = i
            record['src_name'] = "startup_items"
            self._output.write_entry(record.values())

    def _parse_PeriodicItems_rcItems_emondItems(self):
        PeriodicItems = multiglob(self.options.inputdir, ['private/etc/periodic.conf', 'private/etc/periodic/*/*', 'private/etc/*.local'])
        rcItems = multiglob(self.options.inputdir, ['private/etc/rc.common'])
        emondItems = multiglob(self.options.inputdir, ['private/etc/emond.d/*','private/etc/emond.d/*/*'])

        for i in PeriodicItems+rcItems+emondItems:
            record = OrderedDict((h, '') for h in self._headers)
            metadata = stats2(i,oMACB=True)
            record.update(metadata)
            record['src_file'] = i
            record['src_name'] = "periodic_rules_items"

            self._output.write_entry(record.values())


    def _parse_loginitems(self):
        user_loginitems_plist = multiglob(self.options.inputdir, ['Users/*/Library/Preferences/com.apple.loginitems.plist'])

        for i in user_loginitems_plist:
            record = OrderedDict((h, '') for h in self._headers)
            metadata = stats2(i,oMACB=True)
            record.update(metadata)
            record['src_file'] = i
            record['src_name'] = "login_items"

            try:
                p = plistlib.readPlist(i)
            except:
                try:
                    p = read_bplist(i)
                except:
                    self.log.debug('Could not read plist {0}: {1}'.format(i, [traceback.format_exc()]))
                    p = 'ERROR'


            if p != 'ERROR':
                items = p[0]['SessionItems']['CustomListItems']
                for i in items:
                    record['prog_name'] = i['Name']
                    if 'Alias' in i:
                        try:
                            alias_bin = i['Alias']
                        except:
                            alias_bin = 'ERROR'

                        if alias_bin != 'ERROR':
                            c = [i.encode('hex') for i in alias_bin]
                            for i in range(len(c)):
                                l = int(c[i],16)
                                if l < len(c) and l > 2:
                                    test = os.path.join(self.options.inputdir, (''.join(c[i+1:i+l+1])).decode('hex'))
                                    try:
                                        if not os.path.exists(test):
                                            continue
                                        else:
                                            record['program'] = test
                                            cs_check_path = os.path.join(self.options.inputdir, test.lstrip('/'))
                                            record['code_signatures'] = str(get_codesignatures(cs_check_path, self.options.dir_no_code_signatures))

                                    except:
                                        continue
                                        record['program'] = 'ERROR'
                                        record['code_signatures'] = 'ERROR'

                    elif 'Bookmark' in i:
                        try:
                            bookmark_bin = i['Bookmark']
                        except:
                            bookmark_bin = 'ERROR'

                        if bookmark_bin != 'ERROR':
                            program = [i.encode('hex') for i in bookmark_bin]
                            data =  Bookmark.from_bytes(''.join(program).decode('hex'))
                            d = data.get(0xf081,default=None)
                            d =  ast.literal_eval(str(d).replace('Data',''))
                            if d is not None:
                                prog = d.split(';')[-1].replace('\x00','')
                                record['program'] = prog
                                cs_check_path = os.path.join(self.options.inputdir, prog.lstrip('/'))
                                record['code_signatures'] = str(get_codesignatures(cs_check_path, self.options.dir_no_code_signatures))

                    self._output.write_entry(record.values())
            else:
                errors = {k:'ERROR-CNR-PLIST' for k,v in record.items() if v  == ''}
                record.update(errors)

    def run(self):
        self._parse_sandboxed_loginitems()
        self._parse_loginitems()
        self._parse_cron()
        self._parse_LaunchAgentsDaemons()
        self._parse_StartupItems()
        self._parse_ScriptingAdditions()
        self._parse_PeriodicItems_rcItems_emondItems()
