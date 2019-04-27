#!/usr/bin/env python

'''
@ author: Kshitij Kumar
@ email: kshitijkumar14@gmail.com, kshitij.kumar@crowdstrike.com

@ purpose:

The main framework which can be used to call and run automactc modules.

Basic invocation: sudo /usr/bin/python2.7 automactc.py -m all

By specifying the python path as above, the necessary libraries
(natively available on macOS) should be found and loaded without issue.

This program and all of its modules are
'''

import argparse
import glob
import gzip
import itertools
import logging
import os
import plistlib
import shutil
import string
import subprocess
import sqlite3
import sys
import traceback
from collections import OrderedDict
from datetime import datetime
from importlib import import_module
from multiprocessing import Pool
from random import choice

import pytz

from . import __version__
from .modules.common.base import ModuleRegistry
from .modules.common.functions import finditem
from .utils.output import BuildTar


# Establish argparser.
def parseArguments():
    parser = argparse.ArgumentParser(description="AutoMacTC: an Automated macOS forensic triage collection framework.", add_help=False)

    module_filter = parser.add_argument_group('module filter')
    mods = module_filter.add_mutually_exclusive_group(required=False)
    mods.add_argument('-m', '--include_modules', type=str, nargs='+', help='module(s) to use, use "all" to run all modules, space separated list only', default=[''], required=False)
    mods.add_argument('-x', '--exclude_modules', type=str, nargs='+', help='assumes you want to run all modules EXCEPT those specified here, space separated list only', default=[''], required=False)
    mods.add_argument('-l', '--list_modules', help='if flag is provided, will list available modules and exit.', default=False, action='store_true', required=False)

    general = parser.add_argument_group('general arguments')
    general.add_argument("-h", "--help", action="help", help="show this help message and exit")
    general.add_argument('-i', '--inputdir', default='/', help='input directory (mount dmg with mountdmg.sh script and use -f to analyze mounted HFS or APFS Volume)', required=False)
    general.add_argument('-o', '--outputdir', default='./', help='output directory', required=False)
    general.add_argument('-p', '--prefix', help='prefix to append to tarball and/or output files', default='automactc-output', required=False)
    general.add_argument('-f', '--forensic_mode', help='if flag is provided, will analyze mounted volume provided as inputdir', default=False, action='store_true', required=False)
    general.add_argument('-nt', '--no_tarball', help='if flag is provided, will NOT package output files into tarball', default=False, action='store_true', required=False)
    general.add_argument('-nl', '--no_logfile', help='if flag is provided, will NOT generate logfile on disk', default=False, action='store_true', required=False)
    general.add_argument('-fmt', '--output_format', help='toggle between csv and json output, defaults to csv', default='csv', action='store', required=False, choices=['csv', 'json'])
    general.add_argument('-np', '--no_low_priority', help='if flag is provided, will NOT run automactc with highest niceness (lowest CPU priority). high niceness is default', default=False, action='store_true', required=False)
    general.add_argument('-b', '--multiprocessing', help='if flag is provided, WILL multiprocess modules [WARNING: Experimental!]', default=False, action='store_true', required=False)

    console_log_args = parser.add_argument_group('console logging verbosity')
    console_logging_args = console_log_args.add_mutually_exclusive_group(required=False)
    console_logging_args.add_argument('-q', '--quiet', help='if flag is provided, will NOT output to console at all', default=False, action='store_true', required=False)
    console_logging_args.add_argument('-d', '--debug', help='enable debug logging to console', default=False, action='store_true', required=False)

    dirlist_args = parser.add_argument_group('specific module arguments')
    dirlist_args.add_argument('-K', '--dir_include_dirs', type=str, nargs='+', help='directory inclusion filter for dirlist module, defaults to volume root, space separated list only', default=[''], required=False)
    dirlist_args.add_argument('-E', '--dir_exclude_dirs', type=str, nargs='+', help='directory and file exclusion filter for dirlist module. defaults are specified in README. space separated list only. \
                               put \'no-defaults\' as first item to overwrite default exclusions and then provide your own exclusions', default=[''], required=False)
    dirlist_args.add_argument('-H', '--dir_hash_alg', nargs='+', help='either sha256 or md5 or both or none, at least one is recommended, defaults to sha256. also applies to autoruns module', default='sha256', required=False)
    dirlist_args.add_argument('-S', '--dir_hash_size_limit', type=int, help='file size filter for which files to hash, in megabytes, defaults to 10MB. also applies to autoruns module', default=10, required=False)
    dirlist_args.add_argument('-R', '--dir_recurse_bundles', help='will fully recurse app bundles if flag is provided. this takes much more time and space', default=False, action='store_true', required=False)
    dirlist_args.add_argument('-NC', '--dir_no_code_signatures', help='if flag is provided, will NOT check code signatures for app and kext files. also applies to autoruns module', default=False, action='store_true', required=False)
    dirlist_args.add_argument('-NM', '--dir_no_multithreading', help='if flag is provided, will NOT multithread the dirlist module', default=False, action='store_true', required=False)

    return parser.parse_args()


class CLIRunner(object):

    def __init__(self, args):
        self.args = args
        self.run_id = self._set_run_id()
        self.log = self._setup_logging()
        self.archive = None
        self._initialize()

    def _set_run_id(self):
        if self.args.no_tarball:
            return ''

        # Generate unique runID when tarballs are being generated, else no runID val.
        return '-' + "".join(choice(string.ascii_letters + string.digits) for x in range(10))

    def _setup_logging(self):
        # Establish logger.
        self.args.log_file = '/dev/null'
        if not self.args.no_logfile:
            if self.args.output_format == "json":
                self.args.log_filename = 'runtime{0}.json'.format(self.run_id)
            else:
                self.args.log_filename = 'runtime{0}.log'.format(self.run_id)

            self.args.log_file = os.path.join(self.args.outputdir, self.args.log_filename)

        if self.args.output_format == "json":
            logging.basicConfig(
                level=logging.DEBUG,
                format='{"logtime": "%(asctime)s", "program": "%(name)s", "pid": "%(process)s", "loglevel": "%(levelname)s", "message": "%(message)s"}',
                datefmt='%Y-%m-%dT%H:%M:%S%z',
                filename=self.args.log_file
            )
        else:
            logging.basicConfig(
                level=logging.DEBUG,
                format='%(asctime)s - %(name)s[%(process)s] - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%dT%H:%M:%S%z',
                filename=self.args.log_file
            )

        log = logging.getLogger('automactc')

        # Create handler for CONSOLE printing.
        ch = logging.StreamHandler(sys.stderr)

        # Handle console logging verbosity.
        if self.args.quiet:
            loglevel = logging.CRITICAL
        elif self.args.debug:
            loglevel = logging.DEBUG
        else:
            loglevel = logging.INFO

        ch.setLevel(loglevel)

        formatter = logging.Formatter('%(name)-15s: %(levelname)-8s %(message)s')
        ch.setFormatter(formatter)

        logging.getLogger('').addHandler(ch)

        return log

    def _initialize(self):
        # Generate outputdir if it doesn't already exist.
        if os.path.isdir(self.args.outputdir) is False:
            os.makedirs(self.args.outputdir)

        self._get_os_version()
        self.args.dir_hash_size_limit = self.args.dir_hash_size_limit * 1048576

        # determine which hashing algorithms to run
        if type(self.args.dir_hash_alg) is list:
            self.args.dir_hash_alg = [''.join([x.lower() for x in i]) for i in self.args.dir_hash_alg]
        elif type(self.args.dir_hash_alg) is str:
            self.args.dir_hash_alg = [self.args.dir_hash_alg]

    def _get_os_version(self):
        # Capture the OS version as a float for comparison tests in modules.
        os_version = None
        try:
            systemversion = plistlib.readPlist(os.path.join(self.args.inputdir, 'System/Library/CoreServices/SystemVersion.plist'))
            os_version = finditem(systemversion, 'ProductVersion')
            self.log.debug("Got OSVersion: {0}".format(os_version))
        except IOError:
            if 'Volumes' not in self.args.inputdir and self.args.forensic_mode is not True:
                try:
                    os_version, e = subprocess.Popen(["sw_vers", "-productVersion"], stdout=subprocess.PIPE).communicate()
                    self.log.debug("Got OSVersion: {0}".format(os_version))
                except Exception:
                    self.log.error("Could not get OSVersion: {0}".format([traceback.format_exc()]))
            else:
                self.log.error("Could not get OSVersion: alternative method does not work on forensic image.")
        except Exception:
            self.log.error("Could not get OSVersion: {0}".format([traceback.format_exc()]))

        self.args.os_version = os_version

    def _gen_fullprefix(self):
        self.log.debug("Building output file prefix.")

        # Get system serial number.
        g = glob.glob(os.path.join(self.args.inputdir, 'private/var/folders/zz/zyxvpxvq6csfxvn_n00000sm00006d/C/*'))
        check_dbs = ['consolidated.db', 'cache_encryptedA.db', 'lockCache_encryptedA.db']
        serial_dbs = [loc for loc in g if any(loc.endswith(db) for db in check_dbs)]
        serial_query = 'SELECT SerialNumber FROM TableInfo;'

        for db in serial_dbs:
            try:
                cursor = sqlite3.connect(db).cursor()
                _serial = cursor.execute(serial_query).fetchone()[0]

                self.log.debug("Retrieved serial number {0} from {1}.".format(_serial, db))

                break

            except sqlite3.OperationalError:
                _serial = 'SERIALERROR'
                self.log.error("Could not extract serial number from {0}: OperationalError.".format(db))

            except sqlite3.DatabaseError:
                _serial = 'SERIALERROR'
                self.log.error("Could not extract serial number from {0}: DatabaseError.".format(db))

            except Exception:
                _serial = 'SERIALERROR'
                self.log.error("Could not extract serial number from {0}: {1}".format(db, [traceback.format_exc()]))

        # Get local hostname.
        if 'Volumes' not in self.args.inputdir and self.args.forensic_mode is not True:
            try:
                hostname_cmd, e = subprocess.Popen(["hostname"], stdout=subprocess.PIPE).communicate()
                _hostname = hostname_cmd.rstrip('\n')
                self.log.debug("Retrieved hostname {0}.".format(_hostname))
            except Exception:
                _hostname = 'HNERROR'
                self.log.error("Could not retrieve hostname.")
        else:
            try:
                pref_plist = os.path.join(self.args.inputdir, 'Library/Preferences/SystemConfiguration/preferences.plist')
                preferences = plistlib.readPlist(pref_plist)
                _hostname = finditem(preferences, 'LocalHostName')
                if not _hostname:
                    _hostname = finditem(preferences, 'HostName')
                    self.log.debug("Got hostname from the HostName key, rather than LocalHostName.")
            except Exception:
                _hostname = 'HNERROR'
                self.log.error("Could not retrieve hostname.")

        # Get current system IP address (if running on live machine).
        if 'Volumes' not in self.args.inputdir and self.args.forensic_mode is not True:
            _ip, e = subprocess.Popen(["ifconfig", "en0"], stdout=subprocess.PIPE).communicate()
            try:
                _ip = ''.join([i for i in _ip.split('\n\t') if i.startswith("inet ")]).split(' ')[1]
                self.log.debug("Retrieved IPv4 address as {0}.".format(_ip))
            except IndexError:
                _ip = "255.255.255.255"
                self.log.error("IPv4 not available, recorded as 255.255.255.255.")
        else:
            wifilog = os.path.join(self.args.inputdir, 'private/var/log/wifi.log')
            wifi_bzlogs = glob.glob(os.path.join(self.args.inputdir, 'private/var/log/wifi.log.*.bz2'))

            try:
                wifi_data = open(wifilog, 'r').readlines()
                try:
                    last_ip = [i for i in wifi_data if "Local IP" in i][-1].rstrip()
                    _ip = last_ip.split(' ')[-1]
                    iptime = ' '.join(last_ip.split(' ')[0:4])
                    self.log.debug("Last IP address {0} was assigned around {1} (local time).".format(_ip,iptime))
                except IndexError:
                    self.log.debug("Could not find last IP in wifi.log, will check historical wifi.log.*.bz2 files.")
            except IOError:
                self.log.debug("Could not parse wifi.log, will check historical wifi.log.*.bz2 files.")

            wdata = []
            if len(wifi_bzlogs) > 0:
                for i in wifi_bzlogs:
                    try:
                        wifi_bzdata, e = subprocess.Popen(["bzcat", i], stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()
                        wdata.append(wifi_bzdata.split('\n'))
                    except Exception:
                        self.log.debug("Could not parse {0}.".format(i))
            w = list(itertools.chain.from_iterable(wdata))

            try:
                last_ip = [i for i in w if "Local IP" in i][0].rstrip()
                _ip = last_ip.split(' ')[-1]
                iptime = ' '.join(last_ip.split(' ')[0:4])
                self.log.debug("Last IP address {0} was assigned around {1} (local time).".format(_ip,iptime))
            except Exception:
                self.log.debug("Could not get last IP from current or historical wifi.log files. Recorded at 255.255.255.255.")
                _ip = "255.255.255.255"

        # Get automactc runtime.
        _runtime = str(self.args.start_time.replace(microsecond=0)).replace('+00:00', 'Z').replace(' ', 'T')

        # Assemble prefix.
        self.args.full_prefix = '{0},{1},{2},{3}'.format(self.args.prefix, _hostname, _ip, _runtime).replace(':', '_')

    # Generate the list of modules to run.
    def _gen_runlist(self, selected, available_mods):
        # selected is the user input via -m or -x.

        selected = list(OrderedDict.fromkeys(selected))
        # Handle what to do if the user inputs 'all'
        if 'all' in selected and len(selected) == 1:
            return available_mods
        elif 'all' in selected and len(selected) > 1:
            return available_mods

        else:
            # If 'live' is selected, convert that to the set of modules to be run live.
            if 'live' in selected:
                live_index = selected.index('live')
                live_run = [x for x in available_mods if "live" in x]

                # Move the live modules to the front of the module queue.
                if live_index > 0:
                    selected.insert(0, selected.pop(live_index))

                selected[0:1] = live_run

            # Convert user selections to full module names to be run.
            unclean = [[x for x in available_mods if module in x] for module in selected]
            clean = [x for x in unclean if len(x) > 0]
            runlist = [x[0] for x in clean]

            # Raise errors for selected modules that are neither valid nor available to run.
            not_a_mod = [x for x in selected if not any(x in mod for mod in runlist)]
            for m in not_a_mod:
                self.log.error("\'{}\' was not identified as a valid, available module to run!".format(m))

            return runlist

    # GZIP the tar archive.
    def _gz_tar(self):
        tarfile = os.path.join(self.args.outputdir, self.args.full_prefix + '.tar')
        with open(tarfile, 'rb') as f_in, gzip.open(tarfile + '.gz', 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
        os.remove(tarfile)

        return tarfile + '.gz'

    # Run the module specified.
    def _mod_exec(self, module):
        modName = module.split('_')[-2]
        modVers = '.'.join(list(module.split('_')[-1][1:]))
        dn = '{0} (v{1})'.format(modName.upper(), modVers)

        module_class = ModuleRegistry.modules()[modName]
        module = module_class(self.run_id, self.args)
        try:
            modStart = datetime.now(pytz.UTC)
            self.log.info("Running {0}".format(dn))

            module.run()

            modOutput = [i for i in glob.glob(self.args.outputdir + '/*') if all(p in i for p in [modName, self.run_id])]
            try:
                if self.archive:
                    arch = [self.archive.add_file(os.path.basename(outfile)) for outfile in modOutput]
            except IndexError:
                pass

            modEnd = datetime.now(pytz.UTC)
            modRuntime = modEnd - modStart
            self.log.debug("{0} finished in {1}.".format(dn, modRuntime))

        except KeyboardInterrupt:
            sys.stdout.write('\r')
            sys.stdout.flush()
            self.log.error("{0} was killed.    ".format(module))

        except Exception:
            self.log.error("{0} failed: {1}".format(module, [traceback.format_exc()]))

    # Run the modules that were selected via _gen_runlist().
    def _run_modules(self):
        available_mods = [mod.module_fullname() for mod in ModuleRegistry.modules().itervalues()]

        pool = Pool()
        if self.args.include_modules != ['']:
            runmods = self._gen_runlist(self.args.include_modules, available_mods)

            if not self.args.multiprocessing:
                for module in runmods:
                    self._mod_exec(module)
            else:
                runner = pool.map(self._mod_exec, runmods)

        elif self.args.exclude_modules != ['']:
            runmods = [x for x in available_mods if x not in self._gen_runlist(self.args.exclude_modules, available_mods)]

            if not self.args.multiprocessing:
                for module in runmods:
                    self._mod_exec(module)
            else:
                runner = pool.map(self._mod_exec, runmods)

        pool.close()
        pool.join()

    def execute(self):
        # Mark startime of program.
        self.args.start_time = datetime.now(pytz.UTC)

        self.log.info("Started automactc (v. {0}) at {1}.".format(__version__, self.args.start_time))
        self.log.info("Invocation: {0}".format(' '.join(sys.argv)))

        # Check if user is trying to run AMTC against mounted volume.
        if self.args.inputdir.startswith('/Volumes') and not self.args.forensic_mode:
            print "Your input appears to begin with /Volumes."
            chk_4n6 = raw_input("Are you trying to run automactc against a mounted volume? (y/n/q)")
            if chk_4n6.lower() in ['y', 'yes']:
                self.args.forensic_mode = True
            elif chk_4n6.lower() in ['n', 'no']:
                self.args.forensic_mode = False
            elif chk_4n6.lower() in ['q', 'quit']:
                sys.exit(0)

        # Generate full prefix of the filenames.
        self._gen_fullprefix()
        self.args.filename_prefix = ', '.join(self.args.full_prefix.split(', ')[:4])
        self.log.debug("Full prefix: {0}".format(self.args.full_prefix))

        if not self.args.no_logfile:
            prefix_logfile = os.path.join(self.args.outputdir, self.args.filename_prefix + ',' + self.args.log_filename)
            os.rename(self.args.log_file, prefix_logfile)

        # Clean up inputdir by removing trailing slash.
        if len(self.args.inputdir) > 1 and self.args.inputdir[-1] == '/':
            self.args.inputdir = self.args.inputdir[:-1]

        # Instantiate archive as BuildTar object.
        tarname = self.args.full_prefix + ".tar"
        if not self.args.no_tarball:
            self.archive = BuildTar(self.run_id, self.args.outputdir, tarname)

        # Set CPU priority based on CLI invocation. Default is low priority.
        if not self.args.no_low_priority:
            self.log.info("Going to run in low CPU priority mode.")
            os.nice(19)

        # Run the modules!
        if self.archive:
            self.log.info("RunID: {0}".format(self.run_id[1:]))
        else:
            self.log.info("RunID: {0}".format("N/A"))

        self._run_modules()

        # Get program end time.
        end_time = datetime.now(pytz.UTC)
        total_run_time = end_time - self.args.start_time
        self.log.info("Finished program at {0}.".format(end_time))
        self.log.info("Total runtime: {0}.".format(total_run_time))

        # Clean up any straggler files in the outputdir based on runID.
        stragglers = [i for i in glob.glob(self.args.outputdir + '/*') if self.run_id in i]
        for i in stragglers:
            if self.archive:
                self.log.debug("Archiving straggler file {0}.".format(i))
                self.archive.add_file(os.path.basename(i))

        # Compress tar to tarball.
        if self.archive:
            tarball = self._gz_tar()

def main():
    # Set environmental variable TZ to UTC.
    os.environ['TZ'] = 'UTC0'

    # Establish static variables for program based on CLI invocation.
    args = parseArguments()

    # Add functionality for --list argument to enumerate available mods.
    if args.list_modules:
        print "Modules available for use:"
        for value in ModuleRegistry.modules().itervalues():
            fullname = value.module_fullname()
            _modName = fullname.split('_')[-2]
            _modVers = '.'.join(list(fullname.split('_')[-1][1:]))
            print '\t {0} (v{1})'.format(_modName, _modVers)
        sys.exit(0)

    # Check if at least -m all is invoked, else quit.
    if args.include_modules == [''] and args.exclude_modules == ['']:
        print "You must provide at least '-m all' to run with all default settings. Exiting."
        sys.exit(0)

    # Confirm that user is running script with root privileges.
    if os.geteuid() != 0:
        print "You need to have root privileges to run this script.\nPlease try again, this time as 'sudo'. Exiting."
        sys.exit(0)

    # Confirm that mount point in forensic mode has required directories - to see if the volume is actually mounted.
    mount_test = glob.glob(os.path.join(args.inputdir,'*'))
    required_dirs = ['Library', 'System', 'Users', 'Applications', 'Network']
    litmus = [i for i in mount_test if any(i.endswith(d) for d in required_dirs)]
    if len(litmus) < len(required_dirs) and args.forensic_mode:
        print "Mount point doesn't have any of the expected directories underneath. Check if the mount was completed successfully."
        sys.exit(0)

    runner = CLIRunner(args)
    runner.execute()


if __name__ == "__main__":
    main()
