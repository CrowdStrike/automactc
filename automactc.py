#!/usr/bin/env python

'''
@ purpose:

The main framework which can be used to call and run automactc modules.

Basic invocation: sudo /usr/bin/python2.7 automactc.py -m all

By specifying the python path as above, the necessary libraries
(natively available on macOS) should be found and loaded without issue.

'''

import argparse
import csv
import glob
import gzip
import io
import itertools
import json
import logging
import os
import plistlib
import shutil
import sqlite3
import string
import subprocess
import sys
import tarfile
import traceback
from collections import OrderedDict
from datetime import datetime
from importlib import import_module
from multiprocessing import Pool
from random import choice
from threading import Lock

from modules.common.functions import finditem

if sys.version_info[0] < 3:
    import codecs
    import cStringIO

__version__ = '1.2.0.13-alpha'


def parseArguments():
    """Initialize argparser
    Returns argparse object of captured arguments.
    """
    parser = argparse.ArgumentParser(description="AutoMacTC: an Automated macOS forensic triage collection framework.", add_help=False)

    module_filter = parser.add_argument_group('module filter')
    mods = module_filter.add_mutually_exclusive_group(required=False)
    mods.add_argument('-m', '--include_modules', type=str, nargs='+', help='module(s) to use, use "all" to run all modules, space separated list only', default=[''], required=False)
    mods.add_argument('-x', '--exclude_modules', type=str, nargs='+', help='assumes you want to run all modules EXCEPT those specified here, space separated list only', default=[''], required=False)
    mods.add_argument('-l', '--list_modules', help='if flag is provided, will list available modules and exit.', default=False, action='store_true', required=False)

    general = parser.add_argument_group('general arguments')
    general.add_argument("-h", "--help", action="help", help="show this help message and exit")
    general.add_argument("-v", "--verbose", default=False, action='store_true', help="enable verbose logging")
    general.add_argument('-i', '--inputdir', default='/', help='input directory; mount dmg with mountdmg.sh script and use -f to analyze mounted HFS or APFS Volume, use volume appended with "Data" (e.g. "Macintosh HD - Data") for 10.15+ systems', required=False)
    general.add_argument('-is', '--inputsysdir', default='', help='input system drive if using mounted drive from 10.15+ system (e.g. "Macintosh HD")', required=False)
    general.add_argument('-o', '--outputdir', default='./', help='output directory', required=False)
    general.add_argument('-p', '--prefix', help='prefix to append to tarball and/or output files', default='automactc-output', required=False)
    general.add_argument('-f', '--forensic_mode', help='if flag is provided, will analyze mounted volume provided as inputdir', default=False, action='store_true', required=False)
    general.add_argument('-nt', '--no_tarball', help='if flag is provided, will NOT package output files into tarball', default=False, action='store_true', required=False)
    general.add_argument('-nl', '--no_logfile', help='if flag is provided, will NOT generate logfile on disk', default=False, action='store_true', required=False)
    general.add_argument('-fmt', '--output_format', help='toggle between csv and json output, defaults to csv', default='csv', action='store', required=False, choices=['csv', 'json'])
    general.add_argument('-np', '--no_low_priority', help='if flag is provided, will NOT run automactc with highest niceness (lowest CPU priority). high niceness is default', default=False, action='store_true', required=False)
    general.add_argument('-b', '--multiprocessing', help='if flag is provided, WILL multiprocess modules [WARNING: Experimental!]', default=False, action='store_true', required=False)
    general.add_argument('-O', '--override_mount', help='if flag is provided, WILL bypass error where inputdir does not contain expected subdirs', default=False, action='store_true', required=False)

    console_log_args = parser.add_argument_group('console logging verbosity')
    console_logging_args = console_log_args.add_mutually_exclusive_group(required=False)
    console_logging_args.add_argument('-q', '--quiet', help='if flag is provided, will NOT output to console at all', default=False, action='store_true', required=False)
    console_logging_args.add_argument('-r', '--rtr', help='reduce verbosity to display nicely on RTR console', default=False, action='store_true', required=False)
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
    args = parser.parse_args()

    return args


def gen_availablemods(dir_path):
    """Generate list of mods available to be run.
    """
    mod_dir = os.listdir(os.path.join(dir_path, 'modules'))
    mods = [i.replace('.py', '') for i in mod_dir if i.startswith('mod_') and i.endswith('.py')]

    live_or_dead_mods = [i for i in mods if not i.startswith('mod_live_') and not i.startswith('mod_dead_')]
    only_live_mods = sorted([i for i in mods if i.startswith('mod_live_')])

    available_mods = only_live_mods + live_or_dead_mods

    return available_mods


def gen_runlist(selected, available_mods):
    """Generate list of modules to run.
    selected is the user input via -m (specify module list) or -x (specify
    exclude list).
    """
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
        runlist = []
        # for x in clean[0]:
        #     for i in selected:
        #         if i == x.split('_')[-2]:
        #             runlist.append(x)
        runlist = [x[0] for x in clean]
        log.debug(runlist)

        # Raise errors for selected modules that are neither valid nor available to run.
        not_a_mod = [x for x in selected if not any(x in mod for mod in runlist)]
        for m in not_a_mod:
            log.error("\'{}\' was not identified as a valid, available module to run!".format(m))

        return runlist


def gen_fullprefix(startTime):
    """Build AutoMacTC prefix based on prefix, hostname, ip, runtime.
    Returns the generated prefix and the serial number if found.
    """
    log.debug("Building output file prefix.")

    # Get system serial number.
    g = glob.glob(os.path.join(inputdir, 'private/var/folders/zz/zyxvpxvq6csfxvn_n00000sm00006d/C/*'))
    check_dbs = ['consolidated.db', 'cache_encryptedA.db', 'lockCache_encryptedA.db']
    serial_dbs = [loc for loc in g if any(loc.endswith(db) for db in check_dbs)]
    serial_query = 'SELECT SerialNumber FROM TableInfo;'
    _serial = "SERROR"

    for db in serial_dbs:
        try:
            cursor = sqlite3.connect(db).cursor()
            _serial = cursor.execute(serial_query).fetchone()[0]

            log.debug("Retrieved serial number {0} from {1}.".format(_serial, db))
            break

        except sqlite3.OperationalError:
            error = [x for x in traceback.format_exc().split('\n') if "OperationalError" in x]
            log.debug("Could not connect [{0}].".format(error[0]))
            if "database is locked" or "unable to open" in error[0]:
                tmpdb = os.path.basename(db) + '-tmp'
                log.debug("Trying to connect to db copied to temp location...")

                shutil.copyfile(db, os.path.join(outputdir, tmpdb))
                db = os.path.join(outputdir, tmpdb)
                try:
                    cursor = sqlite3.connect(db).cursor()
                    _serial = cursor.execute(serial_query).fetchone()[0]
                    log.debug("Successfully connected.")
                    os.remove(db)
                    break
                except Exception:
                    log.debug("Could not get serial number from {0}. Trying another directory.".format(db))
                os.remove(db)

    # Get local hostname.
    if 'Volumes' not in inputdir and forensic_mode is not True:
        try:
            hostname_cmd, e = subprocess.Popen(["hostname"], stdout=subprocess.PIPE).communicate()
            hostname_cmd = hostname_cmd.decode('utf-8')
            _hostname = hostname_cmd.rstrip('\n')
            log.debug("Retrieved hostname {0}.".format(_hostname))
        except Exception:
            _hostname = 'HNERROR'
            log.error("Could not retrieve hostname.")
    else:
        try:
            pref_plist = open(os.path.join(inputdir, 'Library/Preferences/SystemConfiguration/preferences.plist'), 'rb')
            if sys.version_info[0] < 3:
                preferences = plistlib.readPlist(pref_plist)
            else:
                preferences = plistlib.load(pref_plist)
            _hostname = finditem(preferences, 'HostName')
            if not _hostname:
                _hostname = finditem(preferences, 'LocalHostName')
                log.debug("Got hostname from the LocalHostName key, rather than HostName.")
        except Exception:
            _hostname = 'HNERROR'
            log.error("Could not retrieve hostname.")

    # Get current system IP address (if running on live machine).
    if 'Volumes' not in inputdir and forensic_mode is not True:
        _ip, e = subprocess.Popen(["ifconfig", "en0"], stdout=subprocess.PIPE).communicate()
        try:
            _ip = ''.join([i for i in _ip.decode().split('\n\t') if i.startswith("inet ")]).split(' ')[1]
            log.debug("Retrieved IPv4 address as {0}.".format(_ip))
        except IndexError:
            _ip = "255.255.255.255"
            log.error("IPv4 not available, recorded as 255.255.255.255.")
    else:
        wifilog = os.path.join(inputdir, 'private/var/log/wifi.log')
        wifi_bzlogs = glob.glob(os.path.join(inputdir, 'private/var/log/wifi.log.*.bz2'))

        try:
            wifi_data = open(wifilog, 'r').readlines()
            try:
                last_ip = [i for i in wifi_data if "Local IP" in i][-1].rstrip()
                _ip = last_ip.split(' ')[-1]
                iptime = ' '.join(last_ip.split(' ')[0:4])
                log.debug("Last IP address {0} was assigned around {1} (local time).".format(_ip, iptime))
            except IndexError:
                log.debug("Could not find last IP in wifi.log, will check historical wifi.log.*.bz2 files.")
        except IOError:
            log.debug("Could not parse wifi.log, will check historical wifi.log.*.bz2 files.")

        wdata = []
        if len(wifi_bzlogs) > 0:
            for i in wifi_bzlogs:
                try:
                    wifi_bzdata, e = subprocess.Popen(["bzcat", i], stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()
                    wdata.append(wifi_bzdata.split('\n'))
                except Exception:
                    log.debug("Could not parse {0}.".format(i))
        w = list(itertools.chain.from_iterable(wdata))

        try:
            last_ip = [i for i in w if "Local IP" in i][0].rstrip()
            _ip = last_ip.split(' ')[-1]
            iptime = ' '.join(last_ip.split(' ')[0:4])
            log.debug("Last IP address {0} was assigned around {1} (local time).".format(_ip, iptime))
        except Exception:
            log.debug("Could not get last IP from current or historical wifi.log files. Recorded at 255.255.255.255.")
            _ip = "255.255.255.255"

    # Get automactc runtime.
    _runtime = str(startTime.replace(microsecond=0)).replace('+00:00', 'Z').replace(' ', 'T')
    if _runtime[-1] != 'Z':
        _runtime = _runtime + 'Z'

    # Assemble prefix.
    full_prefix = '{0},{1},{2},{3}'.format(_prefix, _hostname, _ip, _runtime).replace(':', '_')

    return full_prefix, _serial


def del_none(d):
    """Utility to recursively delete keys with no value.
    """
    for key, value in list(d.items()):
        if value is None or value == "":
            del d[key]
        elif isinstance(value, dict):
            del_none(value)
    return d


class UnicodeWriter:
    """
    A CSV writer which will write rows to CSV file "f",
    which is encoded in the given encoding.

    Adopted from the Python documentation
    Source: https://docs.python.org/2.7/library/csv.html
    """

    def __init__(self, f, dialect=csv.excel, encoding="utf-8", **kwds):
        self.queue = cStringIO.StringIO()
        self.writer = csv.writer(self.queue, dialect=dialect, **kwds)
        self.stream = f
        self.encoder = codecs.getincrementalencoder(encoding)()

    def writerow(self, row):
        self.writer.writerow([s.encode("utf-8") for s in row])
        data = self.queue.getvalue()  # Fetch UTF-8 output from the queue ...
        data = data.decode("utf-8")

        self.stream.write(data)  # write to the target stream
        self.queue.truncate(0)

    def writerows(self, rows):
        for row in rows:
            self.writerow(row)


class data_writer:
    """
    Establish data_writer class to handle output file format and naming scheme.
    """

    output_format = parseArguments().output_format

    def __init__(self, name, headers, datatype=output_format):
        """
        Initialize the data_writer.
        If headers is None, treats as just a wrapper.
        If datatype is 'all', writes in all available formats (csv, json).

        Caller must call the flush method at the close of the module to ensure
        all contents of queue that were < buffer_size at the end are written
        to the file.
        """
        possible_formats = ["json", "csv", "file"]
        if datatype not in possible_formats and datatype != 'all':
            raise ValueError('Unable to instantiate data_writer for datatype {0}'.format(datatype))

        if sys.version_info[0] < 3 and headers is not None:
            self.headers = [str(h).decode('utf-8') for h in headers]
        else:
            self.headers = headers
        self.name = filename_prefix + ',' + name + runID
        self.mod = name
        self.datatype = datatype
        self._log = logging.getLogger(self.mod)
        self.__queue = list()
        self.__queue_data_writer = None
        self.__mux = Lock()  # make thread-safe for concurrent modules

        formats = []
        if datatype == 'all':
            formats = possible_formats
        else:
            formats.append(datatype)

        self.output_filename = self.name + '.' + self.datatype
        self.data_file_name = os.path.join(outputdir, self.output_filename)

        if headers is None:  # no file generated here. simply to manage file name for output to be captured.
            return
        if self.datatype == 'csv':
            with io.open(self.data_file_name, 'w', encoding='utf-8') as data_file:
                if sys.version_info[0] < 3:
                    writer = UnicodeWriter(data_file)
                else:
                    writer = csv.writer(data_file)
                writer.writerow(self.headers)
        elif self.datatype == 'json':
            with io.open(self.data_file_name, 'w', encoding='utf-8') as data_file:
                pass
        elif self.datatype == 'file':  # no file generated here. simply to manage file name for output to be captured.
            return

    def write_entry(self, data):
        """
        Writes output entry to output file.
        data is a list of strings.
        """
        log.warn("write_entry will be deprecated in future versions, use write_record instead :) ")
        if self.datatype == 'csv':
            self.__csv_write_entry(data)
        elif self.datatype == 'json':
            self.__json_write_entry(data)
        elif self.datatype == 'all':
            self.__json_write_entry(data, all=True)
            self.__csv_write_entry(data, All=True)
        return ""

    def write_record(self, record, buffer_cap=10000):
        """
        Writes output entry to buffer.
        Record is a list object or dict like object.
        Once buffer_cap entries are stored in the queue, it is flushed to file.

        Caller must call the flush method at the close of the module to ensure
        all contents of queue that were < buffer_size at the end are written
        to the file.
        """
        if record is not None:
            # We need to enforce the correct encoding for both versions of python
            if sys.version_info[0] < 3:
                if isinstance(record, list):
                    self.__queue.append([str(s).decode('utf-8') if isinstance(s, unicode) is False else s for s in record])
                else:
                    self.__queue.append([str(s).decode('utf-8') if isinstance(s, unicode) is False else s for s in record.values()])
            else:
                if isinstance(record, list):
                    self.__queue.append([s.decode('utf-8') if isinstance(s, bytes) else str(s) for s in record])
                else:
                    self.__queue.append(s.decode('utf-8') if isinstance(s, bytes) else str(s) for s in record.values())
        if len(self.__queue) > buffer_cap:
            self.flush_record()
        return ""

    def flush_record(self):
        """
        Flush the queue to the output file.
        Blocking method.
        This method should be called at the close of the module to handle
        straggling entries in the buffer.
        """
        self.__mux.acquire()
        try:
            if self.datatype == 'csv':
                self.__csv_flush_record()
            elif self.datatype == 'json':
                self.__json_flush_record()
            elif self.datatype == 'all':
                self.__csv_flush_record(all=True)
                self.__json_flush_record(all=True)
        except Exception as e:
            log.debug("data_writer: Failed to flush queue: {0}: {1}".format(str(e), [traceback.format_exc()]))
        finally:
            try:
                if sys.version_info[0] < 3:
                    del self.__queue[:]
                else:
                    self.__queue.clear()
            except Exception as e:
                log.error("data_writer: Failed to clear datawriter queue: {0}".format(str(e)))
            self.__mux.release()

    def __csv_flush_record(self, all=False):
        """
        Lower method for flushing contents of data_writer queue to CSV file.
        all is a bool determining if we are writing all output types as well.
        After this method exits, the contents of the queue will be stored
        in the CSV file.
        """
        data_file_name = self.data_file_name
        if all is True:
            data_file_name = data_file_name.split('all')[0] + 'csv'

        with io.open(data_file_name, 'a', encoding='utf-8') as data_file:
            if sys.version_info[0] < 3:
                self.__queue_data_writer = UnicodeWriter(data_file)
            else:
                self.__queue_data_writer = csv.writer(data_file)
            self.__queue_data_writer.writerows([row for row in self.__queue])
            data_file.flush()

    def __json_flush_record(self, all=False):
        """
        Lower method for flushing contents of data_writer queue to JSON file.
        all is a bool determining if we are writing all output types as well.
        After this method exits, the contents of the queue will be stored in
        the JSON file.
        """
        data_file_name = self.data_file_name
        if all is True:
            data_file_name = data_file_name.split('all')[0] + 'json'
        zipped_data_list = [del_none(dict(zip(self.headers, entry))) for entry in self.__queue]
        with io.open(data_file_name, 'a', encoding='utf-8') as data_file:
            for zipped_data in zipped_data_list:
                if sys.version_info[0] < 3:
                    data_file.write(unicode(json.dumps(zipped_data, indent=None)))
                    data_file.write('\n'.decode('utf-8'))
                else:
                    # json.dump(zipped_data, data_file, indent=None)
                    data_file.write(json.dumps(zipped_data, indent=None))
                    data_file.write('\n')
            data_file.flush()

    def __json_write_entry(self, data, all=False):
        log.warn("__json_write_entry will be deprecated in future versions, use __json_write_record instead :) ")
        data_file_name = self.data_file_name
        if all is True:
            data_file_name = data_file_name.split('all')[0] + 'json'
        zipped_data = del_none(dict(zip(self.headers, data)))
        with io.open(data_file_name, 'a', encoding='utf-8') as data_file:

            if sys.version_info[0] < 3:
                data_file.write(unicode(json.dumps(zipped_data, indent=None)))
                data_file.write('\n'.decode('utf-8'))
            else:
                json.dump(zipped_data, data_file, indent=None)
                data_file.write('\n')

            data_file.flush()

    def __csv_write_entry(self, data, all=False):
        log.warn("__csv_write_entry will be deprecated in future versions, use __csv_write_record instead :) ")
        data_file_name = self.data_file_name
        if all is True:
            data_file_name = data_file_name.split('all')[0] + 'csv'
        with io.open(data_file_name, 'a', encoding='utf-8') as data_file:
            if sys.version_info[0] < 3:
                writer = UnicodeWriter(data_file)
            else:
                writer = csv.writer(data_file)
            writer.writerow(data)


class build_tar:
    """
    Establish class to build tarball of AutoMacTC output files on the fly.
    """

    def __init__(self, name):
        """
        Initialize the build_rar wrapper.
        name is a string denoting filename of the tarball.
        """
        self.name = name

    def add_file(self, fname):
        """
        Add the filepath specified by fname to the tarball.
        fname is a valid filepath to an AutoMacTC output file.
        """
        if not no_tarball:
            out_tar = os.path.join(outputdir, self.name)
            t_fname = os.path.join(outputdir, fname)
            archive = tarfile.open(out_tar, 'a')

            archive.add(t_fname, fname.replace(runID, ''))
            archive.close()
            try:
                if not os.path.isdir(t_fname):
                    os.remove(t_fname)
                else:
                    shutil.rmtree(t_fname)
            except OSError:
                log.error("Added to archive, but could not delete {0}.".format(t_fname))


def run_modules():
    """Run the modules that were selected via gen_runlist().
    """
    pool = Pool()
    if module_inc_opts != ['']:
        runmods = gen_runlist(module_inc_opts, available_mods)
        if not multiprocessing:
            for module in runmods:
                modExec(module)
        else:
            runner = pool.map(modExec, runmods)

    elif module_exc_opts != ['']:
        runmods = [x for x in available_mods if x not in gen_runlist(module_exc_opts, available_mods)]

        if not multiprocessing:
            for module in runmods:
                modExec(module)
        else:
            runner = pool.map(modExec, runmods)

    pool.close()
    pool.join()


def modExec(module):
    """Run the module specified.
    module is a string denoting the module file name
    """
    modName = module.split('_')[-1]
    if "live" in module:
        dn = '{0} (live)'.format(modName.upper())
    else:
        dn = '{0}'.format(modName.upper())

    try:
        modStart = datetime.utcnow()
        log.info("Running {0}".format(dn))
        modImport = 'modules.' + module

        import_module(modImport)

        modOutput = [i for i in glob.glob(outputdir + '/*') if all(p in i for p in [modName, runID])]
        try:
            arch = [archive.add_file(os.path.basename(outfile)) for outfile in modOutput]
        except IndexError:
            pass

        modEnd = datetime.utcnow()
        modRuntime = modEnd - modStart
        log.debug("{0} finished in {1}.".format(dn, modRuntime))

    except KeyboardInterrupt:
        sys.stdout.write('\r')
        sys.stdout.flush()
        log.error("{0} was killed.    ".format(module))

    except Exception:
        log.error("{0} failed: {1}".format(module, [traceback.format_exc()]))


def gz_tar(full_prefix):
    """GZIP the tar archive.
    full_prefix is a string denoting the filename prefix of the tar file.
    """
    tarfile = os.path.join(outputdir, full_prefix + '.tar')
    try:
        with open(tarfile, 'rb') as f_in, gzip.open(tarfile + '.gz', 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
        os.remove(tarfile)
    except Exception as e:
        log.error("Tarfile {0} was not generated. Module(s) run collected no info?".format(tarfile))
        log.error(e)

    return tarfile + '.gz'


def subq_remove(subqpath):
    """Subprocess remove quarantine xattrs.
    """
    xattr_cmd = "xattr -d com.apple.quarantine " + subqpath
    try:
        subprocess.call(xattr_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:
        return ''


if __name__ == "__main__":

    # Remove quarantine xattrs for 10.15+
    quarantine_remove = ['./modules/common/dep/_cffi_backend.cpython-37m-darwin.so',
                         './modules/common/dep/_cffi_backend.cpython-39-darwin.so',
                         './modules/common/dep/_cffi_backend.cpython-38-darwin.so']
    for p in glob.glob('./modules/common/dep/xattr/__pycache__/*'):
        quarantine_remove.append(p)
    for p in glob.glob('./modules/common/Crypto/*/*.so'):
        quarantine_remove.append(p)
    for i in quarantine_remove:
        subq_remove(i)

    startTime = datetime.utcnow()

    # Set environmental variable TZ to UTC.
    os.environ['TZ'] = 'UTC'
    os.environ['LC_ALL'] = 'en_US.UTF-8'

    # Establish static variables for program based on CLI invocation.
    args = parseArguments()

    inputdir = args.inputdir
    inputsysdir = args.inputsysdir
    outputdir = args.outputdir

    module_inc_opts = args.include_modules
    module_exc_opts = args.exclude_modules

    no_tarball = args.no_tarball
    quiet = args.quiet
    rtr = args.rtr
    verbose = args.verbose
    debug = args.debug
    _prefix = args.prefix
    output_format = args.output_format
    multiprocessing = args.multiprocessing
    forensic_mode = args.forensic_mode
    dirlist_include_dirs = args.dir_include_dirs
    dirlist_exclude_dirs = args.dir_exclude_dirs
    hash_alg = args.dir_hash_alg
    hash_size_limit = args.dir_hash_size_limit * 1048576
    no_code_signatures = args.dir_no_code_signatures
    recurse_bundles = args.dir_recurse_bundles
    dirlist_no_multithreading = args.dir_no_multithreading
    override_mount = args.override_mount

    # Establish filepath of amtc.
    dir_path = os.path.dirname(os.path.realpath(__file__))

    # Generate list of modules available to be run.
    available_mods = gen_availablemods(dir_path)

    # Generate unique runID when tarballs are being generated, else no runID val.
    if not no_tarball:
        runID = '-' + "".join(choice(string.ascii_letters + string.digits) for x in range(10))
    else:
        runID = ''

    # Add functionality for --list argument to enumerate available mods.
    if args.list_modules:
        print("Modules available for use:")
        available_mods.sort()
        for i in available_mods:
            if "live" in i:
                _modName = i.split('_')[-1]
                print('\t {0} (live)'.format(_modName))
            else:
                _modName = i.split('_')[-1]
                print('\t {0}'.format(_modName))
        sys.exit(0)

    # Check if at least -m all is invoked, else quit.
    if module_inc_opts == [''] and module_exc_opts == ['']:
        print("You must provide at least '-m all' to run with all default settings. Exiting.")
        sys.exit(0)

    # Confirm that user is running script with root privileges.
    if os.geteuid() != 0:
        print("You need to have root privileges to run this script.\nPlease try again, this time as 'sudo'. Exiting.")
        sys.exit(0)

    # Confirm that mount point in forensic mode has required directories - to see if the volume is actually mounted.
    mount_test = glob.glob(os.path.join(inputdir, '*'))
    required_dirs = ['Library', 'System', 'Users', 'Applications']
    litmus = [i for i in mount_test if any(i.endswith(d) for d in required_dirs)]
    if len(litmus) < len(required_dirs) and forensic_mode and override_mount is False:
        print("Mount point doesn't have any of the expected directories underneath. Check if the mount was completed successfully.")
        sys.exit(0)
    elif override_mount:
        print("Mount point doesn't have any of the expected directories underneath, but will proceeed despite this...")

    # Generate outputdir if it doesn't already exist.
    if os.path.isdir(outputdir) is False:
        os.makedirs(outputdir)

    # Establish logger.
    if not args.no_logfile:
        if output_format == "json":
            logfilename = 'runtime{0}.json'.format(runID)
        else:
            logfilename = 'runtime{0}.log'.format(runID)

        logfile = os.path.join(outputdir, logfilename)
    else:
        logfile = '/dev/null'

    if output_format == "json":
        logging.basicConfig(
            level=logging.DEBUG,
            format='{"logtime": "%(asctime)s", "program": "%(name)s", "pid": "%(process)s", "loglevel": "%(levelname)s", "message": "%(message)s"}',
            datefmt='%Y-%m-%dT%H:%M:%S%z',
            filename=logfile
        )
    else:
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(name)s[%(process)s] - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%dT%H:%M:%S%z',
            filename=logfile
        )

    log = logging.getLogger('automactc')

    # Create handler for CONSOLE printing.
    ch = logging.StreamHandler(sys.stdout)

    # Handle console logging verbosity.
    if args.quiet:
        loglevel = logging.CRITICAL
    elif args.debug:
        loglevel = logging.DEBUG
    else:
        loglevel = logging.INFO

    ch.setLevel(loglevel)

    formatter = logging.Formatter('%(name)-15s: %(levelname)-8s %(message)s')
    ch.setFormatter(formatter)

    logging.getLogger('').addHandler(ch)

    log.info("Started automactc (v. {0}) at {1}.".format(__version__, startTime))
    log.debug("Invocation: {0}".format(' '.join(sys.argv)))

    # Check if user is trying to run AMTC against mounted volume.
    if inputdir.startswith('/Volumes') and not forensic_mode:
        print("Your input appears to begin with /Volumes.")
        if sys.version_info[0] < 3:
            chk_4n6 = raw_input("Are you trying to run automactc against a mounted volume? (y/n/q)")
        else:
            chk_4n6 = input("Are you trying to run automactc against a mounted volume? (y/n/q)")
        if chk_4n6.lower() in ['y', 'yes']:
            forensic_mode = True
        elif chk_4n6.lower() in ['n', 'no']:
            forensic_mode = False
        elif chk_4n6.lower() in ['q', 'quit']:
            sys.exit(0)

    # Generate full prefix of the filenames.
    full_prefix, serial = gen_fullprefix(startTime)
    filename_prefix = ', '.join(full_prefix.split(', ')[:4])
    log.debug("Full prefix: {0}".format(full_prefix))

    # Capture the OS version as a float for comparison tests in modules.
    try:
        pslistfile = open(os.path.join(inputdir, 'System/Library/CoreServices/SystemVersion.plist'), 'rb')
        if sys.version_info[0] < 3:
            systemversion = plistlib.readPlist(pslistfile)
        else:
            systemversion = plistlib.load(pslistfile)
        OSVersion = finditem(systemversion, 'ProductVersion')
        log.debug("Got OSVersion: {0}".format(OSVersion))
    except IOError:
        try:
            pslistfile = open(os.path.join(inputsysdir, 'System/Library/CoreServices/SystemVersion.plist'), 'rb')
            if sys.version_info[0] < 3:
                systemversion = plistlib.readPlist(pslistfile)
            else:
                systemversion = plistlib.load(pslistfile)

            OSVersion = finditem(systemversion, 'ProductVersion')
            log.debug("Got OSVersion: {0}".format(OSVersion))
        except IOError:
            if 'Volumes' not in inputdir and forensic_mode is not True:
                try:
                    OSVersion, e = subprocess.Popen(["sw_vers", "-productVersion"], stdout=subprocess.PIPE).communicate()
                    log.debug("Got OSVersion: {0}".format(OSVersion))
                except Exception:
                    log.error("Could not get OSVersion: {0}".format([traceback.format_exc()]))
            else:
                log.error("Could not get OSVersion: alternative method does not work on forensic image.")
                OSVersion = None
    except Exception:
        log.error("Could not get OSVersion: {0}".format([traceback.format_exc()]))
        OSVersion = None

    if not args.no_logfile:
        prefix_logfile = os.path.join(outputdir, filename_prefix + ',' + logfilename)

        os.rename(logfile, prefix_logfile)

    # Clean up inputdir by removing trailing slash.
    if len(inputdir) > 1 and inputdir[-1] == '/':
        inputdir = inputdir[:-1]
    if len(inputsysdir) > 1 and inputsysdir[-1] == '/':
        inputsysdir = inputsysdir[:-1]

    # Instantiate archive as build_tar object.
    tarname = full_prefix + ".tar"
    archive = build_tar(tarname)

    # Set CPU priority based on CLI invocation. Default is low priority.
    if not args.no_low_priority:
        log.info("Going to run in low CPU priority mode.")
        os.nice(19)

    # Run the modules!
    if not no_tarball:
        log.info("RunID: {0}".format(runID[1:]))
    else:
        log.info("RunID: {0}".format("N/A"))
    run_modules()

    # Get program end time.
    endTime = datetime.utcnow()
    total_runTime = endTime - startTime
    log.info("Modules finished at {0}.".format(endTime))
    log.info("Module runtime: {0}.".format(total_runTime))

    # Clean up any straggler files in the outputdir based on runID.
    stragglers = [i for i in glob.glob(outputdir + '/*') if runID in i]
    for i in stragglers:
        if not no_tarball:
            log.debug("Archiving straggler file {0}.".format(i))
            archive.add_file(os.path.basename(i))

    # Compress tar to tarball.
    if not no_tarball:
        log.info("Creating tarball of output")
        tarball = gz_tar(full_prefix)

    # Get program end time.
    endTime = datetime.utcnow()
    total_runTime = endTime - startTime
    log.info("Finished program at {0}.".format(endTime))
    log.info("Total runtime: {0}.".format(total_runTime))
