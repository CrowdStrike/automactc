#!/usr/bin/env python
import os
import glob
import sys
import hashlib
import itertools
import traceback
from collections import OrderedDict
from datetime import datetime
from functools import partial
from multiprocessing.dummy import Pool as ThreadPool

import pytz
from xattr import listxattr, getxattr

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from automactc.modules.common.base import AutoMacTCModule
from automactc.modules.common.functions import stats2
from automactc.modules.common.functions import get_codesignatures
from automactc.modules.common.functions import read_stream_bplist
from automactc.modules.common.functions import multiglob
from automactc.utils.output import DataWriter


class DirListModule(AutoMacTCModule):
    _mod_filename = __name__

    _headers = [
        'mode', 'size', 'uid', 'gid', 'mtime', 'atime', 'ctime', 'btime', 'path',
        'name', 'sha256', 'md5', 'quarantine', 'wherefrom_1', 'wherefrom_2', 'code_signatures'
    ]

    def __init__(self, *args, **kwargs):
        super(DirListModule, self).__init__(*args, **kwargs)
        self._counter = 0

    def _shasum(self, filename, filesize, block_size=65536):
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

    @staticmethod
    def _xattr_get(fullpath, attr_name):
        try:
            list_attrs = listxattr(fullpath)
            if len(list_attrs) > 0 and attr_name in list_attrs:
                out = getxattr(fullpath, attr_name)
                return out
            else:
                return ''
        except:
            return 'ERROR'

    def _handle_files(self, root, name):
        self._counter += 1

        if not self.options.quiet:
            if self.options.debug:
                sys.stdout.write('dirlist        : INFO     Wrote %d lines in %s | FileName: %s \033[K\r' % (self._counter, datetime.now(pytz.UTC)-self.options.start_time, name))
            else:
                sys.stdout.write('dirlist        : INFO     Wrote %d lines in %s \r' % (self._counter, datetime.now(pytz.UTC)-self.options.start_time))
            sys.stdout.flush()
        # get timestamps and metadata for each file
        record = OrderedDict((h, '') for h in self._headers)
        stat_data = stats2(os.path.join(root, name))
        record.update(stat_data)

        # get quarantine extended attribute for each file, if available
        if stat_data['mode'] != "Other":
            try:
                quarantine = self._xattr_get(os.path.join(root, name),"com.apple.quarantine").split(';')[2]
            except:
                quarantine = self._xattr_get(os.path.join(root, name),"com.apple.quarantine")
            record['quarantine'] = quarantine.replace('\\x20',' ')

        # get wherefrom extended attribute for each file, if available
        wherefrom = self._xattr_get(os.path.join(root, name),"com.apple.metadata:kMDItemWhereFroms")
        if wherefrom != "" and wherefrom.startswith("bplist"):
            record['wherefrom_1'] = wherefrom
        else:
            record['wherefrom_1'] = ['']

        # if hash alg is specified 'none' at amtc runtime, do not hash files. else do sha256 and md5 as specified (sha256 is default at runtime, md5 is user-specified)
        if "none" not in self.options.dir_hash_alg and stat_data['mode'] == "Regular File":
            if 'sha256' in self.options.dir_hash_alg:
                record['sha256'] = self._shasum(os.path.join(root, name),record['size'])
            if 'md5' in self.options.dir_hash_alg:
                record['md5'] = self._md5sum(os.path.join(root, name),record['size'])

        # output.write_entry(record.values())
        return record

    def _filePooler(self, root, file_pool, files):
        func = partial(self._handle_files, root)
        file_data = file_pool.map(func, files)
        return file_data

    def run(self):
        output = DataWriter(self.module_name(), self._headers, self.log, self.run_id, self.options)

        # if there are specific directories to recurse, recurse them.
        if self.options.dir_include_dirs != ['']:
            root_list = []
            for i in self.options.dir_include_dirs:
                root_list.append(os.path.join(self.options.inputdir, i))

            root_list = list(itertools.chain.from_iterable([glob.glob(i) for i in root_list]))
        # if there are no specific directories to recurse, recurse from the root of the inputdir. also write the stats data to
        else:
            root_list = glob.glob(self.options.inputdir)
            record = OrderedDict((h, '') for h in self._headers)
            stat_data = stats2(self.options.inputdir)
            record.update(stat_data)
            output.write_entry(record.values())

        # by default (if no-defaults is NOT in exclusion flag) exclude the following directories
        if 'no-defaults' not in self.options.dir_exclude_dirs:
            if not self.options.forensic_mode:
                default_exclude = [
                    '.fseventsd', '.DocumentRevisions-V100', '.Spotlight-V100',
                    'Users/*/Pictures', 'Users/*/Library/Application Support/AddressBook',
                    'Users/*/Calendar', 'Users/*/Library/Calendars',
                    'Users/*/Library/Preferences/com.apple.AddressBook.plist'
                ]
            else:
                default_exclude = ['.fseventsd', '.DocumentRevisions-V100', '.Spotlight-V100']

        # if no-defaults is in the exclusion flag, remove no-defaults and use the user-provided exclusion list
        else:
            default_exclude = []
            self.options.dir_exclude_dirs.remove('no-defaults')


        # if there are specific directories to exclude, do not recurse them
        if self.options.dir_exclude_dirs != ['']:
            exclude_list = [os.path.join(self.options.inputdir, i).strip("/") for i in default_exclude + self.options.dir_exclude_dirs]
        # if no specific directories are excluded, use default-list (created above)
        else:
            exclude_list = [os.path.join(self.options.inputdir, i).strip("/") for i in default_exclude]

        # if NOT running with -f flag for forensic mode, exclude everything in /Volumes/* to prevent recursion of mounted volumes IN ADDITION to other exclusions.
        if not self.options.forensic_mode:
            exclude_list += [i for i in glob.glob(os.path.join(self.options.inputdir, 'Volumes/*'))]
            exclude_list = multiglob(self.options.inputdir, exclude_list)
        else:
            exclude_list = multiglob('/', exclude_list)

        self.log.debug("The following directories will be excluded from dirlist enumeration: {0}".format(exclude_list))

        filePool = ThreadPool(4)
        for i in root_list:
            for root, dirs, files in os.walk(i, topdown=True):

                # prune excluded directories and files to prevent further recursion into them
                dirs[:] = [d for d in dirs if os.path.join(root,d) not in exclude_list]
                files[:] = [f for f in files if os.path.join(root,f) not in exclude_list]

                # do not recurse into bundles that end with any of the file extensions below UNLESS told to at amtc runtime
                exc_bundles = ('.app', '.framework','.lproj','.plugin','.kext','.osax','.bundle','.driver','.wdgt')
                if root.strip().endswith(exc_bundles) and not (os.path.basename(root)).startswith('.') and self.options.dir_recurse_bundles == False:
                    dirs[:] = []
                    files[:] = []

                if self.options.dir_no_multithreading:
                    file_data = [self._handle_files(root, file_item) for file_item in files]
                else:
                    file_data = self._filePooler(root, filePool, files)

                for record in file_data:
                    wf = record['wherefrom_1']
                    if wf != ['']:
                        try:
                            parsed_wf = read_stream_bplist(wf)
                            parsed_wf_utf8 = [str(a.encode('utf-8')) for a in parsed_wf if a != ""]
                        except:
                            pathname = os.path.join(record['path'],record['name'])
                            parsed_wf_utf8 = ['ERROR']
                            self.log.debug("Could not parse embedded binary plist for kMDItemWhereFroms data from file {0}. {1}".format(pathname,[traceback.format_exc()]))

                        if len(parsed_wf_utf8) > 0:
                            record['wherefrom_1'] = parsed_wf_utf8[0]
                        if len(parsed_wf_utf8) > 1:
                            record['wherefrom_2'] = parsed_wf_utf8[1]
                        else:
                            record['wherefrom_1'] = ''
                    else:
                        record['wherefrom_1'] = ''

                    output.write_entry(record.values())

                # bundles that will be code-sig checked
                check_signatures_bundles = ('.app','.kext','.osax')
                for name in dirs:
                    self._counter += 1
                    if not self.options.quiet:
                        if self.options.debug:
                            sys.stdout.write('dirlist        : INFO     Wrote %d lines in %s | FileName: %s \033[K\r' % (self._counter, datetime.now(pytz.UTC)-self.options.start_time, name))
                        else:
                            sys.stdout.write('dirlist        : INFO     Wrote %d lines in %s \r' % (self._counter, datetime.now(pytz.UTC)-self.options.start_time))
                        sys.stdout.flush()

                    # get timestamps and metadata for each file
                    record = OrderedDict((h, '') for h in self._headers)
                    stat_data = stats2(os.path.join(root, name))
                    record.update(stat_data)

                    # directory is bundle that ends with either of the three extensions, check its code signatures
                    if self.options.dir_no_code_signatures is False and name.endswith(check_signatures_bundles) and not name.startswith('.'): #meaning DO process code signatures
                        record['code_signatures'] = str(get_codesignatures(os.path.join(root, name)))

                    output.write_entry(record.values())

        filePool.close()
        filePool.join()

        if not self.options.quiet:
            sys.stdout.write('\n')
            sys.stdout.flush()
