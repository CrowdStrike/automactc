#!/usr/bin/env python

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from .common.dep import six
from .common.functions import stats2
from .common.functions import get_codesignatures
from .common.functions import read_stream_bplist
from .common.functions import multiglob
if six.PY3:
	from .common.dep.xattr import listxattr, getxattr
else:
	from xattr import listxattr, getxattr


# IMPORT STATIC VARIABLES FROM MAIN
from __main__ import inputdir
from __main__ import outputdir
from __main__ import forensic_mode
from __main__ import no_tarball
from __main__ import quiet
from __main__ import dirlist_include_dirs
from __main__ import dirlist_exclude_dirs
from __main__ import dirlist_no_multithreading
from __main__ import hash_alg
from __main__ import hash_size_limit
from __main__ import no_code_signatures
from __main__ import recurse_bundles
from __main__ import debug

from __main__ import archive
from __main__ import startTime
from __main__ import full_prefix
from __main__ import data_writer

import os
import glob
import sys
import hashlib
import itertools
import time
import io
import logging
import traceback
from collections import OrderedDict
from datetime import datetime
from multiprocessing.dummy import Pool as ThreadPool

_modName = __name__.split('_')[-2]
_modVers = '.'.join(list(__name__.split('_')[-1][1:]))
log = logging.getLogger(_modName)


def shasum(filename, filesize, block_size=65536):
	if filesize <= hash_size_limit and filesize > 0:
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


def md5sum(filename, filesize, block_size=65536):
	if filesize <= hash_size_limit and filesize > 0:
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


def xattr_get(fullpath, attr_name):
	try:
		list_attrs = listxattr(fullpath)
		if len(list_attrs) > 0 and attr_name in list_attrs:
			out = getxattr(fullpath, attr_name)
			return out
		else:
			return ''
	except:
		return 'ERROR'


def handle_files(name):
	global counter
	counter+=1

	if not quiet:
		if debug:
			sys.stdout.write('dirlist        : INFO     Wrote %d lines in %s | FileName: %s \033[K\r' % (counter,datetime.utcnow()-startTime,name))
		else:
			sys.stdout.write('dirlist        : INFO     Wrote %d lines in %s \r' % (counter,datetime.utcnow()-startTime))
		sys.stdout.flush()
	# get timestamps and metadata for each file
	record = OrderedDict((h, '') for h in headers)
	stat_data = stats2(os.path.join(root, name))
	record.update(stat_data)

	# get quarantine extended attribute for each file, if available
	if stat_data['mode'] != "Other":
		try:
			quarantine = xattr_get(os.path.join(root, name),"com.apple.quarantine").split(';')[2]
		except:
			quarantine = xattr_get(os.path.join(root, name),"com.apple.quarantine")
		try:
			record['quarantine'.encode()] = quarantine.replace('\\x20',' ')
		except TypeError as e:
			log.debug(e)
			log.debug("Encode/decoding error")
			record['quarantine'] = quarantine.decode('utf-8').replace('\\x20',' ')

	# get wherefrom extended attribute for each file, if available
	wherefrom = xattr_get(os.path.join(root, name),"com.apple.metadata:kMDItemWhereFroms")
	try: #handle diff encoding for dirlist files
		if wherefrom != "" and wherefrom.startswith("bplist".encode()):
			record['wherefrom_1'] = wherefrom
		else:
			record['wherefrom_1'] = ['']
	except TypeError:
		if wherefrom != "" and wherefrom.startswith("bplist"):
			record['wherefrom_1'] = wherefrom
		else:
			record['wherefrom_1'] = ['']

	# if hash alg is specified 'none' at amtc runtime, do not hash files. else do sha256 and md5 as specified (sha256 is default at runtime, md5 is user-specified)
	if "none" not in hash_alg and stat_data['mode'] == "Regular File":
		if 'sha256' in hash_alg:
			record['sha256'] = shasum(os.path.join(root, name),record['size'])
		if 'md5' in hash_alg:
			record['md5'] = md5sum(os.path.join(root, name),record['size'])

	# output.write_entry(record.values())
	return record


def filePooler(files):
	file_data = filePool.map(handle_files, files)
	return file_data


headers = ['mode','size','owner','uid','gid','mtime','atime','ctime','btime','path','name','sha256','md5','quarantine','wherefrom_1','wherefrom_2','code_signatures']
output = data_writer(_modName, headers)

# if there are specific directories to recurse, recurse them.
if dirlist_include_dirs != ['']:
	root_list = []
	for i in dirlist_include_dirs:
		root_list.append(os.path.join(inputdir, i))

	root_list = list(itertools.chain.from_iterable([glob.glob(i) for i in root_list]))
# if there are no specific directories to recurse, recurse from the root of the inputdir. also write the stats data to
else:
	root_list = glob.glob(inputdir)
	record = OrderedDict((h, '') for h in headers)
	stat_data = stats2(inputdir)
	record.update(stat_data)
	output.write_entry(record.values())


# by default (if no-defaults is NOT in exclusion flag) exclude the following directories
if 'no-defaults' not in dirlist_exclude_dirs:
	if not forensic_mode:
		default_exclude = [
					   '.fseventsd','.DocumentRevisions-V100','.Spotlight-V100',
					   'Users/*/Pictures', 'Users/*/Library/Application Support/AddressBook',
					   'Users/*/Calendar', 'Users/*/Library/Calendars',
					   'Users/*/Library/Preferences/com.apple.AddressBook.plist'
					   ]
	else:
		default_exclude = ['.fseventsd','.DocumentRevisions-V100','.Spotlight-V100']

# if no-defaults is in the exclusion flag, remove no-defaults and use the user-provided exclusion list
else:
	default_exclude = []
	dirlist_exclude_dirs.remove('no-defaults')


# if there are specific directories to exclude, do not recurse them
if dirlist_exclude_dirs != ['']:
	exclude_list = [os.path.join(inputdir, i).strip("/") for i in default_exclude + dirlist_exclude_dirs]
# if no specific directories are excluded, use default-list (created above)
else:
	exclude_list = [os.path.join(inputdir, i).strip("/") for i in default_exclude]

# if NOT running with -f flag for forensic mode, exclude everything in /Volumes/* to prevent recursion of mounted volumes IN ADDITION to other exclusions.
if not forensic_mode:
	exclude_list += [i for i in glob.glob(os.path.join(inputdir, 'Volumes/*'))]
	exclude_list = multiglob(inputdir, exclude_list)
else:
	exclude_list = multiglob('/', exclude_list)

log.debug("The following directories will be excluded from dirlist enumeration: {0}".format(exclude_list))

# determine which hashing algorithms to run
if type(hash_alg) is list:
	hash_alg = [''.join([x.lower() for x in i]) for i in hash_alg]
elif type(hash_alg) is str:
	hash_alg = [hash_alg]

counter=0

filePool = ThreadPool(4)
for i in root_list:
	for root, dirs, files in os.walk(i, topdown=True):

		# prune excluded directories and files to prevent further recursion into them
		dirs[:] = [d for d in dirs if os.path.join(root,d) not in exclude_list]
		files[:] = [f for f in files if os.path.join(root,f) not in exclude_list]

		# do not recurse into bundles that end with any of the file extensions below UNLESS told to at amtc runtime
		exc_bundles = ('.app', '.framework','.lproj','.plugin','.kext','.osax','.bundle','.driver','.wdgt')
		if root.strip().endswith(exc_bundles) and not (os.path.basename(root)).startswith('.') and recurse_bundles == False:
			dirs[:] = []
			files[:] = []

		if dirlist_no_multithreading:
			file_data = [handle_files(file) for file in files]
		else:
			file_data = filePooler(files)

		for record in file_data:
			wf = record['wherefrom_1']
			if wf != ['']:
				try:
					parsed_wf = read_stream_bplist(wf)
					parsed_wf_utf8 = [str(a.encode('utf-8')) for a in parsed_wf if a != ""]
				except:
					pathname = os.path.join(record['path'],record['name'])
					parsed_wf_utf8 = ['ERROR']
					log.debug("Could not parse embedded binary plist for kMDItemWhereFroms data from file {0}. {1}".format(pathname,[traceback.format_exc()]))

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
			counter+=1
			if not quiet:
				if debug:
					sys.stdout.write('dirlist        : INFO     Wrote %d lines in %s | FileName: %s \033[K\r' % (counter,datetime.utcnow()-startTime,name))
				else:
					sys.stdout.write('dirlist        : INFO     Wrote %d lines in %s \r' % (counter,datetime.utcnow()-startTime))
				sys.stdout.flush()

			# get timestamps and metadata for each file
			record = OrderedDict((h, '') for h in headers)
			stat_data = stats2(os.path.join(root, name))
			record.update(stat_data)

			# directory is bundle that ends with either of the three extensions, check its code signatures
			if no_code_signatures is False and name.endswith(check_signatures_bundles) and not name.startswith('.'): #meaning DO process code signatures
				record['code_signatures'] = str(get_codesignatures(os.path.join(root, name)))

			output.write_entry(record.values())

filePool.close()
filePool.join()

if not quiet:
	sys.stdout.write('\n')
	sys.stdout.flush()
