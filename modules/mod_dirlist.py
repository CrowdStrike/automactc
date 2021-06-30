"""A module to recurse through the file system and capture metadata for files
and folders on disk.

The metadata collected includes:
- MD5 and SHA256 hashes
- MACB timestamps
- quarantine, wherefrom, and downloaddate xattribute information
See the stats2 function in common/functions.py for further details
on the metadata collected.
"""

from __future__ import print_function

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from .common.functions import (get_codesignatures, multiglob,
								read_stream_bplist, stats2,
								MultiprocessingPool)

try:
	from xattr import getxattr, listxattr
except Exception:
	from .common.dep.xattr import getxattr, listxattr


# IMPORT STATIC VARIABLES FROM MAIN
import errno
import glob
import hashlib
import itertools
import logging
import os
import sys
import traceback
from collections import OrderedDict
from datetime import datetime

from __main__ import (archive, data_writer, debug, dirlist_exclude_dirs,
						dirlist_include_dirs, dirlist_no_multithreading,
						forensic_mode, full_prefix, hash_alg, hash_size_limit,
						inputdir, inputsysdir, no_code_signatures, no_tarball,
						outputdir, quiet, rtr, recurse_bundles, startTime, verbose)

if sys.version_info[0] < 3:
	import Foundation

_modName = __name__.split('_')[-1]
_modVers = '2.0.0'
log = logging.getLogger(_modName)

INVALID_EXTENSIONS = {'.app', '.framework', '.lproj', '.plugin', '.kext', '.osax', '.bundle', '.driver', '.wdgt', '.Office', '.blacklight'}
CHECK_SIGNATURE_BUNDLES = {'.app', '.kext', '.osax'}
DEFAULT_DIR_EXCLUDE = [  	# must be file paths glob format from root (not simply extensions)
	'.fseventsd', '.DocumentRevisions-V100', '.Spotlight-V100',
	'Users/*/Pictures', 'Users/*/Library/Application Support/AddressBook',
	'Users/*/Calendar', 'Users/*/Library/Calendars',
	'Users/*/Library/Preferences/com.apple.AddressBook.plist',
	'/System/Volumes/Data/private/var/folders/kb/*', '/System/Volumes/Data/private/var/folders/zz/*'
]
FORENSIC_DIR_EXCLUDE = [  	# must be file paths glob format from root (not simply extensions)
	'.fseventsd', '.DocumentRevisions-V100', '.Spotlight-V100'
]
OUTPUT_BUFFER_CAP = 100000  # cap num entries to keep in output buffer
WORKERS = 5  				# number of parallel threads to run when multithreading
HEADERS = ['mode', 'size', 'owner', 'uid', 'gid', 'mtime', 'atime', 'ctime', 'btime', 'path', 'name', 'sha256', 'md5', 'quarantine', 'wherefrom_1', 'wherefrom_2', 'downloaddate', 'code_signatures']
counter = 0
output = None


def _shasum(filename, filesize, block_size=65536):
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


def _md5sum(filename, filesize, block_size=65536):
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


def _xattr_get(fullpath, attr_name):
	"""
	Get an extended attribute, attr_name, from a file specified as fullpath.
	Caller must handle all types of returns.
	Returns list of extended attributes if Py2 and no exception.
	Returns raw bplist value (bytes) if Py3 or error with Py2.
	Returns None if unhandled exception.

	This method is adapted from Yelp/osxcollector, which in turn adopted their
	method from https://gist.github.com/dunhamsteve/2889617
	"""
	try:  # TODO: Make more generic
		attr_val = getxattr(fullpath, attr_name)
		if attr_val.startswith(b'bplist'):
			if sys.version_info[0] < 3:
				try:
					plist_array, _, plist_error = Foundation.NSPropertyListSerialization.propertyListWithData_options_format_error_(buffer(attr_val), 0, None, None)
					if plist_error:
						log.debug('plist de-serialization error: {0}'.format(plist_error))
						return None
					return list(plist_array)
				except Exception as e:
					log.debug('_xattr_get failed on {0} for {1}: {2}'.format(fullpath, attr_name, str(e)))
					return attr_val  # caller must handle, raw bplist
			else:
				return attr_val  # caller must handle, raw bplist
		else:
			return [attr_val]
	except KeyError:
		pass
	except IOError:
		pass
	except Exception as e:
		log.debug('Unhandled exception in _xattr_get: {0}, {1}: {2}'.format(fullpath, attr_name, str(e)))
		pass
	return None  # caller must handle


def _is_valid_dir(dir):
	"""
	Returns True if directory should be included in parse set.
	Omits directories with invalid extension
	"""
	return _is_valid_file(dir)


def _is_valid_file(file):
	"""
	Returns True if file should be included in parse set.
	Omits files with invalid extension (ex. bundles)
	"""
	if file == "":
		return False
	ext = os.path.splitext(file)
	return ext[1] not in INVALID_EXTENSIONS


def _get_wherefrom_xattr(fullpath):
	"""
	Returns a tuple containing the up to two wherefrom xattr values for the file at fullpath.
	Tuple contains empty strings where the value did not exist.
	"""
	wf1 = ''
	wf2 = ''
	attr_val = _xattr_get(fullpath, "com.apple.metadata:kMDItemWhereFroms")
	if attr_val is None:
		return (wf1, wf2)
	if isinstance(attr_val, list):
		if len(attr_val) > 1:
			return (attr_val[0], attr_val[1])
		else:
			return (attr_val[0], '')
	if attr_val.startswith(b'bplist'):
		try:
			parsed_attr_val = read_stream_bplist(attr_val)
			parsed_attr_val_utf8 = [str(a.encode('utf-8')) for a in parsed_attr_val if a != ""]
		except Exception as e:
			pathname = os.path.join(record['path'], record['name'])
			parsed_attr_val_utf8 = ['ERROR']
			log.debug("Could not parse embedded binary plist for kMDItemWhereFroms data from file {0}: {1}. {2}".format(pathname, attr_val, str(e)))

		if len(parsed_attr_val_utf8) > 0:
			wf1 = parsed_attr_val_utf8[0]
		if len(parsed_attr_val_utf8) > 1:
			wf2 = parsed_attr_val_utf8[1]
		else:
			wf1 = ''
	return (wf1, wf2)


def _get_quarantine_xattr(fullpath):
	attr_val = _xattr_get(fullpath, "com.apple.quarantine")
	if attr_val is not None:
		if isinstance(attr_val, list):
			spl = attr_val[0].split(b';')
			if len(spl) > 2:
				return [spl[2]]
		return attr_val
	return ''


def _get_downloaddate_xattr(fullpath):
	attr_val = _xattr_get(fullpath, "com.apple.metadata:kMDItemDownloadedDate")
	if attr_val is not None:
		return attr_val
	return ''


def parse_file(file):
	"""
	Parses a file (filepath) and writes output
	"""
	try:
		global counter
		counter += 1

		record = OrderedDict((h, '') for h in HEADERS)
		stat = os.lstat(file)  # one os.stat call

		# get timestamps and metadata for each file
		stat_data = stats2(file, stat=stat)
		record.update(stat_data)

		# get quarantine extended attribute for each file, if available
		if stat_data['mode'] != "Other":
			record['quarantine'] = _get_quarantine_xattr(file)

		# get wherefrom extended attribute for each file, if available
		wf1, wf2 = _get_wherefrom_xattr(file)
		record['wherefrom_1'] = wf1
		record['wherefrom_2'] = wf2

		# get downloaddate extended attribute for each file, if available
		record['downloaddate'] = _get_downloaddate_xattr(file)

		# if hash alg is specified 'none' at amtc runtime, do not hash files. else do sha256 and md5 as specified (sha256 is default at runtime, md5 is user-specified)
		if "none" not in hash_alg and stat_data['mode'] == "Regular File":
			if 'sha256' in hash_alg:
				record['sha256'] = _shasum(file, record['size'])
			if 'md5' in hash_alg:
				record['md5'] = _md5sum(file, record['size'])

	except EnvironmentError as e:  # Optionally log this
		if e.errno == errno.ENOENT:
			# log.debug("%s: %s", str(e), file)
			pass
		elif e.errno == errno.EPERM:
			# log.debug("%s: %s", str(e), file)
			pass
		else:
			log.debug("Unhandled exception: %s: %s", file, str(e))

	except Exception as e:
		log.debug(
			'Unhandled exception in worker process: {0} - {1}'.format(str(e), [traceback.format_exc()])
		)
	finally:
		if quiet is False and rtr is False:
			if debug:
				sys.stdout.write('dirlist        : INFO     Parsed %d files & dirs in %s | FileName: %s \033[K\r' % (counter, datetime.utcnow() - startTime, file))
			else:
				sys.stdout.write('dirlist        : INFO     Parsed %d files & dirs in %s \r' % (counter, datetime.utcnow() - startTime))
			sys.stdout.flush()

		global output
		output.write_record(record, buffer_cap=OUTPUT_BUFFER_CAP)


def parse_dir(dir):
	"""
	Parses a directory (full filepath) and writes output
	"""
	try:
		global counter
		counter += 1

		record = OrderedDict((h, '') for h in HEADERS)
		stat = os.lstat(dir)  # one os.stat call

		# get timestamps and metadata for each dir
		stat_data = stats2(dir, stat=stat)
		record.update(stat_data)

		# bundles that will be code-sig checked
		if no_code_signatures is False and os.path.splitext(dir)[1].lower() in CHECK_SIGNATURE_BUNDLES and not dir.startswith('.'):
			print("\nSTART Code Sig: {0}\n".format(dir))
			try:
				record['code_signatures'] = str(get_codesignatures(dir))
			except Exception as e:
				log.error("Dirlist Codesig: {0}".format(str(e)))
				record['code_signatures'] = 'ERROR'
			print("\nEND Code Sig: {0}\n".format(dir))

	except EnvironmentError as e:    # TODO: Do we log this?
		if e.errno != errno.ENOENT:
			log.debug("Unhandled exception: %s: %s", dir, str(e))
		# else:
			# log.debug("parse_file: File not found? '{0}': {1}".format(dir, str(e)))
	except Exception as e:
		log.debug(
			'Unhandled exception in worker process: {0} - {1}'.format(str(e), [traceback.format_exc()])
		)
	finally:
		if quiet is False and rtr is False:
			if debug:
				sys.stdout.write('dirlist        : INFO     Parsed %d files & dirs in %s | FileName: %s \033[K\r' % (counter, datetime.utcnow() - startTime, dir))
			else:
				sys.stdout.write('dirlist        : INFO     Parsed %d files & dirs in %s \r' % (counter, datetime.utcnow() - startTime))
			sys.stdout.flush()

		global output
		output.write_record(record, buffer_cap=OUTPUT_BUFFER_CAP)


if __name__ != "__main__":
	output = data_writer(_modName, HEADERS)

	inputdir_list = [inputdir, inputsysdir]  	# 10.15+ style fs roots
	root_list = []  							# these are the 'roots' we will recurse
	dir_exclude_list = []  						# actual filepaths to exclude
	dir_include_list = []						# specific filepaths to process only

	# check for specific directories to recurse
	if dirlist_include_dirs != ['']:
		for e in inputdir_list:
			for i in dirlist_include_dirs:
				dir_include_list.extend([fp for fp in glob.glob(os.path.join(e, i))])
		root_list = dir_include_list
	else:  # otherwise, recurse from the root of inputdir
		for idir in inputdir_list:
			if idir == '':
				continue
			root_list += glob.glob(idir)
			record = OrderedDict((h, '') for h in HEADERS)
			stat_data = stats2(idir)
			record.update(stat_data)
			output.write_record(record)

	# by default (if no-defaults is NOT in exclusion flag) exclude the following directories
	if 'no-defaults' not in dirlist_exclude_dirs:
		if not forensic_mode:
			default_exclude = DEFAULT_DIR_EXCLUDE
		else:
			default_exclude = FORENSIC_DIR_EXCLUDE
	else:  # if no-defaults is in the exclusion flag, remove no-defaults and use the user-provided exclusion list
		default_exclude = []
		dirlist_exclude_dirs.remove('no-defaults')

	# if there are specific directories to exclude, do not recurse them
	if dirlist_exclude_dirs != ['']:
		for e in inputdir_list:
			for i in dirlist_exclude_dirs:
				dir_exclude_list.extend([fp for fp in glob.glob(os.path.join(e, i))])
			for i in default_exclude:
				dir_exclude_list.extend([fp for fp in glob.glob(os.path.join(e, i))])

	# if no specific directories are excluded, use default-list (created above)
	else:
		for e in inputdir_list:
			for i in default_exclude:
				dir_exclude_list.extend([fp for fp in glob.glob(os.path.join(e, i))])

	# if NOT running with -f flag for forensic mode, exclude everything in /Volumes/* to prevent recursion of mounted volumes IN ADDITION to other exclusions.
	if not forensic_mode:
		for e in inputdir_list:
			dir_exclude_list.extend([i for i in glob.glob(os.path.join(e, 'Volumes/*'))])

	dir_exclude_set = set(dir_exclude_list)
	log.debug("The following directories will be excluded from dirlist enumeration: {0}".format(dir_exclude_list))

	# determine which hashing algorithms to run
	if type(hash_alg) is list:
		hash_alg = [''.join([x.lower() for x in i]) for i in hash_alg]
	elif type(hash_alg) is str:
		hash_alg = [hash_alg]

	if debug or verbose:
		log.debug("inputdir_list: %s", inputdir_list)
		log.debug("root_list: %s", root_list)
		log.debug("dirlist_include_dirs: %s", dirlist_include_dirs)
		log.debug("dirlist_exclude_dirs: %s", dirlist_exclude_dirs)
		log.debug("dir_exclude_set: %s", dir_exclude_set)
		log.debug("default_exclude: %s", default_exclude)
		log.debug("hash_alg: %s", hash_alg)

	file_count = 0
	dir_count = 0
	filepaths = []
	dirpaths = []
	start = datetime.now()
	for root in root_list:
		for dirpath, dirnames, filenames in os.walk(root, topdown=True):
			# exclude directories and files, must use topdown=True
			dirnames[:] = list(filter(lambda x: x not in dir_exclude_set, dirnames))
			dirnames[:] = list(filter(lambda x: _is_valid_dir(x), dirnames))
			filenames[:] = list(filter(lambda x: _is_valid_file(x), filenames))

			# Convert filenames to full paths
			full_path_fnames = map(lambda fn: os.path.join(dirpath, fn), filenames)
			filepaths.extend(list(full_path_fnames))
			file_count += len(filenames)

			full_path_dirnames = map(lambda dr: os.path.join(dirpath, dr), dirnames)
			dirpaths.extend(list(full_path_dirnames))
			dir_count += len(dirnames)

			if quiet is False and rtr is False:
				sys.stdout.write('dirlist        : INFO	 Found %d files & dirs in %s \r' % (file_count + dir_count, datetime.utcnow() - startTime))
				sys.stdout.flush()

	if debug or verbose:
		log.debug("time to walk: %s", (datetime.now() - start))
		log.info("found {0} files/folders                   ".format(file_count + dir_count))
		log.info("filepaths: {0} | dirpaths: {1} | total: {2}".format(len(filepaths), len(dirpaths), len(filepaths) + len(dirpaths)))

	# parse files
	start = datetime.now()
	counter = 0
	if dirlist_no_multithreading:
		file_results = [parse_file(file) for file in filepaths]
	else:
		file_results = MultiprocessingPool(parse_file, filepaths, WORKERS).run()

	if debug or verbose:
		log.debug("time to parse files: %s", datetime.now() - start)
		log.debug("processsed files: %d", counter)
		log.debug("file_results: %d", len(list(file_results)))

	# parse dirs
	start = datetime.now()
	if dirlist_no_multithreading:
		dir_results = [parse_dir(dir) for dir in dirpaths]
	else:
		dir_results = MultiprocessingPool(parse_dir, dirpaths, WORKERS).run()

	if debug or verbose:
		log.debug("time to parse dirs: %s", datetime.now() - start)
		log.debug("processsed dirs: %d", counter)
		log.debug("dir_results: %d", len(list(dir_results)))

	output.flush_record()  # flush output writer buffer for entries < buffer_cap

	if quiet is False and rtr is False:  # Final flush to account for filecount status printer
		print('\n', end='\x1b[1K\r')
		sys.stdout.flush()
