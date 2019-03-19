#!/usr/bin/env python

'''
@ author: Kshitij Kumar
@ email: kshitijkumar14@gmail.com, kshitij.kumar@crowdstrike.com

@ purpose:

Helper functions for repeated use in various modules are called from here.

'''

from itertools import groupby
from operator import itemgetter
from collections import OrderedDict
from stat import *
from datetime import datetime, timedelta
from codesign import CodeSignChecker
from importlib import import_module

import os
import time
import subprocess
import ccl_bplist as bplist
import csv
import re
import dateutil.parser as parser
from functools import wraps
import errno
import os
import signal
import io
import logging
import traceback
import sqlite3
import shutil
import glob

log = logging.getLogger('functions')


# Borrowed from https://stackoverflow.com/questions/2281850/timeout-function-if-it-takes-too-long-to-finish
class TimeoutError(Exception):
	pass


def timeout(seconds=10, error_message=os.strerror(errno.ETIME)):
	def decorator(func):
		def _handle_timeout(signum, frame):
			raise TimeoutError("Process timed out")

		def wrapper(*args, **kwargs):
			signal.signal(signal.SIGALRM, _handle_timeout)
			signal.alarm(seconds)
			try:
				result = func(*args, **kwargs)
			finally:
				signal.alarm(0)
			return result

		return wraps(func)(wrapper)

	return decorator


def multiglob(inputdir, list_of_locs):
    compilation = []
    for loc in list_of_locs:
        globbed = glob.glob(os.path.join(inputdir, loc))
        if len(globbed) == 0:
            log.debug("Files not found in: {0}".format(os.path.join(inputdir, loc)))
        else:
            compilation.append(globbed)

    out = sum(compilation, [])
    return out


# Run sqlite query against a sqlite database and return data (a list).
def query_db(db_file, query, outputdir):
	try:
		data = sqlite3.connect(db_file+'s').cursor().execute(query).fetchall()
	except sqlite3.OperationalError:
		db_tmp = os.path.join(outputdir,str(os.path.basename(db_file))+'-tmp_amtc')
		shutil.copyfile(db_file,db_tmp)
		time.sleep(3)
		try:
			data = sqlite3.connect(db_tmp).cursor().execute(query).fetchall()
		except:        
			data = []
			log.error("Could not parse: {0}".format(db_file))
			log.error("Sqlite3 traceback: {0}".format([traceback.format_exc()]))
		rm_tmp = glob.glob(os.path.join(outputdir,'*-tmp_amtc*'))
		rm = [os.remove(tmpfile) for tmpfile in rm_tmp]
	return data


# Return value of a key from a nested dictionary-like object.
def finditem(obj, key):
	if key in obj: return obj[key]
	for k, v in obj.items():
		if isinstance(v,dict):
			item = finditem(v, key)
			if item is not None:
				return item


# Check code signatures of a file based on filepath.
def get_codesignatures(fullpath, nocheck=False):
	if not nocheck:
		if not os.path.exists(fullpath):
			return ['ERROR-FILE-DNE']
		try:
			signers = CodeSignChecker.get_signature_chain(fullpath)
			if len(signers) == 0:
				return ['Unsigned']
			else:
				return signers
		except:
			p = subprocess.Popen(['codesign', '-dv', '--verbose=2', 
				str(fullpath)],stderr=subprocess.PIPE).communicate()[-1].split('\n')
			signers = [line.replace('Authority=','') for line in p if line.startswith('Authority=')]
			if len(signers) == 0:
				return ['Unsigned']
			else:
				return signers
	else:
		return ""


# Convert chrome DB timestamp to ISO8601, UTC format.
def chrome_time(microseconds):
	if microseconds not in ['',None,0]:
		timestamp = datetime(1601,1,1) + timedelta(microseconds=int(microseconds))
		return parser.parse(str(timestamp)).isoformat()+'Z'
	else:
		return ''


# Convert firefox DB timestamp to ISO8601, UTC format.
def firefox_time(microseconds):
	if microseconds not in ['',None,0]:
		timestamp = datetime(1970,1,1) + timedelta(microseconds=int(microseconds))
		return parser.parse(str(timestamp)).isoformat()+'Z'
	else:
		return ''


# Convert cocoa webkit DB timestamp to ISO8601, UTC format.
def cocoa_time(seconds):
	if seconds not in ['',None,0]:
		timestamp = datetime(2001,1,1) + timedelta(seconds=int(seconds))
		return parser.parse(str(timestamp)).isoformat()+'Z'
	else:
		return ''


# Read data from plist stored in a file.
def read_bplist(file_location):
	with open(file_location,'rb') as fd:
		plist_array = bplist.load(fd)
		return [plist_array]


# Read data from plist stored in a file.
def read_stream_bplist(string):
	w = buffer(string)
	plist_array = bplist.load(io.BytesIO(w))
	return plist_array


# Get file metadata.
def stats2(file,oMACB=False):
	os.environ['TZ'] = 'UTC0'
	fields = ['mode','size','uid','gid','mtime','atime','ctime','btime','path','name']
	
	try:
		stat = os.lstat(file)
		statrecord = OrderedDict((h, '') for h in fields)
		mode = stat.st_mode

		if S_ISDIR(mode):
			statrecord['mode'] = "Directory"
		elif S_ISREG(mode):
			statrecord['mode'] = "Regular File"
		else:
			statrecord['mode'] = "Other"

		statrecord['uid'] = stat.st_uid
		statrecord['gid'] = stat.st_gid
		statrecord['size'] = stat.st_size

		statrecord['name'] = os.path.basename(file)
		path = os.path.dirname(file)
		if statrecord['mode'] == "Directory":
			path = os.path.join(path,statrecord['name'])
			statrecord['name'] = ''
		elif statrecord['mode'] == "Regular File":
			path = path+'/'
		statrecord['path'] = path.replace('//','/').replace('//','/')

		statrecord['mtime'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(stat.st_mtime))
		statrecord['atime'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(stat.st_atime))
		statrecord['ctime'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(stat.st_ctime))
		statrecord['btime'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(stat.st_birthtime))
	except:
		statrecord = OrderedDict((h, 'ERROR') for h in fields)
		statrecord['path'] = file
	
	if oMACB is False:
		return(statrecord)
	else:
		return({k:v for k,v in statrecord.items() if 'time' in k})
