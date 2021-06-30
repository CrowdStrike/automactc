#!/usr/bin/env python

'''

@ purpose:

Helper functions for repeated use in various modules are called from here.

'''

import errno
import glob
import io
import logging
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
import traceback
from collections import OrderedDict
from datetime import datetime, timedelta
from functools import wraps
from multiprocessing.dummy import Pool as ThreadPool
from pwd import getpwuid
from stat import *

from . import ccl_bplist as bplist
from .codesign import CodeSignChecker
from .dateutil import parser

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


class SQLiteDB(object):
	"""
	Class to wrap SQLite3 operations
	"""

	def __init__(self, db_filepath='', is_temp_filepath=False):
		"""
		Initialize the SQLiteDB wrapper class
		"""
		super(SQLiteDB, self).__init__()
		self._db_conn = None
		self._is_temp_filepath = is_temp_filepath
		self._db_filepath = db_filepath
		self._db_wal_filepath = ''

	def tables(self):
		"""
		Return a list of the tables in the database
		"""
		if self._db_conn is None:
			raise ValueError('DB connection not set, must run open first.')

		query = "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
		return self.query(query)

	def column_headers(self, table_name):
		"""
		Return a list of column headers for the specified table_name
		"""
		if self._db_conn is None:
			raise ValueError('DB connection not set, must run open first.')
		try:
			col_headers = self._db_conn.cursor().execute('SELECT * from {0}'.format(table_name))
			names = list(map(lambda x: x[0], col_headers.description))
		except sqlite3.OperationalError:
			log.debug("table_name '{0}' was not found in database.".format(table_name))
			names = []
		return names

	def close(self):
		"""
		Close the SQLite database the class wraps
		Returns boolean of success or failure to close, or exception raised
		"""
		if self._db_conn is not None:
			try:
				pass
			except Exception as e:
				log.warn('Unable to close connection to db {0}: {1}'.format(self._db_filepath, str(e)))
				return False
		if self._is_temp_filepath:
			if self._db_filepath != '':
				if os.path.exists(self._db_filepath):
					try:
						os.remove(self._db_filepath)
						self._db_filepath = ''
						self._is_temp_filepath = False
					except (OSError, IOError) as e:
						log.warn('Unable to remove temp db file {0}: {1}'.format(self._db_filepath, str(e)))
						self._db_filepath = ''
						self._is_temp_filepath = False
						return False

			if self._db_wal_filepath != '':
				if os.path.exists(self._db_wal_filepath):
					try:
						os.remove(self._db_wal_filepath)
					except (OSError, IOError) as e:
						log.warn('Unable to remove temp db wal file {0}: {1}'.format(self._db_wal_filepath, str(e)))
						self._db_wal_filepath = ''
						return False
		return True

	def open(self, db_filepath, outputdir):
		"""
		Open the specified SQLite3 db file at db_filepath. If the file cannot be opened, 
		it attempts to copy then open it from a temporary location. 
		Sets the _db_filepath, _db_conn as appropriate.

		Returns True if successfully connected and False or an exception is raised otherwise.
		"""
		if not db_filepath:
			raise ValueError('Missing db_filepath string.')

		if sys.version_info[0] < 3:
			self._db_filepath = db_filepath
			try:
				self._db_conn = sqlite3.connect(db_filepath)
				return True
			except sqlite3.OperationalError:
				# copy to temp location
				curr_db_filepath = self._db_filepath
				temp_db_filepath = os.path.join(outputdir, str(os.path.basename(db_filepath)) + '-tmp_amtc')
				shutil.copyfile(curr_db_filepath, temp_db_filepath)  # blocking

				# open in temp location
				try:
					self._db_conn = sqlite3.connect(temp_db_filepath)
					self.tables()
					self._db_filepath = temp_db_filepath  # success, replace filepath
					return True
				except sqlite3.OperationalError as e:
					log.error('Unable to open SQLite3 db {0} normally or via temp copy: {1}'.format(db_filepath, str(e)))

					if os.path.exists(temp_db_filepath):  # clean up
						try:
							os.remove(temp_db_filepath)
						except (OSError, IOError) as e:
							log.warn('Unable to remove temp db file {0}: {1}'.format(temp_db_filepath, str(e)))

					self._db_conn = None
					self._db_filepath = ''
					self._is_temp_filepath = False
					return False

		else:  # py3
			self._db_filepath = db_filepath
			try:
				self._db_conn = sqlite3.connect('file:{' + db_filepath + '}?mode=ro', uri=True)  # enforce RO for 3.4+ version
				return True
			except sqlite3.OperationalError:
				# copy to temp location
				curr_db_filepath = self._db_filepath
				temp_db_filepath = os.path.join(outputdir, str(os.path.basename(db_filepath)) + '-tmp_amtc')
				shutil.copyfile(curr_db_filepath, temp_db_filepath)  # blocking

				# open in temp location
				try:
					self._db_conn = sqlite3.connect(temp_db_filepath)
					self.tables()
					self._db_filepath = temp_db_filepath  # success, replace filepath
					return True
				except sqlite3.OperationalError as e:
					log.error('Unable to open SQLite3 db {0} normally or via temp copy: {1}'.format(db_filepath, str(e)))

					if os.path.exists(temp_db_filepath):  # clean up
						try:
							os.remove(temp_db_filepath)
						except (OSError, IOError) as e:
							log.warn('Unable to remove temp db file {0}: {1}'.format(temp_db_filepath, str(e)))

					self._db_conn = None
					self._db_filepath = ''
					self._is_temp_filepath = False
					return False

	def query(self, query):
		"""
		Query the db and return the results List
		Requires open be run first
		"""
		if self._db_conn is None:
			raise ValueError('DB connection not set, must run open first.')

		data = []
		try:
			curs = self._db_conn.cursor()
			data = curs.execute(query).fetchall()
		except sqlite3.OperationalError as e:
			if 'no such table' in repr(e):
				log.debug('Could not query {0} for \'{1}\': {2}'.format(self._db_filepath, query, str(e)))
			else:
				log.error('Unable to query db file {0} with query {1}: {2}'.format(self._db_filepath, query, [traceback.format_exc()]))
		return data

	def query_db(self, db_filepath, query, outputdir):
		"""
		Query the db located at db_filepath and return the results List.
		Does not require open be run first
		"""
		if self._db_conn is not None:
			return self.query(query)

		data = []
		self._db_filepath = db_filepath
		if self.open(db_filepath, outputdir):
			data = self.query(query)
		return data

	def table_exists(self, table):
		"""
		Returns true if db table exists, false or exception otherwise. 
		Requires that open have run before calling
		"""
		if self._db_conn is None:
			raise ValueError('DB connection not set, must run open first.')
		try:
			curs = self._db_conn.cursor()
			q = "PRAGMA table_info('{0}')".format(table)
			curs.execute(q)
			res = curs.fetchone
			if res is not None:
				return True
			else:
				return False
		except sqlite3.OperationalError as e:
			log.debug("error accessing database {0}: {1}".format(self._db_filepath, str(e)))
			return False

	@staticmethod
	def db_table_exists(db, table):
		"""
		Returns True if db table exists, false or exception otherwise
		"""
		if SQLiteDB.db_exists(db):
			try:
				curs = sqlite3.connect(db).cursor()
				q = "PRAGMA table_info('{0}')".format(table)
				curs.execute(q)
				res = curs.fetchone()
				if res is not None:
					return True
				else:
					return False
			except sqlite3.OperationalError as e:
				log.debug("error accessing database {0}: {1}".format(db, str(e)))
				return False
		else:
			return False

	@staticmethod
	def db_exists(db_filepath):
		"""
		Returns True if db exists, false or exception otherwise
		"""
		try:
			if os.path.exists(db_filepath):
				return True
			else:
				return False
		except Exception as e:
			log.debug('db_exists: ' + str(e))
			return False


def query_db(db_file, query, outputdir):
	"""
	query_db runs sqlite query against a sqlite database and return a list of the resulting data, returns empty list if none or error.
	"""
	log.debug("query_db will be deprecated in future versions, please use the SQLiteDB Class wrapper")
	try:
		if sys.version_info[0] < 3:
			conn = sqlite3.connect(db_file)
			curs = conn.cursor()
			data = curs.execute(query).fetchall()
		else:  # enforce RO for 3.4+ version
			conn = sqlite3.connect('file:{' + db_file + 's' + '}?mode=ro', uri=True)
			curs = conn.cursor()
			data = curs.execute(query).fetchall()
	except sqlite3.OperationalError as e:
		# return none if database exists but table does not
		if "no such table" in repr(e):
			log.debug(repr(e))
			if conn:
				conn.close()
			return []

		# clone to temp location
		db_tmp = os.path.join(outputdir, str(os.path.basename(db_file)) + '-tmp_amtc')
		shutil.copyfile(db_file, db_tmp)
		time.sleep(3)
		try:
			conn = sqlite3.connect(db_tmp)
			curs = conn.cursor()
			data = curs.execute(query).fetchall()
		except Exception:
			data = []
			log.error("Sqlite3 traceback: {0} - could not parse {1} with query {2}".format([traceback.format_exc()], db_file, query))
		rm_tmp = glob.glob(os.path.join(outputdir, '*-tmp_amtc*'))
		rm = [os.remove(tmpfile) for tmpfile in rm_tmp]
	finally:
		if conn:
			conn.close()
	return data


def get_db_column_headers(db, table):
	"""
	Returns a list of column names from the specified sqlite table, or an empty list if an error occurred
	"""
	log.debug("get_db_column_headers will be deprecated in future versions, please use the SQLiteDB Class wrapper")
	try:
		if db_table_exists(db, table) is False:
			return []
		col_headers = sqlite3.connect(db).cursor().execute('SELECT * from {0}'.format(table))
		names = list(map(lambda x: x[0], col_headers.description))
	except sqlite3.OperationalError:
		log.debug("table '{0}' was not found in database.".format(table))
		names = []
	return names


def db_table_exists(db, table):
	log.debug("db_table_exists will be deprecated in future versions, please use the SQLiteDB Class wrapper")
	try:
		curs = sqlite3.connect(db).cursor()
		q = "PRAGMA table_info('{0}')".format(table)
		curs.execute(q)
		res = curs.fetchone()
		if res is not None:
			return True
		else:
			return False
	except sqlite3.OperationalError:
		log.debug("error accessing database {0}".format(db))
		return False


def finditem(obj, key):
	"""Return value of a key from a nested dictionary-like object.
	"""
	if key in obj:
		return obj[key]
	for k, v in obj.items():
		if isinstance(v, dict):
			item = finditem(v, key)
			if item is not None:
				return item


def get_codesignatures(fullpath, nocheck=False):
	"""Check code signatures of a file based on filepath.
	"""
	if not nocheck:
		if not os.path.exists(fullpath):
			return ['ERROR-FILE-DNE']
		try:
			signers = CodeSignChecker.get_signature_chain(fullpath)
			if len(signers) == 0:
				return ['Unsigned']
			else:
				return signers
		except Exception:
			try:
				p = subprocess.Popen(['codesign', '-dv', '--verbose=2', 
					str(fullpath)], stderr=subprocess.PIPE).communicate()[-1].decode().split('\n')
			except Exception:
				p = subprocess.Popen(['codesign', '-dv', '--verbose=2', 
					str(fullpath)], stderr=subprocess.PIPE).communicate()[-1].split('\n')
			signers = [line.replace('Authority=', '') for line in p if line.startswith('Authority=')]
			if len(signers) == 0:
				return ['Unsigned']
			else:
				return signers
	else:
		return ""


def chrome_time(microseconds):
	"""Convert chrome DB timestamp to ISO8601, UTC format.
	"""
	if microseconds not in ['', None, 0]:
		timestamp = datetime(1601, 1, 1) + timedelta(microseconds=int(microseconds))
		return parser.parse(str(timestamp)).isoformat() + 'Z'
	else:
		return ''


def firefox_time(microseconds):
	"""Convert firefox DB timestamp to ISO8601, UTC format.
	"""
	if microseconds not in ['', None, 0]:
		timestamp = datetime(1970, 1, 1) + timedelta(microseconds=int(microseconds))
		return parser.parse(str(timestamp)).isoformat() + 'Z'
	else:
		return ''


def cocoa_time(seconds):
	"""Convert cocoa webkit DB timestamp to ISO8601, UTC format.
	"""
	if seconds not in ['', None, 0]:
		timestamp = datetime(2001, 1, 1) + timedelta(seconds=int(seconds))
		return parser.parse(str(timestamp)).isoformat() + 'Z'
	else:
		return ''


def read_bplist(file_location):
	"""Read data from plist stored in a file.
	"""
	with open(file_location, 'rb') as fd:
		plist_array = bplist.load(fd)
		return [plist_array]


def read_stream_bplist(string):
	"""Read data from plist stored in a file.
	"""
	if sys.version_info[0] < 3:
		w = buffer(string)
	else:
		try:
			w = memoryview(string)
		except TypeError:
			w = memoryview(string.encode())
	plist_array = bplist.load(io.BytesIO(w))
	return plist_array


def stats2(file, oMACB=False, stat=None):
	"""Get file metadata.
	"""
	os.environ['TZ'] = 'UTC'
	fields = ['mode', 'size', 'uid', 'gid', 'mtime', 'atime', 'ctime', 'btime', 'path', 'name']

	try:
		if stat is None:
			stat = os.lstat(file)
		statrecord = OrderedDict((h, '') for h in fields)

		try:
			mode = stat.st_mode
			if S_ISDIR(mode):
				statrecord['mode'] = "Directory"
			elif S_ISREG(mode):
				statrecord['mode'] = "Regular File"
			else:
				statrecord['mode'] = "Other"
		except Exception:
			log.debug("Failed to get file stat 'mode': {0}: {1}".format(file, [traceback.format_exc()]))
			statrecord['mode'] = "ERROR"

		try:
			statrecord['uid'] = stat.st_uid
			statrecord['gid'] = stat.st_gid
		except Exception:
			log.debug("Failed to get file owner info: {0}: {1}".format(file, [traceback.format_exc()]))
			statrecord['uid'] = "ERROR"
			statrecord['gid'] = "ERROR"

		try:
			statrecord['owner'] = getpwuid(stat.st_uid).pw_name
		except Exception:
			log.debug("Failed to get file owner info: {0}: {1}".format(file, [traceback.format_exc()]))
			statrecord['owner'] = "ERROR"

		try:
			statrecord['size'] = stat.st_size
		except Exception:
			log.debug("Failed to get file size: {0}: {1}".format(file, [traceback.format_exc()]))
			statrecord['size'] = "ERROR"

		statrecord['name'] = os.path.basename(file)
		path = os.path.dirname(file)
		if statrecord['mode'] == "Directory":
			path = os.path.join(path, statrecord['name'])
			statrecord['name'] = ''
		elif statrecord['mode'] == "Regular File":
			path = path + '/'
		elif statrecord['mode'] == 'ERROR':
			path = os.path.join(path, statrecord['name'])
			statrecord['name'] = ''
		statrecord['path'] = path.replace('//', '/').replace('//', '/')

		try:
			statrecord['mtime'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(stat.st_mtime))
			statrecord['atime'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(stat.st_atime))
			statrecord['ctime'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(stat.st_ctime))
			statrecord['btime'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(stat.st_birthtime))
		except Exception:
			log.debug("Failed to get file timestamp info: {0}: {1}".format(file, [traceback.format_exc()]))
			statrecord['mtime'] = "ERROR"
			statrecord['atime'] = "ERROR"
			statrecord['ctime'] = "ERROR"
			statrecord['btime'] = "ERROR"

	except Exception:
		log.debug("Failed to stat file: '{0}': {1}".format(file, [traceback.format_exc()]))
		statrecord = OrderedDict((h, 'ERROR') for h in fields)
		statrecord['path'] = file

	if oMACB is False:
		return(statrecord)
	else:
		return({k: v for k, v in statrecord.items() if 'time' in k})


class MultiprocessingPool():
	"""
	Wrapper for multiprocessing Pool map
	"""
	def __init__(self, func, arg_array, workers):
		"""
		Args:
			func - method to run
			arg_array - list of input for function
			workers - integer number of threads for multiprocessing
		"""
		if workers < 1:
			raise ValueError("MultiprocessingPool - Workers must be >= 1: Got value '{0}'".format(workers))
		if not isinstance(arg_array, list):
			raise ValueError("MultiprocessingPool - Expected list for arg_array, got '{0}'".format(type(arg_array)))
		self.__pool = ThreadPool(workers)
		self.__func = func
		self.__arg_array_iter = iter(arg_array)

	def run(self):
		"""Start the multiprocessing pool map

		Returns:
			returns list of return values of function
		"""
		try:
			res = self.__pool.map(self.__run_func, self.__arg_array_iter)
			self.__pool.close()
			self.__pool.join()
			return res
		except KeyboardInterrupt:
			log.debug("Keyboard interrupt while mapping pool.")
			self.__pool.terminate()
		except Exception as e:
			log.error("Unhandled Exception in pool: {0} - {1}".format(str(e), [traceback.format_exc()]))
			self.__pool.terminate()

	def __run_func(self, arg):
		"""Wrapper for worker functions

		Args:
			arg - argument to pass into function
		Returns:
			return value of function
		"""
		try:
			return self.__func(arg)
		except KeyboardInterrupt:
			raise RuntimeError("Keyboard Interrupt")
		except Exception as e:
			log.error("Unhandled Exception in worker: {0} - {1}".format(str(e), [traceback.format_exc()]))
		return
