#!/usr/bin/env python
# coding: utf-8

'''

@ purpose:

A module intended to decode and parse savedState files for the Terminal application
for each user on disk.

'''

# KEEP THIS - IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from .common.dep import six
from .common.functions import read_bplist
from .common.functions import read_stream_bplist
from .common.functions import multiglob
from .common import ccl_bplist as bplist
if six.PY3:
    from .common.CryptoOld.Cipher import AES
else:
    from .common.Crypto.Cipher import AES


# KEEP THIS - IMPORT STATIC VARIABLES FROM MAIN
from __main__ import inputdir
from __main__ import outputdir
from __main__ import forensic_mode
from __main__ import quiet

from __main__ import archive
from __main__ import startTime
from __main__ import full_prefix
from __main__ import OSVersion
from __main__ import data_writer

# MODULE-SPECIFIC IMPORTS, UPDATE AS NEEDED
import traceback
import sys
from collections import OrderedDict
import logging
import glob
import os
import glob
import plistlib
import struct
import subprocess
from xml.parsers.expat import ExpatError



_modName = __name__.split('_')[-2]
_modVers = '.'.join(list(__name__.split('_')[-1][1:]))
log = logging.getLogger(_modName)


def module():

    _headers = ['user', 'window_id', 'datablock' ,'window_title', 'tab_working_directory_url', 'tab_working_directory_url_string', 'line_index', 'line']
    _output = data_writer(_modName, _headers)

    user_inputdir = multiglob(inputdir, ["Users/*/Library/Saved Application State/com.apple.Terminal.savedState/",
                                         "private/var/*/Library/Saved Application State/com.apple.Terminal.savedState/"])
    if len(user_inputdir) <= 0:
        log.info("No Terminal.savedState files were found")
        return

    bplist.set_object_converter(bplist.NSKeyedArchiver_common_objects_convertor)

    for udir in user_inputdir:

        # Get username from path.
        userpath = udir.split('/')
        if 'Users' in userpath:
            userindex = len(userpath) - 1 - userpath[::-1].index('Users') + 1
        else:
            userindex = len(userpath) - 1 - userpath[::-1].index('var') + 1
        user = userpath[userindex]

        log.debug("Going to parse Terminal saved state data under {0} user.".format(user))

        # Check if windows.plist and data.data exist under user profiles.
        windows = glob.glob(os.path.join(udir, "windows.plist"))
        data_loc = glob.glob(os.path.join(udir, "data.data"))

        if len(windows) < 1:
            log.error("Required file windows.plist not found, cannot parse Terminal saved state data under {0} user.".format(user))
            continue

        if len(data_loc) < 1:
            log.error("Required file data.data not found, cannot parse Terminal saved state data under {0} user.".format(user))
            continue

        # Check if file header for data.data is NSCR1000.
        data = open(data_loc[0], 'rb').read()
        if not data[0:8].decode() == "NSCR1000":
            log.error("Bad file header for data.data. Cannot parse further.")
            continue

        # Try to read XML and binary style windows.plist files.
        try:
            windows_plist = plistlib.readPlist(windows[0])
            xmltype = True
        except ExpatError:
            windows_plist = read_bplist(windows[0])[0]
            xmltype = False
        except Exception as e:
            log.error("Could not read windows.plist: {0}".format([traceback.format_exc()]))
            continue

        # Get NSWindowID and NSDataKey values from windows.plist, for each window available.
        windows_data = {}
        for i in windows_plist:
            win_id = i['NSWindowID']
            if xmltype:
                try:
                    decryption_key = i['NSDataKey'].data
                except KeyError:
                    log.debug("Could not find decryption key in windows.plist for WindowID {0}.".format(win_id))
                    decryption_key = None
            else:
                try:
                    decryption_key = i['NSDataKey']
                except KeyError:
                    log.debug("Could not find decryption key in windows.plist for WindowID {0}.".format(win_id))
                    decryption_key = None

            windows_data[win_id] = decryption_key
        log.debug("WindowIDs and keys found: {0}".format(windows_data))


        # Parse each NSCR1000 block.
        data_chunks = [i for i in data.decode('latin-1').split('NSCR1000') if i != '']
        datablock_index = 0
        for chunk in data_chunks:
            datablock_index += 1
            (NSWindowID,) = struct.unpack('>I', chunk[0:4].encode('latin-1'))
            (blocksize,) = struct.unpack('>I', chunk[4:8].encode('latin-1'))
            available = len(chunk)+8
            if available == blocksize:
                datablock = chunk[8:blocksize].encode('latin-1')
                if not NSWindowID in windows_data.keys() or not windows_data[NSWindowID]:
                    log.debug("Key not found in windows.plist for WindowID {0} (datablock {1}).".format(NSWindowID, str(datablock_index)))
                    continue
                iv = os.urandom(16)
                key = windows_data[NSWindowID]
                try:
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    pt = cipher.decrypt(datablock)
                    log.debug("Successfully decrypted datablock {0}.".format(str(datablock_index)))
                except Exception as e:
                    log.debug("Could not decrypt data for WindowID {0} (datablock {1}).".format(NSWindowID, str(datablock_index)))
                    continue

        # Carve and parse each binary plist from the decrypted blocks.
                if 'bplist'.encode() in pt:
                    header_off = pt.find('bplist'.encode())
                    plist_size_hex = pt[header_off-4:header_off]
                    (plist_size,) = struct.unpack('>I', plist_size_hex)
                    plist_data = pt[header_off:header_off+plist_size]
                    oname = str(datablock_index)+'.txt'
                    parsed_plist = read_stream_bplist(plist_data)
                    ns_parsed = bplist.deserialise_NsKeyedArchiver(parsed_plist, parse_whole_structure=True)

                    if "TTWindowState" in ns_parsed.keys():
                        record = OrderedDict((h, '') for h in _headers)
                        record['user'] = user
                        record['window_id'] = NSWindowID
                        record['datablock'] = datablock_index

                        if sys.version_info[0] >= 3:
                            record['window_title'] = ns_parsed['NSTitle']
                        else:
                            record['window_title'] = ns_parsed['NSTitle'].encode('utf-8')

                        try:
                            record['tab_working_directory_url'] = ns_parsed['TTWindowState']['Window Settings'][0]["Tab Working Directory URL"]
                        except KeyError:
                            log.debug("Did not find value for: Tab Working Directory URL")

                        try:
                            record['tab_working_directory_url_string'] = ns_parsed['TTWindowState']['Window Settings'][0]["Tab Working Directory URL String"]
                        except KeyError:
                            log.debug("Did not find value for: Tab Working Directory URL String")

                        try:
                            terminal_data = ns_parsed['TTWindowState']['Window Settings'][0]["Tab Contents v2"]
                            indx = 0
                            for i in terminal_data:
                                if type(i) == bytes:
                                    indx += 1
                                    record['line_index'] = str(indx)
                                    try:
                                        record['line'] = i.decode().rstrip()
                                    except:
                                        record['line'] = i.rstrip()
                                    _output.write_entry(record.values())

                        except KeyError:
                            log.debug("Did not find value for: Tab Contents v2")

                    else:
                        log.debug("Did not find TTWindowState key in carved bplist.")

                else:
                    log.debug("Did not find bplist header for WindowID {0}.".format(NSWindowID))
                    continue
            else:
                log.debug("Available data does not match expected size for WindowID {0}.".format(NSWindowID))
                continue


# KEEP THIS - ESTABLISHES THAT THIS SCRIPT CAN'T BE RUN WITHOUT THE FRAMEWORK.
if __name__ == "__main__":
    print("This is an AutoMacTC module, and is not meant to be run stand-alone.")
    print("Exiting.")
    sys.exit(0)
else:
    module()
