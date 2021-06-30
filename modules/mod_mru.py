"""A module intended to parse SFL, SFL2, and other various MRU plist files.

Thank you to Sarah Edwards and her tool macMRU-Parser for pointing me towards
ccl_bplist and for her blog posts about deserializing the
NSKeyedArchiver plist format. Her tool can be found here:

https://github.com/mac4n6/macMRU-Parser/blob/master/macMRU.py

Borrowed some snippets and logic from the same.
License included under `licenses` directory as macMRU-LICENSE.txt.
"""

import logging
import plistlib
import sys
import traceback
from collections import OrderedDict

# IMPORT STATIC VARIABLES FROM MAIN
from __main__ import (archive, data_writer, forensic_mode, full_prefix,
                      inputdir, no_tarball, outputdir, quiet, startTime)


# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from .common import ccl_bplist as ccl_bplist
from .common.functions import multiglob, read_bplist, stats2

_modName = __name__.split('_')[-1]
_modVers = '1.0.3'
log = logging.getLogger(_modName)


def parse_sfls(headers, output):

    sfl_list = multiglob(inputdir, ['Users/*/Library/Application Support/com.apple.sharedfilelist/*.sfl',
                                    'Users/*/Library/Application Support/com.apple.sharedfilelist/*/*.sfl',
                                    'private/var/*/Library/Application Support/com.apple.sharedfilelist/*/*.sfl'])

    for mru_file in sfl_list:

        userpath = mru_file.split('/')
        userindex = userpath.index('Library') - 1
        user = userpath[userindex]

        plist_objects = ccl_bplist.deserialise_NsKeyedArchiver(
            ccl_bplist.load(open(mru_file, "rb")), parse_whole_structure=True)
        try:
            if plist_objects["root"]["NS.objects"][1]["NS.keys"][0] == "com.apple.LSSharedFileList.MaxAmount":
                numberOfItems = plist_objects["root"]["NS.objects"][1]["NS.objects"][0]
        except Exception:
            pass

        try:
            if plist_objects["root"]["NS.keys"][2] == "items":
                items = plist_objects["root"]["NS.objects"][2]["NS.objects"]
        except Exception:
            log.debug('Could not parse SFL {0}: {1}'.format(mru_file, [traceback.format_exc()]))
            items = None

        if items:
            for n, item in enumerate(items):
                record = OrderedDict((h, '') for h in headers)
                record['src_file'] = mru_file
                record['user'] = user
                record['src_name'] = "SharedFileList"
                try:
                    try:
                        name = item["name"]
                    except Exception:
                        name = ''
                    record['name'] = name
                    record['item_index'] = str(n)
                    record['order'] = item['order']
                    record['url'] = item['URL']['NS.relative']

                except Exception:
                    log.debug("Could not parse SFL item: {0}".format(item))

                output.write_record(record)


def parse_sfl2s(headers, output):
    sfl2_list = multiglob(inputdir, ['Users/*/Library/Application Support/com.apple.sharedfilelist/*.sfl2',
                                     'Users/*/Library/Application Support/com.apple.sharedfilelist/*/*.sfl2'
                                     'private/var/*/Library/Application Support/com.apple.sharedfilelist/*/*.sfl2'])

    for mru_file in sfl2_list:

        userpath = mru_file.split('/')
        userindex = userpath.index('Library') - 1
        user = userpath[userindex]

        plist_objects = ccl_bplist.deserialise_NsKeyedArchiver(
            ccl_bplist.load(open(mru_file, "rb")), parse_whole_structure=True)

        try:
            if plist_objects["root"]["NS.objects"][1]["NS.keys"][0] == "com.apple.LSSharedFileList.MaxAmount":
                numberOfItems = plist_objects["root"]["NS.objects"][1]["NS.objects"][0]
        except Exception:
            pass

        try:
            if plist_objects["root"]["NS.keys"][0] == "items":
                items = plist_objects["root"]["NS.objects"][0]["NS.objects"]
        except Exception:
            log.debug('Could not parse SFL {0}: {1}'.format(mru_file, [traceback.format_exc()]))
            items = None

        if items:
            for n, item in enumerate(items):
                record = OrderedDict((h, '') for h in headers)
                record['src_file'] = mru_file
                record['user'] = user
                record['src_name'] = "SharedFileList"

                try:

                    attribute_keys = plist_objects["root"][
                        "NS.objects"][0]["NS.objects"][n]["NS.keys"]
                    attribute_values = plist_objects["root"][
                        "NS.objects"][0]["NS.objects"][n]["NS.objects"]
                    attributes = dict(zip(attribute_keys, attribute_values))

                    try:
                        name = str(attributes['Name'])
                    except Exception:
                        name = ''

                    if 'Bookmark' in attributes:
                        try:
                            url = [
                                'file://' + x.split(';')[-1] for x in attributes['Bookmark'].decode('latin-1').split('\x00') if x != '' and ';' in x][0]
                        except Exception:
                            try:
                                url = ', '.join(['file://' + x.split(';')[-1] for x in [x for x in attributes['Bookmark']['NS.data'].decode('latin-1').split('\x00') if x != '' and ';' in x]])
                            except Exception:
                                try:
                                    url = [x for x in attributes['Bookmark'].decode('latin-1').split('\x00') if x != '' and 'x' in x][0]
                                except IndexError:
                                    url = 'ERROR-EMPTY'
                                    log.debug("Could not parse URL from {0}: {1}".format(mru_file, [traceback.format_exc()]))
                                except Exception:
                                    # log.debug('Could not parse SFL {0}: {1}'.format(x, [traceback.format_exc()]))
                                    url = 'ERROR-COULDNOTPARSE'
                                    log.debug("Could not parse URL from {0}: {1}".format(mru_file, [traceback.format_exc()]))

                    else:
                        url = 'ERROR-NODATA'

                    record['item_index'] = str(n)
                    record['name'] = name
                    record['url'] = url

                except Exception:
                    log.debug("Could not parse SFL2 item: {0}".format(item))

                output.write_record(record)


def parse_securebookmarks(headers, output):
    secure_bookmarks = multiglob(inputdir, ['Users/*/Library/Containers/*/Data/Library/Preferences/*.securebookmarks.plist',
                                            'private/var/*/Library/Containers/*/Data/Library/Preferences/*.securebookmarks.plist'])

    for secure_bookmark_file in secure_bookmarks:

        userpath = secure_bookmark_file.split('/')
        userindex = userpath.index('Library') - 1
        user = userpath[userindex]

        try:
            if sys.version_info[0] < 3:
                data = plistlib.readPlist(secure_bookmark_file)
            else:
                data = plistlib.load(secure_bookmark_file)
        except Exception:
            log.debug('Could not parse securebookmark file {0}: {1}'.format(secure_bookmark_file, [traceback.format_exc()]))
            data = None

        if data:
            for k, v in data.items():
                record = OrderedDict((h, '') for h in headers)
                record['src_file'] = secure_bookmark_file
                record['src_name'] = "SecureBookmarks"
                record['user'] = user
                try:
                    record['url'] = k
                    record['name'] = k.split('/')[-1].encode('utf-8')
                except Exception:
                    log.debug("Could not parse securebookmark item for key: {0}".format(k))
                output.write_record(record)


def parse_finderplists(headers, output):
    finder_plists = multiglob(inputdir, ['Users/*/Library/Preferences/com.apple.finder.plist', 'private/var/*/Library/Preferences/com.apple.finder.plist'])

    for fplist in finder_plists:

        userpath = fplist.split('/')
        userindex = userpath.index('Library') - 1
        user = userpath[userindex]

        try:
            data = read_bplist(fplist)[0]
        except Exception:
            log.debug('Could not parse finderplist {0}: {1}'.format(fplist, [traceback.format_exc()]))
            data = None

        if data:
            try:
                recentfolders = data['FXRecentFolders']
            except KeyError:
                log.debug("Could not find FXRecentFolders key in plist.")
                recentfolders = []

            try:
                moveandcopy = data['RecentMoveAndCopyDestinations']
            except KeyError:
                log.debug("Could not find FXRecentFolders key in {0}.".format(fplist))
                moveandcopy = []

            for i in recentfolders:
                record = OrderedDict((h, '') for h in headers)
                record['src_file'] = fplist
                record['src_name'] = "FinderPlist"
                record['user'] = user
                try:
                    record['source_key'] = 'FXRecentFolders'
                    record['name'] = i['name']
                    bkmk = i['file-bookmark']
                    record['url'] = 'file:///' + bkmk.decode('latin-1').split(';')[-1].split('\x00')[0]
                except Exception:
                    log.debug("Could not parse finderplist item: {0}: {1}".format(i, [traceback.format_exc()]))
                    log.debug("Could not parse finderplist item: {0}".format(i))
                output.write_record(record)

            for i in moveandcopy:
                record = OrderedDict((h, '') for h in headers)
                record['src_file'] = fplist
                record['src_name'] = "FinderPlist"
                record['user'] = user
                try:
                    record['url'] = i
                    record['name'] = i.split('/')[-2]
                    record['source_key'] = 'RecentMoveAndCopyDestinations'
                except Exception:
                    log.debug("Could not parse finderplist item: {0}: {1}".format(i, [traceback.format_exc()]))
                output.write_record(record)


def parse_sidebarplists(headers, output):
    sidebar_plists = multiglob(inputdir, ['Users/*/Library/Preferences/com.apple.sidebarlists.plist', 'private/var/*/Library/Preferences/com.apple.sidebarlists.plist'])

    for sblist in sidebar_plists:

        userpath = sblist.split('/')
        userindex = userpath.index('Library') - 1
        user = userpath[userindex]

        try:
            data = read_bplist(sblist)[0]
        except Exception:
            log.debug('Could not parse sidebarplist {0}: {1}'.format(sblist, [traceback.format_exc()]))
            data = None

        if data:
            for i in data['systemitems']['VolumesList']:
                record = OrderedDict((h, '') for h in headers)
                record['src_file'] = sblist
                record['src_name'] = "SidebarPlist"
                record['user'] = user
                try:
                    record['name'] = i['Name']
                    if 'Bookmark' in i:
                        record['url'] = 'file:///' + str(i['Bookmark']).split('file:///')[1].split('\x00')[0]
                    record['source_key'] = 'VolumesList'
                except Exception:
                    log.debug("Could not parse sidebarplist item: {0}".format(i))
                output.write_record(record)


def module():
    headers = ['src_file', 'user', 'src_name', 'item_index', 'order', 'name', 'url', 'source_key']
    output = data_writer(_modName, headers)

    parse_sfls(headers, output)
    parse_sfl2s(headers, output)
    parse_securebookmarks(headers, output)
    parse_sidebarplists(headers, output)
    parse_finderplists(headers, output)
    output.flush_record()


if __name__ == "__main__":
    print("This is an AutoMacTC module, and is not meant to be run stand-alone.")
    print("Exiting.")
    sys.exit(0)
else:
    module()
