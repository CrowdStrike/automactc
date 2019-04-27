#!/usr/bin/env python

'''
@ author: Kshitij Kumar
@ email: kshitijkumar14@gmail.com, kshitij.kumar@crowdstrike.com

@ purpose:

A module intended to parse SFL, SFL2, and other various MRU plist files.
Thank you to Sarah Edwards and her tool macMRU-Parser for pointing me towards
ccl_bplist and for her blog posts about deserializing the
NSKeyedArchiver plist format. Her tool can be found here:

https://github.com/mac4n6/macMRU-Parser/blob/master/macMRU.py

Borrowed some snippets and logic from the same.
License included under `licenses` directory as macMRU-LICENSE.txt.

'''
import plistlib
import traceback
from collections import OrderedDict

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from automactc.modules.common.base import AutoMacTCModule
from automactc.modules.common.functions import read_bplist
from automactc.modules.common.functions import multiglob
import automactc.modules.common.ccl_bplist as ccl_bplist
from automactc.utils.output import DataWriter


class MRUModule(AutoMacTCModule):
    _mod_filename = __name__

    _headers = [
        'src_file', 'src_name', 'item_index', 'order', 'name', 'url', 'source_key'
    ]

    def __init__(self, *args, **kwargs):
        super(MRUModule, self).__init__(*args, **kwargs)
        self._output = DataWriter(self.module_name(), self._headers, self.log, self.run_id, self.options)

    def _parse_sfls(self):
        sfl_list = multiglob(self.options.inputdir, ['Users/*/Library/Application Support/com.apple.sharedfilelist/*.sfl',
                              'Users/*/Library/Application Support/com.apple.sharedfilelist/*/*.sfl'])

        for mru_file in sfl_list:
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
                self.log.debug('Could not parse SFL {0}: {1}'.format(mru_file, [traceback.format_exc()]))
                items = None

            if items:
                for n, item in enumerate(items):
                    record = OrderedDict((h, '') for h in self._headers)
                    record['src_file'] = mru_file
                    record['src_name'] = "SharedFileList"
                    try:
                        try:
                            name = item["name"].encode('utf-8')
                        except Exception:
                            name = ''
                        record['name'] = name
                        record['item_index'] = str(n)
                        record['order'] = item['order']
                        record['url'] = item['URL']['NS.relative']

                    except Exception:
                        self.log.debug("Could not parse SFL item: {0}".format(item))

                    self._output.write_entry(record.values())

    def _parse_sfl2s(self):
        sfl2_list = multiglob(self.options.inputdir, ['Users/*/Library/Application Support/com.apple.sharedfilelist/*.sfl2',
                               'Users/*/Library/Application Support/com.apple.sharedfilelist/*/*.sfl2'])

        for mru_file in sfl2_list:
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
                self.log.debug('Could not parse SFL {0}: {1}'.format(mru_file, [traceback.format_exc()]))
                items = None

            if items:
                for n, item in enumerate(items):
                    record = OrderedDict((h, '') for h in self._headers)
                    record['src_file'] = mru_file
                    record['src_name'] = "SharedFileList"

                    try:

                        attribute_keys = plist_objects["root"][
                            "NS.objects"][0]["NS.objects"][n]["NS.keys"]
                        attribute_values = plist_objects["root"][
                            "NS.objects"][0]["NS.objects"][n]["NS.objects"]
                        attributes = dict(zip(attribute_keys, attribute_values))

                        try:
                            name = str(attributes['Name']).encode('utf-8')
                        except:
                            name = ''

                        if 'Bookmark' in attributes:
                            try:
                                url = [
                                    'file://' + x.split(';')[-1] for x in attributes['Bookmark'].split('\x00') if x != '' and ';' in x][0]
                            except:
                                try:
                                    url = ', '.join(['file://' + x.split(';')[-1] for x in [x for x in attributes['Bookmark']['NS.data'].split('\x00') if x != '' and ';' in x]])
                                except:
                                    try:
                                        url = [x for x in attributes['Bookmark'].split('\x00') if x != '' and x.startswith('x')][0]
                                    except:
                                        url = 'ERROR-COULDNOTPARSE'
                        else:
                            url = 'ERROR-NODATA'

                        record['item_index'] = str(n)
                        record['name'] = name
                        record['url'] = url

                    except Exception:
                        self.log.debug("Could not parse SFL item: {0}".format(item))

                    self._output.write_entry(record.values())

    def _parse_securebookmarks(self):
        secure_bookmarks = multiglob(self.options.inputdir, ['Users/*/Library/Containers/*/Data/Library/Preferences/*.securebookmarks.plist'])

        for secure_bookmark_file in secure_bookmarks:
            try:
                data = plistlib.readPlist(secure_bookmark_file)
            except Exception:
                self.log.debug('Could not parse securebookmark file {0}: {1}'.format(secure_bookmark_file, [traceback.format_exc()]))
                data = None

            if data:
                for k, v in data.items():
                    record = OrderedDict((h, '') for h in self._headers)
                    record['src_file'] = secure_bookmark_file
                    record['src_name'] = "SecureBookmarks"
                    try:
                        record['url'] = k
                        record['name'] = k.split('/')[-1].encode('utf-8')
                    except Exception:
                        self.log.debug("Could not parse securebookmark item for key: {0}".format(k))
                    self._output.write_entry(record.values())

    def _parse_sidebarplists(self):
        sidebar_plists = multiglob(self.options.inputdir, ['Users/*/Library/Preferences/com.apple.sidebarlists.plist'])

        for sblist in sidebar_plists:
            try:
                data = read_bplist(sblist)[0]
            except Exception:
                self.log.debug('Could not parse sidebarplist {0}: {1}'.format(sblist, [traceback.format_exc()]))
                data = None

            if data:
                for i in data['systemitems']['VolumesList']:
                    record = OrderedDict((h, '') for h in self._headers)
                    record['src_file'] = sblist
                    record['src_name'] = "SidebarPlist"
                    try:
                        record['name'] = i['Name'].encode('utf-8')
                        if 'Bookmark' in i:
                            record['url'] = 'file:///' + str(i['Bookmark']).split('file:///')[1].split('\x00')[0]
                        record['source_key'] = 'VolumesList'
                    except:
                        self.log.debug("Could not parse sidebarplist item: {0}".format(i))
                    self._output.write_entry(record.values())

    def _parse_finderplists(self):
        finder_plists = multiglob(self.options.inputdir, ['Users/*/Library/Preferences/com.apple.finder.plist'])

        for fplist in finder_plists:
            try:
                data = read_bplist(fplist)[0]
            except Exception:
                self.log.debug('Could not parse finderplist {0}: {1}'.format(fplist, [traceback.format_exc()]))
                data = None

            if data:
                try:
                    recentfolders = data['FXRecentFolders']
                except KeyError:
                    self.log.debug("Could not find FXRecentFolders key in plist.")
                    recentfolders = []

                try:
                    moveandcopy = data['RecentMoveAndCopyDestinations']
                except KeyError:
                    self.log.debug("Could not find FXRecentFolders key in plist.")
                    moveandcopy = []

                for i in recentfolders:
                    record = OrderedDict((h, '') for h in self._headers)
                    record['src_file'] = fplist
                    record['src_name'] = "FinderPlist"
                    try:
                        record['source_key'] = 'FXRecentFolders'
                        record['name'] = i['name'].encode('utf-8')
                        bkmk = i['file-bookmark']
                        record['url'] = 'file:///' + str(bkmk).split(';')[-1].split('\x00')[0]
                    except Exception:
                        self.log.debug("Could not parse finderplist item: {0}".format(i))
                    self._output.write_entry(record.values())

                for i in moveandcopy:
                    record = OrderedDict((h, '') for h in self._headers)
                    record['src_file'] = fplist
                    record['src_name'] = fplist
                    try:
                        record['url'] = i
                        record['name'] = i.split('/')[-2].encode('utf-8')
                        record['source_key'] = 'RecentMoveAndCopyDestinations'
                    except Exception:
                        self.log.debug("Could not parse finderplist item: {0}: {1}".format(i, [traceback.format_exc()]))
                    self._output.write_entry(record.values())

    def run(self):
        self._parse_sfls()
        self._parse_sfl2s()
        self._parse_securebookmarks()
        self._parse_sidebarplists()
        self._parse_finderplists()
