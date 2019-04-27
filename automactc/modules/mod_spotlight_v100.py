#!/usr/bin/env python

'''
@ author: Kshitij Kumar
@ email: kshitijkumar14@gmail.com, kshitij.kumar@crowdstrike.com

@ purpose:

A module intended to parse the com.apple.spotlight.Shortcuts plist file,
which contains a record of every application opened with Spotlight, as
well as the timestamp that it was last opened.

'''
import os
import plistlib
import glob

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from automactc.modules.common.base import AutoMacTCModule
from automactc.utils.output import DataWriter


class SpotlightModule(AutoMacTCModule):
    _mod_filename = __name__

    _headers = ['user', 'shortcut', 'display_name', 'last_used', 'url']

    def run(self):
        output = DataWriter(self.module_name(), self._headers, self.log, self.run_id, self.options)

        user_inputdir = glob.glob(os.path.join(self.options.inputdir, "Users/*"))
        user_inputdir.append(os.path.join(self.options.inputdir, "var/root"))

        spotlight_path = 'Library/Application Support/com.apple.spotlight.Shortcuts'
        for user_home in user_inputdir:

            sl_path = os.path.join(user_home, spotlight_path)
            u_spotlight = glob.glob(sl_path)
            if len(u_spotlight) == 0:
                self.log.debug("File not found: {0}".format(sl_path))

            for item in u_spotlight:
                try:
                    spotlight_data = plistlib.readPlist(item)
                    for k, v in spotlight_data.items():
                        user = os.path.basename(user_home)
                        shortcut = k
                        display_name = spotlight_data[k]['DISPLAY_NAME']
                        last_used = spotlight_data[k]['LAST_USED'].isoformat() + "Z"
                        url = spotlight_data[k]['URL']

                        line_raw = [user, shortcut, display_name, last_used, url]
                        line = [x.encode('utf-8') for x in line_raw]

                        output.write_entry(line)

                except Exception:
                    self.log.error("Could not parse: {0}".format(file))
