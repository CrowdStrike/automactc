"""A module intended to collect Unified Logging events from a live system
based on specified predicates using the log show command.
"""

import logging
import os
import subprocess
import sys

# IMPORT STATIC VARIABLES FROM MAIN
from __main__ import (archive, data_writer, forensic_mode, full_prefix,
                      inputdir, no_tarball, outputdir, quiet, startTime)

_modName = __name__.split('_')[-1]
_modVers = '1.0.3'
log = logging.getLogger(_modName)


def module():
    if forensic_mode:
        log.error("Module did not run: input is not a live system!")
        return

    output = data_writer("unifiedlogs_live", None)

    predicates = [
        'process == "sudo" && eventMessage CONTAINS[c] "User=root" && (NOT eventMessage CONTAINS[c] "root : PWD=/ ; USER=root") && (NOT eventMessage CONTAINS[c] "    root : PWD=")',    # Captures command line activity run with elevated privileges
        # 'process == "logind"',  # Captures user login events < Large
        # 'process == "tccd"',    # Captures events that indicate permissions and access violations < Very Large
        'process == "sshd" ',   # Captures successful, failed and general ssh activity
        # '(process == "kextd" && sender == "IOKit")',  # Captures successful and failed attempts to add kernel extensions < Large
        '(process == "screensharingd" || process == "ScreensharingAgent")',  # Captures events that indicate successful or failed authentication via screen sharing
        # '(process == "loginwindow" && sender == "Security")',     # Captures keychain.db unlock events < Large
        '(process == "securityd" && eventMessage CONTAINS "Session" && subsystem == "com.apple.securityd")',    # Captures session creation and destruction events
    ]
    predicate = ' OR '.join(predicates)
    predicate = "'" + predicate + "'"

    cmd = 'log show --info --backtrace --debug --loss --signpost --style ndjson --force --timezone UTC --predicate'
    outcmd = '> {0}'.format(output.data_file_name.split(output.datatype)[0] + 'json')

    cmd = cmd + " " + predicate + " " + outcmd

    log.debug("Collecting Unified Logs via {0}".format(cmd))

    if sys.version_info[0] < 3:
        outbytes = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True).communicate()
        out = outbytes[0].decode('utf-8').split('\n')
    else:
        outbytes = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
        out = outbytes.stdout.decode('utf-8').split('\n')
    if "Bad predicate" in out[0]:
        log.debug("command was: {0}".format(cmd))
        raise Exception("Failed to collect unified logs: {0}".format(out[0]))

    if output.datatype == "csv":
        log.debug('converting unified logs output to csv')
        from .common import json_to_csv
        json_to_csv.json_file_to_csv(output.data_file_name.split(output.datatype)[0] + 'json')
        os.remove(output.data_file_name.split(output.datatype)[0] + 'json')
    elif output.datatype == "all":
        log.debug('converting unified logs output to csv')
        from .common import json_to_csv
        json_to_csv.json_file_to_csv(output.data_file_name.split(output.datatype)[0] + 'json')


if __name__ == "__main__":
    print("This is an AutoMacTC module, and is not meant to be run stand-alone.")
    print("Exiting.")
    sys.exit(0)
else:
    module()
