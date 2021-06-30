"""A module intended to parse audit log files on disk.
"""

import glob
import logging
import os
import subprocess
import sys
import traceback
import xml.etree.ElementTree as ET
from collections import OrderedDict
from datetime import datetime

# KEEP THIS - IMPORT STATIC VARIABLES FROM MAIN
from __main__ import data_writer, forensic_mode, inputdir, outputdir, quiet

_modName = __name__.split('_')[-1]
_modVers = '1.0.1'
log = logging.getLogger(_modName)


def module():

    _headers = ['src_file', 'timestamp', 'version', 'event', 'modifier',
                'msec', 'audit_uid', 'uid', 'gid', 'ruid', 'rgid',
                'pid', 'sid', 'tid', 'errval', 'retval', 'text_fields']
    _output = data_writer(_modName, _headers)

    os.environ['TZ'] = 'UTC0'

    auditlog_loc = 'private/var/audit/*'
    auditlog_inputdir = glob.glob(os.path.join(inputdir, auditlog_loc))

    if len(auditlog_inputdir) == 0:
        log.debug("Files not found in: {0}".format(auditlog_loc))

    for aud_log in auditlog_inputdir:
        audit_data, e = subprocess.Popen(["praudit", "-x", "-l", aud_log], stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()
        try:
            audit_records = [i for i in audit_data.decode().split('\n') if i.startswith('<record version=')]
        except Exception:
            audit_records = [i for i in audit_data.split('\n') if i.startswith('<record version=')]

        if len(audit_records) == 0:
            log.debug("Audit log file {0} had no records that could be parsed.".format(aud_log))
            continue

        for rec in audit_records:
            record = OrderedDict((h, '') for h in _headers)
            record['src_file'] = os.path.basename(aud_log)

            # Get root attributes from XML record.
            try:
                root = ET.fromstring(rec)
            except ET.ParseError:
                log.debug("Could not parse XML for auditlog record in {0}: {1}".format(aud_log, [traceback.format_exc()]))
                continue
            root_values = root.attrib

            # Get subject attributes and text attributes from XML record.
            text_fields = []
            subject_values = {}
            return_values = {}
            for child in root:
                if child.tag == 'subject':
                    subject_values = child.attrib
                elif child.tag == 'text':
                    text_fields.append(child.text)
                elif child.tag == 'return':
                    return_values = child.attrib

            # Parse root attributes.
            root_keys = ['time', 'modifier', 'msec', 'version', 'event']
            for key in root_keys:
                try:
                    if key == 'time':
                        parsed_time = str(datetime.strptime(root_values[key].replace('  ', ' '), '%a %b %d %H:%M:%S %Y'))
                        record['timestamp'] = str(parsed_time).replace(' ', 'T') + 'Z'
                    else:
                        record[key] = root_values[key]
                except KeyError:
                    log.debug("Did not find value for key '{0}' in record.".format(key))

            # Parse subject attributes.
            if len(subject_values) == 0:
                log.debug("XML record does not contain 'subject' key.")
            else:
                subject_keys = ['audit-uid', 'uid', 'gid', 'ruid', 'rgid', 'pid', 'sid', 'tid']
                for key in subject_keys:
                    try:
                        if key == 'audit-uid':
                            record['audit_uid'] = subject_values[key]
                        else:
                            record[key] = subject_values[key]
                    except KeyError:
                        log.debug("Did not find value for key '{0}' in record.".format(key))

            # Parse return attributes.
            if len(return_values) == 0:
                log.debug("XML record does not contain 'return' key.")
            else:
                return_keys = ['errval', 'retval']
                for key in return_keys:
                    try:
                        record[key] = return_values[key]
                    except KeyError:
                        log.debug("Did not find value for key '{0}' in record.".format(key))

            record['text_fields'] = str(text_fields)
            _output.write_record(record)
    _output.flush_record()

# KEEP THIS - ESTABLISHES THAT THIS SCRIPT CAN'T BE RUN WITHOUT THE FRAMEWORK.
if __name__ == "__main__":
    print("This is an AutoMacTC module, and is not meant to be run stand-alone.")
    print("Exiting.")
    sys.exit(0)
else:
    module()
