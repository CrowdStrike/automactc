"""A module intented to parse the coreanalytics artifact.
https://www.crowdstrike.com/blog/i-know-what-you-did-last-month-a-new-artifact-of-execution-on-macos-10-13/
"""

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from .common.functions import stats2
from .common.functions import finditem
from .common.functions import multiglob

# IMPORT STATIC VARIABLES FROM MAIN
from __main__ import inputdir
from __main__ import outputdir
from __main__ import forensic_mode
from __main__ import no_tarball
from __main__ import quiet

from __main__ import archive
from __main__ import startTime
from __main__ import full_prefix
from __main__ import OSVersion
from __main__ import data_writer

# MODULE-SPECIFIC IMPORTS
import json
import glob
import time
import os
import sys
import ast
import logging
import plistlib
import traceback
from .common.dateutil import parser
from collections import OrderedDict
try:
    from datetime import timezone
except Exception:
    if sys.version_info[0] < 3:
        import pytz as timezone
    else:
        raise Exception("pytz not native to python3 on macos - libary include pending")


_modName = __name__.split('_')[-1]
_modVers = '1.0.4'
log = logging.getLogger(_modName)


def module():

    if OSVersion is not None:
        ver = float('.'.join(OSVersion.split('.')[1:]))
        if ver < 13:
            log.error("Artifact is not present below OS version 10.13.")
            return
        if ver >= 15:
            # log.warning("Artifact contents and information have changed for macOS 10.15+ - Experimental parsing available, see module file.")
            log.error("Artifact contents and information have changed for macOS 10.15+")
            # return parseCatalina() # WARN: EXPERIMENTAL
            return
    else:
        log.debug("OSVersion not detected, but going to try to parse anyway.")

    headers = ['src_report', 'diag_start', 'diag_end', 'name', 'uuid', 'processName',
               'appDescription', 'appName', 'appVersion', 'foreground', 'uptime',
               'uptime_parsed', 'powerTime', 'powerTime_parsed', 'activeTime', 'activeTime_parsed',
               'activations', 'launches', 'activityPeriods', 'idleTimeouts', 'Uptime',
               'Count', 'version', 'identifier', 'overflow']

    output = data_writer(_modName, headers)

    analytics_location = multiglob(inputdir, ['Library/Logs/DiagnosticReports/Analytics*.core_analytics',
    								          'Library/Logs/DiagnosticReports/Retired/Analytics*.core_analytics'])

    if len(analytics_location) < 1:
        log.debug("No .core_analytics files found.")
    else:
        log.debug("Found {0} .core_analytics files to parse.".format(len(analytics_location)))

    counter = 0
    for file in analytics_location:
        data = open(file, 'r').read()
        data_lines = [json.loads(i) for i in data.split('\n') if i.startswith("{\"message\":")]

        try:
            diag_start = [json.loads(i) for i in data.split('\n') if
                          i.startswith("{\"_marker\":") and "end-of-file"
                          not in i][0]['startTimestamp']
        except ValueError:
            diag_start = "ERROR"

        try:
            diag_end = [json.loads(i) for i in data.split('\n') if
                        i.startswith("{\"timestamp\":")][0]['timestamp']
            diag_end = str(parser.parse(diag_end).astimezone(timezone.utc))
            diag_end = diag_end.replace(' ', 'T').replace('+00:00', 'Z')
        except ValueError:
            diag_end = "ERROR"

        for i in data_lines:
            record = OrderedDict((h, '') for h in headers)
            record['src_report'] = file
            record['diag_start'] = diag_start
            record['diag_end'] = diag_end
            record['name'] = i['name']
            record['uuid'] = i['uuid']

            # If any fields not currently recorded (based on the headers above) appear,
            # they will be added to overflow.
            record['overflow'] = {}

            for k, v in i['message'].items():
                if k in record.keys():
                    record[k] = i['message'][k]
                else:
                    record['overflow'].update({k: v})

            if len(record['overflow']) == 0:
                record['overflow'] = ''

            if record['uptime'] != '':
                record['uptime_parsed'] = time.strftime("%H:%M:%S",
                                                        time.gmtime(record['uptime']))

            if record['activeTime'] != '':
                record['activeTime_parsed'] = time.strftime("%H:%M:%S",
                                                            time.gmtime(record['activeTime']))

            if record['powerTime'] != '':
                record['powerTime_parsed'] = time.strftime("%H:%M:%S",
                                                           time.gmtime(record['powerTime']))

            if record['appDescription'] != '':
                record['appName'] = record['appDescription'].split(' ||| ')[0]
                record['appVersion'] = record['appDescription'].split(' ||| ')[1]

            output.write_record(record)
            counter += 1

    # Parse aggregate files either from their directory on disk.
    agg_location = glob.glob(os.path.join(inputdir,'private/var/db/analyticsd/aggregates/4d7c9e4a-8c8c-4971-bce3-09d38d078849'))

    if ver > 13.6:
        log.debug("Cannot currently parse aggregate file above OS version 10.13.6.")
        return

    if len(agg_location) < 1:
        log.debug("No aggregate files found.")
    else:
        log.debug("Found {0} aggregate files to parse.".format(len(agg_location)))

    for aggregate in agg_location:
        data = open(aggregate, 'r').read()
        obj_list = data.split('\n')

        if len(obj_list) > 1:
            obj = [i for i in obj_list if '[[[' in i][0]
            try:
                data_lines = json.loads(obj)
            except ValueError:
                try:
                    data_lines = json.loads(json.dumps(list(ast.literal_eval(obj))))
                except Exception as e:
                    data_lines = []
                    log.debug("Could not parse aggregate file: {0}.".format([traceback.format_exc()]))
            except Exception as e:
                data_lines = []
                log.debug("Could not parse aggregate file: {0}.".format([traceback.format_exc()]))

        elif len(obj_list) == 1:
            obj = obj_list[0]
            try:
                data_lines = json.loads(obj)
            except ValueError:
                try:
                    data_lines = json.loads(json.dumps(list(ast.literal_eval(obj))))
                except Exception as e:
                    data_lines = []
                    log.debug("Could not parse aggregate file: {0}.".format([traceback.format_exc()]))
            except Exception as e:
                data_lines = []
                log.debug("Could not parse aggregate file: {0}.".format([traceback.format_exc()]))

        else:
            data_lines = []
            log.debug("Could not parse aggregate file. File had unusual number of objects to parse: {0}. | {1}".format(str(len(obj_list)), [traceback.format_exc()]))


        diag_start = stats2(aggregate)['btime']
        diag_end = stats2(aggregate)['mtime']

        raw = [i for i in data_lines if len(i) == 2 and (len(i[0]) == 3 and len(i[1]) == 7)]
        for i in raw:
            record = OrderedDict((h, '') for h in headers)

            record['src_report'] = aggregate
            record['diag_start'] = diag_start
            record['diag_end'] = diag_end
            record['uuid'] = os.path.basename(aggregate)
            record['processName'] = i[0][0]

            record['appDescription'] = i[0][1]
            if record['appDescription'] != '':
                record['appName'] = record['appDescription'].split(' ||| ')[0]
                record['appVersion'] = record['appDescription'].split(' ||| ')[1]

            record['foreground'] = i[0][2]

            record['uptime'] = i[1][0]
            record['uptime_parsed'] = time.strftime("%H:%M:%S", time.gmtime(i[1][0]))

            record['activeTime'] = i[1][1]
            record['activeTime_parsed'] = time.strftime("%H:%M:%S", time.gmtime(i[1][1]))

            record['launches'] = i[1][2]
            record['idleTimeouts'] = i[1][3]
            record['activations'] = i[1][4]
            record['activityPeriods'] = i[1][5]

            record['powerTime'] = i[1][6]
            record['powerTime_parsed'] = time.strftime("%H:%M:%S", time.gmtime(i[1][6]))

            output.write_record(record)
            counter += 1

    output.flush_record()
    if counter > 0:
        log.debug("Done. Wrote {0} lines.".format(counter))

"""EXPERIMENTAL"""
# Artifact data changed from OS10.14 - 10.15
def parseCatalina():
    crashreporter_headers = [
    'crashreporter_key',
    'crashreporter_timestamp',
    'crashreporter_os_version',
    'EXTRA',
    ]

    message_headers = [
    'message-message',
    'message-name',
    'message-uuid',
    'EXTRA',
    ]

    event_headers = [
    'event-eventCount',
    'event-message-BootDiskType',
    'event-message-BootPartitionFS',
    'event-message-Category',
    'event-message-DurationInSeconds',
    'event-message-EndProcessName',
    'event-message-FrameRate',
    'event-message-IntervalType',
    'event-message-Name',
    'event-message-Number1Name',
    'event-message-Number1Value',
    'event-message-Number2Name',
    'event-message-Number2Value',
    'event-message-StartProcessName',
    'event-message-String1Name',
    'event-message-String1Value',
    'event-message-String2Name',
    'event-message-String2Value',
    'event-message-SubSystem',
    'event-message-name',
    'event-message-uuid',
    'EXTRA',
    ]
    crashreporter_output = data_writer("EXPERIMENTAL_"+ _modName+"crashreporter", crashreporter_headers)
    message_output = data_writer("EXPERIMENTAL_"+ _modName+"messages", message_headers)
    event_output = data_writer("EXPERIMENTAL_"+ _modName+"events", event_headers)
    analytics_files = multiglob(inputdir, ['Library/Logs/DiagnosticReports/Analytics*.core_analytics',
    								          'Library/Logs/DiagnosticReports/Retired/Analytics*.core_analytics'])

    if len(analytics_files) < 1:
        log.debug("No .core_analytics files found.")
    else:
        log.debug("Found {0} .core_analytics files to parse.".format(len(analytics_files)))

    total_count = 0
    for file in analytics_files:
        with open(file, 'r') as analytics_file:
            log.debug("Parsing {0}".format(file))
            count = 0

            event_record = OrderedDict((h, 'N/A') for h in event_headers)
            crash_record = OrderedDict((h, 'N/A') for h in crashreporter_headers)
            message_record = OrderedDict((h, 'N/A') for h in message_headers)
            for line in analytics_file:
                if line.startswith("{\"crashreporter_key\""):
                    jline = json.loads(line)
                    crash_record["crashreporter_key"] = jline['crashreporter_key']
                    crash_record["timestamp"] = jline['timestamp']
                    crash_record["os_version"] = jline['os_version']
                elif line.startswith("{\"_marker\""):
                    pass
                elif line.startswith("{\"message\""):
                    jline = json.loads(line)
                    message_record["message"] = jline['message']
                    message_record["name"] = jline['name']
                    message_record["uuid"] = jline['uuid']
                elif "eventCount" in line:
                    jline = json.loads(line)
                    message=jline['message']
                    event_record['event-eventCount'] = jline['eventCount']
                    event_record['event-message-BootDiskType'] = message['BootDiskType']
                    event_record['event-message-BootPartitionFS'] = message['BootPartitionFS']
                    event_record['event-message-Category'] = message['Category']
                    event_record['event-message-DurationInSeconds'] = message['DurationInSeconds']
                    event_record['event-message-EndProcessName'] = message['EndProcessName']
                    event_record['event-message-FrameRate'] = message['FrameRate']
                    event_record['event-message-IntervalType'] = message['IntervalType']
                    event_record['event-message-Name'] = message['Name']
                    event_record['event-message-Number1Name'] = message['Number1Name']
                    event_record['event-message-Number1Value'] = message['Number1Value']
                    event_record['event-message-Number2Name'] = message['Number2Name']
                    event_record['event-message-Number2Value'] = message['Number2Value']
                    event_record['event-message-StartProcessName'] = message['StartProcessName']
                    event_record['event-message-String1Name'] = message['String1Name']
                    event_record['event-message-String1Value'] = message['String1Value']
                    event_record['event-message-String2Name'] = message['String2Name']
                    event_record['event-message-String2Value'] = message['String2Value']
                    event_record['event-message-SubSystem'] = message['Subsystem']
                    event_record['event-message-name'] = jline['name']
                    event_record['event-message-uuid'] = jline['uuid']
                else:
                    pass
                count += 1
                line1 = event_record.values()
                line2 = crash_record.values()
                line3 = message_record.values()
                if len(line1) > 0 : event_output.write_record(line1)
                if len(line2) > 0 : crashreporter_output.write_record(line2)
                if len(line3) > 0 : message_output.write_record(line3)
            log.debug("Finished parsing {0}: had {1} entries".format(file, count))
            total_count += count
    log.info("Parsed {0} total coreanalytics entries from {1} files".format(total_count, len(analytics_files)))
    crashreporter_output.flush_record()
    message_output.flush_record()
    event_output.flush_record()

if __name__ == "__main__":
    print("This is an AutoMacTC module, and is not meant to be run stand-alone.")
    print("Exiting.")
    sys.exit(0)
else:
    module()
