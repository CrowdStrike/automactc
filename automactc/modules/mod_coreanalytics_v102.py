#!/usr/bin/env python

# MODULE-SPECIFIC IMPORTS
import json
import pytz
import glob
import time
import os
import ast
import traceback
from collections import OrderedDict
import dateutil.parser as parser

# IMPORT FUNCTIONS FROM COMMON.FUNCTIONS
from automactc.modules.common.base import AutoMacTCModule
from automactc.modules.common.functions import stats2
from automactc.modules.common.functions import multiglob
from automactc.utils.output import DataWriter


class CoreAnalyticsModule(AutoMacTCModule):
    _mod_filename = __name__

    _headers = [
        'src_report', 'diag_start', 'diag_end', 'name', 'uuid', 'processName',
        'appDescription', 'appName', 'appVersion', 'foreground', 'uptime',
        'uptime_parsed', 'powerTime', 'powerTime_parsed', 'activeTime', 'activeTime_parsed',
        'activations', 'launches', 'activityPeriods', 'idleTimeouts', 'Uptime',
        'Count', 'version', 'identifier', 'overflow'
    ]

    def run(self):
        output = DataWriter(self.module_name(), self._headers, self.log, self.run_id, self.options)

        if self.options.os_version is not None:
            ver = float('.'.join(self.options.os_version.split('.')[1:]))
            if ver < 13:
                self.log.error("Artifacts are not present below OS version 10.13.")
                return
        else:
            self.log.debug("OSVersion not detected, but going to try to parse anyway.")

        analytics_location = multiglob(self.options.inputdir, ['Library/Logs/DiagnosticReports/Analytics*.core_analytics',
        								          'Library/Logs/DiagnosticReports/Retired/Analytics*.core_analytics'])

        if len(analytics_location) < 1:
            self.log.debug("No .core_analytics files found.")
        else:
            self.log.debug("Found {0} .core_analytics files to parse.".format(len(analytics_location)))

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
                diag_end = str(parser.parse(diag_end).astimezone(pytz.utc))
                diag_end = diag_end.replace(' ', 'T').replace('+00:00', 'Z')
            except ValueError:
                diag_end = "ERROR"

            for i in data_lines:
                record = OrderedDict((h, '') for h in self._headers)
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

                line = record.values()
                output.write_entry(line)
                counter += 1

        # Parse aggregate files either from their directory on disk.
        agg_location = glob.glob(os.path.join(self.options.inputdir,'private/var/db/analyticsd/aggregates/4d7c9e4a-8c8c-4971-bce3-09d38d078849'))

        if ver > 13.6:
            self.log.debug("Cannot currently parse aggregate file above OS version 10.13.6.")
            return

        if len(agg_location) < 1:
            self.log.debug("No aggregate files found.")
        else:
            self.log.debug("Found {0} aggregate files to parse.".format(len(agg_location)))

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
                    except Exception:
                        data_lines = []
                        self.log.debug("Could not parse aggregate file: {0}.".format([traceback.format_exc()]))
                except Exception:
                    data_lines = []
                    self.log.debug("Could not parse aggregate file: {0}.".format([traceback.format_exc()]))

            elif len(obj_list) == 1:
                obj = obj_list[0]
                try:
                    data_lines = json.loads(obj)
                except ValueError:
                    try:
                        data_lines = json.loads(json.dumps(list(ast.literal_eval(obj))))
                    except Exception:
                        data_lines = []
                        self.log.debug("Could not parse aggregate file: {0}.".format([traceback.format_exc()]))
                except Exception:
                    data_lines = []
                    self.log.debug("Could not parse aggregate file: {0}.".format([traceback.format_exc()]))

            else:
                data_lines = []
                self.log.debug("Could not parse aggregate file. File had unusual number of objects to parse: {0}. | {1}".format(str(len(obj_list)), [traceback.format_exc()]))


            diag_start = stats2(aggregate)['btime']
            diag_end = stats2(aggregate)['mtime']

            raw = [i for i in data_lines if len(i) == 2 and (len(i[0]) == 3 and len(i[1]) == 7)]
            for i in raw:
                record = OrderedDict((h, '') for h in self._headers)

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

                line = record.values()
                output.write_entry(line)
                counter += 1

        if counter > 0:
            self.log.debug("Done. Wrote {0} lines.".format(counter))
