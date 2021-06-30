#!/usr/bin/env python

'''
Convert a JSON file to CSV

Modified and adopted from https://github.com/Yelp/dataset-examples/blob/master/json_to_csv_converter.py
Copyright 2011 Yelp

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
  implied.
  See the License for the specific language governing permissions and
  limitations under the License.
'''

import csv
import json
import sys

if sys.version_info[0] < 3:
    from collections import MutableMapping
else:
    from collections.abc import MutableMapping

def read_and_write_file(json_filepath, csv_filepath, column_names):
    """Read in the json file and write it out to a csv file, given the column names."""
    if sys.version_info[0] < 3:
        with open(csv_filepath, 'wb+') as fout:
            csv_file = csv.writer(fout)
            csv_file.writerow(list(column_names))
            try:
                with open(json_filepath) as fin:
                    for line in fin:
                        line_contents = json.loads(line)
                        csv_file.writerow(get_row(line_contents, column_names))
            except Exception:  # handle single json outer entry files
                line_contents = json.load(open(json_filepath))
                csv_file.writerow(get_row(line_contents, column_names))
    else:
        with open(csv_filepath, 'w+') as fout:
            csv_file = csv.writer(fout)
            csv_file.writerow(list(column_names))
            try:
                with open(json_filepath) as fin:
                    for line in fin:
                        line_contents = json.loads(line)
                        csv_file.writerow(get_row(line_contents, column_names))
            except Exception:  # handle single json outer entry files
                line_contents = json.load(open(json_filepath))
                csv_file.writerow(get_row(line_contents, column_names))


def get_superset_of_column_names_from_file(json_filepath, column_limit):
    """Read in the json file and return the superset of column names."""
    column_names = set()
    # dat = json.load(open(json_filepath, 'r'))
    # print(dat)
    try:
        with open(json_filepath) as fin:
            for line in fin:
                line_contents = json.loads(line)
                column_names.update(set(get_column_names(line_contents).keys()))
                if (len(column_names)) > column_limit:  # Limit number of CSV columns to column_limit
                    return column_names
        return column_names
    except Exception:  # handle single json outer entry files
        line_contents = json.load(open(json_filepath, 'r'))
        column_names.update(set(get_column_names(line_contents).keys()))
        return column_names


def get_column_names(line_contents, parent_key=''):
    """Return a list of flattened key names given a dict.
    Example:
        line_contents = {
            'a': {
                'b': 2,
                'c': 3,
                },
        }
        will return: ['a.b', 'a.c']
    These will be the column names for the eventual csv file.
    """
    column_names = []
    if sys.version_info[0] < 3:
        for k, v in line_contents.iteritems():
            column_name = "{0}.{1}".format(parent_key, k) if parent_key else k
            if isinstance(v, MutableMapping):
                column_names.extend(get_column_names(v, column_name).items())
            else:
                column_names.append((column_name, v))
        return dict(column_names)
    else:
        for k, v in line_contents.items():
            column_name = "{0}.{1}".format(parent_key, k) if parent_key else k
            if isinstance(v, MutableMapping):
                column_names.extend(get_column_names(v, column_name).items())
            else:
                column_names.append((column_name, v))
        return dict(column_names)


def get_nested_value(d, key):
    """Return a dictionary item given a dictionary `d` and a flattened key from `get_column_names`.

    Example:
        d = {
            'a': {
                'b': 2,
                'c': 3,
                },
        }
        key = 'a.b'
        will return: 2

    """
    if key is None or d is None:
        return None
    if '.' not in key:
        if key not in d:
            return None
        return d[key]
    base_key, sub_key = key.split('.', 1)
    if base_key not in d:
        return None
    sub_dict = d[base_key]
    return get_nested_value(sub_dict, sub_key)


def get_row(line_contents, column_names):
    """Return a csv compatible row given column names and a dict."""
    row = []
    for column_name in column_names:
        line_value = get_nested_value(
            line_contents,
            column_name,
        )
        if sys.version_info[0] < 3:
            if isinstance(line_value, unicode):
                row.append('{0}'.format(line_value.encode('utf-8')))
            elif line_value is not None:
                row.append('{0}'.format(line_value))
            else:
                row.append('')
        else:
            if isinstance(line_value, str):
                row.append('{0}'.format(line_value))
            elif isinstance(line_value, bytes):
                row.append('{0}'.format(line_value.decode('UTF-8')))

            elif line_value is not None:
                row.append('{0}'.format(line_value))
            else:
                row.append('')
        
    return row


def json_file_to_csv(json_filepath, column_limit=21):
    csv_filepath = '{0}.csv'.format(json_filepath.split('.json')[0])
    column_names = get_superset_of_column_names_from_file(json_filepath, column_limit)
    read_and_write_file(json_filepath, csv_filepath, column_names)
