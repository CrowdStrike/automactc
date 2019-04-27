import csv
import json
import logging
import os
import shutil
import tarfile
import traceback

log = logging.getLogger(__name__)


# Establish class to build tarball of output files on the fly.
class BuildTar(object):

    def __init__(self, run_id, output_dir, name):
        self.run_id = run_id
        self.outputdir = output_dir
        self.name = name

    def add_file(self, fname):
        out_tar = os.path.join(self.outputdir, self.name)
        t_fname = os.path.join(self.outputdir, fname)
        archive = tarfile.open(out_tar, 'a')

        archive.add(t_fname, fname.replace(self.run_id, ''))
        archive.close()
        try:
            if not os.path.isdir(t_fname):
                os.remove(t_fname)
            else:
                shutil.rmtree(t_fname)
        except OSError:
            log.error("Added to archive, but could not delete {0}.".format(t_fname))


# Establish DataWriter class to handle output file format and naming scheme.
class DataWriter(object):

    def __init__(self, name, headers, logger, run_id, args):
        # TODO: Remove the 'replace' of output once all that stuff is removed from the modules.
        self.name = args.filename_prefix + ',' + name + run_id
        self.mod = name
        self.datatype = args.output_format
        self.headers = headers
        self.output_filename = self.name + '.' + self.datatype
        self.data_file_name = os.path.join(args.outputdir, self.output_filename)

        self._log = logger

        if self.datatype == 'csv':
            with open(self.data_file_name, 'w') as data_file:
                writer = csv.writer(data_file)
                writer.writerow(self.headers)
        elif self.datatype == 'json':
            with open(self.data_file_name, 'w') as data_file:
                pass

    def _del_none(self, d):
        for key, value in list(d.items()):
            if value is None or value is "":
                del d[key]
            elif isinstance(value, dict):
                self._del_none(value)
        return d

    def write_entry(self, data):
        if self.datatype == 'csv':
            with open(self.data_file_name, 'a') as data_file:
                writer = csv.writer(data_file)
                try:
                    writer.writerow(data)
                except Exception:
                    self._log.debug("Could not write line {0} | {1}".format(data, [traceback.format_exc()]))
        elif self.datatype == 'json':
            zipped_data = self._del_none(dict(zip(self.headers, data)))
            with open(self.data_file_name, 'a') as data_file:
                try:
                    json.dump(zipped_data, data_file)
                    data_file.write('\n')
                except Exception:
                    self._log.debug("Could not write line {0} | {1}".format(data, [traceback.format_exc()]))
