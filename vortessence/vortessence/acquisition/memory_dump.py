# Vortessence  Memory Forensics
# Copyright 2015 Bern University of Applied Sciences
#
# Author Beni Urech, beni@vortessence.org
#
# This program is  free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import subprocess
import time
import shutil
import multiprocessing
import random
import string
import json
from datetime import datetime
from django.utils import text

from vortessence import utils
from vortessence.utils import Base, Store
from vortessence.models import Snapshot, Profile
from vortessence import settings
import volatility_parser


class MemoryDump(Base):
    threads = None
    profile = None
    description = None
    user = None
    filename = None
    hostname = None

    def __init__(self, profile_name=None, filename=None, hostname=None, description=None, config=None,
                 threads=None):
        self.description = description if description else ""
        self.user = ''.join(random.choice(string.ascii_lowercase + string.digits) for x in range(10))
        self.filename = filename
        self.hostname = hostname if hostname else ""

        if not threads:
            self.threads = multiprocessing.cpu_count()

        if profile_name is not None:
            try:
                self.profile = Profile.objects.get(name=profile_name)
            except Profile.DoesNotExist:
                print "Error: profile {0} does not exist".format(profile_name)
                exit(-1)

        if config is not None or os.path.isfile(os.path.expanduser("~") + os.sep + ".vortconf"):
            try:
                data = json.loads(
                    file(config if config is not None else os.path.expanduser("~") + os.sep + ".vortconf").read())
                settings.vort_path["ramdisk"] = data["vort_path"]["ramdisk"]
                settings.vort_path["upload"] = data["vort_path"]["upload"]
                settings.vort_path["target"] = data["vort_path"]["target"]
                settings.malfind_dump_path = data["malfind_dump_path"]
            except IOError as e:
                print "Error reading config file: {}".format(e)
                exit(-1)
            except ValueError as e:
                print "Error parsing config file: {}".format(e)
                exit(-1)

    def check_subprocesses(self, subprocesses):
        for i in range(len(subprocesses)):
            try:
                if subprocesses[i].poll() is not None:
                    subprocesses.remove(subprocesses[i])
            except IndexError:
                pass
        time.sleep(0.1)

    def start_analysis(self, hostname, snapshot_file, existing_snapshot=False):
        skip_volatility = True if existing_snapshot else False
        ramdisk_path = settings.vort_path["ramdisk"]
        if self.user:
            ramdisk_path += os.sep + text.get_valid_filename(self.user)
            settings.malfind_dump_path += os.sep + text.get_valid_filename(self.user)
            if not os.path.isdir(ramdisk_path):
                os.makedirs(ramdisk_path)

        if not skip_volatility:
            #cleanup ramdisk
            for item in os.listdir(ramdisk_path):
                if os.path.isdir(ramdisk_path + os.sep + item):
                    shutil.rmtree(ramdisk_path + os.sep + item)
                else:
                    os.remove(ramdisk_path + os.sep + item)

            # copy snapshot to ramdisk
            shutil.copy2(snapshot_file, ramdisk_path)
            temp_snapshot = ramdisk_path + os.sep + snapshot_file.split(os.sep)[-1]

        # create the snapshot in DB
        utils.item_store = None
        utils.item_store = Store()

        snapshot = Snapshot()
        snapshot.os = self.profile.name
        snapshot.hostname = hostname
        snapshot.profile = self.profile

        if skip_volatility:
            snapshot.description = existing_snapshot.description
            snapshot.filename = existing_snapshot.filename
        snapshot.date = datetime.now()
        snapshot.save()
        utils.item_store.snapshot = snapshot

        if not skip_volatility:
            # create target dir
            os.makedirs(settings.vort_path["target"] + os.sep + str(snapshot.id))
            if not os.path.isdir(settings.malfind_dump_path):
                os.makedirs(settings.malfind_dump_path)
            final_destination = settings.vort_path["target"] + os.sep + str(snapshot.id)
            snapshot.filename = final_destination + os.sep + snapshot_file.split(os.sep)[-1]
            snapshot.save()

            # run the volatility plugins!
            subprocesses = []
            for (plugin, output, options) in settings.vol_plugins:
                # skip x86 only plugins for x64 snapshots
                if snapshot.profile.name.endswith("x64") and plugin in settings.x86_only_plugins:
                    continue
                while len(subprocesses) >= int(self.threads):
                    self.check_subprocesses(subprocesses)

                print("Executing plugin " + plugin + "...")

                if options is not None:
                    if plugin == "malfind":
                        options = "--dump-dir={}".format(settings.malfind_dump_path)
                    print("... with options " + options)
                    process = subprocess.Popen(
                        [settings.python_path, settings.vol_path, "-f", temp_snapshot, "--profile=" + self.profile.name,
                         plugin, output, options,
                         "--output-file=" + ramdisk_path + os.sep + plugin + "_" + str(snapshot.id)],
                        stdout=open(ramdisk_path + os.sep + plugin + "_" + str(snapshot.id) + "_log", "w"))
                else:
                    process = subprocess.Popen(
                        [settings.python_path, settings.vol_path, "-f", temp_snapshot, "--profile=" + self.profile.name,
                         plugin, output, "--output-file=" + ramdisk_path + os.sep + plugin + "_" + str(snapshot.id)],
                        stdout=open(ramdisk_path + os.sep + plugin + "_" + str(snapshot.id) + "_log", "w"))

                subprocesses.append(process)

            # wait until all volatility plugins finished
            while len(subprocesses) > 0:
                self.check_subprocesses(subprocesses)

        # run the parsers
        voloutput_folder = ramdisk_path + os.sep if not skip_volatility else os.path.dirname(
            snapshot.filename) + os.sep

        # parse the JSON files
        for (plugin, output, options) in settings.vol_plugins:
            if snapshot.profile.name.endswith("x64") and plugin in settings.x86_only_plugins:
                continue
            print("Storing " + plugin + "..."),
            volatility_parser.parse_json(plugin, voloutput_folder,
                                         snapshot.id if not skip_volatility else existing_snapshot.id,
                                         self if plugin == "malfind" else None)
            print "Done!"

        # set the parent processes
        utils.set_process_ppid()

        if not skip_volatility:
            # move everything to the final destination
            for item in os.listdir(ramdisk_path):
                try:
                    shutil.move(voloutput_folder + item, final_destination + os.sep + item)
                except:
                    print "Warning: Could not move", item
            for item in os.listdir(settings.malfind_dump_path):
                try:
                    shutil.move(settings.malfind_dump_path + os.sep + item, final_destination + os.sep + item)
                except:
                    print "Warning: Could not move", item

            # clean up
            os.remove(snapshot_file)
            os.rmdir(ramdisk_path)

        # set the snapshot status to 1 (partially stored)
        snapshot.status = 1
        snapshot.save()

        return snapshot

    def preprocess_base(self, snapshot=None):
        snapshots = []
        if self.filename:
            if os.path.isfile(self.filename):
                hostname = self.hostname if self.hostname else ""
                snapshots.append(self.start_analysis(hostname, self.filename))
                return snapshots
            else:
                print "Error: {} is not a valid file".format(self.filename)
                exit(-1)
        if not snapshot:
            for snapshot_file in os.listdir(settings.vort_path["upload"]):
                snapshot_path = settings.vort_path["upload"] + os.sep + snapshot_file
                # ignore files below 50MB
                if os.path.isfile(snapshot_path) and os.path.getsize(snapshot_path) > 50000000:
                    snapshots.append(
                        self.start_analysis(self.hostname, snapshot_path))
            return snapshots
        else:
            self.start_analysis(snapshot.hostname, snapshot.filename, snapshot)
            snapshots.append(snapshot)
            return snapshots

    def preprocess_slow_plugins(self, snapshot):
        utils.item_store = None
        utils.item_store = Store()
        utils.item_store.snapshot = snapshot

        ramdisk_path = settings.vort_path["ramdisk"]
        if self.user:
            ramdisk_path += os.sep + text.get_valid_filename(self.user)
            if not os.path.isdir(ramdisk_path):
                os.mkdir(ramdisk_path)

        # copy the snapshot file back to the ramdisk
        shutil.copy2(snapshot.filename, ramdisk_path)
        temp_snapshot = ramdisk_path + os.sep + snapshot.filename.split(os.sep)[-1]

        subprocesses = []
        for (plugin, output, options) in settings.slow_vol_plugins:
            while len(subprocesses) >= int(self.threads):
                self.check_subprocesses(subprocesses)

            print("Executing plugin " + plugin + "...")

            if options is not None:
                print("... with options " + options)
                process = subprocess.Popen(
                    [settings.python_path, settings.vol_path, "-f", temp_snapshot, "--profile=" + snapshot.profile.name,
                     plugin, output, options],
                    stdout=open(ramdisk_path + os.sep + plugin + "_" + str(snapshot.id), "w"))
            else:
                process = subprocess.Popen(
                    [settings.python_path, settings.vol_path, "-f", temp_snapshot, "--profile=" + snapshot.profile.name,
                     plugin, output],
                    stdout=open(ramdisk_path + os.sep + plugin + "_" + str(snapshot.id), "w"))

            subprocesses.append(process)

        # run the registry part
        registry_counter = 0
        autostart_registry_keys = []
        parent_key_files = []

        # recursive autostart registry keys
        print("Executing autostart key search...")
        number_of_keys = len(settings.autostart_registry_keys)
        current_number = 1
        for parent_key in settings.autostart_registry_keys:
            print "Searching key {} of {}: {}".format(current_number, number_of_keys, parent_key)
            tempfile = "registryautostart_" + str(registry_counter) + "_" + str(snapshot.id) + "_" + parent_key. \
                replace("\\", "-backslash-").replace("*", "-asterisk-")
            registry_counter += 1

            process = subprocess.Popen(
                [settings.python_path, settings.vol_path, "-f", snapshot.filename,
                 "--profile=" + snapshot.profile.name, "printkey", "-K", parent_key],
                stdout=open(ramdisk_path + os.sep + tempfile, "w"), stderr=open(os.devnull, "w"))

            subprocesses.append(process)
            autostart_registry_keys.append(parent_key)
            parent_key_files.append(tempfile)
            current_number += 1
            while len(subprocesses) >= int(self.threads):
                self.check_subprocesses(subprocesses)

        current_number = 1

        # wait until all registry plugins finished
        while len(subprocesses) > len(settings.slow_vol_plugins):
            self.check_subprocesses(subprocesses)

        for tempfile in parent_key_files:
            # open file
            f = file(ramdisk_path + os.sep + tempfile)
            parent_key = "_".join(tempfile.split("_")[3:]).replace("-backslash-", "\\").replace("-asterisk-", "*")
            while True:

                line = f.readline()
                if len(line) == 0:
                    break

                if line.startswith("  (S)"):
                    registry_counter += 1
                    subkey = line[6:-1]
                    print "Searching subkey {}: {}\\{}".format(current_number, parent_key, subkey)
                    current_number += 1
                    output_file = "registryautostart_" + str(registry_counter) + "_" + str(
                        snapshot.id) + "_" + parent_key + "_" + subkey
                    output_file = ramdisk_path + os.sep + output_file.replace("\\", "-backslash-").replace("*",
                                                                                                           "-asterisk-").replace(
                        "/", "-slash-")
                    process = subprocess.Popen(
                        [settings.python_path, settings.vol_path, "-f", snapshot.filename,
                         "--profile=" + snapshot.profile.name, "printkey", "-K",
                         "{}\\{}".format(parent_key, subkey)],
                        stdout=open(output_file, "w"), stderr=open(os.devnull, "w"))

                    subprocesses.append(process)
                    autostart_registry_keys.append(parent_key + "\\" + subkey)
                    while len(subprocesses) >= int(self.threads):
                        self.check_subprocesses(subprocesses)
            f.close()

        # wait until all volatility plugins finished
        while len(subprocesses) > 0:
            self.check_subprocesses(subprocesses)

        # parse the autostart registry console files
        print("Storing autostart keys...")
        for item in os.listdir(ramdisk_path):
            if os.path.isfile(ramdisk_path + os.sep + item) and item.startswith("registryautostart_"):
                volatility_parser.registryautostart(ramdisk_path + os.sep + item)
        print "Storing apihooks..."
        volatility_parser.parse_json("apihooks", ramdisk_path + os.sep, snapshot.id,
                                     {"memory_dump": self, "snapshot": snapshot})

        # remove the original snapshot
        os.remove(temp_snapshot)

        # set the snapshot status to 2 (stored)
        if snapshot.status == 1:
            snapshot.status = 2
            snapshot.save()

        for item in os.listdir(ramdisk_path):
            try:
                shutil.move(ramdisk_path + os.sep + item,
                            os.path.dirname(snapshot.filename) + os.sep + item)
            except WindowsError:
                print "Warning: Could not move", item

