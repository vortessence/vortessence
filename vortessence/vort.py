#!/usr/bin/env python
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

import argparse
import sys
import os

# Setup environ
if __name__ == "__main__":
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', "vortessence.settings")
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    import django

    django.setup()

    from vortessence.console.snapshot_manager import SnapshotManager
    from vortessence.console.writer import SnapshotWriter
    from vortessence.acquisition.memory_dump import MemoryDump

parser = argparse.ArgumentParser(description='Vortessence command line interface')
parser.add_argument('-l', dest='list', action='store_true',
                    help='List memory images in Vortessence database')
parser.add_argument('-a', dest='action', action='store',
                    help='Specify action: whitelist, detect, preprocess, preprocess_base, preprocess_additional, '
                         'output, delete, delete_detections')
parser.add_argument('-s', dest='image', action='store',
                    help='[optional] Image ID as found in Vortessence DB, which is used in certain commands')
parser.add_argument('--profile', dest='profile', action='store',
                    help='Name of Volatility profile used in preprocess or preprocess_base commands')
parser.add_argument('-f', dest='image_filename', action='store',
                    help='[optional] Filename of image to load into Vortessence database using preprocess '
                         'or preprocess_base commands')
parser.add_argument('-H', dest='hostname', action='store',
                    help='[optional] Hostname to store in Vortessence DB to identify origin of memory image '
                         '(informative only)')
parser.add_argument('-c', dest='comment', action='store',
                    help='[optional] specify comment to be stored with image when using preprocess, or preprocess_base '
                         'actions (informative only)')
parser.add_argument('--plugin', dest='plugin', action='store', help='[optional] Specify Volatility plugin for which '
                                                                    'anomaly detection results are shown')
parser.add_argument('-p', dest='process', action='store',
                    help='[optional] Specify process PID to be used with certain plugin outputs')
parser.add_argument('--filter', dest='anomalies_only', action='store_true', help='[optional] Only output anomalies, '
                                                                                 'and suppress other output')
parser.add_argument('--search', dest='search', action='store',
                    help='[optional] Search for anomalies identified by base address or name')
parser.add_argument('--yes', dest='skip_confirm', action='store_true',
                    help='Assume Yes to all queries and do not prompt')
parser.add_argument('--config', dest='config', action='store', help='[optional] Specify alternate config file')

if not len(sys.argv) > 1:
    parser.print_help()
    exit(0)

args = parser.parse_args()

if args.list:
    snapshot_writer = SnapshotWriter()
    snapshot_writer.list_snapshots()

elif args.action:

    sm = SnapshotManager(snapshot_id=args.image) if args.image else None

    if args.action.lower() == "whitelist":
        if not args.image:
            if not args.profile:
                parser.print_help()
                exit(0)
            md = MemoryDump(profile_name=args.profile, filename=args.image_filename, hostname=args.hostname,
                            description=args.comment, config=args.config)
            snapshots = md.preprocess_base()
            for snapshot in snapshots:
                md.preprocess_slow_plugins(snapshot)
                sm = SnapshotManager(snapshot=snapshot)
                sm.engine.whitelist()
        else:
            sm.engine.whitelist()

    elif args.action.lower() == "detect":
        if not args.image:
            if not args.profile:
                parser.print_help()
                exit(0)
            md = MemoryDump(profile_name=args.profile, filename=args.image_filename, hostname=args.hostname,
                            description=args.comment, config=args.config)
            snapshots = md.preprocess_base()
            for snapshot in snapshots:
                md.preprocess_slow_plugins(snapshot)
                sm = SnapshotManager(snapshot=snapshot)
                sm.engine.detect()
        else:
            sm.engine.detect()

    elif args.action.lower() == "preprocess_base":
        if not args.profile:
            parser.print_help()
            exit(0)
        md = MemoryDump(profile_name=args.profile, filename=args.image_filename, hostname=args.hostname,
                        description=args.comment, config=args.config)
        snapshots = md.preprocess_base(sm.snapshot if sm else None)

    elif args.action.lower() == "preprocess_additional":
        if not args.image:
            print "Error: Image required"
            parser.print_help()
            exit(0)
        md = MemoryDump()
        md.preprocess_slow_plugins(sm.snapshot)

    elif args.action.lower() == "preprocess":
        if not args.profile:
            parser.print_help()
            exit(0)
        md = MemoryDump(profile_name=args.profile, filename=args.image_filename, hostname=args.hostname,
                        description=args.comment, config=args.config)
        snapshots = md.preprocess_base(sm.snapshot if sm else None)
        for snapshot in snapshots:
            md.preprocess_slow_plugins(snapshot)

    elif args.action.lower() == "output":
        if not args.image:
            parser.print_help()
            exit(0)

        sw = SnapshotWriter(args.image)
        sw.print_results(args.plugin, args.anomalies_only, args.process)

    elif args.action.lower() == "delete":
        if not args.image:
            parser.print_help()
            exit(0)
        if not args.skip_confirm:
            deleting_confirmed = raw_input(
                "WARNING: this will delete every result data related to this image. Type YES to continue: ")
            if deleting_confirmed.lower() == "yes":
                sm.delete()
            else:
                print "Canceled"
        else:
            sm.delete()
    elif args.action.lower() == "delete_detections":
        if not args.image:
            parser.print_help()
            exit(0)
        sm.delete_results()
    else:
        parser.print_help()
        exit(0)

elif args.search:
    if not args.image or not args.search:
        parser.print_help()
        exit(0)
    sw = SnapshotWriter(args.image)
    sw.search(args.search, args.anomalies_only)

else:
    parser.print_help()
    exit(0)

