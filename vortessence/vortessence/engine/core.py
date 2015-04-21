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

from vortessence.engine import detection, whitelist
from vortessence.models import Registry


class Engine:
    snapshot = None

    def __init__(self, snapshot, snapshot_manager):
        self.snapshot = snapshot
        self.snapshot_manager = snapshot_manager

    def whitelist(self):
        if self.snapshot.status == 3 or self.snapshot.status == 4:
            print "Error: image {} already has detection results. Delete them before whitelisting the image".format(
                self.snapshot.id)
            return
        self.snapshot.status = 6 if Registry.objects.filter(snapshot=self.snapshot).exists() else 5
        self.snapshot.save()
        whitelist.run(self.snapshot)

    def detect(self):
        if self.snapshot.status == 4 or (
                    self.snapshot.status == 3 and not Registry.objects.filter(snapshot=self.snapshot).exists()):
            print "All data for image {} has been processed already".format(self.snapshot.id)
        elif self.snapshot.status == 3:
            print "found new data from store_slow. processing..."
            self.detect_slow_plugins()
        else:
            self.snapshot.status = 4 if Registry.objects.filter(snapshot=self.snapshot).exists() else 3
            self.snapshot.save()
            detection.run(self.snapshot)
