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

from vortessence.utils import Base
from vortessence.engine.core import Engine
from vortessence.models import *


class SnapshotManager(Base):
    snapshot = None
    engine = None

    def __init__(self, snapshot_id=None, snapshot=None):
        if snapshot_id is None and snapshot is None:
            print "Error: no image ID received or no file found. Aborting"
            exit()
        if snapshot:
            self.snapshot = snapshot
            self.engine = Engine(self.snapshot, self)
        else:
            try:
                snapshot_id = long(snapshot_id)
            except ValueError:
                print "Error: ", snapshot_id, "is not numeric. Aborting"
                exit()

            try:
                self.snapshot = Snapshot.objects.get(pk=snapshot_id)
                self.engine = Engine(self.snapshot, self)
            except Snapshot.DoesNotExist:
                print "Error: Image %s not found " % snapshot_id
                exit()

    def delete_results(self):
        DetCallback.objects.filter(snapshot=self.snapshot).delete()
        DetDriver.objects.filter(snapshot=self.snapshot).delete()
        DetFile.objects.filter(snapshot=self.snapshot).delete()
        DetGdt.objects.filter(snapshot=self.snapshot).delete()
        DetIdt.objects.filter(snapshot=self.snapshot).delete()
        DetRegistry.objects.filter(snapshot=self.snapshot).delete()
        DetService.objects.filter(snapshot=self.snapshot).delete()
        DetSsdt.objects.filter(snapshot=self.snapshot).delete()
        DetTimer.objects.filter(snapshot=self.snapshot).delete()
        DetUnloadedModules.objects.filter(snapshot=self.snapshot).delete()
        DetConnection.objects.filter(snapshot=self.snapshot).delete()
        DetModscan.objects.filter(snapshot=self.snapshot).delete()

        for process in self.snapshot.process_set.all():
            DetApihook.objects.filter(process=process).delete()
            DetDll.objects.filter(process=process).delete()
            DetLdrmodule.objects.filter(process=process).delete()
            DetMalfind.objects.filter(process=process).delete()
            DetProcess.objects.filter(process=process).delete()
            DetHandle.objects.filter(process=process).delete()
            DetSid.objects.filter(process=process).delete()
            DetThread.objects.filter(process=process).delete()

        self.snapshot.status = 2 if Registry.objects.filter(snapshot=self.snapshot).exists() else 1
        self.snapshot.save()

    def delete_slow_results(self):
        DetRegistry.objects.filter(snapshot=self.snapshot).delete()
        for process in self.snapshot.process_set.all():
            DetApihook.objects.filter(process=process).delete()

    def delete(self):
        self.delete_results()
        self.snapshot.delete()
