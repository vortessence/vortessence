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

import logging
import datetime


class DbLogHandler(logging.Handler):
    def __init__(self):
        logging.Handler.__init__(self)

    def emit(self, record):
        try:
            #NOTE: need to import this here otherwise it causes a circular reference and doesn't work
            #  i.e. settings imports loggers imports models imports settings...
            from vortessence.models import Log
            try:
                snapshot = record.args["snapshot"]
            except KeyError:
                snapshot = None

            logEntry = Log(level=record.levelname, message=record.getMessage(), timestamp=datetime.datetime.now(),
                           snapshot=snapshot)
            logEntry.save()

        except:
            print "Error while trying to log something. Exiting..."
            exit(-1)

        return