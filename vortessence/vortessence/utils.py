# Vortessence  Memory Forensics
# Copyright 2015 Bern University of Applied Sciences
# Copyright 2007-2015 Volatility Foundation
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

import sys
import os
import distorm3
import volatility25.volatility.fmtspec as fmtspec


class Base(object):
    def __init__(self):
        # Setup environ
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', "vortessence.settings")
        sys.path.append(os.path.dirname(os.path.abspath(__file__)))

    # copied from volatility
    def _formatlookup(self, profile, code):
        """Code to turn profile specific values into format specifications"""
        code = code or ""
        if not code.startswith('['):
            return code

        # Strip off the square brackets
        code = code[1:-1].lower()
        if code.startswith('addr'):
            spec = fmtspec.FormatSpec("#10x")
            if profile.endswith('64'):
                spec.minwidth += 8
            if 'pad' in code:
                spec.fill = "0"
                spec.align = spec.align if spec.align else "="
            else:
                # Non-padded addresses will come out as numbers,
                # so titles should align >
                spec.align = ">"
            return spec.to_string()

    # copied from volatility
    def format_value(self, value, fmt, profile="Win7SP1x86"):
        """ Formats an individual field using the table formatting codes"""
        return ("{0:" + self._formatlookup(profile, fmt) + "}").format(value)


item_store = None


class Store:
    snapshot = None
    snapshot_id = None
    processes = None
    dlls = None

    def __init__(self):
        self.snapshot = None
        self.snapshot_id = None
        self.processes = {}
        self.dlls = []


def get_process_index_by_pid(pid):
    for i in range(len(item_store.processes)):
        if int(item_store.processes[i].pid) == int(pid):
            return i
    return None


def get_process_by_pid(pid):
    try:
        return item_store.processes[pid]
    except KeyError:
        return None


def get_pid_by_index(index):
    return item_store.processes[index].pid


def get_db_pid_by_index(index):
    return item_store.processes[index]._db_id


def get_dll_by_pid_and_base(pid, base):
    for d in item_store.dlls:
        if d.process.id == pid and d.base == base:
            return d


def get_dll_by_process_and_path(process, path):
    for d in item_store.dlls:
        if d.process == process and path.rstrip().lower() == d.path.rstrip().lower():
            return d
    return None


def set_process_ppid():
    for pid, process in item_store.processes.iteritems():
        item_store.processes[pid].parent = get_process_by_pid(process.ppid)
        item_store.processes[pid].save()


# copied from volatility
def disassemble(data, start, bits='32bit', stoponret=False):
    """Dissassemble code with distorm3.

    @param data: python byte str to decode
    @param start: address where `data` is found in memory
    @param bits: use 32bit or 64bit decoding
    @param stoponret: stop disasm when function end is reached

    @returns: tuple of (offset, instruction, hex bytes)
    """

    if bits == '32bit':
        mode = distorm3.Decode32Bits
    else:
        mode = distorm3.Decode64Bits

    for o, _, i, h in distorm3.DecodeGenerator(start, data, mode):
        if stoponret and i.startswith("RET"):
            raise StopIteration
        yield o, i, h


# copied from volatility
def hexdump(self, data, width=16):
    """ Hexdump function shared by various plugins """
    for offset in xrange(0, len(data), width):
        row_data = data[offset:offset + width]
        translated_data = [x if ord(x) < 127 and ord(x) > 32 else "." for x in row_data]
        hexdata = " ".join(["{0:02x}".format(ord(x)) for x in row_data])

        yield offset, hexdata, translated_data




