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

from __future__ import unicode_literals

from django.db import models
from django.db.models.fields import BigIntegerField


class PositiveBigIntegerField(BigIntegerField):
    """
    Custom PositiveBigIntegerField class to store unsigned 64bit values in MySQL
    """
    empty_strings_allowed = False
    description = "Big (8 byte) positive integer"

    def db_type(self, connection):
        if 'mysql' in connection.__class__.__module__:
            return 'bigint UNSIGNED'
        return super(BigIntegerField, self).db_type(connection)

    def formfield(self, **kwargs):
        defaults = {'min_value': 0,
                    'max_value': BigIntegerField.MAX_BIGINT * 2 - 1}
        defaults.update(kwargs)
        return super(PositiveBigIntegerField, self).formfield(**defaults)


class Apihook(models.Model):
    id = models.AutoField(primary_key=True)
    hook_mode = models.CharField(max_length=128)
    hook_type = models.CharField(max_length=128)
    process = models.ForeignKey('Process', blank=True, null=True)
    dll = models.ForeignKey('Dll', blank=True, null=True)
    function = models.CharField(max_length=500)
    hook_address = PositiveBigIntegerField(db_index=True)
    hooking_module = models.CharField(max_length=255, db_index=True)
    disassembly = models.TextField()

    class Meta:
        db_table = 'apihook'
        app_label = 'vortessence'


class Callback(models.Model):
    id = models.AutoField(primary_key=True)
    type = models.CharField(max_length=128)
    callback = PositiveBigIntegerField()
    module = models.CharField(max_length=128)
    details = models.CharField(max_length=256)
    snapshot = models.ForeignKey('Snapshot')

    class Meta:
        db_table = 'callback'
        app_label = 'vortessence'


class Connection(models.Model):
    id = models.AutoField(primary_key=True)
    offset = PositiveBigIntegerField(blank=True, null=True)
    source_port = models.IntegerField()
    destination_ip = models.CharField(max_length=128, blank=True)
    destination_port = models.IntegerField(blank=True, null=True)
    protocol = models.CharField(max_length=16)
    state = models.CharField(max_length=16, blank=True)
    time_created = models.CharField(max_length=64, blank=True)
    process = models.ForeignKey('Process', blank=True, null=True)
    snapshot = models.ForeignKey('Snapshot', blank=True, null=True)

    class Meta:
        db_table = 'connection'
        app_label = 'vortessence'


class DetApihook(models.Model):
    id = models.AutoField(primary_key=True)
    process = models.ForeignKey('Process')
    apihook = models.ForeignKey('Apihook')

    class Meta:
        db_table = 'det_apihook'
        app_label = 'vortessence'


class DetCallback(models.Model):
    callback = models.ForeignKey('Callback')
    snapshot = models.ForeignKey('Snapshot')

    class Meta:
        db_table = 'det_callback'
        app_label = 'vortessence'


class DetConnection(models.Model):
    connection = models.ForeignKey('Connection')
    process = models.ForeignKey('Process', blank=True, null=True)
    snapshot = models.ForeignKey('Snapshot')

    class Meta:
        db_table = 'det_connection'
        app_label = 'vortessence'


class DetDevice(models.Model):
    id = models.AutoField(primary_key=True)
    device = models.ForeignKey('Device')
    det_driver = models.ForeignKey('DetDriver', blank=True, null=True)

    class Meta:
        db_table = 'det_device'
        app_label = 'vortessence'


class DetDll(models.Model):
    id = models.AutoField(primary_key=True)
    unknown_for_process = models.BooleanField(default=False)
    unknown_overall = models.BooleanField(default=False)
    unknown_size = models.BooleanField(default=False)
    unknown_load_count = models.BooleanField(default=False)
    dll = models.ForeignKey('Dll')
    process = models.ForeignKey('Process')

    class Meta:
        db_table = 'det_dll'
        app_label = 'vortessence'


class DetDriver(models.Model):
    id = models.AutoField(primary_key=True)
    driver = models.ForeignKey('Driver')
    snapshot = models.ForeignKey('Snapshot')

    class Meta:
        db_table = 'det_driver'
        app_label = 'vortessence'


class DetFile(models.Model):
    id = models.AutoField(primary_key=True)
    filescan = models.ForeignKey('Filescan')
    snapshot = models.ForeignKey('Snapshot', blank=True, null=True)

    class Meta:
        db_table = 'det_file'
        app_label = 'vortessence'


class DetGdt(models.Model):
    id = models.AutoField(primary_key=True)
    gdt = models.ForeignKey('Gdt')
    snapshot = models.ForeignKey('Snapshot')

    class Meta:
        db_table = 'det_gdt'
        app_label = 'vortessence'


class DetHandle(models.Model):
    id = models.AutoField(primary_key=True)
    handle = models.ForeignKey('Handle')
    process = models.ForeignKey('Process')

    class Meta:
        db_table = 'det_handle'
        app_label = 'vortessence'


class DetIdt(models.Model):
    id = models.AutoField(primary_key=True)
    idt = models.ForeignKey('Idt')
    snapshot = models.ForeignKey('Snapshot')

    class Meta:
        db_table = 'det_idt'
        app_label = 'vortessence'


class DetIrpCall(models.Model):
    id = models.AutoField(primary_key=True)
    irp_call = models.ForeignKey('IrpCall')
    det_driver = models.ForeignKey(DetDriver)

    class Meta:
        db_table = 'det_irp_call'
        app_label = 'vortessence'


class DetLdrmodule(models.Model):
    id = models.AutoField(primary_key=True)
    ldrmodule = models.ForeignKey('Ldrmodule')
    process = models.ForeignKey('Process')

    class Meta:
        db_table = 'det_ldrmodule'
        app_label = 'vortessence'


class DetMalfind(models.Model):
    id = models.AutoField(primary_key=True)
    malfind = models.ForeignKey('Malfind')
    is_true_positive = models.BooleanField(default=False)
    reason = models.CharField(max_length=500)
    process = models.ForeignKey('Process')

    class Meta:
        db_table = 'det_malfind'
        app_label = 'vortessence'


class DetModscan(models.Model):
    id = models.AutoField(primary_key=True)
    modscan = models.ForeignKey('Modscan')
    snapshot = models.ForeignKey('Snapshot')

    class Meta:
        db_table = 'det_modscan'
        app_label = 'vortessence'


class DetProcess(models.Model):
    id = models.AutoField(primary_key=True)
    process = models.ForeignKey('Process')
    unknown_number_of_the_same = models.IntegerField(default=0)
    unknown_number_of_threads = models.IntegerField(default=0)
    unknown_number_of_dlls = models.IntegerField(default=0)
    network_anomaly = models.BooleanField(default=False)
    unknown_command_line = models.BooleanField(default=False)
    unknown_parent = models.BooleanField(default=False)
    unknown_process = models.BooleanField(default=False)

    class Meta:
        db_table = 'det_process'
        app_label = 'vortessence'


class DetRegistry(models.Model):
    id = models.AutoField(primary_key=True)
    registry = models.ForeignKey('Registry')
    snapshot = models.ForeignKey('Snapshot')

    class Meta:
        db_table = 'det_registry'
        app_label = 'vortessence'


class DetService(models.Model):
    id = models.AutoField(primary_key=True)
    service = models.ForeignKey('Service')
    process = models.ForeignKey('Process', blank=True, null=True)
    snapshot = models.ForeignKey('Snapshot')

    class Meta:
        db_table = 'det_service'
        app_label = 'vortessence'


class DetSid(models.Model):
    id = models.AutoField(primary_key=True)
    sid = models.ForeignKey('Sid')
    process = models.ForeignKey('Process')

    class Meta:
        db_table = 'det_sid'
        app_label = 'vortessence'


class DetSsdt(models.Model):
    id = models.AutoField(primary_key=True)
    ssdt = models.ForeignKey('Ssdt')
    snapshot = models.ForeignKey('Snapshot')

    class Meta:
        db_table = 'det_ssdt'
        app_label = 'vortessence'


class DetThread(models.Model):
    id = models.AutoField(primary_key=True)
    thread = models.ForeignKey('Thread')
    process = models.ForeignKey('Process')
    base_priority = models.IntegerField()

    class Meta:
        db_table = 'det_thread'
        app_label = 'vortessence'


class DetThreadInjection(models.Model):
    id = models.AutoField(primary_key=True)
    process = models.ForeignKey('Process')
    pid = models.IntegerField()
    name = models.CharField(max_length=128)
    path = models.CharField(max_length=500)
    timestamp = models.CharField(max_length=64)
    process_starttime = models.CharField(max_length=64)
    snapshot = models.ForeignKey('Snapshot')

    class Meta:
        db_table = 'det_thread_injection'
        app_label = 'vortessence'


class DetTimer(models.Model):
    id = models.AutoField(primary_key=True)
    timer = models.ForeignKey('Timer')
    snapshot = models.ForeignKey('Snapshot')

    class Meta:
        db_table = 'det_timer'
        app_label = 'vortessence'


class DetUnloadedModules(models.Model):
    id = models.AutoField(primary_key=True)
    unloaded_modules = models.ForeignKey('UnloadedModules')
    snapshot = models.ForeignKey('Snapshot')

    class Meta:
        db_table = 'det_unloaded_modules'
        app_label = 'vortessence'


class Device(models.Model):
    id = models.AutoField(primary_key=True)
    offset = PositiveBigIntegerField()
    name = models.CharField(max_length=128)
    type = models.CharField(max_length=128)
    level = models.IntegerField()
    parent_device = models.ForeignKey('Device', null=True, blank=True)
    driver = models.ForeignKey('Driver')

    class Meta:
        db_table = 'device'
        app_label = 'vortessence'


class Dll(models.Model):
    id = models.AutoField(primary_key=True)
    base = PositiveBigIntegerField(db_index=True)
    load_count = models.IntegerField()
    path = models.CharField(max_length=255, db_index=True)
    size = PositiveBigIntegerField()
    process = models.ForeignKey('Process')

    class Meta:
        db_table = 'dll'
        app_label = 'vortessence'


class Driver(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=64)
    start = PositiveBigIntegerField()
    size = PositiveBigIntegerField()
    start_io = PositiveBigIntegerField()
    snapshot = models.ForeignKey('Snapshot')

    class Meta:
        db_table = 'driver'
        app_label = 'vortessence'


class Filescan(models.Model):
    id = models.AutoField(primary_key=True)
    offset = PositiveBigIntegerField()
    pointers = models.IntegerField()
    handles = PositiveBigIntegerField()
    access = models.CharField(max_length=32)
    name = models.CharField(max_length=512)
    snapshot = models.ForeignKey('Snapshot', blank=True, null=True)

    class Meta:
        db_table = 'filescan'
        app_label = 'vortessence'


class Gdt(models.Model):
    id = models.AutoField(primary_key=True)
    sel = models.IntegerField()
    base = PositiveBigIntegerField()
    limit = PositiveBigIntegerField()
    type = models.CharField(max_length=64)
    dpl = models.IntegerField()
    gr = models.CharField(max_length=64)
    pr = models.CharField(max_length=64)
    snapshot = models.ForeignKey('Snapshot')

    class Meta:
        db_table = 'gdt'
        app_label = 'vortessence'


class Handle(models.Model):
    id = models.AutoField(primary_key=True)
    process = models.ForeignKey('Process')
    offset_type = models.CharField(max_length=32)
    handle_value = models.IntegerField()
    offset = PositiveBigIntegerField()
    handle_type = models.CharField(max_length=32)
    granted_access = PositiveBigIntegerField()
    handle_name = models.TextField()

    class Meta:
        db_table = 'handle'
        app_label = 'vortessence'


class Idt(models.Model):
    id = models.AutoField(primary_key=True)
    selector = models.IntegerField()
    value = PositiveBigIntegerField()
    module = models.CharField(max_length=64)
    section = models.CharField(max_length=64)
    snapshot = models.ForeignKey('Snapshot')

    class Meta:
        db_table = 'idt'
        app_label = 'vortessence'


class IrpCall(models.Model):
    id = models.AutoField(primary_key=True)
    start = PositiveBigIntegerField()
    name = models.CharField(max_length=128)
    base_dll_name = models.CharField(max_length=128)
    content = models.TextField()
    driver = models.ForeignKey(Driver)

    class Meta:
        db_table = 'irp_call'
        app_label = 'vortessence'


class Ldrmodule(models.Model):
    id = models.AutoField(primary_key=True)
    process = models.ForeignKey('Process', blank=True, null=True)
    dll = models.ForeignKey(Dll, blank=True, null=True)
    base = PositiveBigIntegerField(db_index=True)
    inload = models.IntegerField()
    ininit = models.IntegerField()
    inmem = models.IntegerField()
    mapped_path = models.CharField(max_length=255, db_index=True)
    init_path = models.CharField(max_length=255, db_index=True)
    mem_path = models.CharField(max_length=255, db_index=True)
    load_path = models.CharField(max_length=255, db_index=True)

    class Meta:
        db_table = 'ldrmodule'
        app_label = 'vortessence'


class Log(models.Model):
    id = models.AutoField(primary_key=True)
    level = models.CharField(max_length=200)
    message = models.TextField()
    timestamp = models.DateTimeField('timestamp', null=True, blank=True)
    snapshot = models.ForeignKey('Snapshot', blank=True, null=True)

    class Meta:
        db_table = 'log'
        app_label = 'vortessence'


class Malfind(models.Model):
    id = models.AutoField(primary_key=True)
    process = models.ForeignKey('Process')
    hex_output = models.TextField()
    disasm_output = models.TextField()
    vad = models.CharField(max_length=256)
    flags = models.CharField(max_length=256)
    protection = models.CharField(max_length=64)
    start_address = PositiveBigIntegerField(db_index=True)
    end_address = PositiveBigIntegerField()

    class Meta:
        db_table = 'malfind'
        app_label = 'vortessence'


class Modscan(models.Model):
    id = models.AutoField(primary_key=True)
    offset = PositiveBigIntegerField()
    name = models.CharField(max_length=256)
    base = PositiveBigIntegerField()
    size = PositiveBigIntegerField()
    file = models.CharField(max_length=256)
    snapshot = models.ForeignKey('Snapshot')

    class Meta:
        db_table = 'modscan'
        app_label = 'vortessence'


class Process(models.Model):
    id = models.AutoField(primary_key=True)
    pid = models.IntegerField(blank=True, null=True)
    ppid = models.IntegerField(blank=True, null=True)
    name = models.CharField(max_length=128, db_index=True)
    path = models.CharField(max_length=256, db_index=True)
    command_line = models.TextField()
    offset = PositiveBigIntegerField(db_index=True)
    creation_time = models.CharField(max_length=30)
    exit_time = models.CharField(max_length=30, null=True, blank=True)
    dlls = models.IntegerField(default=0)
    handles = models.BigIntegerField()
    threads = models.IntegerField()
    priority = models.IntegerField(default=0)
    parent = models.ForeignKey('self', blank=True, null=True)
    snapshot = models.ForeignKey('Snapshot')

    class Meta:
        db_table = 'process'
        app_label = 'vortessence'


class Profile(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=32)
    description = models.CharField(max_length=128)
    arch = models.CharField(max_length=8)

    class Meta:
        db_table = 'profile'
        app_label = 'vortessence'


class Registry(models.Model):
    id = models.AutoField(primary_key=True)
    key = models.CharField(max_length=1024)
    hive = models.CharField(max_length=1024)
    last_updated = models.CharField(max_length=64)
    subkeys = models.TextField()
    values = models.TextField()
    snapshot = models.ForeignKey('Snapshot')
    # is this a autostart
    autostart = models.BooleanField(default=False)

    class Meta:
        db_table = 'registry'
        app_label = 'vortessence'


class Snapshot(models.Model):
    id = models.AutoField(primary_key=True)
    os = models.CharField(max_length=64)
    hostname = models.CharField(max_length=256)
    date = models.DateTimeField()

    # 0 = processing pending
    # 1 = partially stored
    # 2 = stored
    # 3 = partially detected
    # 4 = detected
    # 5 = partially whitelisted
    # 6 = whitelisted
    status = models.IntegerField(default=0)
    description = models.TextField(blank=True)
    filename = models.CharField(blank=True, max_length=256)
    profile = models.ForeignKey('Profile')
    result_cache = models.BinaryField(blank=True, null=True)

    class Meta:
        db_table = 'snapshot'
        app_label = 'vortessence'


class Service(models.Model):
    id = models.AutoField(primary_key=True)
    offset = PositiveBigIntegerField()
    order = models.IntegerField()
    start = models.CharField(max_length=256, blank=True)
    process = models.ForeignKey(Process, blank=True, null=True)
    service_name = models.CharField(max_length=256, blank=True)
    display_name = models.CharField(max_length=256, blank=True)
    service_type = models.CharField(max_length=256)
    service_state = models.CharField(max_length=256)
    binary_path = models.CharField(max_length=1024, blank=True)
    service_dll = models.CharField(max_length=1024, blank=True, null=True)
    snapshot = models.ForeignKey(Snapshot, blank=True, null=True)

    class Meta:
        db_table = 'service'
        app_label = 'vortessence'


class Sid(models.Model):
    id = models.AutoField(primary_key=True)
    process_name = models.CharField(max_length=256)
    sid = models.CharField(max_length=128)
    name = models.CharField(max_length=128)
    process = models.ForeignKey(Process, blank=True, null=True)

    class Meta:
        db_table = 'sid'
        app_label = 'vortessence'


class Ssdt(models.Model):
    id = models.AutoField(primary_key=True)
    table = PositiveBigIntegerField()
    index = models.IntegerField()
    entry = models.IntegerField()
    offset = PositiveBigIntegerField()
    function_name = models.CharField(max_length=128)
    owner = models.CharField(max_length=128)
    snapshot = models.ForeignKey(Snapshot)

    class Meta:
        db_table = 'ssdt'
        app_label = 'vortessence'


class Thread(models.Model):
    id = models.AutoField(primary_key=True)
    ethread = PositiveBigIntegerField()
    process = models.ForeignKey(Process, blank=True, null=True)
    tid = PositiveBigIntegerField()
    tags = models.CharField(max_length=64, blank=True)
    created = models.CharField(max_length=64)
    exited = models.CharField(max_length=64)
    owning_process = models.CharField(max_length=64)
    attached_process = models.CharField(max_length=64)
    state = models.CharField(max_length=32)
    base_priority = models.IntegerField()
    priority = models.IntegerField()
    teb = PositiveBigIntegerField()
    start_address = PositiveBigIntegerField()
    service_table = PositiveBigIntegerField(null=True)
    win32_thread = PositiveBigIntegerField()
    cross_thread_flags = PositiveBigIntegerField()
    eip = models.TextField(blank=True)
    assembler = models.TextField(blank=True)
    snapshot = models.ForeignKey(Snapshot, blank=True, null=True)

    class Meta:
        db_table = 'thread'
        app_label = 'vortessence'


class Timer(models.Model):
    id = models.AutoField(primary_key=True)
    offset = PositiveBigIntegerField()
    due_time = models.CharField(max_length=64)
    period = models.CharField(max_length=64)
    signaled = models.CharField(max_length=16)
    routine = PositiveBigIntegerField()
    module = models.CharField(max_length=64)
    snapshot = models.ForeignKey(Snapshot)

    class Meta:
        db_table = 'timer'
        app_label = 'vortessence'


class UnloadedModules(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=128)
    start_address = PositiveBigIntegerField()
    end_address = PositiveBigIntegerField()
    time = models.CharField(max_length=64)
    snapshot = models.ForeignKey(Snapshot)

    class Meta:
        db_table = 'unloaded_modules'
        app_label = 'vortessence'


class Vad(models.Model):
    id = models.AutoField(primary_key=True)
    start = PositiveBigIntegerField()
    end = PositiveBigIntegerField()
    vad_type = models.CharField(max_length=64)
    protection = models.CharField(max_length=64)
    fileobject = models.CharField(max_length=512)
    process = models.ForeignKey(Process)

    class Meta:
        db_table = 'vad'
        app_label = 'vortessence'


class Verinfo(models.Model):
    id = models.AutoField(primary_key=True)
    module = models.CharField(max_length=512, blank=True, null=True)
    file_version = models.CharField(max_length=512, blank=True, null=True)
    product_version = models.CharField(max_length=512, blank=True, null=True)
    flags = models.CharField(max_length=256, blank=True, null=True)
    os = models.CharField(max_length=256, blank=True, null=True)
    file_type = models.CharField(max_length=256, blank=True, null=True)
    file_date = models.CharField(max_length=256, blank=True, null=True)
    info_string = models.TextField(blank=True, null=True)
    process = models.ForeignKey(Process, null=True)
    dll = models.ForeignKey(Dll, null=True)
    snapshot = models.ForeignKey(Snapshot)

    class Meta:
        db_table = 'verinfo'
        app_label = 'vortessence'


class WlApihook(models.Model):
    id = models.AutoField(primary_key=True)
    wl_process = models.ForeignKey('WlProcess', blank=True, null=True)
    dll_path = models.CharField(max_length=1000)
    address = models.CharField(max_length=32)
    function = models.CharField(max_length=500)

    class Meta:
        db_table = 'wl_apihook'
        app_label = 'vortessence'


class WlCallback(models.Model):
    id = models.AutoField(primary_key=True)
    type = models.CharField(max_length=128)
    module = models.CharField(max_length=128)
    details = models.CharField(max_length=256)
    profile = models.ForeignKey('Profile')

    class Meta:
        db_table = 'wl_callback'
        app_label = 'vortessence'


class WlCommandline(models.Model):
    id = models.AutoField(primary_key=True)
    wl_process = models.ForeignKey('WlProcess')
    cl = models.TextField(blank=True)
    cl_regex = models.CharField(max_length=500, blank=True, null=True)

    class Meta:
        db_table = 'wl_commandline'
        app_label = 'vortessence'


class WlConnection(models.Model):
    id = models.AutoField(primary_key=True)
    wl_process = models.ForeignKey('WlProcess')
    source_port = models.IntegerField()
    destination_ip = models.CharField(max_length=128, blank=True)
    destination_port = models.IntegerField(blank=True, null=True)
    protocol = models.CharField(max_length=16)
    state = models.CharField(max_length=16, blank=True)

    class Meta:
        db_table = 'wl_connection'
        app_label = 'vortessence'


class WlDll(models.Model):
    id = models.AutoField(primary_key=True)
    path = models.CharField(max_length=1024)
    size = PositiveBigIntegerField()
    load_count_from = models.IntegerField()
    load_count_to = models.IntegerField()
    wl_process = models.ForeignKey('WlProcess')

    class Meta:
        db_table = 'wl_dll'
        app_label = 'vortessence'


class WlDevice(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=128)
    type = models.CharField(max_length=128)
    is_attached = models.CharField(max_length=8)
    driver = models.CharField(max_length=128)
    wl_driver = models.ForeignKey('WlDriver')

    class Meta:
        db_table = 'wl_device'
        app_label = 'vortessence'


class WlDriver(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=64)
    profile = models.ForeignKey('Profile')

    class Meta:
        db_table = 'wl_driver'
        app_label = 'vortessence'


class WlFile(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=512)
    profile = models.ForeignKey('Profile', blank=True, null=True)

    class Meta:
        db_table = 'wl_file'
        app_label = 'vortessence'


class WlLdrmodule(models.Model):
    id = models.AutoField(primary_key=True)
    wl_process = models.ForeignKey('WlProcess', blank=True, null=True)
    mapped_path = models.CharField(max_length=500)
    inload = models.IntegerField()
    ininit = models.IntegerField()
    inmem = models.IntegerField()
    init_path = models.CharField(max_length=256)
    mem_path = models.CharField(max_length=256)
    load_path = models.CharField(max_length=256)

    class Meta:
        db_table = 'wl_ldrmodule'
        app_label = 'vortessence'


class WlGdt(models.Model):
    id = models.AutoField(primary_key=True)
    type = models.CharField(max_length=64)
    profile = models.ForeignKey('Profile')

    class Meta:
        db_table = 'wl_gdt'
        app_label = 'vortessence'


class WlHandle(models.Model):
    id = models.AutoField(primary_key=True)
    wl_process = models.ForeignKey('WlProcess')
    granted_access = PositiveBigIntegerField()
    handle_type = models.CharField(max_length=32)
    handle_name = models.CharField(max_length=1000)

    class Meta:
        db_table = 'wl_handle'
        app_label = 'vortessence'


class WlIdt(models.Model):
    id = models.AutoField(primary_key=True)
    module = models.CharField(max_length=64)
    section = models.CharField(max_length=64)
    profile = models.ForeignKey('Profile')

    class Meta:
        db_table = 'wl_idt'
        app_label = 'vortessence'


class WlIrpCall(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=128)
    content_hash = models.CharField(max_length=128)
    wl_driver = models.ForeignKey(WlDriver)

    class Meta:
        db_table = 'wl_irp_call'
        app_label = 'vortessence'


class WlModscan(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=256)
    file = models.CharField(max_length=256)
    size = PositiveBigIntegerField()
    profile = models.ForeignKey('Profile')

    class Meta:
        db_table = 'wl_modscan'
        app_label = 'vortessence'


class WlParent(models.Model):
    id = models.AutoField(primary_key=True)
    wl_process = models.ForeignKey('WlProcess')
    wl_process_parent = models.ForeignKey('WlProcess', null=True, related_name='wl_process_parent_k')

    class Meta:
        db_table = 'wl_parent'
        app_label = 'vortessence'


class WlPrio(models.Model):
    id = models.AutoField(primary_key=True)
    wl_process = models.ForeignKey('WlProcess')
    prio = models.IntegerField()

    class Meta:
        db_table = 'wl_prio'
        app_label = 'vortessence'


class WlProcess(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=128)
    path = models.CharField(max_length=256, blank=True)
    nr = models.IntegerField()
    dll_min = models.IntegerField()
    dll_max = models.IntegerField()
    thread_min = models.IntegerField()
    thread_max = models.IntegerField()
    network = models.IntegerField()
    profile = models.ForeignKey('Profile')

    class Meta:
        db_table = 'wl_process'
        app_label = 'vortessence'


class WlRegistry(models.Model):
    id = models.AutoField(primary_key=True)
    key = models.CharField(max_length=1024)
    hive = models.CharField(max_length=1024)
    subkeys = models.TextField()
    values = models.TextField()
    profile = models.ForeignKey('Profile')
    # is this a autostart entry
    autostart = models.BooleanField(default=False)

    class Meta:
        db_table = 'wl_registry'
        app_label = 'vortessence'


class WlService(models.Model):
    id = models.AutoField(primary_key=True)
    wl_process = models.ForeignKey(WlProcess, blank=True, null=True)
    name = models.CharField(max_length=256, blank=True)
    type = models.CharField(max_length=256)
    binary_path = models.CharField(max_length=1024, blank=True)
    dll = models.CharField(max_length=1024, blank=True, null=True)
    profile = models.ForeignKey('Profile')

    class Meta:
        db_table = 'wl_service'
        app_label = 'vortessence'


class WlSid(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    wl_process = models.ForeignKey(WlProcess)

    class Meta:
        db_table = 'wl_sid'
        app_label = 'vortessence'


class WlSsdt(models.Model):
    id = models.AutoField(primary_key=True)
    function = models.CharField(max_length=128)
    owner = models.CharField(max_length=128)
    profile = models.ForeignKey('Profile')

    class Meta:
        db_table = 'wl_ssdt'
        app_label = 'vortessence'
        unique_together = ["function", "owner", "profile"]


class WlTimer(models.Model):
    id = models.AutoField(primary_key=True)
    module = models.CharField(max_length=64)
    profile = models.ForeignKey('Profile')

    class Meta:
        db_table = 'wl_timer'
        app_label = 'vortessence'


class WlUnloadedModules(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=128)
    profile = models.ForeignKey('Profile')

    class Meta:
        db_table = 'wl_unloaded_modules'
        app_label = 'vortessence'


class WlVad(models.Model):
    id = models.AutoField(primary_key=True)
    size = models.IntegerField()
    min = models.IntegerField()
    max = models.IntegerField()
    wl_process = models.ForeignKey('WlProcess')

    class Meta:
        db_table = 'wl_vad'
        app_label = 'vortessence'
