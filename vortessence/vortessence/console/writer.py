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

from tabulate import tabulate

from vortessence.utils import Base
from vortessence.models import *


class SnapshotWriter(Base):
    snapshot = None

    def __init__(self, snapshot_id=None):
        if snapshot_id is not None:
            try:
                snapshot = Snapshot.objects.get(pk=snapshot_id)
                self.snapshot = snapshot
            except Snapshot.DoesNotExist:
                print "Image {} does not exist".format(snapshot_id)
                exit()

    def list_snapshots(self):
        table = []
        headers = ["Image ID", "Hostname", "OS", "Date", "File", "Description"]
        for snapshot in Snapshot.objects.all():
            line = [str(snapshot.id), snapshot.hostname, snapshot.os, snapshot.date, snapshot.filename,
                    snapshot.description[0:30]]
            table.append(line)
        print tabulate(table, headers=headers) if table else "No results found"

    def print_apihooks(self, apihooks, anomalies_only):
        for apihook in apihooks:
            if anomalies_only or apihook.detapihook_set.exists():
                print "*" * 31, "ANOMALY", "*" * 31
            else:
                print "*" * 72
            print "Hook mode: {}".format(apihook.hook_mode)
            print "Hook type: {}".format(apihook.hook_type)
            print "Process: {0} ({1})".format(apihook.process.pid, apihook.process.name)
            print "Victim module: {0} ({1} - {2})".format(apihook.dll.path.split("\\")[-1],
                                                          self.format_value(apihook.dll.base, '[addrpad]',
                                                                            self.snapshot.profile.name),
                                                          self.format_value(apihook.dll.base + apihook.dll.size,
                                                                            '[addrpad]', self.snapshot.profile.name))
            print "Function: {}".format(apihook.function)
            print "Hook address: {}".format(self.format_value(apihook.hook_address, '[addrpad]',
                                                              self.snapshot.profile.name))
            print "Hooking module: {}\n".format(apihook.hooking_module)
            for line in apihook.disassembly.split("\n"):
                terms = line.split("\t")
                if len(terms) < 3:
                    print line
                else:
                    address, optcode, instruction = terms
                    print "{0} {1:<16} {2}".format(address, optcode, instruction)
        if not len(apihooks):
            print "No results found"

    def get_apihook_results(self, anomalies_only, process_filter):
        apihooks = []
        for process in Process.objects.filter(snapshot=self.snapshot):
            if not process_filter or process == process_filter:
                for apihook in Apihook.objects.filter(process=process):
                    if anomalies_only:
                        if apihook.detapihook_set.exists():
                            apihooks.append(apihook)
                    else:
                        apihooks.append(apihook)

        self.print_apihooks(apihooks, anomalies_only)

    def print_callback_results(self, anomalies_only):
        callbacks = []
        for callback in Callback.objects.filter(snapshot=self.snapshot):
            if anomalies_only:
                if callback.detcallback_set.exists():
                    callbacks.append(callback)
            else:
                callbacks.append(callback)
        table = []
        headers = ["Anomaly", "Type", "Callback", "Module", "Details"]
        for callback in callbacks:
            line = ["Yes" if anomalies_only or callback.detcallback_set.exists() else "No",
                    callback.type,
                    self.format_value(callback.callback, '[addrpad]', self.snapshot.profile.name),
                    callback.module,
                    callback.details]
            table.append(line)
        print tabulate(table, headers=headers) if table else "No results found"

    def print_dlls(self, dlls, anomalies_only):
        table = []
        headers = ["Anomaly", "PID", "Process", "DLL", "Base", "Size", "Load count", "Anomaly type"]
        for dll in dlls:
            anomaly_type = ""
            if anomalies_only or dll.detdll_set.exists():
                det_dll = dll.detdll_set.first()
                if det_dll.unknown_overall:
                    anomaly_type = "? Overall"
                elif det_dll.unknown_for_process:
                    anomaly_type = "? Process"
                elif det_dll.unknown_load_count:
                    anomaly_type = "Load count"
            line = ["No" if anomaly_type == "" else "Yes",
                    str(dll.process.pid), dll.process.name, dll.path.split("\\")[-1],
                    self.format_value(dll.base, '[addrpad]', self.snapshot.profile.name),
                    self.format_value(dll.size, '[addr]', self.snapshot.profile.name),
                    self.format_value(dll.load_count, '[addr]', self.snapshot.profile.name),
                    anomaly_type]
            table.append(line)
        print tabulate(table, headers=headers) if table else "No results found"

    def get_dll_results(self, anomalies_only, process_filter):
        dlls = []
        for process in Process.objects.filter(snapshot=self.snapshot):
            if not process_filter or process == process_filter:
                for dll in Dll.objects.filter(process=process):
                    if anomalies_only:
                        if dll.detdll_set.exists():
                            dlls.append(dll)
                    else:
                        dlls.append(dll)

        self.print_dlls(dlls, anomalies_only)

    def print_handles(self, handles, anomalies_only):
        table = []
        headers = ["Anomaly", "Pid", "Handle", "Access", "Type", "Details"]
        for handle in handles:
            line = [
                "Yes" if anomalies_only or handle.dethandle_set.exists() else "No",
                handle.process.pid,
                self.format_value(handle.handle_value, '[addr]'),
                self.format_value(handle.granted_access, '[addr]'),
                handle.handle_type,
                handle.handle_name
            ]
            table.append(line)
        print tabulate(table, headers=headers) if table else "No results found"

    def get_handle_results(self, anomalies_only, process_filter):
        handles = []
        for process in Process.objects.filter(snapshot=self.snapshot):
            if not process_filter or process == process_filter:
                for handle in Handle.objects.filter(process=process):
                    if anomalies_only:
                        if handle.dethandle_set.exists():
                            handles.append(handle)
                    else:
                        handles.append(handle)
        self.print_handles(handles, anomalies_only)

    def print_devicetree_results(self, anomalies_only):
        drivers = []
        for driver in Driver.objects.filter(snapshot=self.snapshot):
            if anomalies_only:
                if driver.detdriver_set.exists():
                    drivers.append(driver)
            else:
                drivers.append(driver)
        for driver in drivers:
            if anomalies_only or driver.detdriver_set.exists():
                print "ANOMALY ",
            else:
                print "OK      ",
            print "DRV {0} {1}".format(self.format_value(driver.start, '[addrpad]', self.snapshot.profile.name),
                                       driver.name)
            for device in Device.objects.filter(driver=driver).order_by('id'):
                print "{0}---{1}| {2} {3} {4} {5}".format(
                    "ANOMALY " if device.detdevice_set.exists() else "OK      ",
                    (device.level + 1) * "---",
                    "ATT" if device.parent_device else "DEV",
                    self.format_value(device.offset, '[addrpad]', self.snapshot.profile.name),
                    device.name,
                    device.type
                )

    def print_driverirp_results(self, anomalies_only):
        drivers = []
        for driver in Driver.objects.filter(snapshot=self.snapshot):
            if anomalies_only:
                if driver.detdriver_set.exists():
                    det_driver = driver.detdriver_set.first()
                    if det_driver.detirpcall_set.exists():
                        drivers.append(driver)
            else:
                drivers.append(driver)
        for driver in drivers:
            if anomalies_only or driver.detdriver_set.exists():
                print "---------------------ANOMALY----------------------"
            else:
                print "--------------------------------------------------"
            print "DriverName: {}".format(driver.name)
            print "DriverStart: {}".format(self.format_value(driver.start, '[addrpad]', self.snapshot.profile.name))
            print "DriverSize: {}".format(self.format_value(driver.size, '[addr]', self.snapshot.profile.name))
            print "DriverStartIo: {}".format(self.format_value(driver.start_io, '[addr]', self.snapshot.profile.name))
            count = 0
            table = []
            for irpcall in driver.irpcall_set.all():
                table.append(["Yes" if anomalies_only or irpcall.detirpcall_set.exists() else "No",
                              count,
                              irpcall.name,
                              self.format_value(irpcall.start, '[addrpad]', self.snapshot.profile.name),
                              irpcall.base_dll_name])
                count = + 1
            print tabulate(table)

    def print_file_results(self, anomalies_only):
        table = []
        headers = ["Anomaly", "Offset", "#Ptr", "#Hnd", "Access", "Name"]
        files = []
        if anomalies_only:
            for det_file in DetFile.objects.filter(snapshot=self.snapshot):
                files.append(det_file.filescan)
        else:
            for file in Filescan.objects.filter(snapshot=self.snapshot):
                files.append(file)

        for file in files:
            table.append(["Yes" if anomalies_only or file.detfile_set.exists() else "No",
                          self.format_value(file.offset, '[addrpad]', self.snapshot.profile.name),
                          str(file.pointers), str(file.handles),
                          file.access, file.name])
        print tabulate(table, headers=headers) if table else "No results found"

    def print_gdt_results(self, anomalies_only):
        table = []
        headers = ["Anomaly", "Sel", "Base", "Limit", "Type", "DPL", "Gr", "Pr"]
        gdts = []
        if anomalies_only:
            for det_gdt in DetGdt.objects.filter(snapshot=self.snapshot):
                gdts.append(det_gdt.gdt)
        else:
            for gdt in Gdt.objects.filter(snapshot=self.snapshot):
                gdts.append(gdt)
        for gdt in gdts:
            table.append(["Yes" if anomalies_only or gdt.detgdt_set.exists() else "No",
                          self.format_value(gdt.sel, '[addr]', self.snapshot.profile.name),
                          self.format_value(gdt.base, '[addrpad]', self.snapshot.profile.name),
                          self.format_value(gdt.limit, '[addrpad]', self.snapshot.profile.name),
                          gdt.dpl, gdt.gr, gdt.pr])
        print tabulate(table, headers=headers) if table else "No results found"

    def print_idt_results(self, anomalies_only):
        table = []
        headers = ["Anomaly", "Selector", "Value", "Module", "Section"]
        idts = []
        if anomalies_only:
            for det_idt in DetIdt.objects.filter(snapshot=self.snapshot):
                idts.append(det_idt.idt)
        else:
            for idt in Idt.objects.filter(snapshot=self.snapshot):
                idts.append(idt)
        for idt in idts:
            table.append(["Yes" if anomalies_only or idt.detidt_set.exists() else "No",
                          self.format_value(idt.selector, '[addr]', self.snapshot.profile.name),
                          self.format_value(idt.value, '[addrpad]', self.snapshot.profile.name),
                          idt.module, idt.section])
        print tabulate(table, headers=headers) if table else "No results found"

    def print_ldrmodules(self, ldrmodules, anomalies_only):
        table = []
        headers = ["Anomaly", "Pid", "Process", "Base", "InLoad", "InInit", "InMem", "MappedPath"]
        for ldrmodule in ldrmodules:
            table.append(["Yes" if anomalies_only or ldrmodule.detldrmodule_set.exists() else "No",
                          str(ldrmodule.process.pid), ldrmodule.process.name,
                          self.format_value(ldrmodule.base, '[addrpad]', self.snapshot.profile.name),
                          "True" if ldrmodule.inload else "False",
                          "True" if ldrmodule.ininit else "False",
                          "True" if ldrmodule.inmem else "False",
                          ldrmodule.mapped_path])
            if ldrmodule.load_path:
                table.append(["", "", "Load Path:", "", "", "", "", ldrmodule.load_path])
            if ldrmodule.init_path:
                table.append(["", "", "Init Path", "", "", "", "", ldrmodule.init_path])
            if ldrmodule.mem_path:
                table.append(["", "", "Mem Path", "", "", "", "", ldrmodule.mem_path])
        print tabulate(table, headers=headers) if table else "No results found"

    def get_ldrmodule_results(self, anomalies_only, process_filter):

        ldrmodules = []
        for process in Process.objects.filter(snapshot=self.snapshot):
            if not process_filter or process_filter == process:
                if anomalies_only:
                    for det_ldrmodule in DetLdrmodule.objects.filter(process=process):
                        ldrmodules.append(det_ldrmodule.ldrmodule)
                else:
                    for ldrmodule in Ldrmodule.objects.filter(process=process):
                        ldrmodules.append(ldrmodule)
        self.print_ldrmodules(ldrmodules, anomalies_only)

    def get_malfind_results(self, anomalies_only, process_filter):
        for process in Process.objects.filter(snapshot=self.snapshot):
            if not process_filter or process_filter == process:
                malfinds = []
                for mf in Malfind.objects.filter(process=process):
                    if anomalies_only:
                        if mf.detmalfind_set.first().is_true_positive:
                            malfinds.append(mf)
                    else:
                        malfinds.append(mf)
                self.print_malfind(malfinds)

    def print_modules(self, anomalies_only):
        table = []
        headers = ["Anomaly", "Offset(P)", "Name", "Base", "Size", "File"]
        modules = []
        for module in Modscan.objects.filter(snapshot=self.snapshot):
            if anomalies_only:
                if module.detmodscan_set.exists():
                    modules.append(module)
            else:
                modules.append(module)

        for module in modules:
            table.append(["Yes" if anomalies_only or module.detmodscan_set.exists() else "No",
                          self.format_value(module.offset, '[addrpad]', self.snapshot.profile.name),
                          module.name,
                          self.format_value(module.base, '[addrpad]', self.snapshot.profile.name),
                          self.format_value(module.size, '[addr]', self.snapshot.profile.name),
                          module.file])
        print tabulate(table, headers=headers) if table else "No results found"

    def get_process_results(self, anomalies_only):
        processes = []
        anomaly_processes = []
        for process in Process.objects.filter(snapshot=self.snapshot):
            has_anomaly = process.detldrmodule_set.exists() or process.detapihook_set.exists() \
                              or process.detdll_set.exists() or process.detmalfind_set.filter(
                is_true_positive=1).exists() or process.detldrmodule_set.exists() \
                              or process.detsid_set.exists() or process.detthread_set.exists() \
                              or process.detprocess_set.exists() or process.dethandle_set.exists()
            if anomalies_only:
                if has_anomaly:
                    anomaly_processes.append(process)
                    processes.append(process)
            else:
                processes.append(process)
                if has_anomaly:
                    anomaly_processes.append(process)

        table = []
        headers = ["Anomaly", "PID", "Name", "Offset", "Parent", "Known", "#", "#Thrds",
                   "#DLLs", "NW", "CL", "Par", "DLLs", "Hndls", "SID", "Hooks", "MF", "LDR", "Prio"]
        for process in processes:
            try:
                det_process = process.detprocess_set.first()
            except DetProcess.DoesNotExist:
                det_process = None
            det_dll = DetDll.objects.filter(process=process).count()
            det_handle = DetHandle.objects.filter(process=process).count()
            det_sid = DetSid.objects.filter(process=process).count()
            det_apihook = DetApihook.objects.filter(process=process).count()
            det_malfind = DetMalfind.objects.filter(process=process, is_true_positive=1).count()
            det_ldrmodule = DetLdrmodule.objects.filter(process=process).count()
            det_thread = DetThread.objects.filter(process=process).first().base_priority if DetThread.objects.filter(
                process=process).exists() else None
            line = ["Yes" if process in anomaly_processes else "No",
                    str(process.pid), process.name,
                    self.format_value(process.offset, '[addrpad]', self.snapshot.profile.name),
                    "{0} ({1})".format(process.parent.name, process.parent.pid) if process.parent else "None",
                    "NOK" if det_process and det_process.unknown_process else "OK",
                    str(
                        det_process.unknown_number_of_the_same) if det_process and det_process.unknown_number_of_the_same else "OK",
                    str(
                        det_process.unknown_number_of_threads) if det_process and det_process.unknown_number_of_threads else "OK",
                    "NOK" if det_process and det_process.unknown_number_of_dlls else "OK",
                    "NOK" if det_process and det_process.network_anomaly else "OK",
                    "NOK" if det_process and det_process.unknown_command_line else "OK",
                    "NOK" if det_process and det_process.unknown_parent else "OK",
                    str(det_dll) if det_dll else "OK",
                    str(det_handle) if det_handle else "OK",
                    str(det_sid) if det_sid else "OK",
                    str(det_apihook) if det_apihook else "OK",
                    str(det_malfind) if det_malfind else "OK",
                    str(det_ldrmodule) if det_ldrmodule else "OK",
                    str(det_thread) if det_thread else "OK"]
            table.append(line)
        print tabulate(table, headers=headers, numalign='decimal') if table else "No results found"

    def print_registry_results(self, anomalies_only):
        reg_keys = []
        if anomalies_only:
            for det_registry in DetRegistry.objects.filter(snapshot=self.snapshot):
                reg_keys.append(det_registry.registry)
        else:
            for registry in Registry.objects.filter(snapshot=self.snapshot):
                reg_keys.append(registry)
        for registry in reg_keys:
            print "Anomaly: {}".format("Yes" if anomalies_only or registry.detregistry_set.exists() else "No")
            print "Hive: {}".format(registry.hive)
            print "Key name: {}".format(registry.key)
            print "Last updated: {}".format(registry.last_updated)
            # is this an autostart entry
            print "Autostart Entry: {}".format(registry.autostart)
            print "Subkeys: \n{}".format(registry.subkeys)
            print "Values: \n{}".format(registry.values)
            print "----------------------------------------------------------------------\n\n"

    def print_service_results(self, anomalies_only):
        services = []
        if anomalies_only:
            for det_service in DetService.objects.filter(snapshot=self.snapshot):
                services.append(det_service.service)
        else:
            for service in Service.objects.filter(snapshot=self.snapshot):
                services.append(service)

        for service in services:
            print "Anomaly: {}".format("Yes" if anomalies_only or service.detservice_set.exists() else "No")
            print "Offset: {}".format(self.format_value(service.offset, '[addrpad]', self.snapshot.profile.name))
            print "Order: {}".format(service.order)
            print "Process ID: {}".format(service.process.pid if service.process else "-")
            print "Service Name: {}".format(service.service_name)
            print "Display Name: {}".format(service.display_name)
            print "Service Type: {}".format(service.service_type)
            print "Service State: {}".format(service.service_state)
            print "Binary Path: {}".format(service.binary_path if service.binary_path else "-")
            if service.service_dll:
                print "ServiceDll: {}\n".format(service.service_dll)
            print "\n"

    def print_sid_results(self, anomalies_only, process_filter):
        sids = []
        for process in Process.objects.filter(snapshot=self.snapshot):
            if not process_filter or process_filter == process:
                for sid in Sid.objects.filter(process=process):
                    if anomalies_only:
                        if sid.detsid_set.exists():
                            sids.append(sid)
                    else:
                        sids.append(sid)

        for sid in sids:
            print "{} {} ({}): {} ({})".format("Anomaly!" if anomalies_only or sid.detsid_set.exists() else "OK",
                                               sid.process_name, sid.process.pid,
                                               sid.sid, sid.name)

        if not sids:
            print "No results found"

    def print_ssdt_results(self, anomalies_only):
        table = []
        headers = ["Anomaly", "Table", "Index", "Addr", "Function", "Owner"]
        ssdts = []
        for ssdt in Ssdt.objects.filter(snapshot=self.snapshot):
            if anomalies_only:
                if ssdt.detssdt_set.exists():
                    ssdts.append(ssdt)
            else:
                ssdts.append(ssdt)

        for ssdt in ssdts:
            table.append(
                ["Yes" if anomalies_only or ssdt.detssdt_set.exists() else "No",
                 self.format_value(ssdt.table, '[addrpad]', self.snapshot.profile.name),
                 ssdt.index, self.format_value(ssdt.offset, '[addrpad]', self.snapshot.profile.name),
                 ssdt.function_name,
                 ssdt.owner])
        print tabulate(table, headers=headers) if table else "No results found"

    def print_thread_results(self, anomalies_only, process_filter):
        table = []
        headers = ["Anomaly", "Process", "Pid", "Tid", "Ethread", "Prio", "Expected"]
        threads = []
        for process in Process.objects.filter(snapshot=self.snapshot):
            if not process_filter or process_filter == process:
                for thread in Thread.objects.filter(process=process):
                    if anomalies_only:
                        if thread.detthread_set.exists():
                            threads.append(thread)
                    else:
                        threads.append(thread)
        for thread in threads:
            # get whitelist values for this process
            expected_prios = ""
            wl_process = WlProcess.objects.filter(path=thread.process.path).first()
            if wl_process:
                for wl_prio in WlPrio.objects.filter(wl_process=wl_process):
                    expected_prios += str(wl_prio.prio) + " "
            else:
                expected_prios = "n/a"
            table.append(["Yes" if anomalies_only or thread.detthread_set.exists() else "No",
                          thread.process.name, thread.process.pid, thread.tid,
                          self.format_value(thread.ethread, '[addrpad]', self.snapshot.profile.name),
                          str(thread.base_priority), expected_prios])
        print tabulate(table, headers=headers) if table else "No results found"

    def print_timer_results(self, anomalies_only):
        table = []
        headers = ["Anomaly", "Offset(V)", "DueTime", "Period(ms)", "Signaled", "Routine", "Module"]
        timers = []
        for timer in Timer.objects.filter(snapshot=self.snapshot):
            if anomalies_only:
                if timer.dettimer_set.exists():
                    timers.append(timer)
            else:
                timers.append(timer)

        for timer in timers:
            table.append(["Yes" if anomalies_only or timer.dettimer_set.exists() else "No",
                          self.format_value(timer.offset, '[addrpad]', self.snapshot.profile.name),
                          timer.due_time, timer.period,
                          timer.signaled, timer.routine, timer.module])
        print tabulate(table, headers=headers) if table else "No results found"

    def print_unloaded_modules_results(self, anomalies_only):
        table = []
        headers = ["Anomaly", "Name", "StartAddress", "EndAddress", "Time"]
        unloaded_modules = []
        for um in UnloadedModules.objects.filter(snapshot=self.snapshot):
            if anomalies_only:
                if um.detunloadedmodules_set.exists():
                    unloaded_modules.append(um)
            else:
                unloaded_modules.append(um)

        for unloaded_module in unloaded_modules:
            table.append(["Yes" if anomalies_only or unloaded_module.detunloadedmodules_set.exists() else "No",
                          unloaded_module.name,
                          self.format_value(unloaded_module.start_address, '[addrpad]',
                                            self.snapshot.profile.name),
                          self.format_value(unloaded_module.end_address, '[addrpad]',
                                            self.snapshot.profile.name),
                          unloaded_module.time])
        print tabulate(table, headers=headers) if table else "No results found"

    def get_netscan_results(self, anomalies_only):
        connections = []
        anomaly_connections = []
        for conn in Connection.objects.filter(snapshot=self.snapshot):
            has_anomaly = conn.detconnection_set.exists()
            if anomalies_only:
                if has_anomaly:
                    anomaly_connections.append(conn)
                    connections.append(conn)
            else:
                connections.append(conn)
                if has_anomaly:
                    anomaly_connections.append(conn)

        table = []
        headers = ["Anomaly", "Source Port", "Dest. IP", "Dest. Port", "Protocol", "State", "Time created", "PID",
                   "Process"]

        for connection in connections:
            line = ["Yes" if connection in anomaly_connections else "No",
                    str(connection.source_port),
                    connection.destination_ip,
                    str(connection.destination_port),
                    connection.protocol,
                    connection.state,
                    connection.time_created,
                    str(connection.process.pid) if connection.process else "-",
                    connection.process.name if connection.process else "-"]
            table.append(line)
        print tabulate(table, headers=headers, numalign='decimal') if table else "No results found"

    def print_results(self, plugin, anomalies_only, process_pid):
        if process_pid:
            try:
                process = Process.objects.get(snapshot=self.snapshot, pid=process_pid)
            except Process.DoesNotExist:
                print "Error: Process with PID {} does not exist".format(process_pid)
                exit(-1)
        else:
            process = None

        if not plugin:
            # print plugins containing anomalies
            print "Process summary of image", self.snapshot.id
            self.get_process_results(anomalies_only)

            print "\nSystem summary of image", self.snapshot.id
            table = []
            headers = ["Plugin", "# of anomalies"]
            table.append(["modules", DetModscan.objects.filter(snapshot=self.snapshot).count()])
            table.append(["drivers", DetDriver.objects.filter(snapshot=self.snapshot).count()])
            table.append(["callbacks", DetCallback.objects.filter(snapshot=self.snapshot).count()])
            table.append(["filescan", DetFile.objects.filter(snapshot=self.snapshot).count()])
            table.append(["gdt", DetGdt.objects.filter(snapshot=self.snapshot).count()])
            table.append(["idt", DetIdt.objects.filter(snapshot=self.snapshot).count()])
            table.append(["netscan", DetConnection.objects.filter(snapshot=self.snapshot).count()])
            table.append(["registry", DetRegistry.objects.filter(snapshot=self.snapshot).count()])
            table.append(["svcscan", DetService.objects.filter(snapshot=self.snapshot).count()])
            table.append(["ssdt", DetSsdt.objects.filter(snapshot=self.snapshot).count()])
            table.append(["timers", DetTimer.objects.filter(snapshot=self.snapshot).count()])
            table.append(["unloaded_modules", DetUnloadedModules.objects.filter(snapshot=self.snapshot).count()])
            print tabulate(table, headers=headers, tablefmt="grid")

        elif plugin.lower().startswith("apihook"):
            self.get_apihook_results(anomalies_only, process)
        elif plugin.lower().startswith("callback"):
            self.print_callback_results(anomalies_only)
        elif plugin.lower().startswith("dll"):
            self.get_dll_results(anomalies_only, process)
        elif plugin.lower().startswith("devicetree"):
            self.print_devicetree_results(anomalies_only)
        elif plugin.lower().startswith("driver"):
            self.print_driverirp_results(anomalies_only)
        elif plugin.lower().startswith("file"):
            self.print_file_results(anomalies_only)
        elif plugin.lower().startswith("gdt"):
            self.print_gdt_results(anomalies_only)
        elif plugin.lower().startswith("handle"):
            self.get_handle_results(anomalies_only, process)
        elif plugin.lower().startswith("idt"):
            self.print_idt_results(anomalies_only)
        elif plugin.lower().startswith("ldr"):
            self.get_ldrmodule_results(anomalies_only, process)
        elif plugin.lower().startswith("malfind"):
            self.get_malfind_results(anomalies_only, process)
        elif plugin.lower().startswith("mod"):
            self.print_modules(anomalies_only)
        elif plugin.lower().startswith("netscan"):
            self.get_netscan_results(anomalies_only)
        elif plugin.lower() == "pslist":
            self.get_process_results(anomalies_only)
        elif plugin.lower().startswith("reg"):
            self.print_registry_results(anomalies_only)
        elif plugin.lower().startswith("svc"):
            self.print_service_results(anomalies_only)
        elif plugin.lower().startswith("sid"):
            self.print_sid_results(anomalies_only, process)
        elif plugin.lower().startswith("ssdt"):
            self.print_ssdt_results(anomalies_only)
        elif plugin.lower().startswith("thread"):
            self.print_thread_results(anomalies_only, process)
        elif plugin.lower().startswith("timer"):
            self.print_timer_results(anomalies_only)
        elif plugin.lower().startswith("unloaded"):
            self.print_unloaded_modules_results(anomalies_only)
        else:
            print "Unknown plugin \"{}\"".format(plugin)

    def search(self, search_string, anomalies_only):
        search_string = search_string.strip().lower()
        search_address = long(search_string, 16) if search_string.startswith("0x") else False
        results = {"dlls": [],
                   "ldrmodules": [],
                   "malfinds": [],
                   "apihooks": []}

        for process in Process.objects.filter(snapshot=self.snapshot):
            for dll in Dll.objects.filter(process=process):
                if search_address:
                    if dll.base == search_address:
                        results['dlls'].append(dll)
                else:
                    if dll.path.lower().find(search_string) != -1:
                        results['dlls'].append(dll)

            for ldrmodule in Ldrmodule.objects.filter(process=process):
                if search_address:
                    if ldrmodule.base == search_address:
                        results['ldrmodules'].append(ldrmodule)
                else:
                    if ldrmodule.mapped_path.lower().find(search_string) != -1:
                        results['ldrmodules'].append(ldrmodule)
                    elif ldrmodule.load_path.lower().find(search_string) != -1:
                        results['ldrmodules'].append(ldrmodule)
                    elif ldrmodule.init_path.lower().find(search_string) != -1:
                        results['ldrmodules'].append(ldrmodule)
                    elif ldrmodule.mem_path.lower().find(search_string) != -1:
                        results['ldrmodules'].append(ldrmodule)

            for malfind in Malfind.objects.filter(process=process):
                if search_address:
                    if malfind.start_address == search_address:
                        results['malfinds'].append(malfind)
                else:
                    if malfind.hex_output.lower().find(search_string) != -1:
                        results['malfinds'].append(malfind)

            for apihook in Apihook.objects.filter(process=process):
                if search_address:
                    if apihook.hook_address == search_address:
                        results['apihooks'].append(apihook)
                else:
                    if apihook.function.lower().find(search_string) != -1 or \
                                    apihook.hooking_module.lower().find(search_string) != -1 or \
                                    apihook.dll.path.lower().find(search_string) != -1:
                        results['apihooks'].append(apihook)
        print "*************************************************************************"
        print "*****   DLLs:"
        print "*************************************************************************"
        self.print_dlls(results['dlls'], anomalies_only)
        print "*************************************************************************"
        print "*****   LDR modules:"
        print "*************************************************************************"
        self.print_ldrmodules(results['ldrmodules'], anomalies_only)
        print "*************************************************************************"
        print "*****   Malfind:"
        print "*************************************************************************"
        self.print_malfind(results['malfinds'])
        print "*************************************************************************"
        print "*****   API hooks:"
        print "*************************************************************************"
        self.print_apihooks(results['apihooks'], anomalies_only)

    def print_malfind(self, malfinds):
        for malfind in malfinds:
            print "Process:", malfind.process.name, "Pid:", malfind.process.pid, \
                "Address:", self.format_value(malfind.start_address, '[addrpad]', self.snapshot.profile.name)
            print "Vad Tag:", malfind.vad, "Protection:", malfind.protection
            print "Flags:", malfind.flags
            if malfind.detmalfind_set.first().is_true_positive:
                print "ANOMALY! Reason: {}\n".format(malfind.detmalfind_set.first().reason)
            else:
                print "Probably False Positive\n"
            print malfind.hex_output
            for line in malfind.disasm_output.split("\n"):
                if len(line.split("\t")) == 3:
                    address, optcode, instruction = line.split("\t")
                    print "{0} {1:<16} {2}".format(address, optcode, instruction)
                else:
                    print
