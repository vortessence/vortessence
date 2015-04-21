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

from vortessence.models import *


def whitelist_callbacks(snapshot):
    print "Whitelisting callbacks..."
    for callback in Callback.objects.filter(snapshot=snapshot):
        if not WlCallback.objects.filter(type=callback.type, module=callback.module, details=callback.details,
                                         profile=snapshot.profile).exists():
            WlCallback(type=callback.type, module=callback.module, details=callback.details,
                       profile=snapshot.profile).save()


def whitelist_drivers(snapshot):
    print "Whitelisting drivers..."
    for driver in Driver.objects.filter(snapshot=snapshot):
        wl_driver = None
        if not WlDriver.objects.filter(name=driver.name, profile=snapshot.profile).exists():
            wl_driver = WlDriver(name=driver.name, profile=snapshot.profile)
            wl_driver.save()
        else:
            wl_driver = WlDriver.objects.get(name=driver.name, profile=snapshot.profile)
        for irp_call in driver.irpcall_set.all():
            if not WlIrpCall.objects.filter(name=irp_call.name, wl_driver=wl_driver).exists():
                WlIrpCall(name=irp_call.name, wl_driver=wl_driver).save()

        for device in driver.device_set.all():
            is_attached = True if device.parent_device else False
            if not WlDevice.objects.filter(name=device.name, type=device.type, is_attached=is_attached,
                                           driver=device.driver, wl_driver=wl_driver).exists():
                WlDevice(name=device.name, type=device.type, is_attached=is_attached, driver=device.driver,
                         wl_driver=wl_driver).save()


def whitelist_gdts(snapshot):
    print "Whitelisting GDTs..."
    for gdt in Gdt.objects.filter(snapshot=snapshot):
        if not WlGdt.objects.filter(type=gdt.type, profile=snapshot.profile).exists():
            WlGdt(type=gdt.type, profile=snapshot.profile).save()


def whitelist_idts(snapshot):
    print "Whitelisting IDTs..."
    for idt in Idt.objects.filter(snapshot=snapshot):
        if not WlIdt.objects.filter(module=idt.module, section=idt.section, profile=snapshot.profile).exists():
            WlIdt(module=idt.module, section=idt.section, profile=snapshot.profile).save()


def whitelist_ssdts(snapshot):
    print "Whitelisting SSDTs..."
    for ssdt in Ssdt.objects.filter(snapshot=snapshot):
        if not WlSsdt.objects.filter(function=ssdt.function_name, owner=ssdt.owner, profile=snapshot.profile).exists():
            WlSsdt(function=ssdt.function_name, owner=ssdt.owner, profile=snapshot.profile).save()


def whitelist_timers(snapshot):
    print "Whitelisting timers..."
    for timer in Timer.objects.filter(snapshot=snapshot):
        if not WlTimer.objects.filter(module=timer.module, profile=snapshot.profile).exists():
            WlTimer(module=timer.module, profile=snapshot.profile).save()


def whitelist_unloaded_modules(snapshot):
    print "Whitelisting unloaded modules..."
    for unloaded_module in UnloadedModules.objects.filter(snapshot=snapshot):
        if not WlUnloadedModules.objects.filter(name=unloaded_module.name, profile=snapshot.profile).exists():
            WlUnloadedModules(name=unloaded_module.name, profile=snapshot.profile).save()


def whitelist_files(snapshot):
    print "Whitelisting files..."
    for file_handle in Filescan.objects.filter(snapshot=snapshot):
        if not WlFile.objects.filter(name__iexact=file_handle.name, profile=snapshot.profile).exists():
            WlFile(name=file_handle.name, profile=snapshot.profile).save()


def whitelist_modscan(snapshot):
    print "Whitelisting modscan..."
    for module in Modscan.objects.filter(snapshot=snapshot):
        if not WlModscan.objects.filter(name__iexact=module.name, file__iexact=module.file, size=module.size,
                                        profile=snapshot.profile).exists():
            WlModscan(name=module.name, file=module.file, size=module.size, profile=snapshot.profile).save()


def whitelist_no_process_services(snapshot):
    print "Whitelisting services without process..."
    for service in Service.objects.filter(snapshot=snapshot, process=None):
        if not WlService.objects.filter(wl_process=None, name=service.service_name, type=service.service_type,
                                        binary_path__iexact=service.binary_path, dll=service.service_dll,
                                        profile=snapshot.profile).exists():
            WlService(wl_process=None, name=service.service_name, type=service.service_type,
                      binary_path=service.binary_path, dll=service.service_dll, profile=snapshot.profile).save()


def whitelist_registry(snapshot):
    print "Whitelisting registry..."
    for registry in Registry.objects.filter(snapshot=snapshot):
        if not WlRegistry.objects.filter(key=registry.key, hive=registry.hive, subkeys=registry.subkeys,
                                         values=registry.values, profile=snapshot.profile).exists():
            WlRegistry(key=registry.key, hive=registry.hive, subkeys=registry.subkeys,
                       values=registry.values, profile=snapshot.profile, autostart=registry.autostart).save()


# process related part
def whitelist_connections(process, w_process):
    for connection in Connection.objects.filter(process=process):
        if not WlConnection.objects.filter(wl_process=w_process, source_port=connection.source_port,
                                           destination_ip=connection.destination_ip,
                                           destination_port=connection.destination_port,
                                           protocol=connection.protocol, state=connection.state).exists():
            WlConnection(wl_process=w_process, source_port=connection.source_port,
                         destination_ip=connection.destination_ip,
                         destination_port=connection.destination_port,
                         protocol=connection.protocol, state=connection.state).save()


def whitelist_dlls(process, w_process):
    for dll in Dll.objects.filter(process=process):
        if not WlDll.objects.filter(wl_process=w_process, path__iexact=dll.path, size=dll.size).exists():
            WlDll(wl_process=w_process, path=dll.path, size=dll.size, load_count_from=dll.load_count,
                  load_count_to=dll.load_count).save()
        else:
            wl_dll = WlDll.objects.get(wl_process=w_process, path__iexact=dll.path, size=dll.size)
            if wl_dll.load_count_from > dll.load_count:
                wl_dll.load_count_from = dll.load_count
                wl_dll.save()
            if wl_dll.load_count_to < dll.load_count:
                wl_dll.load_count_to = dll.load_count
                wl_dll.save()


def whitelist_handles(process, w_process):
    for handle in Handle.objects.filter(process=process).exclude(handle_name='').exclude(handle_type='Thread').exclude(
            handle_type='Process'):
        if not WlHandle.objects.filter(wl_process=w_process, granted_access=handle.granted_access,
                                       handle_type=handle.handle_type, handle_name=handle.handle_name):
            WlHandle(wl_process=w_process, granted_access=handle.granted_access,
                     handle_type=handle.handle_type, handle_name=handle.handle_name).save()


def whitelist_sids(process, w_process):
    for sid in Sid.objects.filter(process=process):
        if not WlSid.objects.filter(wl_process=w_process, name=sid.name).exists():
            WlSid(wl_process=w_process, name=sid.name).save()


def whitelist_services_with_process(process, w_process, snapshot):
    for service in Service.objects.filter(process=process):
        if not WlService.objects.filter(wl_process=w_process, name=service.service_name, type=service.service_type,
                                        binary_path__iexact=service.binary_path, dll=service.service_dll,
                                        profile=snapshot.profile).exists():
            WlService(wl_process=w_process, name=service.service_name, type=service.service_type,
                      binary_path=service.binary_path, dll=service.service_dll, profile=snapshot.profile).save()


def whitelist_ldrmodules(process, w_process):
    for ldrmodule in Ldrmodule.objects.filter(process=process):
        if not WlLdrmodule.objects.filter(wl_process=w_process, mapped_path__iexact=ldrmodule.mapped_path,
                                          inload=ldrmodule.inload, ininit=ldrmodule.ininit,
                                          inmem=ldrmodule.inmem,
                                          mem_path__iexact=ldrmodule.mem_path,
                                          init_path__iexact=ldrmodule.init_path,
                                          load_path__iexact=ldrmodule.load_path).exists():
            WlLdrmodule(wl_process=w_process, mapped_path=ldrmodule.mapped_path,
                        inload=ldrmodule.inload, ininit=ldrmodule.ininit,
                        inmem=ldrmodule.inmem, mem_path=ldrmodule.mem_path, init_path=ldrmodule.init_path,
                        load_path=ldrmodule.load_path).save()


def whitelist_vad(process, w_process):
    vad_entries = Vad.objects.filter(process=process, protection__startswith='PAGE_EXECUTE_READWRITE')
    unique_sizes = []

    # bild tulples with count by size
    for vad in vad_entries:
        found = False
        for i in range(0, len(unique_sizes)):
            size, count = unique_sizes[i]
            if vad.end - vad.start == size:
                unique_sizes[i] = (size, count + 1)
                found = True
        if not found:
            unique_sizes.append((vad.end - vad.start, 1))

    for vad in vad_entries:
        size = vad.end - vad.start
        count = None
        for i in range(0, len(unique_sizes)):
            size, count = unique_sizes[i]
            if vad.end - vad.start == size:
                break

        wl_vad = None
        try:
            wl_vad = WlVad.objects.get(wl_process=w_process, size__exact=size)
        except WlVad.DoesNotExist:
            wl_vad = WlVad(wl_process=w_process, size=size, min=count, max=count)
            wl_vad.save()

        if wl_vad.min > count:
            wl_vad.min = count
            wl_vad.save()
        if wl_vad.max < count:
            wl_vad.max = count
            wl_vad.save()


def whitelist_apihooks(snapshot):
    processes = Process.objects.filter(snapshot=snapshot, threads__gt=0)
    for process in processes:
        w_process = WlProcess.objects.filter(path__iexact=process.path, profile=snapshot.profile).first()
        apihooks = Apihook.objects.filter(process=process)
        for apihook in apihooks:
            if apihook.dll:
                if not WlApihook.objects.filter(wl_process=w_process, dll_path__iexact=apihook.dll.path,
                                                address=apihook.hook_address - apihook.dll.base,
                                                function__iexact=apihook.function if apihook.function.find(
                                                        " at 0x") == -1 else apihook.function[
                                                                             0:apihook.function.find(
                                                                                     " at 0x")]).exists():
                    WlApihook(wl_process=w_process, dll_path=apihook.dll.path,
                              address=apihook.hook_address - apihook.dll.base,
                              function=apihook.function if apihook.function.find(
                                  " at 0x") == -1 else apihook.function[
                                                       0:apihook.function.find(" at 0x")]).save()


def whitelist_processes(snapshot):
    print "Whitelisting processes..."

    dest_ip_ignore_list = ('0.0.0.0', '::', '::1', '127.0.0.1', 'NULL')

    processes = Process.objects.filter(snapshot=snapshot, threads__gt=0)
    for process in processes:
        w_process = WlProcess.objects.filter(path__iexact=process.path, name__iexact=process.name,
                                             profile=snapshot.profile).first()
        if w_process:
            # update the whitelist process
            # network connections
            if w_process.network == 0:
                c = Connection.objects.filter(process=process).exclude(destination_ip__in=dest_ip_ignore_list)
                w_process.network = 1 if c else 0

            # set number of processes
            w_process.nr = max(w_process.nr, processes.filter(path__iexact=process.path).count())

            # set number of dlls
            number_of_dlls = Dll.objects.filter(process=process).count()
            w_process.dll_min = min(w_process.dll_min, number_of_dlls)
            w_process.dll_max = max(w_process.dll_max, number_of_dlls)

            # set number of threads
            w_process.thread_min = min(w_process.thread_min, process.threads)
            w_process.thread_max = max(w_process.thread_max, process.threads)

            w_process.save()

        else:
            # create new whitelist process
            w_process = WlProcess(name=process.name, path=process.path, nr=processes.filter(path=process.path).count(),
                                  dll_min=Dll.objects.filter(process=process).count(),
                                  dll_max=Dll.objects.filter(process=process).count(),
                                  thread_min=process.threads, thread_max=process.threads)

            w_process.network = 1 if Connection.objects.filter(process=process).exclude(
                destination_ip__in=dest_ip_ignore_list) else 0
            w_process.profile = snapshot.profile
            w_process.save()

        # save prio
        for thread in Thread.objects.filter(process=process).exclude(state="Terminated"):
            if not WlPrio.objects.filter(wl_process=w_process, prio=thread.base_priority):
                prio = WlPrio(wl_process=w_process, prio=thread.base_priority)
                prio.save()

        # save command line variants
        if not WlCommandline.objects.filter(wl_process=w_process, cl=process.command_line):
            cl = WlCommandline(wl_process=w_process, cl=process.command_line)
            cl.save()

        # save parent child relation
        w_process_parent = None
        if process.ppid > 0 and process.parent:
            try:
                w_process_parent = WlProcess.objects.get(path__iexact=process.parent.path,
                                                         name__iexact=process.parent.name, profile=snapshot.profile)
            except WlProcess.DoesNotExist:
                # check if parent has terminated. If yes, map him to existing whitelist entry if any
                if process.parent.threads == 0:
                    try:
                        w_process_parent = WlProcess.objects.get(name__iexact=process.parent.name,
                                                                 profile=snapshot.profile)
                    except WlProcess.DoesNotExist:
                        # do nothing because we don't want entries from terminated processes in whitelist
                        pass
                else:
                    # create new whitelist entry for parent process
                    w_process_parent = WlProcess(name=process.parent.name, path=process.parent.path,
                                                 nr=processes.filter(path=process.parent.path).count(),
                                                 dll_min=Dll.objects.filter(process=process.parent).count(),
                                                 dll_max=Dll.objects.filter(process=process.parent).count(),
                                                 thread_min=process.parent.threads, thread_max=process.parent.threads)
                    w_process_parent.network = 1 if Connection.objects.filter(process=process.parent).exclude(
                        destination_ip__in=dest_ip_ignore_list) else 0
                    w_process_parent.profile = snapshot.profile
                    w_process_parent.save()

        if not WlParent.objects.filter(wl_process=w_process, wl_process_parent=w_process_parent).exists():
            wl_parent = WlParent(wl_process=w_process, wl_process_parent=w_process_parent)
            wl_parent.save()

        whitelist_vad(process, w_process)
        whitelist_dlls(process, w_process)
        whitelist_sids(process, w_process)
        whitelist_services_with_process(process, w_process, snapshot)
        whitelist_ldrmodules(process, w_process)
        whitelist_connections(process, w_process)
        whitelist_handles(process, w_process)


def run(snapshot):
    print "Whitelisting image {}".format(snapshot.id)
    whitelist_modscan(snapshot)
    whitelist_callbacks(snapshot)
    whitelist_drivers(snapshot)
    whitelist_gdts(snapshot)
    whitelist_idts(snapshot)
    whitelist_ssdts(snapshot)
    whitelist_timers(snapshot)
    whitelist_unloaded_modules(snapshot)
    whitelist_no_process_services(snapshot)
    whitelist_files(snapshot)
    whitelist_registry(snapshot)
    whitelist_processes(snapshot)
    whitelist_apihooks(snapshot)
    print "-----------------------------------------------------------"
