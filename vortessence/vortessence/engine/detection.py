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

import re
import logging

from vortessence.models import *
from vortessence import settings

logger = logging.getLogger("vortessence")

g_snapshot = None


def detect_service_anomalies(snapshot):
    print "Analysing services..."
    for service in Service.objects.filter(snapshot=snapshot, process=None):
        if not WlService.objects.filter(name__iexact=service.service_name, type__iexact=service.service_type,
                                        binary_path__iexact=service.binary_path, dll__iexact=service.service_dll,
                                        wl_process=None, profile=snapshot.profile).exists():
            DetService(service=service, snapshot=snapshot, process=None).save()


def detect_callback_anomalies(snapshot):
    print "Analysing callbacks..."
    for callback in Callback.objects.filter(snapshot=snapshot):
        if not WlCallback.objects.filter(type__iexact=callback.type, module__iexact=callback.module,
                                         details__iexact=callback.details, profile=snapshot.profile).exists():
            DetCallback(callback=callback, snapshot=snapshot).save()


def detect_gdt_anomalies(snapshot):
    print "Analysing GDT..."
    for gdt in Gdt.objects.filter(snapshot=snapshot):
        if not WlGdt.objects.filter(type__iexact=gdt.type, profile=snapshot.profile).exists():
            DetGdt(gdt=gdt, snapshot=snapshot).save()


def detect_idt_anomalies(snapshot):
    print "Analysing IDT..."
    for idt in Idt.objects.filter(snapshot=snapshot):
        if not WlIdt.objects.filter(module__iexact=idt.module, section__iexact=idt.section,
                                    profile=snapshot.profile).exists():
            DetIdt(idt=idt, snapshot=snapshot).save()


def detect_modscan_anomalies(snapshot):
    print "Analysing modscan..."
    for module in Modscan.objects.filter(snapshot=snapshot):
        if not WlModscan.objects.filter(name__iexact=module.name, file__iexact=module.file, size=module.size,
                                        profile=snapshot.profile).exists():
            DetModscan(modscan=module, snapshot=snapshot).save()


def detect_ssdt_anomalies(snapshot):
    print "Analysing SSDT..."
    ssdts = Ssdt.objects.filter(snapshot=snapshot)
    for ssdt in ssdts:
        if ssdt.offset > 0 and not WlSsdt.objects.filter(owner__iexact=ssdt.owner,
                                                         function__iexact=ssdt.function_name,
                                                         profile=snapshot.profile).exists():
            DetSsdt(ssdt=ssdt, snapshot=snapshot).save()


def detect_timer_anomalies(snapshot):
    print "Analysing timers..."
    for timer in Timer.objects.filter(snapshot=snapshot):
        if not WlTimer.objects.filter(module__iexact=timer.module, profile=snapshot.profile).exists():
            DetTimer(timer=timer, snapshot=snapshot).save()


def detect_unloaded_modules_anomalies(snapshot):
    print "Analysing unloaded modules..."
    for unloaded_module in UnloadedModules.objects.filter(snapshot=snapshot):
        if not WlUnloadedModules.objects.filter(name__iexact=unloaded_module.name, profile=snapshot.profile).exists():
            DetUnloadedModules(unloaded_modules=unloaded_module, snapshot=snapshot).save()


def detect_driver_anomalies(snapshot):
    print "Analysing drivers..."
    for driver in Driver.objects.filter(snapshot=snapshot):
        if not WlDriver.objects.filter(name__iexact=driver.name, profile=snapshot.profile).exists():
            det_driver = DetDriver(driver=driver, snapshot=snapshot)
            det_driver.save()
            for irp_call in driver.irpcall_set.all():
                DetIrpCall(irp_call=irp_call, det_driver=det_driver).save()
            for device in driver.device_set.all():
                DetDevice(device=device, det_driver=det_driver).save()
        else:
            wl_driver = WlDriver.objects.get(name__iexact=driver.name, profile=snapshot.profile)
            for irp_call in driver.irpcall_set.all():
                if not WlIrpCall.objects.filter(name__iexact=irp_call.name, wl_driver=wl_driver).exists():
                    det_driver = DetDriver(driver=driver, snapshot=snapshot)
                    det_driver.save()
                    DetIrpCall(irp_call=irp_call, det_driver=det_driver).save()

            for device in driver.device_set.all():
                if not WlDevice.objects.filter(name__iexact=device.name, type__iexact=device.type,
                                               is_attached=True if device.parent_device else False,
                                               driver__iexact=device.driver,
                                               wl_driver=wl_driver).exists():
                    det_driver = DetDriver(driver=driver, snapshot=snapshot)
                    det_driver.save()
                    DetDevice(device=device, det_driver=det_driver).save()


def detect_registry_anomalies(snapshot):
    print "Analysing registry..."
    for reg in Registry.objects.filter(snapshot=snapshot):
        if not WlRegistry.objects.filter(key__iexact=reg.key, hive__iexact=reg.hive, subkeys__iexact=reg.subkeys,
                                         values__iexact=reg.values, profile=snapshot.profile).exists():
            DetRegistry(registry=reg, snapshot=snapshot).save()


def detect_file_anomalies(snapshot):
    print "Analysing file handles..."
    for file in Filescan.objects.filter(snapshot=snapshot):
        if not WlFile.objects.filter(name__iexact=file.name, profile=snapshot.profile).exists():
            ignore_file = False
            for expr in settings.filescan_filter:
                if re.match(expr.lower(), file.name.lower()):
                    ignore_file = True
                    break
            if not ignore_file:
                DetFile(filescan=file, snapshot=snapshot).save()


def detect_apihooks(snapshot):
    for process in Process.objects.filter(snapshot=snapshot):
        for apihook in Apihook.objects.filter(process=process):
            # find whitelist process
            wl_process = WlProcess.objects.filter(path__iexact=process.path, profile=process.snapshot.profile).first()
            if apihook.dll:
                if not WlApihook.objects.filter(wl_process=wl_process,
                                                dll_path__iexact=apihook.dll.path,
                                                function__iexact=apihook.function if apihook.function.find(
                                                        " at 0x") == -1 else apihook.function[
                                                                             0:apihook.function.find(
                                                                                     " at ")]).exists():
                    DetApihook(apihook=apihook, process=process).save()


def detect_handle(process, w_process):
    for handle in Handle.objects.filter(process=process) \
        .exclude(handle_name='') \
        .exclude(handle_type='Thread') \
        .exclude(handle_type='Process') \
        .exclude(handle_type='ALPC Port', handle_name__startswith='LRPC-') \
        .exclude(handle_type='ALPC Port', handle_name__startswith='OLE') \
        .exclude(handle_type='ALPC Port', handle_name__startswith='WMsgKRpc') \
        .exclude(handle_type='Directory', handle_name__startswith='00000000-0') \
        .exclude(process__name='conhost.exe', handle_name__startswith='ConsoleLPC-') \
        .exclude(process__name='conhost.exe', handle_name__startswith='ConsoleEvent-') \
        .exclude(process__name='winlogon.exe', handle_name__endswith='WlballoonSmartCardUnlockNotificationEventName') \
        .exclude(process__name='winlogon.exe', handle_name__endswith='WlballoonKerberosNotificationEventName') \
        .exclude(process__name='winlogon.exe', handle_name__endswith='WlballoonAlternateCredsNotificationEventName') \
        .exclude(process__name='SearchIndexer.',
                 handle_name__icontains='ProgramData\Microsoft\Search\Data\Applications\Windows\GatherLogs\SystemIndex\SystemIndex') \
        .exclude(process__name='svchost.exe', handle_name__startswith='BFE_Notify_Event_{') \
        .exclude(process__name='svchost.exe', handle_name__startswith='WDI_{') \
        .exclude(process__name='MsMpEng.exe', handle_name__startswith='MpEvent-'):
        if not WlHandle.objects.filter(wl_process=w_process, granted_access=handle.granted_access,
                                       handle_type=handle.handle_type, handle_name=handle.handle_name):
            DetHandle(process=process, handle=handle).save()


def detect_malfind(process, w_process):
    # check malfind
    for mf in Malfind.objects.filter(process=process):
        # pad the address
        malfind_address = mf.start_address
        det_malfind = DetMalfind(malfind=mf, process=process)

        # check if process has READ_WRITE_EXECUTE vad entries
        wl_vads = WlVad.objects.filter(wl_process=w_process)
        if len(wl_vads) > 0:
            try:
                vad = Vad.objects.filter(start=malfind_address, process=process).first()
                found_matching_wl_vad = False
                for wl_vad in wl_vads:
                    if vad.end - vad.start == wl_vad.size:
                        found_matching_wl_vad = True
                        # check for API hook trampoline code
                        external_jump = 0

                        asm_instructions = []
                        asm_lines = mf.disasm_output.split("\n")

                        for l in asm_lines:
                            if len(l) > 3:
                                checked_instruction_pieces = []
                                instruction_pieces = l.split("\t")[2].split(" ")
                                for ip in instruction_pieces:
                                    if len(ip) > 1:
                                        checked_instruction_pieces.append(ip)
                                asm_instructions.append(" ".join(checked_instruction_pieces))

                        for asm in asm_instructions:
                            # filter the jumps
                            if asm.lower().startswith("j"):
                                address = asm.split(" ")[1]
                                if re.match(r'0x[0-9a-fA-F]{6,}', address):
                                    # check for trampolin jumps outside of vad region
                                    if int(address, 16) > (malfind_address + vad.end) \
                                        or int(address, 16) < malfind_address:
                                        external_jump += 1

                        if external_jump > 2:
                            det_malfind.is_true_positive = True
                            det_malfind.reason = "API hook trampolin"
                        else:
                            det_malfind.is_true_positive = False
                        break

                if not found_matching_wl_vad:
                    det_malfind.is_true_positive = True
                    det_malfind.reason = "Process has no VAD entry with size {} in whitelist".format(
                        hex(vad.end - vad.start))
            except Vad.DoesNotExist:
                det_malfind.is_true_positive = True
                det_malfind.reason = "no VAD found???"

        else:
            det_malfind.is_true_positive = True
            det_malfind.reason = "Process has no READ_WRITE_EXECUTE in whitelist"

        det_malfind.save()


def detect_process_anomalies(process, snapshot):
    # check if process is known
    w_process = None
    try:
        w_process = WlProcess.objects.get(path__iexact=process.path, name__iexact=process.name,
                                          profile=snapshot.profile)
    except WlProcess.DoesNotExist:
        DetProcess(unknown_process=True, process=process).save()
        for malfind in Malfind.objects.filter(process=process):
            DetMalfind(process=process, malfind=malfind, is_true_positive=True,
                       reason="Process not in whitelist").save()
        return

    det_process = DetProcess(process=process, unknown_number_of_the_same=False, unknown_number_of_threads=False,
                             unknown_number_of_dlls=False, unknown_command_line=False, unknown_parent=False,
                             network_anomaly=False, unknown_process=False)
    has_anomaly = False

    # check number of processes with the same path
    if Process.objects.filter(snapshot=snapshot, path__iexact=process.path,
                              name__iexact=process.name).count() > w_process.nr:
        det_process.unknown_number_of_the_same = Process.objects.filter(snapshot=snapshot, path__iexact=process.path,
                                                                        name__iexact=process.name).count()
        has_anomaly = True

    # check number of threads
    if not w_process.thread_min <= process.threads <= w_process.thread_max:
        det_process.unknown_number_of_threads = process.threads
        has_anomaly = True

    # check numbers of dlls
    if not w_process.dll_min <= Dll.objects.filter(process=process).count() <= w_process.dll_max:
        det_process.unknown_number_of_dlls = Dll.objects.filter(process=process).count()
        has_anomaly = True

    # check network anomaly
    if w_process.network == 0:
        for con in Connection.objects.filter(process=process):
            if con.destination_ip is not None and con.destination_ip != "NULL" and con.destination_ip not in {'0.0.0.0',
                                                                                                              '::',
                                                                                                              '::1',
                                                                                                              '127.0.0.1'}:
                det_process.network_anomaly = True
                has_anomaly = True
                break
    else:
        # process is known to have network, now check if suspicious
        suspicious_connection = False
        for con in Connection.objects.filter(process=process, state="LISTENING"):
            # check if whitelisted
            if not WlConnection.objects.filter(wl_process=w_process,
                                               source_port=con.source_port,
                                               protocol=con.protocol, state=con.state).exists():
                DetConnection(connection=con, snapshot=snapshot, process=process).save()
                suspicious_connection = True

        if suspicious_connection:
            det_process.network_anomaly = True
            has_anomaly = True

    # check command line
    if not WlCommandline.objects.filter(wl_process=w_process, cl__iexact=process.command_line).exists():
        # exclude known always changing parameters
        ignore_command_line = False
        for expr in settings.command_line_filter:
            if re.search(expr, process.command_line.lower()) is not None:
                ignore_command_line = True
                break
        if not ignore_command_line:
            det_process.unknown_command_line = True
            has_anomaly = True

    # check parent
    if process.parent is not None:
        try:
            w_process_parents = WlProcess.objects.filter(path__iexact=process.parent.path,
                                                         name__iexact=process.parent.name, profile=snapshot.profile)
            for w_process_parent in w_process_parents:
                if not WlParent.objects.filter(wl_process=w_process, wl_process_parent=w_process_parent).exists():
                    det_process.unknown_parent = True
                    has_anomaly = True
        except WlProcess.DoesNotExist:
            det_process.unknown_parent = True
            has_anomaly = True
    else:
        if not WlParent.objects.filter(wl_process=w_process, wl_process_parent=None).exists():
            det_process.unknown_parent = True
            has_anomaly = True

    if has_anomaly:
        det_process.save()

    # check base prios of threads
    base_prios = []
    for wl_prio in WlPrio.objects.filter(wl_process=w_process):
        base_prios.append(wl_prio.prio)
    for thread in Thread.objects.filter(process=process).exclude(state__iexact="Terminated"):
        if thread.base_priority not in base_prios:
            DetThread(thread=thread, process=process, base_priority=thread.base_priority).save()

    # check dll anomalies. These are: unknown path for this process, unknown path in whole DB
    for dll in process.dll_set.all():
        try:
            wl_dll = WlDll.objects.filter(path__iexact=dll.path, wl_process=w_process)[0]
            # Size check make no sense without PE versioning
            unknown_size = False
            unknown_load_count = False
            if wl_dll.load_count_from == 65535 and dll.load_count != 65535:
                unknown_load_count = True
            if wl_dll.load_count_to != 65535 and dll.load_count == 65535:
                unknown_load_count = True
            if unknown_size or unknown_load_count:
                DetDll(unknown_for_process=False, unknown_overall=False, unknown_size=unknown_size,
                       unknown_load_count=unknown_load_count, dll=dll, process=process).save()
        except IndexError:
            unknown_overall = not WlDll.objects.filter(path__iexact=dll.path).exists()
            DetDll(unknown_for_process=True, unknown_overall=unknown_overall,
                   unknown_size=False if unknown_overall else True, dll=dll,
                   process=process, unknown_load_count=0).save()

    # check services related to this process
    for service in Service.objects.filter(process=process):
        if not WlService.objects.filter(name__iexact=service.service_name, type__iexact=service.service_type,
                                        binary_path__iexact=service.binary_path, dll__iexact=service.service_dll,
                                        wl_process=w_process).exists():
            DetService(service=service, process=process, snapshot=snapshot).save()

    # check loader modules
    for ldrmodule in process.ldrmodule_set.all():
        if not WlLdrmodule.objects.filter(mapped_path__iexact=ldrmodule.mapped_path, inload=ldrmodule.inload,
                                          inmem=ldrmodule.inmem, ininit=ldrmodule.ininit,
                                          wl_process=w_process).exists():
            DetLdrmodule(process=process, ldrmodule=ldrmodule).save()

    # check SID
    for sid in process.sid_set.all():
        if not WlSid.objects.filter(wl_process=w_process, name__iexact=sid.name).exists():
            DetSid(sid=sid, process=process).save()

    detect_malfind(process, w_process)
    detect_handle(process, w_process)


def run(snapshot):
    global g_snapshot
    g_snapshot = snapshot

    print "Analyzing image {}".format(snapshot.id)
    detect_modscan_anomalies(snapshot)
    detect_service_anomalies(snapshot)
    detect_callback_anomalies(snapshot)
    detect_gdt_anomalies(snapshot)
    detect_idt_anomalies(snapshot)
    detect_ssdt_anomalies(snapshot)
    detect_timer_anomalies(snapshot)
    detect_unloaded_modules_anomalies(snapshot)
    detect_driver_anomalies(snapshot)
    detect_file_anomalies(snapshot)
    detect_apihooks(snapshot)
    detect_registry_anomalies(snapshot)

    print "Analysing processes..."
    for process in Process.objects.filter(snapshot=snapshot):
        detect_process_anomalies(process, snapshot)

    # removed cached results
    snapshot.result_cache = None
    snapshot.save()
    print "-----------------------------------------------------------"
