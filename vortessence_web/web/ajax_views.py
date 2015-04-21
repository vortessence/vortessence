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

from django.shortcuts import render_to_response
from django.template import RequestContext
from django.contrib.auth.decorators import login_required

from web.models import *


@login_required
def det_dlls(request, process_id):
    context = RequestContext(request)
    context_dict = {}

    try:
        process = Process.objects.get(pk=process_id)
        dlls = Dll.objects.filter(process=process)
        context_dict['dlls'] = dlls
        context_dict['process'] = process
        context_dict['arch'] = "x86" if process.snapshot.profile.name.endswith("x86") else "x64"
        context_dict['filter_anomalies'] = request.session.get('filter_anomalies', False)

    except Process.DoesNotExist:
        pass

    return render_to_response('web/ajax/det_dlls.html', context_dict, context)


@login_required
def verinfo(request, dll_id):
    context = RequestContext(request)
    context_dict = {}

    try:
        context_dict['verinfo'] = Verinfo.objects.get(dll_id=dll_id)

    except Verinfo.DoesNotExist:
        pass

    return render_to_response('web/ajax/verinfo.html', context_dict, context)


@login_required
def det_sids(request, process_id):
    context = RequestContext(request)
    context_dict = {}

    try:
        process = Process.objects.get(pk=process_id)
        sids = Sid.objects.filter(process=process)
        context_dict['sids'] = sids
        context_dict['filter_anomalies'] = request.session.get('filter_anomalies', False)

    except Process.DoesNotExist:
        pass

    return render_to_response('web/ajax/det_sids.html', context_dict, context)


@login_required
def det_ldrmodules(request, process_id):
    context = RequestContext(request)
    context_dict = {}

    try:
        process = Process.objects.get(pk=process_id)
        ldrmodules = Ldrmodule.objects.filter(process=process)
        context_dict['ldrmodules'] = ldrmodules
        context_dict['arch'] = "x86" if process.snapshot.profile.name.endswith("x86") else "x64"
        context_dict['filter_anomalies'] = request.session.get('filter_anomalies', False)

    except Process.DoesNotExist:
        pass

    return render_to_response('web/ajax/det_ldrmodules.html', context_dict, context)


@login_required
def det_malfinds(request, process_id):
    context = RequestContext(request)
    context_dict = {}

    try:
        process = Process.objects.get(pk=process_id)
        context_dict['malfind_true_positives'] = DetMalfind.objects.filter(process=process, is_true_positive=1)
        context_dict['malfind_false_positives'] = DetMalfind.objects.filter(process=process, is_true_positive=0)
        context_dict['arch'] = "x86" if process.snapshot.profile.name.endswith("x86") else "x64"
        context_dict['filter_anomalies'] = request.session.get('filter_anomalies', False)
        context_dict['pid'] = process_id

    except Process.DoesNotExist:
        pass

    return render_to_response('web/ajax/det_malfinds.html', context_dict, context)


@login_required
def det_handles(request, process_id):
    context = RequestContext(request)
    context_dict = {}

    try:
        process = Process.objects.get(pk=process_id)
        handles = Handle.objects.filter(process=process)
        context_dict['handles'] = handles
        context_dict['arch'] = "x86" if process.snapshot.profile.name.endswith("x86") else "x64"
        context_dict['filter_anomalies'] = request.session.get('filter_anomalies', False)

    except Process.DoesNotExist:
        pass

    return render_to_response('web/ajax/det_handles.html', context_dict, context)


@login_required
def det_apihooks(request, process_id):
    context = RequestContext(request)
    try:
        process = Process.objects.get(pk=process_id)
        context_dict = {}
        context_dict["apihooks"] = Apihook.objects.filter(process=process)
        context_dict['arch'] = "x86" if process.snapshot.profile.name.endswith("x86") else "x64"
        context_dict['process'] = process
        context_dict['filter_anomalies'] = request.session.get('filter_anomalies', False)
    except Process.DoesNotExist:
        pass

    return render_to_response('web/ajax/det_apihooks.html', context_dict, context)


@login_required
def det_registry_keys(request, snapshot_id):
    context = RequestContext(request)
    context_dict = {}

    try:
        snapshot = Snapshot.objects.get(pk=snapshot_id)
        registry_keys = Registry.objects.filter(snapshot=snapshot)
        context_dict['registry_keys'] = registry_keys
        context_dict['filter_anomalies'] = request.session.get('filter_anomalies', False)

    except Snapshot.DoesNotExist:
        pass

    return render_to_response('web/ajax/det_registry_keys.html', context_dict, context)


@login_required
def det_callbacks(request, snapshot_id):
    context = RequestContext(request)
    context_dict = {}

    try:
        snapshot = Snapshot.objects.get(pk=snapshot_id)
        context_dict['callbacks'] = Callback.objects.filter(snapshot=snapshot)
        context_dict['arch'] = "x86" if snapshot.profile.name.endswith("x86") else "x64"
        context_dict['filter_anomalies'] = request.session.get('filter_anomalies', False)

    except Snapshot.DoesNotExist:
        pass

    return render_to_response('web/ajax/det_callbacks.html', context_dict, context)


@login_required
def det_connections(request, process_id):
    context = RequestContext(request)
    context_dict = {}

    try:
        process = Process.objects.get(pk=process_id)
        context_dict['connections'] = Connection.objects.filter(process=process)
        context_dict['arch'] = "x86" if process.snapshot.profile.name.endswith("x86") else "x64"
        context_dict['filter_anomalies'] = request.session.get('filter_anomalies', False)

    except Process.DoesNotExist:
        pass

    return render_to_response('web/ajax/det_connections.html', context_dict, context)


@login_required
def det_drivers(request, snapshot_id):
    context = RequestContext(request)
    context_dict = {}

    try:
        snapshot = Snapshot.objects.get(pk=snapshot_id)
        drivers = []
        for driver in Driver.objects.filter(snapshot=snapshot):
            has_driver_anomaly = driver.detdriver_set.exists()
            has_irpcall_anomaly = False
            for irpcall in driver.irpcall_set.all():
                if irpcall.detirpcall_set.exists():
                    has_irpcall_anomaly = True
                    break

            has_device_anomaly = False
            for device in driver.device_set.all():
                if device.detdevice_set.exists():
                    has_device_anomaly = True
                    break

            drivers.append({
                'driver': driver,
                'devices': driver.device_set.all().order_by('id') if driver.device_set.exists() else None,
                'hasDriverAnomaly': has_driver_anomaly,
                'hasIrpCallAnomalies': has_irpcall_anomaly,
                'hasDeviceAnomaly': has_device_anomaly
            })
        context_dict['drivers'] = drivers
        context_dict['arch'] = "x86" if snapshot.profile.name.endswith("x86") else "x64"
        context_dict['filter_anomalies'] = request.session.get('filter_anomalies', False)

    except Snapshot.DoesNotExist:
        pass

    return render_to_response('web/ajax/det_drivers.html', context_dict, context)


@login_required
def det_irps(request, driver_id):
    context = RequestContext(request)
    context_dict = {}

    try:
        driver = Driver.objects.get(pk=driver_id)
        context_dict['driver'] = driver
        context_dict['irps'] = IrpCall.objects.filter(driver=driver)
        context_dict['arch'] = "x86" if driver.snapshot.profile.name.endswith("x86") else "x64"
        context_dict['filter_anomalies'] = request.session.get('filter_anomalies', False)

    except Snapshot.DoesNotExist:
        pass

    return render_to_response('web/ajax/det_irps.html', context_dict, context)


@login_required
def det_unloaded_modules(request, snapshot_id):
    context = RequestContext(request)
    context_dict = {}

    try:
        snapshot = Snapshot.objects.get(pk=snapshot_id)
        context_dict['unloaded_modules'] = UnloadedModules.objects.filter(snapshot=snapshot)
        context_dict['arch'] = "x86" if snapshot.profile.name.endswith("x86") else "x64"
        context_dict['filter_anomalies'] = request.session.get('filter_anomalies', False)

    except Snapshot.DoesNotExist:
        pass

    return render_to_response('web/ajax/det_unloaded_modules.html', context_dict, context)


@login_required
def det_timers(request, snapshot_id):
    context = RequestContext(request)
    context_dict = {}

    try:
        snapshot = Snapshot.objects.get(pk=snapshot_id)
        timers = Timer.objects.filter(snapshot=snapshot)
        context_dict['timers'] = timers
        context_dict['arch'] = "x86" if snapshot.profile.name.endswith("x86") else "x64"
        context_dict['filter_anomalies'] = request.session.get('filter_anomalies', False)

    except Snapshot.DoesNotExist:
        pass

    return render_to_response('web/ajax/det_timers.html', context_dict, context)


@login_required
def det_gdts(request, snapshot_id):
    context = RequestContext(request)
    context_dict = {}

    try:
        snapshot = Snapshot.objects.get(pk=snapshot_id)
        context_dict['gdts'] = Gdt.objects.filter(snapshot=snapshot)
        context_dict['arch'] = "x86" if snapshot.profile.name.endswith("x86") else "x64"
        context_dict['filter_anomalies'] = request.session.get('filter_anomalies', False)

    except Snapshot.DoesNotExist:
        pass

    return render_to_response('web/ajax/det_gdts.html', context_dict, context)


@login_required
def det_idts(request, snapshot_id):
    context = RequestContext(request)
    context_dict = {}

    try:
        snapshot = Snapshot.objects.get(pk=snapshot_id)
        context_dict['idts'] = Idt.objects.filter(snapshot=snapshot)
        context_dict['arch'] = "x86" if snapshot.profile.name.endswith("x86") else "x64"
        context_dict['filter_anomalies'] = request.session.get('filter_anomalies', False)

    except Snapshot.DoesNotExist:
        pass

    return render_to_response('web/ajax/det_idts.html', context_dict, context)


@login_required
def det_files(request, snapshot_id):
    context = RequestContext(request)
    context_dict = {}

    try:
        snapshot = Snapshot.objects.get(pk=snapshot_id)
        context_dict['files'] = Filescan.objects.filter(snapshot=snapshot)
        context_dict['arch'] = "x86" if snapshot.profile.name.endswith("x86") else "x64"
        context_dict['filter_anomalies'] = request.session.get('filter_anomalies', False)

    except Snapshot.DoesNotExist:
        pass

    return render_to_response('web/ajax/det_files.html', context_dict, context)


@login_required
def det_modscans(request, snapshot_id):
    context = RequestContext(request)
    context_dict = {}

    try:
        snapshot = Snapshot.objects.get(pk=snapshot_id)
        context_dict['modscans'] = Modscan.objects.filter(snapshot=snapshot)
        context_dict['arch'] = "x86" if snapshot.profile.name.endswith("x86") else "x64"
        context_dict['filter_anomalies'] = request.session.get('filter_anomalies', False)

    except Snapshot.DoesNotExist:
        pass

    return render_to_response('web/ajax/det_modscans.html', context_dict, context)


@login_required
def det_services(request, snapshot_id):
    context = RequestContext(request)
    context_dict = {}

    try:
        snapshot = Snapshot.objects.get(pk=snapshot_id)
        services = Service.objects.filter(snapshot=snapshot)
        context_dict['services'] = services
        context_dict['arch'] = "x86" if snapshot.profile.name.endswith("x86") else "x64"
        context_dict['filter_anomalies'] = request.session.get('filter_anomalies', False)

    except Snapshot.DoesNotExist:
        pass

    return render_to_response('web/ajax/det_services.html', context_dict, context)


@login_required
def w_process_cl(request, process_id):
    context = RequestContext(request)
    context_dict = {}
    try:
        process = Process.objects.get(pk=process_id)
        w_process = WlProcess.objects.get(path__iexact=process.path, name__iexact=process.name,
                                          profile=process.snapshot.profile)
        context_dict['command_lines'] = WlCommandline.objects.filter(wl_process=w_process)
    except WlProcess.DoesNotExist:
        pass
    except process.DoesNotExist:
        pass

    return render_to_response('web/ajax/w_process_cl.html', context_dict, context)


@login_required
def w_process_parent(request, process_id):
    context = RequestContext(request)
    context_dict = {}
    try:
        process = Process.objects.get(pk=process_id)
        w_process = WlProcess.objects.get(path__iexact=process.path, name__iexact=process.name,
                                          profile=process.snapshot.profile)
        context_dict['parents'] = WlParent.objects.filter(wl_process=w_process)
    except WlProcess.DoesNotExist:
        pass
    except process.DoesNotExist:
        pass

    return render_to_response('web/ajax/w_process_parent.html', context_dict, context)


@login_required
def w_connections(request, wl_process_id):
    context = RequestContext(request)
    context_dict = {}

    try:
        wl_process = WlProcess.objects.get(pk=wl_process_id)
        context_dict['wl_connections'] = WlConnection.objects.filter(wl_process=wl_process)

    except WlProcess.DoesNotExist:
        pass

    return render_to_response('web/ajax/w_connections.html', context_dict, context)


@login_required
def w_dlls(request, wl_process_id):
    context = RequestContext(request)
    context_dict = {}

    try:
        wl_process = WlProcess.objects.get(pk=wl_process_id)
        context_dict['wl_dlls'] = WlDll.objects.filter(wl_process=wl_process).order_by('path')

    except WlProcess.DoesNotExist:
        pass

    return render_to_response('web/ajax/w_dlls.html', context_dict, context)


@login_required
def w_ldrmodules(request, wl_process_id):
    context = RequestContext(request)
    context_dict = {}

    try:
        wl_process = WlProcess.objects.get(pk=wl_process_id)
        context_dict['wl_ldrmodules'] = WlLdrmodule.objects.filter(wl_process=wl_process).order_by('mapped_path')

    except WlProcess.DoesNotExist:
        pass

    return render_to_response('web/ajax/w_ldrmodules.html', context_dict, context)


@login_required
def w_handles(request, wl_process_id):
    context = RequestContext(request)
    context_dict = {}

    try:
        wl_process = WlProcess.objects.get(pk=wl_process_id)
        context_dict['wl_handles'] = WlHandle.objects.filter(wl_process=wl_process)

    except WlProcess.DoesNotExist:
        pass

    return render_to_response('web/ajax/w_handles.html', context_dict, context)


@login_required
def w_sids(request, wl_process_id):
    context = RequestContext(request)
    context_dict = {}

    try:
        wl_process = WlProcess.objects.get(pk=wl_process_id)
        context_dict['wl_sids'] = WlSid.objects.filter(wl_process=wl_process).order_by('name')

    except WlProcess.DoesNotExist:
        pass

    return render_to_response('web/ajax/w_sids.html', context_dict, context)


@login_required
def w_malfinds(request, wl_process_id):
    context = RequestContext(request)
    context_dict = {}

    try:
        wl_process = WlProcess.objects.get(pk=wl_process_id)
        context_dict['wl_vad'] = WlVad.objects.filter(wl_process=wl_process)

    except WlProcess.DoesNotExist:
        pass

    return render_to_response('web/ajax/w_malfinds.html', context_dict, context)


@login_required
def w_apihooks(request, wl_process_id):
    context = RequestContext(request)
    context_dict = {}

    try:
        wl_process = WlProcess.objects.get(pk=wl_process_id)
        context_dict['wl_apihooks'] = WlApihook.objects.filter(wl_process=wl_process)

    except WlProcess.DoesNotExist:
        pass

    return render_to_response('web/ajax/w_apihooks.html', context_dict, context)


@login_required
def w_proc_details(request, wl_process_id):
    context = RequestContext(request)
    context_dict = {}

    try:
        wl_process = WlProcess.objects.get(pk=wl_process_id)
        context_dict['wl_process'] = wl_process
        context_dict['prios'] = wl_process.wlprio_set.order_by('prio').all()
        context_dict['commandlines'] = wl_process.wlcommandline_set.order_by('cl').all()
        context_dict['parents'] = wl_process.wlparent_set.all()

    except WlProcess.DoesNotExist:
        pass

    return render_to_response('web/ajax/w_proc_details.html', context_dict, context)


@login_required
def w_irps(request, wl_driver_id):
    context = RequestContext(request)
    context_dict = {}

    try:
        wl_driver = WlDriver.objects.get(pk=wl_driver_id)
        context_dict['wl_driver'] = wl_driver
        context_dict['wl_irps'] = WlIrpCall.objects.filter(wl_driver=wl_driver)

    except WlDriver.DoesNotExist:
        pass

    return render_to_response('web/ajax/w_irps.html', context_dict, context)