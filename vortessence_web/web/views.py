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

import json

from django.shortcuts import render_to_response
from django.template import RequestContext
from django.http import HttpResponseRedirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.views.generic import ListView
from django.db.models import Q
from extra_views import SearchableListMixin, SortableListMixin
from pure_pagination.mixins import PaginationMixin

from web.models import *
from web.forms import *


def class_view_decorator(function_decorator):
    """Convert a function based decorator into a class based decorator usable
    on class based Views.

    Can't subclass the `View` as it breaks inheritance (super in particular),
    so we monkey-patch instead.
    """

    def simple_decorator(View):
        View.dispatch = method_decorator(function_decorator)(View.dispatch)
        return View

    return simple_decorator


@login_required
def index(request):
    return HttpResponseRedirect('/image/')


class LogListView(SearchableListMixin, SortableListMixin, PaginationMixin, ListView):
    template_name = 'web/logs.html'

    sort_fields = ['timestamp', 'message', 'snapshot__id', 'level']
    search_fields = ['message', 'snapshot__id', 'level']

    model = Log
    paginate_by = 20

    def get_context_data(self, *args, **kwargs):
        sort_mode = 'asc'
        sort_mode_pag = 'asc'
        sort_by = ''
        search_value = ""
        try:
            if self.request.GET['o']:
                sort_by = self.request.GET['o']

            if self.request.GET['ot'] == 'asc':
                sort_mode = 'desc'
                sort_mode_pag = 'asc'

            if self.request.GET['ot'] == 'desc':
                sort_mode = 'asc'
                sort_mode_pag = 'desc'
        except:
            pass

        try:
            if self.request.GET['q']:
                search_value = self.request.GET['q']
        except:
            pass

        context = super(LogListView, self).get_context_data(*args, **kwargs)
        context['sort_mode'] = sort_mode
        context['sort_mode_pag'] = sort_mode_pag
        context['sort_by'] = sort_by
        context['search_value'] = search_value
        return context


@login_required
def tools(request):
    context = RequestContext(request)
    context_dict = {"logs": Log.objects.all().order_by('timestamp', 'desc')}

    return render_to_response('web/logs.html', context_dict, context)


@login_required
def whitelist(request):
    context = RequestContext(request)
    context_dict = {"stats": []}
    for profile in Profile.objects.all():
        profile_stats = {
            "name": profile.name,
            "processes": WlProcess.objects.filter(profile=profile).count(),
            "callbacks": WlCallback.objects.filter(profile=profile).count(),
            "drivers": WlDriver.objects.filter(profile=profile).count(),
            "files": WlFile.objects.filter(profile=profile).count(),
            "gdts": WlGdt.objects.filter(profile=profile).count(),
            "idts": WlIdt.objects.filter(profile=profile).count(),
            "modules": WlModscan.objects.filter(profile=profile).count(),
            "unloaded_modules": WlUnloadedModules.objects.filter(profile=profile).count(),
            "registry": WlRegistry.objects.filter(profile=profile).count(),
            "services": WlService.objects.filter(profile=profile).count(),
            "ssdts": WlSsdt.objects.filter(profile=profile).count(),
            "timers": WlTimer.objects.filter(profile=profile).count()
        }

        context_dict["stats"].append(profile_stats)

    return render_to_response('web/whitelist/whitelist.html', context_dict, context)


@class_view_decorator(login_required)
class WhitelistCallbacksListView(SearchableListMixin, SortableListMixin, PaginationMixin, ListView):
    template_name = 'web/whitelist/whitelist_callbacks.html'

    sort_fields = ['type', 'module', 'details', 'profile__name']
    search_fields = ['type', 'module', 'details', 'profile__name']

    model = WlCallback
    paginate_by = 20

    def get_context_data(self, *args, **kwargs):
        sort_mode = 'asc'
        sort_mode_pag = 'asc'
        sort_by = ''
        search_value = ""
        try:
            if self.request.GET['o']:
                sort_by = self.request.GET['o']

            if self.request.GET['ot'] == 'asc':
                sort_mode = 'desc'
                sort_mode_pag = 'asc'

            if self.request.GET['ot'] == 'desc':
                sort_mode = 'asc'
                sort_mode_pag = 'desc'
        except:
            pass

        try:
            if self.request.GET['q']:
                search_value = self.request.GET['q']
        except:
            pass

        context = super(WhitelistCallbacksListView, self).get_context_data(*args, **kwargs)
        context['sort_mode'] = sort_mode
        context['sort_mode_pag'] = sort_mode_pag
        context['sort_by'] = sort_by
        context['search_value'] = search_value
        return context


@class_view_decorator(login_required)
class WhitelistDriversListView(SearchableListMixin, SortableListMixin, PaginationMixin, ListView):
    template_name = 'web/whitelist/whitelist_drivers.html'

    sort_fields = ['name', 'wl_driver__name', 'type', 'is_attached', 'wl_driver__profile__name']
    search_fields = ['name', 'wl_driver__name', 'type', 'is_attached', 'wl_driver__profile__name']

    model = WlDevice
    paginate_by = 20

    def get_context_data(self, *args, **kwargs):
        sort_mode = 'asc'
        sort_mode_pag = 'asc'
        sort_by = ''
        search_value = ""
        try:
            if self.request.GET['o']:
                sort_by = self.request.GET['o']

            if self.request.GET['ot'] == 'asc':
                sort_mode = 'desc'
                sort_mode_pag = 'asc'

            if self.request.GET['ot'] == 'desc':
                sort_mode = 'asc'
                sort_mode_pag = 'desc'
        except:
            pass

        try:
            if self.request.GET['q']:
                search_value = self.request.GET['q']
        except:
            pass

        context = super(WhitelistDriversListView, self).get_context_data(*args, **kwargs)
        context['sort_mode'] = sort_mode
        context['sort_mode_pag'] = sort_mode_pag
        context['sort_by'] = sort_by
        context['search_value'] = search_value
        return context


@class_view_decorator(login_required)
class WhitelistFileListView(SearchableListMixin, SortableListMixin, PaginationMixin, ListView):
    template_name = 'web/whitelist/whitelist_files.html'

    sort_fields = ['name', 'profile__name']
    search_fields = ['name', 'profile__name']

    model = WlFile
    paginate_by = 20

    def get_context_data(self, *args, **kwargs):
        sort_mode = 'asc'
        sort_mode_pag = 'asc'
        sort_by = ''
        search_value = ""
        try:
            if self.request.GET['o']:
                sort_by = self.request.GET['o']

            if self.request.GET['ot'] == 'asc':
                sort_mode = 'desc'
                sort_mode_pag = 'asc'

            if self.request.GET['ot'] == 'desc':
                sort_mode = 'asc'
                sort_mode_pag = 'desc'
        except:
            pass

        try:
            if self.request.GET['q']:
                search_value = self.request.GET['q']
        except:
            pass

        context = super(WhitelistFileListView, self).get_context_data(*args, **kwargs)
        context['sort_mode'] = sort_mode
        context['sort_mode_pag'] = sort_mode_pag
        context['sort_by'] = sort_by
        context['search_value'] = search_value
        return context


@class_view_decorator(login_required)
class WhitelistGdtListView(SearchableListMixin, SortableListMixin, PaginationMixin, ListView):
    template_name = 'web/whitelist/whitelist_gdts.html'

    sort_fields = ['type', 'profile__name']
    search_fields = ['type', 'profile__name']

    model = WlGdt
    paginate_by = 20

    def get_context_data(self, *args, **kwargs):
        sort_mode = 'asc'
        sort_mode_pag = 'asc'
        sort_by = ''
        search_value = ""
        try:
            if self.request.GET['o']:
                sort_by = self.request.GET['o']

            if self.request.GET['ot'] == 'asc':
                sort_mode = 'desc'
                sort_mode_pag = 'asc'

            if self.request.GET['ot'] == 'desc':
                sort_mode = 'asc'
                sort_mode_pag = 'desc'
        except:
            pass

        try:
            if self.request.GET['q']:
                search_value = self.request.GET['q']
        except:
            pass

        context = super(WhitelistGdtListView, self).get_context_data(*args, **kwargs)
        context['sort_mode'] = sort_mode
        context['sort_mode_pag'] = sort_mode_pag
        context['sort_by'] = sort_by
        context['search_value'] = search_value
        return context


@class_view_decorator(login_required)
class WhitelistIdtListView(SearchableListMixin, SortableListMixin, PaginationMixin, ListView):
    template_name = 'web/whitelist/whitelist_idts.html'

    sort_fields = ['module', 'section', 'profile__name']
    search_fields = ['module', 'section', 'profile__name']

    model = WlIdt
    paginate_by = 20

    def get_context_data(self, *args, **kwargs):
        sort_mode = 'asc'
        sort_mode_pag = 'asc'
        sort_by = ''
        search_value = ""
        try:
            if self.request.GET['o']:
                sort_by = self.request.GET['o']

            if self.request.GET['ot'] == 'asc':
                sort_mode = 'desc'
                sort_mode_pag = 'asc'

            if self.request.GET['ot'] == 'desc':
                sort_mode = 'asc'
                sort_mode_pag = 'desc'
        except:
            pass

        try:
            if self.request.GET['q']:
                search_value = self.request.GET['q']
        except:
            pass

        context = super(WhitelistIdtListView, self).get_context_data(*args, **kwargs)
        context['sort_mode'] = sort_mode
        context['sort_mode_pag'] = sort_mode_pag
        context['sort_by'] = sort_by
        context['search_value'] = search_value
        return context


@class_view_decorator(login_required)
class WhitelistModulesListView(SearchableListMixin, SortableListMixin, PaginationMixin, ListView):
    template_name = 'web/whitelist/whitelist_modules.html'

    sort_fields = ['name', 'file', 'size', 'profile__name']
    search_fields = ['name', 'file', 'profile__name']

    model = WlModscan
    paginate_by = 20

    def get_context_data(self, *args, **kwargs):
        sort_mode = 'asc'
        sort_mode_pag = 'asc'
        sort_by = ''
        search_value = ""
        try:
            if self.request.GET['o']:
                sort_by = self.request.GET['o']

            if self.request.GET['ot'] == 'asc':
                sort_mode = 'desc'
                sort_mode_pag = 'asc'

            if self.request.GET['ot'] == 'desc':
                sort_mode = 'asc'
                sort_mode_pag = 'desc'
        except:
            pass

        try:
            if self.request.GET['q']:
                search_value = self.request.GET['q']
        except:
            pass

        context = super(WhitelistModulesListView, self).get_context_data(*args, **kwargs)
        context['sort_mode'] = sort_mode
        context['sort_mode_pag'] = sort_mode_pag
        context['sort_by'] = sort_by
        context['search_value'] = search_value
        return context


@class_view_decorator(login_required)
class WhitelistUnloadedModulesListView(SearchableListMixin, SortableListMixin, PaginationMixin, ListView):
    template_name = 'web/whitelist/whitelist_unloadedmodules.html'

    sort_fields = ['name', 'profile__name']
    search_fields = ['name', 'profile__name']

    model = WlUnloadedModules
    paginate_by = 20

    def get_context_data(self, *args, **kwargs):
        sort_mode = 'asc'
        sort_mode_pag = 'asc'
        sort_by = ''
        search_value = ""
        try:
            if self.request.GET['o']:
                sort_by = self.request.GET['o']

            if self.request.GET['ot'] == 'asc':
                sort_mode = 'desc'
                sort_mode_pag = 'asc'

            if self.request.GET['ot'] == 'desc':
                sort_mode = 'asc'
                sort_mode_pag = 'desc'
        except:
            pass

        try:
            if self.request.GET['q']:
                search_value = self.request.GET['q']
        except:
            pass

        context = super(WhitelistUnloadedModulesListView, self).get_context_data(*args, **kwargs)
        context['sort_mode'] = sort_mode
        context['sort_mode_pag'] = sort_mode_pag
        context['sort_by'] = sort_by
        context['search_value'] = search_value
        return context


@class_view_decorator(login_required)
class WhitelistServicesListView(SearchableListMixin, SortableListMixin, PaginationMixin, ListView):
    template_name = 'web/whitelist/whitelist_services.html'

    sort_fields = ['name', 'type', 'binary_path', 'dll', 'wl_process__name', 'profile__name']
    search_fields = ['name', 'type', 'binary_path', 'dll', 'wl_process__name', 'profile__name']

    model = WlService
    paginate_by = 20

    def get_context_data(self, *args, **kwargs):
        sort_mode = 'asc'
        sort_mode_pag = 'asc'
        sort_by = ''
        search_value = ""
        try:
            if self.request.GET['o']:
                sort_by = self.request.GET['o']

            if self.request.GET['ot'] == 'asc':
                sort_mode = 'desc'
                sort_mode_pag = 'asc'

            if self.request.GET['ot'] == 'desc':
                sort_mode = 'asc'
                sort_mode_pag = 'desc'
        except:
            pass

        try:
            if self.request.GET['q']:
                search_value = self.request.GET['q']
        except:
            pass

        context = super(WhitelistServicesListView, self).get_context_data(*args, **kwargs)
        context['sort_mode'] = sort_mode
        context['sort_mode_pag'] = sort_mode_pag
        context['sort_by'] = sort_by
        context['search_value'] = search_value
        return context


@class_view_decorator(login_required)
class WhitelistSsdtListView(SearchableListMixin, SortableListMixin, PaginationMixin, ListView):
    template_name = 'web/whitelist/whitelist_ssdts.html'

    sort_fields = ['function', 'owner', 'profile__name']
    search_fields = ['function', 'owner', 'profile__name']

    model = WlSsdt
    paginate_by = 20

    def get_context_data(self, *args, **kwargs):
        sort_mode = 'asc'
        sort_mode_pag = 'asc'
        sort_by = ''
        search_value = ""
        try:
            if self.request.GET['o']:
                sort_by = self.request.GET['o']

            if self.request.GET['ot'] == 'asc':
                sort_mode = 'desc'
                sort_mode_pag = 'asc'

            if self.request.GET['ot'] == 'desc':
                sort_mode = 'asc'
                sort_mode_pag = 'desc'
        except:
            pass

        try:
            if self.request.GET['q']:
                search_value = self.request.GET['q']
        except:
            pass

        context = super(WhitelistSsdtListView, self).get_context_data(*args, **kwargs)
        context['sort_mode'] = sort_mode
        context['sort_mode_pag'] = sort_mode_pag
        context['sort_by'] = sort_by
        context['search_value'] = search_value
        return context


@class_view_decorator(login_required)
class WhitelistTimerListView(SearchableListMixin, SortableListMixin, PaginationMixin, ListView):
    template_name = 'web/whitelist/whitelist_timers.html'

    sort_fields = ['module', 'profile__name']
    search_fields = ['module', 'profile__name']

    model = WlTimer
    paginate_by = 20

    def get_context_data(self, *args, **kwargs):
        sort_mode = 'asc'
        sort_mode_pag = 'asc'
        sort_by = ''
        search_value = ""
        try:
            if self.request.GET['o']:
                sort_by = self.request.GET['o']

            if self.request.GET['ot'] == 'asc':
                sort_mode = 'desc'
                sort_mode_pag = 'asc'

            if self.request.GET['ot'] == 'desc':
                sort_mode = 'asc'
                sort_mode_pag = 'desc'
        except:
            pass

        try:
            if self.request.GET['q']:
                search_value = self.request.GET['q']
        except:
            pass

        context = super(WhitelistTimerListView, self).get_context_data(*args, **kwargs)
        context['sort_mode'] = sort_mode
        context['sort_mode_pag'] = sort_mode_pag
        context['sort_by'] = sort_by
        context['search_value'] = search_value
        return context


@class_view_decorator(login_required)
class WhitelistRegistryListView(SearchableListMixin, SortableListMixin, PaginationMixin, ListView):
    template_name = 'web/whitelist/whitelist_registry.html'

    sort_fields = ['key', 'hive', 'autostart', 'profile__name']
    search_fields = ['key', 'hive', 'autostart', 'subkeys', 'values', 'profile__name']

    model = WlRegistry
    paginate_by = 20

    def get_context_data(self, *args, **kwargs):
        sort_mode = 'asc'
        sort_mode_pag = 'asc'
        sort_by = ''
        search_value = ""
        try:
            if self.request.GET['o']:
                sort_by = self.request.GET['o']

            if self.request.GET['ot'] == 'asc':
                sort_mode = 'desc'
                sort_mode_pag = 'asc'

            if self.request.GET['ot'] == 'desc':
                sort_mode = 'asc'
                sort_mode_pag = 'desc'
        except:
            pass

        try:
            if self.request.GET['q']:
                search_value = self.request.GET['q']
        except:
            pass

        context = super(WhitelistRegistryListView, self).get_context_data(*args, **kwargs)
        context['sort_mode'] = sort_mode
        context['sort_mode_pag'] = sort_mode_pag
        context['sort_by'] = sort_by
        context['search_value'] = search_value
        return context


@login_required
def whitelist_processes(request):
    context = RequestContext(request)

    return render_to_response('web/whitelist/whitelist_processes.html', {}, context)


@class_view_decorator(login_required)
class WhitelistProcessListView(SearchableListMixin, SortableListMixin, ListView):
    template_name = 'web/whitelist/whitelist_processes.html'

    sort_fields = ['name', 'path', 'profile__name']
    search_fields = ['name', 'path', 'profile__name']

    model = WlProcess
    paginate_by = 20

    def get_context_data(self, *args, **kwargs):
        sort_mode = 'asc'
        sort_mode_pag = 'asc'
        sort_by = ''
        search_value = ""
        try:
            if self.request.GET['o']:
                sort_by = self.request.GET['o']

            if self.request.GET['ot'] == 'asc':
                sort_mode = 'desc'
                sort_mode_pag = 'asc'

            if self.request.GET['ot'] == 'desc':
                sort_mode = 'asc'
                sort_mode_pag = 'desc'

        except:
            pass

        try:
            if self.request.GET['q']:
                search_value = self.request.GET['q']

        except:
            pass

        context = super(WhitelistProcessListView, self).get_context_data(*args, **kwargs)
        context['sort_mode'] = sort_mode
        context['sort_mode_pag'] = sort_mode_pag
        context['sort_by'] = sort_by
        context['search_value'] = search_value
        return context


def user_login(request):
    context = RequestContext(request)
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        user = authenticate(username=username, password=password)

        if user is not None:
            if user.is_active:
                login(request, user)
                return HttpResponseRedirect('/image/')

        else:
            return render_to_response('web/login.html', {}, context)

    else:
        return render_to_response('web/login.html', {}, context)


@login_required
def user_logout(request):
    print "logout"
    logout(request)
    return HttpResponseRedirect('/login/')


@class_view_decorator(login_required)
class SnapshotListView(SearchableListMixin, SortableListMixin, PaginationMixin, ListView):
    template_name = 'web/image_list.html'

    sort_fields = ['id', 'hostname', 'date', 'status']
    search_fields = ['id', 'hostname', 'description', 'filename']

    model = Snapshot
    paginate_by = 20

    def get_queryset(self):
        sort_mode = '-'
        sort_by = 'id'
        search_value = ""
        try:
            if self.request.GET['o']:
                sort_by = self.request.GET['o']

            if self.request.GET['ot'] == 'asc':
                sort_mode = ''

            if self.request.GET['ot'] == 'desc':
                sort_mode = '-'

        except:
            pass

        try:
            if self.request.GET['q']:
                search_value = self.request.GET['q']
        except:
            pass

        if self.request.session.get('filter_whitelisted_images', True):
            return Snapshot.objects.filter(Q(status__lt=5),
                                           Q(id=int(search_value) if isinstance(search_value,
                                                                                (int, long)) else 0) | Q(
                                               hostname__icontains=search_value) | Q(
                                               description__icontains=search_value) | Q(
                                               filename__icontains=search_value)).order_by(sort_mode + sort_by)
        else:
            return Snapshot.objects.filter(Q(id=int(search_value) if isinstance(search_value, (int, long)) else 0) | Q(
                hostname__icontains=search_value) | Q(
                description__icontains=search_value) | Q(
                filename__icontains=search_value)).order_by(sort_mode + sort_by)

    def get_context_data(self, *args, **kwargs):

        sort_mode = 'asc'
        sort_mode_pag = 'asc'
        sort_by = ''
        search_value = ""
        try:
            if self.request.GET['o']:
                sort_by = self.request.GET['o']

            if self.request.GET['ot'] == 'asc':
                sort_mode = 'desc'
                sort_mode_pag = 'asc'

            if self.request.GET['ot'] == 'desc':
                sort_mode = 'asc'
                sort_mode_pag = 'desc'

        except:
            pass

        try:
            if self.request.GET['q']:
                search_value = self.request.GET['q']
        except:
            pass

        context = super(SnapshotListView, self).get_context_data(*args, **kwargs)
        context['sort_mode'] = sort_mode
        context['sort_mode_pag'] = sort_mode_pag
        context['sort_by'] = sort_by
        context['search_value'] = search_value
        context['form'] = SnapshotViewFilterForm()
        context['form'].fields["filter_whitelisted_images"].initial = self.request.session.get(
            'filter_whitelisted_images', True)
        return context


@login_required
def image_filter_whitelisted(request):
    if request.method == 'POST':
        request.session[
            'filter_whitelisted_images'] = True if 'filter_whitelisted_images' in request.POST else False

    return HttpResponseRedirect("/image/")


@login_required
def image_detail_display(request, snapshot_id):
    if request.method == 'POST':
        request.session['filter_anomalies'] = True if 'filter_anomalies' in request.POST else False

    return HttpResponseRedirect("/image/" + str(snapshot_id))


@login_required
def image_details(request, snapshot_id):
    context = RequestContext(request)
    context_dict = {}

    try:
        snapshot = Snapshot.objects.get(pk=snapshot_id)
        context_dict['snapshot'] = snapshot
        context_dict['arch'] = "x86" if snapshot.profile.name.endswith("x86") else "x64"

        if request.method == 'POST':
            form = SnapshotDescForm(request.POST)
            if form.is_valid():
                snapshot.description = form.cleaned_data['description']
                snapshot.save()
                return HttpResponseRedirect("/image/" + str(snapshot.id))

        else:
            context_dict['form'] = SnapshotDescForm()
            context_dict['form'].fields["description"].initial = snapshot.description
            context_dict['display_form'] = SnapshotDetailDispForm()
            context_dict['display_form'].fields["filter_anomalies"].initial = request.session.get('filter_anomalies',
                                                                                                  False)

        # check if there are cached results
        if snapshot.result_cache:
            context_dict['result_set'] = json.loads(snapshot.result_cache)

        else:
            rs = ResultSet(snapshot)

            for process in Process.objects.filter(snapshot=snapshot).order_by('creation_time'):

                try:
                    wl_process = WlProcess.objects.get(path__iexact=process.path, name__iexact=process.name,
                                                       profile=snapshot.profile)
                except WlProcess.DoesNotExist:
                    wl_process = None

                try:
                    det_process = DetProcess.objects.get(process=process)
                except DetProcess.DoesNotExist:
                    det_process = None

                pr = ProcessResult(process, det_process, wl_process)

                rs.process_results.append(pr)

            snapshot.result_cache = rs.to_JSON()
            snapshot.save()

            context_dict['result_set'] = rs

        # Get boot time
        systemProcess = Process.objects.filter(snapshot=snapshot, pid=4)
        context_dict['boot_time'] = \
            Thread.objects.filter(process=systemProcess, created__gt='1970-01-01 00:00:00 UTC+0000') \
                .order_by('created').first().created

    except Snapshot.DoesNotExist:
        return HttpResponseRedirect('/image/')

    return render_to_response('web/image_details.html', context_dict, context)


# helper classes
class ProcessResult():
    def __init__(self, process, det_process, wl_process):
        self.process = process
        self.wl_process = wl_process
        self.det_process = det_process
        self.parent_process = process.parent

        self.connections = Connection.objects.filter(process=process).count()
        self.det_connections = DetConnection.objects.filter(process=process).count()
        self.sids = Sid.objects.filter(process=process).count()
        self.det_sids = DetSid.objects.filter(process=process).count()
        self.dlls = Dll.objects.filter(process=process).count()
        self.det_dlls = DetDll.objects.filter(process=process).count()
        self.handles = Handle.objects.filter(process=process).count()
        self.det_handles = DetHandle.objects.filter(process=process).count()
        self.ldrmodules = Ldrmodule.objects.filter(process=process).count()
        self.det_ldrmodules = DetLdrmodule.objects.filter(process=process).count()
        self.apihooks = Apihook.objects.filter(process=process).count()
        self.det_apihooks = DetApihook.objects.filter(process=process).count()

        self.priorities = []
        for thread in Thread.objects.filter(process=process):
            if thread.base_priority not in self.priorities:
                self.priorities.append(thread.base_priority)

        self.malfind_true_positives = DetMalfind.objects.filter(process=process, is_true_positive=1).count()
        self.malfind_false_positives = DetMalfind.objects.filter(process=process, is_true_positive=0).count()

        self.unknown_command_line = True if det_process and det_process.unknown_command_line else False
        self.unknown_parent = True if det_process and det_process.unknown_parent else False
        self.unknown_number_of_threads = det_process.unknown_number_of_threads if det_process and det_process.unknown_number_of_threads else False
        self.prio_anomaly = True if DetThread.objects.filter(process=process).exists() else False

        self.unknown_number_of_dlls = det_process.unknown_number_of_dlls if det_process and det_process.unknown_number_of_dlls else False
        self.network_anomaly = True if det_process and det_process.network_anomaly else False
        self.unknown_number_of_the_same = det_process.unknown_number_of_the_same if det_process and det_process.unknown_number_of_the_same else False
        self.unknown_process = True if det_process and det_process.unknown_process else False
        if self.prio_anomaly:
            self.wl_prios = []
            for prio in wl_process.wlprio_set.all():
                self.wl_prios.append(prio)
        self.has_anomaly = True if self.det_connections or self.det_sids or self.det_dlls or self.det_ldrmodules \
                                   or self.malfind_true_positives or self.unknown_command_line \
                                   or self.unknown_parent or self.prio_anomaly \
                                   or self.unknown_number_of_dlls or self.unknown_number_of_the_same else False

        self.has_weak_anomaly = True if self.det_handles or self.det_apihooks or self.unknown_process \
                                        or self.unknown_number_of_threads  else False


class ResultSet():
    def __init__(self, snapshot):
        self.process_results = []
        self.registry_keys = Registry.objects.filter(snapshot=snapshot).count()
        self.det_registry_keys = DetRegistry.objects.filter(snapshot=snapshot).count()
        self.callbacks = Callback.objects.filter(snapshot=snapshot).count()
        self.det_callbacks = DetCallback.objects.filter(snapshot=snapshot).count()
        self.drivers = Driver.objects.filter(snapshot=snapshot).count()
        self.det_drivers = DetDriver.objects.filter(snapshot=snapshot).count()
        self.unloaded_modules = UnloadedModules.objects.filter(snapshot=snapshot).count()
        self.det_unloaded_modules = DetUnloadedModules.objects.filter(snapshot=snapshot).count()
        self.timers = Timer.objects.filter(snapshot=snapshot).count()
        self.det_timers = DetTimer.objects.filter(snapshot=snapshot).count()
        self.gdts = Gdt.objects.filter(snapshot=snapshot).count()
        self.det_gdts = DetGdt.objects.filter(snapshot=snapshot).count()
        self.idts = Idt.objects.filter(snapshot=snapshot).count()
        self.det_idts = DetIdt.objects.filter(snapshot=snapshot).count()
        self.files = Filescan.objects.filter(snapshot=snapshot).count()
        self.det_files = DetFile.objects.filter(snapshot=snapshot).count()
        self.modscans = Modscan.objects.filter(snapshot=snapshot).count()
        self.det_modscans = DetModscan.objects.filter(snapshot=snapshot).count()
        self.services = Service.objects.filter(snapshot=snapshot).count()
        self.det_services = DetService.objects.filter(snapshot=snapshot).count()

    def to_JSON(self):
        return json.dumps(self, default=lambda o: o.__dict__,
                          sort_keys=True, indent=4)