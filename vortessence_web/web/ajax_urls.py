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

from django.conf.urls import patterns, url
from web import ajax_views

urlpatterns = patterns('',
                       url(r'^det_dlls/(?P<process_id>\d+)$', ajax_views.det_dlls, name='det_dlls'),
                       url(r'^det_sids/(?P<process_id>\d+)$', ajax_views.det_sids, name='det_sids'),
                       url(r'^det_ldrmodules/(?P<process_id>\d+)$', ajax_views.det_ldrmodules, name='det_ldrmodules'),
                       url(r'^det_malfinds/(?P<process_id>\d+)$', ajax_views.det_malfinds, name='det_malfinds'),
                       url(r'^det_connections/(?P<process_id>\d+)$', ajax_views.det_connections, name='det_connections'),
                       url(r'^det_handles/(?P<process_id>\d+)$', ajax_views.det_handles, name='det_handles'),
                       url(r'^det_apihooks/(?P<process_id>\d+)$', ajax_views.det_apihooks, name='det_apihooks'),
                       url(r'^det_registry_keys/(?P<snapshot_id>\d+)$', ajax_views.det_registry_keys,
                           name='det_registry_keys'),
                       url(r'^det_callbacks/(?P<snapshot_id>\d+)$', ajax_views.det_callbacks, name='det_callbacks'),
                       url(r'^det_drivers/(?P<snapshot_id>\d+)$', ajax_views.det_drivers, name='det_drivers'),
                       url(r'^det_irps/(?P<driver_id>\d+)$', ajax_views.det_irps, name='det_irps'),
                       url(r'^det_unloaded_modules/(?P<snapshot_id>\d+)$', ajax_views.det_unloaded_modules,
                           name='det_unloaded_modules'),
                       url(r'^det_timers/(?P<snapshot_id>\d+)$', ajax_views.det_timers, name='det_timers'),
                       url(r'^det_gdts/(?P<snapshot_id>\d+)$', ajax_views.det_gdts, name='det_gdts'),
                       url(r'^det_idts/(?P<snapshot_id>\d+)$', ajax_views.det_idts, name='det_idts'),
                       url(r'^det_files/(?P<snapshot_id>\d+)$', ajax_views.det_files, name='det_files'),
                       url(r'^det_modscans/(?P<snapshot_id>\d+)$', ajax_views.det_modscans, name='det_modscans'),
                       url(r'^det_servies/(?P<snapshot_id>\d+)$', ajax_views.det_services, name='det_services'),
                       url(r'^verinfo/(?P<dll_id>\d+)$', ajax_views.verinfo, name='verinfo'),

                       url(r'^w_process_cl/(?P<process_id>\d+)$', ajax_views.w_process_cl, name='w_process_cl'),
                       url(r'^w_process_parent/(?P<process_id>\d+)$', ajax_views.w_process_parent, name='w_process_parent'),
                       url(r'^w_dlls/(?P<wl_process_id>\d+)$', ajax_views.w_dlls, name='w_dlls'),
                       url(r'^w_connections/(?P<wl_process_id>\d+)$', ajax_views.w_connections, name='w_connections'),
                       url(r'^w_ldrmodules/(?P<wl_process_id>\d+)$', ajax_views.w_ldrmodules, name='w_ldrmodules'),
                       url(r'^w_handles/(?P<wl_process_id>\d+)$', ajax_views.w_handles, name='w_handles'),
                       url(r'^w_sids/(?P<wl_process_id>\d+)$', ajax_views.w_sids, name='w_sids'),
                       url(r'^w_malfinds/(?P<wl_process_id>\d+)$', ajax_views.w_malfinds, name='w_malfinds'),
                       url(r'^w_apihooks/(?P<wl_process_id>\d+)$', ajax_views.w_apihooks, name='w_apihooks'),
                       url(r'^w_proc_details/(?P<wl_process_id>\d+)$', ajax_views.w_proc_details, name='w_dlls'),
                       url(r'^w_irps/(?P<wl_driver_id>\d+)$', ajax_views.w_irps, name='w_irps'),

)