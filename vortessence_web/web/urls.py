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
from web import views

urlpatterns = patterns('',
                       url(r'^$', views.index, name='dashboard'),
                       url(r'^login/$', views.user_login, name='login'),
                       url(r'^logout/$', views.user_logout, name='logout'),
                       url(r'^image/$', views.SnapshotListView.as_view(), name='images'),
                       url(r'^image/(?P<snapshot_id>\d+)/$', views.image_details, name='image_details'),
                       url(r'^image_detail_display/(?P<snapshot_id>\d+)/$', views.image_detail_display,
                           name='image_detail_display'),
                       url(r'^image_filter_whitelisted/$', views.image_filter_whitelisted,
                           name='image_filter_whitelisted'),
                       url(r'^tools/$', views.LogListView.as_view(), name='tools'),
                       url(r'^whitelist/$', views.whitelist, name="whitelist"),
                       url(r'^whitelist/processes/$', views.WhitelistProcessListView.as_view(),
                           name="whitelist_processes"),
                       url(r'^whitelist/callbacks/$', views.WhitelistCallbacksListView.as_view(),
                           name="whitelist_callbacks"),
                       url(r'^whitelist/drivers/$', views.WhitelistDriversListView.as_view(), name="whitelist_drivers"),
                       url(r'^whitelist/files/$', views.WhitelistFileListView.as_view(), name="whitelist_files"),
                       url(r'^whitelist/gdts/$', views.WhitelistGdtListView.as_view(), name="whitelist_gdts"),
                       url(r'^whitelist/idts/$', views.WhitelistIdtListView.as_view(), name="whitelist_idts"),
                       url(r'^whitelist/modules/$', views.WhitelistModulesListView.as_view(), name="whitelist_modules"),
                       url(r'^whitelist/unloadedmodules/$', views.WhitelistUnloadedModulesListView.as_view(),
                           name="whitelist_unloadedmodules"),
                       url(r'^whitelist/services/$', views.WhitelistServicesListView.as_view(),
                           name="whitelist_services"),
                       url(r'^whitelist/ssdts/$', views.WhitelistSsdtListView.as_view(), name="whitelist_ssdts"),
                       url(r'^whitelist/timers/$', views.WhitelistTimerListView.as_view(), name="whitelist_timers"),
                       url(r'^whitelist/registry/$', views.WhitelistRegistryListView.as_view(),
                           name="whitelist_registry"),
)