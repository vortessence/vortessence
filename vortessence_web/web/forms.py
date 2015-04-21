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

from django import forms


class SnapshotDescForm(forms.Form):
    description = forms.CharField(widget=forms.Textarea)


class SnapshotDetailDispForm(forms.Form):
    filter_anomalies = forms.BooleanField(label="Filter for anomalies")


class SnapshotViewFilterForm(forms.Form):
    filter_whitelisted_images = forms.BooleanField(label="Filter whitelisted images")