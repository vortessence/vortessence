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

from django import template
from utils import fmtspec

register = template.Library()

# copied from volatility
def _formatlookup(profile, code):
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
# Django template filters just accept one argument, os the format and the profile have to be concatenated with a .
@register.filter(name='format_value')
def format_value(value, format):
    formats = format.split(".")
    fmt = formats[0]
    profile = formats[1] if len(formats) > 1 else "Win7SP1x86"
    """ Formats an individual field using the table formatting codes"""
    return ("{0:" + _formatlookup(profile, fmt) + "}").format(value)
