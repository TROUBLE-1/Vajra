# Copyright (C) 2022 Raunak Parmar, @trouble1_raunak
# All rights reserved to Raunak Parmar

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

# This tool is meant for educational purposes only. 
# The creator takes no responsibility of any mis-use of this tool.


import datetime
import json
import collections


DEFAULT_ENCODING = 'utf-8'


def map_nested_dicts(ob, func):
    if isinstance(ob, collections.Mapping):
        return {k: map_nested_dicts(v, func) for k, v in ob.iteritems()}
    else:
        return func(ob)


def json_encoder(o):
    if type(o) is datetime.date or type(o) is datetime.datetime:
        return o.isoformat()

    if isinstance(o, unicode):
        return o.encode('utf-8', errors='ignore')

    if isinstance(o, str):
        return o.encode('utf-8', errors='ignore')


def smart_str(s, encoding=DEFAULT_ENCODING, errors='ignore'):
    """
    Return a byte-string version of 's', encoded as specified in 'encoding'.
    """
    if isinstance(s, unicode):
        return s.encode(encoding, errors)

    # Already a byte-string, nothing to do here
    if isinstance(s, str):
        return s

    return s


def json_write(filename, data):
    data = map_nested_dicts(data, smart_str)

    data_str = json.dumps(data,
                          indent=4,
                          sort_keys=True,
                          default=json_encoder)

    file(filename, 'wb').write(data_str)
