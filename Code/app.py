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

from vajra import app, context, socketio

if '__main__' == __name__:
    socketio.run(app, host='0.0.0.0', port=80, debug=False)
    #app.run(port=80, host="0.0.0.0", debug=False)                                     # For HTTP
    
    #app.run(port=443, host="0.0.0.0", debug=True, ssl_context=context)  # For HTTPS
