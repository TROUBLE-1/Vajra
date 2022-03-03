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

from flask_bcrypt import Bcrypt
from flask import Flask
from sqlite3 import Error  
import sqlite3 , crayons, os
from os.path import exists
import psycopg2

app = Flask(__name__)
bcrypt = Bcrypt(app)


db_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), "vajra", "site.db")
POSTGRES = "postgresql://postgres:postgres@localhost/vajra"

try:
    conn = psycopg2.connect(POSTGRES)
    print(crayons.green("[+] Connected To Database \r\n", bold=True))
except:
    try:
        conn = sqlite3.connect(db_file)
        print(crayons.green("[+] Connected To Database \r\n", bold=True))
    except Error as e:
        print(crayons.red("Error create_connection: " + str(e), bold=True))
        exit()

username = repr(input("Username: "))
password = input("Password: ")

hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
query = f"UPDATE admin set password = '{hashed_password}' WHERE username = {username}"
cur = conn.cursor()
try:
    cur.execute(query)
    conn.commit()
    print(crayons.green("[+] New Account Created and old account have been deleted", bold=True))
except Error as e:
    print(crayons.red("Error: " + str(e), bold=True))