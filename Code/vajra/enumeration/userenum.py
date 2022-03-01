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

from os import times
import requests
from sqlalchemy.orm.query import Query
from sqlalchemy.sql.expression import false, true
from vajra import db
from sqlalchemy.sql import text
from vajra.models import ForUserEnum, userenumLogs, validEmails
from email_validator import validate_email, EmailNotValidError

class userenumerate():
    def enum(uuid):
        db.engine.execute(f"UPDATE enumeration_status SET userenum ='True' WHERE uuid = '{uuid}'")
        try:
            emails = ForUserEnum.query.filter_by(uuid=uuid).all()

            for email in emails:
                email = email.emails.replace(" ", "")
                if email == "":
                    continue
                try:
                    valid = validate_email(email)
                    valid.email
                except EmailNotValidError as e:
                    # email is not valid, exception message is human-readable
                    log = (f"<br><span style=\"color:red\">[-] Invalid: {email}</span>" )
                    db.session.add(userenumLogs(uuid=uuid, message=log))
                    db.session.commit()
                    continue

                body = '{"Username":"%s"}' % email
                response = requests.post("https://login.microsoftonline.com/common/GetCredentialType", data=body).json()
                try:
                    if response["IfExistsResult"] == 0:
                        log  = (f"<br><span style=\"color:#7FFFD4\">[+] Valid: {email}</span>" )
                        db.session.add(userenumLogs(uuid=uuid, message=log))
                        validEmail = validEmails(uuid=uuid,email=email)
                        try:
                            db.session.add(validEmail)
                            db.session.commit()
                        except Exception as e:
                            
                            db.session.rollback()
                    else:
                        log= (f"<br><span style=\"color:red\">[-] Invalid: {email}</span>" )
                        db.session.add(userenumLogs(uuid=uuid, message=log))
                        db.session.commit()
                except:
                    pass
        except:
            pass
        db.engine.execute(f"UPDATE enumeration_status SET userenum ='False' WHERE uuid = '{uuid}'")