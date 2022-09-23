

import requests, re
from vajra import db
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
                regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                if re.fullmatch(regex, email) :
                    pass
                else:
                    log = (f"<br><span style=\"color:red\">[-] Invalid: {email}</span>" )
                    db.session.add(userenumLogs(uuid=uuid, message=log))
                    db.session.commit()
                    continue
                print(33)
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