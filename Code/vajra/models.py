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

from email.policy import default
from enum import unique
from itertools import permutations
from vajra import db, login_manager
from flask_login import UserMixin
from sqlalchemy.sql import expression

@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get((user_id))
 
class Admin(db.Model, UserMixin):
    id = db.Column(db.String(), primary_key=True)
    username = db.Column(db.String(200), unique=True)
    email = db.Column(db.String(200), unique=True)
    password = db.Column(db.String(100))
    enableIp = db.Column(db.String(10))
    theme = db.Column(db.String(10))
    ips = db.Column(db.String())


class Allusers(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String())
    id = db.Column(db.String(100))
    displayName = db.Column(db.String(100))
    givenName = db.Column(db.String(100))
    jobTitle = db.Column(db.String(100))
    mail = db.Column(db.String(100))
    mobilePhone = db.Column(db.String(100))
    officeLocation = db.Column(db.String(100))
    preferredLanguage = db.Column(db.String(100))
    surname = db.Column(db.String(100))
    userPrincipalName = db.Column(db.String(100))


class Attachments(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, unique=True, autoincrement=True)
    id = db.Column(db.String())
    receiver = db.Column(db.String())
    sender = db.Column(db.String())
    data = db.Column(db.String())
    filename = db.Column(db.String())
    size = db.Column(db.String())
    date = db.Column(db.String())
    sig = db.Column(db.String())

class StealerConfig(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, unique=True, autoincrement=True)
    client_id = db.Column(db.String(), default="")
    client_secret = db.Column(db.String(), default="")
    redirect_url = db.Column(db.String(), default="")
    redirect_after_stealing = db.Column(db.String(), default="")
    macros = db.Column(db.String(), default="")
    extension = db.Column(db.String(), default="")
    delay = db.Column(db.Integer, default=0)
    phishUrl = db.Column(db.String(), default="")
    stealAll = db.Column(db.String(), default="")
    victimsColleague = db.Column(db.String(), default="")
    oneDrive = db.Column(db.String(), default="")
    oneNote = db.Column(db.String(), default="")
    outlook = db.Column(db.String(), default="")
    noStealing = db.Column(db.String(), default="")
    macroInjection = db.Column(db.String(), default="")


class AddedVictims(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, unique=True, autoincrement=True)
    userPrincipalName = db.Column(db.String())

class sprayingConfig(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, unique=True, autoincrement=True)
    id = db.Column(db.Integer)
    customVictims = db.Column(db.String())
    advanceSpray = db.Column(db.String()) 
    password = db.Column(db.String(), default="")

class sprayingLogs(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, unique=True, autoincrement=True)
    message = db.Column(db.String())

class sprayingResult(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, unique=True, autoincrement=True)
    victim = db.Column(db.String(200))
    password = db.Column(db.String(200))
    errorCode = db.Column(db.String(200))
    message = db.Column(db.String(200))
    endpoint = db.Column(db.String(200))

class bruteforceResult(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, unique=True, autoincrement=True)
    victim = db.Column(db.String(200))
    password = db.Column(db.String(200))
    errorCode = db.Column(db.String(200))
    message = db.Column(db.String(200))
    endpoint = db.Column(db.String(200))

class enumerationdata(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, unique=True, autoincrement=True)
    id = db.Column(db.Integer)
    subdomainWordlist = db.Column(db.String(50))

class bruteforceLogs(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, unique=True, autoincrement=True)
    message = db.Column(db.String())

class phishingLogs(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, unique=True, autoincrement=True)
    message = db.Column(db.String())

class userenumLogs(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, unique=True, autoincrement=True)
    message = db.Column(db.String())

class subdomainLogs(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, unique=True, autoincrement=True)
    message = db.Column(db.String())

class bruteforceConfig(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, unique=True, autoincrement=True)
    id = db.Column(db.Integer)
    usernames = db.Column(db.String())
    passwords = db.Column(db.String())

class ForUserEnum(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, unique=True, autoincrement=True)
    id = db.Column(db.Integer)
    emails = db.Column(db.String(200))

class validEmails(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, unique=True, autoincrement=True)
    id = db.Column(db.Integer)
    email = db.Column(db.String(200))

class Token(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, unique=True, autoincrement=True)
    username = db.Column(db.String())
    refreshtoken = db.Column(db.String())
    clientId = db.Column(db.String())
    clientSecret = db.Column(db.String())
    redirectUrl = db.Column(db.String())


class backupToken(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, unique=True, autoincrement=True)
    username = db.Column(db.String())
    refreshtoken = db.Column(db.String())
    clientId = db.Column(db.String())
    clientSecret = db.Column(db.String())
    redirectUrl = db.Column(db.String())


class OneDrive(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    id = db.Column(db.String(), unique=True )
    username = db.Column(db.String(200))
    data = db.Column(db.String())
    filename = db.Column(db.String())
    date = db.Column(db.String())
    fileSize = db.Column(db.String())
    signature = db.Column(db.String())


class Outlook(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    id = db.Column(db.String(200))
    victim = db.Column(db.String(200))
    username = db.Column(db.String(200))
    Body = db.Column(db.String())
    bodyPreview= db.Column(db.String())
    Sender = db.Column(db.String(200))
    ToRecipients = db.Column(db.String())
    BccRecipients = db.Column(db.String())
    CcRecipients = db.Column(db.String())
    ReplyTo = db.Column(db.String(200))
    Subject = db.Column(db.String(500))
    Flag = db.Column(db.String(10))
    HasAttachments = db.Column(db.String(10))
    date = db.Column(db.String(50))


class OneNote(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    id = db.Column(db.String(200))
    username = db.Column(db.String(200))
    data = db.Column(db.String())
    filename = db.Column(db.String(200))
    date = db.Column(db.String(200))
    fileSize = db.Column(db.String(10))
    signature = db.Column(db.String(200))
         

class Visitors(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    time = db.Column(db.String())
    ip = db.Column(db.String(100))


class AttackStatus(db.Model):
    uuid = db.Column(db.String(), primary_key=True, unique=True)
    phishing = db.Column(db.String(5))
    spraying = db.Column(db.String(5))
    bruteforce = db.Column(db.String(5))

class enumerationStatus(db.Model):
    uuid = db.Column(db.String(),  primary_key=True, unique=True)
    userenum = db.Column(db.String(5))
    subdomain = db.Column(db.String(5))
    azureAdEnum = db.Column(db.String(5))

class azureAdEnumeratedUsers(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    victim = db.Column(db.String())
    id = db.Column(db.String(100))
    displayName = db.Column(db.String())
    givenName = db.Column(db.String())
    jobTitle = db.Column(db.String())
    mail = db.Column(db.String())
    mobilePhone = db.Column(db.String())
    officeLocation = db.Column(db.String(100))
    preferredLanguage = db.Column(db.String(100))
    surname = db.Column(db.String(100))
    userPrincipalName = db.Column(db.String())
    roles = db.Column(db.String())

class azureAdEnumeratedUserProfile(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    victim = db.Column(db.String())
    id = db.Column(db.String(100))
    displayName = db.Column(db.String())
    givenName = db.Column(db.String())
    jobTitle = db.Column(db.String())
    mail = db.Column(db.String())
    mobilePhone = db.Column(db.String())
    officeLocation = db.Column(db.String(100))
    preferredLanguage = db.Column(db.String(100))
    surname = db.Column(db.String(100))
    userPrincipalName = db.Column(db.String())
    groups = db.Column(db.String())
    accessToken = db.Column(db.String())

class azureAdEnumeratedGroups(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    victim = db.Column(db.String())
    id = db.Column(db.String(200))
    description = db.Column(db.String())
    mail = db.Column(db.String())
    displayName = db.Column(db.String())
    ownerName = db.Column(db.String())
    roleAssignment = db.Column(db.String())

class azureAdEnumeratedGroupMembers(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, unique=True, autoincrement=True)
    victim = db.Column(db.String())
    id = db.Column(db.String())
    groupName = db.Column(db.String())
    displayName = db.Column(db.String())
    givenName = db.Column(db.String())
    jobTitle = db.Column(db.String())
    mail = db.Column(db.String())
    mobilePhone = db.Column(db.String())
    officeLocation = db.Column(db.String(100))
    preferredLanguage = db.Column(db.String(100))
    surname = db.Column(db.String()) 
    userPrincipalName = db.Column(db.String())

class azureAdEnumeratedDevices(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    victim = db.Column(db.String())
    deviceName     = db.Column(db.String())
    model          = db.Column(db.String())
    osVersion      = db.Column(db.String())
    deviceId       = db.Column(db.String())
    accountEnabled = db.Column(db.String())
    manufacturer   = db.Column(db.String())
 
class azureAdEnumeratedAdmins(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    victim = db.Column(db.String())
    id                = db.Column(db.Integer)
    directoryRoleName = db.Column(db.String())
    adminName         = db.Column(db.String())

class azureAdEnumeratedCustomDirectoryRoles(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    victim = db.Column(db.String())
    id                = db.Column(db.String())
    directoryRoleName = db.Column(db.String())
    description       = db.Column(db.String())

class azureAdEnumeratedApplications(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    victim = db.Column(db.String())
    appId           = db.Column(db.String())
    identifierUris  = db.Column(db.String())
    appName         = db.Column(db.String())
    publisherDomain = db.Column(db.String())
    signInAudience  = db.Column(db.String())
    appRoles = db.Column(db.String())

class azureAdEnumeratedServicePrinciple(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    victim = db.Column(db.String())
    appDisplayName        = db.Column(db.String())
    id                    = db.Column(db.String())
    homepage              = db.Column(db.String())
    appDescription        = db.Column(db.String())
    servicePrincipalNames = db.Column(db.String())
    signInAudience        = db.Column(db.String())
    keyCredentials        = db.Column(db.String())
    passwordCredentials   = db.Column(db.String())
    replyUrls              = db.Column(db.String()) 

class azureAdEnumeratedConditionalAccessPolicy(db.Model):
    uuid                                        = db.Column(db.String())
    temp                                        = db.Column(db.Integer, primary_key=True, autoincrement=True)
    victim                                      = db.Column(db.String())
    id                                          = db.Column(db.String())
    displayName                                 = db.Column(db.String())
    createdDateTime                             = db.Column(db.String())
    modifiedDateTime                            = db.Column(db.String())
    state                                       = db.Column(db.String())
    sessionControls                             = db.Column(db.String())
    conditions_clientAppTypes                   = db.Column(db.String())
    conditions_platforms	                    = db.Column(db.String())
    conditions_locations	                    = db.Column(db.String())
    conditions_applications_includeApplications	= db.Column(db.String())
    conditions_users_includeUsers	            = db.Column(db.String())
    grantControls_operator	                    = db.Column(db.String())
    grantControls_builtInControls               = db.Column(db.String())


class azureEnumUsers(db.Model):
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid = db.Column(db.String())
    username = db.Column(db.String())

class azureEnumResourcesGroups(db.Model):
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid = db.Column(db.String())
    username = db.Column(db.String())
    resourceGroupName = db.Column(db.String())
    location = db.Column(db.String())
    subscriptionId = db.Column(db.String())

class azureEnumResources(db.Model):
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid = db.Column(db.String())
    username = db.Column(db.String())
    subscriptionId = db.Column(db.String())
    resourceGroupName = db.Column(db.String())
    resourceName = db.Column(db.String())
    type = db.Column(db.String())
    location = db.Column(db.String())

class azureEnumSubscriptions(db.Model):
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid = db.Column(db.String())
    username = db.Column(db.String())
    displayName = db.Column(db.String())
    subscriptionId   = db.Column(db.String())
    state   = db.Column(db.String())
    locationPlacementId   = db.Column(db.String())
    quotaId   = db.Column(db.String())
    spendingLimit   = db.Column(db.String())

class enumerationResults(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    id = db.Column(db.Integer)
    validSubdomain = db.Column(db.String(100))

class SSLCert(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    id = db.Column(db.Integer)
    publicname = db.Column(db.String(100))
    keyname = db.Column(db.String(100))

class azureStorageAccountConfig(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    commonWord = db.Column(db.String(), default="")
    permutations = db.Column(db.String(), default="")

class specificAttackStatus(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    storageAccounts = db.Column(db.String())

class specificAttackStorageLogs(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    message = db.Column(db.String())

class specificAttackStorageResults(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    valid = db.Column(db.String())
