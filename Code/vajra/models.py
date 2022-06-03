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
    awsUsage = db.Column(db.Integer, default=0)
    azureUsage = db.Column(db.Integer, default=0)


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
    usersGroups = db.Column(db.String())

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
    enumStatus = db.Column(db.String())

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
    status = db.Column(db.String())

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
    validSubdomain = db.Column(db.String())

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








#################################      AWS         #################################################################

class awsIAMVictims(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    victim = db.Column(db.String(), default="")
    userId = db.Column(db.String(), default="")
    key = db.Column(db.String(), default="")
    secret = db.Column(db.String(), default="")
    session = db.Column(db.String(), default="")
    enumStatus = db.Column(db.String(), default="")

class awsIAMUsers(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    victim = db.Column(db.String(), default="")
    username = db.Column(db.String(), default="")
    arn = db.Column(db.String(), default="")
    userId = db.Column(db.String(), default="")
    createdate = db.Column(db.String(), default="")
    passwordLastUsed = db.Column(db.String(), default="")
    groupName = db.Column(db.String(), default="")
    inlineUserPolicy = db.Column(db.String(), default="")
    attachedUserPolicy = db.Column(db.String(), default="")
    Certificates = db.Column(db.String(), default="")
    sshPublicKey = db.Column(db.String(), default="")
    MFADevices = db.Column(db.String(), default="")
    loginProfile = db.Column(db.String(), default="")


class awsIAMGroups(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    victim = db.Column(db.String(), default="")
    groupName = db.Column(db.String(), default="")
    members = db.Column(db.String(), default="")
    groupId = db.Column(db.String(), default="")
    arn = db.Column(db.String(), default="")
    createDate = db.Column(db.String(), default="")
    policyName = db.Column(db.String(), default="")



class awsEc2(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    victim = db.Column(db.String(), default="")
    jsonOutput = db.Column(db.String(), default="")
    instancesId = db.Column(db.String(), default="")
    instancesState = db.Column(db.String(), default="")
    instancesType = db.Column(db.String(), default="")
    statusCheck = db.Column(db.String(), default="")
    alarmStatus = db.Column(db.String(), default="")
    availabilityZone = db.Column(db.String(), default="")
    publicIPv4DNS = db.Column(db.String(), default="")
    publicIPv4Address = db.Column(db.String(), default="")
    elasticIP = db.Column(db.String(), default="")
    ipv6IPs = db.Column(db.String(), default="")
    monitoring = db.Column(db.String(), default="")
    securityGroupName = db.Column(db.String(), default="")
    keyname = db.Column(db.String(), default="")
    launchTime = db.Column(db.String(), default="")

class awsIAMRolePolicies(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    victim = db.Column(db.String(), default="")
    roleName = db.Column(db.String(), default="")
    policyName = db.Column(db.String(), default="")
    inlinePolicies = db.Column(db.String(), default="")
    jsonBody = db.Column(db.String(), default="")

class awsIAMPolicies(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    victim = db.Column(db.String(), default="")
    policyName = db.Column(db.String(), default="")
    policyId = db.Column(db.String(), default="")
    arn = db.Column(db.String(), default="")
    jsonBody = db.Column(db.String(), default="")

class awsCognitoUserPool(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    victim = db.Column(db.String(), default="")
    id = db.Column(db.String(), default="")
    name = db.Column(db.String(), default="")
    lambdaConfig = db.Column(db.String(), default="")
    lastModifiedDate = db.Column(db.String(), default="")
    creationDate = db.Column(db.String(), default="")
    json_identity_providers = db.Column(db.String(), default="")

class awsS3(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    victim = db.Column(db.String(), default="")
    bucketName = db.Column(db.String(), default="")
    isPublic = db.Column(db.String(), default="")
    acl = db.Column(db.String(), default="")
    policy = db.Column(db.String(), default="")


class awsLambda(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    victim = db.Column(db.String(), default="")
    jsonBody = db.Column(db.String(), default="")
    functionName = db.Column(db.String(), default="")
    arn = db.Column(db.String(), default="")
    runtime = db.Column(db.String(), default="")
    description = db.Column(db.String(), default="")
    zipFile =  db.Column(db.String(), default="")


class awsEC2SS(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    victim = db.Column(db.String(), default="")
    jsonBody = db.Column(db.String(), default="")
    Description = db.Column(db.String(), default="")
    Encrypted = db.Column(db.String(), default="")
    KmsKeyId = db.Column(db.String(), default="")
    OwnerId = db.Column(db.String(), default="")
    Progress = db.Column(db.String(), default="")
    SnapshotId = db.Column(db.String(), default="")
    StartTime = db.Column(db.String(), default="")
    State = db.Column(db.String(), default="")
    VolumeId = db.Column(db.String(), default="")
    VolumeSize = db.Column(db.String(), default="")

class awsSecurityGroups(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    victim = db.Column(db.String(), default="")
    groupName = db.Column(db.String(), default="")
    vpcId = db.Column(db.String(), default="")
    Description = db.Column(db.String(), default="")
    GroupId = db.Column(db.String(), default="")
    jsonBody = db.Column(db.String(), default="")
    adminPorts = db.Column(db.String(), default="")

class awsVPCs(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    victim = db.Column(db.String(), default="")
    vpcId = db.Column(db.String())
    CidrBlock = db.Column(db.String())
    DhcpOptionsId = db.Column(db.String())
    IsDefault = db.Column(db.String())
    jsonBody = db.Column(db.String())

class awsRoute53(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    victim = db.Column(db.String(), default="")
    zoneId = db.Column(db.String())
    Name = db.Column(db.String())
    CallerReference = db.Column(db.String())
    Config = db.Column(db.String())
    ResourceRecordSetCount = db.Column(db.String())
    RecordSets = db.Column(db.String())

class awsbeanstalk(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    victim = db.Column(db.String(), default="")
    ApplicationName = db.Column(db.String())
    DateCreated = db.Column(db.String())
    jsonOutput  = db.Column(db.String())


class awsECR(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    victim = db.Column(db.String(), default="")
    repositoryArn = db.Column(db.String(), default="")
    registryId = db.Column(db.String(), default="")
    repositoryName = db.Column(db.String(), default="")
    repositoryUri = db.Column(db.String(), default="")
    createdAt = db.Column(db.String(), default="")
    imageTagMutability = db.Column(db.String(), default="")
    jsonBody = db.Column(db.String(), default="")

class awsEKS(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    victim = db.Column(db.String(), default="")
    cluster = db.Column(db.String(), default="")


class awsECS(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    victim = db.Column(db.String(), default="")
    clusterArn = db.Column(db.String(), default="")


class awsEFS(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    victim = db.Column(db.String(), default="")
    FileSystemId = db.Column(db.String(), default="")
    FileSystemArn = db.Column(db.String(), default="")
    CreationTime = db.Column(db.String(), default="")
    LifeCycleState = db.Column(db.String(), default="")
    Name = db.Column(db.String(), default="")
    SizeInBytes = db.Column(db.String(), default="")
    jsonBody = db.Column(db.String(), default="")

class awsStorageGateway(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    victim = db.Column(db.String(), default="")
    GatewayId = db.Column(db.String(), default="")
    GatewayARN = db.Column(db.String(), default="")
    GatewayType = db.Column(db.String(), default="")
    GatewayOperationalState = db.Column(db.String(), default="")
    GatewayName = db.Column(db.String(), default="")
    Ec2InstanceId = db.Column(db.String(), default="")
    Ec2InstanceRegion = db.Column(db.String(), default="")
    HostEnvironment = db.Column(db.String(), default="")
    HostEnvironmentId = db.Column(db.String(), default="")
    jsonBody = db.Column(db.String(), default="")

class awsCloudFront(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    victim = db.Column(db.String(), default="")
    ARN = db.Column(db.String(), default="")
    DomainName = db.Column(db.String(), default="")
    Status = db.Column(db.String(), default="")
    jsonBody = db.Column(db.String(), default="")

class aws_config(db.Model):
    uuid = db.Column(db.String(), default="")
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    victim = db.Column(db.String(), default="")
    checkNo = db.Column(db.Integer, default="")
    checkTitle = db.Column(db.String(), default="")
    status = db.Column(db.String(), default="")
    result = db.Column(db.String(), default="")
    arn   = db.Column(db.String(), default="")    

class awsConfigVictims(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    victim = db.Column(db.String(), default="")
    userId = db.Column(db.String(), default="")
    key = db.Column(db.String(), default="")
    secret = db.Column(db.String(), default="")
    session = db.Column(db.String(), default="")
    configStatus = db.Column(db.String(), default="")

class awsS3Scanner(db.Model):
    uuid = db.Column(db.String())
    temp = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(), default="")
    valid = db.Column(db.String(), default="")
    permutations = db.Column(db.String(), default="")
    progress = db.Column(db.String(), default="")
