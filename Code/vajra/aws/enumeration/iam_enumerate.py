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

import threading, json, time
from vajra import db
from vajra.models import *
from vajra.aws.enumeration.function import osCommand
from vajra.aws.enumeration.utils.json_utils import json_encoder

def public_ssh_keys_for_user(uuid, username, profile):
    res = osCommand(uuid, f"aws iam list-ssh-public-keys --user-name {username} --profile {profile}")
    try:
        res["SSHPublicKeys"]
    except:
        return

    for data in res["SSHPublicKeys"]:
        username = "UserName: " + data["UserName"]
        SSHPublicKeyId = "SSHPublicKeyId: " + data["SSHPublicKeyId"]
        Status = "Status: " + data["Status"]
        UploadDate = "UploadDate: " + data["UploadDate"]
        sshkey = osCommand(uuid, f"aws iam get-ssh-public-key --user-name {username} --encoding PEM --ssh-public-key-id {SSHPublicKeyId} --profile {profile}")["SSHPublicKey"]
        
        SSHPublicKey = username + "\r\n" + SSHPublicKeyId + "\r\n" + sshkey["Fingerprint"] + "\r\n" + sshkey["SSHPublicKeyBody"] + "\r\n" + Status + "\r\n" + UploadDate 
        iamUser = awsIAMUsers.query.filter_by(uuid=uuid, username=username).first()
        iamUser.sshPublicKey = SSHPublicKey
        db.session.commit()


def users_signing_certificates(uuid, username, profile):
    res =  osCommand(uuid, f"aws iam list-signing-certificates --user-name {username} --profile {profile}")
    try:
        res["Certificates"]
    except:
        return

    for data in res["Certificates"]:
        username            = "UserName: " + data["UserName"]
        Status          = "Status: " + data["Status"]
        CertificateBody = "CertificateBody: " + data["CertificateBody"]
        CertificateId   = "CertificateId: " + data["CertificateId"]
        UploadDate      = "UploadDate: " +  data["UploadDate"]

        Certificates = username + "\r\n" + Status + "\r\n" + CertificateBody + "\r\n" + CertificateId + "\r\n" + UploadDate + "\r\n" 
        iamUser = awsIAMUsers.query.filter_by(uuid=uuid, username=username).first()
        iamUser.Certificates = Certificates
        try:
            db.session.commit()
        except:
            db.session.rollback()

def iam_policies(uuid, victim, client):
    try:
        policies = client.list_policies(Scope='Local')
    except:
        return    
    for policy in policies["Policies"]:
        PolicyName = policy["PolicyName"]
        PolicyId = policy["PolicyId"]
        Arn = policy["Arn"]
        jsonBody = json.dumps(policy, indent=4, default=json_encoder)
        db.session.add(awsIAMPolicies(uuid=uuid, victim=victim, policyName=PolicyName, policyId=PolicyId, arn=Arn, jsonBody=jsonBody))

    db.session.commit()

def iam_roles(uuid, victim, client):
    RoleDetailList = client.list_roles()

    def get_role_policy(uuid, victim, client, RoleName):
        RolePolicyList = "\r\n".join(client.list_role_policies(RoleName=RoleName)["PolicyNames"])
        policy = awsIAMRolePolicies.query.filter_by(uuid=uuid, victim=victim, roleName=RoleName).first()
        policy.inlinePolicies = RolePolicyList
        db.session.commit()

    def get_attached_role_policy(uuid, victim, client, RoleName):
        AttachedPolicies = []
        Policies = client.list_attached_role_policies(RoleName=RoleName)
        for policy in Policies["AttachedPolicies"]:
            AttachedPolicies.append(policy["PolicyArn"])

        AttachedPolicies = "\r\n".join(AttachedPolicies)

        policy = awsIAMRolePolicies.query.filter_by(uuid=uuid, victim=victim, roleName=RoleName).first()
        policy.policyName = AttachedPolicies
        db.session.commit()

    for role in RoleDetailList["Roles"]:
        RoleName = role["RoleName"]
        detailed = json.dumps(role, indent=4, default=json_encoder)
        db.session.add(awsIAMRolePolicies(uuid=uuid, victim=victim, roleName=RoleName, jsonBody=detailed))
        db.session.commit()
        threading.Thread(target=get_role_policy, args=(uuid, victim, client, RoleName)).start()
        threading.Thread(target=get_attached_role_policy, args=(uuid, victim, client, RoleName)).start()
        time.sleep(0.2)

def iam_groups(uuid, victim, GroupDetailList, UserDetailList, client):
    
    for group in GroupDetailList:
        groupName = group["GroupName"]
        groupId = group["GroupId"]
        arn = group["Arn"]
        createDate = group["CreateDate"]
        policies = []
        attachedManagedPolicies = client.list_attached_group_policies(GroupName=groupName)
        for policy in attachedManagedPolicies["AttachedPolicies"]:
            policies.append(policy["PolicyArn"])

        policies = "\r\n".join(policies)

        members = []
        for user in UserDetailList:
            if groupName in user["GroupList"]:
                members.append(user["UserName"])

        members = "\r\n".join(members)
        groups = awsIAMGroups(uuid=uuid, victim=victim, groupName=groupName, groupId=groupId, arn=arn, createDate=createDate, policyName=policies, members=members)
        db.session.add(groups)

    db.session.commit()    

def iam_users(uuid, victim, UserDetailList, client):
    def inline_user_policy(uuid, victim, username, client):
        policy = client.list_user_policies(UserName=username)["PolicyNames"]
        policy = "\r\n".join(policy)
        user = awsIAMUsers.query.filter_by(uuid=uuid, victim=victim, username=username).first()
        user.inlineUserPolicy = policy
        db.session.commit()

    def get_login_profile(uuid, victim, username, client):

        try:
            client.get_login_profile(UserName=username)["LoginProfile"]["UserName"]
            iamUser = awsIAMUsers.query.filter_by(uuid=uuid, victim=victim, username=username).first()
            iamUser.loginProfile = "True"
            db.session.commit()
        except:
            return  

    
    for data in UserDetailList:
        username = data["UserName"]
        userId   = data["UserId"]
        arn      = data["Arn"]
        createDate = data["CreateDate"]
        groupList = "\r\n".join(data["GroupList"])
        attachedManagedPolicies = []

        for policy in data["AttachedManagedPolicies"]:
            attachedManagedPolicies.append(policy["PolicyArn"])
        attachedManagedPolicies = "\r\n".join(attachedManagedPolicies)
        try:
            passwordLastUsed = data["PasswordLastUsed"]
        except:
            passwordLastUsed = ""

        db.session.add(awsIAMUsers(uuid=uuid, victim=victim, username=username, userId=userId, arn=arn, createdate=createDate, passwordLastUsed=passwordLastUsed, groupName=groupList, attachedUserPolicy=attachedManagedPolicies))
        db.session.commit()

        threading.Thread(target=inline_user_policy, args=(uuid, victim, username, client)).start()
        threading.Thread(target=get_login_profile, args=(uuid, victim, username, client)).start()
        time.sleep(0.2)
    