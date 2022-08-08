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

import boto3, json, threading, os
from botocore.client import Config
from botocore.endpoint import MAX_POOL_CONNECTIONS
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from vajra.aws.enumeration.utils.json_utils import json_encoder
from vajra import db
from vajra.models import aws_config, awsConfigVictims
import pandas as pd
import sqlite3 as sqlite
from vajra import db, DB_PATH


BASE_PATH = os.path.dirname(os.path.realpath(__file__))
engine = sqlite.connect(DB_PATH)


regions = ["eu-north-1","ap-south-1","eu-west-3","eu-west-2","eu-west-1","ap-northeast-3", "ap-northeast-2","ap-northeast-1","sa-east-1","ca-central-1","ap-southeast-1", "ap-southeast-2","eu-central-1","us-east-1","us-east-2","us-west-1","us-west-2",]
ports = ( 1414, 1364, 15672, 7474, 8200, 50000, 6379, 1521, 27017, 3306, 1433, 11211, 3306, 156, 50000, 6379, 1521, 27017, 3306, 1433, 11211, 3306, 156, 8080, 8443, 8005, 8009, 8080, 8181, 4848, 8080, 9000, 8008, 8080, 9990, 7001, 9043, 9060, 9080, 9443, 8080, 1527, 7777, 4443, 8080, 4848, 8080, 8181, 3700, 3820, 3920, 8686 )

def insert_results(uuid, victim, checkNo, checkTitle, status, result, arn):

    config = aws_config(uuid=uuid, victim=victim, checkNo=float(checkNo), checkTitle=checkTitle, status=status, result=result, arn=arn)
    db.session.add(config)
    db.session.commit()


def get_client(access_key, secret_key, session_token, service_name, region):
    key = '%s-%s-%s-%s-%s' % (access_key, secret_key, session_token, service_name, region)

    config = Config(connect_timeout=60,
                    read_timeout=180,
                    retries={'max_attempts': 30},
                    max_pool_connections=MAX_POOL_CONNECTIONS * 2)

    try:
        client = boto3.client(
            service_name,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token,
            region_name=region,
            config=config,
        )
    except Exception as e:
        # The service might not be available in this region
        print(e)
        return
        
    return client


def get_iso_format_date(date):
    date_format = "%Y-%m-%d"
    return datetime.strptime(datetime.fromisoformat(str(datetime.fromisoformat(date))).strftime("%Y-%m-%d"), date_format)


def iam(uuid, victim, client):
    print("started")
    try:
        client.generate_credential_report()
    except:
        insert_results(uuid, victim, 1, "IAM", "AccessDenied", "", "")
        return

    while True:
        try:
            credential_report = (client.get_credential_report()["Content"]).decode("utf-8")
            break
        except Exception as e:
            if "ReportInProgress" in str(e):
                   continue

    credential_report = (client.get_credential_report()["Content"]).decode("utf-8")
    def check1_1(uuid, victim):                                             # Avoid the use of the "root" accoun
        report = credential_report.splitlines()
        report.pop(0)
        for line in report:
            if "<root_account>" in line:
                array =  line.split(",")
                date_format = "%Y-%m-%d"
                last_used = get_iso_format_date(array[4])
                now = datetime.strptime(datetime.now().strftime("%Y-%m-%d"), date_format)
                difference = (now - last_used).days
                checkNo = "1.1"
                checkTitle = "Avoid the use of the \"root\" account"
                arn = array[1]
                result = ""
                if difference < 30:                    
                    status = "Non-Compliant"
                    result = "Root used being used!"
                    insert_results(uuid, victim, checkNo, checkTitle, status, result, arn)
                else:
                    insert_results(uuid, victim, checkNo, checkTitle, "Compliant", result, arn)


    def check1_2(uuid, victim):                                               # Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password
        report = credential_report.splitlines()
        report.pop(0)
        for line in report:
            array =  line.split(",")
            arn = array[1]
            checkNo = "1.2"
            checkTitle = "Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password"
            if array[3] == "true" and array[7] == "false":
                status = "Non-Compliant"
                result = "Mfa Not enabled!"
                insert_results(uuid, victim, checkNo, checkTitle, status, result, arn)
            else:
                insert_results(uuid, victim, checkNo, checkTitle, "Compliant", "", arn)

    def check1_3(uuid, victim):                                                # Ensure credentials unused for 90 days or greater are disabled
        report = credential_report.splitlines()
        report.pop(0)
        for line in report:
            array =  line.split(",")
            pass_last_used = array[4]
            try:
                last_used = get_iso_format_date(pass_last_used)
                now = datetime.strptime(datetime.now().strftime("%Y-%m-%d"), "%Y-%m-%d")
            except:
                continue
            difference = (now - last_used).days
            arn = array[1]
            checkNo = "1.3"
            checkTitle = "Ensure credentials unused for 90 days or greater are disabled"
            if difference > 90:
                status = "Non-Compliant"
                result = f"Credential unused for {difference} days."
                insert_results(uuid, victim, checkNo, checkTitle, status, result, arn)
            else:
                insert_results(uuid, victim, checkNo, checkTitle, "Compliant", "", arn)



    def check1_4(uuid, victim):                                                   # Ensure access keys are rotated every 90 days or less
        checkNo = "1.4"
        checkTitle = "Ensure access keys are rotated every 90 days or less"
        report = credential_report.splitlines()
        report.pop(0)
        for line in report:
            array =  line.split(",")
            # access_key_1
            try:
                arn = array[1]
                access_key_1_last_rotated = get_iso_format_date(array[9])
                now = datetime.strptime(datetime.now().strftime("%Y-%m-%d"), "%Y-%m-%d")
                difference = (now - access_key_1_last_rotated).days
                if difference > 90:
                    status = "Non-Compliant"
                    result = f"Access_key_1_last_rotated: {difference}"
                    insert_results(uuid, victim, checkNo, checkTitle, status, result, arn)
                else:
                    insert_results(uuid, victim, checkNo, checkTitle, "Compliant", f"Access_key_1_last_rotated: {array[9]}", arn)
            except:
                insert_results(uuid, victim, checkNo, checkTitle, "Compliant", f"Access_key_1_last_rotated: {array[9]}", arn)

            # access_key_2
            try:
                arn = array[1]
                access_key_2_last_rotated = get_iso_format_date(array[14])
                now = datetime.strptime(datetime.now().strftime("%Y-%m-%d"), "%Y-%m-%d")
                difference = (now - access_key_2_last_rotated).days
                if difference > 90:
                    status = "Non-Compliant"
                    result = f"Access_key_2_last_rotated: {difference}"
                    insert_results(uuid, victim, checkNo, checkTitle, status, result, arn)
                else:
                    insert_results(uuid, victim, checkNo, checkTitle, "Compliant", f"Access_key_2_last_rotated: {array[14]}", arn)
            except:
                insert_results(uuid, victim, checkNo, checkTitle, "Compliant", f"Access_key_2_last_rotated: {array[14]}", arn)


    def check1_5(uuid, victim, client):                                                   # Ensure IAM password policy requires at least one uppercase letter
        checkNo = "1.5"
        checkTitle = "Ensure IAM password policy requires at least one uppercase letter"
        try:
            try:
                res = client.get_account_password_policy()
            except:
                insert_results(uuid, victim, checkNo, checkTitle, "AccessDenied", "", "")
                return

            if res["PasswordPolicy"]["RequireUppercaseCharacters"] != True:
                insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", "", "")
            else:
                insert_results(uuid, victim, checkNo, checkTitle, "Compliant", "", "")
        except:
            insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", "The Password Policy cannot be found", "")



    def check1_6(uuid, victim, client):                                                    # Ensure IAM password policy require at least one lowercase letter
        checkNo = "1.6"
        checkTitle = "Ensure IAM password policy require at least one lowercase letter"
        try:
            try:
                res = client.get_account_password_policy()
            except:
                insert_results(uuid, victim, checkNo, checkTitle, "AccessDenied", "", "")
                return

            if res["PasswordPolicy"]["RequireLowercaseCharacters"] != True:
                insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", "", "")
            else:
                insert_results(uuid, victim, checkNo, checkTitle, "Compliant", "", "")
        except:
            insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", "The Password Policy cannot be found", "")


    def check1_7(uuid, victim, client):                                                    # Ensure IAM password policy require at least one symbol
        checkNo = "1.7"
        checkTitle = "Ensure IAM password policy require at least one symbol"
        try:
            try:
                res = client.get_account_password_policy()
            except:
                insert_results(uuid, victim, checkNo, checkTitle, "AccessDenied", "", "")
                return    
            if res["PasswordPolicy"]["RequireSymbols"] != True:
                insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", "", "")
            else:
                insert_results(uuid, victim, checkNo, checkTitle, "Compliant", "", "")
        except:
            insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", "The Password Policy cannot be found", "")


    def check1_8(uuid, victim, client):                                                    # Ensure IAM password policy require at least one number
        checkNo = "1.7"
        checkTitle = "Ensure IAM password policy require at least one number"
        try:
            try:
                res = client.get_account_password_policy()
            except:
                insert_results(uuid, victim, checkNo, checkTitle, "AccessDenied", "", "")
                return

            if res["PasswordPolicy"]["RequireNumbers"] != True:
                insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", "", "")
            else:
                insert_results(uuid, victim, checkNo, checkTitle, "Compliant", "", "")
        except:
            insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", "The Password Policy cannot be found", "")

    def check1_9(uuid, victim, client):                                                    # Ensure IAM password policy requires minimum length of 14 or greater
        checkNo = "1.9"
        checkTitle = "Ensure IAM password policy requires minimum length of 14 or greater"
        try:
            try:
                res = client.get_account_password_policy()
            except:
                insert_results(uuid, victim, checkNo, checkTitle, "AccessDenied", "", "")
                return

            if res["PasswordPolicy"]["MinimumPasswordLength"] < 23:
                insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", "", "")
            else:
                insert_results(uuid, victim, checkNo, checkTitle, "Compliant", "", "")
        except:
            insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", "The Password Policy cannot be found", "")


    def check1_10(uuid, victim, client):                                                    #  Ensure IAM password policy prevents password reuse
        checkNo = "1.10"
        checkTitle = " Ensure IAM password policy prevents password reuse"
        try:
            try:
                res = client.get_account_password_policy()
            except:
                insert_results(uuid, victim, checkNo, checkTitle, "AccessDenied", "", "")
                return

            if res["PasswordPolicy"]["PasswordReusePrevention"] != 24:
                result = "PasswordReusePrevention should be 24"
                insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", result, "")
            else:
                insert_results(uuid, victim, checkNo, checkTitle, "Compliant", "", "")
        except:
            insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", "The Password Policy cannot be found", "")


    def check1_11(uuid, victim, client):                                                    # Ensure IAM password policy expires passwords within 90 days or less
        checkNo = "1.11"
        checkTitle = "Ensure IAM password policy expires passwords within 90 days or less"
        try:
            try:
                res = client.get_account_password_policy()
            except:
                insert_results(uuid, victim, checkNo, checkTitle, "AccessDenied", "", "")
                return

            if res["PasswordPolicy"]["MaxPasswordAge"] > 90:
                result = "MaxPasswordAge should be <= 90"
                insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", result, "")
            else:
                insert_results(uuid, victim, checkNo, checkTitle, "Compliant", "", "")
        except:
            insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", "The Password Policy cannot be found", "")


    def check1_12(uuid, victim):                                                    # Ensure no root account access key exists
        checkNo = "1.12"
        checkTitle = "Ensure no root account access key exists"
        report = credential_report.splitlines()
        report.pop(0)
        for line in report:
            array =  line.split(",")
            if "<root_account>" == array[0]:
                arn = array[1]
                key_1 = array[9]
                key_2 = array[14]
                if key_1 != False:
                    insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", "Access Key 1 found!", arn)
                else:
                    insert_results(uuid, victim, checkNo, checkTitle, "Compliant", "", arn)

                if key_2 != False:
                    insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", "Access Key 1 found!", arn)
                else:
                    insert_results(uuid, victim, checkNo, checkTitle, "Compliant", "", arn)

    def check1_13(uuid, victim):                                                    # Ensure MFA is enabled for the "root" account
        checkNo = "1.13"
        checkTitle = "Ensure MFA is enabled for the \"root\" account"
        report = credential_report.splitlines()
        report.pop(0)
        for line in report:
            array =  line.split(",")
            if "<root_account>" == array[0]:
                arn = array[1]
                mfa = array[7]
                if mfa == True:
                    insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", "Mfa Not enabled for \"root\"", arn)
                else:
                    insert_results(uuid, victim, checkNo, checkTitle, "Compliant", "", arn)
                
    def check1_14(uuid, victim, client):                                                    # Ensure hardware MFA is enabled for the "root" account
        checkNo = "1.14"
        checkTitle = "Ensure hardware MFA is enabled for the \"root\" account"
    
        try:
            res = client.list_virtual_mfa_devices()
        except:
            insert_results(uuid, victim, checkNo, checkTitle, "AccessDenied", "", "")
            return

        for VirtualMFADevices in res["VirtualMFADevices"]:
            serial = VirtualMFADevices["SerialNumber"]
            if "root-account-mfa-device" in serial:
                insert_results(uuid, victim, checkNo, checkTitle, "Compliant", "Hardware MFA enabled for \"root\"", serial)
                return

            insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", "Hardware Mfa Not enabled for \"root\"", serial)

    def check1_15(uuid, victim):                                                     # Ensure security questions are registered in the AWS account
        checkNo = "1.15"
        checkTitle = "Ensure security questions are registered in the AWS account"
        result = '''1. Login to the AWS account as root
2. On the top right you will see the <Root_Account_Name>
3. Click on the <Root_Account_Name>
4. From the drop-down menu Click My Account
5. In the Configure Security Challenge Questions section on the Personal Information page, configure three security challenge questions.
6. Click Save questions.'''

        insert_results(uuid, victim, checkNo, checkTitle, "N/A", result, "")


    def check1_16(uuid, victim, client):                                                     # Ensure IAM policies are attached only to groups or roles

        def check_attached_policy(client, username):
            checkNo = "1.16"
            checkTitle = "Ensure IAM policies are attached only to groups or roles"
            
            try:
                res = client.list_attached_user_policies(UserName=username)
            except:
                insert_results(uuid, victim, checkNo, checkTitle, "AccessDenied", "", "")
                return

            if res["AttachedPolicies"] != []:
                jsonBody = json.dumps(res["AttachedPolicies"][0], indent=4, default=json_encoder)
                insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", jsonBody, username)
            
            else:
                insert_results(uuid, victim, checkNo, checkTitle, "Compliant", "", username)

        report = credential_report.splitlines()[2:]

        processes = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            for line in report:
                array =  line.split(",")
                username = array[0]
                processes.append(executor.submit(check_attached_policy, client, username))

        for task in as_completed(processes):
            (task.result())

        

        #insert_results(uuid, victim, checkNo, checkTitle, "N/A", "", "")

    def check1_17(uuid, victim):                                                     # Maintain current contact details
        checkNo = "1.17"
        checkTitle = "Maintain current contact details"
        result = '''This activity can only be performed via the AWS Console, with a user who has permissionto read and write Billing information (aws-portal:*Billing ).

•	Sign in to the AWS Management Console and open the Billing and Cost Management console at https://console.aws.amazon.com/billing/home#/. 
•	On the navigation bar, choose your account name, and then choose My Account. 
•	On the Account Settings page, review and verify the current details. 
•	Under Contact Information, review and verify the current details. Remediation: 

This activity can only be performed via the AWS Console, with a user who has permission to read and write Billing information (aws-portal:*Billing ). 

•	Sign in to the AWS Management Console and open the Billing and Cost Management console at https://console.aws.amazon.com/billing/home#/. 
•	On the navigation bar, choose your account name, and then choose My Account. 
•	On the Account Settings page, next to Account Settings, choose Edit. 
•	Next to the field that you need to update, choose Edit. 
•	After you have entered your changes, choose Save changes. 
•	After you have made your changes, choose Done. 
•	To edit your contact information, under Contact Information, choose Edit. 
•	For the fields that you want to change, type your updated information, and then choose Update.
'''

        insert_results(uuid, victim, checkNo, checkTitle, "N/A", result, "")



    def check1_18(uuid, victim):                                                     # Ensure security contact information is registered
        checkNo = "1.18"
        checkTitle = "Ensure security contact information is registered"
        result = '''Perform the following in the AWS Management Console to determine if security contact information is present:

1. Click on your account name at the top right corner of the console
2. From the drop-down menu Click My Account
3. Scroll down to the Alternate Contacts section
4. Ensure contact information is specified in the Security section'''

        insert_results(uuid, victim, checkNo, checkTitle, "N/A", result, "")

    def check1_19(uuid, victim):                                                     # Ensure IAM instance roles are used for AWS resource access from instances
        checkNo = "1.19"
        checkTitle = "Ensure IAM instance roles are used for AWS resource access from instances"
        result = '''Whether an Instance Is Associated With a Role
For instances that are known to perform AWS actions, ensure that they belong to an instance role that has the necessary permissions:

1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
2. Open the EC2 Dashboard and choose "Instances"
3. Click the EC2 instance that performs AWS actions, in the lower pane details find "IAM Role"
4. If the Role is blank, the instance is not assigned to one.
5. If the Role is filled in, it does not mean the instance might not *also* have credentials encoded on it for some activities'''

        insert_results(uuid, victim, checkNo, checkTitle, "N/A", result, "")

    def check1_20(uuid, victim, client):                                                     # Ensure a support role has been created to manage incidents with AWS Support
        checkNo = "1.20"
        checkTitle = "Ensure a support role has been created to manage incidents with AWS Support"
        
        try:
            res = client.list_policies()
        except:
            insert_results(uuid, victim, checkNo, checkTitle, "AccessDenied", "", "")
            return

        found = False
        for policy in res["Policies"]:
            if policy["PolicyName"] == "AWSSupportAccess":
                found = True
                try:
                    res = client.list_entities_for_policy(PolicyArn=policy["Arn"])
                except:
                    insert_results(uuid, victim, checkNo, checkTitle, "AccessDenied", "", "")
                    return    
                PolicyGroupsattached = False
                PolicyUsersattached = False
                PolicyRolessattached = False
                if res["PolicyGroups"] != []:
                    PolicyGroupsattached = True
                if res["PolicyUsers"] != []:
                    PolicyUsersattached = True
                if res["PolicyRoles"] != []:
                    PolicyRolessattached = True

                jsonBody = json.dumps(policy, indent=4, default=json_encoder)
                if PolicyGroupsattached == True or PolicyUsersattached == True or PolicyRolessattached == True:
                    
                    insert_results(uuid, victim, checkNo, checkTitle, "Compliant", jsonBody, policy["Arn"])    
                else:
                    insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", jsonBody, policy["Arn"])
                return
            
        if found == False:
            insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", "AWSSupportAccess Not Found!", "")


    def check1_21(uuid, victim, client):                                                     # Do not setup access keys during initial user setup for all IAM users that have a console password
        checkNo = "1.21"
        checkTitle = "Do not setup access keys during initial user setup for all IAM users that have a console password"
        report = credential_report.splitlines()
        report.pop(0)
        for line in report:
            array =  line.split(",")
            password_last_used = array[4]
            try:
                datetime.fromisoformat(password_last_used)
            except:
                return
            
            
        


    def check1_22(uuid, victim, client):                                                     # Ensure IAM policies that allow full "*:*" administrative privileges are not created
        checkNo = "1.22"
        checkTitle = "Ensure IAM policies that allow full \"*:*\" administrative privileges are not created"
        try:
            res = client.list_policies()
        except:
            insert_results(uuid, victim, checkNo, checkTitle, "AccessDenied", "", "")
            return

        def get_policy_version(uuid, victim, policy):
            checkNo = "1.22"
            checkTitle = "Ensure IAM policies that allow full \"*:*\" administrative privileges are not created"
            arn = policy["Arn"]
            version = policy["DefaultVersionId"]
            policyName = policy["PolicyName"]
            res = client.get_policy_version(PolicyArn=arn, VersionId=version)
            for policies in res["PolicyVersion"]["Document"]["Statement"]: 
                try:
                    Effect =  policies["Effect"]
                    Action =  policies["Action"]
                    Resource =  policies["Resource"]
                    
                except Exception as e:
                    try:
                        Effect =  res["PolicyVersion"]["Document"]["Statement"]["Effect"]
                    except:
                        Effect = ""
                    try:    
                        Action =  res["PolicyVersion"]["Document"]["Statement"]["Action"]
                    except:
                        Action = ""
                    try:        
                        Resource =  res["PolicyVersion"]["Document"]["Statement"]["Resource"]
                    except:
                        Resource = ""
                
                if Effect == "Allow" and Action == "*" and Resource == "*":
                    insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", f"Policy {policyName} allows \"*:*\"", "")

        processes = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            for policy in res["Policies"]:
                processes.append(executor.submit(get_policy_version, uuid, victim, policy))

        for task in as_completed(processes):
            (task.result())            
            


    p1  = threading.Thread(target=check1_1, args=(uuid, victim))
    p2  = threading.Thread(target=check1_2, args=(uuid, victim))
    p3  = threading.Thread(target=check1_3, args=(uuid, victim))
    p4  = threading.Thread(target=check1_4, args=(uuid, victim))
    p5  = threading.Thread(target=check1_5, args=(uuid, victim, client))
    p6  = threading.Thread(target=check1_6, args=(uuid, victim, client))
    p7  = threading.Thread(target=check1_7, args=(uuid, victim, client))
    p8  = threading.Thread(target=check1_8, args=(uuid, victim, client))
    p9  = threading.Thread(target=check1_9, args=(uuid, victim, client))
    p10 = threading.Thread(target=check1_10, args=(uuid, victim, client))
    p11 = threading.Thread(target=check1_11, args=(uuid, victim, client))
    p12 = threading.Thread(target=check1_12, args=(uuid, victim))
    p13 = threading.Thread(target=check1_13, args=(uuid, victim))
    p14 = threading.Thread(target=check1_14, args=(uuid, victim, client))
    p15 = threading.Thread(target=check1_15, args=(uuid, victim))
    p16 = threading.Thread(target=check1_16, args=(uuid, victim, client))
    p17 = threading.Thread(target=check1_17, args=(uuid, victim))
    p18 = threading.Thread(target=check1_18, args=(uuid, victim))
    p19 = threading.Thread(target=check1_19, args=(uuid, victim))
    p20 = threading.Thread(target=check1_20, args=(uuid, victim, client))
    p21 = threading.Thread(target=check1_21, args=(uuid, victim, client))
    p22 = threading.Thread(target=check1_22, args=(uuid, victim, client))

    p1.start();p2.start();p3.start();p4.start();p5.start();p6.start();p7.start();p8.start();p9.start();p10.start();p11.start();p12.start();p13.start();p14.start();p15.start();p16.start();p17.start();p18.start();p19.start();p20.start();p21.start();p22.start()
    p1.join();p2.join();p3.join();p4.join();p5.join();p6.join();p7.join();p8.join();p9.join();p10.join();p11.join();p12.join();p13.join();p14.join();p15.join();p16.join();p17.join();p18.join();p19.join();p20.join();p21.join();p22.join()



def logging(uuid, victim, access_key, secret_key, session_token, region):
    clientCloudTrial = get_client(access_key, secret_key, session_token, "cloudtrail", region)
    try:
        trailList = clientCloudTrial.describe_trails()
    except:
        insert_results(uuid, victim, 2, "Logging", "AccessDenied", "", "")
        return

    def check2_1(uuid, victim, client):                                                                                # Ensure CloudTrail is enabled in all regions
        
        def validate_trail(uuid, victim, trail):

            if trail["LogFileValidationEnabled"] == True:                                                              # Ensure CloudTrail log file validation is enabled
                insert_results(uuid, victim, 2.2, "Ensure CloudTrail log file validation is enabled", "Compliant", "", trail["TrailARN"])
            else:
                insert_results(uuid, victim, 2.2, "Ensure CloudTrail log file validation is enabled", "Non-Compliant", "LogFileValidationEnabled not set to True", trail["TrailARN"])    

            checkNo = 2.1    
            checkTitle = "Ensure CloudTrail is enabled in all regions"
            Name = trail["Name"]
            IsMultiRegionTrail = trail["IsMultiRegionTrail"]

            try:
                trailStatus = client.get_trail_status(Name=Name)
            except:
                insert_results(uuid, victim, checkNo, checkTitle, "AccessDenied", "", "")
                return

            IsLogging = trailStatus["IsLogging"]

            try:
                get_event_selectors = client.get_event_selectors(TrailName=Name)
            except:
                insert_results(uuid, victim, checkNo, checkTitle, "AccessDenied", "", "")
                return
            result = "Ensure there is at least one Event Selector for a Trail with IncludeManagementEvents set totrue and ReadWriteType set to All"
            status = "Non-Compliant"
            for event_selector in get_event_selectors["EventSelectors"]:
                if event_selector["ReadWriteType"] != "All" and event_selector["IncludeManagementEvents"] != True:
                    result = "Ensure Event Selector for a Trail with IncludeManagementEvents set to true and ReadWriteType set to All"
                    status = "Non-Compliant"

            insert_results(uuid, victim, checkNo, checkTitle, status, result, trail["TrailARN"])


        processes = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            for trail in trailList["trailList"]:
                processes.append(executor.submit(validate_trail, uuid, victim, trail))
        for task in as_completed(processes):
            (task.result())   


    def check2_3(uuid, victim, client):                                                 # Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible
        checkNo = 2.3
        checkTitle = "Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible"

        def check_for_s3_trail( uuid, victim, trail):
            client = get_client(access_key, secret_key, session_token, "s3", region)
            bucketName = trail["S3BucketName"]
            try:
                bucket_acl = client.get_bucket_acl(Bucket=bucketName)
                bucket_policy = client.get_bucket_policy(Bucket=bucketName)
            except:
                insert_results(uuid, victim, checkNo, checkTitle, "AccessDenied", "", "")
                return    

            AllUsers = ""
            AuthenticatedUsers = ""
            policy_check = ""
            for grant in bucket_acl["Grants"]:
                if "URI" in grant["Grantee"]:
                    if grant["Grantee"]["URI"] == "http://acs.amazonaws.com/groups/global/AllUsers":
                        AllUsers = "AllUsers are allowed\n"
                    if grant["Grantee"]["URI"] == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers":
                        AuthenticatedUsers = "AuthenticatedUsers are allowed\n"

            Effect = ""
            Principal = ""
            policy = json.loads(bucket_policy["Policy"])

            for policy in policy["Statement"]:
                Effect = policy["Effect"]
                Principal = policy["Principal"]
                
                if Effect == "Allow" and Principal == "*" or Principal == {"AWS" : "*"}:
                    policy_check = "Policy are in danger!\n"
                else:
                    policy_check = ""

                if AllUsers == "" and AuthenticatedUsers == "":
                    status = "Compliant"
                else:
                    status = "Non-Compliant"
                    result = ""

                result = f"{AllUsers} {AuthenticatedUsers} {policy_check}"
                insert_results(uuid, victim, checkNo, checkTitle, status, result, bucketName)

        processes = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            for trail in trailList["trailList"]:
                processes.append(executor.submit(check_for_s3_trail, uuid, victim, trail))
        for task in as_completed(processes):
            (task.result())



    def check2_4(uuid, victim, client):                                                 # Ensure CloudTrail trails are integrated with CloudWatch Logs
        checkNo = 2.4
        checkTitle = "Ensure CloudTrail trails are integrated with CloudWatch Logs"

        def get_trail_status( uuid, victim, trail, client):
            try:
                res = client.get_trail_status(Name=trail)
            except:
                insert_results(uuid, victim, checkNo, checkTitle, "AccessDenied", "", "")
                return

            if "LatestcloudwatchLogdDeliveryTime" in res:
                date = get_iso_format_date(res["LatestcloudwatchLogdDeliveryTime"])
                now = datetime.strptime(datetime.now().strftime("%Y-%m-%d"), "%Y-%m-%d")
                difference = (now - date).days
                if difference > 1:
                    insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", f"{trail} trail is not logging in the last 24h or not configured", trail)
                else:
                    insert_results(uuid, victim, checkNo, checkTitle, "Compliant", "", trail)

        processes = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            for trail in trailList["trailList"]:
                if "CloudWatchLogsLogGroupArn" in trail:
                    if trail["CloudWatchLogsLogGroupArn"] != "":
                        processes.append(executor.submit(get_trail_status, uuid, victim, trail["Name"], client))
                    else:
                        insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", "CloudWatchLogsLog Not Found!", trail["Name"])    
                else:
                    insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", "CloudWatchLogsLog Not Found!", trail["Name"])
        for task in as_completed(processes):
            (task.result())

    def check2_5(uuid, victim):                                                 # Ensure AWS Config is enabled in all regions 
        checkNo = 2.5
        checkTitle = "Ensure AWS Config is enabled in all regions "
        client = get_client(access_key, secret_key, session_token, "config", region)
        try:
            res = client.describe_configuration_recorders()
        except:
            insert_results(uuid, victim, checkNo, checkTitle, "AccessDenied", "", "")
            return

        for data in res["ConfigurationRecorders"]:
            allSupported = data["recordingGroup"]["allSupported"]
            includeGlobalResourceTypes = data["recordingGroup"]["includeGlobalResourceTypes"]
            roleARN = data["roleARN"]
            if allSupported == True and includeGlobalResourceTypes == True:
                insert_results(uuid, victim, checkNo, checkTitle, "Compliant", "", roleARN)
            else:
                try:
                    res = client.describe_configuration_recorder_status(ConfigurationRecorderNames=[data["name"]])
                except:
                    insert_results(uuid, victim, checkNo, checkTitle, "AccessDenied", "", "")
                    return
                for data in res["ConfigurationRecordersStatus"]:
                    recording = data["recording"]
                    
                    if "lastStatus" in data:
                        lastStatus = data["lastStatus"]
                        if recording == True and lastStatus == "SUCCESS":
                            insert_results(uuid, victim, checkNo, checkTitle, "Compliant", "", roleARN)
                        else:
                            insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", "", roleARN)    
                    else:
                        insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", "", roleARN)    

    def check2_6(uuid, victim, clientCloudTrial):                                                 # Ensure S3 bucket access logging is enabled on the CloudTrail S3bucket
        checkNo = 2.6
        checkTitle = "Ensure S3 bucket access logging is enabled on the CloudTrail S3bucket"
        s3client = get_client(access_key, secret_key, session_token, "s3", region)

        def get_bucket_logging(uuid, victim, bucketName, client):
            try:
                res = s3client.get_bucket_logging(Bucket=bucketName)
            except:
                insert_results(uuid, victim, checkNo, checkTitle, "AccessDenied", "", "")
                return    
            if "LoggingEnabled" in res:
                if "TargetBucket" in res["LoggingEnabled"]:
                    insert_results(uuid, victim, checkNo, checkTitle, "Compliant", "", bucketName)
                else:
                    insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", "Logging not Enabled!", bucketName)
            else:
                insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", "Logging not Enabled!", bucketName)

        processes = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            for trail in trailList["trailList"]:
                processes.append(executor.submit(get_bucket_logging, uuid, victim, trail["S3BucketName"], s3client))
        for task in as_completed(processes):
            (task.result())

    def check2_7(uuid, victim):                                                                 # Ensure CloudTrail logs are encrypted at rest using KMS CMKs
        checkNo = 2.7
        checkTitle = "Ensure CloudTrail logs are encrypted at rest using KMS CMKs"        

        for trail in trailList["trailList"]:
            if "KmsKeyId" not in trail:
                insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", "KMS not used!", trail["Name"])
            else:
                insert_results(uuid, victim, checkNo, checkTitle, "Compliant", "", trail["Name"])
             

    def check2_8(uuid, victim):                                                                        # Ensure rotation for customer created CMKs is enabled
        checkNo = 2.8
        checkTitle = "Ensure rotation for customer created CMKs is enabled"
        client = get_client(access_key, secret_key, session_token, "kms", region)
        try:
            res = client.list_keys()
        except:
            insert_results(uuid, victim, checkNo, checkTitle, "AccessDenied", "", "")
            return

        def get_key_rotation(uuid, victim, keyId, client):
            
            try:
                try:
                    res = client.get_key_rotation_status(KeyId= keyId)
                except:
                    insert_results(uuid, victim, checkNo, checkTitle, "AccessDenied", "", "")
                    return
                if res["KeyRotationEnabled"] == True:
                    insert_results(uuid, victim, checkNo, checkTitle, "Compliant", "", keyId)
                else:
                    insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", "Key rotation not enabled!", keyId)

            except Exception as e:
                insert_results(uuid, victim, checkNo, checkTitle, "AccessDenied", str(e), keyId)

        processes = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            for key in res["Keys"]:
                processes.append(executor.submit(get_key_rotation, uuid, victim, key["KeyId"], client))
        for task in as_completed(processes):
            (task.result())

    def check2_9(uuid, victim):                                                                        # Ensure VPC flow logging is enabled in all VPCs
        checkNo = 2.9
        checkTitle = "Ensure VPC flow logging is enabled in all VPCs"            
        try:
            ec2client = get_client(access_key, secret_key, session_token, "ec2", region)
            res = ec2client.describe_vpcs()
        except:
            insert_results(uuid, victim, checkNo, checkTitle, "AccessDenied", "", "")
            return

        ec2client = get_client(access_key, secret_key, session_token, "ec2", region)
        try:
            res = ec2client.describe_vpcs()
            flowlogs = ec2client.describe_flow_logs()
        except:
            insert_results(uuid, victim, checkNo, checkTitle, "AccessDenied", "", "")
            return
        
        for vpc in res["Vpcs"]:    
        
            if vpc["State"] == "available":
                vpcId = vpc["VpcId"]
                if flowlogs["FlowLogs"] != []:
                    for data in flowlogs["FlowLogs"]:
                        if data["FlowLogStatus"] == "ACTIVE" and data["ResourceId"] == vpcId:
                            FlowLogId = data["FlowLogId"]
                            results = f"VPCFlowLog is enabled for LogGroupName: {FlowLogId} in Region {region}"
                            insert_results(uuid, victim, checkNo, checkTitle, "Compliant", results, FlowLogId)
                        else:
                            FlowLogId = data["FlowLogId"]
                            results = f"VPCFlowLog is not enabled for LogGroupName: {FlowLogId} in Region {region}"
                            insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", results, vpcId)
                else:
                    results = f"VPCFlowLog is disabled for vpcId: {vpcId} in Region {region}"
                    insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", results, vpcId)

        

    p1 = threading.Thread(target=check2_1, args=(uuid, victim, clientCloudTrial))
    p2 = threading.Thread(target=check2_3, args=(uuid, victim, clientCloudTrial))
    p3 = threading.Thread(target=check2_4, args=(uuid, victim, clientCloudTrial))
    p4 = threading.Thread(target=check2_5, args=(uuid, victim))
    p5 = threading.Thread(target=check2_6, args=(uuid, victim, clientCloudTrial))
    p6 = threading.Thread(target=check2_7, args=(uuid, victim))
    p7 = threading.Thread(target=check2_8, args=(uuid, victim))
    p8 = threading.Thread(target=check2_9, args=(uuid, victim))


    p1.start();p2.start();p3.start();p4.start();p5.start();p6.start();p7.start();p8.start()
    p1.join();p2.join();p3.join();p4.join();p5.join();p6.join();p7.join();p8.join()


def monitoring(uuid, victim, access_key, secret_key, session_token, region):
    try:
        client= get_client(access_key, secret_key, session_token, "cloudtrail", region)
        trails = client.describe_trails()
    except:
        insert_results(uuid, victim, 3, "Monitoring", "AccessDenied", "", "")
        return

    def getmetricFilters(uuid, victim, checkNo, checkTitle, client, filters, resultsfilter):
        try:
            trails = client.describe_trails()
        except:
            insert_results(uuid, victim, checkNo, checkTitle, "AccessDenied", "", "")
            return
        for trail in trails["trailList"]:
            Name = trail["Name"]
            #Identify the log group name configured for use with active multi-region CloudTrail:
            if trail["IsMultiRegionTrail"] != True:
                insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", "CloudTrail Multi Region Not enabled!", CloudWatchLogsRoleArn)
                continue 
            #Ensure Identified Multi region CloudTrail is active
            if "CloudWatchLogsLogGroupArn" in trail:
                CloudWatchLogsRoleArn = trail["TrailARN"].split(":")[5].split("/")[1]
                try:
                    get_trail_status = client.get_trail_status(Name=CloudWatchLogsRoleArn)
                except:
                    insert_results(uuid, victim, checkNo, checkTitle, "AccessDenied", "", "")
                    return
                IsLogging = get_trail_status["IsLogging"]
                if IsLogging != True:
                    results = "Ensure Identified Multi region CloudTrail is active"
                    insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", results, CloudWatchLogsRoleArn)
                    continue 
                try:
                    get_event_selectors = client.get_event_selectors(TrailName=Name)
                except:
                    insert_results(uuid, victim, checkNo, checkTitle, "AccessDenied", "", "")
                    return
                if "IncludeManagementEvents" not in get_event_selectors:
                    results = "Ensure there is at least one Event Selector for a Trail with IncludeManagementEvents set to true and ReadWriteType set to All"
                    insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", results, CloudWatchLogsRoleArn)
                    continue 
                
                results = "Ensure there is at least one Event Selector for a Trail with IncludeManagementEvents set to true and ReadWriteType set to All"
                compliant = "Non-Compliant"
                for EventSelectors in get_event_selectors["EventSelectors"]:
                    ReadWriteType = EventSelectors["ReadWriteType"]
                    IncludeManagementEvents = EventSelectors["IncludeManagementEvents"]
                    if ReadWriteType == "All" and IncludeManagementEvents == True:
                        results = ""
                        compliant = "Compliant"
                    
                if compliant == "Non-Compliant":
                    insert_results(uuid, victim, checkNo, checkTitle, compliant, results, CloudWatchLogsRoleArn)
                    continue

                logclient = get_client(access_key, secret_key, session_token, "logs", region)
                log_group_name = trail["CloudWatchLogsLogGroupArn"].split(":")[6]
                try:
                    logs = logclient.describe_metric_filters(logGroupName=log_group_name)
                except:
                    insert_results(uuid, victim, checkNo, checkTitle, "AccessDenied", "", "")
                    return
                results = ""
                compliant = "Compliant"
                for metric in logs:
                    filterPattern = metric["filterPattern"]
                    for filter in filters:
                        if filter not in filterPattern:
                            results = resultsfilter
                            compliant = "Non-Compliant"

                    insert_results(uuid, victim, checkNo, checkTitle, compliant, results, logs["logGroupName"])

            else:
                compliant = "Non-Compliant"
                results = " CloudWatchLogsLogGroupArn not Found!"
                insert_results(uuid, victim, checkNo, checkTitle, compliant, results, Name)

    client = get_client(access_key, secret_key, session_token, "cloudtrail", region)
    def check3_1(uuid, victim):                                                             # Ensure a log metric filter and alarm exist for unauthorized API calls
        checkNo = 3.1
        checkTitle = "Ensure a log metric filter and alarm exist for unauthorized API calls"
        filters = ["*UnauthorizedOperation", "AccessDenied"]
        resultsfilter = '"filterPattern": "{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }"'
        getmetricFilters(uuid, victim, checkNo, checkTitle, client, filters, resultsfilter)
        

    def check3_2(uuid, victim):                                                             # Ensure a log metric filter and alarm exist for Management Console sign-in without MFA
        checkNo = 3.2
        checkTitle = "Ensure a log metric filter and alarm exist for Management Console sign-in without MFA"
        filters = ["ConsoleLogin", "additionalEventData.MFAUsed"]
        resultsfilter = '"filterPattern": "{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") }"'
        getmetricFilters(uuid, victim, checkNo, checkTitle, client, filters, resultsfilter)


    def check3_3(uuid, victim):                                                             # Ensure a log metric filter and alarm exist for usage of "root" account
        checkNo = 3.3
        checkTitle = "Ensure a log metric filter and alarm exist for usage of \"root\" account"
        filters = ["Root", "AwsServiceEvent", "$.userIdentity.invokedBy NOT EXISTS"]
        resultsfilter = '"filterPattern": "{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }"'
        getmetricFilters(uuid, victim, checkNo, checkTitle, client, filters, resultsfilter)

    def check3_4(uuid, victim):                                                             # Ensure a log metric filter and alarm exist for IAM policy changes
        checkNo = 3.4
        checkTitle = "Ensure a log metric filter and alarm exist for IAM policy changes"
        filters = ["DeleteGroupPolicy", "DeleteRolePolicy", "DeleteUserPolicy", "CreatePolicy", "PutUserPolicy", "DetachRolePolicy", ]
        resultsfilter = '"filterPattern":"{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}"'
        getmetricFilters(uuid, victim, checkNo, checkTitle, client, filters, resultsfilter)


    def check3_5(uuid, victim):                                                             # Ensure a log metric filter and alarm exist for CloudTrail configuration changes
        checkNo = 3.5
        checkTitle = "Ensure a log metric filter and alarm exist for CloudTrail configuration changes"
        filters = ["CreateTrail", "UpdateTrail", "DeleteTrail"]
        resultsfilter = '"filterPattern": "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"'
        getmetricFilters(uuid, victim, checkNo, checkTitle, client, filters, resultsfilter)


    def check3_6(uuid, victim):                                                             # Ensure a log metric filter and alarm exist for AWS Management Console authentication failures
        checkNo = 3.6
        checkTitle = "Ensure a log metric filter and alarm exist for AWS Management Console authentication failures"
        filters = ["ConsoleLogin", "Failed authentication"]
        resultsfilter = '"filterPattern": "{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication") }"'
        getmetricFilters(uuid, victim, checkNo, checkTitle, client, filters, resultsfilter)


    def check3_7(uuid, victim):                                                             # Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs
        checkNo = 3.7
        checkTitle = "Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs"
        filters = ["kms.amazonaws.com", "DisableKey", "ScheduleKeyDeletion"]
        resultsfilter = '"filterPattern": "{($.eventSource = kms.amazonaws.com) && (($.eventName=DisableKey)||($.eventName=ScheduleKeyDeletion)) }"'
        getmetricFilters(uuid, victim, checkNo, checkTitle, client, filters, resultsfilter)            

    def check3_8(uuid, victim):                                                             # Ensure a log metric filter and alarm exist for S3 bucket policy changes
        checkNo = 3.8
        checkTitle = "Ensure a log metric filter and alarm exist for S3 bucket policy changes"
        filters = ["s3.amazonaws.com", "PutBucketAcl", "PutBucketPolicy", "PutBucketCors", "PutBucketLifecycle", "DeleteBucketReplication", "DeleteBucketLifecycle"]
        resultsfilter = '"filterPattern": "{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }"'
        getmetricFilters(uuid, victim, checkNo, checkTitle, client, filters, resultsfilter) 

    def check3_9(uuid, victim):                                                             # Ensure a log metric filter and alarm exist for AWS Config configuration changes
        checkNo = 3.9
        checkTitle = "Ensure a log metric filter and alarm exist for AWS Config configuration changes"
        filters = ["config.amazonaws.com", "StopConfigurationRecorder", "DeleteDeliveryChannel", "PutDeliveryChannel", "PutConfigurationRecorder"]
        resultsfilter = '"filterPattern": "{ ($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel) ||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder)) }"'
        getmetricFilters(uuid, victim, checkNo, checkTitle, client, filters, resultsfilter)

    def check3_10(uuid, victim):                                                             # Ensure a log metric filter and alarm exist for security group changes
        checkNo = 3.10
        checkTitle = "Ensure a log metric filter and alarm exist for security group changes"
        filters = ["uthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress", "RevokeSecurityGroupIngress", "CreateSecurityGroup", "DeleteSecurityGroup"]
        resultsfilter = '"filterPattern": "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }"'
        getmetricFilters(uuid, victim, checkNo, checkTitle, client, filters, resultsfilter)

    def check3_11(uuid, victim):                                                             # Ensure a log metric filter and alarm exist for changes to Network Access Control Lists
        checkNo = 3.11
        checkTitle = "Ensure a log metric filter and alarm exist for changes to Network Access Control Lists"
        filters = ["CreateNetworkAcl", "CreateNetworkAclEntry", "DeleteNetworkAcl", "DeleteNetworkAclEntry", "ReplaceNetworkAclAssociation"]
        resultsfilter = '"filterPattern": "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"'
        getmetricFilters(uuid, victim, checkNo, checkTitle, client, filters, resultsfilter)


    def check3_12(uuid, victim):                                                             # Ensure a log metric filter and alarm exist for changes to network gateways
        checkNo = 3.12
        checkTitle = "Ensure a log metric filter and alarm exist for changes to network gateways"
        filters = ["CreateCustomerGateway", "DeleteCustomerGateway", "AttachInternetGateway", "DeleteInternetGateway", "DetachInternetGateway"]
        resultsfilter = '"filterPattern": "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }"'
        getmetricFilters(uuid, victim, checkNo, checkTitle, client, filters, resultsfilter)

    def check3_13(uuid, victim):                                                             # Ensure a log metric filter and alarm exist for route table changes
        checkNo = 3.13
        checkTitle = "Ensure a log metric filter and alarm exist for route table changes"
        filters = ["CreateRoute", "CreateRouteTable", "ReplaceRoute", "ReplaceRouteTableAssociation", "DeleteRouteTable", "DeleteRoute", "DisassociateRouteTable"]
        resultsfilter = '"filterPattern": "{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }"'
        getmetricFilters(uuid, victim, checkNo, checkTitle, client, filters, resultsfilter)

    def check3_14(uuid, victim):                                                             # Ensure a log metric filter and alarm exist for VPC changes
        checkNo = 3.14
        checkTitle = "Ensure a log metric filter and alarm exist for VPC changes"
        filters = ["CreateVpc", "DeleteVpc", "ModifyVpcAttribute", "AcceptVpcPeeringConnection", "CreateVpcPeeringConnection", "DeleteVpcPeeringConnection", "RejectVpcPeeringConnection", "AttachClassicLinkVpc", "DetachClassicLinkVpc", "DisableVpcClassicLink"]
        resultsfilter = '"filterPattern": "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }"'
        getmetricFilters(uuid, victim, checkNo, checkTitle, client, filters, resultsfilter)

                                     
    p1 = threading.Thread(target=check3_1,  args=(uuid, victim))
    p2 = threading.Thread(target=check3_2,  args=(uuid, victim))
    p3 = threading.Thread(target=check3_3,  args=(uuid, victim))
    p4 = threading.Thread(target=check3_4,  args=(uuid, victim))
    p5 = threading.Thread(target=check3_5,  args=(uuid, victim))
    p6 = threading.Thread(target=check3_6,  args=(uuid, victim))
    p7 = threading.Thread(target=check3_7,  args=(uuid, victim))
    p8 = threading.Thread(target=check3_8,  args=(uuid, victim))
    p9 = threading.Thread(target=check3_9,  args=(uuid, victim))
    p10 = threading.Thread(target=check3_10, args=(uuid, victim))
    p11 = threading.Thread(target=check3_11, args=(uuid, victim))
    p12 = threading.Thread(target=check3_12, args=(uuid, victim))
    p13 = threading.Thread(target=check3_13, args=(uuid, victim))
    p14 = threading.Thread(target=check3_14, args=(uuid, victim))


    p1.start();p2.start();p3.start();p4.start();p5.start();p6.start();p7.start();p8.start();p9.start();p10.start();p11.start();p12.start();p13.start();p14.start()
    p1.join(); p2.join(); p3.join(); p4.join(); p5.join(); p6.join(); p7.join(); p8.join(); p9.join(); p10.join(); p11.join(); p12.join(); p13.join(); p14.join()
  
def network(uuid, victim, access_key, secret_key, session_token, region):
    client = get_client(access_key, secret_key, session_token, "ec2", region)        
    try:
        security_groups = client.describe_security_groups()
    except:
        insert_results(uuid, victim, 4, "Network", "AccessDenied", "", "")
        return

    def check4_1(uuid, victim, access_key, secret_key, session_token):
        checkNo = 4.1
        checkTitle = "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports"
        client = get_client(access_key, secret_key, session_token, "ec2", region)        
        try:
            security_groups = client.describe_security_groups()
        except:
            insert_results(uuid, victim, checkNo, checkTitle, "AccessDenied", "", "")
            return

        for groups in security_groups['SecurityGroups']:
            groupName = groups["GroupName"]
            Id = groups["GroupId"]
            adminports = []
            for group in groups["IpPermissions"]:
                if "FromPort" not in group:
                    continue
                formPort = group["FromPort"]
                toPort = group["ToPort"]
                
                for port in range(formPort, toPort + 1):
                    if port in ports:
                        adminports.append(str(port))
                if adminports != []:
                    results = f"[!] Vpc {Id} - Admin Ports open: " + ",".join(adminports)
                    insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", results, Id)
                    break
                
            if adminports == []:
                insert_results(uuid, victim, checkNo, checkTitle, "Compliant", "", Id)    

    def check4_3(uuid, victim):
        checkNo = 4.3
        checkTitle = "Ensure the default security group of every VPC restricts all traffic"
        client = get_client(access_key, secret_key, session_token, "ec2", region)
        try:
            res = client.describe_security_groups(Filters=[{"Name":"group-name","Values":['default']}])
        except:
            insert_results(uuid, victim, checkNo, checkTitle, "AccessDenied", "", "")
            return

        for data in res["SecurityGroups"]:
            if "0.0.0.0" in str(data):
                results = "Default Security Groups found that allow 0.0.0.0 IN or OUT traffic"
                Id = data["GroupId"]
                insert_results(uuid, victim, checkNo, checkTitle, "Non-Compliant", results, Id)
            else:
                results = "No Default Security Groups open to 0.0.0.0 found"
                Id = data["GroupId"]
                insert_results(uuid, victim, checkNo, checkTitle, "Compliant", results, Id)

    def check4_4(uuid, victim):
        checkNo = 4.4
        checkTitle = "Ensure routing tables for VPC peering are \"least access\""
        client = get_client(access_key, secret_key, session_token, "ec2", region)
        try:
            res = client.describe_vpc_peering_connections()
        except:
            insert_results(uuid, victim, checkNo, checkTitle, "AccessDenied", "", "")
            return

        VpcPeeringConnectionId = []
        for data in res["VpcPeeringConnections"]:
            VpcPeeringConnectionId.append(data["VpcPeeringConnectionId"])
        Ids = "\r\n".join(VpcPeeringConnectionId)
        results = "Review routing tables"
        if VpcPeeringConnectionId != []:
            insert_results(uuid, victim, checkNo, checkTitle, "N/A", results, Ids)
        else:
            insert_results(uuid, victim, checkNo, checkTitle, "N/A", "", Ids)


    ps1 = threading.Thread(target=check4_1, args=(uuid, victim, access_key, secret_key, session_token))
    ps2 = threading.Thread(target=check4_3, args=(uuid, victim))
    ps3 = threading.Thread(target=check4_4, args=(uuid, victim))

    ps1.start();ps2.start();ps3.start()
    ps1.join();ps2.join();ps3.join()

#------------------------------------------------------------------------------------------------------------


def startconfigReview(uuid, victim, access_key, secret_key, session_token):
    # IAM
    
    try:
        iam_client = get_client(access_key, secret_key, session_token, "iam", None)
    except Exception as e:
        print(e)    
    
    psiam = threading.Thread(target=iam, args=(uuid, victim, iam_client))
    psiam.start()
    psiam.join()
    
    for region in regions:
        pslog = threading.Thread(target=logging, args=(uuid, victim, access_key, secret_key, session_token, region))
        pslog.start()

    pslog.join()   

    # Monitoring
    for region in regions:
        psmonitor = threading.Thread(target=monitoring, args=(uuid, victim, access_key, secret_key, session_token, region))
        psmonitor.start()

    psmonitor.join()    

    for region in regions:
        psnetwork = threading.Thread(target=network, args=(uuid, victim, access_key, secret_key, session_token, region))
        psnetwork.start()
        
    psnetwork.join()

    iamVictim = awsConfigVictims.query.filter_by(uuid=uuid, victim=victim).first()
    iamVictim.configStatus="completed"
    db.session.commit()
