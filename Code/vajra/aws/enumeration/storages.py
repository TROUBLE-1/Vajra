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

import json, time
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from vajra.aws.enumeration.utils.json_utils import json_encoder
from vajra.models import awsS3, awsEC2SS, awsEFS, awsStorageGateway, awsCloudFront
from vajra import db

def s3BucketGetPolicy(uuid, victim, client, bucketName):

    try:
        res = client.get_bucket_policy(Bucket=bucketName)
        res["Policy"]
    except Exception as e:
        return

    isPublic = "False"
    jsonBody = json.loads(res["Policy"].replace('\\"', "\""))
    for data in jsonBody["Statement"]:
        try:
            if "AWS" in data["Principal"]:
                if data["Principal"]["AWS"] == "*":
                    isPublic = "Public"
        except:
            pass

    s3bucket = awsS3.query.filter_by(uuid=uuid, victim=victim, bucketName=bucketName).first()
    s3bucket.isPublic = isPublic
    s3bucket.policy = json.dumps(jsonBody, indent=4, default=json_encoder)
    db.session.commit()


def s3BucketAcl(uuid, victim, client, bucketName):
    res1 = client.get_bucket_acl(Bucket=bucketName)
    s3bucket = awsS3.query.filter_by(uuid=uuid, victim=victim, bucketName=bucketName).first()
    try:
        if "URI" in res1["Grants"][0]["Grantee"]:
            if "http://acs.amazonaws.com/groups/global/AllUsers" == res1["Grants"][0]["Grantee"]["URI"]:
                s3bucket.acl = "All Users"
            elif "http://acs.amazonaws.com/groups/global/AuthenticatedUsers" == res1["Grants"][0]["Grantee"]["URI"]:
                s3bucket.acl = "Authenticated Users"
    except:
        s3bucket.acl = "Private"
        
    db.session.commit()

def s3bucket(uuid, victim, client, bucket):

    bucketName = bucket["Name"]
    db.session.add(awsS3(uuid=uuid, victim=victim, bucketName=bucketName))
    try:
        db.session.commit()
    except:
        db.session.rollback()

    
    threading.Thread(target=s3BucketAcl, args=(uuid, victim, client, bucketName)).start()
    threading.Thread(target=s3BucketGetPolicy, args=(uuid, victim, client, bucketName)).start()
    time.sleep(0.2)

def s3enum(uuid, victim, client):
    
    try:
        res = client.list_buckets()
        res["Buckets"]
    except:
        return

    processes = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        for bucket in res["Buckets"]:
            processes.append(executor.submit(s3bucket, uuid, victim, client, bucket))

    for task in as_completed(processes):
        (task.result())



def ebsEnum(uuid, victim, client):
    
    try:
        res = client.describe_snapshots(OwnerIds=['self'])
        res["Snapshots"]
    except:
        return
    for data in res["Snapshots"]:
        jsonBody = json.dumps(data, indent=4, default=json_encoder)
        SnapshotId = data["SnapshotId"]
        Description = data["Description"]
        Encrypted = data["Encrypted"]
        try:
            KmsKeyId = data["KmsKeyId"]
        except:
            KmsKeyId = ""

        OwnerId = data["OwnerId"]
        Progress = data["Progress"]
        StartTime = data["StartTime"]
        State = data["State"]
        VolumeId = data["VolumeId"]
        VolumeSize = data["VolumeSize"]

        ebs = awsEC2SS(uuid=uuid, victim=victim, jsonBody=jsonBody, SnapshotId=SnapshotId, Description=Description, 
                    Encrypted=Encrypted, KmsKeyId=KmsKeyId, OwnerId=OwnerId, Progress=Progress, StartTime=StartTime, 
                    State=State, VolumeId=VolumeId, VolumeSize=VolumeSize)
        db.session.add(ebs)

    db.session.commit()
  

def efsEnum(uuid, victim, client):
    try:
        res = client.describe_file_systems()
        res["FileSystems"]
    except:
        return

    for data in res["FileSystems"]:
        FileSystemId = data["FileSystemId"]
        FileSystemArn = data["FileSystemArn"]
        CreationTime = data["CreationTime"]
        LifeCycleState = data["LifeCycleState"]
        Name = ""
        if "Name" in data:
            Name = data["Name"]
        SizeInBytes = data["SizeInBytes"]["Value"]
        jsonBody = json.dumps(data, indent=4, default=json_encoder)

        insertEFS = awsEFS(uuid=uuid, victim=victim, FileSystemId=FileSystemId, FileSystemArn=FileSystemArn, CreationTime=CreationTime,
                LifeCycleState=LifeCycleState, Name=Name, SizeInBytes=SizeInBytes, jsonBody=jsonBody)
        db.session.add(insertEFS)

    db.session.commit()


def storageGateway(uuid, victim, client):
    try:
        res = client.list_gateways()
        res["FileSystems"]
    except:
        return

    for data in res["FileSystems"]:
        GatewayId = data["GatewayId"]
        GatewayARN = data["GatewayARN"]
        GatewayType = data["GatewayType"]
        GatewayOperationalState = data["GatewayOperationalState"]
        GatewayName = data["GatewayName"]
        Ec2InstanceId = data["Ec2InstanceId"]
        Ec2InstanceRegion = data["Ec2InstanceRegion"]
        HostEnvironment = data["HostEnvironment"]
        HostEnvironmentId = data["HostEnvironmentId"]
        jsonBody = json.dumps(data, indent=4, default=json_encoder)

        insertStorageGateway = awsStorageGateway(uuid=uuid, victim=victim, GatewayId=GatewayId, GatewayARN=GatewayARN, GatewayType=GatewayType,
                 GatewayOperationalState=GatewayOperationalState, GatewayName=GatewayName, Ec2InstanceId=Ec2InstanceId, 
                Ec2InstanceRegion=Ec2InstanceRegion, HostEnvironment=HostEnvironment, HostEnvironmentId=HostEnvironmentId, jsonBody=jsonBody)
        
        db.session.add(insertStorageGateway)

    db.session.commit()



def cloudfront(uuid, victim, client):
    try:
        res = client.list_distributions()
        res["DistributionList"]["Items"]
    except:
        return

    for data in res["DistributionList"]["Items"]:
        ARN = data["ARN"]
        DomainName = data["DomainName"]
        Status = data["Status"]
        jsonBody = json.dumps(data, indent=4, default=json_encoder)

        db.session.add(awsCloudFront(uuid=uuid, victim=victim, ARN=ARN, DomainName=DomainName, Status=Status, jsonBody=jsonBody))
    
    db.session.commit()