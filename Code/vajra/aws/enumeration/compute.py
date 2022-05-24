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

import json, requests, base64
from vajra.aws.enumeration.utils.json_utils import json_encoder
from vajra.models import awsEc2, awsLambda, awsbeanstalk, awsECS, awsEKS, awsECR
from vajra import db

def list_lambda_function(uuid, victim, client):
    try:
        res = client.list_functions()
        res["Functions"]
    except:
        return

    for function in res["Functions"]:
        jsonBody = json.dumps(function, indent=4, default=json_encoder)
        functionName = function["FunctionName"]
        arn = function["FunctionArn"]
        runtime = function["Runtime"]
        description = function["Description"]
        try:
            function_code_url = client.get_function(FunctionName=functionName)["Code"]["Location"]
            response = requests.get(function_code_url, timeout=10)
            base64_function_zip = base64.b64encode(response.content)
        except:
            base64_function_zip = ""
        lambdaInsert = awsLambda(uuid=uuid, victim=victim, functionName=functionName, arn=arn, runtime=runtime, description=description, jsonBody=jsonBody, zipFile=base64_function_zip)
        db.session.add(lambdaInsert)
        
    db.session.commit()    

def list_ec2_instances(uuid, victim, client):

    try:
        res = client.describe_instances()
        res["Reservations"]
    except Exception as e:
        print()
        return
     
    for data in res["Reservations"]:
        jsonOutput = json.dumps(data, indent=4, default=json_encoder)
        for instance in data["Instances"]:
            try:
                instancesId = instance["InstanceId"]
                instancesState = instance["State"]["Name"]
                instancesType = instance["InstanceType"]
                availabilityZone = instance["Placement"]["AvailabilityZone"]

                publicIPv4DNS = instance["PrivateDnsName"]
                publicIPv4Address = instance["PrivateIpAddress"]
                ipv6IPs = str("\r\n".join(instance["NetworkInterfaces"][0]["Ipv6Addresses"]))
                monitoring = instance["Monitoring"]["State"]
                securityGroupName = instance["SecurityGroups"][0]["GroupName"]
                launchTime = instance["LaunchTime"]

                ec2 = awsEc2(uuid=uuid, victim=victim, instancesId=instancesId, jsonOutput=jsonOutput, instancesState=instancesState,
                    instancesType=instancesType, availabilityZone=availabilityZone, publicIPv4DNS=publicIPv4DNS, publicIPv4Address=publicIPv4Address,
                    ipv6IPs=ipv6IPs, monitoring=monitoring, securityGroupName=securityGroupName, launchTime=launchTime)
                db.session.add(ec2)
            except Exception as e:
                print(e)
                continue      
        
        try:
            db.session.commit()
        except:
            db.session.rollback()


def beanStalk(uuid, victim, client):
    try:
        res = client.describe_applications()
        res["Applications"]
    except:
        return

    for data in res["Applications"]:
        ApplicationName = data["ApplicationName"]
        DateCreated = data["DateCreated"]
        jsonOutput = json.dumps(data, indent=4, default=json_encoder)

        db.session.add(awsbeanstalk(uuid=uuid, victim=victim, ApplicationName=ApplicationName, DateCreated=DateCreated, jsonOutput=jsonOutput))
    
    db.session.commit()

def ecs(uuid, victim, client):

    try:
        ecsClusters = client.list_clusters()
        ecsClusters["clusterArns"]
    except:
        return

    for data in ecsClusters["clusterArns"]:
        clusterArn = data
        db.session.add(awsECS(uuid=uuid, victim=victim, clusterArn=clusterArn))
    db.session.commit()


def eks(uuid, victim, client):
    try:
        eksClusters = client.list_clusters()
        eksClusters["clusters"]
    except:
        return

    for data in eksClusters["clusters"]:
        cluster = data
        db.session.add(awsEKS(uuid=uuid, victim=victim, cluster=cluster))

    db.session.commit()    

def ecr(uuid, victim, client):
    try:
        ecrRepos = client.describe_repositories()
        ecrRepos["repositories"]
    except:
        return

    for data in ecrRepos["repositories"]:
        repositoryArn = data["repositoryArn"]
        registryId = data["registryId"]
        repositoryName = data["repositoryName"]
        repositoryUri = data["repositoryUri"]
        createdAt = data["createdAt"]
        imageTagMutability = data["imageTagMutability"]
        jsonBody = json.dumps(data, indent=4, default=json_encoder)

        insertECR = (awsECR(uuid=uuid, victim=victim, repositoryArn=repositoryArn, registryId=registryId, repositoryName=repositoryName,
                repositoryUri=repositoryUri, createdAt=createdAt, imageTagMutability=imageTagMutability, jsonBody=jsonBody))
        db.session.add(insertECR)
    db.session.commit()    