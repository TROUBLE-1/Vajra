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

import json
from vajra.aws.enumeration.utils.json_utils import json_encoder
from vajra.models import awsSecurityGroups, awsVPCs, awsRoute53
from vajra import db
from vajra.aws.enumeration.ports_list import ports
from multiprocessing.pool import ThreadPool as Pool
from concurrent.futures import ThreadPoolExecutor, as_completed

def security_groups(uuid, victim, client):
    try:
        res = client.describe_security_groups()
        res['SecurityGroups']
    except:
        return
    for groups in res['SecurityGroups']:
        groupName = groups["GroupName"]
        vpcId = groups["VpcId"]
        Description = groups["Description"]
        GroupId = groups["GroupId"]
        jsonBody = json.dumps(groups, indent=4, default=json_encoder)
        openAdminPorts = ""
        adminports = []
        for group in groups["IpPermissions"]:
            if "FromPort" not in group:
                continue
            formPort = group["FromPort"]
            toPort = group["ToPort"]
            
            for port in range(formPort, toPort + 1):
                if port in ports:
                    adminports.append(port)
        if adminports == []:
            adminports= ""
        db.session.add(awsSecurityGroups(uuid=uuid, victim=victim, groupName=groupName, vpcId=vpcId, Description=Description, GroupId=GroupId, jsonBody=jsonBody, adminPorts=str(adminports)))

    db.session.commit()

def vpcs(uuid, victim, client):
    try:
        res = client.describe_vpcs()
        res["Vpcs"]
    except:
        return

    for data in res["Vpcs"]:
        vpcId = data["VpcId"]
        CidrBlock = data["CidrBlock"]
        DhcpOptionsId = data["DhcpOptionsId"]
        IsDefault = data["IsDefault"]
        jsonBody = json.dumps(data, indent=4, default=json_encoder)
        
        db.session.add(awsVPCs(uuid=uuid, victim=victim, vpcId=vpcId, CidrBlock=CidrBlock, DhcpOptionsId=DhcpOptionsId, IsDefault=IsDefault, jsonBody=jsonBody))

    db.session.commit()    

def route53(uuid, victim, client):
    try:
        res = client.list_hosted_zones()
        res["HostedZones"]
    except:
        return

    def insertRoute53(data, client):
        zoneId = data["Id"]
        Name = data["Name"]
        CallerReference = data["CallerReference"]
        Config = json.dumps(data["Config"], indent=4, default=json_encoder)
        ResourceRecordSetCount = data["ResourceRecordSetCount"]
        #print(ResourceRecordSetCount)
        try:
            recordSets = client.list_resource_record_sets(HostedZoneId=zoneId)
            recordSets = json.dumps(recordSets["ResourceRecordSets"], indent=4, default=json_encoder)
        except:
            recordSets = ""

        insertdata = awsRoute53(uuid=uuid, victim=victim, zoneId=zoneId, Name=Name, CallerReference=CallerReference, Config=Config, ResourceRecordSetCount=ResourceRecordSetCount, RecordSets=recordSets)
        db.session.add(insertdata)
        
        
        try:
            db.session.commit()
        except:
            db.session.rollback()

    processes = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        for data in res["HostedZones"]:
            processes.append(executor.submit(insertRoute53, data, client))
    for task in as_completed(processes):
        (task.result())


def networks(uuid, victim, client):
    security_groups(uuid, victim, client)
    vpcs(uuid, victim, client)
