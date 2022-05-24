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

import threading
from vajra import db
from vajra.models import *
from vajra.aws.enumeration.iam_enumerate import *
from vajra.aws.enumeration.compute import *
from vajra.aws.enumeration.function import get_client
from vajra.aws.enumeration.all_services import regions
from vajra.aws.enumeration.storages import *
from vajra.aws.enumeration.networks import networks, route53
from concurrent.futures import ThreadPoolExecutor, as_completed

def start_iam(uuid, victim, client):

    try:
        iam_all_details = client.get_account_authorization_details()   # UserDetailList
    except:
        return
    
    UserDetailList = iam_all_details["UserDetailList"]
    GroupDetailList = client.list_groups()["Groups"]
    p1 = threading.Thread(target=iam_users, args=(uuid, victim, UserDetailList, client))
    p2 = threading.Thread(target=iam_groups, args=(uuid, victim, GroupDetailList, UserDetailList, client))
    p3 = threading.Thread(target=iam_roles, args=(uuid, victim, client))
    p4 = threading.Thread(target=iam_policies, args=(uuid, victim, client))
    
    p1.start()
    p2.start()
    p3.start()
    p4.start()

    p1.join()
    p2.join()
    p3.join()
    p4.join()


def startEnumerate(uuid, keyId, secret, session):

    client = get_client(keyId, secret, session, 'sts', None)
    Victim_user = client.get_caller_identity()
    victim = Victim_user["Arn"]
    userId = Victim_user["UserId"]
    
    p1 = threading.Thread(target=start_iam, args=(uuid, victim, get_client(keyId, secret, session, 'iam', "")))
    p2 = threading.Thread(target=s3enum, args=(uuid, victim, get_client(keyId, secret, session, 's3', None)))
    p3 = threading.Thread(target=route53, args=(uuid, victim, get_client(keyId, secret, session, 'route53', None)))
    p4 = threading.Thread(target=cloudfront, args=(uuid, victim, get_client(keyId, secret, session, 'cloudfront', None)))
    
    p1.start()
    p2.start()
    p3.start()
    p4.start()
    
    # Compute Services
    processes = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        for region in regions:
            processes.append(executor.submit(list_ec2_instances, uuid, victim, get_client(keyId, secret, session, 'ec2', region)))
            processes.append(executor.submit(list_lambda_function, uuid, victim, get_client(keyId, secret, session, 'lambda', region)))
            processes.append(executor.submit(ebsEnum, uuid, victim, get_client(keyId, secret, session, 'ec2', region)))
            processes.append(executor.submit(networks, uuid, victim, get_client(keyId, secret, session, 'ec2', region)))
            processes.append(executor.submit(beanStalk, uuid, victim, get_client(keyId, secret, session, 'elasticbeanstalk', region)))
            processes.append(executor.submit(ecs, uuid, victim, get_client(keyId, secret, session, 'ecs', region)))
            processes.append(executor.submit(eks, uuid, victim, get_client(keyId, secret, session, 'eks', region)))
            processes.append(executor.submit(ecr, uuid, victim, get_client(keyId, secret, session, 'ecr', region)))
            processes.append(executor.submit(storageGateway, uuid, victim, get_client(keyId, secret, session, 'storagegateway', region)))
            processes.append(executor.submit(efsEnum, uuid, victim, get_client(keyId, secret, session, 'efs', region)))
    for task in as_completed(processes):
        (task.result())    

    p1.join()
    p2.join()
    p3.join()
    p4.join()

    victimA = awsIAMVictims.query.filter_by(uuid=uuid, victim=victim, userId=userId).first()
    victimA.enumStatus = "completed"
    db.session.commit()
