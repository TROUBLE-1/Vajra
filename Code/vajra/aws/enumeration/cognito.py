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

import json, threading
from vajra.models import awsCognitoUserPool
from vajra import db
from vajra.aws.enumeration.function import osCommand

def list_user_pools(uuid, victim, profile):
    
    res = osCommand(uuid, f"aws cognito-idp list-user-pools --max-results 60 --profile {profile}")
    
    try:
        res["UserPools"]
    except:
        return

    for pool in res["UserPools"]:
        Id = pool["Id"]
        Name = pool["Name"]
        LambdaConfig = str(json.dumps(pool["LambdaConfig"], indent=4))
        LastModifiedDate = pool["LastModifiedDate"]
        CreationDate = pool["CreationDate"]
        json_identity_providers = osCommand(uuid, f"aws cognito-idp list-identity-providers --user-pool-id {Id} --profile {profile}")
        if json_identity_providers["Providers"] == []:
            json_identity_providers = None

        cognito = awsCognitoUserPool(uuid=uuid, victim=victim, id=Id, name=Name, lambdaConfig=LambdaConfig, 
                                       lastModifiedDate=LastModifiedDate, creationDate=CreationDate, json_identity_providers=str(json.dumps(json_identity_providers, indent=4)))

        db.session.add(cognito)
        db.session.commit()


def cognitoEnum(uuid, victim, profile):
    threading.Thread(target=list_user_pools, args=(uuid, victim, profile)).start()