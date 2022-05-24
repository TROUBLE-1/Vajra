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

from subprocess import STDOUT
import subprocess, json, boto3, botocore
from vajra import db
from vajra.models import Admin
from botocore.endpoint import MAX_POOL_CONNECTIONS
from botocore.client import Config
from vajra.aws.enumeration.utils.remove_metadata import remove_metadata

MAX_THREADS = 25
CLIENT_POOL = {}

def osCommand(uuid, cmd):
    try:
        client = Admin.query.filter_by(id=uuid).first()
        client.awsUsage = client.awsUsage + 1
        db.session.commit()
        res = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=STDOUT).stdout.read()
        return json.loads(res)
    except Exception as e:
        return ""


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

def check_one_permission(arg_tuple):
    access_key, secret_key, session_token, region, service_name, operation_name = arg_tuple

    service_client = get_client(access_key, secret_key, session_token, service_name, region)
    if service_client is None:
        return

    try:
        action_function = getattr(service_client, operation_name)
    except AttributeError:
        return

    try:
        action_response = action_function()
    except (botocore.exceptions.ClientError,
            botocore.exceptions.EndpointConnectionError,
            botocore.exceptions.ConnectTimeoutError,
            botocore.exceptions.ReadTimeoutError):
        return
    except botocore.exceptions.ParamValidationError:
        return


    key = '%s.%s' % (service_name, operation_name)

    return key, remove_metadata(action_response)
