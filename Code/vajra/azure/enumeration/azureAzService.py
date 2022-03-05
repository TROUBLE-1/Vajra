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

import msal, threading, requests , json
from vajra import db
from vajra.models import  *

class azureAzServiceEnum():
    def flushPreviousdata(uuid, username):
        db.session.query(azureEnumResourcesGroups).filter_by(uuid=uuid, username=username).delete()
        db.session.query(azureEnumSubscriptions).filter_by(uuid=uuid, username=username).delete()
        db.session.query(azureEnumResources).filter_by(uuid=uuid, username=username).delete()
        db.session.query(azureEnumUsers).filter_by(uuid=uuid, username=username).delete()
        db.session.commit()

    def apiCall(url, method, contentType, data, accessToken):
        headers = {"Authorization": "Bearer " + accessToken,
                    "Content-Type": contentType}
        url = "https://management.azure.com/" + url

        if method == "GET":
            req = requests.get(url, headers=headers)
            return  req
        elif method == "POST":
            req = requests.post(url, headers=headers, data = data)
            return req
        elif method == "PUT":
            req = requests.put(url, headers=headers, data = data)
            return req
        elif method == "PATCH":
            req = requests.patch(url, headers=headers, data = data)
            return req            
        elif method == "DELETE":
            req = requests.delete(url, headers=headers)
            return  req

    def listResourcesInGroups(uuid, token, username, subscriptionId, resourceGroupName):
        response = azureAzServiceEnum.apiCall(f"subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/resources?api-version=2021-04-01", 'GET', None, "", token)
        if response.status_code == 403:
            return
        response = response.json()
        for data in response["value"]:
            resourceName = data["name"]
            type = data["type"]
            location = data["location"]
            try:
                db.session.add(azureEnumResources(uuid=uuid, username=username, resourceGroupName=resourceGroupName, subscriptionId=subscriptionId, resourceName=resourceName, type=type, location=location))
                db.session.commit()
            except Exception as e:
                print(e)
                db.session.rollback()
             

    def listResourceGroups(uuid, token, username, subscriptionId):
        response = azureAzServiceEnum.apiCall(f"subscriptions/{subscriptionId}/resourcegroups?api-version=2021-04-01", 'GET', None, "", token)
        if response.status_code == 403:
            return
        response = response.json()
        for data in response["value"]:
            GroupName = data["name"]
            location = data["location"]
            try:
                db.session.add(azureEnumResourcesGroups(uuid=uuid, username=username, resourceGroupName=GroupName, subscriptionId=subscriptionId, location=location))
                db.session.commit()
            except Exception as e:
                print(e)
                db.session.rollback()
            azureAzServiceEnum.listResourcesInGroups(uuid, token, username, subscriptionId, GroupName)

    def listSubscription(uuid, token, username):
        response = azureAzServiceEnum.apiCall("subscriptions?api-version=2020-01-01", 'GET', None, "", token)
        if response.status_code == 403:
            return
        response = response.json()
        
        for data in response["value"]:        
            displayName = data["displayName"]
            subscriptionId = data["subscriptionId"]
            state = data["state"]
            locationPlacementId = data["subscriptionPolicies"]["locationPlacementId"]
            quotaId = data["subscriptionPolicies"]["quotaId"]
            spendingLimit = data["subscriptionPolicies"]["spendingLimit"]

            insertSubscription = azureEnumSubscriptions(uuid=uuid, username=username, displayName=displayName, subscriptionId=subscriptionId, state=state, locationPlacementId=locationPlacementId, quotaId=quotaId, spendingLimit=spendingLimit)

        try:
            db.session.add(insertSubscription)
            db.session.commit()
        except:
            db.session.rollback()

        for data in response["value"]:
            subscriptionId = data["subscriptionId"]
            azureAzServiceEnum.listResourceGroups(uuid, token, username, subscriptionId)
            
    
    def enum(uuid, token, username):
        azureAzServiceEnum.flushPreviousdata(uuid, username)

        try:
            db.session.add(azureEnumUsers(uuid=uuid, username=username))
            db.session.commit()
        except Exception as e:
            db.session.rollback()

        threading.Thread(target=azureAzServiceEnum.listSubscription, name="Applications", args=(uuid, token, username)).start()

        return "success", "Enumeration running in background please refresh the page after few seconds."


    def enumCred(uuid, username, password, clientId):
        if clientId == "":
            return "error", "ClientId No found!"
        app = msal.ClientApplication(clientId, authority="https://login.microsoftonline.com/organizations")
        try:
            result = app.acquire_token_by_username_password(username, password, scopes=["https://management.azure.com/.default"])

            return azureAzServiceEnum.enum(uuid, result["access_token"], username)
        except Exception as e:
            try:
                return "error", result["error_description"].split(":")[1].split(".")[0]
            except:
                return "error", str(e)


    def enumToken(uuid, accessToken, victim):
        response = azureAzServiceEnum.apiCall("subscriptions?api-version=2020-01-01", 'GET', None, "", accessToken)
        print(json.dumps(response.json(), indent=4))
        if response.status_code != 200:
            try:
                msg = response.json()["error"]["message"]
            except:
                msg = "Invalid or Expired Token!"
            return "error", msg
        try:
            return azureAzServiceEnum.enum(uuid, accessToken, victim)
        except:
            return "error", "Invalid or Expired Token!"