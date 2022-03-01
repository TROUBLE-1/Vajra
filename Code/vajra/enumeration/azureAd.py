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

import msal, threading, requests , os, sys, json, time
from vajra import db
from vajra.models import  *
from concurrent.futures import ThreadPoolExecutor, as_completed
from vajra.enumeration.roles.applicationPermission import listOfAppRoles
from vajra.enumeration.roles.adRoles import listAdroles

class azureAdEnum():
    def apiCall(url, method, contentType, data, accessToken):
        headers = {"Authorization": "Bearer " + accessToken,
                    "Content-Type": contentType}
        url = "https://graph.microsoft.com/v1.0" + url

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

    def flushAllData(uuid):
        db.session.query(azureAdEnumeratedGroupMembers).filter_by(uuid=uuid).delete()
        db.session.query(azureAdEnumeratedGroups).filter_by(uuid=uuid).delete()
        db.session.query(azureAdEnumeratedUsers).filter_by(uuid=uuid).delete()
        db.session.query(azureAdEnumeratedDevices).filter_by(uuid=uuid).delete()
        db.session.query(azureAdEnumeratedAdmins).filter_by(uuid=uuid).delete()
        db.session.query(azureAdEnumeratedCustomDirectoryRoles).filter_by(uuid=uuid).delete()
        db.session.query(azureAdEnumeratedApplications).filter_by(uuid=uuid).delete()
        db.session.query(azureAdEnumeratedServicePrinciple).filter_by(uuid=uuid).delete()
        db.session.query(azureAdEnumeratedConditionalAccessPolicy).filter_by(uuid=uuid).delete()
        db.session.query(azureAdEnumeratedUserProfile).filter_by(uuid=uuid).delete()
        db.session.commit()

    def flushPreviousdata(uuid, victim):
        db.session.query(azureAdEnumeratedUsers).filter_by(uuid=uuid, victim=victim).delete()
        db.session.query(azureAdEnumeratedGroupMembers).filter_by(uuid=uuid, victim=victim).delete()
        db.session.query(azureAdEnumeratedGroups).filter_by(uuid=uuid, victim=victim).delete()
        db.session.query(azureAdEnumeratedAdmins).filter_by(uuid=uuid, victim=victim).delete()
        db.session.query(azureAdEnumeratedApplications).filter_by(uuid=uuid, victim=victim).delete()
        db.session.query(azureAdEnumeratedCustomDirectoryRoles).filter_by(uuid=uuid, victim=victim).delete()
        db.session.query(azureAdEnumeratedDevices).filter_by(uuid=uuid, victim=victim).delete()
        db.session.query(azureAdEnumeratedServicePrinciple).filter_by(uuid=uuid, victim=victim).delete()
        db.session.query(azureAdEnumeratedConditionalAccessPolicy).filter_by(uuid=uuid, victim=victim).delete()
        db.session.query(azureAdEnumeratedUserProfile).filter_by(uuid=uuid, victim=victim).delete()
        db.session.commit()

    def getAdRolesForUser(uuid, accessToken, response, victim):
        with ThreadPoolExecutor(max_workers=200) as executor:
            for data in response["value"]:
                displayName       = data['displayName']
                givenName         = data['givenName']
                jobTitle          = data['jobTitle']
                mail              = data['mail']
                mobilePhone       = data['mobilePhone']
                officeLocation    = data['officeLocation']
                preferredLanguage = data['preferredLanguage']
                surname           = data['surname']
                userPrincipalName = data['userPrincipalName']
                Id                = data['id']
                response = azureAdEnum.apiCall(f"/rolemanagement/directory/roleAssignments?$filter=principalId+eq+'{Id}'", 'GET', None, "", accessToken)
                if response.status_code != 200:
                    return
                    
                roles = ""
                response = response.json()
                for data in response["value"]:
                    id = data["roleDefinitionId"]
                    for search in listAdroles:
                        if id in search["id"]:
                            roles = roles + "\r\n" + search["role"]

                insertColleagues = azureAdEnumeratedUsers(uuid=uuid,
                                id=Id,
                                victim=victim,
                                displayName=displayName,
                                givenName=givenName,
                                jobTitle=jobTitle,
                                mail=mail, 
                                mobilePhone=mobilePhone,
                                officeLocation=officeLocation,
                                preferredLanguage=preferredLanguage,
                                surname=surname,
                                userPrincipalName=userPrincipalName,
                                roles=roles)
                db.session.add(insertColleagues)
                print(str(displayName) + " " + Id, end="\r")
                db.session.commit()

    def listusers(uuid, accessToken, victim, endpoint):
        response = azureAdEnum.apiCall(endpoint, 'GET', None, "", accessToken)
        if response.status_code != 200:
            return
        response = response.json()
        
        threading.Thread(target=azureAdEnum.getAdRolesForUser, args=(uuid, accessToken, response, victim)).start()

        if "@odata.nextLink" in response:
            endpoint = response["@odata.nextLink"].split("/v1.0")[1]
            azureAdEnum.listusers(uuid, accessToken, victim, endpoint)

    def getGroupMembers(uuid, token, id, groupName, victim):
        response = azureAdEnum.apiCall("/groups/"+id+"/members", 'GET', None, "", token).json()
        for data in response["value"]:
            try:
                if data['@odata.type'] == "#microsoft.graph.user":
                    userPrincipalName = data['userPrincipalName']
                elif data['@odata.type'] == "#microsoft.graph.group":
                    userPrincipalName = data['displayName'] + " (Group)"
                else:
                    userPrincipalName = data['displayName'] + "( " +data['@odata.type']  + " )"
                memberName        = data['displayName']
                givenName         = ""
                jobTitle          = ""
                mail              = ""
                mobilePhone       = ""
                officeLocation    = ""
                preferredLanguage = ""
                surname           = ""
                id                = data['id']
                
                insertGroupMembers = azureAdEnumeratedGroupMembers(uuid=uuid,
                                id=id, 
                                victim=victim,
                                displayName=memberName,
                                groupName = groupName,
                                givenName=givenName,
                                jobTitle=jobTitle,
                                mail=mail, 
                                mobilePhone=mobilePhone,
                                officeLocation=officeLocation,
                                preferredLanguage=preferredLanguage,
                                surname=surname,
                                userPrincipalName=userPrincipalName
                                )
                 
                db.session.add(insertGroupMembers) 
                
            except Exception as e:
                print("Get GroupMember=> " + str(e))
                print(json.dumps(response["value"], indent=4))

        try:
            db.session.commit()
        except:
            db.session.rollback()

    def listGroupsThread(data, accessToken, victim, uuid):
        try:
            id          = data['id']
            description = data['description']
            mail        = data['mail']
            groupName   = data['displayName']
            owner             = ""
            roleAssignment    = ""
            res = azureAdEnum.apiCall("/groups/"+id+"/owners", 'GET', None, "", accessToken)
            if res.status_code != 200:
                return
            for data1 in res.json()["value"]:
                try:
                    name  = data1["userPrincipalName"]
                    owner = owner + "\r\n" + name
                except Exception as e:
                    print(e)
                    break

            response = azureAdEnum.apiCall("/roleManagement/directory/roleAssignments?$filter=principalId eq '"+id+"'", 'GET', None, "", accessToken)
            if response.status_code != 200:
                return
            #print(str(response.status_code) + " " + id, end="\r")
            response = response.json()
            for data in response["value"]:
                roleId = data["roleDefinitionId"]
                res = azureAdEnum.apiCall("/roleManagement/directory/roleDefinitions/"+roleId, 'GET', None, "", accessToken).json()["displayName"]
                roleAssignment = roleAssignment + "\r\n" + res

            insertGroupData = azureAdEnumeratedGroups(uuid=uuid, id=id, victim=victim, description=description, mail=mail, displayName=groupName, ownerName=owner, roleAssignment=roleAssignment)
            db.session.add(insertGroupData)
            azureAdEnum.getGroupMembers(uuid, accessToken, id, groupName, victim)
        except Exception as e:
            print("listgroupsThread=> " + str(e))

        try:
            db.session.commit()
        except:
            db.session.rollback()
  

    def listGroups(uuid, accessToken, victim, endpoint):
        response = azureAdEnum.apiCall(endpoint, 'GET', None, "", accessToken)
        if response.status_code != 200:
            return
        response = response.json()

        processes = []
        with ThreadPoolExecutor(max_workers=500) as executor:
            for data in response["value"]:
                processes.append(executor.submit(azureAdEnum.listGroupsThread, data, accessToken, victim, uuid))
                  
        for task in as_completed(processes):
            (task.result())

        if "@odata.nextLink" in response:
            endpoint = response["@odata.nextLink"].split("/v1.0")[1]
            azureAdEnum.listGroups(uuid, accessToken, victim, endpoint)


    def listAzureDevices(uuid, accessToken, victim, endpoint):
        response = azureAdEnum.apiCall(endpoint, 'GET', None, "", accessToken)
        if response.status_code != 200:
            return
        response = response.json()
        try:
            response["value"]
        except:
            print("listAzureDevices")
            print(response["value"])
        for data in response["value"]:
            try:
                deviceName     = data['displayName']
                model          = data['model']
                osVersion      = data['operatingSystemVersion']
                deviceId       = data['deviceId']
                accountEnabled = data['accountEnabled']
                manufacturer   = data['manufacturer']
                insertDeviceData = azureAdEnumeratedDevices(uuid=uuid,
                                                            victim=victim,
                                                            deviceName=deviceName, 
                                                            model=model, 
                                                            osVersion=osVersion, 
                                                            deviceId=deviceId, 
                                                            accountEnabled=accountEnabled, 
                                                            manufacturer=manufacturer)
                db.session.add(insertDeviceData)
        
            except Exception as e:
                print("ListAzureDevices" + str(e))
        try:
            db.session.commit()
        except:
            db.session.rollback()
        if "@odata.nextLink" in response:
            endpoint = response["@odata.nextLink"].split("/v1.0")[1]
            azureAdEnum.listAzureDevices(uuid, accessToken, victim, endpoint)

    def listAdminUsers(uuid, accessToken, victim):
        response = azureAdEnum.apiCall("/directoryRoles", 'GET', None, "", accessToken)
        if response.status_code != 200:
            return
        response = response.json()
        with ThreadPoolExecutor(max_workers=20) as executor: 
            for data in response["value"]:
                if "Admin" in data["displayName"]:
                    id = data["id"]
                    roleName = data["displayName"]
                    response1 = azureAdEnum.apiCall(f"/directoryRoles/{id}/members", 'GET', None, "", accessToken).json()

                    try:
                        for data in response1["value"]:
                            if data['@odata.type'] == "#microsoft.graph.user":
                                adminName = data['userPrincipalName']
                            elif data['@odata.type'] == "#microsoft.graph.group":
                                adminName = data['displayName'] + " (Group)"
                            else:
                                adminName = data['displayName'] + "( " +data['@odata.type']  + " )"

                            db.session.add(azureAdEnumeratedAdmins(uuid=uuid, victim=victim, directoryRoleName=roleName, adminName=adminName))
                    except Exception as e:
                        print("listAdminusers 1" + str(e))
                        pass

    
        db.session.commit()

    def listCustomDirectoryroles(uuid, accessToken, victim):
        response = azureAdEnum.apiCall("/roleManagement/directory/roleDefinitions?$filter=(isBuiltIn+eq+false)", 'GET', None, "", accessToken)
        if response.status_code != 200:
            return
        response = response.json()
        for data in response["value"]:
            try:
                id                 = data['id']
                directoryRoleName  = data['displayName']
                description        = data['description']
                
                db.session.add(azureAdEnumeratedCustomDirectoryRoles(uuid=uuid, victim=victim, id=id, directoryRoleName=directoryRoleName, description=description))
            except Exception as e:
                print("listCustomDirectoryroles => " + str(e))
                break
        
        db.session.commit()

    def listApplication(uuid, accessToken, victim, endpoint):
        response = azureAdEnum.apiCall(endpoint, 'GET', None, "", accessToken)
        if response.status_code != 200:
            return
        response = response.json()

        for data in response["value"]:
            try:
                appId           = data["appId"]
                identifierUris  = str("\r\n".join(data["identifierUris"]))
                appName         = data["displayName"]
                publisherDomain = data["publisherDomain"]
                signInAudience  = data["signInAudience"]
                roles = ""
                appRoles  = data["requiredResourceAccess"]
                if appRoles:
                    for role in appRoles[0]["resourceAccess"]:
                        for search in listOfAppRoles:
                            if role["id"] in search["id"]:
                    
                                roles = roles + "\r\n" + search["roleName"]
                    
                insertApplications = azureAdEnumeratedApplications(uuid=uuid, victim=victim, appId=appId, identifierUris=identifierUris, appName=appName, publisherDomain=publisherDomain, signInAudience=signInAudience, appRoles=roles)
                
                db.session.add(insertApplications)    
            except Exception as e:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                print(exc_type, fname, exc_tb.tb_lineno)
                print("listApplication => " + str(e))
                pass

        db.session.commit()
        if "@odata.nextLink" in response:
            endpoint = response["@odata.nextLink"].split("/v1.0")[1]
            azureAdEnum.listApplication(uuid, accessToken, victim, endpoint)
        


    def listServicePrinciples(uuid, token, victim, endpoint):
        response = azureAdEnum.apiCall(endpoint, 'GET', None, "", token)
        if response.status_code != 200:
            return
        response = response.json()

        for data in response["value"]:
            try:
                appDisplayName        = data["appDisplayName"]
                id                    = data["id"]
                homepage              = data["homepage"]
                appDescription        = data["appDescription"]
                servicePrincipalNames = "\r\n".join(data["servicePrincipalNames"])
                signInAudience        = data["signInAudience"]
                keyCredentials        = json.dumps((data["keyCredentials"]), indent=4)
                passwordCredentials   = json.dumps((data["passwordCredentials"]), indent=4)
                replyUrls             = "\r\n".join(data["replyUrls"])
                insertServicePrinciple = azureAdEnumeratedServicePrinciple(uuid=uuid, victim=victim, appDisplayName=appDisplayName, id=id, homepage=homepage, appDescription=appDescription, 
                                                                    servicePrincipalNames=servicePrincipalNames, signInAudience=signInAudience, keyCredentials=keyCredentials, passwordCredentials=passwordCredentials, replyUrls=replyUrls )

                
                db.session.add(insertServicePrinciple)

            except Exception as e:
                print("listServicePrinciples > " + str(e))
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                print(exc_type, fname, exc_tb.tb_lineno)
        db.session.commit()
        if "@odata.nextLink" in response:
            endpoint = response["@odata.nextLink"].split("/v1.0")[1]
            azureAdEnum.listServicePrinciples(uuid, token, victim, endpoint)


    def listConditonalAccessPolicies(uuid, token, victim):
        response = azureAdEnum.apiCall("/identity/conditionalAccess/policies?$top=999", 'GET', None, "", token)
        if response.status_code != 200:
            return
        response = response.json()
        for data in response["value"]:
            try:
                id                                          = data["id"]
                displayName                                 = data["displayName"] 
                createdDateTime                             = data["createdDateTime"]
                modifiedDateTime                            = data["modifiedDateTime"]
                state                                       = data["state"]
                sessionControls                             = data["sessionControls"]
                conditions_clientAppTypes                   = "\r\n".join(data["conditions"]["clientAppTypes"])
                conditions_platforms	                    = data["conditions"]["platforms"]
                conditions_locations	                    = data["conditions"]["locations"]
                conditions_applications_includeApplications	= "\r\n".join(data["conditions"]["applications"]["includeApplications"])
                conditions_users_includeUsers	            = "\r\n".join(data["conditions"]["users"]["includeUsers"])
                grantControls_operator	                    = data["grantControls"]["operator"]
                grantControls_builtInControls               = "\r\n".join(data["grantControls"]["builtInControls"])

                insertConditionalAccessPolicy = azureAdEnumeratedConditionalAccessPolicy(uuid=uuid, victim=victim, id=id, displayName=displayName, createdDateTime=createdDateTime, modifiedDateTime=modifiedDateTime, state=state, sessionControls=sessionControls,
                                                            conditions_clientAppTypes=conditions_clientAppTypes, conditions_platforms=conditions_platforms, conditions_locations=conditions_locations,
                                                            conditions_applications_includeApplications=conditions_applications_includeApplications, conditions_users_includeUsers=conditions_users_includeUsers,
                                                            grantControls_operator=grantControls_operator, grantControls_builtInControls=grantControls_builtInControls)
                
                db.session.add(insertConditionalAccessPolicy)
            except Exception as e:
                print("listConditonalAccessPolicies " + str(e))

        db.session.commit()

    def userProfile(uuid, token, victim):
        profile_res = azureAdEnum.apiCall("/me", 'GET', None, "", token).json()
        displayName       = profile_res['displayName']
        givenName         = profile_res['givenName']
        jobTitle          = profile_res['jobTitle']
        mail              = profile_res['mail']
        mobilePhone       = profile_res['mobilePhone']
        officeLocation    = profile_res['officeLocation']
        preferredLanguage = profile_res['preferredLanguage']
        surname           = profile_res['surname']
        userPrincipalName = profile_res['userPrincipalName']
        Id                = profile_res['id']
        groups = ""
        usersGroup_res = azureAdEnum.apiCall("/users/"+Id+"/memberOf", 'GET', None, "", token).json()
        for group in usersGroup_res["value"]:
            try:
                if group["@odata.type"] == "#microsoft.graph.group":
                    name  = group["displayName"]
                    groups = groups + "\r\n" + name
            except:
                pass
        usersGroups       = groups[2:]
        insertProfile = azureAdEnumeratedUserProfile(uuid=uuid, 
                        victim=victim,
                        id=Id,
                        groups=usersGroups,
                        displayName=displayName,
                        givenName=givenName,
                        jobTitle=jobTitle,
                        mail=mail, 
                        mobilePhone=mobilePhone,
                        officeLocation=officeLocation,
                        preferredLanguage=preferredLanguage,
                        surname=surname,
                        userPrincipalName=userPrincipalName,
                        accessToken=token
                        )
        
        db.session.add(insertProfile)
        
        db.session.commit()

        

    def enum(uuid, token, victim):
        print("started")
        azureAdEnum.flushPreviousdata(uuid, victim)
        azureAdEnum.userProfile(uuid, token, victim)

        ps1 = threading.Thread(target=azureAdEnum.listusers, name="users", args=(uuid, token, victim, "/users?$top=999"))
        ps2 = threading.Thread(target=azureAdEnum.listApplication, name="Applications", args=(uuid, token, victim, "/applications?$top=999"))
        ps3 = threading.Thread(target=azureAdEnum.listAzureDevices, name="device", args=(uuid, token, victim, "/devices?$top=999"))
        ps4 = threading.Thread(target=azureAdEnum.listAdminUsers, name="Admin Users", args=(uuid, token, victim))
        ps5 = threading.Thread(target=azureAdEnum.listCustomDirectoryroles, name="Custom Directory Roles", args=(uuid, token, victim))
        ps6 = threading.Thread(target=azureAdEnum.listServicePrinciples, name="Service Principle", args=(uuid, token, victim, "/servicePrincipals?$top=999"))
        ps7 = threading.Thread(target=azureAdEnum.listConditonalAccessPolicies, name="Conditional Access Policies", args=(uuid, token, victim))
        ps8 = threading.Thread(target=azureAdEnum.listGroups, name="Groups", args=(uuid, token, victim, "/groups?$top=999"))
        
        ps1.start()
        ps2.start()
        ps3.start()
        ps4.start()
        ps5.start()
        ps6.start()
        ps7.start()
        ps8.start()

        ps1.join()
        ps2.join()
        ps3.join()
        ps4.join()
        ps5.join()
        ps6.join()
        ps7.join()
        ps8.join()

        print("Done")


    def enumCred(uuid, username, password, clientId):
        if clientId == "":
            return "error", "ClientId No found!"
        app = msal.ClientApplication(clientId, authority="https://login.microsoftonline.com/organizations")
        result = app.acquire_token_by_username_password(username, password, scopes=[])
        try:
            threading.Thread(target=azureAdEnum.enum, args=(uuid, result["access_token"], username)).start()
            time.sleep(3)
            return "success", "Enumeration running in background please refresh the page after few seconds."
        except Exception as e:
            try:
                return "error", result["error_description"].split(":")[1].split(".")[0]
            except:
                return "error", str(e)


    def enumToken(uuid, accessToken, victim):
        try:
            profile_res = azureAdEnum.apiCall("/me", 'GET', None, "", accessToken).json()
            profile_res['displayName']
        except:
            return "error", "Access Token Expired!"
        try:
            threading.Thread(target=azureAdEnum.enum, args=(uuid, accessToken, victim)).start()
            return "success", "Enumeration running in background please refresh the page after few seconds."
        except:
            return "error", "Invalid or Access Token Expired!"

