

import msal, threading, requests , os, sys, json, time
from vajra import db
from vajra.models import  *
from concurrent.futures import ThreadPoolExecutor, as_completed
from vajra.azure.enumeration.roles.applicationPermission import listOfAppRoles
from vajra.azure.enumeration.roles.adRoles import listAdroles
from vajra.azure.enumeration.roles.adminRoles import adminRoles, adRoles


class azureAdEnum():
    def apiCall(uuid, url, method, contentType, data, accessToken):
        #admin = Admin.query.filter_by(id=uuid).first()
        #admin.azureUsage = admin.azureUsage + 1
        #db.session.commit();db.session.close()
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
        db.session.commit();db.session.close()

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
        db.session.commit();db.session.close()

    def getAdRolesForUser(uuid, accessToken, data, victim):
        
        
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
        
        
        groups = ""
        usersGroup_res = azureAdEnum.apiCall(uuid, "/users/"+Id+"/memberOf", 'GET', None, "", accessToken).json()
        if "value" in usersGroup_res:
            for group in usersGroup_res["value"]:
                try:
                    if group["@odata.type"] == "#microsoft.graph.group":
                        name  = group["displayName"]
                        groups = groups + "\r\n" + name
                except:
                    pass
        usersGroups       = groups[2:]

        roles = ""
        response = azureAdEnum.apiCall(uuid, f"/rolemanagement/directory/roleAssignments?$filter=principalId+eq+'{Id}'", 'GET', None, "", accessToken)
        if response.status_code == 200:
            response = response.json()
            
            if "value" in response:
                for data in response["value"]:
            
                    id = data["roleDefinitionId"]
                    for search in listAdroles:
                        if id in search["id"]:
                            roles = roles + "\r\n" + search["role"]

        insertColleagues = azureAdEnumeratedUsers(uuid=uuid,id=Id,victim=victim,displayName=displayName,givenName=givenName,jobTitle=jobTitle,mail=mail, 
                        mobilePhone=mobilePhone,officeLocation=officeLocation,preferredLanguage=preferredLanguage,surname=surname,userPrincipalName=userPrincipalName,
                        roles=roles, usersGroups=usersGroups)
        db.session.add(insertColleagues)
        time.sleep(2)
        db.session.commit()


    def listusers(uuid, accessToken, victim, endpoint):
        response = azureAdEnum.apiCall(uuid, endpoint, 'GET', None, "", accessToken)
        if response.status_code != 200:
            return
        response = response.json()
        processes = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            for data in response["value"]:
                processes.append(executor.submit(azureAdEnum.getAdRolesForUser, uuid, accessToken, data, victim))
                  
        for task in as_completed(processes):
            (task.result())

        if "@odata.nextLink" in response:
            endpoint = response["@odata.nextLink"].split("/v1.0")[1]
            azureAdEnum.listusers(uuid, accessToken, victim, endpoint)

    def getGroupMembers(uuid, token, id, groupName, victim):
        response = azureAdEnum.apiCall(uuid, "/groups/"+id+"/members", 'GET', None, "", token).json()
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
            db.session.commit();db.session.close()
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
            res = azureAdEnum.apiCall(uuid, "/groups/"+id+"/owners", 'GET', None, "", accessToken)
            if res.status_code != 200:
                return
            for data1 in res.json()["value"]:
                try:
                    name  = data1["userPrincipalName"]
                    owner = owner + "\r\n" + name
                except Exception as e:
                    print(e)
                    break

            response = azureAdEnum.apiCall(uuid, "/roleManagement/directory/roleAssignments?$filter=principalId eq '"+id+"'", 'GET', None, "", accessToken)
            if response.status_code != 200:
                return
            #print(str(response.status_code) + " " + id, end="\r")
            response = response.json()
            for data in response["value"]:
                roleId = data["roleDefinitionId"]
                res = azureAdEnum.apiCall(uuid, "/roleManagement/directory/roleDefinitions/"+roleId, 'GET', None, "", accessToken).json()["displayName"]
                roleAssignment = roleAssignment + "\r\n" + res

            insertGroupData = azureAdEnumeratedGroups(uuid=uuid, id=id, victim=victim, description=description, mail=mail, displayName=groupName, ownerName=owner, roleAssignment=roleAssignment)
            db.session.add(insertGroupData)
            azureAdEnum.getGroupMembers(uuid, accessToken, id, groupName, victim)
        except Exception as e:
            print("listgroupsThread=> " + str(e))

        try:
            time.sleep(2)
            db.session.commit();db.session.close()
        except:
            db.session.rollback()
  

    def listGroups(uuid, accessToken, victim, endpoint):
        response = azureAdEnum.apiCall(uuid, endpoint, 'GET', None, "", accessToken)
        if response.status_code != 200:
            return
        response = response.json()

        processes = []
        with ThreadPoolExecutor(max_workers=100) as executor:
            for data in response["value"]:
                processes.append(executor.submit(azureAdEnum.listGroupsThread, data, accessToken, victim, uuid))
                  
        for task in as_completed(processes):
            (task.result())

        if "@odata.nextLink" in response:
            endpoint = response["@odata.nextLink"].split("/v1.0")[1]
            azureAdEnum.listGroups(uuid, accessToken, victim, endpoint)


    def listAzureDevices(uuid, accessToken, victim, endpoint):
        response = azureAdEnum.apiCall(uuid, endpoint, 'GET', None, "", accessToken)
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
            db.session.commit();db.session.close()
        except:
            db.session.rollback()
        if "@odata.nextLink" in response:
            endpoint = response["@odata.nextLink"].split("/v1.0")[1]
            azureAdEnum.listAzureDevices(uuid, accessToken, victim, endpoint)

    def listAdminUsers(uuid, accessToken, victim, endpoint):
        response = azureAdEnum.apiCall(uuid, endpoint, 'GET', None, "", accessToken)
        if response.status_code != 200:
            return
        response = response.json()

        def adminusers(uuid, victim, user, accessToken, endpoint):
#            print(user["userPrincipalName"])
            id = user["id"]
            adminroles = []
            assignments = azureAdEnum.apiCall(uuid, f"/rolemanagement/directory/roleAssignments?$filter=principalId+eq+'{id}'", 'GET', None, "", accessToken).json()
            if "value" in assignments:
                for role in assignments["value"]:
                    roleDefinitionId = role["roleDefinitionId"]
                    if roleDefinitionId in adminRoles:
                        adminroles.append(adRoles[roleDefinitionId] + " : " + roleDefinitionId)

            if adminroles != []:
                adminName = user['userPrincipalName']
                roleName = "\r\n".join(adminroles)

                db.session.add(azureAdEnumeratedAdmins(uuid=uuid, victim=victim, directoryRoleName=roleName, adminName=adminName))
                db.session.commit();db.session.close()
            
        processes = []
        with ThreadPoolExecutor(max_workers=10) as executor: 
            for user in response["value"]:
                processes.append(executor.submit(adminusers, uuid, victim, user, accessToken, endpoint))
        for task in as_completed(processes):
            (task.result())

        db.session.commit()
        
        db.session.commit();db.session.close()
        if "@odata.nextLink" in response:
            endpoint = response["@odata.nextLink"].split("/v1.0")[1]
            azureAdEnum.listAdminUsers(uuid, accessToken, victim, endpoint)


    def listCustomDirectoryroles(uuid, accessToken, victim):
        response = azureAdEnum.apiCall(uuid, "/roleManagement/directory/roleDefinitions?$filter=(isBuiltIn+eq+false)", 'GET', None, "", accessToken)
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
        
        db.session.commit();db.session.close()

    def listApplication(uuid, accessToken, victim, endpoint):
        response = azureAdEnum.apiCall(uuid, endpoint, 'GET', None, "", accessToken)
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

        db.session.commit();db.session.close()
        if "@odata.nextLink" in response:
            endpoint = response["@odata.nextLink"].split("/v1.0")[1]
            azureAdEnum.listApplication(uuid, accessToken, victim, endpoint)
        


    def listServicePrinciples(uuid, token, victim, endpoint):
        response = azureAdEnum.apiCall(uuid, endpoint, 'GET', None, "", token)
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
        db.session.commit();db.session.close()
        if "@odata.nextLink" in response:
            endpoint = response["@odata.nextLink"].split("/v1.0")[1]
            azureAdEnum.listServicePrinciples(uuid, token, victim, endpoint)


    def listConditonalAccessPolicies(uuid, token, victim):
        response = azureAdEnum.apiCall(uuid, "/identity/conditionalAccess/policies?$top=999", 'GET', None, "", token)
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

        db.session.commit();db.session.close()

    def userProfile(uuid, token, victim):
        profile_res = azureAdEnum.apiCall(uuid, "/me", 'GET', None, "", token).json()
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
        usersGroup_res = azureAdEnum.apiCall(uuid, "/users/"+Id+"/memberOf", 'GET', None, "", token).json()
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
                        accessToken=token,
                        enumStatus="progress"
                        )
        
        db.session.add(insertProfile)
        
        db.session.commit();db.session.close()

        

    def enum(uuid, token, victim):
        
        ps1 = threading.Thread(target=azureAdEnum.listusers, name="users", args=(uuid, token, victim, "/users?$top=999"))
        ps2 = threading.Thread(target=azureAdEnum.listApplication, name="Applications", args=(uuid, token, victim, "/applications?$top=999"))
        ps3 = threading.Thread(target=azureAdEnum.listAzureDevices, name="device", args=(uuid, token, victim, "/devices?$top=999"))
        ps4 = threading.Thread(target=azureAdEnum.listAdminUsers, name="Admin Users", args=(uuid, token, victim, "/users?$top=999"))
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

        victim = azureAdEnumeratedUserProfile.query.filter_by(uuid=uuid, victim=victim).first()
        victim.enumStatus = "completed"
        db.session.commit();db.session.close()        


    def enumCred(uuid, username, password, clientId):
        if clientId == "":
            return "error", "ClientId No found!"
        app = msal.ClientApplication(clientId, authority="https://login.microsoftonline.com/organizations")
        result = app.acquire_token_by_username_password(username, password, scopes=[])
        try:
            azureAdEnum.flushPreviousdata(uuid, username)
            azureAdEnum.userProfile(uuid, result["access_token"], username)
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
            profile_res = azureAdEnum.apiCall(uuid, "/me", 'GET', None, "", accessToken).json()
            profile_res['displayName']
        except:
            return "error", "Access Token Expired!"
        try:
            azureAdEnum.flushPreviousdata(uuid, victim)
            azureAdEnum.userProfile(uuid, accessToken, victim)
            threading.Thread(target=azureAdEnum.enum, args=(uuid, accessToken, victim)).start()
            return "success", "Enumeration running in background please refresh the page after few seconds."
        except:
            return "error", "Invalid or Access Token Expired!"

