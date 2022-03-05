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

import socket
from vajra import db
from vajra.models import  enumerationdata, enumerationResults, subdomainLogs


class subdomainenum():
    def dnsResult(uuid, newDomain):
        try:
            socket.gethostbyname(newDomain)
            db.session.add(enumerationResults(uuid=uuid, validSubdomain=newDomain))
            try:
                log = (f"<br><span style=\"color:#7FFFD4\">[+] Valid: {newDomain}</span>" )
                db.session.add(subdomainLogs(uuid=uuid, message=log))
                db.session.commit()
            except:
                db.session.rollback()

        except Exception as e:
            pass  

    def enum(uuid):
        enumerationResults.query.filter_by(uuid=uuid).delete()
        db.session.commit()
        db.engine.execute(f"UPDATE enumeration_status SET subdomain ='True' WHERE uuid = '{uuid}'")
        azureSubdomains= {"onmicrosoft.com":"Microsoft Hosted Domain",
                    "msappproxy.net": "Application Proxy",
					"scm.azurewebsites.net":"App Services - Management",
					"azurewebsites.net":"App Services",
					"p.azurewebsites.net":"App Services",
					"cloudapp.net":"App Services",
					"file.core.windows.net":"Storage Accounts - Files",
					"blob.core.windows.net":"Storage Accounts - Blobs",
					"queue.core.windows.net":"Storage Accounts - Queues",
					"table.core.windows.net":"Storage Accounts - Tables",
					"mail.protection.outlook.com":"Email",
					"sharepoint.com":"SharePoint",
					"redis.cache.windows.net":"Databases-Redis",
					"documents.azure.com":"Databases-Cosmos DB",
					"database.windows.net":"Databases-MSSQL",
					"vault.azure.net":"Key Vaults",
					"azureedge.net":"CDN",
					"search.windows.net":"Search Appliance",
					"azure-api.net":"API Services",
					"azurecr.io":"Azure Container Registry",
                    "trafficmanager.net": "Azure Traffic Manager",
                    "servicebus.windows.net": "Azure Service Bus",
                    "azure-mobile.net": "Azure Mobile Apps",
                    "gin.mediaservices.windows.net":"Azure Media Services",
                    "vo.msecnd.net":"Azure Content Delivery Network",
                    "cloudapp.azure.com": "Azure Cloud Services",
                    "biztalk.windows.net":"Azure BizTalk Services",
                    "graph.windows.net":"Azure Active Directory"
					}

                    
        wordlist = enumerationdata.query.filter_by(uuid=uuid).all()
        for word in wordlist:
            for domin in azureSubdomains:
                newDomain = word.subdomainWordlist + "." + domin
                subdomainenum.dnsResult(uuid, newDomain)

        log = (f"<br><span style=\"color:#7FFFD4\">[+] Valid: Done</span>" ) 
        db.session.add(subdomainLogs(uuid=uuid, message=log))
        db.session.commit()
        db.engine.execute(f"UPDATE enumeration_status SET subdomain ='False' WHERE uuid = '{uuid}'")