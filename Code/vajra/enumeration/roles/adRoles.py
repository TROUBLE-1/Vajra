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

listAdroles = [
 {
   "role": "Application Administrator",
   "id": "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
   "Description": "Can create and manage all aspects of app registrations and enterprise apps."
 },
 {
   "role": "Application Developer",
   "id": "cf1c38e5-3621-4004-a7cb-879624dced7c",
   "Description": "Can create application registrations independent of the ‘Users can register applications’ setting."
 },
 {
   "role": "Authentication Administrator",
   "id": "c4e39bd9-1100-46d3-8c65-fb160da0071f",
   "Description": "Allowed to view, set and reset authentication method information for any non-admin user."
 },
 {
   "role": "Azure DevOps Administrator",
   "id": "e3973bdf-4987-49ae-837a-ba8e231c7286",
   "Description": "Can manage Azure DevOps organization policy and settings."
 },
 {
   "role": "Azure Information Protection Administrator",
   "id": "7495fdc4-34c4-4d15-a289-98788ce399fd",
   "Description": "Can manage all aspects of the Azure Information Protection product."
 },
 {
   "role": "B2C IEF Keyset Administrator",
   "id": "aaf43236-0c0d-4d5f-883a-6955382ac081",
   "Description": "Can manage secrets for federation and encryption in the Identity Experience Framework (IEF)."
 },
 {
   "role": "B2C IEF Policy Administrator",
   "id": "3edaf663-341e-4475-9f94-5c398ef6c070",
   "Description": "Can create and manage trust framework policies in the Identity Experience Framework (IEF)."
 },
 {
   "role": "B2C User Flow Administrator",
   "id": "6e591065-9bad-43ed-90f3-e9424366d2f0",
   "Description": "Can create and manage all aspects of user flows."
 },
 {
   "role": "B2C User Flow Attribute Administrator",
   "id": "0f971eea-41eb-4569-a71e-57bb8a3eff1e",
   "Description": "Can create and manage the attribute schema available to all user flows."
 },
 {
   "role": "Billing Administrator",
   "id": "b0f54661-2d74-4c50-afa3-1ec803f12efe",
   "Description": "Can perform common billing related tasks like updating payment information."
 },
 {
   "role": "Cloud Application Administrator",
   "id": "158c047a-c907-4556-b7ef-446551a6b5f7",
   "Description": "Can create and manage all aspects of app registrations and enterprise apps except App Proxy."
 },
 {
   "role": "Cloud Device Administrator",
   "id": "7698a772-787b-4ac8-901f-60d6b08affd2",
   "Description": "Full access to manage devices in Azure AD."
 },
 {
   "role": "Company Administrator",
   "id": "62e90394-69f5-4237-9190-012177145e10",
   "Description": "Can manage all aspects of Azure AD and Microsoft services that use Azure AD identities."
 },
 {
   "role": "Compliance Administrator",
   "id": "17315797-102d-40b4-93e0-432062caca18",
   "Description": "Can read and manage compliance configuration and reports in Azure AD and Office 365."
 },
 {
   "role": "Compliance Data Administrator",
   "id": "e6d1a23a-da11-4be4-9570-befc86d067a7",
   "Description": "Creates and manages compliance content."
 },
 {
   "role": "Conditional Access Administrator",
   "id": "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
   "Description": "Can manage conditional access capabilities."
 },
 {
   "role": "CRM Service Administrator",
   "id": "44367163-eba1-44c3-98af-f5787879f96a",
   "Description": "Can manage all aspects of the Dynamics 365 product."
 },
 {
   "role": "Customer LockBox Access Approver",
   "id": "5c4f9dcd-47dc-4cf7-8c9a-9e4207cbfc91",
   "Description": "Can approve Microsoft support requests to access customer organizational data."
 },
 {
   "role": "Desktop Analytics Administrator",
   "id": "38a96431-2bdf-4b4c-8b6e-5d3d8abac1a4",
   "Description": "Can access and manage Desktop management tools and services."
 },
 {
   "role": "Device Administrators",
   "id": "9f06204d-73c1-4d4c-880a-6edb90606fd8",
   "Description": "Device Administrators"
 },
 {
   "role": "Device Join",
   "id": "9c094953-4995-41c8-84c8-3ebb9b32c93f",
   "Description": "Device Join"
 },
 {
   "role": "Device Managers",
   "id": "2b499bcd-da44-4968-8aec-78e1674fa64d",
   "Description": "Deprecated – Do Not Use."
 },
 {
   "role": "Device Users",
   "id": "d405c6df-0af8-4e3b-95e4-4d06e542189e",
   "Description": "Device Users"
 },
 {
   "role": "Directory Readers",
   "id": "88d8e3e3-8f55-4a1e-953a-9b9898b8876b",
   "Description": "Can read basic directory information. Commonly used to grant directory read access to applications and guests."
 },
 {
   "role": "Directory Synchronization Accounts",
   "id": "d29b2b05-8046-44ba-8758-1e26182fcf32",
   "Description": "Only used by Azure AD Connect service."
 },
 {
   "role": "Directory Writers",
   "id": "9360feb5-f418-4baa-8175-e2a00bac4301",
   "Description": "Can read and write basic directory information. For granting access to applications, not intended for users."
 },
 {
   "role": "Exchange Service Administrator",
   "id": "29232cdf-9323-42fd-ade2-1d097af3e4de",
   "Description": "Can manage all aspects of the Exchange product."
 },
 {
   "role": "External Identity Provider Administrator",
   "id": "be2f45a1-457d-42af-a067-6ec1fa63bc45",
   "Description": "Can configure identity providers for use in direct federation."
 },
 {
   "role": "Global Reader",
   "id": "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
   "Description": "Can read everything that a global admin can read but not update anything."
 },
 {
   "role": "Groups Administrator",
   "id": "fdd7a751-b60b-444a-984c-02652fe8fa1c",
   "Description": "Members of this role can create/manage groups, create/manage groups settings like naming and expiration policies, and view groups activity and audit reports."
 },
 {
   "role": "Guest Inviter",
   "id": "95e79109-95c0-4d8e-aee3-d01accf2d47b",
   "Description": "Can invite guest users independent of the ‘members can invite guests’ setting."
 },
 {
   "role": "Helpdesk Administrator",
   "id": "729827e3-9c14-49f7-bb1b-9608f156bbb8",
   "Description": "Can reset passwords for non-administrators and Helpdesk Administrators."
 },
 {
   "role": "Intune Service Administrator",
   "id": "3a2c62db-5318-420d-8d74-23affee5d9d5",
   "Description": "Can manage all aspects of the Intune product."
 },
 {
   "role": "Kaizala Administrator",
   "id": "74ef975b-6605-40af-a5d2-b9539d836353",
   "Description": "Can manage settings for Microsoft Kaizala."
 },
 {
   "role": "License Administrator",
   "id": "4d6ac14f-3453-41d0-bef9-a3e0c569773a",
   "Description": "Can manage product licenses on users and groups."
 },
 {
   "role": "Lync Service Administrator",
   "id": "75941009-915a-4869-abe7-691bff18279e",
   "Description": "Can manage all aspects of the Skype for Business product."
 },
 {
   "role": "Message Center Privacy Reader",
   "id": "ac16e43d-7b2d-40e0-ac05-243ff356ab5b",
   "Description": "Can read security messages and updates in Office 365 Message Center only."
 },
 {
   "role": "Message Center Reader",
   "id": "790c1fb9-7f7d-4f88-86a1-ef1f95c05c1b",
   "Description": "Can read messages and updates for their organization in Office 365 Message Center only."
 },
 {
   "role": "Office Apps Administrator",
   "id": "2b745bdf-0803-4d80-aa65-822c4493daac",
   "Description": "Can manage Office apps cloud services, including policy and settings management, and manage the ability to select, unselect and publish ‘what’s new’ feature content to end-user’s devices."
 },
 {
   "role": "Partner Tier1 Support",
   "id": "4ba39ca4-527c-499a-b93d-d9b492c50246",
   "Description": "Do not use – not intended for general use."
 },
 {
   "role": "Partner Tier2 Support",
   "id": "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8",
   "Description": "Do not use – not intended for general use."
 },
 {
   "role": "Password Administrator",
   "id": "966707d0-3269-4727-9be2-8c3a10f19b9d",
   "Description": "Can reset passwords for non-administrators and Password Administrators."
 },
 {
   "role": "Power BI Service Administrator",
   "id": "a9ea8996-122f-4c74-9520-8edcd192826c",
   "Description": "Can manage all aspects of the Power BI product."
 },
 {
   "role": "Power Platform Administrator",
   "id": "11648597-926c-4cf3-9c36-bcebb0ba8dcc",
   "Description": "Can create and manage all aspects of Microsoft Dynamics 365, PowerApps and Microsoft Flow."
 },
 {
   "role": "Printer Administrator",
   "id": "644ef478-e28f-4e28-b9dc-3fdde9aa0b1f",
   "Description": "Can manage all aspects of printers and printer connectors."
 },
 {
   "role": "Printer Technician",
   "id": "e8cef6f1-e4bd-4ea8-bc07-4b8d950f4477",
   "Description": "Can manage all aspects of printers and printer connectors."
 },
 {
   "role": "Privileged Authentication Administrator",
   "id": "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
   "Description": "Allowed to view, set and reset authentication method information for any user (admin or non-admin)."
 },
 {
   "role": "Privileged role Administrator",
   "id": "e8611ab8-c189-46e8-94e1-60213ab1f814",
   "Description": "Can manage role assignments in Azure AD, and all aspects of Privileged Identity Management."
 },
 {
   "role": "Reports Reader",
   "id": "4a5d8f65-41da-4de4-8968-e035b65339cf",
   "Description": "Can read sign-in and audit reports."
 },
 {
   "role": "Search Administrator",
   "id": "0964bb5e-9bdb-4d7b-ac29-58e794862a40",
   "Description": "Can create and manage all aspects of Microsoft Search settings."
 },
 {
   "role": "Search Editor",
   "id": "8835291a-918c-4fd7-a9ce-faa49f0cf7d9",
   "Description": "Can create and manage the editorial content such as bookmarks, Q and As, locations, floorplan."
 },
 {
   "role": "Security Administrator",
   "id": "194ae4cb-b126-40b2-bd5b-6091b380977d",
   "Description": "Security Administrator allows ability to read and manage security configuration and reports."
 },
 {
   "role": "Security Operator",
   "id": "5f2222b1-57c3-48ba-8ad5-d4759f1fde6f",
   "Description": "Creates and manages security events."
 },
 {
   "role": "Security Reader",
   "id": "5d6b6bb7-de71-4623-b4af-96380a352509",
   "Description": "Can read security information and reports in Azure AD and Office 365."
 },
 {
   "role": "Service Support Administrator",
   "id": "f023fd81-a637-4b56-95fd-791ac0226033",
   "Description": "Can read service health information and manage support tickets."
 },
 {
   "role": "SharePoint Service Administrator",
   "id": "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
   "Description": "Can manage all aspects of the SharePoint service."
 },
 {
   "role": "Teams Communications Administrator",
   "id": "baf37b3a-610e-45da-9e62-d9d1e5e8914b",
   "Description": "Can manage calling and meetings features within the Microsoft Teams service."
 },
 {
   "role": "Teams Communications Support Engineer",
   "id": "f70938a0-fc10-4177-9e90-2178f8765737",
   "Description": "Can troubleshoot communications issues within Teams using advanced tools."
 },
 {
   "role": "Teams Communications Support Specialist",
   "id": "fcf91098-03e3-41a9-b5ba-6f0ec8188a12",
   "Description": "Can troubleshoot communications issues within Teams using basic tools."
 },
 {
   "role": "Teams Service Administrator",
   "id": "69091246-20e8-4a56-aa4d-066075b2a7a8",
   "Description": "Can manage the Microsoft Teams service."
 },
 {
   "role": "User Account Administrator",
   "id": "fe930be7-5e62-47db-91af-98c3a49a38b1",
   "Description": "Can manage all aspects of users and groups, including resetting passwords for limited admins."
 },
 {
   "role": "Workplace Device Join",
   "id": "c34f683f-4d5a-4403-affd-6615e00e3a7f",
   "Description": "Workplace Device Join"
 }
]