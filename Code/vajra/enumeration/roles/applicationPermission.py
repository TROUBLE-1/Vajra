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

listOfAppRoles = [
 {
   "roleName": "APIConnectors.Read.All",
   "id": "b86848a7-d5b1-41eb-a9b4-54a4e6306e97",
   "Display Name": "Read API connectors for authentication flows",
   "Description": "Allows the app to read the API connectors used in user authentication flows, without a signed-in user."
 },
 {
   "roleName": "APIConnectors.ReadWrite.All",
   "id": "1dfe531a-24a6-4f1b-80f4-7a0dc5a0a171",
   "Display Name": "Read and write API connectors for authentication flows",
   "Description": "Allows the app to read, create and manage the API connectors used in user authentication flows, without a signed-in user."
 },
 {
   "roleName": "AccessReview.Read.All",
   "id": "d07a8cc0-3d51-4b77-b3b0-32704d1f69fa",
   "Display Name": "Read all access reviews",
   "Description": "Allows the app to read access reviews, reviewers, decisions and settings in the organization, without a signed-in user."
 },
 {
   "roleName": "AccessReview.ReadWrite.All",
   "id": "ef5f7d5c-338f-44b0-86c3-351f46c8bb5f",
   "Display Name": "Manage all access reviews",
   "Description": "Allows the app to read, update, delete and perform actions on access reviews, reviewers, decisions and settings in the organization, without a signed-in user."
 },
 {
   "roleName": "AccessReview.ReadWrite.Membership",
   "id": "18228521-a591-40f1-b215-5fad4488c117",
   "Display Name": "Manage access reviews for group and app memberships",
   "Description": "Allows the app to read, update, delete and perform actions on access reviews, reviewers, decisions and settings in the organization for group and app memberships, without a signed-in user."
 },
 {
   "roleName": "AdministrativeUnit.Read.All",
   "id": "134fd756-38ce-4afd-ba33-e9623dbe66c2",
   "Display Name": "Read all administrative units",
   "Description": "Allows the app to read administrative units and administrative unit membership without a signed-in user."
 },
 {
   "roleName": "AdministrativeUnit.ReadWrite.All",
   "id": "5eb59dd3-1da2-4329-8733-9dabdc435916",
   "Display Name": "Read and write all administrative units",
   "Description": "Allows the app to create, read, update, and delete administrative units and manage administrative unit membership without a signed-in user."
 },
 {
   "roleName": "Agreement.Read.All",
   "id": "2f3e6f8c-093b-4c57-a58b-ba5ce494a169",
   "Display Name": "Read all terms of use agreements",
   "Description": "Allows the app to read terms of use agreements, without a signed in user."
 },
 {
   "roleName": "Agreement.ReadWrite.All",
   "id": "c9090d00-6101-42f0-a729-c41074260d47",
   "Display Name": "Read and write all terms of use agreements",
   "Description": "Allows the app to read and write terms of use agreements, without a signed in user."
 },
 {
   "roleName": "AgreementAcceptance.Read.All",
   "id": "d8e4ec18-f6c0-4620-8122-c8b1f2bf400e",
   "Display Name": "Read all terms of use acceptance statuses",
   "Description": "Allows the app to read terms of use acceptance statuses, without a signed in user."
 },
 {
   "roleName": "AppRoleAssignment.ReadWrite.All",
   "id": "06b708a9-e830-4db3-a914-8e69da51d44f",
   "Display Name": "Manage app permission grants and app role assignments",
   "Description": "Allows the app to manage permission grants for application permissions to any API (including Microsoft Graph) and application assignments for any app, without a signed-in user."
 },
 {
   "roleName": "Application.Read.All",
   "id": "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30",
   "Display Name": "Read all applications",
   "Description": "Allows the app to read all applications and service principals without a signed-in user."
 },
 {
   "roleName": "Application.ReadWrite.All",
   "id": "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9",
   "Display Name": "Read and write all applications",
   "Description": "Allows the app to create, read, update and delete applications and service principals without a signed-in user.  Does not allow management of consent grants."
 },
 {
   "roleName": "Application.ReadWrite.OwnedBy",
   "id": "18a4783c-866b-4cc7-a460-3d5e5662c884",
   "Display Name": "Manage apps that this app creates or owns",
   "Description": "Allows the app to create other applications, and fully manage those applications (read, update, update application secrets and delete), without a signed-in user.  It cannot update any apps that it is not an owner of."
 },
 {
   "roleName": "ApprovalRequest.Read.AdminConsentRequest",
   "id": "0d9d2e88-e2eb-4ac7-9b1d-9b68ed9f9f4f",
   "Display Name": "Read all admin consent approval requests",
   "Description": "Allows the app to read admin consent requests, business flows, and governance policy templates without a signed-in user."
 },
 {
   "roleName": "ApprovalRequest.Read.CustomerLockbox",
   "id": "080ce695-a830-4d5c-a45a-375e3ab11b11",
   "Display Name": "Read all customer lockbox approval requests",
   "Description": "Allows the app to read customer lockbox requests, business flows, and governance policy templates without a signed-in user."
 },
 {
   "roleName": "ApprovalRequest.Read.EntitlementManagement",
   "id": "b2a3adf0-5774-4846-986c-a91c705b0141",
   "Display Name": "Read all entitlement management approval requests",
   "Description": "Allows the app to read entitlement management requests, business flows, and governance policy templates without a signed-in user."
 },
 {
   "roleName": "ApprovalRequest.Read.PriviligedAccess",
   "id": "3f410ed8-2d83-4435-b2c4-c776f44e4ae1",
   "Display Name": "Read all privileged access approval requests",
   "Description": "Allows the app to read privileged access requests, business flows, and governance policy templates without a signed-in user."
 },
 {
   "roleName": "ApprovalRequest.ReadWrite.AdminConsentRequest",
   "id": "afe5c674-a576-4b80-818c-e3d7f6afd299",
   "Display Name": "Read and write all admin consent approval requests",
   "Description": "Allows the app to read and write admin consent requests, business flows, and governance policy templates without a signed-in user."
 },
 {
   "roleName": "ApprovalRequest.ReadWrite.CustomerLockbox",
   "id": "5f411d27-abad-4dc3-83c6-b84a46ffa434",
   "Display Name": "Read and write all customer lockbox approval requests",
   "Description": "Allows the app to read and write customer lockbox requests, business flows, and governance policy templates without a signed-in user."
 },
 {
   "roleName": "ApprovalRequest.ReadWrite.EntitlementManagement",
   "id": "fbfdecc9-4b78-4882-bb98-7decbddcbddf",
   "Display Name": "Read and write all entitlement management approval requests",
   "Description": "Allows the app to read and write entitlement management requests, business flows, and governance policy templates without a signed-in user."
 },
 {
   "roleName": "ApprovalRequest.ReadWrite.PriviligedAccess",
   "id": "60182ac6-4565-4baa-8b04-9350fe8dbfca",
   "Display Name": "Read and write all privileged access approval requests",
   "Description": "Allows the app to read and write privileged access requests, business flows, and governance policy templates without a signed-in user."
 },
 {
   "roleName": "AuditLog.Read.All",
   "id": "b0afded3-3588-46d8-8b3d-9842eff778da",
   "Display Name": "Read all audit log data",
   "Description": "Allows the app to read and query your audit log activities, without a signed-in user."
 },
 {
   "roleName": "BitlockerKey.Read.All",
   "id": "57f1cf28-c0c4-4ec3-9a30-19a2eaaf2f6e",
   "Display Name": "Read all BitLocker keys",
   "Description": "Allows an app to read BitLocker keys for all devices, without a signed-in user. Allows read of the recovery key."
 },
 {
   "roleName": "BitlockerKey.ReadBasic.All",
   "id": "f690d423-6b29-4d04-98c6-694c42282419",
   "Display Name": "Read all BitLocker keys basic information",
   "Description": "Allows an app to read basic BitLocker key properties for all devices, without a signed-in user. Does not allow read of the recovery key."
 },
 {
   "roleName": "Calendars.Read",
   "id": "798ee544-9d2d-430c-a058-570e29e34338",
   "Display Name": "Read calendars in all mailboxes",
   "Description": "Allows the app to read events of all calendars without a signed-in user."
 },
 {
   "roleName": "Calendars.ReadWrite",
   "id": "ef54d2bf-783f-4e0f-bca1-3210c0444d99",
   "Display Name": "Read and write calendars in all mailboxes",
   "Description": "Allows the app to create, read, update, and delete events of all calendars without a signed-in user."
 },
 {
   "roleName": "CallRecord-PstnCalls.Read.All",
   "id": "a2611786-80b3-417e-adaa-707d4261a5f0",
   "Display Name": "Read PSTN and direct routing call log data",
   "Description": "Allows the app to read all PSTN and direct routing call log data without a signed-in user."
 },
 {
   "roleName": "CallRecords.Read.All",
   "id": "45bbb07e-7321-4fd7-a8f6-3ff27e6a81c8",
   "Display Name": "Read all call records",
   "Description": "Allows the app to read call records for all calls and online meetings without a signed-in user."
 },
 {
   "roleName": "Calls.AccessMedia.All",
   "id": "a7a681dc-756e-4909-b988-f160edc6655f",
   "Display Name": "Access media streams in a call as an app",
   "Description": "Allows the app to get direct access to media streams in a call, without a signed-in user."
 },
 {
   "roleName": "Calls.Initiate.All",
   "id": "284383ee-7f6e-4e40-a2a8-e85dcb029101",
   "Display Name": "Initiate outgoing 1 to 1 calls from the app",
   "Description": "Allows the app to place outbound calls to a single user and transfer calls to users in your organization’s directory, without a signed-in user."
 },
 {
   "roleName": "Calls.InitiateGroupCall.All",
   "id": "4c277553-8a09-487b-8023-29ee378d8324",
   "Display Name": "Initiate outgoing group calls from the app",
   "Description": "Allows the app to place outbound calls to multiple users and add participants to meetings in your organization, without a signed-in user."
 },
 {
   "roleName": "Calls.JoinGroupCall.All",
   "id": "f6b49018-60ab-4f81-83bd-22caeabfed2d",
   "Display Name": "Join group calls and meetings as an app",
   "Description": "Allows the app to join group calls and scheduled meetings in your organization, without a signed-in user.  The app will be joined with the privileges of a directory user to meetings in your organization."
 },
 {
   "roleName": "Calls.JoinGroupCallAsGuest.All",
   "id": "fd7ccf6b-3d28-418b-9701-cd10f5cd2fd4",
   "Display Name": "Join group calls and meetings as a guest",
   "Description": "Allows the app to anonymously join group calls and scheduled meetings in your organization, without a signed-in user.  The app will be joined as a guest to meetings in your organization."
 },
 {
   "roleName": "Channel.Create",
   "id": "f3a65bd4-b703-46df-8f7e-0174fea562aa",
   "Display Name": "Create channels",
   "Description": "Create channels in any team, without a signed-in user."
 },
 {
   "roleName": "Channel.Delete.All",
   "id": "6a118a39-1227-45d4-af0c-ea7b40d210bc",
   "Display Name": "Delete channels",
   "Description": "Delete channels in any team, without a signed-in user."
 },
 {
   "roleName": "Channel.ReadBasic.All",
   "id": "59a6b24b-4225-4393-8165-ebaec5f55d7a",
   "Display Name": "Read the names and descriptions  of all channels",
   "Description": "Read all channel names and channel descriptions, without a signed-in user."
 },
 {
   "roleName": "ChannelMember.Read.All",
   "id": "3b55498e-47ec-484f-8136-9013221c06a9",
   "Display Name": "Read the members of all channels",
   "Description": "Read the members of all channels, without a signed-in user."
 },
 {
   "roleName": "ChannelMember.ReadWrite.All",
   "id": "35930dcf-aceb-4bd1-b99a-8ffed403c974",
   "Display Name": "Add and remove members from all channels",
   "Description": "Add and remove members from all channels, without a signed-in user. Also allows changing a member’s role, for example from owner to non-owner."
 },
 {
   "roleName": "ChannelMessage.Read.All",
   "id": "7b2449af-6ccd-4f4d-9f78-e550c193f0d1",
   "Display Name": "Read all channel messages",
   "Description": "Allows the app to read all channel messages in Microsoft Teams"
 },
 {
   "roleName": "ChannelMessage.UpdatePolicyViolation.All",
   "id": "4d02b0cc-d90b-441f-8d82-4fb55c34d6bb",
   "Display Name": "Flag channel messages for violating policy",
   "Description": "Allows the app to update Microsoft Teams channel messages by patching a set of Data Loss Prevention (DLP) policy violation properties to handle the output of DLP processing."
 },
 {
   "roleName": "ChannelSettings.Read.All",
   "id": "c97b873f-f59f-49aa-8a0e-52b32d762124",
   "Display Name": "Read the names, descriptions, and settings of all channels",
   "Description": "Read all channel names, channel descriptions, and channel settings, without a signed-in user."
 },
 {
   "roleName": "ChannelSettings.ReadWrite.All",
   "id": "243cded2-bd16-4fd6-a953-ff8177894c3d",
   "Display Name": "Read and write the names, descriptions, and settings of all channels",
   "Description": "Read and write the names, descriptions, and settings of all channels, without a signed-in user."
 },
 {
   "roleName": "Chat.Create",
   "id": "d9c48af6-9ad9-47ad-82c3-63757137b9af",
   "Display Name": "Create chats",
   "Description": "Allows the app to create chats without a signed-in user."
 },
 {
   "roleName": "Chat.Read.All",
   "id": "6b7d71aa-70aa-4810-a8d9-5d9fb2830017",
   "Display Name": "Read all chat messages",
   "Description": "Allows the app to read all 1-to-1 or group chat messages in Microsoft Teams."
 },
 {
   "roleName": "Chat.ReadBasic.All",
   "id": "b2e060da-3baf-4687-9611-f4ebc0f0cbde",
   "Display Name": "Read names and members of all chat threads",
   "Description": "Read names and members of all one-to-one and group chats in Microsoft Teams, without a signed-in user."
 },
 {
   "roleName": "Chat.ReadWrite.All",
   "id": "294ce7c9-31ba-490a-ad7d-97a7d075e4ed",
   "Display Name": "Read and write all chat messages",
   "Description": "Allows an app to read and write all chat messages in Microsoft Teams, without a signed-in user."
 },
 {
   "roleName": "Chat.UpdatePolicyViolation.All",
   "id": "7e847308-e030-4183-9899-5235d7270f58",
   "Display Name": "Flag chat messages for violating policy",
   "Description": "Allows the app to update Microsoft Teams 1-to-1 or group chat messages by patching a set of Data Loss Prevention (DLP) policy violation properties to handle the output of DLP processing."
 },
 {
   "roleName": "ChatMember.Read.All",
   "id": "a3410be2-8e48-4f32-8454-c29a7465209d",
   "Display Name": "Read the members of all chats",
   "Description": "Read the members of all chats, without a signed-in user."
 },
 {
   "roleName": "ChatMember.ReadWrite.All",
   "id": "57257249-34ce-4810-a8a2-a03adf0c5693",
   "Display Name": "Add and remove members from all chats",
   "Description": "Add and remove members from all chats, without a signed-in user."
 },
 {
   "roleName": "ChatMessage.Read.All",
   "id": "b9bb2381-47a4-46cd-aafb-00cb12f68504",
   "Display Name": "Read all chat messages",
   "Description": "Allows the app to read all one-to-one and group chats messages in Microsoft Teams, without a signed-in user."
 },
 {
   "roleName": "CloudPC.Read.All",
   "id": "a9e09520-8ed4-4cde-838e-4fdea192c227",
   "Display Name": "Read Cloud PCs",
   "Description": "Allows the app to read the properties of Cloud PCs, without a signed-in user."
 },
 {
   "roleName": "CloudPC.ReadWrite.All",
   "id": "3b4349e1-8cf5-45a3-95b7-69d1751d3e6a",
   "Display Name": "Read and write Cloud PCs",
   "Description": "Allows the app to read and write the properties of Cloud PCs, without a signed-in user."
 },
 {
   "roleName": "ConsentRequest.Read.All",
   "id": "1260ad83-98fb-4785-abbb-d6cc1806fd41",
   "Display Name": "Read all consent requests",
   "Description": "Allows the app to read consent requests and approvals without a signed-in user."
 },
 {
   "roleName": "ConsentRequest.ReadWrite.All",
   "id": "9f1b81a7-0223-4428-bfa4-0bcb5535f27d",
   "Display Name": "Read and write all consent requests",
   "Description": "Allows the app to read app consent requests and approvals, and deny or approve those requests without a signed-in user."
 },
 {
   "roleName": "Contacts.Read",
   "id": "089fe4d0-434a-44c5-8827-41ba8a0b17f5",
   "Display Name": "Read contacts in all mailboxes",
   "Description": "Allows the app to read all contacts in all mailboxes without a signed-in user."
 },
 {
   "roleName": "Contacts.ReadWrite",
   "id": "6918b873-d17a-4dc1-b314-35f528134491",
   "Display Name": "Read and write contacts in all mailboxes",
   "Description": "Allows the app to create, read, update, and delete all contacts in all mailboxes without a signed-in user."
 },
 {
   "roleName": "DelegatedPermissionGrant.ReadWrite.All",
   "id": "8e8e4742-1d95-4f68-9d56-6ee75648c72a",
   "Display Name": "Manage all delegated permission grants",
   "Description": "Allows the app to manage permission grants for delegated permissions exposed by any API (including Microsoft Graph), without a signed-in user."
 },
 {
   "roleName": "Device.Read.All",
   "id": "7438b122-aefc-4978-80ed-43db9fcc7715",
   "Display Name": "Read all devices",
   "Description": "Allows the app to read your organization’s devices’ configuration information without a signed-in user."
 },
 {
   "roleName": "Device.ReadWrite.All",
   "id": "1138cb37-bd11-4084-a2b7-9f71582aeddb",
   "Display Name": "Read and write devices",
   "Description": "Allows the app to read and write all device properties without a signed in user.  Does not allow device creation, device deletion or update of device alternative security identifiers."
 },
 {
   "roleName": "DeviceManagementApps.Read.All",
   "id": "7a6ee1e7-141e-4cec-ae74-d9db155731ff",
   "Display Name": "Read Microsoft Intune apps",
   "Description": "Allows the app to read the properties, group assignments and status of apps, app configurations and app protection policies managed by Microsoft Intune, without a signed-in user."
 },
 {
   "roleName": "DeviceManagementApps.ReadWrite.All",
   "id": "78145de6-330d-4800-a6ce-494ff2d33d07",
   "Display Name": "Read and write Microsoft Intune apps",
   "Description": "Allows the app to read and write the properties, group assignments and status of apps, app configurations and app protection policies managed by Microsoft Intune, without a signed-in user."
 },
 {
   "roleName": "DeviceManagementConfiguration.Read.All",
   "id": "dc377aa6-52d8-4e23-b271-2a7ae04cedf3",
   "Display Name": "Read Microsoft Intune device configuration and policies",
   "Description": "Allows the app to read properties of Microsoft Intune-managed device configuration and device compliance policies and their assignment to groups, without a signed-in user."
 },
 {
   "roleName": "DeviceManagementConfiguration.ReadWrite.All",
   "id": "9241abd9-d0e6-425a-bd4f-47ba86e767a4",
   "Display Name": "Read and write Microsoft Intune device configuration and policies",
   "Description": "Allows the app to read and write properties of Microsoft Intune-managed device configuration and device compliance policies and their assignment to groups, without a signed-in user."
 },
 {
   "roleName": "DeviceManagementManagedDevices.PrivilegedOperations.All",
   "id": "5b07b0dd-2377-4e44-a38d-703f09a0dc3c",
   "Display Name": "Perform user-impacting remote actions on Microsoft Intune devices",
   "Description": "Allows the app to perform remote high impact actions such as wiping the device or resetting the passcode on devices managed by Microsoft Intune, without a signed-in user."
 },
 {
   "roleName": "DeviceManagementManagedDevices.Read.All",
   "id": "2f51be20-0bb4-4fed-bf7b-db946066c75e",
   "Display Name": "Read Microsoft Intune devices",
   "Description": "Allows the app to read the properties of devices managed by Microsoft Intune, without a signed-in user."
 },
 {
   "roleName": "DeviceManagementManagedDevices.ReadWrite.All",
   "id": "243333ab-4d21-40cb-a475-36241daa0842",
   "Display Name": "Read and write Microsoft Intune devices",
   "Description": "Allows the app to read and write the properties of devices managed by Microsoft Intune, without a signed-in user. Does not allow high impact operations such as remote wipe and password reset on the device’s owner"
 },
 {
   "roleName": "DeviceManagementRBAC.Read.All",
   "id": "58ca0d9a-1575-47e1-a3cb-007ef2e4583b",
   "Display Name": "Read Microsoft Intune RBAC settings",
   "Description": "Allows the app to read the properties relating to the Microsoft Intune Role-Based Access Control (RBAC) settings, without a signed-in user."
 },
 {
   "roleName": "DeviceManagementRBAC.ReadWrite.All",
   "id": "e330c4f0-4170-414e-a55a-2f022ec2b57b",
   "Display Name": "Read and write Microsoft Intune RBAC settings",
   "Description": "Allows the app to read and write the properties relating to the Microsoft Intune Role-Based Access Control (RBAC) settings, without a signed-in user."
 },
 {
   "roleName": "DeviceManagementServiceConfig.Read.All",
   "id": "06a5fe6d-c49d-46a7-b082-56b1b14103c7",
   "Display Name": "Read Microsoft Intune configuration",
   "Description": "Allows the app to read Microsoft Intune service properties including device enrollment and third party service connection configuration, without a signed-in user."
 },
 {
   "roleName": "DeviceManagementServiceConfig.ReadWrite.All",
   "id": "5ac13192-7ace-4fcf-b828-1a26f28068ee",
   "Display Name": "Read and write Microsoft Intune configuration",
   "Description": "Allows the app to read and write Microsoft Intune service properties including device enrollment and third party service connection configuration, without a signed-in user."
 },
 {
   "roleName": "Directory.Read.All",
   "id": "7ab1d382-f21e-4acd-a863-ba3e13f7da61",
   "Display Name": "Read directory data",
   "Description": "Allows the app to read data in your organization’s directory, such as users, groups and apps, without a signed-in user."
 },
 {
   "roleName": "Directory.ReadWrite.All",
   "id": "19dbc75e-c2e2-444c-a770-ec69d8559fc7",
   "Display Name": "Read and write directory data",
   "Description": "Allows the app to read and write data in your organization’s directory, such as users, and groups, without a signed-in user.  Does not allow user or group deletion."
 },
 {
   "roleName": "Domain.Read.All",
   "id": "dbb9058a-0e50-45d7-ae91-66909b5d4664",
   "Display Name": "Read domains",
   "Description": "Allows the app to read all domain properties without a signed-in user."
 },
 {
   "roleName": "Domain.ReadWrite.All",
   "id": "7e05723c-0bb0-42da-be95-ae9f08a6e53c",
   "Display Name": "Read and write domains",
   "Description": "Allows the app to read and write all domain properties without a signed in user.  Also allows the app to add,  verify and remove domains."
 },
 {
   "roleName": "EduAdministration.Read.All",
   "id": "7c9db06a-ec2d-4e7b-a592-5a1e30992566",
   "Display Name": "Read Education app settings",
   "Description": "Read the state and settings of all Microsoft education apps."
 },
 {
   "roleName": "EduAdministration.ReadWrite.All",
   "id": "9bc431c3-b8bc-4a8d-a219-40f10f92eff6",
   "Display Name": "Manage education app settings",
   "Description": "Manage the state and settings of all Microsoft education apps."
 },
 {
   "roleName": "EduAssignments.Read.All",
   "id": "4c37e1b6-35a1-43bf-926a-6f30f2cdf585",
   "Display Name": "Read class assignments with grades",
   "Description": "Allows the app to read assignments and their grades for all users."
 },
 {
   "roleName": "EduAssignments.ReadBasic.All",
   "id": "6e0a958b-b7fc-4348-b7c4-a6ab9fd3dd0e",
   "Display Name": "Read class assignments without grades",
   "Description": "Allows the app to read assignments without grades for all users."
 },
 {
   "roleName": "EduAssignments.ReadWrite.All",
   "id": "0d22204b-6cad-4dd0-8362-3e3f2ae699d9",
   "Display Name": "Read and write class assignments with grades",
   "Description": "Allows the app to read and write assignments and their grades for all users."
 },
 {
   "roleName": "EduAssignments.ReadWriteBasic.All",
   "id": "f431cc63-a2de-48c4-8054-a34bc093af84",
   "Display Name": "Read and write class assignments without grades",
   "Description": "Allows the app to read and write assignments without grades for all users."
 },
 {
   "roleName": "EduRoster.Read.All",
   "id": "e0ac9e1b-cb65-4fc5-87c5-1a8bc181f648",
   "Display Name": "Read the organization’s roster",
   "Description": "Allows the app to read the structure of schools and classes in the organization’s roster and education-specific information about all users to be read."
 },
 {
   "roleName": "EduRoster.ReadBasic.All",
   "id": "0d412a8c-a06c-439f-b3ec-8abcf54d2f96",
   "Display Name": "Read a limited subset of the organization’s roster",
   "Description": "Allows the app to read a limited subset of properties from both the structure of schools and classes in the organization’s roster and education-specific information about all users. Includes name, status, role, email address and photo."
 },
 {
   "roleName": "EduRoster.ReadWrite.All",
   "id": "d1808e82-ce13-47af-ae0d-f9b254e6d58a",
   "Display Name": "Read and write the organization’s roster",
   "Description": "Allows the app to read and write the structure of schools and classes in the organization’s roster and education-specific information about all users to be read and written."
 },
 {
   "roleName": "EntitlementManagement.Read.All",
   "id": "c74fd47d-ed3c-45c3-9a9e-b8676de685d2",
   "Display Name": "Read all entitlement management resources",
   "Description": "Allows the app to read access packages and related entitlement management resources without a signed-in user."
 },
 {
   "roleName": "EntitlementManagement.ReadWrite.All",
   "id": "9acd699f-1e81-4958-b001-93b1d2506e19",
   "Display Name": "Read and write all entitlement management resources",
   "Description": "Allows the app to read and write access packages and related entitlement management resources without a signed-in user."
 },
 {
   "roleName": "ExternalConnection.ReadWrite.OwnedBy",
   "id": "f431331c-49a6-499f-be1c-62af19c34a9d",
   "Display Name": "Read and write external connections",
   "Description": "Allows the app to read and write external connections without a signed-in user. The app can only read and write external connections that it is authorized to, or it can create new external connections."
 },
 {
   "roleName": "ExternalItem.ReadWrite.All",
   "id": "38c3d6ee-69ee-422f-b954-e17819665354",
   "Display Name": "Read and write items in external datasets",
   "Description": "Allow the app to read or write items in all external datasets that the app is authorized to access"
 },
 {
   "roleName": "ExternalItem.ReadWrite.OwnedBy",
   "id": "8116ae0f-55c2-452d-9944-d18420f5b2c8",
   "Display Name": "Read and write external items",
   "Description": "Allows the app to read and write external items without a signed-in user. The app can only read external items of the connection that it is authorized to."
 },
 {
   "roleName": "Files.Read.All",
   "id": "01d4889c-1287-42c6-ac1f-5d1e02578ef6",
   "Display Name": "Read files in all site collections",
   "Description": "Allows the app to read all files in all site collections without a signed in user."
 },
 {
   "roleName": "Files.ReadWrite.All",
   "id": "75359482-378d-4052-8f01-80520e7db3cd",
   "Display Name": "Read and write files in all site collections",
   "Description": "Allows the app to read, create, update and delete all files in all site collections without a signed in user."
 },
 {
   "roleName": "Group.Create",
   "id": "bf7b1a76-6e77-406b-b258-bf5c7720e98f",
   "Display Name": "Create groups",
   "Description": "Allows the app to create groups without a signed-in user."
 },
 {
   "roleName": "Group.Read.All",
   "id": "5b567255-7703-4780-807c-7be8301ae99b",
   "Display Name": "Read all groups",
   "Description": "Allows the app to read group properties and memberships, and read the calendar and conversations for all groups, without a signed-in user."
 },
 {
   "roleName": "Group.ReadWrite.All",
   "id": "62a82d76-70ea-41e2-9197-370581804d09",
   "Display Name": "Read and write all groups",
   "Description": "Allows the app to create groups, read all group properties and memberships, update group properties and memberships, and delete groups. Also allows the app to read and write group calendar and conversations.  All of these operations can be performed by the app without a signed-in user."
 },
 {
   "roleName": "GroupMember.Read.All",
   "id": "98830695-27a2-44f7-8c18-0c3ebc9698f6",
   "Display Name": "Read all group memberships",
   "Description": "Allows the app to read memberships and basic group properties for all groups without a signed-in user."
 },
 {
   "roleName": "GroupMember.ReadWrite.All",
   "id": "dbaae8cf-10b5-4b86-a4a1-f871c94c6695",
   "Display Name": "Read and write all group memberships",
   "Description": "Allows the app to list groups, read basic properties, read and update the membership of the groups this app has access to without a signed-in user. Group properties and owners cannot be updated and groups cannot be deleted."
 },
 {
   "roleName": "identityProvider.Read.All",
   "id": "e321f0bb-e7f7-481e-bb28-e3b0b32d4bd0",
   "Display Name": "Read identity providers",
   "Description": "Allows the app to read your organization’s identity (authentication) providers’ properties without a signed in user."
 },
 {
   "roleName": "identityProvider.ReadWrite.All",
   "id": "90db2b9a-d928-4d33-a4dd-8442ae3d41e4",
   "Display Name": "Read and write identity providers",
   "Description": "Allows the app to read and write your organization’s identity (authentication) providers’ properties without a signed in user."
 },
 {
   "roleName": "identityRiskEvent.Read.All",
   "id": "6e472fd1-ad78-48da-a0f0-97ab2c6b769e",
   "Display Name": "Read all identity risk event information",
   "Description": "Allows the app to read the identity risk event information for your organization without a signed in user."
 },
 {
   "roleName": "identityRiskEvent.ReadWrite.All",
   "id": "db06fb33-1953-4b7b-a2ac-f1e2c854f7ae",
   "Display Name": "Read and write all risk detection information",
   "Description": "Allows the app to read and update identity risk detection information for your organization without a signed-in user. Update operations include confirming risk event detections."
 },
 {
   "roleName": "identityRiskyUser.Read.All",
   "id": "dc5007c0-2d7d-4c42-879c-2dab87571379",
   "Display Name": "Read all identity risky user information",
   "Description": "Allows the app to read the identity risky user information for your organization without a signed in user."
 },
 {
   "roleName": "identityRiskyUser.ReadWrite.All",
   "id": "656f6061-f9fe-4807-9708-6a2e0934df76",
   "Display Name": "Read and write all risky user information",
   "Description": "Allows the app to read and update identity risky user information for your organization without a signed-in user.  Update operations include dismissing risky users."
 },
 {
   "roleName": "identityUserFlow.Read.All",
   "id": "1b0c317f-dd31-4305-9932-259a8b6e8099",
   "Display Name": "Read all identity user flows",
   "Description": "Allows the app to read your organization’s user flows, without a signed-in user."
 },
 {
   "roleName": "identityUserFlow.ReadWrite.All",
   "id": "65319a09-a2be-469d-8782-f6b07debf789",
   "Display Name": "Read and write all identity user flows",
   "Description": "Allows the app to read or write your organization’s user flows, without a signed-in user."
 },
 {
   "roleName": "InformationProtectionPolicy.Read.All",
   "id": "19da66cb-0fb0-4390-b071-ebc76a349482",
   "Display Name": "Read all published labels and label policies for an organization.",
   "Description": "Allows an app to read published sensitivity labels and label policy settings for the entire organization or a specific user, without a signed in user."
 },
 {
   "roleName": "Mail.Read",
   "id": "810c84a8-4a9e-49e6-bf7d-12d183f40d01",
   "Display Name": "Read mail in all mailboxes",
   "Description": "Allows the app to read mail in all mailboxes without a signed-in user."
 },
 {
   "roleName": "Mail.ReadBasic",
   "id": "6be147d2-ea4f-4b5a-a3fa-3eab6f3c140a",
   "Display Name": "Read basic mail in all mailboxes",
   "Description": "Allows the app to read basic mail properties in all mailboxes without a signed-in user. Includes all properties except body, previewBody, attachments and any extended properties."
 },
 {
   "roleName": "Mail.ReadBasic.All",
   "id": "693c5e45-0940-467d-9b8a-1022fb9d42ef",
   "Display Name": "Read basic mail in all mailboxes",
   "Description": "Allows the app to read basic mail properties in all mailboxes without a signed-in user. Includes all properties except body, previewBody, attachments and any extended properties."
 },
 {
   "roleName": "Mail.ReadWrite",
   "id": "e2a3a72e-5f79-4c64-b1b1-878b674786c9",
   "Display Name": "Read and write mail in all mailboxes",
   "Description": "Allows the app to create, read, update, and delete mail in all mailboxes without a signed-in user. Does not include permission to send mail."
 },
 {
   "roleName": "Mail.Send",
   "id": "b633e1c5-b582-4048-a93e-9f11b44c7e96",
   "Display Name": "Send mail as any user",
   "Description": "Allows the app to send mail as any user without a signed-in user."
 },
 {
   "roleName": "MailboxSettings.Read",
   "id": "40f97065-369a-49f4-947c-6a255697ae91",
   "Display Name": "Read all user mailbox settings",
   "Description": "Allows the app to read user’s mailbox settings without a signed-in user. Does not include permission to send mail."
 },
 {
   "roleName": "MailboxSettings.ReadWrite",
   "id": "6931bccd-447a-43d1-b442-00a195474933",
   "Display Name": "Read and write all user mailbox settings",
   "Description": "Allows the app to create, read, update, and delete user’s mailbox settings without a signed-in user. Does not include permission to send mail."
 },
 {
   "roleName": "Member.Read.Hidden",
   "id": "658aa5d8-239f-45c4-aa12-864f4fc7e490",
   "Display Name": "Read all hidden memberships",
   "Description": "Allows the app to read the memberships of hidden groups and administrative units without a signed-in user."
 },
 {
   "roleName": "Notes.Read.All",
   "id": "3aeca27b-ee3a-4c2b-8ded-80376e2134a4",
   "Display Name": "Read all OneNote notebooks",
   "Description": "Allows the app to read all the OneNote notebooks in your organization, without a signed-in user."
 },
 {
   "roleName": "Notes.ReadWrite.All",
   "id": "0c458cef-11f3-48c2-a568-c66751c238c0",
   "Display Name": "Read and write all OneNote notebooks",
   "Description": "Allows the app to read all the OneNote notebooks in your organization, without a signed-in user."
 },
 {
   "roleName": "OnPremisesPublishingProfiles.ReadWrite.All",
   "id": "0b57845e-aa49-4e6f-8109-ce654fffa618",
   "Display Name": "Manage on-premises published resources",
   "Description": "Allows the app to create, view, update and delete on-premises published resources, on-premises agents and agent groups, as part of a hybrid identity configuration, without a signed in user."
 },
 {
   "roleName": "OnlineMeetings.Read.All",
   "id": "c1684f21-1984-47fa-9d61-2dc8c296bb70",
   "Display Name": "Read online meeting details",
   "Description": "Allows the app to read online meeting details in your organization, without a signed-in user."
 },
 {
   "roleName": "OnlineMeetings.ReadWrite.All",
   "id": "b8bb2037-6e08-44ac-a4ea-4674e010e2a4",
   "Display Name": "Read and create online meetings",
   "Description": "Allows the app to read and create online meetings as an application in your organization."
 },
 {
   "roleName": "OrgContact.Read.All",
   "id": "e1a88a34-94c4-4418-be12-c87b00e26bea",
   "Display Name": "Read organizational contacts",
   "Description": "Allows the app to read all organizational contacts without a signed-in user.  These contacts are managed by the organization and are different from a user’s personal contacts."
 },
 {
   "roleName": "Organization.Read.All",
   "id": "498476ce-e0fe-48b0-b801-37ba7e2685c6",
   "Display Name": "Read organization information",
   "Description": "Allows the app to read the organization and related resources, without a signed-in user. Related resources include things like subscribed skus and tenant branding information."
 },
 {
   "roleName": "Organization.ReadWrite.All",
   "id": "292d869f-3427-49a8-9dab-8c70152b74e9",
   "Display Name": "Read and write organization information",
   "Description": "Allows the app to read and write the organization and related resources, without a signed-in user. Related resources include things like subscribed skus and tenant branding information."
 },
 {
   "roleName": "People.Read.All",
   "id": "b528084d-ad10-4598-8b93-929746b4d7d6",
   "Display Name": "Read all users’ relevant people lists",
   "Description": "Allows the app to read any user’s scored list of relevant people, without a signed-in user. The list can include local contacts, contacts from social networking, your organization’s directory, and people from recent communications (such as email and Skype)."
 },
 {
   "roleName": "Place.Read.All",
   "id": "913b9306-0ce1-42b8-9137-6a7df690a760",
   "Display Name": "Read all company places",
   "Description": "Allows the app to read company places (conference rooms and room lists) for calendar events and other applications, without a signed-in user."
 },
 {
   "roleName": "Policy.Read.All",
   "id": "246dd0d5-5bd0-4def-940b-0421030a5b68",
   "Display Name": "Read your organization’s policies",
   "Description": "Allows the app to read all your organization’s policies without a signed in user."
 },
 {
   "roleName": "Policy.Read.ConditionalAccess",
   "id": "37730810-e9ba-4e46-b07e-8ca78d182097",
   "Display Name": "Read your organization’s conditional access policies",
   "Description": "Allows the app to read your organization’s conditional access policies, without a signed-in user."
 },
 {
   "roleName": "Policy.Read.PermissionGrant",
   "id": "9e640839-a198-48fb-8b9a-013fd6f6cbcd",
   "Display Name": "Read consent and permission grant policies",
   "Description": "Allows the app to read policies related to consent and permission grants for applications, without a signed-in user."
 },
 {
   "roleName": "Policy.ReadWrite.ApplicationConfiguration",
   "id": "be74164b-cff1-491c-8741-e671cb536e13",
   "Display Name": "Read and write your organization’s application configuration policies",
   "Description": "Allows the app to read and write your organization’s application configuration policies, without a signed-in user.  This includes policies such as activityBasedTimeoutPolicy, claimsMappingPolicy, homeRealmDiscoveryPolicy, tokenIssuancePolicy  and tokenLifetimePolicy."
 },
 {
   "roleName": "Policy.ReadWrite.AuthenticationFlows",
   "id": "25f85f3c-f66c-4205-8cd5-de92dd7f0cec",
   "Display Name": "Read and write authentication flow policies",
   "Description": "Allows the app to read and write all authentication flow policies for the tenant, without a signed-in user."
 },
 {
   "roleName": "Policy.ReadWrite.AuthenticationMethod",
   "id": "29c18626-4985-4dcd-85c0-193eef327366",
   "Display Name": "Read and write all authentication method policies",
   "Description": "Allows the app to read and write all authentication method policies for the tenant, without a signed-in user."
 },
 {
   "roleName": "Policy.ReadWrite.Authorization",
   "id": "fb221be6-99f2-473f-bd32-01c6a0e9ca3b",
   "Display Name": "Read and write your organization’s authorization policy",
   "Description": "Allows the app to read and write your organization’s authorization policy without a signed in user. For example, authorization policies can control some of the permissions that the out-of-the-box user role has by default."
 },
 {
   "roleName": "Policy.ReadWrite.ConditionalAccess",
   "id": "01c0a623-fc9b-48e9-b794-0756f8e8f067",
   "Display Name": "Read and write your organization’s conditional access policies",
   "Description": "Allows the app to read and write your organization’s conditional access policies, without a signed-in user."
 },
 {
   "roleName": "Policy.ReadWrite.ConsentRequest",
   "id": "999f8c63-0a38-4f1b-91fd-ed1947bdd1a9",
   "Display Name": "Read and write your organization’s consent request policy",
   "Description": "Allows the app to read and write your organization’s consent requests policy without a signed-in user."
 },
 {
   "roleName": "Policy.ReadWrite.FeatureRollout",
   "id": "2044e4f1-e56c-435b-925c-44cd8f6ba89a",
   "Display Name": "Read and write feature rollout policies",
   "Description": "Allows the app to read and write feature rollout policies without a signed-in user. Includes abilities to assign and remove users and groups to rollout of a specific feature."
 },
 {
   "roleName": "Policy.ReadWrite.PermissionGrant",
   "id": "a402ca1c-2696-4531-972d-6e5ee4aa11ea",
   "Display Name": "Manage consent and permission grant policies",
   "Description": "Allows the app to manage policies related to consent and permission grants for applications, without a signed-in user."
 },
 {
   "roleName": "Policy.ReadWrite.TrustFramework",
   "id": "79a677f7-b79d-40d0-a36a-3e6f8688dd7a",
   "Display Name": "Read and write your organization’s trust framework policies",
   "Description": "Allows the app to read and write your organization’s trust framework policies without a signed in user."
 },
 {
   "roleName": "Presence.ReadWrite.All",
   "id": "83cded22-8297-4ff6-a7fa-e97e9545a259",
   "Display Name": "Read and write presence information for all users",
   "Description": "Allows the app to read all presence information and write activity and availability of all users in the directory without a signed-in user. Presence information includes activity, availability, status note, calendar out-of-office message, time zone and location."
 },
 {
   "roleName": "PrintJob.Manage.All",
   "id": "58a52f47-9e36-4b17-9ebe-ce4ef7f3e6c8",
   "Display Name": "Perform advanced operations on print jobs",
   "Description": "Allows the application to perform advanced operations like redirecting a print job to another printer without a signed-in user. Also allows the application to read and update the metadata of print jobs."
 },
 {
   "roleName": "PrintJob.Read.All",
   "id": "ac6f956c-edea-44e4-bd06-64b1b4b9aec9",
   "Display Name": "Read print jobs",
   "Description": "Allows the application to read the metadata and document content of print jobs without a signed-in user."
 },
 {
   "roleName": "PrintJob.ReadBasic.All",
   "id": "fbf67eee-e074-4ef7-b965-ab5ce1c1f689",
   "Display Name": "Read basic information for print jobs",
   "Description": "Allows the application to read the metadata of print jobs without a signed-in user. Does not allow access to print job document content."
 },
 {
   "roleName": "PrintJob.ReadWrite.All",
   "id": "5114b07b-2898-4de7-a541-53b0004e2e13",
   "Display Name": "Read and write print jobs",
   "Description": "Allows the application to read and update the metadata and document content of print jobs without a signed-in user."
 },
 {
   "roleName": "PrintJob.ReadWriteBasic.All",
   "id": "57878358-37f4-4d3a-8c20-4816e0d457b1",
   "Display Name": "Read and write basic information for print jobs",
   "Description": "Allows the application to read and update the metadata of print jobs without a signed-in user. Does not allow access to print job document content."
 },
 {
   "roleName": "PrintSettings.Read.All",
   "id": "b5991872-94cf-4652-9765-29535087c6d8",
   "Display Name": "Read tenant-wide print settings",
   "Description": "Allows the application to read tenant-wide print settings without a signed-in user."
 },
 {
   "roleName": "PrintTaskDefinition.ReadWrite.All",
   "id": "456b71a7-0ee0-4588-9842-c123fcc8f664",
   "Display Name": "Read, write and update print task definitions",
   "Description": "Allows the application to read and update print task definitions without a signed-in user."
 },
 {
   "roleName": "Printer.Read.All",
   "id": "9709bb33-4549-49d4-8ed9-a8f65e45bb0f",
   "Display Name": "Read printers",
   "Description": "Allows the application to read printers without a signed-in user."
 },
 {
   "roleName": "Printer.ReadWrite.All",
   "id": "f5b3f73d-6247-44df-a74c-866173fddab0",
   "Display Name": "Read and update printers",
   "Description": "Allows the application to read and update printers without a signed-in user. Does not allow creating (registering) or deleting (unregistering) printers."
 },
 {
   "roleName": "PrivilegedAccess.Read.AzureAD",
   "id": "4cdc2547-9148-4295-8d11-be0db1391d6b",
   "Display Name": "Read privileged access to Azure AD roles",
   "Description": "Allows the app to read time-based assignment and just-in-time elevation (including scheduled elevation) of Azure AD built-in and custom administrative roles in your organization, without a signed-in user."
 },
 {
   "roleName": "PrivilegedAccess.Read.AzureADGroup",
   "id": "01e37dc9-c035-40bd-b438-b2879c4870a6",
   "Display Name": "Read privileged access to Azure AD groups",
   "Description": "Allows the app to read time-based assignment and just-in-time elevation (including scheduled elevation) of Azure AD groups in your organization, without a signed-in user."
 },
 {
   "roleName": "PrivilegedAccess.Read.AzureResources",
   "id": "5df6fe86-1be0-44eb-b916-7bd443a71236",
   "Display Name": "Read privileged access to Azure resources",
   "Description": "Allows the app to read time-based assignment and just-in-time elevation of user privileges to audit Azure resources in your organization, without a signed-in user."
 },
 {
   "roleName": "PrivilegedAccess.ReadWrite.AzureAD",
   "id": "854d9ab1-6657-4ec8-be45-823027bcd009",
   "Display Name": "Read and write privileged access to Azure AD roles",
   "Description": "Allows the app to request and manage time-based assignment and just-in-time elevation (including scheduled elevation) of Azure AD built-in and custom administrative roles in your organization, without a signed-in user."
 },
 {
   "roleName": "PrivilegedAccess.ReadWrite.AzureADGroup",
   "id": "2f6817f8-7b12-4f0f-bc18-eeaf60705a9e",
   "Display Name": "Read and write privileged access to Azure AD groups",
   "Description": "Allows the app to request and manage time-based assignment and just-in-time elevation (including scheduled elevation) of Azure AD groups in your organization, without a signed-in user."
 },
 {
   "roleName": "PrivilegedAccess.ReadWrite.AzureResources",
   "id": "6f9d5abc-2db6-400b-a267-7de22a40fb87",
   "Display Name": "Read and write privileged access to Azure resources",
   "Description": "Allows the app to request and manage time-based assignment and just-in-time elevation of Azure resources (like your subscriptions, resource groups, storage, compute) in your organization, without a signed-in user."
 },
 {
   "roleName": "ProgramControl.Read.All",
   "id": "eedb7fdd-7539-4345-a38b-4839e4a84cbd",
   "Display Name": "Read all programs",
   "Description": "Allows the app to read programs and program controls in the organization, without a signed-in user."
 },
 {
   "roleName": "ProgramControl.ReadWrite.All",
   "id": "60a901ed-09f7-4aa5-a16e-7dd3d6f9de36",
   "Display Name": "Manage all programs",
   "Description": "Allows the app to read, update, delete and perform actions on programs and program controls in the organization, without a signed-in user."
 },
 {
   "roleName": "Reports.Read.All",
   "id": "230c1aed-a721-4c5d-9cb4-a90514e508ef",
   "Display Name": "Read all usage reports",
   "Description": "Allows an app to read all service usage reports without a signed-in user.  Services that provide usage reports include Office 365 and Azure Active Directory."
 },
 {
   "roleName": "RoleManagement.Read.All",
   "id": "c7fbd983-d9aa-4fa7-84b8-17382c103bc4",
   "Display Name": "Read role management data for all RBAC providers",
   "Description": "Allows the app to read role-based access control (RBAC) settings for all RBAC providers without a signed-in user. This includes reading role definitions and role assignments."
 },
 {
   "roleName": "RoleManagement.Read.Directory",
   "id": "483bed4a-2ad3-4361-a73b-c83ccdbdc53c",
   "Display Name": "Read all directory RBAC settings",
   "Description": "Allows the app to read the role-based access control (RBAC) settings for your company’s directory, without a signed-in user.  This includes reading directory role templates, directory roles and memberships."
 },
 {
   "roleName": "RoleManagement.ReadWrite.Directory",
   "id": "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8",
   "Display Name": "Read and write all directory RBAC settings",
   "Description": "Allows the app to read and manage the role-based access control (RBAC) settings for your company’s directory, without a signed-in user. This includes instantiating directory roles and managing directory role membership, and reading directory role templates, directory roles and memberships."
 },
 {
   "roleName": "Schedule.Read.All",
   "id": "7b2ebf90-d836-437f-b90d-7b62722c4456",
   "Display Name": "Read all schedule items",
   "Description": "Allows the app to read all schedules, schedule groups, shifts and associated entities in the Teams or Shifts application without a signed-in user."
 },
 {
   "roleName": "Schedule.ReadWrite.All",
   "id": "b7760610-0545-4e8a-9ec3-cce9e63db01c",
   "Display Name": "Read and write all schedule items",
   "Description": "Allows the app to manage all schedules, schedule groups, shifts and associated entities in the Teams or Shifts application without a signed-in user."
 },
 {
   "roleName": "SecurityActions.Read.All",
   "id": "5e0edab9-c148-49d0-b423-ac253e121825",
   "Display Name": "Read your organization’s security actions",
   "Description": "Allows the app to read security actions, without a signed-in user."
 },
 {
   "roleName": "SecurityActions.ReadWrite.All",
   "id": "f2bf083f-0179-402a-bedb-b2784de8a49b",
   "Display Name": "Read and update your organization’s security actions",
   "Description": "Allows the app to read or update security actions, without a signed-in user."
 },
 {
   "roleName": "SecurityEvents.Read.All",
   "id": "bf394140-e372-4bf9-a898-299cfc7564e5",
   "Display Name": "Read your organization’s security events",
   "Description": "Allows the app to read your organization’s security events without a signed-in user."
 },
 {
   "roleName": "SecurityEvents.ReadWrite.All",
   "id": "d903a879-88e0-4c09-b0c9-82f6a1333f84",
   "Display Name": "Read and update your organization’s security events",
   "Description": "Allows the app to read your organization’s security events without a signed-in user. Also allows the app to update editable properties in security events."
 },
 {
   "roleName": "ServiceHealth.Read.All",
   "id": "79c261e0-fe76-4144-aad5-bdc68fbe4037",
   "Display Name": "Read service health",
   "Description": "Allows the app to read your tenant’s service health information, without a signed-in user. Health information may include service issues or service health overviews."
 },
 {
   "roleName": "ServiceMessage.Read.All",
   "id": "1b620472-6534-4fe6-9df2-4680e8aa28ec",
   "Display Name": "Read service messages",
   "Description": "Allows the app to read your tenant’s service announcement messages, without a signed-in user. Messages may include information about new or changed features."
 },
 {
   "roleName": "ServicePrincipalEndpoint.Read.All",
   "id": "5256681e-b7f6-40c0-8447-2d9db68797a0",
   "Display Name": "Read service principal endpoints",
   "Description": "Allows the app to read service principal endpoints"
 },
 {
   "roleName": "ServicePrincipalEndpoint.ReadWrite.All",
   "id": "89c8469c-83ad-45f7-8ff2-6e3d4285709e",
   "Display Name": "Read and update service principal endpoints",
   "Description": "Allows the app to update service principal endpoints"
 },
 {
   "roleName": "ShortNotes.Read.All",
   "id": "0c7d31ec-31ca-4f58-b6ec-9950b6b0de69",
   "Display Name": "Read all users’ short notes",
   "Description": "Allows the app to read all the short notes without a signed-in user."
 },
 {
   "roleName": "ShortNotes.ReadWrite.All",
   "id": "842c284c-763d-4a97-838d-79787d129bab",
   "Display Name": "Read, create, edit, and delete all users’ short notes",
   "Description": "Allows the app to read, create, edit, and delete all the short notes without a signed-in user."
 },
 {
   "roleName": "Sites.FullControl.All",
   "id": "a82116e5-55eb-4c41-a434-62fe8a61c773",
   "Display Name": "Have full control of all site collections",
   "Description": "Allows the app to have full control of all site collections without a signed in user."
 },
 {
   "roleName": "Sites.Manage.All",
   "id": "0c0bf378-bf22-4481-8f81-9e89a9b4960a",
   "Display Name": "Create, edit, and delete items and lists in all site collections",
   "Description": "Allows the app to create or delete document libraries and lists in all site collections without a signed in user."
 },
 {
   "roleName": "Sites.Read.All",
   "id": "332a536c-c7ef-4017-ab91-336970924f0d",
   "Display Name": "Read items in all site collections",
   "Description": "Allows the app to read documents and list items in all site collections without a signed in user."
 },
 {
   "roleName": "Sites.ReadWrite.All",
   "id": "9492366f-7969-46a4-8d15-ed1a20078fff",
   "Display Name": "Read and write items in all site collections",
   "Description": "Allows the app to create, read, update, and delete documents and list items in all site collections without a signed in user."
 },
 {
   "roleName": "Sites.Selected",
   "id": "883ea226-0bf2-4a8f-9f9d-92c9162a727d",
   "Display Name": "Access selected site collections",
   "Description": "Allow the application to access a subset of site collections without a signed in user.  The specific site collections and the permissions granted will be configured in SharePoint Online."
 },
 {
   "roleName": "Team.Create",
   "id": "23fc2474-f741-46ce-8465-674744c5c361",
   "Display Name": "Create teams",
   "Description": "Allows the app to create teams without a signed-in user."
 },
 {
   "roleName": "Team.ReadBasic.All",
   "id": "2280dda6-0bfd-44ee-a2f4-cb867cfc4c1e",
   "Display Name": "Get a list of all teams",
   "Description": "Get a list of all teams, without a signed-in user."
 },
 {
   "roleName": "TeamMember.Read.All",
   "id": "660b7406-55f1-41ca-a0ed-0b035e182f3e",
   "Display Name": "Read the members of all teams",
   "Description": "Read the members of all teams, without a signed-in user."
 },
 {
   "roleName": "TeamMember.ReadWrite.All",
   "id": "0121dc95-1b9f-4aed-8bac-58c5ac466691",
   "Display Name": "Add and remove members from all teams",
   "Description": "Add and remove members from all teams, without a signed-in user. Also allows changing a team member’s role, for example from owner to non-owner."
 },
 {
   "roleName": "TeamMember.ReadWriteNonOwnerRole.All",
   "id": "4437522e-9a86-4a41-a7da-e380edd4a97d",
   "Display Name": "Add and remove members with non-owner role for all teams",
   "Description": "Add and remove members from all teams, without a signed-in user. Does not allow adding or removing a member with the owner role. Additionally, does not allow the app to elevate an existing member to the owner role."
 },
 {
   "roleName": "TeamSettings.Read.All",
   "id": "242607bd-1d2c-432c-82eb-bdb27baa23ab",
   "Display Name": "Read all teams’ settings",
   "Description": "Read all team’s settings, without a signed-in user."
 },
 {
   "roleName": "TeamSettings.ReadWrite.All",
   "id": "bdd80a03-d9bc-451d-b7c4-ce7c63fe3c8f",
   "Display Name": "Read and change all teams’ settings",
   "Description": "Read and change all teams’ settings, without a signed-in user."
 },
 {
   "roleName": "TeamsActivity.Read.All",
   "id": "70dec828-f620-4914-aa83-a29117306807",
   "Display Name": "Read all users’ teamwork activity feed",
   "Description": "Allows the app to read all users’ teamwork activity feed, without a signed-in user."
 },
 {
   "roleName": "TeamsActivity.Send",
   "id": "a267235f-af13-44dc-8385-c1dc93023186",
   "Display Name": "Send a teamwork activity to any user",
   "Description": "Allows the app to create new notifications in users’ teamwork activity feeds without a signed in user. These notifications may not be discoverable or be held or governed by compliance policies."
 },
 {
   "roleName": "TeamsApp.Read.All",
   "id": "afdb422a-4b2a-4e07-a708-8ceed48196bf",
   "Display Name": "Read all users’ installed Teams apps",
   "Description": "Allows the app to read the Teams apps that are installed for any user, without a signed-in user. Does not give the ability to read application-specific settings."
 },
 {
   "roleName": "TeamsApp.ReadWrite.All",
   "id": "eb6b3d76-ed75-4be6-ac36-158d04c0a555",
   "Display Name": "Manage all users’ Teams apps",
   "Description": "Allows the app to read, install, upgrade, and uninstall Teams apps for any user, without a signed-in user. Does not give the ability to read or write application-specific settings."
 },
 {
   "roleName": "TeamsAppInstallation.ReadForChat.All",
   "id": "cc7e7635-2586-41d6-adaa-a8d3bcad5ee5",
   "Display Name": "Read installed Teams apps for all chats",
   "Description": "Allows the app to read the Teams apps that are installed in any chat, without a signed-in user. Does not give the ability to read application-specific settings."
 },
 {
   "roleName": "TeamsAppInstallation.ReadForTeam.All",
   "id": "1f615aea-6bf9-4b05-84bd-46388e138537",
   "Display Name": "Read installed Teams apps for all teams",
   "Description": "Allows the app to read the Teams apps that are installed in any team, without a signed-in user. Does not give the ability to read application-specific settings."
 },
 {
   "roleName": "TeamsAppInstallation.ReadForUser.All",
   "id": "9ce09611-f4f7-4abd-a629-a05450422a97",
   "Display Name": "Read installed Teams apps for all users",
   "Description": "Allows the app to read the Teams apps that are installed for any user, without a signed-in user. Does not give the ability to read application-specific settings."
 },
 {
   "roleName": "TeamsAppInstallation.ReadWriteForChat.All",
   "id": "9e19bae1-2623-4c4f-ab6e-2664615ff9a0",
   "Display Name": "Manage Teams apps for all chats",
   "Description": "Allows the app to read, install, upgrade, and uninstall Teams apps in any chat, without a signed-in user. Does not give the ability to read application-specific settings."
 },
 {
   "roleName": "TeamsAppInstallation.ReadWriteForTeam.All",
   "id": "5dad17ba-f6cc-4954-a5a2-a0dcc95154f0",
   "Display Name": "Manage Teams apps for all teams",
   "Description": "Allows the app to read, install, upgrade, and uninstall Teams apps in any team, without a signed-in user. Does not give the ability to read application-specific settings."
 },
 {
   "roleName": "TeamsAppInstallation.ReadWriteForUser.All",
   "id": "74ef0291-ca83-4d02-8c7e-d2391e6a444f",
   "Display Name": "Manage Teams apps for all users",
   "Description": "Allows the app to read, install, upgrade, and uninstall Teams apps for any user, without a signed-in user. Does not give the ability to read application-specific settings."
 },
 {
   "roleName": "TeamsAppInstallation.ReadWriteSelfForChat.All",
   "id": "73a45059-f39c-4baf-9182-4954ac0e55cf",
   "Display Name": "Allow the Teams app to manage itself for all chats",
   "Description": "Allows a Teams app to read, install, upgrade, and uninstall itself for any chat, without a signed-in user."
 },
 {
   "roleName": "TeamsAppInstallation.ReadWriteSelfForTeam.All",
   "id": "9f67436c-5415-4e7f-8ac1-3014a7132630",
   "Display Name": "Allow the Teams app to manage itself for all teams",
   "Description": "Allows a Teams app to read, install, upgrade, and uninstall itself in any team, without a signed-in user."
 },
 {
   "roleName": "TeamsAppInstallation.ReadWriteSelfForUser.All",
   "id": "908de74d-f8b2-4d6b-a9ed-2a17b3b78179",
   "Display Name": "Allow the app to manage itself for all users",
   "Description": "Allows a Teams app to read, install, upgrade, and uninstall itself to any user, without a signed-in user."
 },
 {
   "roleName": "TeamsTab.Create",
   "id": "49981c42-fd7b-4530-be03-e77b21aed25e",
   "Display Name": "Create tabs in Microsoft Teams.",
   "Description": "Allows the app to create tabs in any team in Microsoft Teams, without a signed-in user. This does not grant the ability to read, modify or delete tabs after they are created, or give access to the content inside the tabs."
 },
 {
   "roleName": "TeamsTab.Read.All",
   "id": "46890524-499a-4bb2-ad64-1476b4f3e1cf",
   "Display Name": "Read tabs in Microsoft Teams.",
   "Description": "Read the names and settings of tabs inside any team in Microsoft Teams, without a signed-in user. This does not give access to the content inside the tabs."
 },
 {
   "roleName": "TeamsTab.ReadWrite.All",
   "id": "a96d855f-016b-47d7-b51c-1218a98d791c",
   "Display Name": "Read and write tabs in Microsoft Teams.",
   "Description": "Read and write tabs in any team in Microsoft Teams, without a signed-in user. This does not give access to the content inside the tabs."
 },
 {
   "roleName": "TeamsTab.ReadWriteForChat.All",
   "id": "fd9ce730-a250-40dc-bd44-8dc8d20f39ea",
   "Display Name": "Allow the Teams app to manage all tabs for all chats",
   "Description": "Allows a Teams app to read, install, upgrade, and uninstall all tabs for any chat, without a signed-in user."
 },
 {
   "roleName": "TeamsTab.ReadWriteForTeam.All",
   "id": "6163d4f4-fbf8-43da-a7b4-060fe85ed148",
   "Display Name": "Allow the Teams app to manage all tabs for all teams",
   "Description": "Allows a Teams app to read, install, upgrade, and uninstall all tabs in any team, without a signed-in user."
 },
 {
   "roleName": "TeamsTab.ReadWriteForUser.All",
   "id": "425b4b59-d5af-45c8-832f-bb0b7402348a",
   "Display Name": "Allow the app to manage all tabs for all users",
   "Description": "Allows a Teams app to read, install, upgrade, and uninstall all tabs for any user, without a signed-in user."
 },
 {
   "roleName": "Teamwork.Migrate.All",
   "id": "dfb0dd15-61de-45b2-be36-d6a69fba3c79",
   "Display Name": "Create chat and channel messages with anyone’s identity and with any timestamp",
   "Description": "Allows the app to create chat and channel messages, without a signed in user. The app specifies which user appears as the sender, and can backdate the message to appear as if it was sent long ago. The messages can be sent to any chat or channel in the organization."
 },
 {
   "roleName": "TeamworkTag.Read.All",
   "id": "b74fd6c4-4bde-488e-9695-eeb100e4907f",
   "Display Name": "Read tags in Teams",
   "Description": "Allows the app to read tags in Teams without a signed-in user."
 },
 {
   "roleName": "TeamworkTag.ReadWrite.All",
   "id": "a3371ca5-911d-46d6-901c-42c8c7a937d8",
   "Display Name": "Read and write tags in Teams",
   "Description": "Allows the app to read and write tags in Teams without a signed-in user."
 },
 {
   "roleName": "TermStore.Read.All",
   "id": "ea047cc2-df29-4f3e-83a3-205de61501ca",
   "Display Name": "Read all term store data",
   "Description": "Allows the app to read all term store data, without a signed-in user. This includes all sets, groups and terms in the term store."
 },
 {
   "roleName": "TermStore.ReadWrite.All",
   "id": "f12eb8d6-28e3-46e6-b2c0-b7e4dc69fc95",
   "Display Name": "Read and write all term store data",
   "Description": "Allows the app to read, edit or write all term store data, without a signed-in user. This includes all sets, groups and terms in the term store."
 },
 {
   "roleName": "ThreatAssessment.Read.All",
   "id": "f8f035bb-2cce-47fb-8bf5-7baf3ecbee48",
   "Display Name": "Read threat assessment requests",
   "Description": "Allows an app to read your organization’s threat assessment requests, without a signed-in user."
 },
 {
   "roleName": "ThreatIndicators.Read.All",
   "id": "197ee4e9-b993-4066-898f-d6aecc55125b",
   "Display Name": "Read all threat indicators",
   "Description": "Allows the app to read all the indicators for your organization, without a signed-in user."
 },
 {
   "roleName": "ThreatIndicators.ReadWrite.OwnedBy",
   "id": "21792b6c-c986-4ffc-85de-df9da54b52fa",
   "Display Name": "Manage threat indicators this app creates or owns",
   "Description": "Allows the app to create threat indicators, and fully manage those threat indicators (read, update and delete), without a signed-in user.  It cannot update any threat indicators it does not own."
 },
 {
   "roleName": "TrustFrameworkKeySet.Read.All",
   "id": "fff194f1-7dce-4428-8301-1badb5518201",
   "Display Name": "Read trust framework key sets",
   "Description": "Allows the app to read trust framework key set properties without a signed-in user."
 },
 {
   "roleName": "TrustFrameworkKeySet.ReadWrite.All",
   "id": "4a771c9a-1cf2-4609-b88e-3d3e02d539cd",
   "Display Name": "Read and write trust framework key sets",
   "Description": "Allows the app to read and write trust framework key set properties without a signed-in user."
 },
 {
   "roleName": "User.Export.All",
   "id": "405a51b5-8d8d-430b-9842-8be4b0e9f324",
   "Display Name": "Export user’s data",
   "Description": "Allows the app to export data (e.g. customer content or system-generated logs), associated with any user in your company, when the app is used by a privileged user (e.g. a Company Administrator)."
 },
 {
   "roleName": "User.Invite.All",
   "id": "09850681-111b-4a89-9bed-3f2cae46d706",
   "Display Name": "Invite guest users to the organization",
   "Description": "Allows the app to invite guest users to the organization, without a signed-in user."
 },
 {
   "roleName": "User.Manageidentities.All",
   "id": "c529cfca-c91b-489c-af2b-d92990b66ce6",
   "Display Name": "Manage all users’ identities",
   "Description": "Allows the app to read, update and delete identities that are associated with a user’s account, without a signed in user. This controls the identities users can sign-in with."
 },
 {
   "roleName": "User.Read.All",
   "id": "df021288-bdef-4463-88db-98f22de89214",
   "Display Name": "Read all users’ full profiles",
   "Description": "Allows the app to read user profiles without a signed in user."
 },
 {
   "roleName": "User.ReadWrite.All",
   "id": "741f803b-c850-494e-b5df-cde7c675a1ca",
   "Display Name": "Read and write all users’ full profiles",
   "Description": "Allows the app to read and update user profiles without a signed in user."
 },
 {
   "roleName": "UserAuthenticationMethod.Read.All",
   "id": "38d9df27-64da-44fd-b7c5-a6fbac20248f",
   "Display Name": "Read all users’ authentication methods",
   "Description": "Allows the app to read authentication methods of all users in your organization, without a signed-in user.                       Authentication methods include things like a user’s phone numbers and Authenticator app settings. This does not allow the                      app to see secret information like passwords, or to sign-in or otherwise use the authentication methods."
 },
 {
   "roleName": "UserAuthenticationMethod.ReadWrite.All",
   "id": "50483e42-d915-4231-9639-7fdb7fd190e5",
   "Display Name": "Read and write all users’ authentication methods",
   "Description": "Allows the application to read and write authentication methods of all users in your organization, without a signed-in user.                       Authentication methods include things like a user’s phone numbers and Authenticator app settings. This                      does not allow the app to see secret information like passwords, or to sign-in or otherwise use the authentication methods"
 },
 {
   "roleName": "UserNotification.ReadWrite.CreatedByApp",
   "id": "4e774092-a092-48d1-90bd-baad67c7eb47",
   "Display Name": "Deliver and manage all user’s notifications",
   "Description": "Allows the app to send, read, update and delete user’s notifications, without a signed-in user."
 },
 {
   "roleName": "UserShiftPreferences.Read.All",
   "id": "de023814-96df-4f53-9376-1e2891ef5a18",
   "Display Name": "Read all user shift preferences",
   "Description": "Allows the app to read all users’ shift schedule preferences without a signed-in user."
 },
 {
   "roleName": "UserShiftPreferences.ReadWrite.All",
   "id": "d1eec298-80f3-49b0-9efb-d90e224798ac",
   "Display Name": "Read and write all user shift preferences",
   "Description": "Allows the app to manage all users’ shift schedule preferences without a signed-in user."
 },
 {
   "roleName": "WindowsUpdates.ReadWrite.All",
   "id": "7dd1be58-6e76-4401-bf8d-31d1e8180d5b",
   "Display Name": "Read and write all Windows update deployment settings",
   "Description": "Allows the app to read and write all Windows update deployment settings for the organization without a signed-in user."
 },
 {
   "roleName": "WorkforceIntegration.ReadWrite.All",
   "id": "202bf709-e8e6-478e-bcfd-5d63c50b68e3",
   "Display Name": "Read and write workforce integrations",
   "Description": "Allows the app to manage workforce integrations to synchronize data from Microsoft Teams Shifts, without a signed-in user."
 }
]