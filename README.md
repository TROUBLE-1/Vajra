<h1 align="center">
<b>Vajra - Your Weapon To Cloud</b><br>
  <br>
  <a href="https://github.com/TROUBLE-1/Vajra/"><img src="https://github.com/TROUBLE-1/Vajra/raw/main/images/demon.png"></a>
</h1>

## About Vajra

Vajra is a UI based tool with multiple techniques for attacking and enumerating in target's Azure environment. 

The term Vajra refers to the Weapon of God Indra in Indian mythology (God of Thunder &amp; Storms). Its connection to the cloud makes it a perfect name for the tool.

Vajra currently supports Azure Cloud environments and plans to support AWS cloud environments and some OSINT in the future.

**Following features are available at the moment:**

- Azure
  - Attacking
      1. OAuth Based Phishing (Illicit Consent Grant Attack)
          - Exfiltrate Data
          - Enumerate Environment
          - Deploy Backdoors
          - Send mails/Create Rules
      2. Password Spray
      3. Password Brute Force
  - Enumeration
      1. Users 
      2. Subdomain 
      3. Azure Ad
      4. Azure Services
  - Specific Service
      1. Storage Accounts
- AWS
  - Attacking(In progress)
      1. Under Development
  - Enumeration
      1. IAM Enumeration
      2. S3 Scanner
      3. Under Development
  - Misconfiguration

_**Note:** This tool have been tested in a environment which had around 3 Lakh principals like users, groups, enterprise application, etc._

<span align="center">
  <br>
  <img src="https://github.com/TROUBLE-1/Vajra/raw/main/images/dashboard.png">
</span>

<span align="center">
  <br>
  <img src="https://github.com/TROUBLE-1/Vajra/raw/main/images/aws-dashboard.png">
</span>

It features an intuitive web-based user interface built with the Python Flask module for a better user experience.

# **About Author**

Raunak Parmar works as a senior security engineer. Web/Cloud security, source code review, scripting, and development are some of his interests. Also, familiar with PHP, NodeJs, Python, Ruby, and Java. He is OSWE certified and the author of Vajra and 365-Stealer.

### **Social Media Links**

- Twitter: [https://twitter.com/trouble1\_raunak](https://twitter.com/trouble1_raunak)
- YouTube: [https://www.youtube.com/channel/UCkJ\_sEF8iUDXPCI3UL0DAcg](https://www.youtube.com/channel/UCkJ_sEF8iUDXPCI3UL0DAcg)
- Linkedin: [https://www.linkedin.com/in/trouble1raunak/](https://www.linkedin.com/in/trouble1raunak/)
- GitHub: [https://github.com/TROUBLE-1/](https://github.com/TROUBLE-1/)

# Installation

Install postgres database with credential postgres/postgres and create a database name vajra. If postgres is not installed then by default sqlite will be used.

Run the following command to install all the modules.

```
pip install -r requirements.txt
```
Once installed run the following to start the application.

```
python app.py
```

# **Why use Vajra**

Whenever I come across during [Cloud Security assessment](https://www.crowdstrike.com/cybersecurity-101/cloud-security/cloud-security-assessment/#:~:text=A%20cloud%20security%20assessment%20is,of%20security%20risks%20and%20threats.&amp;text=Identify%20weaknesses%20and%20potential%20points%20of%20entry%20within%20the%20organization's%20cloud%20infrastructure) or some Cloud [Red Team](https://whatis.techtarget.com/definition/red-teaming) projects, there is a need to run a lot of tools to enumerate stuff from nothing to something. Where some requires lots of automation like brute-forcing or finding a particular privileged service or policies from thousands of resources.

Initially, I wrote a tool [365-Stealer](https://github.com/AlteredSecurity/365-Stealer) which had capabilities to perform Illicit Consent Grant Attack but I was not satisfied with the code structure and its web interface which made me rewrite the whole tool again and add it as a module in Vajra. The most interesting part of this module is it uses refresh tokens stolen from the victims which can be used for a minimum of 3 months and a max 1 year or no limit. Will explain how to use this module and in what circumstances it should be used.

_**Note:** No future release or update will be done in [365-Stealer](https://github.com/AlteredSecurity/365-Stealer) as I have abandoned this tool._

Vajra will have more modules in future which will help in simulate tha attacks while performing Cloud security assessment.

# **Modules**

Let me take you through all the modules that the current tool has and will guide you on how we can setup up and also when to use what.

<span align="center">
  <br>
  <img src="https://github.com/TROUBLE-1/Vajra/raw/main/images/attacks-lists.png">
</span>

## **Userenum**

The First tool that anyone would like to perform is for user enumeration. During a black box, you might perform some OSINT techniques to gather email id's for the targeted company let's say company XYZ Ltd. You could try to enumerate all over google with matching regex.

`^[\w.+\-]+@XYZ\.com$`


Or maybe using some secret technique you got dozens of email id's. Now it is important to validate those id's before our further attacks.

Once you are ready with your list you just need to paste it in the text field or upload a file then click save and click attack as shown below.

<span align="center">
  <br>
  <img src="https://github.com/TROUBLE-1/Vajra/raw/main/images/userenum-in-action.png">
</span>

Results are saved on the same page which can even be download.

<span align="center">
  <br>
  <img src="https://github.com/TROUBLE-1/Vajra/raw/main/images/userenum-results.png">
</span>

### **What's happing in the background?**

By making the POST request to "[https://login.microsoftonline.com/common/GetCredentialType](https://login.microsoftonline.com/common/GetCredentialType)" with a JSON body containing the email id its possible to analyze the valid email id. If the  "**IfExistsResult**" key value is 0 it means the user exists.

Following is the sample code for the same.

``` 
import requests
body = '{"Username":"random.name@XYZ.com"}'
response = requests.post("https://login.microsoftonline.com/common/GetCredentialType", data=body).json()
if response["IfExistsResult"] == 0:
    print("Valid User")
```

## **Phishing**

The second module will help you perform phishing attacks over the valid victims you got from the first module. The type of phishing we going to perform is called the Illicit consent Grant attack.

#### **Illicit Consent Grant Attack**

In an illicit consent grant attack, the attacker creates an Azure-registered application that requests access to data such as contact information, email, or documents. The attacker then tricks an end-user into granting consent to the application so that the attacker can gain access to the data that the target user has access to. After the application has been granted consent, it has user account-level access to the data without the need for an organizational account.

In simple words when the victim clicks on that beautiful blue button of "Accept", Azure AD sends a token to the third party site which belongs to an attacker where the attacker will use the token to perform actions on behalf of the victims like accessing all the Files, Read Mails, Send Mails, etc.

#### **Attack Flow**

<span align="center">
  <br>
  <img src="https://github.com/TROUBLE-1/Vajra/raw/main/images/illicit-consent-attack-flow.png">
</span>

To further comprehend the Illicit Consent Grant attack, consider the following scenario: two hypothetical corporations, "ECorp" and "PentestCorp". PentestCorp has won a contract from ECorp to mimic a phishing assault to gain information about the users and extract sensitive information from the users' email, OneDrive, OneNote, and other accounts.PentestCorp chose to conduct an Illicit Consent Grant attack, in which they simply lure and convince their victims to click a link that brings them to the official Microsoft third-party app consent page which allowed them to steal all the data from the victim's accounts.

PentestCorp launched this attack by registering a domain called "safedomainlogin.com" and creating a subdomain called "ecorp.safedomainlogin.com" where they hosted the application that captured the authorization code and subsequently requested the access tokens.PentestCorp then created a Multi-Tenant Application in their Azure AD Tenant and titled it "ECorp," as well as adding a Redirect URL that refers to "ecorp.safedomainlogin.com," which hosts an application to collect the authorization code.PentestCorp also included a new client secret and a few API permissions such as Mail.Read, Notes.Read.All, Files.ReadWrite.All, User.ReadBasic.All, User.Read in the application, read. As a result, after the user authorizes permission to the program, PentestCorp can harvest sensitive information on the user's behalf.

PentestCorp then generates a link with the respected client id and redirect URL of the malicious program and distributes it to the targeted users in order to get their approval.PentestCorp obtains the authorization code for the users who consented to the third-party application called ECorp. PentestCorp then utilized an authorization code to obtain an access token and refresh token, where access tokens were used to retrieve all of the information using GraphAPI.

To lessen the overhead of manually extracting data, we may utilize the Phishing module of Vajra.

Follow the procedures outlined in the section below to configure the phishing module for executing Illicit Consent Grant Attack.

#### **Register Application**

To register an application on Azure, follow the procedures outlined below.

1. Login to https://portal.azure.com
2. Navigate to Azure Active Directory
3. Click on App registrations
4. Click New registration
5. Enter the Name for our application (The same name will be displayed to the victim while granting consent)
6. Under support account types select "Accounts in any organizational directory (Any Azure AD directory - Multitenant)"
7. Enter the Redirect URL. This URL should be pointed towards our Vajra phishing application that we will host for hosting our phishing page. eg, http://localhost:8080/azure/getcode/[--UUID--]
8. Click Register

<span align="center">
  <br>
  <img src="https://github.com/TROUBLE-1/Vajra/raw/main/images/app-registration-1.png">
</span>

<span align="center">
  <br>
  <img src="https://github.com/TROUBLE-1/Vajra/raw/main/images/app-registration-2.png">
</span>

After registering the application we will be redirected to the app's overview tab. Take a note of the Application (client) ID

#### **Configure Application**

Let's start by generating a new Client Secret for our app.

1. Select "Certificates &amp; Secrets" from the drop-down menu.
2. Select New Client Secret from the drop-down menu, then add a description and click Add.
3. Store the value of the secret in a secure location.

<span align="center">
  <br>
  <img src="https://github.com/TROUBLE-1/Vajra/raw/main/images/app-registration-3.png">
</span>

Let's now provide our application permissions.

1. Select API rights from the drop-down menu.
2. Select Add a Permission from the drop-down menu.
3. Select Microsoft Graph from the drop-down menu.
4. Select Delegated Permissions from the drop-down menu.
5. Find and choose the permissions listed below, then click Add permission (This depends upon what permissions you want from the victim)

    1. Contacts.Read
    2. Mail.Read
    3. Mail.Send
    4. Notes.Read.All
    5. Mailboxsettings.ReadWrite
    6. Files.ReadWrite.All
    7. User.ReadBasic.All

<span align="center">
  <br>
  <img src="https://github.com/TROUBLE-1/Vajra/raw/main/images/app-registration-4.png">
</span>


#### **Setup Phishing Module**

Provide all the details and click save. Once done you should get your phishing URL as shown below

<span align="center">
  <br>
  <img src="https://github.com/TROUBLE-1/Vajra/raw/main/images/phishing-in-action.png">
</span>

Click on Start Phishing and click on Browse.

<span align="center">
  <br>
  <img src="https://github.com/TROUBLE-1/Vajra/raw/main/images/phishing-action-button.png">
</span>

A new tab will be open with a sample phishing Page which can be used to phish the user by making them believe it's one of the legitimate sites of Microsoft.

<span align="center">
  <br>
  <img src="https://github.com/TROUBLE-1/Vajra/raw/main/images/phishing-page-1.png">
</span>

<span align="center">
  <br>
  <img src="https://github.com/TROUBLE-1/Vajra/raw/main/images/phishing-page-2.png">
</span>

Once you click anywhere like "Read More", "Take The Exam" you will be redirected to the Microsoft official approval page shown below.

<span align="center">
  <br>
  <img src="https://github.com/TROUBLE-1/Vajra/raw/main/images/azure-consent-page-1.png">
</span>


#### **Approach**

But first, let's understand when to use this and the question is will you be able to grant all the permission from any user?

This question may have come to your mind if you have ever seen or come across as shown below.

<span align="center">
  <br>
  <img src="https://github.com/TROUBLE-1/Vajra/raw/main/images/azure-consent-page-2.png">
</span>

So the answer is no you can't get all those permission from your vuctms except some admin users, you could have gotten before 2020 but not after the Microsoft new updates. So let's understand what will be our approach for it.

_**Note:** If you have a user on the target tenant and create an app registration from it only then a normal user can provide all the permissions as the app belongs to the victim's tenant._

You can get those high privileges consent only from Admin users like Global, Application, and Cloud Administrator. But still, there are some permissions available that can be granted from a normal user as well, which are:

1. Calendars.Read
2. Tasks.Read
3. User.ReadBasic.All

From these, the best permission for us is the 3rd one `User.ReadBasic.All`. This will let us list all the names of the users available in the victim's tenant. You can find a list of all the users in Office365 section under victims tab.

<span align="center">
  <br>
  <img src="https://github.com/TROUBLE-1/Vajra/raw/main/images/victims-list.png">
</span>


Now you have more valid emails than you had previously, let's say you have around 100 users or even maybe more than that. The more the email Id's the better chance of getting a successful password spray attack. With this let's jump to the next module.

## **Spraying**

Password spraying is a sort of brute force attack where an attacker will utilize a list of users and default passwords on the application to brute force logins. To prevent account lockouts that would typically occur while brute forcing a single account with several passwords, an attacker may use one password say "Secure@123" against many other accounts on the application.

This technique is frequent when an application or administrator creates a default password for new users.

In our Spraying Module, you can upload your custom list containing emails or just provide a password click save, and start the Attack, this will perform only on the victims we got while performing phishing attacks.

<span align="center">
  <br>
  <img src="https://github.com/TROUBLE-1/Vajra/raw/main/images/spraying-in-action.png">
</span>


## **BruteForce**

This module is similar to what we do in Spraying the only difference is that instead of providing 1 password you can provide multiple passwords. By default, Microsoft allows 10 attempts so you can try up to 9 passwords. You can just provide your passwords and users list click save and start the attack.

![](https://github.com/TROUBLE-1/Vajra/raw/main/images/bruteforce-in-action.png)

# **Post Exploitation**

Once you gain access to the target's tenant you can now grant all those high privileged permissions from any user you want. So this time you can create new App registration in the victim's tenant and configure it with all permission like Files.ReadWrite.All, etc. Once Phished all the data will be displayed in the Vajra as shown below.

**OneDrive Data**![](https://github.com/TROUBLE-1/Vajra/raw/main/images/oneDrive-files-list.png)

**Outlook Mails**![](https://github.com/TROUBLE-1/Vajra/raw/main/images/outlook-dashboard.png)

**Attachment Files**![](https://github.com/TROUBLE-1/Vajra/raw/main/images/attachments-list.png)

**Onenote Files**![](https://github.com/TROUBLE-1/Vajra/raw/main/images/oneNote-list.png)

You may replace any file in OneDrive, which means you can inject macros in .docx and .xlsx files by changing the filename to .doc or .xlx, respectively.

If you desire to grant an access token to your phished victims in order to conduct your custom API request, simply click Get Token and you will receive one. And also you wished to again steal its data then simply click on Steal Again and customize your stealing, for example, to steal only mails just configure it in the phishing module.

![](https://github.com/TROUBLE-1/Vajra/raw/main/images/phished-victims.png)

## Azure Ad Enumeration

![](https://github.com/TROUBLE-1/Vajra/raw/main/images/azure-ad-enum.png)

You have 2 different ways for extracting data from Azure ad.
1. Provide credentials along with client Id
2. Provide Access Token of `https://graph.microsoft.com`

Option 2 is fairly easy just need to provide a token so will talk about the option 1. For using credentials will need to provide client Id of App Registration with the following Application permission.
1. Directory.AccessAsUser.All

![](https://github.com/TROUBLE-1/Vajra/raw/main/images/azure-enum-app.png)

Or you can just log into az cli and get a token with the below command.

```
az account get-access-token --resource=https://graph.microsoft.com
```

## Azure Resources Enumeration

![](https://github.com/TROUBLE-1/Vajra/raw/main/images/azure-services.png)

You have 2 different ways for extracting resources Azure.
1. Provide credentials along with client Id
2. Provide Access Token of `https://management.azure.com`

Option 2 is fairly easy just need to provide a token so will talk about the option 1. For using credentials will need to provide client Id of App Registration with the following Application permission.
1. user_impersonation

![](https://github.com/TROUBLE-1/Vajra/raw/main/images/azure-enum-app.png)

Or you can just log into az cli and get a token with the below command.

```
az account get-access-token --resource=https://management.azure.com
```


# **Protect your tenant**

First of all, you need to make sure that your users should not be able to provide any consent to any untrusted apps. For which navigate to Active directory -\&gt; Enterprise Application -\&gt; Consent and permissions and select "Do not allow user consent" and "Do not allow group owner consent".

This will disallow any user to provide consent to any apps. Or you can even let users provide consent to only the verified Apps as well.

<span align="center">
  <br>
  <img src="https://github.com/TROUBLE-1/Vajra/raw/main/images/protect-your-tenant.png">
</span>

# AWS

# IAM Enumeration
<span align="center">
  <br>
  <img src="https://github.com/TROUBLE-1/Vajra/raw/main/images/aws-iam-navigation.png">
</span>

IAM Enumeration module gives provides a lot more detailed information from an IAM credentials. For example, suppose you discovered SSRF and got credentials from EC2 instances and now want to see what role, policies, or services can be used for further exploitation. Currently, this module searches for the following services:

- IAM
  - Users
  - Groups
  - Roles
  - Policies
- Compute Services
  - Ec2
  - Lambda
  - BeanStalk
  - ecr
  - eks
  - ecs
- Storages
  - S3 Buckets
  - EC2 SnapShots
  - Cloud Front
  - Storage Gateway
  - EFS
- Network
  - Security Groups
  - VPCs
  - Route53


# S3 Scanner
<span align="center">
  <br>
  <img src="https://github.com/TROUBLE-1/Vajra/raw/main/images/aws-s3scanner.png">
</span>

S3 Scanner works just like other tool where you provide a common word and permutaion list which scans for valid bucket nothing fancy here.


# Bugs and Feature Requests

Please raise an issue if you encounter a bug or have a feature request. 

# Contributing

If you want to contribute to a project and make it better, your help is very welcome.
