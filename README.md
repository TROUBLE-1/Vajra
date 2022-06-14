<h1 align="center">
  Vajra - Your Weapon To Cloud 
</h1>

<p align="center">
  <a href="https://github.com/s0md3v/Arjun/releases">
    <img src="https://raw.githubusercontent.com/toolswatch/badges/b3a921c9e9084018758752aacc9bd9ec95cd11f8/arsenal/europe/2021.svg">
  </a>
  <a href="https://github.com/s0md3v/Arjun/releases">
    <img src="https://img.shields.io/badge/License-AGPL_v3-blue.svg">
  </a>
  
</p>


<br>
<p align="center">
  <a href="https://github.com/TROUBLE-1/Vajra/">
    <img src="https://media3.giphy.com/media/pZOMvUVfVKJWP05Kww/giphy.gif"  width="750" >
  </a>
</p>



## About Vajra

Vajra is a UI based tool with multiple techniques for attacking and enumerating in target's Azure environment. 

The term Vajra refers to the Weapon of God Indra in Indian mythology (God of Thunder &amp; Storms). Its connection to the cloud makes it a perfect name for the tool.

Vajra presently supports Azure and AWS Cloud environments, with plans to add support for Google Cloud Platform and certain OSINT in the future.

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

Raunak Parmar is an information security professional whose areas of interest include web penetration testing, Azure/AWS security, source code review, scripting, and development.

He has 2+ years of experience in information security. Raunak likes to research new attack methodologies and create open-source tools that can be used during the Cloud Security assessments. He has worked extensively on Azure and AWS.

He is the author of [Vajra](https://github.com/TROUBLE-1/Vajra) and [365-Stealer](https://github.com/AlteredSecurity/365-Stealer) an offensive cloud security tool. He has spoken in multiple conferences and local meetups.

<a target="_blank"><img alt="readme-stats" src="https://github-readme-stats.vercel.app/api?username=trouble-1&show_icons=true&theme=vue-dark"/></a>

### **Social Media Links**

- Twitter: [https://twitter.com/trouble1\_raunak](https://twitter.com/trouble1_raunak)
- YouTube: [https://www.youtube.com/channel/UCkJ\_sEF8iUDXPCI3UL0DAcg](https://www.youtube.com/channel/UCkJ_sEF8iUDXPCI3UL0DAcg)
- Linkedin: [https://www.linkedin.com/in/trouble1raunak/](https://www.linkedin.com/in/trouble1raunak/)
- GitHub: [https://github.com/TROUBLE-1/](https://github.com/TROUBLE-1/)




# Installation
<!--
Install postgres database with credential postgres/postgres and create a database name vajra. If postgres is not installed then by default sqlite will be used.
--->
## Docker

Pull the image file from dockerhub
```
docker pull tr0uble1/vajra   
```
Run Vajra with following and navigate to http://localhost
```
docker run -p 80:80 -d tr0uble1/vajra
```

## Manually

Run the following command to install all the modules.

```
pip install -r requirements.txt
```
Once installed run the following to start the application.

```
python app.py
```


## How to use Vajra?

A detailed usage guide is available on [Documentation](https://github.com/TROUBLE-1/Vajra/wiki/Documentation) section of the Wiki.

## Bugs and Feature Requests

Please raise an issue if you encounter a bug or have a feature request.

## Contributing

If you want to contribute to a project and make it better, your help is very welcome.
