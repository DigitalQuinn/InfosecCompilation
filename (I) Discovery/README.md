# Discovery

Discovery consists of techniques an adversary may use to gain knowledge about the system and internal network. These techniques help adversaries observe the environment and orient themselves before deciding how to act. They also allow adversaries to explore what they can control and what’s around their entry point in order to discover how it could benefit their current objective. Native operating system tools are often used toward this post-compromise information-gathering objective.

<br>
<hr>

# Table of Contents
- [Account Discovery](#account-discovery)
  - [Local Account](#local-account)
  - [Domain Account](#domain-account)
  - [Email Account](#email-account)
  - [Cloud Account](#cloud-account)
- [Application Window Discovery](#application-window-discovery)
- [Browser Bookmark Discovery](#browser-bookmark-discovery)
- [Cloud Infrastructure Discovery](#cloud-infrastructure-discovery)
  - [AWS](#aws)
  - [GCP & Azure](#gcp--azure)
- [Cloud Service Dashboard](#cloud-service-dashboard)
- [Cloud Service Discovery](#cloud-service-discovery)
- [Cloud Storage Object Discovery](#cloud-storage-object-discovery)
- [Container & Resource Discovery](#container--resource-discovery)
- [Debugger Evasion](#debugger-evasion)
- [Domain Trust Discovery](#domain-trust-discovery)
- [File & Directory Discovery](#file--directory-discovery)
- [Group Policy Discovery](#group-policy-discovery)
- [Network Service Discovery](#network-service-discovery)
- [Network Share Discovery](#network-share-discovery)
- [Network Sniffing](#network-sniffing)
- [Password Policy Discovery](#password-policy-discovery)
- [Peripheral Device Discovery](#peripheral-device-discovery)
- [Permission Groups Discovery](#permission-groups-discovery)
  - [Local Groups](#local-groups)
  - [Domain Groups](#domain-groups)
  - [Cloud Groups](#cloud-groups)
- [Process Discovery](#process-discovery)
- [Query Registry](#query-registry)
- [Remote System Discovery](#remote-system-discovery)
- [Software Discovery](#software-discovery)
  - [Security Software Discovery](#security-software-discovery)
- [System Information Discovery](#system-information-discovery)
- [System Location Discovery](#system-location-discovery)
  - [System Language Discovery](#system-language-discovery)
- [System Network Configurations Discovery](#system-network-configuration-discovery)
  - [Internet Connection Discovery](#internet-connection-discovery)
- [System Network Connections Discovery](#system-network-connections-discovery)
- [System Owner / User Discovery](#system-owneruser-discovery)
- [System Service Discovery](#system-service-discovery)
- [Virtualization / Sandbox Evasion](#virtualizationsandbox-evasion)
  - [System Checks](#system-checks)
  - [User Activity Based Checks](#user-activity-based-checks)
  - [Time-Based Evasion](#time-based-evasion)

# Account Discovery
Adversaries may attempt to get a listing of accounts on a system or within an environment. This information can help adversaries determine which accounts exist to aid in follow-on behavior.

<br>

## Local Account
**List local users and groups**
* Windows: `net user` and `net localgroup` and `id`
* macOS: `groups` and `dscacheutil -q group` 
  * `dscl . list /Users`
* Linux: `ldapsearch` 

<br>

## Domain Account
**List domain users and groups**
* Windows: `net user /domain` and `net group /domain` 
* macOS: `dscacheutil -q group` 
* Linux: `ldapsearch` 

<br>

## Email Account
Adversaries may try to dump Exchange address lists such as global address lists (GALs)
* In on-premises Exchange and Exchange Online, `theGet-GlobalAddressList` PowerShell cmdlet can be used to obtain email addresses and accounts from a domain using an authenticated session


In Google Workspace, the GAL is shared with Microsoft Outlook users through the Google Workspace Sync for Microsoft Outlook (GWSMO) service
* Additionally, the Google Workspace Directory allows for users to get a listing of other users within the organization

<br>

## Cloud Account
With authenticated access there are several tools that can be used to find accounts
* `Get-MsolRoleMember` PowerShell cmdlet: Obtain account names given a role or permissions group in Office 365
* Azure CLI (AZ CLI) also provides an interface to obtain user accounts with authenticated access to a domain
  * `az ad user list`: Lists all users within a domain
* The AWS command `aws iam list-users` may be used to obtain a list of users in the current account while aws iam list-roles can obtain IAM roles that have a specified path prefix
* In GCP, `gcloud iam service-accounts list` and `gcloud projects get-iam-policy` may be used to obtain a listing of service accounts and users in a project

<br>
<hr>

# Application Window Discovery
Adversaries may attempt to get a listing of open application windows. Window listings could convey information about how the system is used or give context to information collected by a keylogger

<br>
<hr>

# Browser Bookmark Discovery
Browser bookmarks may reveal personal information about users as well as details about internal network resources such as servers, tools/dashboards, or other related infrastructure

Browser bookmarks may also highlight additional targets after an adversary has access to valid credentials, especially Credentials In Files associated with logins cached by a browser
* Specific storage locations vary based on platform and/or application, but browser bookmarks are typically stored in local files/databases

<br>
<hr>

# Cloud Infrastructure Discovery
Cloud providers offer methods such as APIs and commands issued through CLIs to serve information about infrastructure

<br>

## AWS
* `DescribeInstances` API: Returns information about one or more instances within an account
* `ListBuckets` API: Returns a list of all buckets owned by the authenticated sender of the request
* `HeadBucket` API: Determines a bucket’s existence along with access permissions of the request sender
* `GetPublicAccessBlock` API: Retrieves access block configuration for a bucket
  
<br>

## GCP & Azure
* `gcloud compute instances list`: Lists all Google Compute Engine instances in a project
* `az vm list`: Lists details of VMss
  
In addition to API commands, adversaries can utilize open source tools to discover cloud storage infrastructure through Wordlist Scanning

An adversary may enumerate resources using a compromised user's access keys to determine which are available to that user

* The discovery of available resources may help adversaries determine their next steps in the Cloud environment -- Establishing Persistence
* An adversary may also use this information to change the configuration to make the bucket publicly accessible, allowing data to be accessed without authentication
* Adversaries have also may use infrastructure discovery APIs such as `DescribeDBInstances` to determine size, owner, permissions, and network ACLs of database resources
* Adversaries can use this information to determine the potential value of databases and discover the requirements to access them
  
Unlike in Cloud Service Discovery, this technique focuses on the discovery of components of the provided services rather than the services themselves

<br>
<hr>

# Cloud Service Dashboard
An adversary may use a cloud service dashboard GUI with stolen credentials to gain useful information from an operational cloud environment, such as specific services, resources, and features

* **GCP Command Center** can be used to view all assets, findings of potential security risks, and to run additional queries, such as finding public IP addresses and open ports

Depending on the configuration of the environment, an adversary may be able to enumerate more information via the graphical dashboard than an API -- This allows the adversary to gain information without making any API requests

<br>
<hr>

# Cloud Service Discovery
Adversaries may attempt to discover information about the services enabled throughout the environment
* Azure tools and APIs, such as the Azure AD Graph API and Azure Resource Manager API, can enumerate resources and services, including applications, management groups, resources and policy definitions, and their relationships that are accessible by an identity

* **Stormspotter:** An open source tool for enumerating and constructing a graph for Azure resources and services
* **Pacu:** An open source AWS exploitation framework that supports several methods for discovering cloud services

<br>
<hr>

# Cloud Storage Object Discovery
Adversaries may enumerate objects in cloud storage infrastructure. Adversaries may use this information during automated discovery to shape follow-on behaviors, including requesting all or specific objects from cloud storage

* Similar to *File and Directory Discovery* on a local host, after identifying available storage services, adversaries may access the contents/objects stored in cloud infrastructure

Cloud service providers offer APIs allowing users to enumerate objects stored within cloud storage, such as `ListObjectsV2` in AWS and `List Blobs` in Azure

<br>
<hr>

# Container & Resource Discovery
Adversaries may attempt to discover containers and other resources that are available within a containers environment; Other resources may include images, deployments, pods, nodes, and other information such as the status of a cluster

These resources can be viewed within web applications such as the Kubernetes dashboard or can be queried via the Docker and Kubernetes API

* In Docker, logs may leak information about the environment, such as the environment’s configuration, which services are available, and what cloud provider the victim may be utilizing
* The discovery of these resources may inform an adversary’s next steps in the environment, such as how to perform lateral movement and which methods to utilize for execution

<br>
<hr>

# Debugger Evasion
**Debuggers:** Typically used by defenders to trace and/or analyze the execution of potential malware payloads


**Debugger Evasion**
* Changing behaviors based on the results of the checks for the presence of artifacts indicative of a debugged environment
* Similar to *Virtualization/Sandbox Evasion*, if the adversary detects a debugger, they may alter their malware to disengage from the victim or conceal the core functions of the implant
* They may also search for debugger artifacts before dropping secondary or additional payloads

Specific checks will vary based on the target and/or adversary, but may involve Native API function calls such as `IsDebuggerPresent()` and `NtQueryInformationProcess()`, or manually checking the `BeingDebugged` flag of the **Process Environment Block (PEB)**
* Other checks for debugging artifacts may also seek to enumerate hardware breakpoints, interrupt assembly opcodes, time checks, or measurements if exceptions are raised in the current process (assuming a present debugger would "swallow" or handle the potential error)

Adversaries may use the information learned from these debugger checks during automated discovery to shape follow-on behaviors
* **NOTE::** Debuggers can also be evaded by detaching the process or flooding debug logs with meaningless data via messages produced by looping Native API function calls such as `OutputDebugStringW()`

<br>
<hr>

# Domain Trust Discovery
**Domain Trusts** provide a mechanism for a domain to allow access to resources based on the authentication procedures of another domain
* Allows users of the trusted domain to access resources in the trusting domain
* The information discovered may help the adversary conduct **SID-History Injection, Pass the Ticket, and Kerberoasting**
  
* Domain trusts can be enumerated using the `DSEnumerateDomainTrusts()` Win32 API call, `.NET methods`, and `LDAP`
* The Windows utility `Nltest` is known to be used by adversaries to enumerate domain trusts

<br>
<hr>

# File & Directory Discovery
Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system. Adversaries may use the information from File and Directory Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions

Many command shell utilities can be used to obtain this information
* `dir`, `tree`, `ls`, `find`, and `locate`
* Custom tools may also be used to gather file and directory information and interact with the Native API
* Adversaries may also leverage a Network Device CLI on network devices to gather file and directory information

<br>
<hr>

# Group Policy Discovery
**Group Policy:** Allows for centralized management of user and computer settings in AD
* **Group Policy Objects (GPOs):** Containers for group policy settings made up of files stored within a predicable network path `\\SYSVOL\\Policies\` 

Adversaries may gather information on Group Policy settings to identify paths for privilege escalation, security measures applied within a domain, and to discover patterns in domain objects that can be manipulated or used to blend in the environment
* Use commands such as `gpresult` or various publicly available PowerShell functions, such as `Get-DomainGPO` and `Get-DomainGPOLocalGroup`, to gather information on Group Policy settings
  
* **NOTE::** Adversaries may use this information to shape follow-on behaviors, including determining potential attack paths within the target network as well as opportunities to manipulate Group Policy settings (i.e. Domain Policy Modification) for their benefit

<br>
<hr>

# Network Service Discovery
Within cloud environments, adversaries may attempt to discover services running on other cloud hosts
* Additionally, if the cloud environment is connected to a on-premises environment, adversaries may be able to identify services running on non-cloud systems as well

Within macOS environments, adversaries may use the native Bonjour application to discover services running on other macOS hosts within a network
* The **Bonjour mDNSResponder** daemon automatically registers and advertises a host’s registered services on the network
  * Attackers can use a **mDNS** query (such as `dns-sd -B _ssh._tcp .`) to find other systems broadcasting the ssh service

<br>
<hr>

# Network Share Discovery
Adversaries may look for folders and drives shared on remote systems as a means of identifying sources of information to gather as a precursor for Collection and to identify potential systems of interest for Lateral Movement
* Networks often contain shared network drives and folders that enable users to access file directories on various systems across a network

File sharing over a Windows network occurs over the SMB protocol
* `Net` can be used to query a remote system for available shared drives
  * `net view \\remotesystem` 
* Query shared drives on the local system using `net share`
  
* For macOS, the `sharing -l` command lists all shared points used for smb services

<br>
<hr>

# Network Sniffing
**Network Sniffing:** Refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection
* An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data

Data captured via this technique may include user credentials, especially those sent over an insecure, unencrypted protocol
* Techniques for name service resolution poisoning, such as **LLMNR/NBT-NS Poisoning and SMB Relay**, can also be used to capture credentials to websites, proxies, and internal systems by redirecting traffic to an adversary

Network sniffing may also reveal configuration details, such as running services, version numbers, and other network characteristics necessary for *Lateral Movement and/or Defense Evasion* activities

In cloud-based environments, adversaries may still be able to use traffic mirroring services to sniff network traffic from VMss
* AWS Traffic Mirroring, GCP Packet Mirroring, and Azure vTap allow users to define specified instances to collect traffic from and specified targets to send collected traffic to
  * Often, much of this traffic will be in cleartext due to the use of TLS termination at the load balancer level to reduce the strain of encrypting and decrypting traffic
  * The adversary can then use exfiltration techniques such as *Transfer Data to Cloud Account* in order to access the sniffed traffic

<br>
<hr>

# Password Policy Discovery
Password policies are a way to enforce complex passwords that are difficult to guess or crack through Brute Force
* Password policies can be set and discovered on Windows, Linux, and macOS systems via various command shell utilities
  * Windows
    * `net accounts /domain`
    * `Get-ADDefaultDomainPasswordPolicy`
  * Linux
    * `chage -l`
    * `cat /etc/pam.d/common-password`
    * `pwpolicy getaccountpolicies`
  * AWS
    * `GetAccountPasswordPolicy`

Adversaries may also leverage a Network Device CLI on network devices to discover password policy information

<br>
<hr>

# Peripheral Device Discovery
Peripheral devices could include auxiliary resources that support a variety of functionalities such as keyboards, printers, cameras, smart card readers, or removable storage. The information may be used to enhance their awareness of the system and network environment or may be used for further action

<br>
<hr>

# Permission Groups Discovery
Adversaries may attempt to find group and permission settings. This information can help adversaries determine which user accounts and groups are available, the membership of users in particular groups, and which users and groups have elevated permissions

<br>

## Local Groups
Adversaries may attempt to find local system groups and permission settings. The knowledge of local system permission groups can help adversaries determine which groups exist and which users belong to a particular group
* Windows: `net localgroup`
* macOS: `dscl . -list /Groups`
* Linux: `groups` 

<br>

## Domain Groups
The knowledge of domain-level permission groups can help adversaries determine which groups exist and which users belong to a particular group. Adversaries may use this information to determine which users have elevated permissions, such as domain administrators.

* Windows: `net group /domain`
* macOS: `dscacheutil -q group`
* Linux: `ldapsearch`

<br>

## Cloud Groups
The knowledge of cloud permission groups can help adversaries determine the particular roles of users and groups within an environment, as well as which users are associated with a particular group

With authenticated access there are several tools that can be used to find permissions groups

* `Get-MsolRole`: Obtain roles and permissions groups for Exchange and Office 365 accounts 
* `az ad user get-member-groups`: Lists groups associated to a user account for Azure
* API endpoint `GET https://cloudidentity.googleapis.com/v1/groups`: Lists group resources available to a user for Google 

Adversaries may attempt to list ACLs for objects to determine the owner and other accounts with access to the object, for example, via the AWS `GetBucketAcl` API
* Using this information an adversary can target accounts with permissions to a given object or leverage accounts they have already compromised to access the object

<br>
<hr>

# Process Discovery
Information about running processes on a system could be used to gain an understanding of common software/applications running on systems within the network
* Adversaries may use the information from **Process Discovery** during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions

* Windows environments
  * Tasklist utility via cmd or `Get-Process` via PowerShell
* Information about processes can also be extracted from the output of Native API calls such as `CreateToolhelp32Snapshot`
* In Mac and Linux, this is accomplished with the `ps` command
  * Adversaries may also `opt` to enumerate processes via `/proc`

<br>
<hr>

# Query Registry
The Registry contains a significant amount of information about the operating system, configuration, software, and security
* Information can easily be queried using the **Reg utility**
* Adversaries may use the information from Query Registry during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions

<br>
<hr>

# Remote System Discovery
Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system. Functionality could exist within remote access tools to enable this, but utilities available on the operating system could also be used such as `Ping` or `net view`

Adversaries may also analyze data from local host files (ex: `C:\Windows\System32\Drivers\etc\hosts` or `/etc/hosts`) or other passive means (such as local Arp cache entries) in order to discover the presence of remote systems in an environment
* Adversaries may also target discovery of network infrastructure as well as leverage Network Device CLI commands on network devices to gather detailed information about systems within a network

<br>
<hr>

# Software Discovery
Adversaries may attempt to get a listing of software and software versions that are installed on a system or in a cloud environment. Adversaries may use the information from Software Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

Adversaries may attempt to enumerate software for a variety of reasons, such as figuring out what security measures are present or if the compromised system has a version of software that is vulnerable to *Exploitation* for *Privilege Escalation*

<br>

## Security Software Discovery
Adversaries may attempt to get a listing of security software, configurations, defensive tools, and sensors that are installed on a system or in a cloud environment. This may include things such as firewall rules and anti-virus. Adversaries may use the information from Security Software Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions

**Obtain security software information**
* `netsh`
* `reg query`
* `dir`
* Tasklist
  
It is becoming more common to see macOS malware perform checks for `LittleSnitch` and `KnockKnock` software

Adversaries may also utilize cloud APIs to discover the configurations of firewall rules within an environment
* Permitted IP ranges, ports or user accounts for the inbound/outbound rules of security groups, virtual firewalls established within AWS for EC2 and/or VPC instances, can be revealed by the `DescribeSecurityGroups` action with various request parameters

<br>
<hr>

# System Information Discovery
An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture. Adversaries may use the information from System Information Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

`Systeminfo`: Gather detailed system information

* If running with privileged access, a breakdown of system data can be gathered through the systemsetup configuration tool on macOS
  * Adversaries with **user-level access** can execute the `df -aH` command to obtain currently mounted disks and associated freely available space
  * Adversaries may also leverage a Network Device CLI on network devices to gather detailed system information
  
System Information Discovery combined with information gathered from other forms of discovery and reconnaissance can drive payload development and concealment

IaaS providers allow access to instance and VMs information via APIs
* Successful authenticated API calls can return data such as the operating system platform and status of a particular instance or the model view of a VM

<br>
<hr>

# System Location Discovery
Adversaries may gather information in an attempt to calculate the geographical location of a victim host. Adversaries may use the information from System Location Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and attempts specific actions

Adversaries may attempt to infer the location of a system using various system checks, such as time zone, keyboard layout, and/or language settings

* Windows API functions such as `GetLocaleInfoW` can also be used to determine the locale of the host
* In cloud environments, an instance's availability zone may also be discovered by accessing the instance metadata service from the instance
* Adversaries may also attempt to infer the location of a victim host using IP addressing, such as via online geolocation IP-lookup services

<br>

## System Language Discovery
Adversaries may attempt to gather information about the system language of a victim in order to infer the geographical location of that host. This information may be used to shape follow-on behaviors, including whether the adversary infects the target and/or attempts specific actions

* This decision may be employed by malware developers and operators to reduce their risk of attracting the attention of specific law enforcement agencies or prosecution/scrutiny from other entities

There are various sources of data an adversary could use to infer system language, such as **system defaults and keyboard layouts**
* Specific checks will vary based on the target and/or adversary, but may involve behaviors such as Query Registry and calls to Native API functions

On Windows, attackers may attempt to infer the language of a system by querying the registry key `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Nls\Language` or parsing the outputs of Windows API functions `GetUserDefaultUILanguage`, `GetSystemDefaultUILanguage`, `GetKeyboardLayoutList` and `GetUserDefaultLangID`

On a macOS or Linux system, adversaries may query `locale` to retrieve the value of the **$LANG** environment variable

<br>
<hr>

# System Network Configuration Discovery
Adversaries may look for details about the network configuration and settings, such as IP and/or MAC addresses, of systems they access or through information discovery of remote systems
* `arp`, `ipconfig/ifconfig`, `nbtstat`, and `route`

Adversaries may also leverage a Network Device CLI on network devices to gather information about configurations and settings, such as IP addresses of configured interfaces and static/dynamic routes

Adversaries may use the information from System Network Configuration Discovery during automated discovery to shape follow-on behaviors, including determining certain access within the target network and what actions to do next

## Internet Connection Discovery
Adversaries may check for Internet connectivity on compromised systems
* `Ping`, `tracert`, and `GET` requests to websites

Adversaries may use the results and responses from these requests to determine if the system is capable of communicating with their C2 servers before attempting to connect to them; The results may also be used to identify routes, redirectors, and proxy servers

<br>
<hr>

# System Network Connections Discovery
Adversaries may attempt to get a listing of network connections to/from the compromised system they are currently accessing or from remote systems by querying for information over the network

An adversary who gains access to a system that is part of a cloud-based environment may map out Virtual Private Clouds or Virtual Networks in order to determine what systems and services are connected

* Windows: `netstat`, `net use`, and `net session`
* macOS / Linux: `netstat` and `lsof` -- List current connections
  * `who -a` and `w` -- Show which users are currently logged in
* Additionally, built-in features native to network devices and Network Device CLI may be used

<br>
<hr>

# System Owner/User Discovery
Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system
* The information may be collected in a number of different ways using other Discovery techniques, because user and username details are prevalent throughout a system and include *running process ownership*, *file/directory ownership*, *session information*, and *system logs*

* `whoami`, `who`, `who -w`
* `dscl . list /Users | grep -v '_'`: Enumerate macOS user accounts
  * Environment variables, such as `%USERNAME%` and `$USER`, may also be used to access this information

<br>
<hr>

# System Service Discovery
Adversaries may try to gather information about registered local system services
* `sc query`, `tasklist /svc`, `systemctl --type=service`, and `net start`

<br>
<hr>

# System Time Discovery
The system time is set and stored by the Windows Time Service within a domain to maintain time synchronization between systems and services in an enterprise network

* `net time \hostname`: Gather the system time on a remote system
  * The victim's time zone may also be inferred from the current system time or gathered by using `w32tm /tz`

* **NOTE::** This information could be useful for performing other techniques, such as executing a file with a Scheduled Task/Job, or to discover locality information based on time zone to assist in victim targeting (System Location Discovery)
* Adversaries may also use knowledge of system time as part of a time bomb, or delaying execution until a specified date/time

<br>
<hr>

# Virtualization/Sandbox Evasion
Adversaries may employ various means to detect and avoid virtualization and analysis environments; This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a VME/sandbox

* If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant
* They may also search for VME artifacts before dropping secondary or additional payloads
* Adversaries may use the information learned from *Virtualization/Sandbox Evasion* during automated discovery to shape follow-on behaviors

**Accomplish Virtualization/Sandbox Evasion**
* Checking for security monitoring tools or other system artifacts associated with analysis or virtualization
* Check for legitimate user activity to help determine if it is in an analysis environment
* Use of sleep timers or loops within malware code to avoid operating within a temporary sandbox

<br>

## System Checks
Specific checks will vary based on the target and/or adversary, but may involve behaviors such as Windows Management Instrumentation, PowerShell, System Information Discovery, and Query Registry to obtain system information and search for VME artifacts
* Search for VME artifacts in memory, processes, file system, hardware, and/or the Registry
* Use scripting to automate these checks into one script and then have the program exit if it determines the system to be a VME

Checks could include;
* Generic system properties -- host/domain name and samples of network traffic
* Check the network adapters addresses, CPU core count, and available memory/drive size
* Enumerate services running that are unique to these applications, installed programs on the system, manufacturer/product fields for strings relating to VM applications, and VME-specific hardware/processor instructions
  * In applications like VMWare, adversaries can also use a special I/O port to send commands and receive output

Hardware checks, such as the presence of the fan, temperature, and audio devices, could also be used to gather evidence that can be indicative a VME
* Adversaries may also query for specific readings from these devices

<br>

## User Activity Based Checks
Adversaries may employ various user activity checks to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a VME/sandbox
* If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant
  * They may also search for VME artifacts before dropping secondary or additional payloads
  * Adversaries may use the information learned from *Virtualization/Sandbox Evasion* during automated discovery to shape follow-on behaviors

### Attacker Methodology
* Search for user activity on the host based on variables such as the speed/frequency of mouse movements and clicks, browser history, cache, bookmarks, or number of files in common directories such as home or the desktop
* Other methods may rely on specific user interaction with the system before the malicious code is activated, such as waiting for a document to close before activating a macro or waiting for a user to double click on an embedded image to activate

<br>

## Time-Based Evasion
Adversaries may employ various time-based methods to detect and avoid virtualization and analysis environments; This may include enumerating time-based properties, such as uptime or the system clock, as well as the use of timers or other triggers to avoid a VME/sandbox, specifically those that are automated or only operate for a limited amount of time

Adversaries may employ various time-based evasions, such as delaying malware functionality upon initial execution using programmatic sleep commands or native system scheduling functionality (Scheduled Task/Job)
* Delays may also be based on waiting for specific victim conditions to be met (system time, events, etc.) or employ scheduled Multi-Stage Channels to avoid analysis and scrutiny

Benign commands or other operations may also be used to delay malware execution
* Loops or otherwise needless repetitions of commands, such as Pings, may be used to delay malware execution and potentially exceed time thresholds of automated analysis environments
* **API Hammering:** Involves making various calls to Native API functions in order to delay execution (while also potentially overloading analysis environments with junk data)

Adversaries may also use time as a metric to detect sandboxes and analysis environments, particularly those that attempt to manipulate time mechanisms to simulate longer elapses of time
* Attackers may be able to identify a sandbox accelerating time by sampling and calculating the expected value for an environment's timestamp before and after execution of a sleep function