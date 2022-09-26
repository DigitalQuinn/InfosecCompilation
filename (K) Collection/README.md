# Collection

Collection consists of techniques adversaries may use to gather information and the sources information is collected from that are relevant to following through on the adversary's objectives. Frequently, the next goal after collecting data is to steal (exfiltrate) the data. Common target sources include various drive types, browsers, audio, video, and email. Common collection methods include capturing screenshots and keyboard input

<br>
<hr>

# Table of Contents
- [Adversary in the Middle](#adversary-in-the-middle)
  - [LLMNR/NBT-NS Poisoning & SMB Relay](#llmnrnbt-ns-poisoning-and-smb-relay)
  - [ARP Cache Poisoning](#arp-cache-poisoning)
  - [DHCP Spoofing](#dhcp-spoofing)
- [Archive Collected Data](#archive-collected-data)
  - [Archive via Utility](#archive-via-utility)
  - [Archive via Library](#archive-via-library)
  - [Archive via Custom Method](#archive-via-custom-method)
- [Audio Capture](#audio-capture)
- [Automated Collection](#automated-collection)
- [Browser Session Hijacking](#browser-session-hijacking)
- [Clipboard Data](#clipboard-data)
- [Data from Cloud Storage Object](#data-from-cloud-storage-object)
- [Data from Configuration Repository](#data-from-configuration-repository)
  - [SNMP (MIB Dump)](#snmp-mib-dump)
  - [Network Device Configuration Dump](#network-device-configuration-dump)
- [Data from Information Repositories](#data-from-information-repositories)
  - [Confluence](#confluence)
  - [Sharepoint](#sharepoint)
  - [Code Repositories](#code-repositories)
- [Data from Local System](#data-from-local-system)
- [Data from Network-Shared Drives](#data-from-network-shared-drives)
- [Data from Removable Media](#data-from-removable-media)
- [Data Staged](#data-staged)
  - [Local Data Staging](#local-data-staging)
  - [Remote Data Staging](#remote-data-staging)
- [Email Collection](#email-collection)
  - [Local Email Collection](#local-email-collection)
  - [Remote Email Collection](#remote-email-collection)
  - [Email Forwarding Rule](#email-forwarding-rule)
- [Input Capture](#input-capture)
  - [Keylogging](#keylogging)
  - [GUI Input Capture](#gui-input-capture)
  - [Web Portal Capture](#web-portal-capture)
  - [Credential API Hooking](#credential-api-hooking)
- [Screen Capture](#screen-capture)
- [Video Capture](#video-capture)

<br>
<hr>

# Adversary-in-the-Middle
Adversaries may AiTM technique to conduct *Network Sniffing* or *Transmitted Data Manipulation* by abusing common networking protocols that can determine the flow of network traffic (ARP, DNS, LLMNR, etc.)

* Manipulate victim DNS settings to enable other malicious activities such as preventing/redirecting users from accessing legitimate sites and/or pushing additional malware
* **Downgrade Attacks** can also be used to establish an AiTM position, such as by negotiating a less secure, deprecated, or weaker version of communication protocol or encryption algorithm

Adversaries may also leverage the AiTM position to attempt to monitor and/or modify traffic, such as in **Transmitted Data Manipulation**
* Adversaries can setup a position similar to AiTM to prevent traffic from flowing to the appropriate destination, potentially to Impair Defenses and/or in support of DoS

<br>

## LLMNR/NBT-NS Poisoning and SMB Relay
**Link-Local Multicast Name Resolution (LLMNR) & NetBIOS Name Service (NBT-NS)** are Microsoft Windows components that serve as alternate methods of host identification
* **LLMNR:** Based upon the DNS format and allows hosts on the same local link to perform name resolution for other hosts
* **NBT-NS:** Identifies systems on a local network by their NetBIOS name

By responding to LLMNR/NBT-NS network traffic, adversaries may spoof an authoritative source for name resolution to force communication with an adversary controlled system; This activity may be used to collect or relay authentication materials


Adversaries can spoof an authoritative source for name resolution on a victim network by responding to LLMNR (UDP 5355)/NBT-NS (UDP 137) traffic as if they know the identity of the requested host, effectively poisoning the service so that the victims will communicate with the adversary controlled system
* If the requested host belongs to a resource that requires identification/authentication, the `username and NTLMv2 hash` will then be sent to the adversary controlled system
* The adversary can then collect the hash information sent over the wire through tools that monitor the ports for traffic or through Network Sniffing and crack the hashes offline through Brute Force to obtain the plaintext passwords
  * In some cases where an adversary has access to a system that is in the authentication path between systems or when automated scans that use credentials attempt to authenticate to an adversary controlled system, the NTLMv2 hashes can be intercepted and relayed to access and execute code against a target system
* The relay step can happen in conjunction with poisoning but may also be independent of it

### Tools
Several tools exist that can be used to poison name services within local networks such as NBNSpoof, Metasploit, and Responder

<br>

## ARP Cache Poisoning
**ARP:** Used to resolve IPv4 addresses to MAC address. Devices in a local network segment communicate with each other by using link layer addresses

Adversaries may poison ARP caches to position themselves between the communication of two or more networked devices -- This activity may be used to enable follow-on behaviors such as *Network Sniffing* or *Transmitted Data Manipulation*


An adversary may passively wait for an ARP request to poison the ARP cache of the requesting device
* The adversary may reply with their MAC address, thus deceiving the victim by making them believe that they are communicating with the intended networked device
  * For the adversary to poison the ARP cache, their reply must be faster than the one made by the legitimate IP address owner
* Adversaries may also send a gratuitous ARP reply that maliciously announces the ownership of a particular IP address to all the devices in the local network segment

The ARP protocol is stateless and does not require authentication; Therefore, devices may wrongly add or update the MAC address of the IP address in their ARP cache

Adversaries may use ARP cache poisoning as a means to intercept network traffic; This activity may be used to collect and/or relay data such as credentials, especially those sent over an insecure, unencrypted protocol

<br>

## DHCP Spoofing
**DHCP:** Based on a client-server model and has two functionalities
A. A protocol for providing network configuration settings from a DHCP server to a client
B. Mechanism for allocating network addresses to clients; The typical server-client interaction is as follows:

1. Clients broadcasts a DISCOVER message
2. The server responds with an OFFER message, which includes an available network address
3. The client broadcasts a REQUEST message, which includes the network address offered
4. The server acknowledges with an ACK message and the client receives the network configuration parameters


Adversaries may redirect network traffic to adversary-owned systems by spoofing DHCP traffic and acting as a malicious DHCP server on the victim network
* By achieving AiTM, adversaries may collect network communications, including passed credentials, especially those sent over insecure, unencrypted protocols
  * This may also enable follow-on behaviors such as Network Sniffing or Transmitted Data Manipulation.

Malware can act as a DHCP server and provide adversary-owned DNS servers to the victimized computers
* Through the malicious network configurations, an adversary may achieve the AiTM position, route client traffic through adversary-controlled systems, and collect information from the client network

Rather than establishing an AiTM position, adversaries may also abuse DHCP spoofing to perform a DHCP exhaustion attack (**Service Exhaustion Flood**) by generating many broadcast **DISCOVER** messages to exhaust a network’s DHCP allocation pool

<br>
<hr>

# Archive Collected Data
An adversary may compress and/or encrypt data that is collected prior to exfiltration
* Compressing the data can help to obfuscate the collected data and minimize the amount of data sent over the network
* Encryption can be used to hide information that is being exfiltrated from detection or make exfiltration less conspicuous upon inspection by a defender

<br>

## Archive via Utility
Adversaries may abuse various utilities to compress or encrypt data before exfiltration. Some third party utilities may be preinstalled, such as `tar` on Linux and macOS or `zip` on Windows systems
  * On Windows, `diantz` or `makecab` may be used to package collected files into a cabinet (.cab) file
    * `diantz` may also be used to download and compress files from remote locations (*Remote Data Staging*)
  * Additionally, `xcopy` on Windows can copy files and directories with a variety of options

Adversaries may use also third party utilities, such as `7-Zip`, `WinRAR`, and `WinZip`, to perform similar activities

<br>

## Archive via Library
An adversary may compress or encrypt data that is collected prior to exfiltration using 3rd party libraries. Many libraries exist that can archive data, including Python `rarfile`, `libzip`, and `zlib`

* Some archival libraries are preinstalled on systems, such as `bzip2` on macOS and Linux, and `zip` on Windows
* Libraries can be linked against when compiling, while the utilities require spawning a subshell, or a similar execution mechanism

<br>

## Archive via Custom Method
An adversary may compress or encrypt data that is collected prior to exfiltration using a custom method. Adversaries may choose to use custom archival methods, such as encryption with *XOR* or *stream ciphers* implemented with no external library or utility references -- Custom implementations of well-known compression algorithms have also been used

<br>
<hr>

# Audio Capture
An adversary can leverage a computer's peripheral devices (e.g., microphones and webcams) or applications (e.g., voice and video call services) to capture audio recordings for the purpose of listening into sensitive conversations to gather information

Malware or scripts may be used to interact with the devices through an available API provided by the operating system or an application to capture audio. Audio files may be written to disk and exfiltrated later

<br>
<hr>

# Automated Collection
Attackers may use automated techniques for collecting internal data

* Methods for performing this technique could include use of a *Command and Scripting Interpreter* to search for and copy information fitting set criteria such as file type, location, or name at specific time intervals
* In cloud-based environments, adversaries may also use cloud APIs, CLIs, or extract, transform, and load (ETL) services to automatically collect data

This technique may incorporate use of other techniques such as *File and Directory Discovery* and *Lateral Tool Transfer* to identify and move files, as well as *Cloud Service Dashboard* and *Cloud Storage Object Discovery* to identify resources in cloud environments

<br>
<hr>

# Browser Session Hijacking
Adversaries may take advantage of security vulnerabilities and inherent functionality in browser software to change content, modify user-behaviors, and intercept information as part of various browser session hijacking techniques.

* A specific example is when an adversary injects software into a browser that allows them to inherit cookies, HTTP sessions, and SSL client certificates of a user then use the browser as a way to pivot into an authenticated intranet
  * Executing browser-based behaviors such as pivoting may require specific process permissions, such as `SeDebugPrivilege` and/or high-integrity/administrator rights

Another example involves pivoting browser traffic from the adversary's browser through the user's browser by setting up a proxy which will redirect web traffic
  * This does not alter the user's traffic in any way, and the proxy connection can be severed as soon as the browser is closed
* The adversary assumes the security context of whichever browser process the proxy is injected into
* Browsers typically create a new process for each tab that is opened and permissions and certificates are separated accordingly
  * With these permissions, an adversary could potentially browse to any resource on an intranet, such as Sharepoint or webmail, that is accessible through the browser and which the browser has sufficient permissions
  * Browser pivoting may also bypass security provided by 2-factor authentication

<br>
<hr>

# Clipboard Data
Adversaries may collect data stored in the clipboard from users copying information within or between applications

* In Windows, *Applications* can access clipboard data by using the Windows API
* OSX provides a native command, `pbpaste`, to grab clipboard contents

<br>
<hr>

# Data from Cloud Storage Object
CSPs offer solutions for online data storage such as Amazon S3, Azure Storage, and Google Cloud Storage
* Data from these solutions can be retrieved directly using the CSPs APIs -- Solution providers typically offer security guides to help end users configure systems

Common misconfiguration scenarios by end users
* Cloud storage has been improperly secured (Unintentionally allowing public access by unauthenticated users or overly-broad access by all users)
* Allowing open access to sensitive information
* Adversaries may also obtain leaked credentials in source repositories, logs, or other means as a way to gain access to cloud storage objects that have access permission controls

<br>
<hr>

# Data from Configuration Repository
**Configuration repositories** are used by management systems in order to configure, manage, and control data on remote systems. Configuration repositories may also facilitate remote access and administration of devices
* Adversaries may target these repositories in order to collect large quantities of sensitive system administration data
* Data from configuration repositories may be exposed by various protocols and software and can store a wide variety of data, much of which may align with adversary *Discovery* objectives

<br>

## SNMP (MIB Dump)
**Management Information Base (MIB):** A configuration repository that stores variable information accessible via SNMP in the form of **object identifiers (OID)**
* Each OID identifies a variable that can be read or set and permits active management tasks, such as configuration changes, through remote modification of these variables
* SNMP can give administrators great insight in their systems, such as, system information, description of hardware, physical location, and software packages
* MIBs may also contain device operational information, including running configuration, routing table, and interface details

Adversaries may use SNMP queries to collect MIB content directly from SNMP-managed devices in order to collect network information that allows the adversary to build network maps and facilitate future targeted exploitation

<br>

## Network Device Configuration Dump
The **network configuration** is a file containing parameters that determine the operation of the device
* The device typically stores an in-memory copy of the configuration while operating, and a separate configuration on non-volatile storage to load after device reset
  
Adversaries can inspect the configuration files to reveal information about the target network and its layout, the network device and its software, or identifying legitimate accounts and credentials for later use
* Use common maanegement tools suchh as SNMP and Smart Install (SMI), to access network configuration files
  * These tools may be used to query specific data from a configuration repository or configure the device to export the configuration for later analysis

<br>
<hr>

# Data from Information Repositories
**Information repositories** are tools that allow for storage of information, typically to facilitate collaboration or information sharing between users, and can store a wide variety of data that may aid adversaries in further objectives, or direct access to the target information

Information stored in a repository may vary based on the specific instance or environment; Specific common information repositories include web-based platforms such as Sharepoint and Confluence, specific services such as Code Repositories, IaaS databases, enterprise databases, and other storage infrastructure such as SQL Server

<br>

## Confluence
Confluence repositories often holds valuable information; Found in development environments alongside Atlassian JIRA, Confluence is generally used to store development-related documentation, however, in general may contain more diverse categories of useful information, such as:

* Policies, procedures, and standards
* Physical / logical network diagrams
* System architecture diagrams
* Technical system documentation
* Testing / development credentials
* Work / project schedules
* Source code snippets
* Links to network shares and other internal resources

<br>

## Sharepoint
SharePoint will often contain useful information for an adversary to learn about the structure and functionality of the internal network and systems

* Policies, procedures, and standards
* Physical / logical network diagrams
* System architecture diagrams
* Technical system documentation
* Testing / development credentials
* Work / project schedules
* Source code snippets
* Links to network shares and other internal resources

<br>

## Code Repositories
**Code repositories** are tools/services that store source code and automate software builds; They may be hosted internally or privately on third party sites such as Github, GitLab, SourceForge, and BitBucket
* Users typically interact with code repositories through a web application or command-line utilities such as `git`

Once adversaries gain access to a victim network or a private code repository, they may collect sensitive information such as proprietary source code or credentials contained within software's source code
* Having access to software's source code may allow adversaries to develop Exploits, while credentials may provide access to additional resources using *Valid Accounts*

<br>
<hr>

# Data from Local System
Adversaries may search local system sources, such as file systems and configuration files or local databases, to find files of interest and sensitive data prior to *Exfiltration*

Adversaries may do this using a *Command and Scripting Interpreter*, such as cmd as well as a Network Device CLI, which have functionality to interact with the file system to gather information. Adversaries may also use *Automated Collection* on the local system.

<br>
<hr>

# Data from Network-Shared Drives
Adversaries may search network shares on computers they have compromised to find files of interest. Sensitive data can be collected from remote systems via shared network drives (host shared directory, network file server, etc.) that are accessible from the current system prior to Exfiltration. Interactive command shells may be in use, and common functionality within cmd may be used to gather information

<br>
<hr>

# Data from Removable Media
Adversaries may search connected removable media on computers they have compromised to find files of interest. Sensitive data can be collected from any removable media (optical disk drive, USB memory, etc.) connected to the compromised system prior to *Exfiltration*
* Interactive command shells may be in use, and common functionality within cmd may be used to gather information

Some adversaries may also use *Automated Collection* on removable media

<br>
<hr>

# Data Staged
Data may be kept in separate files or combined into one file through techniques such as *Archive Collected Data*. Interactive command shells may be used, and common functionality within cmd and bash may be used to copy data into a staging location 

In cloud environments, adversaries may stage data within a particular instance or virtual machine before exfiltration. An adversary may *Create Cloud Instance* and stage data in that instance 

Adversaries may choose to stage data from a victim network in a centralized location prior to *Exfiltration* to minimize the number of connections made to their C2 server and better evade detection

<br>

## Local Data Staging
Adversaries may stage collected data in a central location or directory on the local system prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as Archive Collected Data. Interactive command shells may be used, and common functionality within cmd and bash may be used to copy data into a staging location.

Adversaries may also stage collected data in various available formats/locations of a system, including local storage databases/repositories or the Windows Registry

<br>

## Remote Data Staging
Adversaries may stage data collected from multiple systems in a central location or directory on one system prior to *Exfiltration*. Data may be kept in separate files or combined into one file through techniques such as Archive Collected Data. Interactive command shells may be used, and common functionality within cmd and bash may be used to copy data into a staging location.

In cloud environments, adversaries may stage data within a particular instance or virtual machine before exfiltration. An adversary may Create Cloud Instance and stage data in that instance

By staging data on one system prior to *Exfiltration*, adversaries can minimize the number of connections made to their C2 server and better evade detection

<br>
<hr>

# Email Collection
Emails may contain sensitive data, including trade secrets or personal information, that can prove valuable to adversaries. Adversaries can collect or forward email from mail servers or clients

<br>

## Local Email Collection
Files containing email data can be acquired from a user’s local system, such as Outlook storage or cache files
* Outlook stores data locally in offline data files with an extension of `.ost`
  * Outlook 2010 and later supports .ost file sizes up to 50GB, while earlier versions of Outlook support up to 20GB
  * IMAP accounts in Outlook 2013 (and earlier) and POP accounts use Outlook Data Files (.pst) as opposed to .ost, whereas IMAP accounts in Outlook 2016 (and later) use .ost files
* Both types of Outlook data files are typically stored in
  * `C:\Users\<username>\Documents\Outlook Files`
  * `C:\Users\<username>\AppData\Local\Microsoft\Outlook`

<br>

## Remote Email Collection
Adversaries may leverage a user's credentials and interact directly with the Exchange server to acquire information from within a network
* Adversaries may also access externally facing Exchange services, Office 365, or Google Workspace to access email using credentials or access tokens
* Tools such as **MailSniper** can be used to automate searches for specific keywords

<br>

## Email Forwarding Rule
Adversaries may abuse email-forwarding rules to monitor the activities of a victim, steal information, and further gain intelligence on the victim or the victim’s organization to use as part of further exploits or operations

* Furthermore, email forwarding rules can allow adversaries to maintain persistent access to victim's emails even after compromised credentials are reset by administrators
* Most email clients allow users to create inbox rules for various email functions, including forwarding to a different recipient
  * These rules may be created through a local email application, a web interface, or by CLI
* Messages can be forwarded to internal or external recipients, and there are no restrictions limiting the extent of this rule
* Administrators may also create forwarding rules for user accounts with the same considerations and outcomes

Any user or administrator within the organization (or adversary with valid credentials) can create rules to automatically forward all received messages to another recipient, forward emails to different locations based on the sender, and more
* Adversaries may also hide the rule by making use of the Microsoft Messaging API (MAPI) to modify the rule properties, making it hidden and not visible from Outlook, OWA or most Exchange Administration tools

<br>
<hr>

# Input Capture
During normal system usage, users often provide credentials to various different locations, such as login pages/portals or system dialog boxes
* Input capture mechanisms may be transparent to the user (*Credential API Hooking*) or rely on deceiving the user into providing input into what they believe to be a genuine service (*Web Portal Capture*)

<br>

## Keylogging
**Keylogging** is likely to be used to acquire credentials for new access opportunities when *OS Credential Dumping* efforts are not effective, and may require an adversary to intercept keystrokes on a system for a substantial period of time before credentials can be successfully captured

Keylogging is the most prevalent type of input capture, with many different ways of intercepting keystrokes; **Some methods include:**

* Hooking API callbacks used for processing keystrokes
  * Unlike Credential API Hooking, this focuses solely on API functions intended for processing keystroke data
* Reading raw keystroke data from the hardware buffer
* Windows Registry modifications
* Custom drivers
* *Modify System Image* may provide adversaries with hooks into the operating system of network devices to read raw keystrokes for login sessions

<br>

## GUI Input Capture
When programs are executed that need additional privileges than are present in the current user context, it is common for the operating system to prompt the user for proper credentials to authorize the elevated privileges for the task (*Bypass User Account Control*)

Adversaries may mimic this functionality to prompt users for credentials with a seemingly legitimate prompt for a number of reasons that mimic normal usage, such as a fake installer requiring additional access or a fake malware removal suite
* This type of prompt can be used to collect credentials via various languages such as AppleScript and PowerShell
* On Linux systems adversaries may launch dialog boxes prompting users for credentials from malicious shell scripts or the CLI

<br>

## Web Portal Capture
Adversaries may install code on externally facing portals to capture and transmit credentials of users who attempt to log into the service

This variation on input capture may be conducted post-compromise using legitimate administrative access as a backup measure to maintain network access through *External Remote Services* and *Valid Accounts* or as part of the initial compromise by exploitation of the externally facing web service

<br>

## Credential API Hooking
Malicious hooking mechanisms may capture API calls that include parameters that reveal user authentication credentials
* Unlike Keylogging, this technique focuses specifically on API functions that include parameters that reveal user credentials
* **Hooking involves redirecting calls to these functions and can be implemented via:**

* **Hooks Procedures:** Intercepts and execute designated code in response to events such as messages, keystrokes, and mouse inputs.
* **Import Address Table (IAT) Hooking:** Uses modifications to a process’s IAT, where pointers to imported API functions are stored
* **Inline Hooking:** Overwrites the first bytes in an API function to redirect code flow

<br>
<hr>

# Screen Capture
Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation. Screen capturing functionality may be included as a feature of a remote access tool used in post-compromise operations
* Taking a screenshot is also typically possible through native utilities or API calls, such as `CopyFromScreen`, `xwd`, or `screencapture`

<br>
<hr>

# Video Capture
An adversary can leverage a computer's peripheral devices or applications to capture video recordings for the purpose of gathering information. Images may also be captured from devices or applications, potentially in specified intervals, in lieu of video files

Malware or scripts may be used to interact with the devices through an available API provided by the operating system or an application to capture video or images
* Video or image files may be written to disk and exfiltrated later
  * This technique differs from *Screen Capture* due to use of specific devices or applications for video recording rather than capturing the victim's screen

**In macOS**, there are a few different malware samples that record the user's webcam such as `FruitFly` and `Proton`