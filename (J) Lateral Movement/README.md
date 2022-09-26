# Lateral Movement

Lateral Movement consists of techniques that adversaries use to enter and control remote systems on a network. Following through on their primary objective often requires exploring the network to find their target and subsequently gaining access to it. Reaching their objective often involves pivoting through multiple systems and accounts to gain. Adversaries might install their own remote access tools to accomplish Lateral Movement or use legitimate credentials with native network and operating system tools, which may be stealthier.

<br>
<hr>

# Table of Contents
- [Exploitation of Remote Services](#exploitation-of-remote-services)
- [Internal Spearphishing](#internal-spearphishing)
- [Lateral Tool Transfer](#lateral-tool-transfer)
- [Remote Service Session Hijacking](#remote-service-session-hijacking)
  - [SSH Hijacking](#ssh-hijacking)
  - [RDP Hijacking](#rdp-hijacking)
- [Remote Services](#remote-services)
  - [Remote Desktop Protocol](#remote-desktop-protocol)
  - [SMB / Windows Admin Shares](#smbwindows-admin-shares)
  - [Distributed Component Object Model](#distributed-component-object-model)
  - [SSH](#ssh)
  - [VNC](#vnc)
  - [Windows Remote Management](#windows-remote-management)
- [Replication Through Removable Media](#replication-through-removable-media)
- [Software Deployment Tools](#software-deployment-tools)
- [Taint Shared Content](#taint-shared-content)
- [Use Alternate Authenication Material](#use-alternate-authentication-material)
  - [Application Access Token](#application-access-token)
  - [Pass the Hash](#pass-the-hash)
  - [Pass the Ticket](#pass-the-ticket)
  - [Web Session Cookie](#web-session-cookie)

<br>
<hr>

# Exploitation of Remote Services
**Exploitation:** Occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code

An adversary may need to determine if the remote system is in a vulnerable state, which may be done through *Network Service Discovery* or other Discovery methods looking for common, vulnerable software that may be deployed in the network, the lack of certain patches that may indicate vulnerabilities, or security software that may be used to detect or contain remote exploitation

<br>
<hr>

# Internal Spearphishing
**Internal Spearphishing:** A multi-staged campaign where an email account is owned either by controlling the user's device with previously installed malware or by compromising the account credentials of the user. Adversaries attempt to take advantage of a trusted internal account to increase the likelihood of tricking the target into falling for the phish attempt

Adversaries may leverage *Spearphishing Attachment* or *Spearphishing Link* as part of internal spearphishing to deliver a payload or redirect to an external site to capture credentials through Input Capture on sites that mimic email login interfaces

<br>
<hr>

# Lateral Tool Transfer
Adversaries may transfer tools or other files between systems in a compromised environment. Once brought into the victim environment (Ingress Tool Transfer) files may then be copied from one system to another to stage adversary tools or other files over the course of an operation

Adversaries may copy files between internal victim systems to support lateral movement using inherent file sharing protocols such as file sharing over SMB/Windows Admin Shares to connected network shares or with authenticated connections via RDP

Files can also be transferred using native or otherwise present tools on the victim system, such as scp, rsync, curl, sftp, and ftp

<br>
<hr>

# Remote Service Session Hijacking
Adversaries may take control of preexisting sessions with remote services to move laterally in an environment. Users may use valid credentials to log into a service specifically designed to accept remote connections
* When a user logs into a service, a session will be established that will allow them to maintain a continuous interaction with that service

Adversaries may commandeer these sessions to carry out actions on remote systems
* *Remote Service Session Hijacking* differs from use of *Remote Services* because it hijacks an existing session rather than creating a new session using Valid Accounts

<br>

## SSH Hijacking
SSH: Allows a user to connect to another system via an encrypted tunnel, commonly authenticating through a password, certificate or the use of an asymmetric encryption key pair

Adversaries may take advantage of trust relationships established with other systems via public key authentication in active SSH sessions by hijacking an existing connection to another system
* This may occur through compromising the SSH agent itself or by having access to the agent's socket
* If an adversary is able to obtain root access, then hijacking SSH sessions is likely trivial

**SSH Hijacking** differs from use of **SSH** because it hijacks an existing SSH session rather than creating a new session using Valid Accounts

<br>

## RDP Hijacking
RDP: Allows a user to log into an interactive session with a system desktop graphical user interface on a remote system
* Adversaries may perform RDP session hijacking which involves stealing a legitimate user's remote session
  * Typically, a user is notified when someone else is trying to steal their session
* With System permissions and using Terminal Services Console, c`:\windows\system32\tscon.exe [session number to be stolen]`, an adversary can hijack a session without the need for credentials or prompts to the user
* This can be done remotely or locally and with active or disconnected sessions
  * It can also lead to **Remote System Discovery** and **Privilege Escalation** by stealing a Domain Admin or higher privileged account session
* All of this can be done by using native Windows commands, but it has also been added as a feature in red teaming tools

<br>
<hr>

# Remote Services
Domains provide centralized identity management, allowing users to login using one set of credentials across the entire network
* If an adversary is able to obtain a set of valid domain credentials, they could login to many different machines using remote access protocols SSH or RDP

Legitimate applications (such as *Software Deployment Tools* and other administrative programs) may utilize Remote Services to access remote hosts

* **Apple Remote Desktop (ARD):** macOS native software used for remote management
  * ARD leverages a blend of protocols, including VNC to send the screen and control buffers and SSH for secure file transfer
  * Adversaries can abuse applications such as ARD to gain remote code execution and perform lateral movement
    * In versions of macOS prior to 10.14, an adversary can escalate an SSH session to an ARD session which enables an adversary to accept TCC (Transparency, Consent, and Control) prompts without user interaction and gain access to data

<br>

## Remote Desktop Protocol
**RDP:** Allows a user to log into an interactive session with a system desktop graphical user interface on a remote system

* Adversaries may connect to a remote system over RDP/RDS to expand access if the service is enabled and allows access to accounts with known credentials
* Adversaries will likely use Credential Access techniques to acquire credentials to use with RDP
* Adversaries may also use RDP in conjunction with the Accessibility Features or Terminal Services DLL for Persistence

<br>

## SMB/Windows Admin Shares
**SMB:** A file, printer, and serial port sharing protocol for Windows machines on the same network or domain. Adversaries may use SMB to interact with file shares, allowing them to move laterally throughout a network. Linux and macOS implementations of SMB typically use Samba

Windows systems have hidden network shares that are accessible only to administrators and provide the ability for remote file copy and other administrative functions

* Example network shares include `C$`, `ADMIN$`, and `IPC$`
  * Adversaries may use this technique in conjunction with administrator-level Valid Accounts to remotely access a networked system over SMB, to interact with systems using remote procedure calls (RPCs), transfer files, and run transferred binaries through remote Execution
  * Example execution techniques that rely on authenticated sessions over SMB/RPC are *Scheduled Task/Job*, *Service Execution*, and *Windows Management Instrumentation*
  * Adversaries can also use NTLM hashes to access administrator shares on systems with Pass the Hash and certain configuration and patch levels

<br>

## Distributed Component Object Model
The Windows **Component Object Model (COM):** A component of the native Windows API that enables interaction between software objects, or executable code that implements one or more interfaces

* Through COM, a client object can call methods of server objects, which are typically DLL or EXEs
* **Distributed COM (DCOM):** Transparent middleware that extends the functionality of COM beyond a local computer using remote procedure call (RPC) technology

Permissions to interact with local and remote server COM objects are specified by ACLs in the Registry

Through DCOM, adversaries operating in the context of an appropriately privileged user can remotely obtain arbitrary and even direct shellcode execution through Office applications as well as other Windows objects that contain insecure methods

* DCOM can also execute macros in existing documents and may also invoke **Dynamic Data Exchange (DDE)** execution directly through a COM created instance of a Microsoft Office application, bypassing the need for a malicious document
* DCOM can be used as a method of remotely interacting with Windows Management Instrumentation

<br>

## SSH
**SSH:** Protocol that allows authorized users to open remote shells on other computers
* SSH servers can be configured to use standard password authentication or public-private keypairs in lieu of or in addition to a password
  * The user’s public key must be in a special file on the computer running the server that lists which keypairs are allowed to login as that user

<br>

## VNC
**Virtual Network Computing (VNC:** A platform-independent desktop sharing system that uses the RFB ("remote framebuffer") protocol to enable users to remotely control another computer’s display by relaying the screen, mouse, and keyboard inputs over the network

* **NOTE::** VNC differs from Remote Desktop Protocol as VNC is screen-sharing software rather than resource-sharing software
  * VNC uses the system's authentication, but it can be configured to use credentials specific to VNC 

Adversaries may abuse VNC to perform malicious actions as the logged-on user such as opening documents, downloading files, and running arbitrary commands

* An adversary could use VNC to remotely control and monitor a system to collect data and information to pivot to other systems within the network
* Specific VNC libraries/implementations have also been susceptible to brute force attacks and memory usage exploitation

<br>

## Windows Remote Management
**WinRM:** Windows service / protocol that allows a user to interact with a remote system (e.g., run an executable, modify the Registry, modify services)
* It may be called with the `winrm` command or by any number of programs such as PowerShell
* WinRM can be used as a method of remotely interacting with Windows Management Instrumentation

<br>
<hr>

# Replication Through Removable Media
Adversaries may move onto systems, possibly those on disconnected or air-gapped networks, by copying malware to removable media and taking advantage of **Autorun** features when the media is inserted into a system and executes

* *Lateral Movement* may occur through modification of executable files stored on removable media or by copying malware and renaming it to look like a legitimate file to trick users into executing it on a separate system
  
* *Initial Access* may occur through manual manipulation of the media, modification of systems used to initially format the media, or modification to the media's firmware itself

<br>
<hr>

# Software Deployment Tools
Third-party applications and software deployment systems may be in use in the network environment for administration purposes (e.g., SCCM, HBSS, Altiris, etc.)

* Access to a third-party network-wide or enterprise-wide software system may enable an adversary to have remote code execution on all systems that are connected to such a system
* The access may be used to laterally move to other systems, gather information, or cause a specific effect, such as wiping the hard drives on all endpoints

<br>
<hr>

# Taint Shared Content
Adversaries may deliver payloads to remote systems by adding content to shared storage locations, such as network drives or internal code repositories

* Content stored on network drives or in other shared locations may be tainted by adding malicious programs, scripts, or exploit code to otherwise valid files
  * Once a user opens the shared tainted content, the malicious portion can be executed to run the adversary's code on a remote system
  * Adversaries may use tainted shared content to move laterally

A directory share pivot is a variation on this technique that uses several other techniques to propagate malware when users access a shared network directory
* Uses *Shortcut Modification* of directory `.LNK` files that use *Masquerading* to look like the real directories, which are hidden through *Hidden Files and Directories*
* The malicious .LNK-based directories have an embedded command that executes the hidden malware file in the directory and then opens the real intended directory so that the user's expected action still occurs
  * When used with frequently used network directories, the technique may result in frequent reinfections and broad access to systems and potentially to new and higher privileged accounts

Adversaries may also compromise shared network directories through binary infections by appending or prepending its code to the healthy binary on the shared network directory
* The malware may modify the **original entry point (OEP)** of the healthy binary to ensure that it is executed before the legitimate code
  * The infection could continue to spread via the newly infected file when it is executed by a remote system
  * These infections may target both binary and non-binary formats that end with extensions (.EXE, .DLL, .SCR, .BAT, .VBS, etc.)

<br>
<hr>

# Use Alternate Authentication Material
Authentication processes generally require a valid identity (e.g., username) along with one or more authentication factors (e.g., password, pin, physical smart card, token generator, etc.)
* Alternate authentication material is legitimately generated by systems after a user or application successfully authenticates by providing a valid identity and the required authentication factor(s)
* Alternate authentication material may also be generated during the identity creation process 

Caching alternate authentication material allows the system to verify an identity has successfully authenticated without asking the user to reenter authentication factor(s)
* Because the alternate authentication must be maintained by the system—either in memory or on disk—it may be at risk of being stolen through Credential Access techniques
* By stealing alternate authentication material, adversaries are able to bypass system access controls and authenticate to systems without knowing the plaintext password or any additional authentication factors

<br>

## Application Access Token
Application access tokens are used to make authorized API requests on behalf of a user or service and are commonly used as a way to access resources in cloud and container-based applications and SaaS



### AWS and GCP environments
Adversaries can trigger a request for a short-lived access token with the privileges of another user account
* The adversary can then use this token to request data or perform actions the original account could not
* If permissions for this feature are misconfigured – for example, by allowing all users to request a token for a particular account - an adversary may be able to gain initial access to a Cloud Account or escalate their privileges

### OAuth
One commonly implemented framework that issues tokens to users for access to systems
* These frameworks are used collaboratively to verify the user and determine what actions the user is allowed to perform
* Once identity is established, the token allows actions to be authorized, without passing the actual credentials of the user
* Therefore, compromise of the token can grant the adversary access to resources of other sites through a malicious application

### Example
With a cloud-based email service, once an OAuth access token is granted to a malicious application, it can potentially gain long-term access to features of the user account if a "refresh" token enabling background access is awarded
* With an OAuth access token an adversary can use the user-granted REST API to perform functions such as email searching and contact enumeration

Compromised access tokens may be used as an initial step in compromising other services
* If a token grants access to a victim’s primary email, the adversary may be able to extend access to all other services which the target subscribes by triggering forgotten password routines
* Direct API access through a token negates the effectiveness of a second authentication factor and may be immune to intuitive countermeasures like changing passwords
* Access abuse over an API channel can be difficult to detect even from the service provider end, as the access can still align well with a legitimate workflow

<br>

## Pass the Hash
**Pass the hash (PTH):** A method of authenticating as a user without having access to the user's cleartext password
* This method bypasses standard authentication steps that require a cleartext password, moving directly into the portion of the authentication that uses the password hash

When performing PTH, valid password hashes for the account being used are captured using a Credential Access technique
* Captured hashes are used with PTH to authenticate as that user
* Once authenticated, PTH may be used to perform actions on local or remote systems

Adversaries may also use stolen password hashes to "Overpass the Hash (OTH)"
* Similar to PTH, this involves using a password hash to authenticate as a user but also uses the password hash to create a valid Kerberos ticket
  * This ticket can then be used to perform Pass the Ticket (PTT) attacks

<br>

## Pass the Ticket 
**Pass the ticket (PTH):** A method of authenticating to a system using Kerberos tickets without having access to an account's password -- Kerberos authentication can be used as the first step to lateral movement to a remote system

When preforming PTH, valid Kerberos tickets for Valid Accounts are captured by OS Credential Dumping
* A user's service tickets or ticket granting ticket (TGT) may be obtained, depending on the level of access
* A service ticket allows for access to a particular resource, whereas a TGT can be used to request service tickets from the Ticket Granting Service (TGS) to access any resource the user has privileges to access

A **Silver Ticket** can be obtained for services that use Kerberos as an authentication mechanism and are used to generate tickets to access that particular resource and the system that hosts the resource (e.g., SharePoint)

A **Golden Ticket** can be obtained for the domain using the Key Distribution Service account KRBTGT account NTLM hash, which enables generation of TGTs for any account in AD

Adversaries may also create a valid Kerberos ticket using other user information, such as stolen password hashes or AES keys
* For example, OTH involves using a NTLM password hash to authenticate as a user (i.e. Pass the Hash) while also using the password hash to create a valid Kerberos ticket

<br>

## Web Session Cookie
Adversaries can use stolen session cookies to authenticate to web applications and services -- This technique bypasses some multi-factor authentication protocols since the session is already authenticated

Authentication cookies are commonly used in web applications, including cloud-based services, after a user has authenticated to the service so credentials are not passed and re-authentication does not need to occur as frequently
* Cookies are often valid for an extended period of time, even if the web application is not actively used
* After the cookie is obtained through Steal Web Session Cookie or Web Cookies, the adversary may then import the cookie into a browser they control and is then able to use the site or application as the user for as long as the session cookie is active