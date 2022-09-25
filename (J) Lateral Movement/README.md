# Lateral Movement

Lateral Movement consists of techniques that adversaries use to enter and control remote systems on a network. Following through on their primary objective often requires exploring the network to find their target and subsequently gaining access to it. Reaching their objective often involves pivoting through multiple systems and accounts to gain. Adversaries might install their own remote access tools to accomplish Lateral Movement or use legitimate credentials with native network and operating system tools, which may be stealthier.


<hr>
Table of Contents

- [Exploitation of Remote Services](#exploitation-of-remote-services)
- [Internal Spearphishing](#internal-spearphishing)
- [Lateral Tool Transfer](#lateral-tool-transfer)
- [Remote Service Session Hijacking](#remote-service-session-hijacking)
- [Remote Services](#remote-services)
- [Replication Through Removable Media](#replication-through-removable-media)
- [Software Deployment Tools](#software-deployment-tools)
- [Taint Shared Content](#taint-shared-content)
- [Use Alternate Authenication Material](#use-alternate-authentication-material)

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
  
* Initial Access may occur through manual manipulation of the media, modification of systems used to initially format the media, or modification to the media's firmware itself
<hr>

# Software Deployment Tools

<hr>

# Taint Shared Content

<hr>

# Use Alternate Authentication Material

