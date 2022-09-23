# Defense Evasion
Defense Evasion consists of techniques that adversaries use to avoid detection throughout their compromise. Techniques used for defense evasion include uninstalling/disabling security software or obfuscating/encrypting data and scripts. Adversaries also leverage and abuse trusted processes to hide and masquerade their malware. Other tactics’ techniques are cross-listed here when those techniques include the added benefit of subverting defenses.


<hr>

# Table of Contents 
- [Abuse Elevation Control Mechanism](#abuse-elevation-control-mechanism)
- [Access Token Manipulation](#access-token-manipulation)
- [BITS Jobs](#bits-jobs)
- [Build Image on Host](#build-image-on-host)
- [Debugger Evasion](#debugger-evasion)
- [Deobfuscate/Decode Files or Information](#deobfuscatedecode-files-or-information)
- [Deploy Container](#deploy-container)
- [Direct Volume Access](#direct-volume-access)
- [Domain Policy Modification](#domain-policy-modification)
- [Execution Guardrails](#execution-guardrails)
- [Exploitation for Defense Evasion](#exploitation-for-defense-evasion)
- [File and Directory Permissions Modification](#file-and-directory-permissions-modification)
- [Hide Artifacts](#hide-artifacts)
- [Hijack Execution Flow](#hijack-execution-flow)
- [Impair Defenses](#impair-defenses)
- [Indicator Removal on Host](#indicator-removal-on-host)
- [Indirect Command Execution](#indirect-command-execution)
- [Masquerading](#masquerading)
- [Modify Authenication Process](#modify-authentication-process)
- [Modify Cloud Compute Infrastructure](#modify-cloud-compute-infrastructure)
- [Modify Registry](#modify-registry)
- [Modify System Image](#modify-system-image)
- [Network Boundary Bridging](#network-boundary-bridging)
- [Obfuscated Files or Information](#obfuscated-files-or-information)
- [Plist File Modification](#plist-file-modification)
- [Pre-OS Boot](#pre-os-boot)
- [Reflective Code Loading](#reflective-code-loading)
- [Rogue Domain Controller](#rogue-domain-controller)
- [Rootkit](#rootkit)
- [Subvert Trust Controls](#subvert-trust-controls)
- [System Binary Proxy Execution](#system-binary-proxy-execution)
- [System Script Proxy Execution](#system-script-proxy-execution)
- [Template Injection](#template-injection)
- [Traffic Signaling](#traffic-signaling)
- [Trusted Developer Utilities Proxy Execution](#trusted-developer-utilities-proxy-execution)
- [Unused/Unsupported Cloud Regions](#unusedunsupported-cloud-regions)
- [Use Alternate Authentication Material](#use-alternate-authentication-material)
- [Valid Accounts](#valid-accounts)
- [Virtualization/Sandbox Evasion](#virtualizationsandbox-evasion)
- [Weaken Encryption](#weaken-encryption)
- [XSL Script Processing](#xsl-script-processing

<br>

<hr>

# Abuse Elevation Control Mechanism
Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions. Most modern systems contain native elevation control mechanisms that are intended to limit privileges that a user can perform on a machine. Authorization has to be granted to specific users in order to perform tasks that can be considered of higher risk. An adversary can perform several methods to take advantage of built-in control mechanisms in order to escalate privileges on a system.

<br>


## Setuid and Setgid
An adversary may abuse configurations where an application has the setuid or setgid bits set in order to get code running in a different (and possibly more privileged) user’s context

**Linux / macOS**
When the setuid or setgid bits are set for an application binary, the application will run with the privileges of the owning user or group respectively. Normally an application is run in the current user’s context, regardless of which user or group owns the application. However, there are instances where programs need to be executed in an elevated context to function properly, but the user running them may not have the specific required privileges

Instead of creating an entry in the sudoers file, which must be done by root, any user can specify the setuid or setgid flag to be set for their own applications
  * `chmod` can set these bits with bitmasking
    * Enable the setuid: `chmod 4777 [file]` or `chmod u+s [file]` 
  * Enable the setgit bit: `chmod 2775` and `chmod g+s` 

**Note:** This abuse is often part of a "shell escape" or other actions to bypass an execution environment with restricted permissions

Adversaries may choose to find and target vulnerable binaries with the setuid or setgid bits already enabled
* The setuid and setguid bits are indicated with an "s" instead of an "x" when viewing a file's attributes via `ls -l`
* `find` command can also be used to search for such files
  * `find / -perm +4000 2>/dev/null`: Find files w/ setuid set
  * `find / -perm +2000 2>/dev/null`: Find files w/ setgid set

<br>


## Bypass User Account Control
Windows UAC allows a program to elevate its privileges to perform a task under administrator-level permissions, possibly by prompting the user for confirmation

If the UAC protection level of a computer is set to anything but the highest level, certain Windows programs can elevate privileges or execute some elevated Component Object Model objects without prompting the user through the UAC notification box
* The use of Rundll32 to load a specifically crafted DLL which loads an auto-elevated Component Object Model object and performs a file operation in a protected directory which would typically require elevated access


Additional bypass methods are regularly discovered and some used in the wild, such as:
* **eventvwr.exe** can auto-elevate and execute a specified binary or script

<br>


## Sudo and Sudo Caching


Adversaries perform sudo caching and/or use the sudoers file to elevate privileges to execute commands as other users or spawn processes with higher privileges

**UNIX**
**sudo:** Allows users to perform commands from terminals with elevated privileges and to control who can perform these commands on the system
* `timestamp_timeout`: The amount of time in minutes between instances of sudo before it will re-prompt for a password
  * sudo has the ability to cache credentials for a period of time
  * sudo creates a file at `/var/db/sudo` with a timestamp of when sudo was last run to determine this timeout
  * Additionally, there is a `tty_tickets` variable that treats each new tty (terminal session) in isolation


The sudoers file (`/etc/sudoers`) describes which users can run which commands and from which terminals and which commands users can run as other users or groups
* The sudoers file can also specify when to not prompt users for passwords with a line like `user1 ALL=(ALL) NOPASSWD: ALL`

Adversaries can abuse poor configurations of these mechanisms to escalate privileges without needing the user's password
* `/var/db/sudo's timestamp` can be monitored to see if it falls within the *timestamp_timeout* range
  * If it does, then malware can execute sudo commands without needing to supply the user's password
  * If *tty_tickets* is disabled, adversaries can do this from any tty for that user


<br>


## Elevated Execution with Prompt
Adversaries may leverage the *AuthorizationExecuteWithPrivileges* API to escalate privileges by prompting the user for credentials. The purpose of this API is to give application developers an easy way to perform operations with root privileges, such as for application installation or updating. This API does not validate that the program requesting root privileges comes from a reputable source or has been maliciously modified.

Although this API is deprecated, it still fully functions in the latest releases of macOS. When calling this API, the user will be prompted to enter their credentials but no checks on the origin or integrity of the program are made. The program calling the API may also load world writable files which can be modified to perform malicious behavior with elevated privileges.

Adversaries may abuse *AuthorizationExecuteWithPrivileges* to obtain root privileges in order to install malicious software on victims and install persistence mechanisms
* This technique may be combined with Masquerading to trick the user into granting escalated privileges to malicious code
* This technique has also been shown to work by modifying legitimate programs present on the machine that make use of this API

<br>
<hr>

# Access Token Manipulation
Windows uses access tokens to determine the ownership of a running process. A user can manipulate access tokens to make a running process appear as though it is the child of a different process or belongs to someone other than the user that started the process. When this occurs, the process also takes on the security context associated with the new token.



An adversary can use built-in Windows API functions to copy access tokens from existing processes (Token Stealing)
* These token can then be applied to an existing process (Token Impersonation) or used to spawn a new process (Create Process with Token)

Any standard user can use the `runas` command, and the Windows API functions, to create impersonation tokens; it does not require access to an administrator account. There are also other mechanisms, such as Active Directory fields, that can be used to modify access tokens


<br>


## Token Impersonation/Theft
An adversary can create a new access token that duplicates an existing token using *DuplicateToken(Ex)*
* The token can then be used with *ImpersonateLoggedOnUser* to allow the calling thread to impersonate a logged on user's security context, or with *SetThreadToken* to assign the impersonated token to a thread

An adversary may do this when they have a specific, existing process they want to assign the new token to
* This may be useful for when the target user has a non-network logon session on the system

<br>


## Create Process with Token
Processes can be created with the token and resulting security context of another user using features such as *CreateProcessWithTokenW* and *runas*

Creating processes with a different token may require the credentials of the target user, specific privileges to impersonate that user, or access to the token to be used (ex: gathered via other means such as *Token Impersonation* or *Make and Impersonate Token*).

<br>


## Make and Impersonate Token
If an adversary has a username and password but the user is not logged onto the system, the adversary can then create a logon session for the user using the *LogonUser* function. The function will return a copy of the new session's access token and the adversary can use SetThreadToken to assign the token to a thread

<br>


## Parent PID Spoofing
New processes are typically spawned directly from their parent, or calling, process unless explicitly specified
* One way of explicitly assigning the PPID of a new process is via the `CreateProcess` API call, which supports a parameter that defines the PPID to use
  * This functionality is used by Windows features such as the UAC to correctly set the PPID after a requested elevated process is spawned by SYSTEM (typically via svchost.exe or consent.exe) rather than the current user context
 

Adversaries may abuse these mechanisms to evade defenses, such as those blocking processes spawning directly from Office documents, and analysis targeting unusual/potentially malicious parent-child process relationships, such as spoofing the PPID of PowerShell/Rundll32 to be explorer.exe rather than an Office document delivered as part of Spearphishing Attachment
* This spoofing could be executed via Visual Basic within a malicious Office document or any code that can perform Native API

Explicitly assigning the PPID may also enable elevated privileges given appropriate access rights to the parent process
* An adversary in a privileged user context (i.e. administrator) may spawn a new process and assign the parent as a process running as SYSTEM (such as lsass.exe), causing the new process to be elevated via the inherited access token

<br>


## SID-History Injection
**Windows security identifier (SID):** A unique value that identifies a user or group account
* SIDs are used by Windows security in both security descriptors and access tokens
  * An account can hold additional SIDs in the SID-History Active Directory attribute, allowing inter-operable account migration between domains (e.g., all values in SID-History are included in access tokens)

With Domain Administrator rights, harvested or well-known SID values may be inserted into SID-History to enable impersonation of arbitrary users/groups such as Enterprise Administrators
* This manipulation may result in elevated access to local resources and/or access to otherwise inaccessible domains via lateral movement techniques such as Remote Services, SMB/Windows Admin Shares, or Windows Remote Management

<br>
<hr>

# BITS Jobs
**Background Intelligent Transfer Service (BITS)::** A low-bandwidth, asynchronous file transfer mechanism exposed through Component Object Model (COM)
* BITS is commonly used by updaters, messengers, and other applications preferred to operate in the background (using available idle bandwidth) without interrupting other networked applications. File transfer tasks are implemented as BITS jobs, which contain a queue of one or more file operations.

The interface to create and manage BITS jobs is accessible through PowerShell and the BITSAdmin tool

Adversaries may abuse BITS to download, execute, and even clean up after running malicious code. BITS tasks are self-contained in the BITS job database, without new files or registry modifications, and often permitted by host firewalls. BITS enabled execution may also enable persistence by creating long-standing jobs (the default maximum lifetime is 90 days and extendable) or invoking an arbitrary program when a job completes or errors (including after system reboots)

BITS upload functionalities can also be used to perform Exfiltration Over Alternative Protocol

<br>
<hr>

# Build Image on Host
Adversaries may build a container image directly on a host to bypass defenses that monitor for the retrieval of malicious images from a public registry. A remote build request may be sent to the Docker API that includes a Dockerfile that pulls a vanilla base image, such as alpine, from a public or local registry and then builds a custom image upon it.

An adversary may take advantage of that build API to build a custom image on the host that includes malware downloaded from their C2 server, and then they then may utilize Deploy Container using that custom image
* If the base image is pulled from a public registry, defenses will likely not detect the image as malicious since it’s a vanilla image
* If the base image already resides in a local registry, the pull may be considered even less suspicious since the image is already in the environment

<br>
<hr>

# Debugger Evasion
Debuggers are typically used by defenders to trace and/or analyze the execution of potential malware payloads

Debugger evasion may include changing behaviors based on the results of the checks for the presence of artifacts indicative of a debugged environment
* Similar to Virtualization/Sandbox Evasion, if the adversary detects a debugger, they may alter their malware to disengage from the victim or conceal the core functions of the implant
* They may also search for debugger artifacts before dropping secondary or additional payloads

Specific checks will vary based on the target and/or adversary, but may involve Native API function calls such as `IsDebuggerPresent()` and `NtQueryInformationProcess()`, or manually checking the `BeingDebugged` flag of the Process Environment Block (PEB)
* Other checks for debugging artifacts may also seek to enumerate hardware breakpoints, interrupt assembly opcodes, time checks, or measurements if exceptions are raised in the current process (assuming a present debugger would "swallow" or handle the potential error)

Adversaries may use the information learned from these debugger checks during automated discovery to shape follow-on behaviors. Debuggers can also be evaded by detaching the process or flooding debug logs with meaningless data via messages produced by looping Native API function calls such as `OutputDebugStringW()`

<br>
<hr>

# Deobfuscate/Decode Files or Information
Adversaries may use obfuscated files or information to hide artifacts of an intrusion from analysis. They may require separate mechanisms to decode or deobfuscate that information depending on how they intend to use it. Methods for doing that include built-in functionality of malware or by using utilities present on the system.

One such example is use of `certutil` to decode a remote access tool portable executable file that has been hidden inside a certificate file
* Another example is using the Windows `copy /b` command to reassemble binary fragments into a malicious payload


Sometimes a user's action may be required to open it for deobfuscation or decryption as part of User Execution. The user may also be required to input a password to open a password protected compressed/encrypted file that was provided by the adversary

<br>
<hr>


# Deploy Container
Adversaries may deploy a container into an environment to facilitate execution or evade defenses. In some cases, adversaries may deploy a new container to execute processes associated with a particular image or deployment, such as processes that execute or download malware
* In others, an adversary may deploy a new container configured without network rules, user limitations, etc. to bypass existing defenses within the environment

Containers can be deployed by various means, such as via Docker's create and start APIs or via a web application such as the Kubernetes dashboard or Kubeflow
* Adversaries may deploy containers based on retrieved or built malicious images or from benign images that download and execute malicious payloads at runtime

<br>
<hr>


# Direct Volume Access
Adversaries may directly access a volume to bypass file access controls and file system monitoring. Windows allows programs to have direct access to logical volumes. Programs with direct access may read and write files directly from the drive by analyzing file system data structures. This technique bypasses Windows file access controls as well as file system monitoring tools

Utilities, such as NinjaCopy, exist to perform these actions in PowerShell

<br>
<hr>


# Domain Policy Modification
Domains provide a centralized means of managing how computer resources can act, and interact with each other, on a network. The policy of the domain also includes configuration settings that may apply between domains in a multi-domain/forest environment. Modifications to domain settings may include altering domain Group Policy Objects (GPOs) or changing trust settings for domains, including federation trusts.

With sufficient permissions, adversaries can modify domain policy settings. Since domain configuration settings control many of the interactions within the Active Directory (AD) environment, there are a great number of potential attacks that can stem from this abuse. Adversaries can also change configuration settings within the AD environment to implement a Rogue Domain Controller.

Adversaries may temporarily modify domain policy, carry out a malicious action(s), and then revert the change to remove suspicious indicators.


<br>


## Group Policy Modification
Group policy allows for centralized management of user and computer settings in AD
* GPOs are containers for group policy settings made up of files stored within a predicable network path `\<DOMAIN>\SYSVOL\<DOMAIN>\Policies\`
  * GPOs have access controls associated with them; Its possible to delegate GPO access control permissions, e.g. write access, to specific users or groups in the domain.

Malicious GPO modifications can be used to implement many other malicious behaviors such as Scheduled Task/Job, Disable or Modify Tools, Ingress Tool Transfer, Create Account, Service Execution, and more. 

Publicly available scripts such as `New-GPOImmediateTask` can be leveraged to automate the creation of a malicious Scheduled Task/Job by modifying GPO settings, in this case modifying `<GPO_PATH>\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml`
* An adversary might modify specific user rights like `SeEnableDelegationPrivilege`, set in `<GPO_PATH>\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf`, to achieve a subtle AD backdoor with complete control of the domain because the user account under the adversary's control would then be able to modify GPOs

<br>


## Domain Trust Modification
Adversaries may add new domain trusts or modify the properties of existing domain trusts to evade defenses and/or elevate privileges. Domain trust details, such as whether or not a domain is federated, allow authentication and authorization properties to apply between domains for the purpose of accessing shared resources. These trust objects may include accounts, credentials, and other authentication material applied to servers, tokens, and domains.

Manipulating the domain trusts may allow an adversary to escalate privileges and/or evade defenses by modifying settings to add objects which they control. For example, this may be used to forge SAML Tokens, without the need to compromise the signing certificate to forge new credentials. Instead, an adversary can manipulate domain trusts to add their own signing certificate.


<br>
<hr>


# Execution Guardrails
Guardrails ensure that a payload only executes against an intended target and reduces collateral damage from an adversary’s campaign. Adversaries may use execution guardrails to constrain execution or actions based on adversary supplied and environment specific conditions that are expected to be present on the target. Values an adversary can provide about a target system or environment to use as guardrails may include specific network share names, attached physical devices, files, joined Active Directory (AD) domains, and local/external IP addresses

Guardrails can be used to prevent exposure of capabilities in environments that are not intended to be compromised or operated within. This use of guardrails is distinct from typical Virtualization/Sandbox Evasion
* While use of Virtualization/Sandbox Evasion may involve checking for known sandbox values and continuing with execution only if there is no match, the use of guardrails will involve checking for an expected target-specific value and only continuing with execution if there is such a match
<br>

## Environmental Keying
**Environmental Keying:** An implementation of *Execution Guardrails* that utilizes cryptographic techniques for deriving encryption/decryption keys from specific types of values in a given computing environment
* Environmental keying uses cryptography to constrain execution or actions based on adversary supplied environment specific conditions that are expected to be present on the target

Adversaries may environmentally key payloads or other features of malware to evade defenses and constraint execution to a specific target environment. 

Values can be derived from target-specific elements and used to generate a decryption key for an encrypted payload. Target-specific values can be derived from specific network shares, physical devices, software/software versions, files, joined AD domains, system time, and local/external IP addresses
* By generating the decryption keys from target-specific environmental values, environmental keying can make sandbox detection, anti-virus detection, crowdsourcing of information, and reverse engineering difficult
  * These difficulties can slow down the incident response process and help adversaries hide their TTPs


<br>
<hr>


# Exploitation for Defense Evasion
Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Vulnerabilities may exist in defensive security software that can be used to disable or circumvent them.

Adversaries may have prior knowledge through reconnaissance that security software exists within an environment or they may perform checks during or shortly after the system is compromised for Security Software Discovery
* The security software will likely be targeted directly for exploitation
<br>
<hr>


# File and Directory Permissions Modification
File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with the appropriate permissions
* File and directory ACL implementations vary by platform, but generally explicitly designate which users or groups can perform which actions

Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files
* Modifications may include changing specific access rights, which may require taking ownership of a file or directory and/or elevated permissions depending on the file or directory’s existing permissions
* This may enable malicious activity such as modifying, replacing, or deleting specific files or directories
* Specific file and directory modifications may be a required step for many techniques, such as establishing Persistence via Accessibility Features, Boot or Logon Initialization Scripts, Unix Shell Configuration Modification, or tainting/hijacking other instrumental binary/configuration files via Hijack Execution Flow
  
<br>

## Windows File and Directory Permissions Modification
Windows implements file and directory ACLs as Discretionary Access Control Lists (DACLs). DACLs identifies the accounts that are allowed or denied access to a securable object
* When an attempt is made to access a securable object, the system checks the access control entries in the DACL in order; If a matching entry is found, access to the object is granted. Otherwise, access is denied.

Adversaries can interact with the DACLs using built-in Windows commands, such as `icacls, cacls, takeown, and attrib`, which can grant adversaries higher permissions on specific files and folders
* PowerShell provides cmdlets that can be used to retrieve or modify file and directory DACLs
  * Specific file and directory modifications may be a required step for many techniques, such as establishing Persistence via Accessibility Features, Boot or Logon Initialization Scripts, or tainting/hijacking other instrumental binary/configuration files via Hijack Execution Flow
<br>

## Linux and Mac File and Directory Permissions Modification
Most Linux and Linux-based platforms provide a standard set of permission groups and a standard set of permissions that are applied to each group
* Most platforms provide two primary commands used to manipulate file and directory ACLs: `chown` (change owner) and `chmod` (change mode)

Adversarial may use these commands to make themselves the owner of files and directories or change the mode if current permissions allow it
* They could subsequently lock others out of the file
* Specific file and directory modifications may be a required step for many techniques, such as establishing Persistence via Unix Shell Configuration Modification or tainting/hijacking other instrumental binary/configuration files via Hijack Execution Flow
<br>

<hr>

# Hide Artifacts
Adversaries may attempt to hide artifacts associated with their behaviors to evade detection. Operating systems may have features to hide various artifacts, such as important system files and administrative task execution, to avoid disrupting user work environments and prevent users from changing files or features on the system. Adversaries may abuse these features to hide artifacts such as files, directories, user accounts, or other system activity to evade detection

Adversaries may also attempt to hide artifacts associated with malicious behavior by creating computing regions that are isolated from common security instrumentation, such as through the use of virtualization technology
<br>

## Hidden Files and Directories
 To prevent normal users from accidentally changing special files on a system, most operating systems have the concept of a ‘hidden’ file. These files don’t show up when a user browses the file system with a GUI or when using normal commands on the command line. Users must explicitly ask to show the hidden files either via a series of Graphical User Interface (GUI) prompts or with command line switches (`dir /a` for Windows and `ls –a` for Linux and macOS)

**Linux and Mac**
Users can mark specific files as hidden simply by putting a "`.`" as the first character in the file or folder name. Files and folders that start with a period are by default hidden from being viewed in the Finder application and standard command-line utilities like "ls". Users must specifically change settings to have these files viewable.

Files on macOS can also be marked with the `UF_HIDDEN` flag which prevents them from being seen in Finder.app, but still allows them to be seen in Terminal.app

**Windows**
Users can mark specific files as hidden by using the `attrib.exe` binary. Many applications create these hidden files and folders to store information so that it doesn’t clutter up the user’s workspace. For example, SSH utilities create a .ssh folder that’s hidden and contains the user’s known hosts and keys

Adversaries can use this to their advantage to hide files and folders anywhere on the system and evading a typical user or system analysis that does not incorporate investigation of hidden files

<br>

## Hidden Users
Adversaries may use hidden users to hide the presence of user accounts they create or modify. Administrators may want to hide users when there are many user accounts on a given system or if they want to hide their administrative or other management accounts from other users.

**macOS**
Attackers can create or modify a user to be hidden through manipulating plist files, folder attributes, and user attributes
* To prevent a user from being shown on the login screen and in System Preferences
*   Set the userID to be under 500 and set the key value `Hide500Users` to TRUE in the `/Library/Preferences/com.apple.loginwindow` plist file
  
Every user has a userID associated with it. When the `Hide500Users` key value is set to TRUE, users with a userID under 500 do not appear on the login screen and in System Preferences
* Using CLI, adversaries can use the *dscl* utility to create hidden user accounts by setting the `IsHidden` attribute to 1
* Adversaries can also hide a user’s home folder by changing the `chflags` to hidden

**Windows**
**Hide user accounts** 
* Set the `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList` Registry key value to 0 for a specific user to prevent that user from being listed on the logon screen

**Linux**
**Hide user accounts from the login screen (referred to as the greeter)**
* The method an adversary may use depends on which Display Manager the distribution is currently using
  * On an Ubuntu system using the GNOME Display Manger (GDM), accounts may be hidden from the greeter using the gsettings command (ex: `sudo -u gdm gsettings set org.gnome.login-screen disable-user-list true`)
  * **Note:** Display Managers are not anchored to specific distributions and may be changed by a user or adversary
<br>

## Hidden Window
In some cases, windows that would typically be displayed when an application carries out an operation can be hidden. This may be utilized by system administrators to avoid disrupting user work environments when carrying out administrative tasks

**Windows**
There are a variety of features in scripting languages in Windows, such as PowerShell, Jscript, and Visual Basic to make windows hidden
* `powershell.exe -WindowStyle Hidden`

**macOS**
The configurations for how applications run are listed in property list (plist) files
* One of the tags in these files can be `apple.awt.UIElement`, which allows for Java applications to prevent the application's icon from appearing in the Dock
* A common use for this is when applications run in the system tray, but don't also want to show up in the Dock
<br>

## NTFS File Attributes
Every NTFS formatted partition contains a Master File Table (MFT) that maintains a record for every file/directory on the partition. Within MFT entries are file attributes, such as Extended Attributes (EA) and Data [known as Alternate Data Streams (ADSs) when more than one Data attribute is present], that can be used to store arbitrary data (and even complete files).

Adversaries may store malicious data or binaries in file attribute metadata instead of directly in files. This may be done to evade some defenses, such as static indicator scanning tools and anti-virus
<br>

## Hidden File System
File systems provide a structure to store and access data from physical storage. Typically, a user engages with a file system through applications that allow them to access files and directories, which are an abstraction from their physical location (ex: disk sector). File systems can also contain other structures, such as the Volume Boot Record (VBR) and Master File Table (MFT) in NTFS

Adversaries may use a hidden file system to conceal malicious activity from users and security tools. 

Adversaries may use their own abstracted file system, separate from the standard file system present on the infected system
* Adversaries can hide the presence of malicious components and file I/O from security tools. Hidden file systems (virtual file systems), can be implemented in numerous ways
  * Store a file system in reserved disk space unused by disk structures or standard file system partitions
  * Drop your own portable partition image as a file on top of the standard file system
  * Fragment files across the existing file system structure in non-standard ways
<br>

## Run Virtual Instance
By running malicious code inside of a virtual instance, adversaries can hide artifacts associated with their behavior from security tools that are unable to monitor activity inside the virtual instance. Additionally, depending on the virtual networking implementation (ex: bridged adapter), network traffic generated by the virtual instance can be difficult to trace back to the compromised host as the IP address and hostname might not match known values

Adversaries may utilize native support for virtualization (ex: Hyper-V) or drop the necessary files to run a virtual instance (ex: VirtualBox binaries)
* After running a virtual instance, adversaries may create a shared folder between the guest and host with permissions that enable the virtual instance to interact with the host file system
<br>

## VBA Stomping
MS Office documents with embedded VBA content store source code inside of module streams. Each module stream has a *PerformanceCache* that stores a separate compiled version of the VBA source code known as p-code. The p-code is executed when the MS Office version specified in the *_VBA_PROJECT* stream (which contains the version-dependent description of the VBA project) matches the version of the host MS Office application

An adversary may hide malicious VBA code by overwriting the VBA source code location with zero’s, benign code, or random bytes while leaving the previously compiled malicious p-code
* Tools that scan for malicious VBA source code may be bypassed as the unwanted code is hidden in the compiled p-code
* If the VBA source code is removed, some tools might even think that there are no macros present
* If there is a version match between the *_VBA_PROJECT* stream and host MS Office application, the p-code will be executed, otherwise the benign VBA source code will be decompressed and recompiled to p-code, thus removing malicious p-code and potentially bypassing dynamic analysis
<br>

## Email Hiding Rules
Many email clients allow users to create inbox rules for various email functions. Rules may be created or modified within email clients or through external features such as the `New-InboxRule` or `Set-InboxRule` PowerShell cmdlets on Windows systems

Adversaries may utilize email rules within a compromised user's mailbox to delete and/or move emails to less noticeable folders
* Adversaries may do this to hide security alerts, C2 communication, or responses to Internal Spearphishing emails sent from the compromised account.

Any user or administrator within the organization (or adversary with valid credentials) may be able to create rules to automatically move or delete emails
* These rules can be abused to impair/delay detection had the email content been immediately seen by a user or defender
* Malicious rules commonly filter out emails based on key words (such as malware, suspicious, phish, and hack) found in message bodies and subject lines
<br>

## Resource Forking
**Resource forks:** Provides applications a structured way to store resources such as thumbnail images, menu definitions, icons, dialog boxes, and code. Usage of a resource fork is identifiable when displaying a file’s extended attributes, using `ls -l@` or `xattr -l` commands
* **Note:** Resource forks have been deprecated and replaced with the application bundle structure; Non-localized resources are placed at the top level directory of an application bundle, while localized resources are placed in the /Resources folder

Adversaries can use resource forks to hide malicious data that may otherwise be stored directly in files. Adversaries can execute content with an attached resource fork, at a specified offset, that is moved to an executable location then invoked. Resource fork content may also be obfuscated/encrypted until execution.
<br>

## Process Argument Spoofing
Process command-line arguments are stored in the process environment block (PEB), a data structure used by Windows to store various information about/used by a process. The PEB includes the process command-line arguments that are referenced when executing the process. When a process is created, defensive tools/sensors that monitor process creations may retrieve the process arguments from the PEB

**Process Hollowing** can be abused to spawn a process in a suspended state with benign arguments
* After the process is spawned and the PEB is initialized (and process information is potentially logged by tools/sensors), adversaries may override the PEB to modify the command-line arguments (ex: using the Native API `WriteProcessMemory()` function) then resume process execution with malicious arguments

Adversaries may also execute a process with malicious command-line arguments then patch the memory with benign arguments that may bypass subsequent process memory analysis
* This behavior may also be combined with other tricks (such as Parent PID Spoofing) to manipulate or further evade process-based detections
<br>

<hr>

# Hijack Execution Flow
Hijacking execution flow can be for the purposes of persistence, since this hijacked execution may reoccur over time
* Adversaries may also use these mechanisms to elevate privileges or evade defenses, such as application control or other restrictions on execution

There are many ways an adversary may hijack the flow of execution, including by manipulating how the operating system locates programs to be executed
* How the operating system locates libraries to be used by a program can also be intercepted
* Locations where the operating system looks for programs/resources, such as file directories and in the case of Windows the Registry, could also be poisoned to include malicious payloads

<br>

## DLL Search Order Hijacking 
Windows systems use a common method to look for required DLLs to load into a program.
Hijacking DLL loads may be for the purpose of establishing persistence as well as elevating privileges and/or evading restrictions on file execution.

**Hijacking DLL loads**
* Planting trojan DLLs in a directory that will be searched before the location of a legitimate library that will be requested by a program, causing Windows to load their malicious library when it is called for by the victim program

* Binary planting attacks -- Placing a malicious DLL with the same name as an ambiguously specified DLL in a location that Windows searches before the legitimate DLL
  * Often this location is the current working directory of the program
  * Remote DLL preloading attacks occur when a program sets its current directory to a remote location such as a Web share before loading a DLL
  

* Directly modify the search order via DLL redirection, which after being enabled (in the Registry and creation of a redirection file) may cause a program to load a different DLL

* If a search order-vulnerable program is configured to run at a higher privilege level, then the adversary-controlled DLL that is loaded will also be executed at the higher level
  * This technique could be used for privilege escalation from user to administrator or SYSTEM or from administrator to SYSTEM, depending on the program


<br>



## DLL Side-Loading
DLL side-loading involves hijacking which DLL a program loads. But rather than just planting the DLL within the search order, adversaries may directly side-load their payloads by planting then invoking a legitimate application that executes their payload

Side-loading takes advantage of the DLL search order used by the loader by positioning both the victim application and malicious payload(s) alongside each other. 
* Benign executables used to side-load payloads may not be flagged during delivery and/or execution
* Adversary payloads may also be encrypted/packed or otherwise obfuscated until loaded into the memory of the trusted process
<br>

## Dylib Hijacking
Adversaries may execute their own payloads by placing a malicious dynamic library (dylib) with an expected name in a path a victim application searches at runtime. The dynamic loader will try to find the dylibs based on the sequential order of the search paths.
* Paths to dylibs may be prefixed with `@rpath`, which allows developers to use relative paths to specify an array of search paths used at runtime based on the location of the executable
* Additionally, if weak linking is used, such as the `LC_LOAD_WEAK_DYLIB` function, an application will still execute even if an expected dylib is not present
* Weak linking enables developers to run an application on multiple macOS versions as new APIs are added

Adversaries may gain execution by inserting malicious dylibs with the name of the missing dylib in the identified path
* Dylibs are loaded into an application's address space allowing the malicious dylib to inherit the application's privilege level and resources
* Based on the application, this could result in privilege escalation and uninhibited network access
  * This method may also evade detection from security products since the execution is masked under a legitimate process
<br>

## Executable Installer File Permissions Weakness
Installers processes may automatically execute specific binaries as part of their functionality or to perform other actions
* If the permissions on the file system directory containing a target binary, or permissions on the binary itself, are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process
  * If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions

Another variation of this technique can be performed by taking advantage of a weakness that is common in executable, self-extracting installers
* During the installation process, it is common for installers to use a subdirectory within the `%TEMP%` directory to unpack binaries such as DLLs, EXEs, or other payloads
* When installers create subdirectories and files they often do not set appropriate permissions to restrict write access, which allows for execution of untrusted code placed in the subdirectories or overwriting of binaries used in the installation process
  * This behavior is related to and may take advantage of DLL Search Order Hijacking.

Adversaries may use this technique to replace legitimate binaries with malicious ones as a means of executing code at a higher permissions level
* Some installers may require elevated privileges that will result in privilege escalation when executing adversary controlled code
  * This behavior is related to Bypass User Account Control
  * If the executing process is set to run at a specific time or during a certain event then this technique can also be used for persistence
<br>

## Dynamic Linker Hijacking
During the execution preparation phase of a program, the dynamic linker loads specified absolute paths of shared libraries from environment variables and files, such as `LD_PRELOAD` on Linux or `DYLD_INSERT_LIBRARIES` on macOS
* Libraries specified in environment variables are loaded first, taking precedence over system libraries with the same function name
* These variables are often used by developers to debug binaries without needing to recompile, deconflict mapped symbols, and implement custom functions without changing the original library

**Linux and macOS**
Hijacking dynamic linker variables grants access to the victim process's memory, system/network resources, and possibly elevated privileges
* This method may evade detection from security products since the execution is masked under a legitimate process
  * Adversaries can set environment variables via CLI using the *export*, *setenv* function, or *putenv* function
  * Adversaries can also leverage Dynamic Linker Hijacking to export variables in a shell or set variables programmatically using higher level syntax such Python’s *os.environ*

**Linux**
Set *LD_PRELOAD* to point to malicious libraries that match the name of legitimate libraries which are requested by a victim program, causing the operating system to load the adversary's malicious code upon execution of the victim program
* *LD_PRELOAD* can be set via the `environment variable` or `/etc/ld.so.preload` file
  * Libraries specified by *LD_PRELOAD* are loaded and mapped into memory by *dlopen()* and *mmap()* 

**macOS**
Set the `DYLD_INSERT_LIBRARIES` environment variable to point to malicious libraries containing names of legitimate libraries or functions requested by a victim program

<br>

## Path Interception by PATH Environment Variable
The *PATH* environment variable contains a list of directories. Certain methods of executing a program rely solely on the PATH environment variable to determine the locations that are searched for a program when the path for the program is not given
  
If any directories are listed in the PATH environment variable before the Windows directory, `%SystemRoot%\system32`, a program may be placed in the preceding directory that is named the same as a Windows program, which will be executed when that command is executed from a script or command-line
<br>

## Path Interception by Search Order Hijacking
**Search order hijacking:** Occurs when an adversary abuses the order in which Windows searches for programs that are not given a path. Unlike DLL Search Order Hijacking, the search order differs depending on the method that is used to execute the program
* **Note:** It's common for Windows to search in the directory of the initiating program before searching through the Windows system directory

Adversaries may execute their own malicious payloads by hijacking the search order used to load other programs. Because some programs do not call other programs using the full path, adversaries may place their own file in the directory where the calling program is located, causing the operating system to launch their malicious software at the request of the calling program.

* Place a program called "net.exe" within the same directory as example.exe, "net.exe" will be run instead of the Windows system utility net
* In addition, if an adversary places a program called "net.com" in the same directory as "net.exe", then cmd.exe /C net user will execute "net.com" instead of "net.exe" due to the order of executable extensions defined under PATHEXT
<br>

## Path Interception by Unquoted Path
Adversaries can take advantage of paths that lack surrounding quotations by placing an executable in a higher level directory within the path, so that Windows will choose the adversary's executable to launch

Service paths and shortcut paths may also be vulnerable to path interception if the path has one or more spaces and is not surrounded by quotation marks (`C:\unsafe path \program.exe` vs. `"C:\safe path \program.exe"`) Stored in Windows Registry keys 

Attackers can place an executable in a higher level directory of the path, and Windows will resolve that executable instead of the intended executable.
* If the path in a shortcut is `C:\program files\myapp.exe`, create a program at `C:\program.exe` that will be run instead of the intended program
<br>

## Services File Permissions Weakness
Adversaries may use flaws in the permissions of Windows services to replace the binary that is executed upon service start
* If the permissions on the file system directory containing a target binary, or permissions on the binary itself are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process
* If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions
<br>


## Services Registry Permissions Weakness
Adversaries may use flaws in the permissions for Registry keys related to services to redirect from the originally specified executable to one that they control, in order to launch their own code when a service starts

Windows stores local service configuration information in the Registry under `HKLM\SYSTEM\CurrentControlSet\Services`
* The information stored under a service's Registry keys can be manipulated to modify a service's execution parameters through tools such as the service controller, sc.exe, PowerShell, or Reg


Access to Registry keys is controlled through access control lists and user permissions
* If the permissions for users and groups are not properly set and allow access to the Registry keys for a service, adversaries may change the service's `binPath/ImagePath` to point to a different executable under their control

Adversaries may also alter other Registry keys in the service’s Registry tree
* The *FailureCommand* key may be changed so that the service is executed in an elevated context anytime the service fails or is intentionally corrupted

The *Performance* key contains the name of a driver service's performance DLL and the names of several exported functions in the DLL
* If the Performance key is not already present and if an adversary-controlled user has the *Create Subkey* permission, adversaries may create the Performance key in the service’s Registry tree to point to a malicious DLL

Adversaries may also add the *Parameters* key, which stores driver-specific data, or other custom subkeys for their malicious services to establish persistence or enable other malicious activities
* Additionally, If adversaries launch their malicious services using svchost.exe, the service’s file may be identified using `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\servicename\Parameters\ServiceDll`

<br>

## COR_PROFILER
**COR_PROFILER:** A .NET Framework feature which allows developers to specify an unmanaged (or external of .NET) profiling DLL to be loaded into each .NET process that loads the Common Language Runtime (CLR). These profilers are designed to monitor, troubleshoot, and debug managed code executed by the .NET CLR.

The COR_PROFILER environment variable can be set at various scopes (system, user, or process) resulting in different levels of influence
* System and user-wide environment variable scopes are specified in the Registry, where a Component Object Model (COM) object can be registered as a profiler DLL
* A process scope COR_PROFILER can also be created in-memory without modifying the Registry
* Starting with .NET Framework 4, the profiling DLL does not need to be registered as long as the location of the DLL is specified in the COR_PROFILER_PATH environment variable.

Adversaries may abuse COR_PROFILER to establish persistence that executes a malicious DLL in the context of all .NET processes every time the CLR is invoked

The COR_PROFILER can also be used to elevate privileges (ex: Bypass User Account Control) if the victim .NET process executes at a higher permission level, as well as to hook and Impair Defenses provided by .NET processes
<br>

## KernelCallbackTable
**KernelCallbackTable:** Can be found in the Process Environment Block (PEB) and is initialized to an array of graphic functions available to a GUI process once user32.dll is loaded

Attackers may hijack the execution flow of a process using the *KernelCallbackTable* by replacing an original callback function with a malicious payload
* Modifying callback functions can be achieved in various ways involving related behaviors such as Reflective Code Loading or Process Injection into another process

A pointer to the memory address of the *KernelCallbackTable* can be obtained by locating the PEB (ex: via a call to the *NtQueryInformationProcess()* Native API function)
* Once the pointer is located, the *KernelCallbackTable* can be duplicated, and a function in the table (e.g., fnCOPYDATA) set to the address of a malicious payload (ex: via WriteProcessMemory())
* The PEB is then updated with the new address of the table -- Once the tampered function is invoked, the malicious payload will be triggered

The tampered function is typically invoked using a Windows message. After the process is hijacked and malicious code is executed, the KernelCallbackTable may also be restored to its original state by the rest of the malicious payload
* Use of the *KernelCallbackTable* to hijack execution flow may evade detection from security products since the execution can be masked under a legitimate process

<br>

<hr>


# Impair Defenses
Adversaries may maliciously modify components of a victim environment in order to hinder or disable defensive mechanisms. This not only involves impairing preventative defenses, such as firewalls and AV solutions, but also detection capabilities that defenders can use to audit activity and identify malicious behavior. This may also span both native defenses as well as supplemental capabilities installed by users and administrators.

Adversaries could also target event aggregation and analysis mechanisms, or otherwise disrupt these procedures by altering other system components.

<br>

## Disable or Modify Tools
Adversaries may modify and/or disable security tools to avoid possible detection of their malware/tools and activities
* Killing security software processes or services
* Modifying / deleting Registry keys or configuration files so that tools do not operate properly
* Other methods to interfere with security tools scanning or reporting information

Adversaries may also tamper with artifacts deployed and utilized by security tools. Security tools may make dynamic changes to system components in order to maintain visibility into specific events
* Security products may load their own modules and/or modify those loaded by processes to facilitate data collection
* Similar to Indicator Blocking, adversaries may unhook or otherwise modify these features added by tools (especially those that exist in userland or are otherwise potentially accessible to adversaries) to avoid detection

<br>

## Disable Windows Event Logging
Windows event logs record user and system activity such as login attempts, process creation, etc.. This data is used by security tools and analysts to generate detections


**EventLog** service: Maintains event logs from various system components and applications
* By default, the service automatically starts when a system powers on
  * An audit policy, maintained by the Local Security Policy (secpol.msc), defines which system events the EventLog service logs
  * Security audit policy settings can be changed by running secpol.msc, then navigating to `Security Settings\Local Policies\Audit Policy` for basic audit policy settings or `Security Settings\Advanced Audit Policy Configuration` for advanced audit policy settings
    * `auditpol.exe` may also be used to set audit policies

Adversaries may disable Windows event logging to limit data that can be leveraged for detections and audits


Adversaries may target system-wide logging or just that of a particular application
* The EventLog service may be disabled using the following PowerShell line: `Stop-Service -Name EventLog`
* Additionally, adversaries may use **auditpol** and its sub-commands in a command prompt to disable auditing or clear the audit policy
  * Enable or disable a specified setting or audit category: `/success` or `/failure` parameters
  * Turns off auditing for the Account Logon category: `auditpol /set /category:"Account Logon" /success:disable /failure:disable`
  * To clear the audit policy: `auditpol /clear /y or auditpol /remove /allusers`

By disabling Windows event logging, adversaries can operate while leaving less evidence of a compromise behind
<br>


## Impair Command History Logging
Adversaries may impair command history logging to hide commands they run on a compromised system. Various command interpreters keep track of the commands users type in their terminal so that users can retrace what they've done.

**UNIX**
`history` command is tracked in a file pointed to by the environment variable *HISTFILE*. When a user logs off a system, this information is flushed to a file in the user's home directory called `~/.bash_history`
* The **HISTCONTROL** environment variable keeps track of what should be saved by the history command and eventually into the `~/.bash_history` file when a user logs out
  * HISTCONTROL does not exist by default on macOS, but can be set by the user and will be respected

Adversaries may clear the history environment variable (unset HISTFILE) or set the command history size to zero (export HISTFILESIZE=0) to prevent logging of commands
* HISTCONTROL can be configured to ignore commands that start with a space by simply setting it to "ignorespace"
* HISTCONTROL can also be set to ignore duplicate commands by setting it to "ignoredups"
  * In some Linux systems, this is set by default to "ignoreboth" which covers both of the previous examples -- This means that " ls" will not be saved, but "ls" would be saved by history
* Adversaries can abuse this to operate without leaving traces by simply prepending a space to all of their terminal commands

**Windows**
The **PSReadLine** module tracks commands used in all PowerShell sessions and writes them to a file (`$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` by default). Adversaries may change where these logs are saved using `Set-PSReadLineOption -HistorySavePath {File Path}`
* This will cause **ConsoleHost_history.txt** to stop receiving logs
* It is possible to turn off logging to this file using the PowerShell command `Set-PSReadlineOption -HistorySaveStyle SaveNothing`

Adversaries may also leverage a Network Device CLI on network devices to disable historical command logging.
<br>


## Disable or Modify System Firewall
Adversaries may disable or modify system firewalls in order to bypass controls limiting network usage. Changes could be disabling the entire mechanism as well as adding, deleting, or modifying particular rules. This can be done numerous ways depending on the operating system, including via command-line, editing Windows Registry keys, and Windows Control Panel.

Modifying or disabling a system firewall may enable adversary C2 communications, lateral movement, and/or data exfiltration that would otherwise not be allowed
<br>


## Indicator Blocking
An adversary may attempt to block indicators or events typically captured by sensors from being gathered and analyzed. This could include maliciously redirecting or even disabling host-based sensors, such as Event Tracing for Windows (ETW),by tampering settings that control the collection and flow of event telemetry
* These settings may be stored on the system in configuration files and/or in the Registry as well as being accessible via administrative utilities such as PowerShell or Windows Management Instrumentation

ETW interruption can be achieved multiple ways, however most directly by defining conditions using the PowerShell `Set-EtwTraceProvider` cmdlet or by interfacing directly with the Registry to make alterations

In the case of network-based reporting of indicators, an adversary may block traffic associated with reporting to prevent central analysis
* This may be accomplished by many means, such as stopping a local process responsible for forwarding telemetry and/or creating a host-based firewall rule to block traffic to specific hosts responsible for aggregating events.
<br>


## Disable or Modify Cloud Firewall
Adversaries may disable or modify a firewall within a cloud environment to bypass controls that limit access to cloud resources. Cloud firewalls are separate from system firewalls that are described in Disable or Modify System Firewall.

Cloud environments typically utilize restrictive security groups and firewall rules that only allow network activity from trusted IP addresses via expected ports and protocols. An adversary may introduce new firewall rules or policies to allow access into a victim cloud environment. For example, an adversary may use a script or utility that creates new ingress rules in existing security groups to allow any TCP/IP connectivity.

Modifying or disabling a cloud firewall may enable adversary C2 communications, lateral movement, and/or data exfiltration that would otherwise not be allowed.
<br>


## Disable Cloud Logs
An adversary may disable cloud logging capabilities and integrations to limit what data is collected on their activities and avoid detection.

Cloud environments allow for collection and analysis of audit and application logs that provide insight into what activities a user does within the environment. If an adversary has sufficient permissions, they can disable logging to avoid detection of their activities
* In AWS an adversary may disable CloudWatch/CloudTrail integrations prior to conducting further malicious activity
<br>


## Safe Mode Boot
Safe mode starts up the Windows operating system with a limited set of drivers and services. Third-party security software such as EDR tools may not start after booting Windows in safe mode. There are two versions of safe mode: Safe Mode and Safe Mode with Networking. It is possible to start additional services after a safe mode boot

Adversaries may abuse safe mode to disable endpoint defenses that may not start with a limited boot
* Hosts can be forced into safe mode after the next reboot via modifications to Boot Configuration Data (BCD) stores, which are files that manage boot application settings

* Adversaries may also add their malicious applications to the list of minimal services that start in safe mode by modifying relevant Registry values
* Malicious Component Object Model (COM) objects may also be registered and loaded in safe mode
<br>


## Downgrade Attack
Adversaries may downgrade or use a version of system features that may be outdated, vulnerable, and/or does not support updated security controls such as logging
* PowerShell versions 5+ includes Script Block Logging (SBL) which can record executed script content; However, adversaries may attempt to execute a previous version of PowerShell that does not support SBL with the intent to Impair Defenses while running malicious scripts that may have otherwise been detected

Adversaries may downgrade and use less-secure versions of various features of a system, such as Command and Scripting Interpreters or even network protocols that can be abused to enable Adversary-in-the-Middle

<hr>


# Indicator Removal on Host
Adversaries may delete or modify artifacts generated on a host system to remove evidence of their presence or hinder defenses. Various artifacts may be created by an adversary or something that can be attributed to an adversary’s actions. Typically these artifacts are used as defensive indicators related to monitored events, such as strings from downloaded files, logs that are generated from user actions, and other data analyzed by defenders. Location, format, and type of artifact (such as command or login history) are often specific to each platform.

Removal of these indicators may interfere with event collection, reporting, or other processes used to detect intrusion activity. This may compromise the integrity of security solutions by causing notable events to go unreported. This activity may also impede forensic analysis and incident response, due to lack of sufficient data to determine what occurred.
<br>

## Clear Windows Event Logs

<br>

## Clear Linux or Mac System Logs

<br>

## Clear Command History

<br>

## File Deletion

<br>

## Network Share Connection Removal

<br>

## Timestomp
<br>

<hr>


# Indirect Command Execution

<br>
<hr>


# Masquerading

<br>
<hr>


# Modify Authentication Process

<br>
<hr>


# Modify Cloud Compute Infrastructure

<br>
<hr>


# Modify Registry

<br>
<hr>


# Modify System Image

<br>
<hr>


# Network Boundary Bridging

<br>
<hr>


# Obfuscated Files or Information

<br>
<hr>


# Plist File Modification

<br>
<hr>


# Pre-OS Boot

<br>
<hr>


# Reflective Code Loading

<br>
<hr>


# Rogue Domain Controller

<br>
<hr>


# Rootkit

<br>
<hr>


# Subvert Trust Controls

<br>
<hr>


# System Binary Proxy Execution

<br>
<hr>


# System Script Proxy Execution

<br>
<hr>


# Template Injection

<br>
<hr>


# Traffic Signaling

<br>
<hr>


# Trusted Developer Utilities Proxy Execution

<br>
<hr>


# Unused/Unsupported Cloud Regions

<br>
<hr>


# Use Alternate Authentication Material

<br>
<hr>


# Valid Accounts

<br>
<hr>


# Virtualization/Sandbox Evasion

<br>
<hr>


# Weaken Encryption

<br>
<hr>


# XSL Script Processing

