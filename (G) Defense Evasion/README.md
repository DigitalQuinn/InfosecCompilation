# Defense Evasion
Defense Evasion consists of techniques that adversaries use to avoid detection throughout their compromise. Techniques used for defense evasion include uninstalling/disabling security software or obfuscating/encrypting data and scripts. Adversaries also leverage and abuse trusted processes to hide and masquerade their malware. Other tactics’ techniques are cross-listed here when those techniques include the added benefit of subverting defenses.

<hr>

-------------------
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

-----------------------------------
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

-----------
# BITS Jobs
**Background Intelligent Transfer Service (BITS)::** A low-bandwidth, asynchronous file transfer mechanism exposed through Component Object Model (COM)
* BITS is commonly used by updaters, messengers, and other applications preferred to operate in the background (using available idle bandwidth) without interrupting other networked applications. File transfer tasks are implemented as BITS jobs, which contain a queue of one or more file operations.

The interface to create and manage BITS jobs is accessible through PowerShell and the BITSAdmin tool

Adversaries may abuse BITS to download, execute, and even clean up after running malicious code. BITS tasks are self-contained in the BITS job database, without new files or registry modifications, and often permitted by host firewalls. BITS enabled execution may also enable persistence by creating long-standing jobs (the default maximum lifetime is 90 days and extendable) or invoking an arbitrary program when a job completes or errors (including after system reboots)

BITS upload functionalities can also be used to perform Exfiltration Over Alternative Protocol

<br>

---------------------
# Build Image on Host
Adversaries may build a container image directly on a host to bypass defenses that monitor for the retrieval of malicious images from a public registry. A remote build request may be sent to the Docker API that includes a Dockerfile that pulls a vanilla base image, such as alpine, from a public or local registry and then builds a custom image upon it.

An adversary may take advantage of that build API to build a custom image on the host that includes malware downloaded from their C2 server, and then they then may utilize Deploy Container using that custom image
* If the base image is pulled from a public registry, defenses will likely not detect the image as malicious since it’s a vanilla image
* If the base image already resides in a local registry, the pull may be considered even less suspicious since the image is already in the environment

<br>

------------------
# Debugger Evasion
Debuggers are typically used by defenders to trace and/or analyze the execution of potential malware payloads

Debugger evasion may include changing behaviors based on the results of the checks for the presence of artifacts indicative of a debugged environment
* Similar to Virtualization/Sandbox Evasion, if the adversary detects a debugger, they may alter their malware to disengage from the victim or conceal the core functions of the implant
* They may also search for debugger artifacts before dropping secondary or additional payloads

Specific checks will vary based on the target and/or adversary, but may involve Native API function calls such as `IsDebuggerPresent()` and `NtQueryInformationProcess()`, or manually checking the `BeingDebugged` flag of the Process Environment Block (PEB)
* Other checks for debugging artifacts may also seek to enumerate hardware breakpoints, interrupt assembly opcodes, time checks, or measurements if exceptions are raised in the current process (assuming a present debugger would "swallow" or handle the potential error)

Adversaries may use the information learned from these debugger checks during automated discovery to shape follow-on behaviors. Debuggers can also be evaded by detaching the process or flooding debug logs with meaningless data via messages produced by looping Native API function calls such as `OutputDebugStringW()`

<br>

-----------------------------------------
# Deobfuscate/Decode Files or Information
Adversaries may use obfuscated files or information to hide artifacts of an intrusion from analysis. They may require separate mechanisms to decode or deobfuscate that information depending on how they intend to use it. Methods for doing that include built-in functionality of malware or by using utilities present on the system.

One such example is use of `certutil` to decode a remote access tool portable executable file that has been hidden inside a certificate file
* Another example is using the Windows `copy /b` command to reassemble binary fragments into a malicious payload


Sometimes a user's action may be required to open it for deobfuscation or decryption as part of User Execution. The user may also be required to input a password to open a password protected compressed/encrypted file that was provided by the adversary

<br>

------------------
# Deploy Container
Adversaries may deploy a container into an environment to facilitate execution or evade defenses. In some cases, adversaries may deploy a new container to execute processes associated with a particular image or deployment, such as processes that execute or download malware
* In others, an adversary may deploy a new container configured without network rules, user limitations, etc. to bypass existing defenses within the environment

Containers can be deployed by various means, such as via Docker's create and start APIs or via a web application such as the Kubernetes dashboard or Kubeflow
* Adversaries may deploy containers based on retrieved or built malicious images or from benign images that download and execute malicious payloads at runtime

<br>

----------------------
# Direct Volume Access
Adversaries may directly access a volume to bypass file access controls and file system monitoring. Windows allows programs to have direct access to logical volumes. Programs with direct access may read and write files directly from the drive by analyzing file system data structures. This technique bypasses Windows file access controls as well as file system monitoring tools

Utilities, such as NinjaCopy, exist to perform these actions in PowerShell

<br>

----------------------------
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

----------------------
# Execution Guardrails
Guardrails ensure that a payload only executes against an intended target and reduces collateral damage from an adversary’s campaign. Adversaries may use execution guardrails to constrain execution or actions based on adversary supplied and environment specific conditions that are expected to be present on the target. Values an adversary can provide about a target system or environment to use as guardrails may include specific network share names, attached physical devices, files, joined Active Directory (AD) domains, and local/external IP addresses

Guardrails can be used to prevent exposure of capabilities in environments that are not intended to be compromised or operated within. This use of guardrails is distinct from typical Virtualization/Sandbox Evasion
* While use of Virtualization/Sandbox Evasion may involve checking for known sandbox values and continuing with execution only if there is no match, the use of guardrails will involve checking for an expected target-specific value and only continuing with execution if there is such a match
<br>

## Environmental Keying
**Environmental Keying:** An implementation of *Execution Guardrails* that utilizes cryptographic techniques for deriving encryption/decryption keys from specific types of values in a given computing environment
* Environmental keying uses cryptography to constrain execution or actions based on adversary supplied environment specific conditions that are expected to be present on the target

Adversaries may environmentally key payloads or other features of malware to evade defenses and constraint execution to a specific target environment. 

Values can be derived from target-specific elements and used to generate a decryption key for an encrypted payload. Target-specific values can be derived from specific network shares, physical devices, software/software versions, files, joined AD domains, system time, and local/external IP addresses.[2][3][4][5][6] By generating the decryption keys from target-specific environmental values, environmental keying can make sandbox detection, anti-virus detection, crowdsourcing of information, and reverse engineering difficult.[2][6] These difficulties can slow down the incident response process and help adversaries hide their tactics, techniques, and procedures (TTPs).

Similar to Obfuscated Files or Information, adversaries may use environmental keying to help protect their TTPs and evade detection. Environmental keying may be used to deliver an encrypted payload to the target that will use target-specific values to decrypt the payload before execution.[2][4][5][6][7] By utilizing target-specific values to decrypt the payload the adversary can avoid packaging the decryption key with the payload or sending it over a potentially monitored network connection. Depending on the technique for gathering target-specific values, reverse engineering of the encrypted payload can be exceptionally difficult.[2] This can be used to prevent exposure of capabilities in environments that are not intended to be compromised or operated within.

Like other Execution Guardrails, environmental keying can be used to prevent exposure of capabilities in environments that are not intended to be compromised or operated within. This activity is distinct from typical Virtualization/Sandbox Evasion. While use of Virtualization/Sandbox Evasion may involve checking for known sandbox values and continuing with execution only if there is no match, the use of environmental keying will involve checking for an expected target-specific value that must match for decryption and subsequent execution to be successful.

----------------------------------
# Exploitation for Defense Evasion

<br>

---------------------------------------------
# File and Directory Permissions Modification

<br>


----------------
# Hide Artifacts

<br>

-----------------------
# Hijack Execution Flow

<br>

-----------------
# Impair Defenses

<br>

---------------------------
# Indicator Removal on Host

<br>

----------------------------
# Indirect Command Execution

<br>

--------------
# Masquerading

<br>

--------------
# Modify Authentication Process

<br>

--------------
# Modify Cloud Compute Infrastructure

<br>

--------------
# Modify Registry

<br>

--------------
# Modify System Image

<br>

--------------
# Network Boundary Bridging

<br>

--------------
# Obfuscated Files or Information

<br>

--------------
# Plist File Modification

<br>

--------------
# Pre-OS Boot

<br>

-------------------------
# Reflective Code Loading

<br>

--------------
# Rogue Domain Controller

<br>

--------------
# Rootkit

<br>

--------------
# Subvert Trust Controls

<br>

--------------
# System Binary Proxy Execution

<br>

--------------
# System Script Proxy Execution

<br>

--------------
# Template Injection

<br>

--------------
# Traffic Signaling

<br>

--------------
# Trusted Developer Utilities Proxy Execution

<br>

--------------
# Unused/Unsupported Cloud Regions

<br>

--------------
# Use Alternate Authentication Material

<br>

--------------
# Valid Accounts

<br>

--------------
# Virtualization/Sandbox Evasion

<br>

--------------
# Weaken Encryption

<br>

--------------
# XSL Script Processing

