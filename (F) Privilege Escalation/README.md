# Privilege Escalation
**Privilege Escalation:** Consists of techniques that adversaries use to gain higher-level permissions on a system or network. Adversaries can often enter and explore a network with unprivileged access but require elevated permissions to follow through on their objectives. Common approaches are to take advantage of system weaknesses, misconfigurations, and vulnerabilities. Examples of elevated access include:

* SYSTEM/root level
* Local Administrator
* User account with admin-like access
* User accounts with access to specific system or perform specific function

<br>
<hr>

# Table of Contents
- [Abuse Elevation Control Mechanism](#abuse-elevation-control-mechanism)
  - [Setuid and Setgid](#setuid-and-setgid)
  - [Bypass User Account Control](#bypass-user-account-control)
  - [Sudo and Sudo Caching](#sudo-and-sudo-caching)
  - [Elevated Execution with Prompt](#elevated-execution-with-prompt)
- [Access Token Manipulation](#access-token-manipulation)
  - [Token Impersonation / Theft](#token-impersonationtheft)
  - [Create Process with Token](#create-process-with-token)
  - [Make & Impersonate Token](#make-and-impersonate-token)
  - [Parent PID Spoofing](#parent-pid-spoofing)
  - [SID-History Injection](#sid-history-injection)
- [Boot or Logon Autostart Execution](#boot-or-logon-autostart-execution)
  - [Registry Run Keys / Startup Folder](#registry-run-keys--startup-folder)
  - [Authentication Package](#authentication-package)
  - [Time Providers](#time-providers)
  - [Winlogon Helper DLL](#winlogon-helper-dll)
  - [Security Support Provider](#security-support-provider)
  - [Kernel Modules & Extensions](#kernel-modules--extensions)
  - [Re-Opened Applications](#re-opened-applications)
  - [LSASS Driver](#lsass-driver)
  - [Shortcut Modification](#shortcut-modification)
  - [Port Monitors](#port-monitors)
  - [Print Processors](#print-processors)
  - [XDG Autostart Entries](#xdg-autostart-entries)
  - [Active Setup](#active-setup)
  - [Login Items](#login-items)
- [Boot or Logon Initialization Scripts](#boot-or-logon-initialization-scripts)
  - [Logon Script (Windows)](#logon-script-windows)
  - [Login Hook](#login-hook)
  - [Network Logon Script](#network-logon-script)
  - [RC Scripts](#rc-scripts)
  - [Startup Items](#startup-items)
- [Create or Modify System Process](#create-or-modify-system-process)
  - [Launch Agent](#launch-agent)
  - [Systemd Service](#systemd-service)
  - [Windows Service](#windows-service)
  - [Launch Daemon](#launch-daemon)
- [Domain Policy Modification](#domain-policy-modification)
  - [Group Policy Modification](#group-policy-modification)
  - [Domain Trust Modification](#domain-trust-modification)
- [Escape to Host](#escape-to-host)
- [Event Triggered Execution](#event-triggered-execution)
  - [Change Default File Association](#change-default-file-allocation)
  - [Screensaver](#screensaver)
  - [Windows Management Instrumentation Event Subscription](#windows-management-instrumentation-event-subscription)
  - [Unix Shell Configuration Modification](#unix-shell-configuration-modification)
  - [Trap](#trap)
  - [LC_LOAD_DYLIB Addition](#lc_load_dylib-addition)
  - [Netsh Helper DLL](#netsh-helper-dll)
  - [Accessibility Features](#accessibility-features)
  - [AppCert DLLs](#appcert-dlls)
  - [AppInit DLLs](#appinit-dlls)
  - [Application Shimming](#application-shimming)
  - [Image File Execution Options Injection](#image-file-execution-options)
  - [PowerShell Profile](#powershell-profile)
  - [Emond](#emond)
  - [Component Object Model Hijacking](#component-object-model-hijacking)
- [Exploitation for Privilege Escalation](#exploitation-for-privilege-escalation)
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
  - [Services Registry Permissions Weakness](#services-registry-permissions-weakness)
  - [COR_PROFILER](#cor_profiler)
  - [KernelCallbackTable](#kernelcallbacktable)
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
- [Scheduled Task/Job](#scheduled-taskjob)
  - [At](#at)
  - [Cron](#cron)
  - [Scheduled Tasks](#scheduled-tasks)
  - [Systemd Timers](#systemd-timers)
  - [Container Orchestration Job](#container-orchestration-job)
- [Valid Accounts](#valid-accounts)
  - [Default Account](#default-account)
  - [Domain Account](#domain-account)
  - [Local Account](#local-account)
  - [Cloud Account](#cloud-account)

<br>
<hr>

# Abuse Elevation Control Mechanism
Most modern systems contain native elevation control mechanisms that are intended to limit privileges that a user can perform on a machine. Authorization has to be granted to specific users in order to perform tasks that can be considered of higher risk

Attackers can perform several methods to take advantage of built-in control mechanisms in order to escalate privileges on a system

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
<hr>

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

# Boot or Logon Autostart Execution
Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence or gain higher-level privileges on compromised systems. Operating systems may have mechanisms for automatically running a program on system boot or account logon
* These mechanisms may include automatically executing programs that are placed in specially designated directories or are referenced by repositories that store configuration information, such as the Windows Registry
  
An adversary may achieve the same goal by modifying or extending features of the kernel. Since some boot or logon autostart programs run with higher privileges, an adversary may leverage these to elevate privileges.

<br>

## Registry Run Keys / Startup Folder
Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key
* Adding an entry to the "run keys" in the Registry or startup folder will cause the program referenced to be executed when a user logs in -- These programs will be executed under the context of the user and will have the account's associated permissions level

* Placing a program within a startup folder will also cause that program to execute when a user logs in
  * There is a startup folder location for individual user accounts as well as a system-wide startup folder that will be checked regardless of which user account logs in
  * The startup folder path for the current user is: `C:\Users\[Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
  * The startup folder path for all users is: `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`

**The following run keys are created by default on Windows systems:**
* `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce`

**Run keys may exist under multiple hives**
* The `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx` is also available but is not created by default on Windows Vista and newer
* Registry run key entries can reference programs directly or list them as a dependency
  * It's possible to load a DLL at logon using a "Depend" key with RunOnceEx: `reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\temp\evil[.]dll`

**The following Registry keys can be used to set startup folder items for persistence:**
* `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
* `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

**The following Registry keys can control automatic startup of services during boot:**
* `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices`
* `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices`

**Using policy settings to specify startup programs creates corresponding values in either of two Registry keys:**
* `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`
* `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`

**Programs listed in the load value of the registry key** `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows` run when any user logs on

By default, the multistring *BootExecute* value of the registry key
`HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session` Manager is set to autocheck `autochk *`
  * This value causes Windows, at startup, to check the file-system integrity of the hard disks if the system has been shut down abnormally
  * Adversaries can add other programs or processes to this registry value which will automatically launch at boot

* **NOTE::** Adversaries can use these configuration locations to execute malware, such as remote access tools, to maintain persistence through system reboots. Adversaries may also use Masquerading to make the Registry entries look as if they are associated with legitimate programs

<br>

## Authentication Package
Windows authentication package DLLs are loaded by the Local Security Authority (LSA) process at system start. They provide support for multiple logon processes and multiple security protocols to the operating system. 

Adversaries may abuse authentication packages to execute DLLs when the system boots
* Use the autostart mechanism provided by LSA authentication packages for persistence by placing a reference to a binary in the Windows Registry location `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\` with the key value of "Authentication Packages"=<target binary>
* The binary will then be executed by the system when the authentication packages are loaded

<br>

## Time Providers 
The Windows Time service (W32Time) enables time synchronization across and within domains. W32Time time providers are responsible for retrieving time stamps from hardware/network resources and outputting these values to other network clients.


* Time providers are implemented as DLLs that are registered in the subkeys of `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\W32Time\TimeProviders\`
* The time provider manager, directed by the service control manager, loads and starts time providers listed and enabled under this key at system startup and/or whenever parameters are changed


Adversaries may abuse this architecture to establish persistence, specifically by registering and enabling a malicious DLL as a time provider. Administrator privileges are required for time provider registration, though execution will run in context of the Local Service account.

<br>

## Winlogon Helper DLL 
**Winlogon.exe:** A Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete
* Registry entries in `HKLM\Software[\Wow6432Node\]\Microsoft\Windows NT\CurrentVersion\Winlogon\` and `HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\` are used to manage additional helper programs and functionalities that support Winlogon

Adversaries may abuse features of Winlogon to execute DLLs and/or executables when a user logs in
* Malicious modifications to these Registry keys may cause Winlogon to load and execute malicious DLLs / executables

The following subkeys have been known to be possibly vulnerable to abuse: 
* **Winlogon\Notify** -- Points to notification package DLLs that handle Winlogon events
* **Winlogon\Userinit** -- Points to userinit.exe, the user initialization program executed when a user logs on
* **Winlogon\Shell** -- Points to explorer.exe, the system shell executed when a user logs on
  
<br>

## Security Support Provider 
Windows Security Support Providers (SSPs) DLLs are loaded into the Local Security Authority (LSA) process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs.


The SSP configuration is stored in two Registry keys:
* `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`
* `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages`
  * An adversary may modify these Registry keys to add new SSPs, which will be loaded the next time the system boots, or when the AddSecurityPackage Windows API function is called

<br>

## Kernel Modules & Extensions 
**Loadable Kernel Modules (LKMs):** Pieces of code that can be loaded and unloaded into the kernel upon demand. They extend the functionality of the kernel without the need to reboot the system
* One type of module is the device driver, which allows the kernel to access hardware connected to the system

LKMs can be a type of kernel-mode Rootkit that run with the highest operating system privilege
* Common features of LKM based rootkits include: hiding itself, selective hiding of files, processes and network activity, as well as log tampering, providing authenticated backdoors, and enabling root access to non-privileged users

Kernel extensions (kext) are used in macOS to load functionality onto a system similar to LKMs for Linux
* Since the kernel is responsible for enforcing security and the kernel extensions run as apart of the kernel, kexts are not governed by macOS security policies
  * Kexts are loaded and unloaded through kextload and kextunload commands
  * Kexts need to be signed with a developer ID that is granted privileges by Apple allowing it to sign Kernel extensions
  * Developers without these privileges may still sign kexts but they will not load unless SIP is disables
  * If SIP is enabled, the kext signature is verified before being added to the AuxKC

**Note:** Since macOS Catalina 10.15, kernel extensions have been deprecated in favor of System Extensions. However, kexts are still allowed as "Legacy System Extensions" since there is no System Extension for Kernel Programming Interfaces

Adversaries can use LKMs and kexts to conduct Persistence and/or Privilege Escalation on a system

<br>

## Re-Opened Applications 

When a user logs out or restarts via the macOS Graphical User Interface (GUI), a prompt is provided to the user with a checkbox to "Reopen windows when logging back in". When selected, all applications currently open are added to a property list file named `com.apple.loginwindow.[UUID].plist` within the `~/Library/Preferences/ByHost` directory. Applications listed in this file are automatically reopened upon the user’s next logon

<br>

## LSASS Driver 
The Windows security subsystem is a set of components that manage and enforce the security policy for a computer or domain. The Local Security Authority (LSA) is the main component responsible for local security policy and user authentication
* The LSA includes multiple DLLs associated with various other security functions, all of which run in the context of the LSA Subsystem Service (LSASS) `lsass.exe` process


Adversaries may target LSASS drivers to obtain persistence by either replacing or adding illegitimate drivers (e.g., Hijack Execution Flow), an adversary can use LSA operations to continuously execute malicious payloads

<br>

## Shortcut Modification 
Shortcuts or symbolic links are ways of referencing other files or programs that will be opened or executed when the shortcut is clicked or executed by a system startup process.

Adversaries could use shortcuts to execute their tools for persistence. They may create a new shortcut as a means of indirection that may use Masquerading to look like a legitimate program. Adversaries could also edit the target path or entirely replace an existing shortcut so their tools will be executed instead of the intended legitimate program.

<br>

## Port Monitors 
Adversaries may use port monitors to run an adversary supplied DLL during system boot for persistence or privilege escalation. A port monitor can be set through the *AddMonitor* API call to set a DLL to be loaded at startup
* This DLL can be located in `C:\Windows\System32` and will be loaded by the print spooler service, spoolsv.exe, on boot
  * The spoolsv.exe process also runs under SYSTEM level permissions
  * Alternatively, an arbitrary DLL can be loaded if permissions allow writing a fully-qualified pathname for that DLL to `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors`

**The Registry key contains entries for the following:**
* Local Port
* Standard TCP/IP Port
* USB Monitor
* WSD Port

Adversaries can use this technique to load malicious code at startup that will persist on system reboot and execute as SYSTEM.

<br>

## Print Processors 
Print processors are DLLs that are loaded by the print spooler service, spoolsv.exe, during boot

Adversaries may abuse the print spooler service by adding print processors that load malicious DLLs at startup
* A print processor can be installed through the *AddPrintProcessor* API call with an account that has *SeLoadDriverPrivilege* enabled
* Alternatively, a print processor can be registered to the print spooler service by adding the `HKLM\SYSTEM\[CurrentControlSet` or `ControlSet001]\Control\Print\Environments\[Windows architecture: e.g., Windows x64]\Print Processors\[user defined]\Driver` Registry key that points to the DLL
* For the print processor to be correctly installed, it must be located in the system print-processor directory that can be found with the *GetPrintProcessorDirectory* API call
* After the print processors are installed, the print spooler service, which starts during boot, must be restarted in order for them to run
  * The print spooler service runs under SYSTEM level permissions, therefore print processors installed by an adversary may run under elevated privileges

<br>

## XDG Autostart Entries 
Adversaries may modify XDG autostart entries to execute programs or commands during system boot. Linux desktop environments that are XDG compliant implement functionality for XDG autostart entries
* These entries will allow an application to automatically start during the startup of a desktop environment after user logon
* By default, XDG autostart entries are stored within the `/etc/xdg/autostart` or `~/.config/autostart` directories and have a .desktop file extension

Within an XDG autostart entry file, the *Type* key specifies if the entry is an application (type 1), link (type 2) or directory (type 3)

The *Name* key indicates an arbitrary name assigned by the creator and the Exec key indicates the application and command line arguments to execute

Adversaries may use XDG autostart entries to maintain persistence by executing malicious commands and payloads, such as remote access tools, during the startup of a desktop environment
* Commands included in XDG autostart entries with execute after user logon in the context of the currently logged on user
* Adversaries may also use Masquerading to make XDG autostart entries look as if they are associated with legitimate programs

<br>

## Active Setup 
Active Setup is a Windows mechanism that is used to execute programs when a user logs in. The value stored in the Registry key will be executed after a user logs into the computer. These programs will be executed under the context of the user and will have the account's associated permissions level

Adversaries may abuse Active Setup by creating a key under `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\` and setting a malicious value for *StubPath* -- This value will serve as the program that will be executed when a user logs into the computer

Adversaries can abuse these components to execute malware, such as remote access tools, to maintain persistence through system reboots. Adversaries may also use Masquerading to make the Registry entries look as if they are associated with legitimate programs.

<br>

## Login Items 
Login items are applications, documents, folders, or server connections that are automatically launched when a user logs in
* Login items can be added via a shared file list or Service Management Framework
* Shared file list login items can be set using scripting languages such as AppleScript, whereas the Service Management Framework uses the API call *SMLoginItemSetEnabled*

Login items installed using the Service Management Framework leverage launchd, are not visible in the System Preferences, and can only be removed by the application that created them
* Login items created using a shared file list are visible in System Preferences, can hide the application when it launches, and are executed through LaunchServices, not launchd, to open applications, documents, or URLs without using Finder
* Users and applications use login items to configure their user environment to launch commonly used services or applications, such as email, chat, and music applications

Adversaries can utilize AppleScript and Native API calls to create a login item to spawn malicious executables
* Prior to version 10.5 on macOS, adversaries can add login items by using AppleScript to send an Apple events to the "System Events" process, which has an AppleScript dictionary for manipulating login items
* Adversaries can use a command such as tell application "System Events" to make login item at end with properties `/path/to/executable`
  * This command adds the path of the malicious executable to the login item file list located in `~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`
* Adversaries can also use login items to launch executables that can be used to control the victim system remotely or as a means to gain privilege escalation by prompting for user credentials

<br>
<hr>

# Boot or Logon Initialization Scripts
Adversaries may use scripts automatically executed at boot or logon initialization to establish persistence. Initialization scripts can be used to perform administrative functions, which may often execute other programs or send information to an internal logging server. These scripts can vary based on operating system and whether applied locally or remotely.

Adversaries may use these scripts to maintain persistence on a single system. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary.

An adversary may also be able to escalate their privileges since some boot or logon initialization scripts run with higher privileges

<br>

## Logon Script (Windows) 
Windows allows logon scripts to be run whenever a specific user or group of users log into a system
* This is done via adding a path to a script to the `HKCU\Environment\UserInitMprLogonScript` Registry key

Adversaries may use these scripts to maintain persistence on a single system. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary.

<br>

## Login Hook 
**Login hook:** A plist file that points to a specific script to execute with root privileges upon user logon
* The plist file is located in the `/Library/Preferences/com.apple.loginwindow.plist` file and can be modified using the defaults command-line utility
* This behavior is the same for logout hooks where a script can be executed upon user logout. All hooks require administrator permissions to modify or create hooks

Adversaries can add or insert a path to a malicious script in the `com.apple.loginwindow.plist` file, using the *LoginHook* or *LogoutHook* key-value pair
* The malicious script is executed upon the next user login
* If a login hook already exists, adversaries can add additional commands to an existing login hook
  * There can be only one login and logout hook on a system at a time

**Note: Login hooks were deprecated in 10.11 version of macOS in favor of Launch Daemon and Launch Agent**

<br>

## Network Logon Script 
Network logon scripts can be assigned using Active Directory or Group Policy Objects. These logon scripts run with the privileges of the user they are assigned to. Depending on the systems within the network, initializing one of these scripts could apply to more than one or potentially all systems.

Adversaries may use these scripts to maintain persistence on a network. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary.

<br>

## RC Scripts 
Adversaries may establish persistence by modifying RC scripts which are executed during a Unix-like system’s startup. These files allow system administrators to map and start custom services at startup for different run levels. RC scripts require root privileges to modify.

Adversaries can establish persistence by adding a malicious binary path or shell commands to rc.local, rc.common, and other RC scripts specific to the Unix-like distribution. Upon reboot, the system executes the script's contents as root, resulting in persistence.

Adversary abuse of RC scripts is especially effective for lightweight Unix-like distributions using the root user as default, such as **IoT or embedded systems**

Several Unix-like systems have moved to Systemd and deprecated the use of RC scripts. 
**This technique can be used on Mac OS X Panther v10.3 and earlier versions which still execute the RC scripts.**
* To maintain backwards compatibility some systems, such as Ubuntu, will execute the RC scripts if they exist with the correct file permissions

<br>

## Startup Items 
Startup items execute during the final phase of the boot process and contain shell scripts or other executable files along with configuration information used by the system to determine the execution order for all startup items

This is technically a deprecated technology (superseded by Launch Daemon), and thus the appropriate folder, /Library/StartupItems isn’t guaranteed to exist on the system by default, but does appear to exist by default on macOS Sierra
* A startup item is a directory whose executable and configuration property list (plist), StartupParameters.plist, reside in the top-level directory

An adversary can create the appropriate folders/files in the StartupItems directory to register their own persistence mechanism. Additionally, since StartupItems run during the bootup phase of macOS, they will run as the elevated root user

<br>
<hr>

# Create or Modify System Process
When operating systems boot up, they can start processes that perform background system functions. On Windows and Linux, these system processes are referred to as services. On macOS, launchd processes known as Launch Daemon and Launch Agent are run to finish system initialization and load user specific parameters

Adversaries may install new services, daemons, or agents that can be configured to execute at startup or a repeatable interval in order to establish persistence
* Attackers may modify existing services, daemons, or agents to achieve the same effect
* Services, daemons, or agents may be created with administrator privileges but executed under root/SYSTEM privileges
* Adversaries may leverage this functionality to create or modify system processes in order to escalate privileges

<br>

## Launch Agent 
When a user logs in, a per-user launchd process is started which loads the parameters for each launch-on-demand user agent from the property list (.plist) file found in `/System/Library/LaunchAgents`, `/Library/LaunchAgents`, and `~/Library/LaunchAgents`. Property list files use the *Label*, *ProgramArguments* , and R*unAtLoad* keys to identify the Launch Agent's name, executable location, and execution time. Launch Agents are often installed to perform updates to programs, launch user specified programs at login, or to conduct other developer tasks


Adversaries may install a new Launch Agent that executes at login by placing a .plist file into the appropriate folders with the R*unAtLoad* or *KeepAlive* keys set to true. The Launch Agent name may be disguised by using a name from the related operating system or benign software. Launch Agents are created with user level privileges and execute with user level permissions

<br>

## Systemd Service 
The systemd service manager is commonly used for managing background daemon processes (services) and other system resources.

Systemd utilizes configuration files known as service units to control how services boot and under what conditions. By default, these unit files are stored in the `/etc/systemd/system` and `/usr/lib/systemd/system` directories and have the file extension *.service*. Each service unit file may contain numerous directives that can execute system commands:

* *ExecStart, ExecStartPre, and ExecStartPost* directives cover execution of commands when a services is started manually by 'systemctl' or on system start if the service is set to automatically start
  * ExecReload directive covers when a service restarts
  * ExecStop and ExecStopPost directives cover when a service is stopped or manually by 'systemctl'
  
Adversaries have used systemd functionality to establish persistent access to victim systems by creating and/or modifying service unit files that cause systemd to execute malicious commands at system boot

While adversaries typically require root privileges to create/modify service unit files in the /etc/systemd/system and /usr/lib/systemd/system directories, low privilege users can create/modify service unit files in directories such as ~/.config/systemd/user/ to achieve user-level persistence

<br>

## Windows Service 
When Windows boots up, it starts programs or applications called services that perform background system functions. Windows service configuration information, including the file path to the service's executable or recovery programs/commands, is stored in the Windows Registry.

Adversaries may install a new service or modify an existing service to execute at startup in order to persist on a system. Service configurations can be set or modified using system utilities by directly modifying the Registry, or by interacting directly with the Windows API.

Adversaries may use services to install and execute malicious drivers
* After dropping a driver file to disk, the payload can be loaded and registered via Native API functions such as `CreateServiceW()` (or manually via functions such as `ZwLoadDriver()` and `ZwSetValueKey()`), by creating the required service Registry values, or by using CLI utilities such as PnPUtil.exe
* Adversaries may leverage these drivers as Rootkits to hide the presence of malicious activity on a system
* Adversaries may load a signed yet vulnerable driver onto a compromised machine (*Bring Your Own Vulnerable Driver" (BYOVD)*) 

Services may be created with administrator privileges but are executed under SYSTEM privileges, so an adversary may also use a service to escalate privileges
* Adversaries may also directly start services through Service Execution
* To make detection analysis more challenging, malicious services may also incorporate Masquerade Task or Service (ex: using a service and/or payload name related to a legitimate OS or benign software component)

<br>

## Launch Daemon 
Adversaries may create or modify Launch Daemons to execute malicious payloads as part of persistence. Launch Daemons are plist files used to interact with Launchd, the service management framework used by macOS
* During the macOS initialization startup, the launchd process loads the parameters for launch-on-demand system-level daemons from plist files found in `/System/Library/LaunchDaemons/` and `/Library/LaunchDaemons/`
* Required Launch Daemons parameters include a Label to identify the task, Program to provide a path to the executable, and RunAtLoad to specify when the task is run
* Launch Daemons are often used to provide access to shared resources, updates to software, or conduct automation tasks

Adversaries may install a Launch Daemon configured to execute at startup by using the RunAtLoad parameter set to true and the Program parameter set to the malicious executable path. The daemon name may be disguised by using a name from a related operating system or benign software (i.e. Masquerading). When the Launch Daemon is executed, the program inherits administrative permissions

Additionally, system configuration changes (such as the installation of third party package managing software) may cause folders such as `usr/local/bin` to become globally writeable. So, it is possible for poor configurations to allow an adversary to modify executables referenced by current Launch Daemon's plist files

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

# Escape to Host
Adversaries may break out of a container to gain access to the underlying host. This can allow an adversary access to other containerized resources from the host level or to the host itself. In principle, containerized resources should provide a clear separation of application functionality and be isolated from the host environment.

**Escape to a host environment**
* Create a container configured to mount the host’s filesystem using the bind parameter -- Allows the adversary to drop payloads and execute control utilities such as cron on the host, or utilizing a privileged container to run commands on the underlying host
* Exploit vulnerabilities in global symbolic links in order to access the root directory of a host machine

Gaining access to the host may provide the adversary with the opportunity to achieve follow-on objectives, such as establishing persistence, moving laterally within the environment, or setting up a command and control channel on the host

<br>
<hr>

# Event Triggered Execution
Adversaries may establish persistence and/or elevate privileges using system mechanisms that trigger execution based on specific events. Various operating systems have means to monitor and subscribe to events such as logons or other user activity such as running specific applications/binaries.

Adversaries may abuse these mechanisms as a means of maintaining persistent access to a victim via repeatedly executing malicious code. After gaining access to a victim system, adversaries may create/modify event triggers to point to malicious content that will be executed whenever the event trigger is invoked.

Since the execution can be proxied by an account with higher permissions, such as SYSTEM or service accounts, an adversary may be able to abuse these triggered execution mechanisms to escalate their privileges.

<br>

## Change Default File Allocation 
When a file is opened, the default program used to open the file (file association or handler) is checked. File association selections are stored in the Windows Registry and can be edited by users, administrators, or programs that have Registry access or by administrators using the built-in assoc utility. Applications can modify the file association for a given file extension to call an arbitrary program when a file with the given extension is opened.

System file associations are listed under `HKEY_CLASSES_ROOT.[extension]`
* The entries point to a handler for that extension located at `HKEY_CLASSES_ROOT\[handler]`
* The various commands are then listed as subkeys underneath the shell key at `HKEY_CLASSES_ROOT\[handler]\shell\[action]\command`; For example:

* `HKEY_CLASSES_ROOT\txtfile\shell\open\command`
* `HKEY_CLASSES_ROOT\txtfile\shell\print\command`
* `HKEY_CLASSES_ROOT\txtfile\shell\printto\command`
The values of the keys listed are commands that are executed when the handler opens the file extension. Adversaries can modify these values to continually execute arbitrary commands

<br>

## Screensaver 
Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr file extension. The Windows screensaver application scrnsave.scr is located in `C:\Windows\System32\`, and `C:\Windows\sysWOW64\` on 64-bit Windows systems, along with screensavers included with base Windows installations.

The following screensaver settings are stored in the Registry (`HKCU\Control Panel\Desktop\`) and could be manipulated to achieve persistence:

* **SCRNSAVE.exe** - set to malicious PE path
* **ScreenSaveActive** - set to '1' to enable the screensaver
* **ScreenSaverIsSecure** - set to '0' to not require a password to unlock
* **ScreenSaveTimeout** - sets user inactivity timeout before screensaver is executed


**Note:** Adversaries can use screensaver settings to maintain persistence by setting the screensaver to run malware after a certain timeframe of user inactivity

<br>

## Windows Management Instrumentation Event Subscription 
WMI can be used to install event filters, providers, consumers, and bindings that execute code when a defined event occurs. Examples of events that may be subscribed to are the wall clock time, user loging, or the computer's uptime.

Adversaries may use the capabilities of WMI to subscribe to an event and execute arbitrary code when that event occurs, providing persistence on a system
* Adversaries may also compile WMI scripts into Windows Management Object (MOF) files (.mof extension) that can be used to create a malicious subscription

WMI subscription execution is proxied by the WMI Provider Host process (WmiPrvSe.exe) and thus may result in elevated SYSTEM privileges.

<br>

## Unix Shell Configuration Modification 
User Unix Shells execute several configuration scripts at different points throughout the session based on events. When a user opens a command-line interface or remotely logs in (such as via SSH) a login shell is initiated
* The login shell executes scripts from the system (/etc) and the user’s home directory (~/) to configure the environment
* All login shells on a system use /etc/profile when initiated
  * These configuration scripts run at the permission level of their directory and are often used to set environment variables, create aliases, and customize the user’s environment
  * When the shell exits or terminates, additional shell scripts are executed to ensure the shell exits appropriately

**Adversaries may attempt to establish persistence by inserting commands into scripts automatically executed by shells**

### Leveraging Bash
Add commands that launch malicious binaries into the `/etc/profile` and `/etc/profile.d` files
* These files require root permissions to modify and are executed each time any shell on a system launches
* For user level permissions, adversaries can insert malicious commands into `~/.bash_profile`, `~/.bash_login`, or `~/` profile which are sourced when a user opens a command-line interface or connects remotely
  * Since the system only executes the first existing file in the listed order, adversaries have used `~/.bash_profile` to ensure execution
* Adversaries have also leveraged the `~/.bashrc` file which is additionally executed if the connection is established remotely or an additional interactive shell is opened, such as a new tab in the command-line interface
* Some malware targets the termination of a program to trigger execution, adversaries can use the `~/.bash_logout` file to execute malicious commands at the end of a session

### Leveraging macOS
Leverage zsh, the default shell for macOS 10.15+
* When the Terminal.app is opened, the application launches a zsh login shell and a zsh interactive shell
  * The login shell configures the system environment using `/etc/profile`, `/etc/zshenv`, `/etc/zprofile`, and `/etc/zlogin`
  * The login shell then configures the user environment with `~/.zprofile` and `~/.zlogin`. The interactive shell uses the `~/.zshrc` to configure the user environment. Upon exiting, `/etc/zlogout` and `~/.zlogout` are executed
* For legacy programs, macOS executes `/etc/bashrc` on startup

<br>

## Trap 
The trap command allows programs and shells to specify commands that will be executed upon receiving interrupt signals. A common situation is a script allowing for graceful termination and handling of common keyboard interrupts like ctrl+c and ctrl+d.

Adversaries can use this to register code to be executed when the shell encounters specific interrupts as a persistence mechanism. Trap commands are of the following format trap 'command list' signals where "command list" will be executed when "signals" are received

<br>

## LC_LOAD_DYLIB Addition 
**Mach-O** binaries have a series of headers that are used to perform certain operations when a binary is loaded. The *LC_LOAD_DYLIB* header in a Mach-O binary tells macOS and OS X which dynamic libraries (dylibs) to load during execution time
* These can be added ad-hoc to the compiled binary as long as adjustments are made to the rest of the fields and dependencies

Adversaries may modify Mach-O binary headers to load and execute malicious dylibs every time the binary is executed

Although any changes will invalidate digital signatures on binaries because the binary is being modified, this can be remediated by simply removing the *LC_CODE_SIGNATURE* command from the binary so that the signature isn’t checked at load time

<br>

## Netsh Helper DLL 
**Netsh.exe (Netshell):** A command-line scripting utility used to interact with the network configuration of a system. It contains functionality to add helper DLLs for extending functionality of the utility
* The paths to registered netsh.exe helper DLLs are entered into the Windows Registry at `HKLM\SOFTWARE\Microsoft\Netsh`

Adversaries can use netsh.exe helper DLLs to trigger execution of arbitrary code in a persistent manner
* This execution would take place anytime netsh.exe is executed, which could happen automatically, with another persistence technique, or if other software (ex: VPN) is present on the system that executes netsh.exe as part of its normal functionality

<br>

## Accessibility Features 
Windows contains accessibility features that may be launched with a key combination before a user has logged in. An adversary can modify the way these programs are launched to get a command prompt or backdoor without logging in to the system

Two common accessibility programs are `C:\Windows\System32\sethc.exe`, launched when the shift key is pressed five times and `C:\Windows\System32\utilman.exe`, launched when the Windows + U key combination is pressed
* *sethc.exe* program (Sticky Keys) has been used by adversaries for unauthenticated access through a remote desktop login screen

Common methods used by adversaries include replacing accessibility feature binaries or pointers/references to these binaries in the Registry
* In newer versions of Windows, the replaced binary needs to be digitally signed for x64 systems, the binary must reside in `%systemdir%\`, and it must be protected by Windows File or Resource Protection (WFP/WRP)
  * **Note:** The Image File Execution Options Injection debugger method was likely discovered as a potential workaround because it does not require the corresponding accessibility feature binary to be replaced

For simple binary replacement the program (`C:\Windows\System32\utilman.exe`) may be replaced with "cmd.exe" or another program that provides backdoor access
* Subsequently, pressing the appropriate key combination at the login screen while sitting at the keyboard or when connected over Remote Desktop Protocol will cause the replaced file to be executed with SYSTEM privileges

Other accessibility features exist that may also be leveraged in a similar fashion:

* On-Screen Keyboard: `C:\Windows\System32\osk.exe`
* Magnifier: `C:\Windows\System32\Magnify.exe`
* Narrator: `C:\Windows\System32\Narrator.exe`
* Display Switcher: `C:\Windows\System32\DisplaySwitch.exe`
* App Switcher: `C:\Windows\System32\AtBroker.exe`

<br>

## AppCert DLLs 
DLLs that are specified in the AppCertDLLs Registry key under `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\` are loaded into every process that calls the ubiquitously used application programming interface (API) functions *CreateProcess*, *CreateProcessAsUser*, *CreateProcessWithLoginW*, CreateProcessWithTokenW, or WinExec

This value can be abused to obtain elevated privileges by causing a malicious DLL to be loaded and run in the context of separate processes on the computer
* Malicious AppCert DLLs may also provide persistence by continuously being triggered by API activity

<br>

## AppInit DLLs 
DLLs that are specified in the *AppInit_DLLs* value in the Registry keys `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows` or `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows` are loaded by user32.dll into every process that loads user32.dll
* This is nearly every program, since user32.dll is a very common library

These values can be abused to obtain elevated privileges by causing a malicious DLL to be loaded and run in the context of separate processes on the computer
* Malicious AppInit DLLs may also provide persistence by continuously being triggered by API activity

* **Note:**The AppInit DLL functionality is disabled in Windows 8 and later versions when secure boot is enabled

<br>

## Application Shimming 
The Microsoft Windows Application Compatibility Infrastructure/Framework (Application Shim) was created to allow for backward compatibility of software as the operating system codebase changes over time
* The application shimming feature allows developers to apply fixes to applications (without rewriting code) that were created for Windows XP so that it will work with Windows 10

Within the framework, shims are created to act as a buffer between the program (or more specifically, the Import Address Table) and the Windows OS
* When a program is executed, the shim cache is referenced to determine if the program requires the use of the shim database (.sdb)
* If so, the shim database uses hooking to redirect the code as necessary in order to communicate with the OS

**A list of all shims currently installed by the default Windows installer (sdbinst.exe) is kept in:**

* %WINDIR%\AppPatch\sysmain.sdb and
`hklm\software\microsoft\windows nt\currentversion\appcompatflags\installedsdb`

**Custom databases are stored in:**

* `%WINDIR%\AppPatch\custom` & `%WINDIR%\AppPatch\AppPatch64\Custom` and
`hklm\software\microsoft\windows nt\currentversion\appcompatflags\custom`


To keep shims secure, Windows designed them to run in user mode so they cannot modify the kernel and you must have administrator privileges to install a shim
* Certain shims can be used to Bypass User Account Control (UAC and RedirectEXE), inject DLLs into processes (InjectDLL), disable Data Execution Prevention (DisableNX) and Structure Exception Handling (DisableSEH), and intercept memory addresses (GetProcAddress)

Utilizing these shims may allow an adversary to perform several malicious acts such as elevate privileges, install backdoors, disable defenses like Windows Defender, etc 
* Shims can also be abused to establish persistence by continuously being invoked by affected programs

<br>

## Image File Execution Options 
Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by Image File Execution Options (IFEO) debuggers. IFEOs enable a developer to attach a debugger to an application. When a process is created, a debugger present in an application’s IFEO will be prepended to the application’s name, effectively launching the new process under the debugger (`C:\dbg\ntsd.exe -g notepad.exe`)

IFEOs can be set directly via the Registry or in Global Flags via the GFlags tool
* IFEOs are represented as Debugger values in the Registry under `HKLM\SOFTWARE{\Wow6432Node}\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\` where <executable> is the binary on which the debugger is attached

IFEOs can also enable an arbitrary monitor program to be launched when a specified program silently exits (i.e. is prematurely terminated by itself or a second, non kernel-mode process). Similar to debuggers, silent exit monitoring can be enabled through GFlags and/or by directly modifying IFEO and silent process exit Registry values in `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\`

Registry key may be modified that configures "cmd.exe," or another program that provides backdoor access, as a "debugger" for an accessibility program (ex: utilman.exe)
* After the Registry is modified, pressing the appropriate key combination at the login screen while at the keyboard or when connected with Remote Desktop Protocol will cause the "debugger" program to be executed with SYSTEM privileges

Similar to Process Injection, these values may also be abused to obtain privilege escalation by causing a malicious executable to be loaded and run in the context of separate processes on the computer. Installing IFEO mechanisms may also provide Persistence via continuous triggered invocation.

Malware may also use IFEO to Impair Defenses by registering invalid debuggers that redirect and effectively disable various system and security applications

<br>

## PowerShell Profile 
A PowerShell profile (profile.ps1) is a script that runs when PowerShell starts and can be used as a logon script to customize user environments


* PowerShell supports several profiles depending on the user or host program
  * There can be different profiles for PowerShell host programs such as the PowerShell console, PowerShell ISE or Visual Studio Code
  * An administrator can also configure a profile that applies to all users and host programs on the local computer


Adversaries may modify these profiles to include arbitrary commands, functions, modules, and/or PowerShell drives to gain persistence
* Every time a user opens a PowerShell session the modified script will be executed unless the *-NoProfile* flag is used when it is launched


An adversary may also be able to escalate privileges if a script in a PowerShell profile is loaded and executed by an account with higher privileges, such as a domain administrator

<br>

## Emond 
Event Monitor Daemon (Emond): A Launch Daemon that accepts events from various services, runs them through a simple rules engine, and takes action. The emond binary at `/sbin/` emond will load any rules from the `/etc/emond.d/rules/` directory and take action once an explicitly defined event takes place

The rule files are in the plist format and define the name, event type, and action to take
* Event types include system startup and user authentication
* Examples of actions are to run a system command or send an email. The emond service will not launch if there is no file present in the QueueDirectories path `/private/var/db/emondClients`, specified in the Launch Daemon configuration file at `/System/Library/LaunchDaemons/com.apple.emond.plist`

Adversaries may abuse this service by writing a rule to execute commands when a defined event occurs, such as system start up or user authentication. Adversaries may also be able to escalate privileges from administrator to root as the emond service is executed with root privileges by the Launch Daemon service

<br>

## Component Object Model Hijacking 
COM: A system within Windows to enable interaction between software components through the operating system -- References to various COM objects are stored in the Registry

Adversaries can use the COM system to insert malicious code that can be executed in place of legitimate software through hijacking the COM references and relationships as a means for persistence
* Hijacking a COM object requires a change in the Registry to replace a reference to a legitimate system component which may cause that component to not work when executed. When that system component is executed through normal system operation the adversary's code will be executed instead
* An adversary is likely to hijack objects that are used frequently enough to maintain a consistent level of persistence, but are unlikely to break noticeable functionality within the system as to avoid system instability that could lead to detection

<br>
<hr>

# External Remote Services 
Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations. There are often remote service gateways that manage connections and credential authentication for these services. Services such as Windows Remote Management and VNC can also be used externally

Access to Valid Accounts to use the service is often a requirement, which could be obtained through credential pharming or by obtaining the credentials from users after compromising the enterprise network
* Access to remote services may be used as a redundant or persistent access mechanism during an operation

Access may also be gained through an exposed service that doesn’t require authentication
* In containerized environments, this may include an exposed Docker API, Kubernetes API server, kubelet, or web application such as the Kubernetes dashboard

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
Set *LD_PRELOAD* to point to malicious libraries that match the name of legitimate libraries which are requested by a victim program, causing the operating system to load the adversary's malicious code upon execution of the victim program
* *LD_PRELOAD* can be set via the `environment variable` or `/etc/ld.so.preload` file
  * Libraries specified by *LD_PRELOAD* are loaded and mapped into memory by *dlopen()* and *mmap()* 

### macOS
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

# Exploitation for Privilege Escalation
Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code
* Security constructs such as permission levels will often hinder access to information and use of certain techniques, so adversaries will likely need to perform privilege escalation to include use of software exploitation to circumvent those restrictions.

When initially gaining access to a system, an adversary may be operating within a lower privileged process which will prevent them from accessing certain resources on the system. Vulnerabilities may exist, usually in operating system components and software commonly running at higher permissions, that can be exploited to gain higher levels of access on the system
* This could enable someone to move from unprivileged or user level permissions to SYSTEM or root permissions depending on the component that is vulnerable
* This could also enable an adversary to move from a virtualized environment, such as within a virtual machine or container, onto the underlying host

Adversaries may bring a signed vulnerable driver onto a compromised machine so that they can exploit the vulnerability to execute code in kernel mode (Bring Your Own Vulnerable Driver)
* Adversaries may include the vulnerable driver with files delivered during Initial Access or download it to a compromised system via Ingress Tool Transfer or Lateral Tool Transfer

<br>
<hr>

# Process Injection
**Process Injection:** A method of executing arbitrary code in the address space of a separate live process
* Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges
* Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process

<br>

## Dynamic-link Library Injection
**DLL Injection:** A method of executing arbitrary code in the address space of a separate live process

DLL injection is commonly performed by writing the path to a DLL in the virtual address space of the target process before loading the DLL by invoking a new thread
* The write can be performed with native Windows API calls such as `VirtualAllocEx` and `WriteProcessMemory`, then invoked with `CreateRemoteThread` (which calls the LoadLibrary API responsible for loading the DLL)

Variations of this method such as Reflective DLL Injection: Writing a self-mapping DLL into a process and Memory Module: Map DLL when writing into process overcome the address relocation issue as well as the additional APIs to invoke execution (since these methods load and execute the files in memory by manually preforming the function of LoadLibrary)

Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via DLL injection may also evade detection from security products since the execution is masked under a legitimate process.

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
<hr>

# Scheduled Task/Job
Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified date and time. A task can also be scheduled on a remote system, provided the proper authentication is met (ex: RPC and file and printer sharing in Windows environments). Scheduling a task on a remote system typically may require being a member of an admin or otherwise privileged group on the remote system

Adversaries may use task scheduling to execute programs at system startup or on a scheduled basis for persistence. These mechanisms can also be abused to run a process under the context of a specified account (such as one with elevated permissions/privileges). Similar to System Binary Proxy Execution, adversaries have also abused task scheduling to potentially mask one-time execution under a trusted system process

<br>

## At
``at`` utility exists as an executable within Windows, Linux, and macOS for scheduling tasks at a specified time and date

On Linux and macOS, ``at`` may be invoked by the superuser as well as any users added to the ``at.allow`` file
* If the ``at.allow`` file does not exist, the ``at.deny`` file is checked
* Every username not listed in ``at.deny`` is allowed to invoke at. If the ``at.deny`` exists and is empty, global use of at is permitted
* If neither file exists (which is often the baseline) only the superuser is allowed to use at

Adversaries may use ``at`` to execute programs at system startup or on a scheduled basis for Persistence. ``at`` can also be abused to conduct remote Execution as part of Lateral Movement and/or to run a process under the context of a specified account (such as SYSTEM)

In Linux environments, adversaries may also abuse ``at`` to break out of restricted environments by using a task to spawn an interactive system shell or to run system commands. Similarly, ``at`` may also be used for Privilege Escalation if the binary is allowed to run as superuser via sudo

<br>

## Cron 
The ``cron`` utility is a time-based job scheduler for Unix-like operating systems. The crontab file contains the schedule of cron entries to be run and the specified times for execution. Any crontab files are stored in operating system-specific file paths.

An adversary may use cron in Linux or Unix environments to execute programs at system startup or on a scheduled basis for Persistence.

<br>

## Scheduled Tasks 
Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code

There are multiple ways to access the Task Scheduler in Windows
* **schtasks** can be run directly on the command line, or the Task Scheduler can be opened through the GUI within the Administrator Tools section of the Control Panel
* Adversaries have used a .NET wrapper for the Windows Task Scheduler, and alternatively, adversaries have used the Windows netapi32 library to create a scheduled task.

The deprecated ``at`` utility could also be abused by adversaries, though at.exe can not access tasks created with schtasks or the Control Panel

* Windows Task Scheduler can execute programs at system startup or on a scheduled basis for persistence
  * Task Scheduler can also be abused to conduct remote Execution as part of Lateral Movement and/or to run a process under the context of a specified account (such as SYSTEM)
  * Adversaries have also abused the Windows Task Scheduler to potentially mask one-time execution under signed/trusted system processes

<br>

## Systemd Timers 
Systemd timers are unit files with file extension .timer that control services. Timers can be set to run on a calendar event or after a time span relative to a starting point. They can be used as an alternative to Cron in Linux environments
* Systemd timers may be activated remotely via the systemctl command line utility, which operates over SSH

* Each ``.timer`` file must have a corresponding ``.service`` file with the same name. 
* .service files are Systemd Service unit files that are managed by the systemd system and service manager.[3] Privileged timers are written to ``/etc/systemd/system/`` and ``/usr/lib/systemd/system`` while user level are written to ``~/.config/systemd/user/``

An adversary may use systemd timers to execute malicious code at system startup or on a scheduled basis for persistence. Timers installed using privileged paths may be used to maintain root level persistence. Adversaries may also install user level timers to achieve user level persistence.

<br>

## Container Orchestration Job 
Container orchestration jobs run these automated tasks at a specific date and time, similar to cron jobs on a Linux system. Deployments of this type can also be configured to maintain a quantity of containers over time, automating the process of maintaining persistence within a cluster.

In Kubernetes, a CronJob may be used to schedule a Job that runs one or more containers to perform specific tasks. An adversary therefore may utilize a CronJob to schedule deployment of a Job that executes malicious code in various nodes within a cluster. 

<br>
<hr>

# Valid Accounts
Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services


Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network

Attackers may abuse inactive accounts -- Using these accounts may allow the adversary to evade detection, as the original account user will not be present to identify any anomalous activity taking place on their account

The overlap of permissions for local, domain, and cloud accounts across a network of systems is of concern because the adversary may be able to pivot across accounts and systems to reach a high level of access to bypass access controls set within the enterprise

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