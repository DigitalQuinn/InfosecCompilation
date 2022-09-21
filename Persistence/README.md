# Persistence #
**Persistence** consists of techniques that adversaries use to keep access to systems across restarts, changed credentials, and other interruptions that could cut off their access. Techniques used for persistence include any access, action, or configuration changes that let them maintain their foothold on systems, such as replacing or hijacking legitimate code or adding startup code

---------------------
# Tables of Contents #
---------------------
- [Account Manipulatiton](#account-manipulation)
- [BITS Jobs](#bits-jobs)
- [Account Manipulation](#account-manipulation)
- [Boot or Logon Autostart Execution](#boot-or-logon-autostart-execution)
- [Boot or Logon Initialization Scripts](#boot-or-logon-initialization-scripts)
- [Browser Extensions](#browser-extensions)
- [Compromise Client Software Binary](#compromise-client-software-binary)
- [Create Account](#create-account)
- [Create or Modify System Processes](#create-or-modify-system-processes)
- [Event Triggered Execution](#event-triggered-execution)
- [External Remote Service](#external-remote-services)
- [Hijack Execution Flow](#hijack-execution-flow)
- [Implant Internal Image](#implant-internal-image)
- [Modify Authentication Process](#modify-authentication-process)
- [Office Application Startup](#office-application-startup)
- [Pre-OS Boot](#pre-os-boot)
- [Server Software Component](#server-software-component)
- [Traffic Signaling](#traffic-signaling)
- [Valid Accounts](#valid-accounts)







------------------------
# Account Manipulation #
Account manipulation may consist of any action that preserves adversary access to a compromised account, such as modifying credentials or permission groups. These actions could also include account activity designed to subvert security policies, such as performing iterative password updates to bypass password duration policies and preserve the life of compromised credentials


## Additional Cloud Credentials ##
Adversaries may add adversary-controlled credentials to a cloud account to maintain persistent access to victim accounts and instances within the environment.

* Adversaries may add credentials for Service Principals and Applications in addition to existing legitimate credentials in Azure AD (These credentials include both x509 keys and passwords)
* With sufficient permissions, there are a variety of ways to add credentials including the Azure Portal, Azure command line interface, and Azure or Az PowerShell modules

In IaaS) environments, after gaining access through Cloud Accounts, adversaries may generate or import their own SSH keys using either the *CreateKeyPair* or *ImportKeyPair API* in AWS or the ``gcloud compute os-login ssh-keys add`` command in GCP
* This allows persistent access to instances within the cloud environment without further usage of the compromised cloud accounts

## Additional Email Delegate Permissions ##
Adversaries may grant additional permission levels to maintain persistent access to an adversary-controlled email account.

``Add-MailboxPermission`` PowerShell cmdlet adds permissions to a mailbox. In Google Workspace, delegation can be enabled via the Google Admin console and users can delegate accounts via their Gmail settings

Adversaries may also assign mailbox folder permissions through individual folder permissions or roles
* In Office 365 environments, adversaries may assign the Default or Anonymous user permissions or roles to the Top of Information Store (root), Inbox, or other mailbox folders
  * By assigning one or both user permissions to a folder, the adversary can utilize any other account in the tenant to maintain persistence to the target user’s mail folders
  
* This may be used in persistent threat incidents as well as BEC (Business Email Compromise) incidents where an adversary can add Additional Cloud Roles to the accounts they wish to compromise
  * This may further enable use of additional techniques for gaining access to systems

## Additional Cloud Roles ##
An adversary may add additional roles or permissions to an adversary-controlled cloud account to maintain persistent access to a tenant
* Update IAM policies in cloud-based environments
* Add a new global administrator in Office 365 environments
* With sufficient permissions, a compromised account can gain almost unlimited access to data and settings

This account modification may immediately follow Create Account or other malicious account activity
* Adversaries may also modify an existing Valid Accounts that they have compromised

## SSH Authorized Keys ##
Adversaries may modify the SSH authorized_keys file to maintain persistence on a victim host
* Linux distributions and macOS commonly use key-based authentication to secure the authentication process of SSH sessions for remote management
  * The authorized_keys file in SSH specifies the SSH keys that can be used for logging into the user account for which the file is configured
  * Users may edit the system’s SSH config file to modify the directives PubkeyAuthentication and RSAAuthentication to the value "yes" to ensure public key and RSA authentication are enabled
  * The SSH config file is usually located under /etc/ssh/sshd_config

Adversaries may modify SSH authorized_keys files directly with scripts or shell commands to add their own adversary-supplied public keys
* In cloud environments, adversaries may be able to modify the SSH authorized_keys file of a particular virtual machine via the command line interface or rest API
* Busing the Google Cloud CLI’s "add-metadata" command an adversary may add SSH keys to a user account
* In Azure, an adversary may update the authorized_keys file of a virtual machine via a PATCH request to the API

Where authorized_keys files are modified via cloud APIs or command line interfaces, an adversary may achieve privilege escalation on the target virtual machine if they add a key to a higher-privileged user

## Device Registration ##
Adversaries may register a device to an adversary-controlled account. Devices may be registered in a multifactor authentication (MFA) system, which handles authentication to the network, or in a device management system, which handles device access and compliance.

MFA systems allow users to associate devices with their accounts in order to complete MFA requirements. An adversary that compromises a user’s credentials may enroll a new device in order to bypass initial MFA requirements and gain persistent access to a network.

* Attackers with existing access to a network may register a device to Azure AD and/or its device management system, Microsoft Intune, in order to access sensitive data or resources while bypassing conditional access policies
* Devices registered in Azure AD may be able to conduct Internal Spearphishing campaigns via intra-organizational emails, which are less likely to be treated as suspicious by the email client
* Adversaries may be able to perform a Service Exhaustion Flood on an Azure AD tenant by registering a large number of devices



-------------
# BITS Jobs #
**Windows Background Intelligent Transfer Service (BITS):** A low-bandwidth, asynchronous file transfer mechanism exposed through Component Object Model (COM)
* BITS is commonly used by updaters, messengers, and other applications preferred to operate in the background (using available idle bandwidth) without interrupting other networked applications
* File transfer tasks are implemented as BITS jobs, which contain a queue of one or more file operations

The interface to create and manage BITS jobs is accessible through PowerShell and the BITSAdmin tool

* Adversaries may abuse BITS to download, execute, and even clean up after running malicious code
* BITS tasks are self-contained in the BITS job database, without new files or registry modifications, and often permitted by host firewalls
* BITS enabled execution may also enable persistence by creating long-standing jobs or invoking an arbitrary program when a job completes or errors (including after system reboots
* BITS upload functionalities can also be used to perform Exfiltration Over Alternative Protocol



-------------------------------------
# Boot or Logon Autostart Execution #
Operating systems may have mechanisms for automatically running a program on system boot or account logon. These mechanisms may include automatically executing programs that are placed in specially designated directories or are referenced by repositories that store configuration information, such as the Windows Registry. An adversary may achieve the same goal by modifying or extending features of the kernel.

Since some boot or logon autostart programs run with higher privileges, an adversary may leverage these to elevate privileges.

## Registry Run Keys / Startup Folder ##
Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key
* Adding an entry to the "run keys" in the Registry or startup folder will cause the program referenced to be executed when a user logs in -- These programs will be executed under the context of the user and will have the account's associated permissions level

* Placing a program within a startup folder will also cause that program to execute when a user logs in
  * There is a startup folder location for individual user accounts as well as a system-wide startup folder that will be checked regardless of which user account logs in
  * The startup folder path for the current user is `C:\Users\[Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
  * The startup folder path for all users is `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`

The following run keys are created by default on Windows systems:
`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce`
`HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`
`HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce`

Run keys may exist under multiple hives
* The `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx` is also available but is not created by default on Windows Vista and newer
* Registry run key entries can reference programs directly or list them as a dependency
  * It's possible to load a DLL at logon using a "Depend" key with RunOnceEx: `reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\temp\evil[.]dll`

The following Registry keys can be used to set startup folder items for persistence:
`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

The following Registry keys can control automatic startup of services during boot:
`HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
`HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices`
`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices`

Using policy settings to specify startup programs creates corresponding values in either of two Registry keys:
`HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`
`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`

**Winlogon Key** Controls actions that occur when a user logs on to a computer running Windows 7. Most of these actions are under the control of the operating system, but you can also add custom actions here. The `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit` and `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows` `NT\CurrentVersion\Winlogon\Shell` subkeys can automatically launch programs.

Programs listed in the load value of the registry key `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows` run when any user logs on

By default, the multistring *BootExecute* value of the registry key `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session` Manager is set to autocheck autochk *
* This value causes Windows, at startup, to check the file-system integrity of the hard disks if the system has been shut down abnormally
* Adversaries can add other programs or processes to this registry value which will automatically launch at boot

Adversaries can use these configuration locations to execute malware, such as remote access tools, to maintain persistence through system reboots. Adversaries may also use Masquerading to make the Registry entries look as if they are associated with legitimate programs.

## Authentication Package ##
Windows authentication package DLLs are loaded by the Local Security Authority (LSA) process at system start. They provide support for multiple logon processes and multiple security protocols to the operating system. 

Adversaries may abuse authentication packages to execute DLLs when the system boots
* Use the autostart mechanism provided by LSA authentication packages for persistence by placing a reference to a binary in the Windows Registry location `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\` with the key value of "Authentication Packages"=<target binary>
* The binary will then be executed by the system when the authentication packages are loaded

## Time Providers ##
The Windows Time service (W32Time) enables time synchronization across and within domains. W32Time time providers are responsible for retrieving time stamps from hardware/network resources and outputting these values to other network clients.


* Time providers are implemented as DLLs that are registered in the subkeys of `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\W32Time\TimeProviders\`
* The time provider manager, directed by the service control manager, loads and starts time providers listed and enabled under this key at system startup and/or whenever parameters are changed.

Adversaries may abuse this architecture to establish persistence, specifically by registering and enabling a malicious DLL as a time provider. Administrator privileges are required for time provider registration, though execution will run in context of the Local Service account.

## Winlogon Helper DLL ##
**Winlogon.exe:** A Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete
* Registry entries in `HKLM\Software[\Wow6432Node\]\Microsoft\Windows NT\CurrentVersion\Winlogon\` and `HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\` are used to manage additional helper programs and functionalities that support Winlogon

Adversaries may abuse features of Winlogon to execute DLLs and/or executables when a user logs in
* Malicious modifications to these Registry keys may cause Winlogon to load and execute malicious DLLs / executables

The following subkeys have been known to be possibly vulnerable to abuse: 
* **Winlogon\Notify** -- Points to notification package DLLs that handle Winlogon events
* **Winlogon\Userinit** -- Points to userinit.exe, the user initialization program executed when a user logs on
* **Winlogon\Shell** -- Points to explorer.exe, the system shell executed when a user logs on
  

## Security Support Provider ##
Windows Security Support Providers (SSPs) DLLs are loaded into the Local Security Authority (LSA) process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs.


The SSP configuration is stored in two Registry keys: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` and `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages`
* An adversary may modify these Registry keys to add new SSPs, which will be loaded the next time the system boots, or when the AddSecurityPackage Windows API function is called


### Procedure ###
* **Empire:** Enumerate SSPs and utilize PowerSploit's `Install-SSP` and `Invoke-Mimikatz` to install malicious SSPs and log authentication events
* **Mimikatz:** Mimikatz credential dumper contains an implementation of an SSP
* * **PowerSploit:** `Install-SSP` module can be used to establish persistence by installing an SSP DLL

### Mitigations Against This ###
Windows 8.1, Windows Server 2012 R2, and later versions may make LSA run as a Protected Process Light (PPL) by setting the Registry key `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL`, which requires all SSP DLLs to be signed by Microsoft.

### Bypassing ###

## Kernel Modules & Extensions ##
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


### Procedure ###
* **Drovorub:** Can be use kernel modules to establish persistence
* **Skidmap:** Has the ability to install several loadable kernel modules (LKMs) on infected systems


### Mitigations ###
* **Antivirus:** Common tools for detecting Linux rootkits include: rkhunter and chrootkit
* **Execution Prevention:** Application control and software restriction tools such as SELinux, KSPP, grsecurity MODHARDEN, and Linux kernel tuning can aid in restricting kernel module loading
* **Privileged Account Management:** Limits access to the root account and prevent users from loading kernel modules and extensions through proper privilege separation and limiting privilege escalation opportunities
* **User Account Management:** Use MDM to disable the user's ability to install or approve kernel extensions, and ensure all approved kernel extensions are in alignment with policies specified in `com.apple.syspolicy.kernel-extension-policy`

### Bypassing ###





## Re-Opened Applications ##

When a user logs out or restarts via the macOS Graphical User Interface (GUI), a prompt is provided to the user with a checkbox to "Reopen windows when logging back in". When selected, all applications currently open are added to a property list file named `com.apple.loginwindow.[UUID].plist` within the `~/Library/Preferences/ByHost` directory. Applications listed in this file are automatically reopened upon the user’s next logon.

* Adversaries may modify plist files to automatically run an application when a user logs in. 




### Procedure ###


### Mitigations ###
* **Disable or Remove Feature or Program:** This feature can be disabled entirely w/ the following command: `defaults write -g ApplePersistence -bool no`
* **User Training:** Holding the shift key while logging in prevents apps from opening automatically

### Bypassing ###




## LSASS Driver ##
The Windows security subsystem is a set of components that manage and enforce the security policy for a computer or domain. The Local Security Authority (LSA) is the main component responsible for local security policy and user authentication
* The LSA includes multiple DLLs associated with various other security functions, all of which run in the context of the LSA Subsystem Service (LSASS) `lsass.exe` process


Adversaries may target LSASS drivers to obtain persistence by either replacing or adding illegitimate drivers (e.g., Hijack Execution Flow), an adversary can use LSA operations to continuously execute malicious payloads


### Procedure ###
* **Pasam:** Establishes by infecting the SAM DLL to load a malicious DLL dropped to disk
* **Wingbird:** Drops a malicious file (sspisrv.dll) along a copy of the lsass.exe, which is used to register a service that loads sspisrv.dll as a driver. The payload of the malicious driver (located in its entry-point function) is executed when loaded by lsass.exe before the spoofed service becomes unstable and crashes.

### Mitigations ###
* **Credential Access Protection:** On Windows 10 and Server 2016, enable Windows Defender Credential Guard to run lsass.exe in an isolated virtualized environment without any device drivers
* * **Privileged Process Integrity:** On Windows 8.1 and Server 2012 R2, enable LSA Protection by setting the Registry key `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL` to dword:00000001. LSA Protection ensures that LSA plug-ins and drivers are only loaded if they are digitally signed with a Microsoft signature and adhere to the Microsoft Security Development Lifecycle (SDL) process guidance
* **Restrict Library Loading:** Ensure safe DLL search mode is enabled `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\SafeDllSearchMode` to mitigate risk that lsass.exe loads a malicious code library

### Bypassing ###



## Shortcut Modification ##
Shortcuts or symbolic links are ways of referencing other files or programs that will be opened or executed when the shortcut is clicked or executed by a system startup process.

Adversaries could use shortcuts to execute their tools for persistence. They may create a new shortcut as a means of indirection that may use Masquerading to look like a legitimate program. Adversaries could also edit the target path or entirely replace an existing shortcut so their tools will be executed instead of the intended legitimate program.




### Procedure ###
* **APT29:** Drops a Windows shortcut file for execution
* **APT39:** Has modified LNK shortcuts
* **Astaroth:** Astaroth's initial payload is a malicious .LNK file
* **BACKSPACE:** BACKSPACE achieves persistence by creating a shortcut to itself in the CSIDL_STARTUP directory
* **Bazar:** Bazar can establish persistence by writing shortcuts to the Windows Startup folder
* **BlackEnergy:** The BlackEnergy 3 variant drops its main DLL component and then creates a .lnk shortcut to that file in the startup folder
* **Comnie:** Comnie establishes persistence via a .lnk file in the victim’s startup path
* **Darkhotel:** Darkhotel has dropped an mspaint.lnk shortcut to disk which launches a shell script that downloads and executes a file
* **Dragonfly:** Dragonfly has manipulated .lnk files to gather user credentials in conjunction with Forced Authentication
* **Empire:** Empire can persist by modifying a .LNK file to include a backdoor
* **FELIXROOT:** FELIXROOT creates a .LNK file for persistence
* **Gazer:** Gazer can establish persistence by creating a .lnk file in the Start menu or by modifying existing .lnk files to execute the malware through cmd.exe
* **Gorgon Group:** Gorgon Group malware can create a .lnk file and add a Registry Run key to establish persistence
* **Grandoreiro:** Grandoreiro can write or modify browser shortcuts to enable launching of malicious browser extensions
* **Helminth:** Helminth establishes persistence by creating a shortcut
* **InvisiMole:** InvisiMole can use a .lnk shortcut for the Control Panel to establish persistence
* **Kazuar:** Kazuar adds a .lnk file to the Windows startup folder
* **KONNI:** A version of KONNI drops a Windows shortcut on the victim’s machine to establish persistence
* **Lazarus Group:** Lazarus Group malware has maintained persistence on a system by creating a LNK shortcut in the user’s Startup folder
* **Leviathan:** Leviathan has used JavaScript to create a shortcut file in the Startup folder that points to its main backdoor
* **MarkiRAT:** MarkiRAT can modify the shortcut that launches Telegram by replacing its path with the malicious payload to launch with the legitimate executable
* **Micropsia:** Micropsia creates a shortcut to maintain persistence
* **Okrum:** Okrum can establish persistence by creating a .lnk shortcut to itself in the Startup folder
* **Reaver:** Reaver creates a shortcut file and saves it in a Startup folder to establish persistence
* **RedLeaves:** RedLeaves attempts to add a shortcut file in the Startup folder to achieve persistence
* **RogueRobin:** RogueRobin establishes persistence by creating a shortcut (.LNK file) in the Windows startup folder to run a script each time the user logs in
* **S-Type:** S-Type may create the file `%HOMEPATH%\Start Menu\Programs\Startup\Realtek {Unique Identifier}.lnk`, which points to the malicious msdtc.exe file already created in the %CommonFiles% directory
* **SeaDuke:** SeaDuke is capable of persisting via a .lnk file stored in the Startup directory
* **SHIPSHAPE:** SHIPSHAPE achieves persistence by creating a shortcut in the Startup folder
* **SPACESHIP:** SPACESHIP achieves persistence by creating a shortcut in the current user's Startup folder
* **SslMM:** To establish persistence, SslMM identifies the Start Menu Startup directory and drops a link to its own executable disguised as an "Office Start," "Yahoo Talk," "MSN Gaming Z0ne," or "MSN Talk" shortcut
* **Stuxnet:** Stuxnet used copies of .lnk shortcuts to propagate through removable media
* **TinyZBot:** TinyZBot can create a shortcut in the Windows startup folder for persistence


### Mitigation ###
* **User Account Management:** Limit permissions for who can create symbolic links in Windows to appropriate groups such as Administrators and necessary groups for virtualization
  * This can be done through GPO: Computer Configuration > [Policies] > Windows Settings > Security Settings > Local Policies > User Rights Assignment: Create symbolic links

### Bypassing ###





## Port Monitors ##
Adversaries may use port monitors to run an adversary supplied DLL during system boot for persistence or privilege escalation. A port monitor can be set through the *AddMonitor* API call to set a DLL to be loaded at startup
* This DLL can be located in `C:\Windows\System32` and will be loaded by the print spooler service, spoolsv.exe, on boot
  * The spoolsv.exe process also runs under SYSTEM level permissions
  * Alternatively, an arbitrary DLL can be loaded if permissions allow writing a fully-qualified pathname for that DLL to `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors`

The Registry key contains entries for the following:

* Local Port
* Standard TCP/IP Port
* USB Monitor
* WSD Port


Adversaries can use this technique to load malicious code at startup that will persist on system reboot and execute as SYSTEM.


### Procedure ###


### Mitigation ###
This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.


### Bypassing ###


## Print Processes ##
Print processors are DLLs that are loaded by the print spooler service, spoolsv.exe, during boot

Adversaries may abuse the print spooler service by adding print processors that load malicious DLLs at startup
* A print processor can be installed through the *AddPrintProcessor* API call with an account that has *SeLoadDriverPrivilege* enabled
* Alternatively, a print processor can be registered to the print spooler service by adding the `HKLM\SYSTEM\[CurrentControlSet` or `ControlSet001]\Control\Print\Environments\[Windows architecture: e.g., Windows x64]\Print Processors\[user defined]\Driver` Registry key that points to the DLL
* For the print processor to be correctly installed, it must be located in the system print-processor directory that can be found with the *GetPrintProcessorDirectory* API call
* After the print processors are installed, the print spooler service, which starts during boot, must be restarted in order for them to run
  * The print spooler service runs under SYSTEM level permissions, therefore print processors installed by an adversary may run under elevated privileges


### Procedure ###
* **Gelsemium:** Gelsemium can drop itself in `C:\Windows\System32\spool\prtprocs\x64\winprint.dll` to be loaded automatically by the spoolsv Windows service
* **PipeMon:** The PipeMon installer has modified the Registry key `HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors` to install PipeMon as a Print Processor

### Mitigation ###
* **User Account Management:** Limit user accounts that can load or unload device drivers by disabling *SeLoadDriverPrivilege*

### Bypassing ###



## XDG Autostart Entries ##
Adversaries may modify XDG autostart entries to execute programs or commands during system boot. Linux desktop environments that are XDG compliant implement functionality for XDG autostart entries
* These entries will allow an application to automatically start during the startup of a desktop environment after user logon
* By default, XDG autostart entries are stored within the `/etc/xdg/autostart` or `~/.config/autostart` directories and have a .desktop file extension

Within an XDG autostart entry file, the *Type* key specifies if the entry is an application (type 1), link (type 2) or directory (type 3)

The *Name* key indicates an arbitrary name assigned by the creator and the Exec key indicates the application and command line arguments to execute

Adversaries may use XDG autostart entries to maintain persistence by executing malicious commands and payloads, such as remote access tools, during the startup of a desktop environment
* Commands included in XDG autostart entries with execute after user logon in the context of the currently logged on user
* Adversaries may also use Masquerading to make XDG autostart entries look as if they are associated with legitimate programs


### Procedure ###
* **Fysbis:** Fysbis has installed itself as an autostart entry under `~/.config/autostart/dbus-inotifier.desktop` to establish persistence
* **NETWIRE:** NETWIRE can use XDG Autostart Entries to establish persistence
  
### Mitigation ###
* **Limit Software Installation:** Restrict software installation to trusted repositories only and be cautious of orphaned software packages
* * **Restrict File & Directory Permissions:** Restrict write access to XDG autostart entries to only select privileged users
* * **User Account Management:** Limit privileges of user accounts so only authorized privileged users can create and modify XDG autostart entries

### Bypassing ###




## Active Setup ##
Active Setup is a Windows mechanism that is used to execute programs when a user logs in. The value stored in the Registry key will be executed after a user logs into the computer. These programs will be executed under the context of the user and will have the account's associated permissions level

Adversaries may abuse Active Setup by creating a key under `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\` and setting a malicious value for *StubPath* -- This value will serve as the program that will be executed when a user logs into the computer

Adversaries can abuse these components to execute malware, such as remote access tools, to maintain persistence through system reboots. Adversaries may also use Masquerading to make the Registry entries look as if they are associated with legitimate programs.

### Procedure ###
* **PoisonIvy:** Creates a Registry key in the Active Setup pointing to a malicious executable

### Mitigation ###
This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features

### Bypassing ###






## Login Items ##
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


### Procedure ###
* **Dok:** Uses AppleScript to install a login Item by sending Apple events to the System Events process
* **Green Lambert:** Can add Login Items to establish persistence
* **NETWIRE:** NETWIRE can persist via startup options for Login items


### Mitigation ###
This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features


### Bypassing ###





----------------------------------------
# Boot or Logon Initialization Scripts #
Initialization scripts can be used to perform administrative functions, which may often execute other programs or send information to an internal logging server

Adversaries may use these scripts to maintain persistence on a single system. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary
* An adversary may also be able to escalate their privileges since some boot or logon initialization scripts run with higher privileges

## Logon Script (Windows) ##
Windows allows logon scripts to be run whenever a specific user or group of users log into a system
* This is done via adding a path to a script to the `HKCU\Environment\UserInitMprLogonScript` Registry key

Adversaries may use these scripts to maintain persistence on a single system. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary.


### Procedure ###
* **APT28:** An APT28 loader Trojan adds the Registry key `HKCU\Environment\UserInitMprLogonScript` to establish persistence
* **Attor:** Attor's dispatcher can establish persistence via adding a Registry key with a logon script `HKEY_CURRENT_USER\Environment` "UserInitMprLogonScript"
* **Cobalt Group:** Cobalt Group has added persistence by registering the file name for the next stage malware under `HKCU\Environment\UserInitMprLogonScript`
* **JHUHUGIT:** JHUHUGIT has registered a Windows shell script under the Registry key `HKCU\Environment\UserInitMprLogonScript` to establish persistence
* **KGH_SPY:** KGH_SPY has the ability to set the `HKCU\Environment\UserInitMprLogonScript` Registry key to execute logon scripts
* **Zebrocy:** Zebrocy performs persistence with a logon script via adding to the Registry key `HKCU\Environment\UserInitMprLogonScript`


### Mitigation ###
* **Restrict Registry Permissions:** Ensure proper permissions are set for Registry hives to prevent users from modifying keys for logon scripts that may lead to persistence

### Bypassing ###



## Login Hook ##
**Login hook:** A plist file that points to a specific script to execute with root privileges upon user logon
* The plist file is located in the `/Library/Preferences/com.apple.loginwindow.plist` file and can be modified using the defaults command-line utility
* This behavior is the same for logout hooks where a script can be executed upon user logout. All hooks require administrator permissions to modify or create hooks

Adversaries can add or insert a path to a malicious script in the `com.apple.loginwindow.plist` file, using the *LoginHook* or *LogoutHook* key-value pair
* The malicious script is executed upon the next user login
* If a login hook already exists, adversaries can add additional commands to an existing login hook
  * There can be only one login and logout hook on a system at a time

**Note: Login hooks were deprecated in 10.11 version of macOS in favor of Launch Daemon and Launch Agent**

### Procedure ###


### Mitigations ###
* **Restrict File and Directory Permissions:** Restrict write access to logon scripts to specific administrators

### Bypass ###

## Network Logon Script ##
Network logon scripts can be assigned using Active Directory or Group Policy Objects. These logon scripts run with the privileges of the user they are assigned to. Depending on the systems within the network, initializing one of these scripts could apply to more than one or potentially all systems.

Adversaries may use these scripts to maintain persistence on a network. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary.


### Procedure ###


### Mitigation ###
* **Restrict File & Directory Permissions:** Restrict write access to logon scripts to specific administrators

### Bypassing ###





## RC Scripts ##
Adversaries may establish persistence by modifying RC scripts which are executed during a Unix-like system’s startup. These files allow system administrators to map and start custom services at startup for different run levels. RC scripts require root privileges to modify.

Adversaries can establish persistence by adding a malicious binary path or shell commands to rc.local, rc.common, and other RC scripts specific to the Unix-like distribution. Upon reboot, the system executes the script's contents as root, resulting in persistence.

Adversary abuse of RC scripts is especially effective for lightweight Unix-like distributions using the root user as default, such as **IoT or embedded systems**

Several Unix-like systems have moved to Systemd and deprecated the use of RC scripts. 
**This technique can be used on Mac OS X Panther v10.3 and earlier versions which still execute the RC scripts.**
* To maintain backwards compatibility some systems, such as Ubuntu, will execute the RC scripts if they exist with the correct file permissions



### Procedure ###
* **Cyclops Blink:** Has the ability to execute on device startup, using a modified RC script named S51armled
* **Green Lambert:** Green Lambert can add init.d and rc.d files in the /etc folder to establish persistence
* **HiddenWasp:** HiddenWasp installs reboot persistence by adding itself to /etc/rc.local
* **iKitten:** iKitten adds an entry to the rc.common file for persistence

### Mitigation ###
* **Restrict File and Directory Permissions:** Limit privileges of user accounts so only authorized users can edit the rc.common file

### Bypassing ###




## Startup Items ##
Startup items execute during the final phase of the boot process and contain shell scripts or other executable files along with configuration information used by the system to determine the execution order for all startup items

This is technically a deprecated technology (superseded by Launch Daemon), and thus the appropriate folder, /Library/StartupItems isn’t guaranteed to exist on the system by default, but does appear to exist by default on macOS Sierra
* A startup item is a directory whose executable and configuration property list (plist), StartupParameters.plist, reside in the top-level directory

An adversary can create the appropriate folders/files in the StartupItems directory to register their own persistence mechanism. Additionally, since StartupItems run during the bootup phase of macOS, they will run as the elevated root user


### Procedure ###
* **jRAT:** jRAT can list and manage startup entries

### Mitigation ###
* **Restrict File and Directory Permissions:** Since StartupItems are deprecated, preventing all users from writing to the /Library/StartupItems directory would prevent any startup items from getting registered

### Bypassing ###


----------------------
# Browser Extensions #
Browser extensions or plugins are small programs that can add functionality and customize aspects of Internet browsers. They can be installed directly or through a browser's app store and generally have access and permissions to everything that the browser can access

Malicious extensions can be installed into a browser through malicious app store downloads masquerading as legitimate extensions, through social engineering, or by an adversary that has already compromised a system. 

In macOS 11+, the use of the profiles tool can no longer install configuration profiles, however .mobileconfig files can be planted and installed with user interaction

Once installed, it can browse to websites in the background, steal all information that a user enters into a browser (including credentials), and be used as an installer for a RAT for persistence




### Procedure ###
* **Bundlore:** Bundlore can install malicious browser extensions that are used to hijack user searches
* **Grandoreiro:** Grandoreiro can use malicious browser extensions to steal cookies and other user information
* **Kimsuky:** Kimsuky has used Google Chrome browser extensions to infect victims and to steal passwords and cookies
* **OSX/Shlayer:** OSX/Shlayer can install malicious Safari browser extensions to serve ads

### Mitigation ###
* **Audit:** Ensure extensions that are installed are the intended ones as many malicious extensions will masquerade as legitimate ones
* **Execution Prevention:** Set a browser extension allow or deny list as appropriate for your security policy
* **Limit Software Installation:** Only install browser extensions from trusted sources that can be verified. Browser extensions for some browsers can be controlled through Group Policy. Change settings to prevent the browser from installing extensions without sufficient permissions
* **Update Software:** Ensure operating systems and browsers are using the most current version
* **User Training:** Close out all browser sessions when finished using them to prevent any potentially malicious extensions from continuing to run



### Bypassing ###



-------------------------------------
# Compromise Client Software Binary #
Client software enables users to access services provided by a server. Common client software types are SSH clients, FTP clients, email clients, and web browsers.

Adversaries may make modifications to client software binaries to carry out malicious tasks when those applications are in use. For example, an adversary may copy source code for the client software, add a backdoor, compile for the target, and replace the legitimate application binary (or support files) with the backdoored one. Since these applications may be routinely executed by the user, the adversary can leverage this for persistent access to the host.

### Procedure ###
* **Bonadan:** Bonadan has maliciously altered the OpenSSH binary on targeted systems to create a backdoor
* **Ebury:** Ebury has been embedded into modified OpenSSH binaries to gain persistent access to SSH credential information
* **Industroyer:** Industroyer has used a Trojanized version of the Windows Notepad application for an additional backdoor persistence mechanism
* **Kessel:** Kessel has maliciously altered the OpenSSH binary on targeted systems to create a backdoor
* **Kobalos:** Kobalos replaced the SSH client with a trojanized SSH client to steal credentials on compromised systems
* **ThiefQuest:** ThiefQuest searches through the /Users/ folder looking for executable files. For each executable, ThiefQuest prepends a copy of itself to the beginning of the file
  * When the file is executed, the ThiefQuest code is executed first. ThiefQuest creates a hidden file, copies the original target executable to the file, then executes the new hidden file to maintain the appearance of normal behavior
* **XCSSET:** XCSSET uses a malicious browser application to replace the legitimate browser in order to continuously capture credentials, monitor web traffic, and download additional modules



### Mitigation ###
* **Code Signing:** Ensure all application component binaries are signed by the correct application developers


### Bypassing ###

------------------
# Create Account #
With a sufficient level of access, creating such accounts may be used to establish secondary credentialed access that do not require persistent remote access tools to be deployed on the system.

Accounts may be created on the local system or within a domain or cloud tenant. In cloud environments, adversaries may create accounts that only have access to specific services, which can reduce the chance of detection.

## Local Account ##
Adversaries may create a local account to maintain access to victim systems. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service. With a sufficient level of access, the net user /add command can be used to create a local account. On macOS systems the dscl -create command can be used to create a local account.

Such accounts may be used to establish secondary credentialed access that do not require persistent remote access tools to be deployed on the system.

### Procedure ###
* **APT3:** has been known to create or enable accounts, such as support_388945a0
* **APT39:** APT39 has created accounts on multiple compromised hosts to perform actions within the network
* **APT41:** APT41 created user accounts and adds them to the User and Admin groups
* **Calisto:** Calisto has the capability to add its own account to the victim's machine
* **Carbanak:** Carbanak can create a Windows account
* **Dragonfly:** Dragonfly has created accounts on victims, including administrator accounts, some of which appeared to be tailored to each individual staging target
* **Empire:** Empire has a module for creating a local user if permissions allow
* **Flame:** Flame can create backdoor accounts with login "HelpAssistant" on domain connected systems if appropriate rights are available
* **Fox Kitten:** Fox Kitten has created a local user account with administrator privileges
* **GoldenSpy:** GoldenSpy can create new users on an infected system
* **HiddenWasp:** HiddenWasp creates a user account as a means to provide initial persistence to the compromised machine
* **Hildegard:** Hildegard has created a user named "monerodaemon"
* **Kimsuky:** Kimsuky has created accounts with net user
* **Leafminer:** Leafminer used a tool called Imecab to set up a persistent remote access account on the victim machine
* **Mis-Type:** Mis-Type may create a temporary user on the system named "Lost_{Unique Identifier}."
* **Net:** The net user username \password commands in Net can be used to create a local account
* **Pupy:** Pupy can user PowerView to execute "net user" commands and create local system accounts
* **S-Type:** S-Type may create a temporary user on the system named "Lost_{Unique Identifier}" with the password "pond~!@6"{Unique Identifier}"
* **ServHelper:** ServHelper has created a new user and added it to the "Remote Desktop Users" and "Administrators" groups
* **SMOKEDHAM:** SMOKEDHAM has created user accounts and added them to local Admin groups
* **TeamTNT:** TeamTNT has created local privileged users on victim machines
* **ZxShell:** ZxShell has a feature to create local user accounts


### Mitigation ###
* **Multi-factor Authentication:** Use multi-factor authentication for user and privileged accounts
* **Privileged Account Management:** Limit the usage of local administrator accounts to be used for day-to-day operations that may expose them to potential adversaries


### Bypassing ###



## Domain Account ##
Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain. Domain accounts can cover user, administrator, and service accounts. With a sufficient level of access, the `net user /add /domain` command can be used to create a domain account


### Procedure ###
* **Empire:** Empire has a module for creating a new domain user if permissions allow
* **GALLIUM:** GALLIUM created high-privileged domain user accounts to maintain access to victim networks
* **HAFNIUM:** HAFNIUM has created and granted privileges to domain accounts
* **Net:** The `net user username \password \domain` commands in Net can be used to create a domain account
* **PsExec:** PsExec has the ability to remotely create accounts on target systems
* **Pupy:** Pupy can user PowerView to execute "net user" commands and create domain accounts
* **Sandworm Team:** Sandworm Team has created new domain accounts on an ICS access server

### Mitigation ###
* **Multi-factor Authentication:** Use multi-factor authentication for user and privileged accounts
* **Network Segmentation:** Configure access controls and firewalls to limit access to domain controllers and systems used to create and manage accounts
* **Operating System Configuration:** Protect domain controllers by ensuring proper security configuration for critical servers
* **Privileged Account Management:** Do not allow domain administrator accounts to be used for day-to-day operations that may expose them to potential adversaries on unprivileged systems



### Bypassing ###


## Cloud Account ##
Adversaries may create a cloud account to maintain access to victim systems. With a sufficient level of access, such accounts may be used to establish secondary credentialed access that does not require persistent remote access tools to be deployed on the system

Adversaries may create accounts that only have access to specific cloud services, which can reduce the chance of detection

### Procedure ###
* **AADInternals:** AADInternals can create new Azure AD users
* **APT29:** APT29 can create new users through Azure AD


### Mitigation ###
* **Multi-factor Authentication:** Use multi-factor authentication for user and privileged accounts
* **Network Segmentation:** Configure access controls and firewalls to limit access to critical systems and domain controllers. Most cloud environments support separate virtual private cloud (VPC) instances that enable further segmentation of cloud systems
* **Privileged Account Management:** Do not allow privileged accounts to be used for day-to-day operations that may expose them to potential adversaries on unprivileged systems



### Bypassing ###







-------------------------------------
# Create or Modify System Processes #
When operating systems boot up, they can start processes that perform background system functions. On Windows and Linux, these system processes are referred to as services. On macOS, launchd processes known as Launch Daemon and Launch Agent are run to finish system initialization and load user specific parameters

Adversaries may install new services, daemons, or agents that can be configured to execute at startup or a repeatable interval in order to establish persistence
* Attackers may modify existing services, daemons, or agents to achieve the same effect
* Services, daemons, or agents may be created with administrator privileges but executed under root/SYSTEM privileges
* Adversaries may leverage this functionality to create or modify system processes in order to escalate privileges


## Launch Agent ##
When a user logs in, a per-user launchd process is started which loads the parameters for each launch-on-demand user agent from the property list (.plist) file found in `/System/Library/LaunchAgents`, `/Library/LaunchAgents`, and `~/Library/LaunchAgents`. Property list files use the *Label*, *ProgramArguments* , and R*unAtLoad* keys to identify the Launch Agent's name, executable location, and execution time. Launch Agents are often installed to perform updates to programs, launch user specified programs at login, or to conduct other developer tasks


Adversaries may install a new Launch Agent that executes at login by placing a .plist file into the appropriate folders with the R*unAtLoad* or *KeepAlive* keys set to true. The Launch Agent name may be disguised by using a name from the related operating system or benign software. Launch Agents are created with user level privileges and execute with user level permissions


### Procedure ###
* **Bundlore:** Bundlore can persist via a LaunchAgent
* **Calisto:** Calisto adds a .plist file to the `/Library/LaunchAgents` folder to maintain persistence
* **CoinTicker:** CoinTicker creates user launch agents named *.espl.plist* and *com.apple.[random string].plist* to establish persistence
* **CookieMiner:** CookieMiner has installed multiple new Launch Agents in order to maintain persistence for cryptocurrency mining software
* **CrossRAT:** CrossRAT creates a Launch Agent on macOS
* **Dacls:** Dacls can establish persistence via a LaunchAgent
* **Dok:** Dok installs two LaunchAgents to redirect all network traffic with a randomly generated name for each plist file maintaining the format *com.random.name.plist.*
* **FruitFly:** FruitFly persists via a Launch Agent
* **Green Lambert:** Green Lambert can create a Launch Agent with the RunAtLoad key-value pair set to true, ensuring the *com.apple.GrowlHelper.plist* file runs every time a user logs in
* **Keydnap:** Keydnap uses a Launch Agent to persist
* **Komplex:** The Komplex trojan creates a persistent launch agent called with *$HOME/Library/LaunchAgents/com.apple.updates.plist* with `launchctl load -w ~/Library/LaunchAgents/com.apple.updates.plist`
* **MacSpy:** MacSpy persists via a Launch Agent
* **NETWIRE:** NETWIRE can use launch agents for persistence
* **OSX_OCEANLOTUS.D:** OSX_OCEANLOTUS.D can create a persistence file in the folder */Library/LaunchAgents*
* **Proton:** Proton persists via Launch Agent
* **ThiefQuest:** ThiefQuest installs a launch item using an embedded encrypted launch agent property list template. The plist file is installed in the *~/Library/LaunchAgents/* folder and configured with the path to the persistent binary located in the ~/Library/ folder

### Mitigation ###
* **Restrict File and Directory Permissions:** Set group policies to restrict file permissions to the ~/launchagents folder

### Bypassing ###




## Systemd Service ##
The systemd service manager is commonly used for managing background daemon processes (services) and other system resources.

Systemd utilizes configuration files known as service units to control how services boot and under what conditions. By default, these unit files are stored in the `/etc/systemd/system` and `/usr/lib/systemd/system` directories and have the file extension *.service*. Each service unit file may contain numerous directives that can execute system commands:

* *ExecStart, ExecStartPre, and ExecStartPost* directives cover execution of commands when a services is started manually by 'systemctl' or on system start if the service is set to automatically start
  * ExecReload directive covers when a service restarts
  * ExecStop and ExecStopPost directives cover when a service is stopped or manually by 'systemctl'
  
Adversaries have used systemd functionality to establish persistent access to victim systems by creating and/or modifying service unit files that cause systemd to execute malicious commands at system boot

While adversaries typically require root privileges to create/modify service unit files in the /etc/systemd/system and /usr/lib/systemd/system directories, low privilege users can create/modify service unit files in directories such as ~/.config/systemd/user/ to achieve user-level persistence



### Procedure ###
* **Exaramel for Linux:** Exaramel for Linux has a hardcoded location under systemd that it uses to achieve persistence if it is running as root
* **Fysbis:** Fysbis has established persistence using a systemd service
* **Hildegard:** Hildegard has started a monero service
* **Pupy:** Pupy can be used to establish persistence using a systemd service
* **Rocke:** Rocke has installed a systemd service script to maintain persistence
* **TeamTNT:** TeamTNT has established persistence through the creation of a cryptocurrency mining system service

### Mitigation ###
* **Limit Software Installation:** Restrict software installation to trusted repositories only and be cautious of orphaned software packages
* **Privileged Account Management:** The creation and modification of systemd service unit files is generally reserved for administrators such as the Linux root user and other users with superuser privileges
* **Restrict File and Directory Permissions:** Restrict read/write access to systemd unit files to only select privileged users who have a legitimate need to manage system services
* **User Account Management:** Limit user access to system utilities such as 'systemctl' to only users who have a legitimate need

### Bypassing ###






## Windows Service ##
Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence. When Windows boots up, it starts programs or applications called services that perform background system functions.[1] Windows service configuration information, including the file path to the service's executable or recovery programs/commands, is stored in the Windows Registry.

Adversaries may install a new service or modify an existing service to execute at startup in order to persist on a system. Service configurations can be set or modified using system utilities (such as sc.exe), by directly modifying the Registry, or by interacting directly with the Windows API.

Adversaries may also use services to install and execute malicious drivers. For example, after dropping a driver file (ex: .sys) to disk, the payload can be loaded and registered via Native API functions such as CreateServiceW() (or manually via functions such as ZwLoadDriver() and ZwSetValueKey()), by creating the required service Registry values (i.e. Modify Registry), or by using command-line utilities such as PnPUtil.exe.[2][3][4] Adversaries may leverage these drivers as Rootkits to hide the presence of malicious activity on a system. Adversaries may also load a signed yet vulnerable driver onto a compromised machine (known as "Bring Your Own Vulnerable Driver" (BYOVD)) as part of Exploitation for Privilege Escalation.[5][4]

Services may be created with administrator privileges but are executed under SYSTEM privileges, so an adversary may also use a service to escalate privileges. Adversaries may also directly start services through Service Execution. To make detection analysis more challenging, malicious services may also incorporate Masquerade Task or Service (ex: using a service and/or payload name related to a legitimate OS or benign software component)


### Procedure ###
* **Anchor:** Anchor can establish persistence by creating a service
* AppleJeus:** AppleJeus can install itself as a service
* **APT19:** An APT19 Port 22 malware variant registers itself as a service
* **APT3:** APT3 has a tool that creates a new service for persistence
* **APT32:** APT32 modified Windows Services to ensure PowerShell scripts were loaded on the system. APT32 also creates a Windows service to establish persistence
* **APT38:** APT38 has installed a new Windows service to establish persistence
* **APT41:** APT41 modified legitimate Windows services to install malware backdoors
  * APT41 created the StorSyncSvc service to provide persistence for Cobalt Strike
* **Attor:** Attor's dispatcher can establish persistence by registering a new service
* **AuditCred:** AuditCred is installed as a new service on the system
* **Bankshot:** Bankshot can terminate a specific process by its process id
* **BBSRAT:** BBSRAT can modify service configurations
* **Bisonal:** Bisonal has been modified to be used as a Windows service
* **BitPaymer:** BitPaymer has attempted to install itself as a service to maintain persistence
* **BlackEnergy:** One variant of BlackEnergy creates a new service using either a hard-coded or randomly generated name
* **Blue Mockingbird:** Blue Mockingbird has made their XMRIG payloads persistent as a Windows Service
* **Briba:** Briba installs a service pointing to a malicious DLL dropped to disk
* **Carbanak:** Carbanak malware installs itself as a service to provide persistence and SYSTEM privileges
* **Carbon:** Carbon establishes persistence by creating a service and naming it based off the operating system version running on the current machine
* **Catchamas:** Catchamas adds a new service named NetAdapter to establish persistence
* **Clambling:** Clambling can register itself as a system service to gain persistence
* **Cobalt Group:** Cobalt Group has created new services to establish persistence
* **Cobalt Strike:** Cobalt Strike can install a new service
* **Conficker:** Conficker copies itself into the %systemroot%\system32 directory and registers as a service
* **CosmicDuke:** CosmicDuke uses Windows services typically named "javamtsup" for persistence
* **CozyCar:** One persistence mechanism used by CozyCar is to register itself as a Windows service
* **Cuba:** Cuba can modify services by using the OpenService and ChangeServiceConfig functions
* **DarkVishnya:** DarkVishnya created new services for shellcode loaders distribution
* **Dtrack:** Dtrack can add a service called WBService to establish persistence
* **Duqu:** Duqu creates a new service that loads a malicious driver when the system starts. When Duqu is active, the operating system believes that the driver is legitimate, as it has been signed with a valid private key
* **Dyre:** Dyre registers itself as a service by adding several Registry keys
* **Elise:** Elise configures itself as a service
* **Emissary:** Emissary is capable of configuring itself as a service
* **Emotet:** Emotet has been observed creating new services to maintain persistence
* **Empire:** Empire can utilize built-in modules to modify service binaries and restore them to their original state
* **Exaramel for Windows:** The Exaramel for Windows dropper creates and starts a Windows service named wsmprovav with the description "Windows Check AV"
* **FALLCHILL:** FALLCHILL has been installed as a Windows service
* **FIN7:** FIN7 created new Windows services and added them to the startup directories for persistence
* **FinFisher:** FinFisher creates a new Windows service with the malicious executable for persistence
* **Gelsemium:** Gelsemium can drop itself in `C:\Windows\System32\spool\prtprocs\x64\winprint.dll` as an alternative Print Processor to be loaded automatically when the spoolsv Windows service starts
* **gh0st RAT:** gh0st RAT can create a new service to establish persistence
* **GoldenSpy:** GoldenSpy has established persistence by running in the background as an autostart service
* **GreyEnergy:** GreyEnergy chooses a service, drops a DLL file, and writes it to that serviceDLL Registry key
* **hcdLoader:** hcdLoader installs itself as a service for persistence
* **HermeticWiper:** HermeticWiper can load drivers by creating a new service using the CreateServiceW API
* **Honeybee:** Honeybee has batch files that modify the system service COMSysApp to load a malicious DLL
* **Hydraq:** Hydraq creates new services to establish persistence
* **Industroyer:** Industroyer can use an arbitrary system service to load at system boot for persistence and replaces the ImagePath registry value of a Windows service with a new backdoor binary
* **InnaputRAT:** Some InnaputRAT variants create a new Windows service to establish persistence
* **InvisiMole:** InvisiMole can register a Windows service named CsPower as part of its execution chain, and a Windows service named *clr_optimization_v2.0.51527_X86* to achieve persistence
* **JHUHUGIT:** JHUHUGIT has registered itself as a service to establish persistence
* **Kazuar:** Kazuar can install itself as a new service
* **Ke3chang:** Ke3chang backdoor RoyalDNS established persistence through adding a service called Nwsapagent
* **KeyBoy:** KeyBoy installs a service pointing to a malicious DLL dropped to disk
* **Kimsuky:** Kimsuky has created new services for persistence
* **KONNI:** KONNI has registered itself as a service using its export function
* **Kwampirs:** Kwampirs creates a new service named WmiApSrvEx to establish persistence
* **Lazarus Group:** Several Lazarus Group malware families install themselves as new services
* **LoudMiner:** LoudMiner can automatically launch a Linux virtual machine as a service at startup if the AutoStart option is enabled in the VBoxVmService configuration file
* **MoonWind:** MoonWind installs itself as a new service with automatic startup to establish persistence. The service checks every 60 seconds to determine if the malware is running; if not, it will spawn a new instance
* **Naid:** Naid creates a new service to establish
* **Nebulae:** Nebulae can create a service to establish persistence
* **Nerex:** Nerex creates a Registry subkey that registers a new service
* **Nidiran:** Nidiran can create a new service named msamger (Microsoft Security Accounts Manager)
* **Okrum:** To establish persistence, Okrum can install itself as a new service named NtmSsvc
* **Pandora:** Pandora has the ability to gain system privileges through Windows services
* **PipeMon:** PipeMon can establish persistence by registering a malicious DLL as an alternative Print Processor which is loaded when the print spooler service starts
* **PlugX:** PlugX can be added as a service to establish persistence. PlugX also has a module to change service configurations as well as start, control, and delete services
* **PoisonIvy:** PoisonIvy creates a Registry subkey that registers a new service. PoisonIvy also creates a Registry entry modifying the Logical Disk Manager service to point to a malicious DLL dropped to disk
* **PowerSploit:** PowerSploit contains a collection of Privesc-PowerUp modules that can discover and replace/modify service binaries, paths, and configs
* **PROMETHIUM:** PROMETHIUM has created new services and modified existing services for persistence
* **PsExec:** PsExec can leverage Windows services to escalate privileges from administrator to SYSTEM with the -s argument
* **Ragnar Locker:** Ragnar Locker has used sc.exe to create a new service for the VirtualBox driver
* **RainyDay:** RainyDay can use services to establish persistence
* **RawPOS:** RawPOS installs itself as a service to maintain persistence
* **RDAT:** RDAT has created a service when it is installed on the victim machine
* **Reaver:** Reaver installs itself as a new service
* **Sakula:** Some Sakula samples install themselves as services for persistence by calling WinExec with the net start argument
* **Seasalt:** Seasalt is capable of installing itself as a service
* **Shamoon:** Shamoon creates a new service named "ntssrv" to execute the payload. Newer versions create the "MaintenaceSrv" and "hdv_725x" services
* **ShimRat:** ShimRat has installed a Windows service to maintain persistence on victim machines
* **SILENTTRINITY:** SILENTTRINITY can establish persistence by creating a new service
* **SLOTHFULMEDIA:** SLOTHFULMEDIA has created a service on victim machines named "TaskFrame" to establish persistence
* **StreamEx:** StreamEx establishes persistence by installing a new service pointing to its DLL and setting the service to auto-start
* **StrongPity:** StrongPity has created new services and modified existing services for persistence
* **Stuxnet:** Stuxnet uses a driver registered as a boot start service as the main load-point
* **SysUpdate:** SysUpdate can create a service to establish persistence
* **TDTESS:** If running as administrator, TDTESS installs itself as a new service named bmwappushservice to establish persistence
* **TeamTNT:** TeamTNT uses malware that adds cryptocurrency miners as a service
* **TEARDROP:** TEARDROP ran as a Windows service from the c:\windows\syswow64 folder
* **Threat Group-3390:** A Threat Group-3390 tool can create a new service, naming it after the config information, to gain persistence
* **ThreatNeedle:** ThreatNeedle can run in memory and register its payload as a Windows service
* **TinyZBot:** TinyZBot can install as a Windows service for persistence
* **TrickBot:** TrickBot establishes persistence by creating an autostart service that allows it to run whenever the machine boots
* **Tropic Trooper:** Tropic Trooper has installed a service pointing to a malicious DLL dropped to disk
* **TYPEFRAME:** TYPEFRAME variants can add malicious DLL modules as new services.TYPEFRAME can also delete services from the victim’s machine
* **Ursnif:** Ursnif has registered itself as a system service in the Registry for automatic execution at system startup
* **Volgmer:** Volgmer installs a copy of itself in a randomly selected service, then overwrites the ServiceDLL entry in the service's Registry entry. Some Volgmer variants also install .dll files as services with names generated by a list of hard-coded strings
* **WannaCry:** WannaCry creates the service "mssecsvc2.0" with the display name "Microsoft Security Center (2.0) Service"
* **WastedLocker:** WastedLocker created and established a service that runs until the encryption process is complete
* **Wiarp:** Wiarp creates a backdoor through which remote attackers can create a service
* **Wingbird:** Wingbird uses services.exe to register a new autostart service named "Audit Service" using a copy of the local lsass.exe file
* **Winnti for Windows:**	Winnti for Windows sets its DLL file as a new service in the Registry to establish persistence
* **Wizard Spider:** Wizard Spider has installed TrickBot as a service named ControlServiceA in order to establish persistence
* **ZeroT:** ZeroT can add a new service to ensure PlugX persists on the system when delivered as another payload onto the system
* **ZLib:** ZLib creates Registry keys to allow itself to run as various services
* **zwShell:** zwShell has established persistence by adding itself as a new service
* **ZxShell:** ZxShell can create a new service using the service parser function ProcessScCommand



### Mitigation ###
* **Audit:** Use auditing tools capable of detecting privilege and service abuse opportunities on systems within an enterprise and correct them
* **Behavior Prevention on Endpoint:** On Windows 10, enable Attack Surface Reduction (ASR) rules to prevent an application from writing a signed vulnerable driver to the system. On Windows 10 and 11, enable Microsoft Vulnerable Driver Blocklist to assist in hardening against third party-developed service drivers.
* **Code Signing:** Enforce registration and execution of only legitimately signed service drivers where possible
* **Operating System Configuration:** Ensure that Driver Signature Enforcement is enabled to restrict unsigned drivers from being installed
* **User Account Management:** Limit privileges of user accounts and groups so that only authorized administrators can interact with service changes and service configurations



### Bypassing ###



## Launch Daemon ## 
Adversaries may create or modify Launch Daemons to execute malicious payloads as part of persistence. Launch Daemons are plist files used to interact with Launchd, the service management framework used by macOS. Launch Daemons require elevated privileges to install, are executed for every user on a system prior to login, and run in the background without the need for user interaction. During the macOS initialization startup, the launchd process loads the parameters for launch-on-demand system-level daemons from plist files found in /System/Library/LaunchDaemons/ and /Library/LaunchDaemons/. Required Launch Daemons parameters include a Label to identify the task, Program to provide a path to the executable, and RunAtLoad to specify when the task is run. Launch Daemons are often used to provide access to shared resources, updates to software, or conduct automation tasks

Adversaries may install a Launch Daemon configured to execute at startup by using the RunAtLoad parameter set to true and the Program parameter set to the malicious executable path. The daemon name may be disguised by using a name from a related operating system or benign software (i.e. Masquerading). When the Launch Daemon is executed, the program inherits administrative permissions

Additionally, system configuration changes (such as the installation of third party package managing software) may cause folders such as usr/local/bin to become globally writeable. So, it is possible for poor configurations to allow an adversary to modify executables referenced by current Launch Daemon's plist files



### Procedure ###
* **AppleJeus:** AppleJeus has placed a plist file within the LaunchDaemons folder and launched it manually
* **Bundlore:** Bundlore can persist via a LaunchDaemon
* **Dacls:** Dacls can establish persistence via a Launch Daemon
* **Green Lambert:** Green Lambert can add a plist file in the Library/LaunchDaemons to establish persistence
* **LoudMiner:** LoudMiner adds plist files with the naming format com.[random_name].plist in the /Library/LaunchDaemons folder with the RunAtLoad and KeepAlive keys set to true
* **OSX_OCEANLOTUS.D:** If running with root permissions, OSX_OCEANLOTUS.D can create a persistence file in the folder /Library/LaunchDaemons
* **ThiefQuest:** When running with root privileges after a Launch Agent is installed, ThiefQuest installs a plist file to the /Library/LaunchDaemons/ folder with the RunAtLoad key set to true establishing persistence as a Launch Daemon
* **XCSSET:** XCSSET uses the ssh launchdaemon to elevate privileges, bypass system controls, and enable remote access to the victim

### Mitigation ###
* **Audit:** Use auditing tools capable of detecting folder permissions abuse opportunities on systems, especially reviewing changes made to folders by third-party software
* **User Account Management:** Limit privileges of user accounts and remediate Privilege Escalation vectors so only authorized administrators can create new Launch Daemons

### Bypassing ###





-----------------------------
# Event Triggered Execution #
Adversaries may establish persistence and/or elevate privileges using system mechanisms that trigger execution based on specific events. Various operating systems have means to monitor and subscribe to events such as logons or other user activity such as running specific applications/binaries.

Adversaries may abuse these mechanisms as a means of maintaining persistent access to a victim via repeatedly executing malicious code. After gaining access to a victim system, adversaries may create/modify event triggers to point to malicious content that will be executed whenever the event trigger is invoked

Since the execution can be proxied by an account with higher permissions, such as SYSTEM or service accounts, an adversary may be able to abuse these triggered execution mechanisms to escalate their privileges.

## Change Default File Allocation ##
When a file is opened, the default program used to open the file (file association or handler) is checked. File association selections are stored in the Windows Registry and can be edited by users, administrators, or programs that have Registry access or by administrators using the built-in assoc utility. Applications can modify the file association for a given file extension to call an arbitrary program when a file with the given extension is opened.

System file associations are listed under `HKEY_CLASSES_ROOT.[extension]`
* The entries point to a handler for that extension located at `HKEY_CLASSES_ROOT\[handler]`
* The various commands are then listed as subkeys underneath the shell key at `HKEY_CLASSES_ROOT\[handler]\shell\[action]\command`; For example:

* `HKEY_CLASSES_ROOT\txtfile\shell\open\command`
* `HKEY_CLASSES_ROOT\txtfile\shell\print\command`
* `HKEY_CLASSES_ROOT\txtfile\shell\printto\command`
The values of the keys listed are commands that are executed when the handler opens the file extension. Adversaries can modify these values to continually execute arbitrary commands

### Procedure ###
* **Kimsuky:** Has a HWP document stealer module which changes the default program association in the registry to open HWP documents
* **SILENTTRINITY:** Conducts an image hijack of an .msc file extension as part of its UAC bypass process


### Mitigation ###
This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features

### Bypassing ###



## Screensaver ##
Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr file extension. The Windows screensaver application scrnsave.scr is located in `C:\Windows\System32\`, and `C:\Windows\sysWOW64\` on 64-bit Windows systems, along with screensavers included with base Windows installations.

The following screensaver settings are stored in the Registry (`HKCU\Control Panel\Desktop\`) and could be manipulated to achieve persistence:

* **SCRNSAVE.exe** - set to malicious PE path
* **ScreenSaveActive** - set to '1' to enable the screensaver
* **ScreenSaverIsSecure** - set to '0' to not require a password to unlock
* **ScreenSaveTimeout** - sets user inactivity timeout before screensaver is executed


**Note:** Adversaries can use screensaver settings to maintain persistence by setting the screensaver to run malware after a certain timeframe of user inactivity


### Procedure ###
* **Gazer:** Establishes persistence through the system screensaver by configuring it to execute the malware

### Mitigation ###
* **Disable or Remove Feature or Program:** Use Group Policy to disable screensavers if they are unnecessary
* **Execution Prevention:** Block .scr files from being executed from non-standard locations


### Bypassing ###


## Windows Management Instrumentation Event Subscription ##
WMI can be used to install event filters, providers, consumers, and bindings that execute code when a defined event occurs. Examples of events that may be subscribed to are the wall clock time, user loging, or the computer's uptime.

Adversaries may use the capabilities of WMI to subscribe to an event and execute arbitrary code when that event occurs, providing persistence on a system
* Adversaries may also compile WMI scripts into Windows Management Object (MOF) files (.mof extension) that can be used to create a malicious subscription

WMI subscription execution is proxied by the WMI Provider Host process (WmiPrvSe.exe) and thus may result in elevated SYSTEM privileges.


### Procedure ###
* **adbupd:** adbupd can use a WMI script to achieve persistence
* **APT29:** APT29 has used WMI event subscriptions for persistence
* **APT33:** APT33 has attempted to use WMI event subscriptions to establish persistence on compromised hosts
* **Blue Mockingbird:** Blue Mockingbird has used mofcomp.exe to establish WMI Event Subscription persistence mechanisms configured from a *.mof file
* **FIN8:** FIN8 has used WMI event subscriptions for persistence
* **Leviathan:** Leviathan has used WMI for persistence
* **Mustang Panda:** Mustang Panda's custom ORat tool uses a WMI event consumer to maintain persistence
* **PoshC2:** PoshC2 has the ability to persist on a system using WMI events
* **POSHSPY:** POSHSPY uses a WMI event subscription to establish persistence
* **POWERTON:** POWERTON can use WMI for persistence
* **RegDuke:** RegDuke can persist using a WMI consumer that is launched every time a process named WINWORD.EXE is started
* **SeaDuke:** SeaDuke uses an event filter in WMI code to execute a previously dropped executable shortly after system startup
* **SILENTTRINITY:** SILENTTRINITY can create a WMI Event to execute a payload for persistence
* **TrailBlazer:** TrailBlazer has the ability to use WMI for persistence
* **Turla:** Turla has used WMI event filters and consumers to establish persistence


### Mitigation ###
* **Behavior Prevention on Endpoint:** On Windows 10, enable Attack Surface Reduction (ASR) rules to prevent malware from abusing WMI to attain persistence
* **Privileged Account Management:** Prevent credential overlap across systems of administrator and privileged accounts
* **User Account Management:** By default, only administrators are allowed to connect remotely using WMI; restrict other users that are allowed to connect, or disallow all users from connecting remotely to WMI

### Bypassing ###



## Unix Shell Configuration Modification ##
User Unix Shells execute several configuration scripts at different points throughout the session based on events. When a user opens a command-line interface or remotely logs in (such as via SSH) a login shell is initiated
* The login shell executes scripts from the system (/etc) and the user’s home directory (~/) to configure the environment
* All login shells on a system use /etc/profile when initiated
  * These configuration scripts run at the permission level of their directory and are often used to set environment variables, create aliases, and customize the user’s environment
  * When the shell exits or terminates, additional shell scripts are executed to ensure the shell exits appropriately

**Adversaries may attempt to establish persistence by inserting commands into scripts automatically executed by shells**

**Leveraging Bash** 
Add commands that launch malicious binaries into the `/etc/profile` and `/etc/profile.d` files
* These files require root permissions to modify and are executed each time any shell on a system launches
* For user level permissions, adversaries can insert malicious commands into `~/.bash_profile`, `~/.bash_login`, or `~/` profile which are sourced when a user opens a command-line interface or connects remotely
  * Since the system only executes the first existing file in the listed order, adversaries have used `~/.bash_profile` to ensure execution
* Adversaries have also leveraged the `~/.bashrc` file which is additionally executed if the connection is established remotely or an additional interactive shell is opened, such as a new tab in the command-line interface
* Some malware targets the termination of a program to trigger execution, adversaries can use the `~/.bash_logout` file to execute malicious commands at the end of a session

**Leveraging macOS**
Leverage zsh, the default shell for macOS 10.15+
* When the Terminal.app is opened, the application launches a zsh login shell and a zsh interactive shell
  * The login shell configures the system environment using `/etc/profile`, `/etc/zshenv`, `/etc/zprofile`, and `/etc/zlogin`
  * The login shell then configures the user environment with `~/.zprofile` and `~/.zlogin`. The interactive shell uses the `~/.zshrc` to configure the user environment. Upon exiting, `/etc/zlogout` and `~/.zlogout` are executed
* For legacy programs, macOS executes `/etc/bashrc` on startup


### Procedure ###
* **Green Lambert:** Establishes persistence on a compromised host through modifying the profile, login, and run command (rc) files associated with the bash, csh, and tcsh shells
* **Linux Rabbit:** Maintains persistence on an infected machine through rc.local and .bashrc files

### Mitigation ###
* **Restrict File and Directory Permissions:** Making these files immutable and only changeable by certain administrators will limit the ability for adversaries to easily create user level persistence.

### Bypassing ###




## Trap ##
The trap command allows programs and shells to specify commands that will be executed upon receiving interrupt signals. A common situation is a script allowing for graceful termination and handling of common keyboard interrupts like ctrl+c and ctrl+d.

Adversaries can use this to register code to be executed when the shell encounters specific interrupts as a persistence mechanism. Trap commands are of the following format trap 'command list' signals where "command list" will be executed when "signals" are received


### Procedure ###
This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features



### Mitigation ###
* **Command	Command Execution:** Monitor executed commands and arguments that may establish persistence by executing malicious content triggered by an interrupt signal
* **File Creation:** Monitor for newly constructed files that may establish persistence by executing malicious content triggered by an interrupt signal
* **File Modification:** Monitor for changes made to files that may establish persistence by executing malicious content triggered by an interrupt signal
* **Process	Process Creation:** Monitor newly executed processes that may establish persistence by executing malicious content triggered by an interrupt signal


### Bypassing ###



## LC_LOAD_DYLIB Addition ##
**Mach-O** binaries have a series of headers that are used to perform certain operations when a binary is loaded. The *LC_LOAD_DYLIB* header in a Mach-O binary tells macOS and OS X which dynamic libraries (dylibs) to load during execution time
* These can be added ad-hoc to the compiled binary as long as adjustments are made to the rest of the fields and dependencies

Adversaries may modify Mach-O binary headers to load and execute malicious dylibs every time the binary is executed

Although any changes will invalidate digital signatures on binaries because the binary is being modified, this can be remediated by simply removing the *LC_CODE_SIGNATURE* command from the binary so that the signature isn’t checked at load time


### Procedure ###


### Mitigation ###
* **Audit:** Binaries can also be baselined for what dynamic libraries they require, and if an app requires a new dynamic library that wasn\u2019t included as part of an update, it should be investigated
* **Code Signing:** Enforce that all binaries be signed by the correct Apple Developer IDs
* **Execution Prevention:** Allow applications via known hashes

### Bypassing ###




## Netsh Helper DLL ##
**Netsh.exe (Netshell):** A command-line scripting utility used to interact with the network configuration of a system. It contains functionality to add helper DLLs for extending functionality of the utility
* The paths to registered netsh.exe helper DLLs are entered into the Windows Registry at `HKLM\SOFTWARE\Microsoft\Netsh`

Adversaries can use netsh.exe helper DLLs to trigger execution of arbitrary code in a persistent manner
* This execution would take place anytime netsh.exe is executed, which could happen automatically, with another persistence technique, or if other software (ex: VPN) is present on the system that executes netsh.exe as part of its normal functionality


### Procedure ###
**netsh:** Can be used as a persistence proxy technique to execute a helper DLL when netsh.exe is executed


### Mitigation ###
* This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features


### Bypassing ###


## Accessibility Features ##
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


### Procedure ###
* **APT29:** Used sticky-keys to obtain unauthenticated, privileged console access
* **APT3:** APT3 replaces the Sticky Keys binary C:\Windows\System32\sethc.exe for persistence
* **APT41:** APT41 leveraged sticky keys to establish persistence
* **Axiom:** Axiom actors have been known to use the Sticky Keys replacement within RDP sessions to obtain persistence
* **Deep Panda:** Deep Panda has used the sticky-keys technique to bypass the RDP login screen on remote systems during intrusions
* **Empire:** Empire can leverage WMI debugging to remotely replace binaries like sethc.exe, Utilman.exe, and Magnify.exe with cmd.exe
* **Fox Kitten:** Fox Kitten has used sticky keys to launch a command prompt


### Mitigation ###
* **Execution Prevention:** Identify and block potentially malicious software executed through accessibility features functionality by using application control tools, like Windows Defender Application Control, AppLocker, or Software Restriction Policies where appropriate
* **Limit Access to Resource Over Network:** Use a Remote Desktop Gateway to manage connections and security configuration of RDP within a network
* **Operating System Configuration:** Ensure that Network Level Authentication is enabled to force the remote desktop session to authenticate before the session is created and the login screen displayed. It is enabled by default on Windows Vista and later


### Bypassing ###







## AppCert DLLs ##
DLLs that are specified in the AppCertDLLs Registry key under `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\` are loaded into every process that calls the ubiquitously used application programming interface (API) functions *CreateProcess*, *CreateProcessAsUser*, *CreateProcessWithLoginW*, CreateProcessWithTokenW, or WinExec

This value can be abused to obtain elevated privileges by causing a malicious DLL to be loaded and run in the context of separate processes on the computer
* Malicious AppCert DLLs may also provide persistence by continuously being triggered by API activity



### Procedure ###
* **Honeybee:** Service-based DLL implant can execute a downloaded file with parameters specified using *CreateProcessAsUser*
* **PUNCHBUGGY:** PUNCHBUGGY can establish using a AppCertDLLs Registry key

### Mitigation ###
* **Execution Prevention:** Identify and block potentially malicious software executed through AppCertDLLs functionality by using application control tools, like Windows Defender Application Control, AppLocker, or Software Restriction Policies where appropriate
  

### Bypassing ###




## AppInit DLLs ##
DLLs that are specified in the *AppInit_DLLs* value in the Registry keys `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows` or `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows` are loaded by user32.dll into every process that loads user32.dll
* This is nearly every program, since user32.dll is a very common library

These values can be abused to obtain elevated privileges by causing a malicious DLL to be loaded and run in the context of separate processes on the computer
* Malicious AppInit DLLs may also provide persistence by continuously being triggered by API activity

* **Note:**The AppInit DLL functionality is disabled in Windows 8 and later versions when secure boot is enabled



### Procedure ###
* **APT39:** Has used malware to set LoadAppInit_DLLs in the Registry key `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows` in order to establish persistence
* **Cherry Picker:** Some variants of Cherry Picker use *AppInit_DLLs* to achieve persistence by creating the following Registry key: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows "AppInit_DLLs"="pserver32.dll`
* **Ramsay:** Ramsay can insert itself into the address space of other applications using the AppInit DLL Registry key
* **T9000:** T9000 uses the *AppInit_DLL* functionality to achieve persistence by ensuring that every user mode process that is spawned will load its malicious DLL, ResN32.dll
  * It does this by creating the following Registry keys: `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` – `%APPDATA%\Intel\ResN32.dll` and `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs` – 0x1

### Mitigation ###
* **Execution Prevention:** Identify and block potentially malicious software executed through AppInit DLLs functionality by using application control tools, like Windows Defender Application Control, AppLocker, or Software Restriction Policies where appropriate
* **Update Software:** Upgrade to Windows 8 or later and enable secure boot


### Bypassing ###







## Application Shimming ##
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


### Procedure ###
* **FIN7:** Has used application shim databases for persistence
* **Pillowmint:** Has used a malicious shim database to maintain persistence
* **SDBbot:** SDBbot has the ability to use application shimming for persistence if it detects it is running as admin on Windows XP or 7, by creating a shim database to patch services.exe
* **ShimRat:** ShimRat has installed shim databases in the AppPatch folder


### Mitigation ###
* **Update Software:** Microsoft released an optional patch update - KB3045645 - that will remove the "auto-elevate" flag within the sdbinst.exe. This will prevent use of application shimming to bypass UAC
* **User Account Control:** Changing UAC settings to "Always Notify" will give the user more visibility when UAC elevation is requested, however, this option will not be popular among users due to the constant UAC interruptions


### Bypassing ###



## Image File Execution ##

Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by Image File Execution Options (IFEO) debuggers. IFEOs enable a developer to attach a debugger to an application. When a process is created, a debugger present in an application’s IFEO will be prepended to the application’s name, effectively launching the new process under the debugger (e.g., C:\dbg\ntsd.exe -g notepad.exe). [1]

IFEOs can be set directly via the Registry or in Global Flags via the GFlags tool. [2] IFEOs are represented as Debugger values in the Registry under HKLM\SOFTWARE{\Wow6432Node}\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ where <executable> is the binary on which the debugger is attached. [1]

IFEOs can also enable an arbitrary monitor program to be launched when a specified program silently exits (i.e. is prematurely terminated by itself or a second, non kernel-mode process). [3] [4] Similar to debuggers, silent exit monitoring can be enabled through GFlags and/or by directly modifying IFEO and silent process exit Registry values in HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\

Similar to Accessibility Features, on Windows Vista and later as well as Windows Server 2008 and later, a Registry key may be modified that configures "cmd.exe," or another program that provides backdoor access, as a "debugger" for an accessibility program (ex: utilman.exe). After the Registry is modified, pressing the appropriate key combination at the login screen while at the keyboard or when connected with Remote Desktop Protocol will cause the "debugger" program to be executed with SYSTEM privileges. [5]

Similar to Process Injection, these values may also be abused to obtain privilege escalation by causing a malicious executable to be loaded and run in the context of separate processes on the computer. [6] Installing IFEO mechanisms may also provide Persistence via continuous triggered invocation.

Malware may also use IFEO to Impair Defenses by registering invalid debuggers that redirect and effectively disable various system and security applications


### Procedure ###
* **SDBbot:** SDBbot has the ability to use image file execution options for persistence if it detects it is running with admin privileges on a Windows version newer than Windows 7
* **SUNBURST:** SUNBURST created an Image File Execution Options (IFEO) Debugger registry value for the process dllhost.exe to trigger the installation of Cobalt Strike
* **TEMP.Veles:** TEMP.Veles has modified and added entries within `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options` to maintain persistence

### Mitigation ###
This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.



### Bypassing ###



## PowerShell Profile ##
A PowerShell profile (profile.ps1) is a script that runs when PowerShell starts and can be used as a logon script to customize user environments


* PowerShell supports several profiles depending on the user or host program
  * There can be different profiles for PowerShell host programs such as the PowerShell console, PowerShell ISE or Visual Studio Code
  * An administrator can also configure a profile that applies to all users and host programs on the local computer


Adversaries may modify these profiles to include arbitrary commands, functions, modules, and/or PowerShell drives to gain persistence
* Every time a user opens a PowerShell session the modified script will be executed unless the *-NoProfile* flag is used when it is launched


An adversary may also be able to escalate privileges if a script in a PowerShell profile is loaded and executed by an account with higher privileges, such as a domain administrator



### Procedure ###
* **Turla:** Turla has used PowerShell profiles to maintain persistence on an infected machine


### Mitigation ###
* **Code Signing:** Enforce execution of only signed PowerShell scripts. Sign profiles to avoid them from being modified
* **Restrict File and Directory Permissions:** Making PowerShell profiles immutable and only changeable by certain administrators will limit the ability for adversaries to easily create user level persistence
* **Software Configuration:** Avoid PowerShell profiles if not needed. Use the -No Profile flag with when executing PowerShell scripts remotely to prevent local profiles and scripts from being executed


### Bypassing ###



## Emond ##
Event Monitor Daemon (Emond): A Launch Daemon that accepts events from various services, runs them through a simple rules engine, and takes action. The emond binary at `/sbin/` emond will load any rules from the `/etc/emond.d/rules/` directory and take action once an explicitly defined event takes place

The rule files are in the plist format and define the name, event type, and action to take
* Event types include system startup and user authentication
* Examples of actions are to run a system command or send an email. The emond service will not launch if there is no file present in the QueueDirectories path `/private/var/db/emondClients`, specified in the Launch Daemon configuration file at `/System/Library/LaunchDaemons/com.apple.emond.plist`

Adversaries may abuse this service by writing a rule to execute commands when a defined event occurs, such as system start up or user authentication. Adversaries may also be able to escalate privileges from administrator to root as the emond service is executed with root privileges by the Launch Daemon service



## Procedure ##
Disable or Remove Feature or Program	
Consider disabling emond by removing the Launch Daemon plist file.


### Detection ###
* **Command	Command Execution:** Monitor executed commands and arguments that may gain persistence and elevate privileges by executing malicious content triggered by the Emond
* **File Creation:** Monitor emond rules creation by checking for files created in `/etc/emond.d/rules/` and `/private/var/db/emondClients`
* **File Modification:** Monitor emond rules creation by checking for files modified in `/etc/emond.d/rules/` and `/private/var/db/emondClients`
* **Process Creation:** Monitor newly executed processes that may gain persistence and elevate privileges by executing malicious content triggered by the Emond

### Bypassing ###




## Component Object Model Hijacking ##
COM: A system within Windows to enable interaction between software components through the operating system -- References to various COM objects are stored in the Registry

Adversaries can use the COM system to insert malicious code that can be executed in place of legitimate software through hijacking the COM references and relationships as a means for persistence
* Hijacking a COM object requires a change in the Registry to replace a reference to a legitimate system component which may cause that component to not work when executed. When that system component is executed through normal system operation the adversary's code will be executed instead
* An adversary is likely to hijack objects that are used frequently enough to maintain a consistent level of persistence, but are unlikely to break noticeable functionality within the system as to avoid system instability that could lead to detection


### Procedure ###
* **ADVSTORESHELL:** Some variants of ADVSTORESHELL achieve persistence by registering the payload as a Shell Icon Overlay handler COM object
* **APT28:** APT28 has used COM hijacking for persistence by replacing the legitimate MMDeviceEnumerator object with a payload
* **BBSRAT:** BBSRAT has been seen persisting via COM hijacking through replacement of the COM object for MruPidlList `{42aedc87-2188-41fd-b9a3-0c966feabec1}` or Microsoft WBEM New Event Subsystem `{F3130CDB-AA52-4C3A-AB32-85FFC23AF9C1}` depending on the system's CPU architecture
* **ComRAT:** ComRAT samples have been seen which hijack COM objects for persistence by replacing the path to shell32.dll in registry location `HKCU\Software\Classes\CLSID``{42aedc87-2188-41fd-b9a3-0c966feabec1}\InprocServer32`
* **Ferocious:** Ferocious can use COM hijacking to establish persistence
* **JHUHUGIT:** JHUHUGIT has used COM hijacking to establish persistence by hijacking a class named MMDeviceEnumerator and also by registering the payload as a Shell Icon Overlay handler COM object (`{3543619C-D563-43f7-95EA-4DA7E1CC396A}`)
* **KONNI:** KONNI has modified ComSysApp service to load the malicious DLL payload
* **Mosquito:** Mosquito uses COM hijacking as a method of persistence
* **SILENTTRINITY:** SILENTTRINITY can add a CLSID key for payload execution through `Registry.CurrentUser.CreateSubKey("Software\\Classes\\CLSID\\{" + clsid + "}\\InProcServer32")`
* **WarzoneRAT:** WarzoneRAT can perform COM hijacking by setting the path to itself to the `HKCU\Software\Classes\Folder\shell\open\command` key with a *DelegateExecute* parameter
  

## Mitigations ##
This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features


### Bypassing ###


----------------------------
# External Remote Services #
Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations. There are often remote service gateways that manage connections and credential authentication for these services. Services such as Windows Remote Management and VNC can also be used externally

Access to Valid Accounts to use the service is often a requirement, which could be obtained through credential pharming or by obtaining the credentials from users after compromising the enterprise network
* Access to remote services may be used as a redundant or persistent access mechanism during an operation

Access may also be gained through an exposed service that doesn’t require authentication
* In containerized environments, this may include an exposed Docker API, Kubernetes API server, kubelet, or web application such as the Kubernetes dashboard


## Procedure ##
* **APT18:** Actors leverage legitimate credentials to log into external remote services
* **APT28:** APT28 has used Tor and a variety of commercial VPN services to route brute force authentication attempts
* **APT29:** APT29 has used compromised identities to access networks via SSH, VPNs, and other remote access tools
* **APT41:** APT41 compromised an online billing/payment service using VPN access between a third-party service provider and the targeted payment service
* **Chimera:** Chimera has used legitimate credentials to login to an external VPN, Citrix, SSH, and other remote services
* **Doki:** Doki was executed through an open Docker daemon API port
* **Dragonfly:** Dragonfly has used VPNs and Outlook Web Access (OWA) to maintain access to victim networks
* **FIN5:** FIN5 has used legitimate VPN, Citrix, or VNC credentials to maintain access to a victim environment
* **GALLIUM:** GALLIUM has used VPN services, including SoftEther VPN, to access and maintain persistence in victim environments
* **GOLD SOUTHFIELD:** GOLD SOUTHFIELD has used publicly-accessible RDP and remote management and monitoring (RMM) servers to gain access to victim machines
* **Hildegard:** Hildegard was executed through an unsecure kubelet that allowed anonymous access to the victim environment
* **Ke3chang:** Ke3chang has gained access through VPNs including with compromised accounts and stolen VPN certificates
* **Kimsuky:** Kimsuky has used RDP to establish persistence
* **Kinsing:** Kinsing was executed in an Ubuntu container deployed via an open Docker daemon API
* **Leviathan:** Leviathan has used external remote services such as virtual private networks (VPN) to gain initial access
* **Linux Rabbit:** Linux Rabbit attempts to gain access to the server via SSH
* **Night Dragon:** Night Dragon has used compromised VPN accounts to gain access to victim systems
* **OilRig:** OilRig uses remote services such as VPN, Citrix, or OWA to persist in an environment
* **Operation Wocao:** Operation Wocao has used stolen credentials to connect to the victim's network via VPN
* **Sandworm Team:** Sandworm Team has used Dropbear SSH with a hardcoded backdoor password to maintain persistence within the target network. Sandworm Team has also used VPN tunnels established in legitimate software company infrastructure to gain access to internal networks of that software company's users
* **TeamTNT:** TeamTNT has used open-source tools such as Weave Scope to target exposed Docker API ports and gain initial access to victim environments
  * TeamTNT has also targeted exposed kubelets for Kubernetes environments
  * **TEMP.Veles:** TEMP.Veles has used a VPN to persist in the victim environment
  * **Threat Group-3390:** Threat Group-3390 actors look for and use VPN profiles during an operation to access the network using external VPN services
    * Threat Group-3390 has also obtained OWA account credentials during intrusions that it subsequently used to attempt to regain access when evicted from a victim network
* Wizard Spider:** Wizard Spider has accessed victim networks by using stolen credentials to access the corporate VPN infrastructure


### Mitigations ###
* **Disable or Remove Feature or Program:** Disable or block remotely available services that may be unnecessary
* **Limit Access to Resource Over Network:** Limit access to remote services through centrally managed concentrators such as VPNs and other managed remote access systems
* **Multi-factor Authentication:** Use strong two-factor or multi-factor authentication for remote service accounts to mitigate an adversary's ability to leverage stolen credentials, but be aware of Multi-Factor Authentication Interception techniques for some two-factor authentication implementations
* **Network Segmentation:** Deny direct remote access to internal systems through the use of network proxies, gateways, and firewalls


### Bypassing ###





-------------------------
# Hijack Execution Flow #
Hijacking execution flow can be for the purposes of persistence, since this hijacked execution may reoccur over time
* Adversaries may also use these mechanisms to elevate privileges or evade defenses, such as application control or other restrictions on execution

There are many ways an adversary may hijack the flow of execution, including by manipulating how the operating system locates programs to be executed
* How the operating system locates libraries to be used by a program can also be intercepted
* Locations where the operating system looks for programs/resources, such as file directories and in the case of Windows the Registry, could also be poisoned to include malicious payloads



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




### Procedure
* **APT41:** APT41 has used search order hijacking to execute malicious payloads, such as Winnti RAT
* **Aquatic Panda:** Aquatic Panda has used DLL search-order hijacking to load exe, dll, and dat files into memory
* **Astaroth:** Astaroth can launch itself via DLL Search Order Hijacking
* **BackdoorDiplomacy:** BackdoorDiplomacy has executed DLL search order hijacking
* **BOOSTWRITE:** BOOSTWRITE has exploited the loading of the legitimate Dwrite.dll file by actually loading the gdi library, which then loads the gdiplus library and ultimately loads the local Dwrite dll
* **Chaes:** Chaes has used search order hijacking to load a malicious DLL
* **Crutch:** Crutch can persist via DLL search order hijacking on Google Chrome, Mozilla Firefox, or Microsoft OneDrive
* **Downdelph:** Downdelph uses search order hijacking of the Windows executable sysprep.exe to escalate privileges
* **Empire:** Empire contains modules that can discover and exploit various DLL hijacking opportunities
* **Evilnum:** Evilnum has used the malware variant, TerraTV, to load a malicious DLL placed in the TeamViewer directory, instead of the original Windows DLL located in a system folder
* **FinFisher:** A FinFisher variant uses DLL search order hijacking
* **FoggyWeb:** FoggyWeb's loader has used DLL Search Order Hijacking to load malicious code instead of the legitimate version.dll during the Microsoft.IdentityServer.ServiceHost.exe execution process
* **Hikit:** Hikit has used DLL Search Order Hijacking to load oci.dll as a persistence mechanism
* **HTTPBrowser:** HTTPBrowser abuses the Windows DLL load order by using a legitimate Symantec anti-virus binary, VPDN_LU.exe, to load a malicious DLL that mimics a legitimate Symantec DLL, navlu.dll
* **InvisiMole:** InvisiMole can be launched by using DLL search order hijacking in which the wrapper DLL is placed in the same folder as explorer.exe and loaded during startup into the Windows Explorer process instead of the legitimate library
* **Melcoz:** Melcoz can use DLL hijacking to bypass security controls
* **menuPass:** menuPass has used DLL search order hijacking
* **MirageFox:** MirageFox is likely loaded via DLL hijacking into a legitimate McAfee binary
* **PlugX:** PlugX has the ability to use DLL search order hijacking for installation on targeted systems
* **PowerSploit:** PowerSploit contains a collection of Privesc-PowerUp modules that can discover and exploit DLL hijacking opportunities in services and processes
* **Prikormka:** Prikormka uses DLL search order hijacking for persistence by saving itself as ntshrui.dll to the Windows directory so it will load before the legitimate ntshrui.dll saved in the System32 subdirectory
* **Ramsay:** Ramsay can hijack outdated Windows application dependencies with malicious versions of its own DLL payload
* **RedLeaves:** RedLeaves is launched through use of DLL search order hijacking to load a malicious dll
* **RTM:** RTM has used search order hijacking to force TeamViewer to load a malicious DLL
* **Threat Group-3390:** Threat Group-3390 has performed DLL search order hijacking to execute their payload
* **Tonto Team:** Tonto Team abuses a legitimate and signed Microsoft executable to launch a malicious DLL
* **WastedLocker:** WastedLocker has performed DLL hijacking before execution
* **WEBC2:** Variants of WEBC2 achieve persistence by using DLL search order hijacking, usually by copying the DLL file to `%SYSTEMROOT%` (C:\WINDOWS\ntshrui.dll)
* **Whitefly:** Whitefly has used search order hijacking to run the loader Vcrodat



### Mitigation
Audit	
Use auditing tools capable of detecting DLL search order hijacking opportunities on systems within an enterprise and correct them. Toolkits like the PowerSploit framework contain PowerUp modules that can be used to explore systems for DLL hijacking weaknesses

Use the program sxstrace.exe that is included with Windows along with manual inspection to check manifest files for side-by-side problems in software
M1038	Execution Prevention	
Adversaries may use new DLLs to execute this technique. Identify and block potentially malicious software executed through search order hijacking by using application control solutions capable of blocking DLLs loaded by legitimate software.
M1044	Restrict Library Loading	
Disallow loading of remote DLLs. This is included by default in Windows Server 2012+ and is available by patch for XP+ and Server 2003+.

Enable Safe DLL Search Mode to force search for system DLLs in directories with greater restrictions (e.g. %SYSTEMROOT%)to be used before local directory DLLs (e.g. a user's home directory)

The Safe DLL Search Mode can be enabled via Group Policy at Computer Configuration > [Policies] > Administrative Templates > MSS (Legacy): MSS: (SafeDllSearchMode) Enable Safe DLL search mode. The associated Windows Registry key for this is located at `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDLLSearchMode`

### Bypass






## DLL Side-Loading
DLL side-loading involves hijacking which DLL a program loads. But rather than just planting the DLL within the search order, adversaries may directly side-load their payloads by planting then invoking a legitimate application that executes their payload

Side-loading takes advantage of the DLL search order used by the loader by positioning both the victim application and malicious payload(s) alongside each other. 
* Benign executables used to side-load payloads may not be flagged during delivery and/or execution
* Adversary payloads may also be encrypted/packed or otherwise obfuscated until loaded into the memory of the trusted process


## Dylib Hijacking
Adversaries may execute their own payloads by placing a malicious dynamic library (dylib) with an expected name in a path a victim application searches at runtime. The dynamic loader will try to find the dylibs based on the sequential order of the search paths.
* Paths to dylibs may be prefixed with `@rpath`, which allows developers to use relative paths to specify an array of search paths used at runtime based on the location of the executable
* Additionally, if weak linking is used, such as the `LC_LOAD_WEAK_DYLIB` function, an application will still execute even if an expected dylib is not present
* Weak linking enables developers to run an application on multiple macOS versions as new APIs are added

Adversaries may gain execution by inserting malicious dylibs with the name of the missing dylib in the identified path
* Dylibs are loaded into an application's address space allowing the malicious dylib to inherit the application's privilege level and resources
* Based on the application, this could result in privilege escalation and uninhibited network access
  * This method may also evade detection from security products since the execution is masked under a legitimate process


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



## Path Interception by PATH Environment Variable
The *PATH* environment variable contains a list of directories. Certain methods of executing a program rely solely on the PATH environment variable to determine the locations that are searched for a program when the path for the program is not given
  
If any directories are listed in the PATH environment variable before the Windows directory, `%SystemRoot%\system32`, a program may be placed in the preceding directory that is named the same as a Windows program, which will be executed when that command is executed from a script or command-line


## Path Interception by Search Order Hijacking
**Search order hijacking:** Occurs when an adversary abuses the order in which Windows searches for programs that are not given a path. Unlike DLL Search Order Hijacking, the search order differs depending on the method that is used to execute the program
* **Note:** It's common for Windows to search in the directory of the initiating program before searching through the Windows system directory

Adversaries may execute their own malicious payloads by hijacking the search order used to load other programs. Because some programs do not call other programs using the full path, adversaries may place their own file in the directory where the calling program is located, causing the operating system to launch their malicious software at the request of the calling program.

* Place a program called "net.exe" within the same directory as example.exe, "net.exe" will be run instead of the Windows system utility net
* In addition, if an adversary places a program called "net.com" in the same directory as "net.exe", then cmd.exe /C net user will execute "net.com" instead of "net.exe" due to the order of executable extensions defined under PATHEXT


## Path Interception by Unquoted Path
Adversaries can take advantage of paths that lack surrounding quotations by placing an executable in a higher level directory within the path, so that Windows will choose the adversary's executable to launch

Service paths and shortcut paths may also be vulnerable to path interception if the path has one or more spaces and is not surrounded by quotation marks (`C:\unsafe path \program.exe` vs. `"C:\safe path \program.exe"`) Stored in Windows Registry keys 

Attackers can place an executable in a higher level directory of the path, and Windows will resolve that executable instead of the intended executable.
* If the path in a shortcut is `C:\program files\myapp.exe`, create a program at `C:\program.exe` that will be run instead of the intended program


## Services File Permissions Weakness
Adversaries may use flaws in the permissions of Windows services to replace the binary that is executed upon service start
* If the permissions on the file system directory containing a target binary, or permissions on the binary itself are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process
* If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions
  


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

## COR_PROFILER
**COR_PROFILER:** A .NET Framework feature which allows developers to specify an unmanaged (or external of .NET) profiling DLL to be loaded into each .NET process that loads the Common Language Runtime (CLR). These profilers are designed to monitor, troubleshoot, and debug managed code executed by the .NET CLR.

The COR_PROFILER environment variable can be set at various scopes (system, user, or process) resulting in different levels of influence
* System and user-wide environment variable scopes are specified in the Registry, where a Component Object Model (COM) object can be registered as a profiler DLL
* A process scope COR_PROFILER can also be created in-memory without modifying the Registry
* Starting with .NET Framework 4, the profiling DLL does not need to be registered as long as the location of the DLL is specified in the COR_PROFILER_PATH environment variable.

Adversaries may abuse COR_PROFILER to establish persistence that executes a malicious DLL in the context of all .NET processes every time the CLR is invoked

The COR_PROFILER can also be used to elevate privileges (ex: Bypass User Account Control) if the victim .NET process executes at a higher permission level, as well as to hook and Impair Defenses provided by .NET processes

## KernelCallbackTable
**KernelCallbackTable:** Can be found in the Process Environment Block (PEB) and is initialized to an array of graphic functions available to a GUI process once user32.dll is loaded

Attackers may hijack the execution flow of a process using the *KernelCallbackTable* by replacing an original callback function with a malicious payload
* Modifying callback functions can be achieved in various ways involving related behaviors such as Reflective Code Loading or Process Injection into another process

A pointer to the memory address of the *KernelCallbackTable* can be obtained by locating the PEB (ex: via a call to the *NtQueryInformationProcess()* Native API function)
* Once the pointer is located, the *KernelCallbackTable* can be duplicated, and a function in the table (e.g., fnCOPYDATA) set to the address of a malicious payload (ex: via WriteProcessMemory())
* The PEB is then updated with the new address of the table -- Once the tampered function is invoked, the malicious payload will be triggered

The tampered function is typically invoked using a Windows message. After the process is hijacked and malicious code is executed, the KernelCallbackTable may also be restored to its original state by the rest of the malicious payload
* Use of the *KernelCallbackTable* to hijack execution flow may evade detection from security products since the execution can be masked under a legitimate process



--------------------------
# Implant Internal Image #
Adversaries may implant cloud or container images with malicious code to establish persistence after gaining access to an environment. Unlike *Upload Malware*, this technique focuses on adversaries implanting an image in a registry within a victim’s environment. Depending on how the infrastructure is provisioned, this could provide persistent access if the infrastructure provisioning tool is instructed to always use the latest image

A tool has been developed to facilitate planting backdoors in cloud container images

If an adversary has access to a compromised AWS instance, and permissions to list the available container images, they may implant a backdoor such as a Web Shell



---------------------------------
# Modify Authentication Process #
The authentication process is handled by mechanisms, such as the Local Security Authentication Server (LSASS) process and the Security Accounts Manager (SAM) on Windows, pluggable authentication modules (PAM) on Unix-based systems, and authorization plugins on MacOS systems, responsible for gathering, storing, and validating credentials. By modifying an authentication process, an adversary may be able to authenticate to a service or system without using Valid Accounts

Adversaries may maliciously modify a part of this process to either reveal credentials or bypass authentication mechanisms. Compromised credentials or access may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services.


## Domain Controller Authentication
Malware may be used to inject false credentials into the authentication process on a domain controller with the intent of creating a backdoor used to access any user’s account and/or credentials (ex: Skeleton Key)
* Skeleton key works through a patch on an enterprise domain controller authentication process (LSASS) with credentials that adversaries may use to bypass the standard authentication system
* Once patched, an adversary can use the injected password to successfully authenticate as any domain user account (until the the skeleton key is erased from memory by a reboot of the domain controller)
* Authenticated access may enable unfettered access to hosts and/or resources within single-factor authentication environments
  

## Password Filter DLL
Windows password filters are password policy enforcement mechanisms for both domain and local accounts. Filters are implemented as DLLs containing a method to validate potential passwords against password policies
* Filter DLLs can be positioned on local computers for local accounts and/or domain controllers for domain accounts
  * Before registering new passwords in the Security Accounts Manager (SAM), the Local Security Authority (LSA) requests validation from each registered filter
  * Any potential changes cannot take effect until every registered filter acknowledges validation

Adversaries can register malicious password filters to harvest credentials from local computers and/or entire domains
* To perform proper validation, filters must receive plain-text credentials from the LSA
* A malicious password filter would receive these plain-text credentials every time a password request is made

## Pluggable Authentication Modules
PAM is a modular system of configuration files, libraries, and executable files which guide authentication for many services
* The most common authentication module is `pam_unix.so`, which retrieves, sets, and verifies account authentication information in `/etc/passwd` and `/etc/shadow`

Adversaries may modify components of the PAM system to create backdoors
* PAM components, such as `pam_unix.so`, can be patched to accept arbitrary adversary supplied values as legitimate credentials

Malicious modifications to the PAM system may also be abused to steal credentials
* Adversaries may infect PAM resources with code to harvest user credentials, since the values exchanged with PAM components may be plain-text since PAM does not store passwords

## Network Device Authentication
Adversaries may use Patch System Image to hard code a password in the operating system, thus bypassing of native authentication mechanisms for local accounts on network devices.

Modify System Image may include implanted code to the operating system for network devices to provide access for adversaries using a specific password. The modification includes a specific password which is implanted in the operating system image via the patch. Upon authentication attempts, the inserted code will first check to see if the user input is the password. If so, access is granted. Otherwise, the implanted code will pass the credentials on for verification of potentially valid credentials

## Reversible Encryption
An adversary may abuse Active Directory authentication encryption properties to gain access to credentials on Windows systems.The *AllowReversiblePasswordEncryption* property specifies whether reversible password encryption for an account is enabled or disabled.
* By default this property is disabled; if the property is enabled and/or a user changes their password after it is enabled, an adversary may be able to obtain the plaintext of passwords created/changed after the property was enabled
  
  
To decrypt the passwords, an adversary needs four components:

1. Encrypted password (G$RADIUSCHAP) from the Active Directory user-structure *userParameters*
2. 16 byte randomly-generated value (G$RADIUSCHAPKEY) also from *userParameters*
3. Global LSA secret (G$MSRADIUSCHAPKEY)
4. Static key hardcoded in the Remote Access Subauthentication DLL (RASSFM.DLL)

With this information, an adversary may be able to reproduce the encryption key and subsequently decrypt the encrypted password value

An adversary may set this property at various scopes through Local Group Policy Editor, user properties, Fine-Grained Password Policy (FGPP), or via the ActiveDirectory PowerShell module.
* An adversary may implement and apply a FGPP to users or groups if the Domain Functional Level is set to "Windows Server 2008" or higher
* In PowerShell, an adversary may make associated changes to user settings using commands similar to `Set-ADUser -AllowReversiblePasswordEncryption $true`



------------------------------
# Office Application Startup #
There are multiple mechanisms that can be used with Microsoft Office for persistence when an Office-based application is started; this can include the use of Office Template Macros and add-ins.

* A variety of features have been discovered in Outlook that can be abused to obtain persistence, such as Outlook rules, forms, and Home Page
* These persistence mechanisms can work within Outlook or be used through Office 365


## Office Template Macros
Microsoft Office contains templates that are part of common Office applications and are used to customize styles. The base templates within the application are used each time an application starts

Office Visual Basic for Applications (VBA) macros can be inserted into the base template and used to execute code when the respective Office application starts in order to obtain persistence
* By default, Word has a Normal.dotm template created that can be modified to include a malicious macro
* Shared templates may also be stored and pulled from remote locations

**Word Normal.dotm location:**
`C:\Users\<username>\AppData\Roaming\Microsoft\Templates\Normal.dotm`

**Excel Personal.xlsb location:**
`C:\Users\<username>\AppData\Roaming\Microsoft\Excel\XLSTART\PERSONAL.XLSB`

Adversaries may change the location of the base template to point to their own by hijacking the application's search order
* Word 2016 will first look for Normal.dotm under `C:\Program Files (x86)\Microsoft Office\root\Office16\`, or by modifying the GlobalDotName registry key
* By modifying the *GlobalDotName* registry key an adversary can specify an arbitrary location, file name, and file extension to use for the template that will be loaded on application startup
* To abuse *GlobalDotName*, adversaries may first need to register the template as a trusted document or place it in a trusted location

An adversary may enable macros to execute unrestricted depending on the system or enterprise security policy on use of macros

## Office Test
An Office Test Registry location exists that allows a user to specify an arbitrary DLL that will be executed every time an Office application is started
* This Registry key is thought to be used by Microsoft to load DLLs for testing and debugging purposes while developing Office applications
  * This Registry key is not created by default during an Office installation

**There exist user and global Registry keys for the Office Test feature:**

* `HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf`
* `HKEY_LOCAL_MACHINE\Software\Microsoft\Office test\Special\Perf`

Adversaries may add this Registry key and specify a malicious DLL that will be executed whenever an Office application, such as Word or Excel, is started

## Outlook Forms
Outlook forms are used as templates for presentation and functionality in Outlook messages
* Custom Outlook forms can be created that will execute code when a specifically crafted email is sent by an adversary utilizing the same custom Outlook form

Once malicious forms have been added to the user’s mailbox, they will be loaded when Outlook is started
* Malicious forms will execute when an adversary sends a specifically crafted email to the user


## Outlook Home Page
Outlook Home Page is a legacy feature used to customize the presentation of Outlook folders
* This feature allows for an internal or external URL to be loaded and presented whenever a folder is opened
* A malicious HTML page can be crafted that will execute code when loaded by Outlook Home Page

Once malicious home pages have been added to the user’s mailbox, they will be loaded when Outlook is started. Malicious Home Pages will execute when the right Outlook folder is loaded/reloaded

## Outlook Rules
Outlook rules allow a user to define automated behavior to manage email messages. A benign rule might, for example, automatically move an email to a particular folder in Outlook if it contains specific words from a specific sender
* Malicious Outlook rules can be created that can trigger code execution when an adversary sends a specifically crafted email to that user

Once malicious rules have been added to the user’s mailbox, they will be loaded when Outlook is started. Malicious rules will execute when an adversary sends a specifically crafted email to the user

## Add-ins
Office add-ins can be used to add functionality to Office programs
* There are different types of add-ins that can be used by the various Office products including:
* Word/Excel add-in Libraries (WLL/XLL), VBA add-ins, Office Component Object Model (COM) add-ins, automation add-ins, VBA Editor (VBE), Visual Studio Tools for Office (VSTO) add-ins, and Outlook add-ins

Add-ins can be used to obtain persistence because they can be set to execute code when an Office application starts



---------------
# Pre-OS Boot #
Adversaries may abuse Pre-OS Boot mechanisms as a way to establish persistence on a system. During the booting process of a computer, firmware and various startup services are loaded before the operating system. These programs control flow of execution before the operating system takes control

Adversaries may overwrite data in boot drivers or firmware such as BIOS (Basic Input/Output System) and The Unified Extensible Firmware Interface (UEFI) to persist on systems at a layer below the operating system. This can be particularly difficult to detect as malware at this level will not be detected by host software-based defenses


## System Firmware
The BIOS and UEFI or EFI are examples of system firmware that operate as the software interface between the operating system and hardware of a computer.

System firmware like BIOS and (U)EFI underly the functionality of a computer and may be modified by an adversary to perform or assist in malicious activity
* Capabilities exist to overwrite the system firmware, which may give sophisticated adversaries a means to install malicious firmware updates as a means of persistence on a system that may be difficult to detect



## Component Firmware
Some adversaries may employ sophisticated means to compromise computer components and install malicious firmware that will execute adversary code outside of the operating system and main system firmware or BIOS
* This technique may be similar to System Firmware but conducted upon other system components/devices that may not have the same capability or level of integrity checking.

Malicious component firmware could provide both a persistent level of access to systems despite potential typical failures to maintain access and hard disk re-images, as well as a way to evade host software-based defenses and integrity checks.

## Bootkit
Bootkit: Malware variant that modifies the boot sectors of a hard drive, including the Master Boot Record (MBR) and Volume Boot Record (VBR)
* MBR: The section of disk that is first loaded after completing hardware initialization by the BIOS -- The location of the boot loader

An adversary who has raw access to the boot drive may overwrite this area, diverting execution during startup from the normal boot loader to adversary code
* The MBR passes control of the boot process to the VBR
* An adversary who has raw access to the boot drive may overwrite the VBR to divert execution during startup to adversary code

## ROMMONkit
ROMMON: Cisco network device firmware that functions as a boot loader, boot image, or boot helper to initialize hardware and software when the platform is powered on or reset
* Similar to TFTP Boot, an adversary may upgrade the ROMMON image locally or remotely with adversary code and restart the device in order to overwrite the existing ROMMON image
* This provides adversaries with the means to update the ROMMON to gain persistence on a system in a way that may be difficult to detect

## TFTP Boot
TFTP boot is commonly used by network administrators to load configuration-controlled network device images from a centralized management server.
* Netbooting is one option in the boot sequence and can be used to centralize, manage, and control device images

Adversaries may manipulate the configuration on the network device specifying use of a malicious TFTP server, which may be used in conjunction with Modify System Image to load a modified image on device startup or reset
* The unauthorized image allows adversaries to modify device configuration, add malicious capabilities to the device, and introduce backdoors to maintain control of the network device while minimizing detection through use of a standard functionality
* This technique is similar to ROMMONkit and may result in the network device running a modified image


-----------------------------
# Server Software Component #
Adversaries may abuse legitimate extensible development features of servers to establish persistent access to systems. Enterprise server applications may include features that allow developers to write and install software or scripts to extend the functionality of the main application. Adversaries may install malicious components to extend and abuse server applications.


## SQL Stored Procedures
SQL Stored Procedures are code that can be saved and reused so that database users do not waste time rewriting frequently used SQL queries
* Stored procedures can be invoked via SQL statements to the database using the procedure name or via defined events

Adversaries may craft malicious stored procedures that can provide a persistence mechanism in SQL database servers
* To execute operating system commands through SQL syntax the adversary may have to enable additional functionality, such as `xp_cmdshell` for MSSQL Server

Microsoft SQL Server can enable common language runtime (CLR) integration. With CLR integration enabled, application developers can write stored procedures using any .NET framework language (VB .NET, C#, etc.)
* Adversaries may craft or modify CLR assemblies that are linked to stored procedures since these CLR assemblies can be made to execute arbitrary commands

## Transport Agent
Microsoft Exchange transport agents can operate on email messages passing through the transport pipeline to perform various tasks such as filtering spam, filtering malicious attachments, journaling, or adding a corporate signature to the end of all outgoing emails

Transport agents can be written by application developers and then compiled to .NET assemblies that are subsequently registered with the Exchange server. Transport agents will be invoked during a specified stage of email processing and carry out developer defined tasks

Adversaries may register a malicious transport agent to provide a persistence mechanism in Exchange Server that can be triggered by adversary-specified email events. Though a malicious transport agent may be invoked for all emails passing through the Exchange transport pipeline, the agent can be configured to only carry out specific tasks in response to adversary defined criteria
* The transport agent may only carry out an action like copying in-transit attachments and saving them for later exfiltration if the recipient email address matches an entry on a list provided by the adversary

## Web Shell
Web shell: A Web script that is placed on an openly accessible Web server to allow an adversary to use the Web server as a gateway into a network. A Web shell may provide a set of functions to execute or a command-line interface on the system that hosts the Web server

In addition to a server-side script, a Web shell may have a client interface program that is used to talk to the Web server 

## IIS Components
IIS provides several mechanisms to extend the functionality of the web servers
* Internet Server Application Programming Interface (ISAPI) extensions and filters can be installed to examine and/or modify incoming and outgoing IIS web requests
* Extensions and filters are deployed as DLL files that export three functions: `Get{Extension/Filter}Version, Http{Extension/Filter}Proc, and Terminate{Extension/Filter}` -- IIS modules may also be installed to extend IIS web servers

Adversaries may install malicious ISAPI extensions and filters to observe and/or modify traffic, execute commands on compromised machines, or proxy command and control traffic
* ISAPI extensions and filters may have access to all IIS web requests and responses
  * An adversary may abuse these mechanisms to modify HTTP responses in order to distribute malicious commands/content to previously comprised hosts

Adversaries may also install malicious IIS modules to observe and/or modify traffic
IIS 7.0 introduced modules that provide the same unrestricted access to HTTP requests and responses as ISAPI extensions and filters
IIS modules can be written as a DLL that exports RegisterModule, or as a .NET application that interfaces with ASP.NET APIs to access IIS HTTP requests

## Terminal Services DLL
Adversaries may abuse components of Terminal Services to enable persistent access to systems. Microsoft Terminal Services, renamed to Remote Desktop Services in some Windows Server OSs as of 2022, enable remote terminal connections to hosts. Terminal Services allows servers to transmit a full, interactive, graphical user interface to clients via RDP

Windows Services that are run as a "generic" process (ex: svchost.exe) load the service's DLL file, the location of which is stored in a Registry entry named ServiceDll
The termsrv.dll file, typically stored in `%SystemRoot%\System32\`, is the default ServiceDll value for Terminal Services in `HKLM\System\CurrentControlSet\services\TermService\Parameters\`

Adversaries may modify and/or replace the Terminal Services DLL to enable persistent access to victimized hosts
* Modifications to this DLL could be done to execute arbitrary payloads as well as to simply enable abusable features of Terminal Services

Attackers may enable features such as concurrent RDP sessions by either patching the termsrv.dll file or modifying the ServiceDll value to point to a DLL that provides increased RDP functionality

On a non-server Windows OS this increased functionality may also enable an adversary to avoid Terminal Services prompts that warn/log out users of a system when a new RDP session is created



---------------------
# Traffic Signaling #
Traffic signaling involves the use of a magic value or sequence that must be sent to a system to trigger a special response, such as opening a closed port or executing a malicious task
* This may take the form of sending a series of packets with certain characteristics before a port will be opened that the adversary can use for C2


Adversaries may also communicate with an already open port, but the service listening on that port will only respond to commands or trigger other malicious functionality if passed the appropriate magic value(s)

The observation of the signal packets to trigger the communication can be conducted through different methods
* One means is to use the *libpcap* libraries to sniff for the packets in question
* Another method leverages raw sockets, which enables the malware to use ports that are already open for use by other programs

On network devices, attackers may use crafted packets to enable Network Device Authentication for standard services offered by the device such as telnet
* Such signaling may also be used to open a closed service port such as telnet, or to trigger module modification of malware implants on the device, adding, removing, or changing malicious capabilities
* Attackers may use crafted packets to attempt to connect to one or more (open or closed) ports, but may also attempt to connect to a router interface, broadcast, and network address IP on the same port in order to achieve their goals and objectives
  * To enable this traffic signaling on embedded devices, adversaries must first achieve and leverage Patch System Image due to the monolithic nature of the architecture

Adversaries may also use the Wake-on-LAN feature to turn on powered off systems
* Wake-on-LAN: Hardware feature that allows a powered down system to be powered on, or woken up, by sending a magic packet to it
  * Once the system is powered on, it may become a target for lateral movement 

## Port Knocking 
To enable a port, an adversary sends a series of attempted connections to a predefined sequence of closed ports
* After the sequence is completed, opening a port is often accomplished by the host based firewall, but could also be implemented by custom software

This technique has been observed both for the dynamic opening of a listening port as well as the initiating of a connection to a listening server on a different system


The observation of the signal packets to trigger the communication can be conducted through different methods
* One means is to use the libpcap libraries to sniff for the packets in question
* Another method leverages raw sockets, which enables the malware to use ports that are already open for use by other programs

# Valid Accounts #
------------------
Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services


Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network

Attackers may abuse inactive accounts -- Using these accounts may allow the adversary to evade detection, as the original account user will not be present to identify any anomalous activity taking place on their account

The overlap of permissions for local, domain, and cloud accounts across a network of systems is of concern because the adversary may be able to pivot across accounts and systems to reach a high level of access to bypass access controls set within the enterprise

## Default Account 
Default accounts are those that are built-into an OS, such as the Guest or Administrator accounts on Windows systems
* Default accounts also include default factory/provider set accounts on other types of systems, software, or devices
* Note: Default accounts are not limited to client machines, rather also include accounts that are preset for equipment such as network devices and computer applications whether they are internal, open source, or commercial
  * Appliances that come preset with a username and password combination pose a serious threat to organizations that do not change it post installation, as they are easy targets for an adversary
  * Attackers may also utilize publicly disclosed or stolen Private Keys or credential materials to legitimately connect to remote environments via Remote Services

## Domain Account 
Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain -- Domain accounts can cover users, administrators, and services

Adversaries may compromise domain accounts, some with a high level of privileges, through various means such as OS Credential Dumping or password reuse, allowing access to privileged resources of the domain

## Local Account 
Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service

Local Accounts may also be abused to elevate privileges and harvest credentials through OS Credential Dumping
* Password reuse may allow the abuse of local accounts across a set of machines on a network for the purposes of Privilege Escalation and Lateral Movement

## Cloud Account
Cloud accounts are those created and configured by an organization for use by users, remote support, services, or for administration of resources within a cloud service provider or SaaS application
* Cloud accounts may be federated with traditional identity management system

Compromised credentials for cloud accounts can be used to harvest sensitive data from online storage accounts and databases
* Access to cloud accounts can also be abused to gain Initial Access to a network by abusing a Trusted Relationship
* Compromise of federated cloud accounts may allow adversaries to more easily move laterally within an environment

Once a cloud account is compromised, an adversary may perform Account Manipulation - for example, by adding Additional Cloud Roles - to maintain persistence and potentially escalate their privileges


