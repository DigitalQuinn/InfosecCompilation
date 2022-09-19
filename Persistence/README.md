Persistence consists of techniques that adversaries use to keep access to systems across restarts, changed credentials, and other interruptions that could cut off their access. Techniques used for persistence include any access, action, or configuration changes that let them maintain their foothold on systems, such as replacing or hijacking legitimate code or adding startup code

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
- [Scheduled Tasks / Jobs](#scheduled-tasks--jobs)
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



### Procedure ###

### Mitigation ###

### Bypassing ###
----------------------------
# External Remote Services #



### Procedure ###

### Mitigation ###

### Bypassing ###
-------------------------
# Hijack Execution Flow #



### Procedure ###

### Mitigation ###

### Bypassing ###
--------------------------
# Implant Internal Image #



### Procedure ###

### Mitigation ###

### Bypassing ###
---------------------------------
# Modify Authentication Process #


### Procedure ###

### Mitigation ###

### Bypassing ###
------------------------------
# Office Application Startup #



### Procedure ###

### Mitigation ###

### Bypassing ###
---------------
# Pre-OS Boot #



### Procedure ###

### Mitigation ###

### Bypassing ###
--------------------------
# Scheduled Tasks / Jobs #


### Procedure ###

### Mitigation ###

### Bypassing ###

-----------------------------
# Server Software Component #



### Procedure ###

### Mitigation ###

### Bypassing ###
---------------------
# Traffic Signaling #


### Procedure ###

### Mitigation ###

### Bypassing ###

------------------
# Valid Accounts #
