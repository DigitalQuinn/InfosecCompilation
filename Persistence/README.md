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
Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key. Adding an entry to the "run keys" in the Registry or startup folder will cause the program referenced to be executed when a user logs in.[1] These programs will be executed under the context of the user and will have the account's associated permissions level.

Placing a program within a startup folder will also cause that program to execute when a user logs in. There is a startup folder location for individual user accounts as well as a system-wide startup folder that will be checked regardless of which user account logs in. The startup folder path for the current user is C:\Users\[Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup. The startup folder path for all users is C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp.

The following run keys are created by default on Windows systems:

`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce`
`HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`
`HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce`

Run keys may exist under multiple hives.[2][3] The HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx is also available but is not created by default on Windows Vista and newer. Registry run key entries can reference programs directly or list them as a dependency.[1] For example, it is possible to load a DLL at logon using a "Depend" key with RunOnceEx: reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\temp\evil[.]dll" [4]

The following Registry keys can be used to set startup folder items for persistence:

HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
The following Registry keys can control automatic startup of services during boot:

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices
Using policy settings to specify startup programs creates corresponding values in either of two Registry keys:

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
The Winlogon key controls actions that occur when a user logs on to a computer running Windows 7. Most of these actions are under the control of the operating system, but you can also add custom actions here. The HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit and HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell subkeys can automatically launch programs.

Programs listed in the load value of the registry key HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows run when any user logs on.

By default, the multistring BootExecute value of the registry key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager is set to autocheck autochk *. This value causes Windows, at startup, to check the file-system integrity of the hard disks if the system has been shut down abnormally. Adversaries can add other programs or processes to this registry value which will automatically launch at boot.

Adversaries can use these configuration locations to execute malware, such as remote access tools, to maintain persistence through system reboots. Adversaries may also use Masquerading to make the Registry entries look as if they are associated with legitimate programs.

## Authentication Package ##


## Time Providers ##


## Winlogon Helper DLL ##


## Security Support Provider ##


## Kernel Modules & Entensions ##


## Re-Opened Applications ##


## LSASS Driver ##


## Shortcut Modification ##


## Port Monitors ##


## Print Processes ##


## XDG Autostart Entries ##


## Active Setup ##


## Login Items ##

----------------------------------------
# Boot or Logon Initialization Scripts #




----------------------
# Browser Extensions #




-------------------------------------
# Compromise Client Software Binary #




------------------
# Create Account #




-------------------------------------
# Create or Modify System Processes #




-----------------------------
# Event Triggered Execution #




----------------------------
# External Remote Services #




-------------------------
# Hijack Execution Flow #




--------------------------
# Implant Internal Image #




---------------------------------
# Modify Authentication Process #




------------------------------
# Office Application Startup #




---------------
# Pre-OS Boot #




--------------------------
# Scheduled Tasks / Jobs #




-----------------------------
# Server Software Component #




---------------------
# Traffic Signaling #




------------------
# Valid Accounts #
