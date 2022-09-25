# Credential Access

Credential Access consists of techniques for stealing credentials like account names and passwords. Techniques used to get credentials include keylogging or credential dumping. Using legitimate credentials can give adversaries access to systems, make them harder to detect, and provide the opportunity to create more accounts to help achieve their goals
<br>

<hr>

# Table of Content
- [Adversary-in-the-Middle](#adversary-in-the-middle)
- [Brute Force](#brute-force)
- [Credentials From Password Stores](#credentials-from-password-stores)
- [Exploitation for Credential Access](#exploitation-for-credential-access)
- [Forced Authentication](#forced-authentication)
- [Forge Web Credentials](#forge-web-credentials)
- [Input Capture](#input-capture)
- [Nodify Authentication Process](#modify-authentication-process)
- [MFA Interception](#mfa-interception)
- [MFA Request Generation](#mfa-request-generation)
- [Network Sniffing](#network-sniffing)
- [OS Credential Dumping](#os-credential-dumping)
- [Steal Application Access Tokens](#steal-application-access-token)
- [Steal or Forge Kerberos Tickets](#steal-or-forge-kerberos-tickets)
- [Steal Web Session Cookie](#steal-web-session-cookie)
- [Unsecured Credentials](#unsecured-credentials)
<br>

<hr>

# Adversary-in-the-Middle
Adversaries may attempt to position themselves between two or more networked devices using an adversary-in-the-middle (AiTM) technique to support follow-on behaviors such as *Network Sniffing or Transmitted Data Manipulation*
* By abusing features of common networking protocols that can determine the flow of network traffic, adversaries may force a device to communicate through an adversary controlled system so they can collect information or perform additional actions

Attackers may manipulate victim DNS settings to enable other malicious activities such as preventing/redirecting users from accessing legitimate sites and/or pushing additional malware
* **Downgrade Attacks** can also be used to establish an AiTM position by negotiating a less secure, deprecated, or weaker version of communication protocol or encryption algorithm

Adversaries may also leverage the AiTM position to attempt to monitor and/or modify traffic, such as in *Transmitted Data Manipulation*
* Adversaries can setup a position similar to AiTM to prevent traffic from flowing to the appropriate destination, potentially to *Impair Defenses* and/or in support of a Network DoS
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

<hr>

# Brute Force
Without knowledge of the password for an account or set of accounts, an adversary may systematically guess the password using a repetitive or iterative mechanism
* Brute forcing passwords can take place via interaction with a service that will check the validity of those credentials or offline against previously acquired credential data, such as password hashes

Brute forcing credentials may take place at various points during a breach
* Attackers may attempt to brute force access to Valid Accounts within a victim environment leveraging knowledge gathered from other post-compromise behaviors such as *OS Credential Dumping, Account Discovery, or Password Policy Discovery*
* Adversaries may also combine brute forcing activity with behaviors such as *External Remote Services as part of Initial Access*
<br>

## Password Guessing
Without knowledge of the password for an account, an adversary may opt to systematically guess the password using a repetitive or iterative mechanism
* An adversary may guess login credentials without prior knowledge of system or environment passwords during an operation by using a list of common passwords
* Password guessing may or may not take into account the target's policies on password complexity or use policies that may lock accounts out after a number of failed attempts

Guessing passwords can be a risky option because it could cause numerous authentication failures and account lockouts, depending on the organization's login failure policies 

Typically, management services over commonly used ports are used when guessing passwords; Commonly targeted services include the following:

* SSH, Telnet, FTP, NetBIOS/ SMB/Samba, LDAP, Kerberos, RDP/Terminal Services, HTTP(S), MSSQL, Oracle, MySQL, VNC, and SNMP

In addition to management services, adversaries may target SSO and cloud-based applications utilizing federated authentication protocols," as well as externally facing email applications
* Further, adversaries may abuse network device interfaces (such as wlanAPI) to brute force accessible wifi-router(s) via wireless authentication protocols

In default environments, LDAP and Kerberos connection attempts are less likely to trigger events over SMB, which creates Windows "logon failure" `event ID 4625`
<br>

## Password Cracking
**OS Credential Dumping** can be used to obtain password hashes, this may only get an adversary so far when PTH is not an option
* Further, adversaries may leverage Data from Configuration Repository in order to obtain hashed credentials for network devices 

Techniques to systematically guess the passwords used to compute hashes are available, or the adversary may use a pre-computed rainbow table to crack hashes
* Cracking hashes is usually done on adversary-controlled systems outside of the target network
* The resulting plaintext password resulting from a successfully cracked hash may be used to log into systems, resources, and services in which the account has access
<br>

## Password Spraying
**Password Spraying:** Uses one password or a small list of commonly used passwords, that may match the complexity policy of the domain
* Logins are attempted with that password against many different accounts on a network to avoid account lockouts that would normally occur when brute forcing a single account with many passwords

<br>

## Credential Stuffing
Adversaries may use credentials obtained from breach dumps of unrelated accounts to gain access to target accounts through credential overlap
* Occasionally, large numbers of username and password pairs are dumped online when a website or service is compromised and the user account credentials accessed
* The information may be useful to an adversary attempting to compromise accounts by taking advantage of the tendency for users to use the same passwords across personal and business accounts

**NOTE::** Credential stuffing is a risky option because it could cause numerous authentication failures and account lockouts, depending on the organization's login failure policies
<hr>

# Credentials From Password Stores
Adversaries may search for common password storage locations to obtain user credentials
* Passwords are stored in several places on a system, depending on the operating system or application holding the credentials
* There are also specific applications that store passwords to make it easier for users manage and maintain
  * Once credentials are obtained, they can be used to perform lateral movement and access restricted information
<br>

## Keychain
**Keychain:** The macOS credential management system that stores account names, passwords, private keys, certificates, sensitive application data, payment data, and secure notes; There are three types of Keychains: 

* **Login Keychain:** Stores user passwords and information
* **System Keychain:** Stores items accessed by the operating system, such as items shared among users on a host
* **The Local Items (iCloud) Keychain:** Used for items synced with Apple’s iCloud service

Keychains can be viewed and edited through the Keychain Access application or using the command-line utility security
* Keychain files are located in `~/Library/Keychains/`, `/Library/Keychains/`, and `/Network/Library/Keychains/` 

Adversaries may gather user credentials from Keychain storage/memory
* `security dump-keychain –d`: Dumps all Login Keychain credentials from `~/Library/Keychains/login.keychain-db`
* Adversaries may also directly read Login Keychain credentials from the `~/Library/Keychains/login.keychain` file
* **NOTE::** Both methods require a password, where the default password for the Login Keychain is the current user’s password to login to the macOS host 
<br>

## Securityd Memory
An adversary may obtain root access (allowing them to read **securityd’s** memory), then they can scan through memory to find the correct sequence of keys in relatively few tries to decrypt the user’s logon keychain
* This provides the adversary with all the plaintext passwords for users, WiFi, mail, browsers, certificates, secure notes, etc.

In OS X prior to El Capitan, users with root access can read plaintext keychain passwords of logged-in users because Apple’s keychain implementation allows these credentials to be cached so that users are not repeatedly prompted for passwords
* Apple’s **securityd** utility takes the user’s logon password, encrypts it with PBKDF2, and stores this master key in memory
* Apple also uses a set of keys and algorithms to encrypt the user’s password, but once the master key is found, an adversary need only iterate over the other values to unlock the final password
<br>

## Credentials from Web Browsers
Adversaries may acquire credentials from web browsers by reading files specific to the target browser. Web browsers commonly save credentials such as website usernames and passwords so that they do not need to be entered manually in the future
* Web browsers typically store the credentials in an encrypted format within a credential store; however, methods exist to extract plaintext credentials from web browsers

On Windows systems, encrypted credentials may be obtained from Google Chrome by reading a database file, `AppData\Local\Google\Chrome\User Data\Default\Login Data` and executing a SQL query: `SELECT action_url, username_value, password_value FROM logins;`
* The plaintext password can then be obtained by passing the encrypted credentials to the Windows API function `CryptUnprotectData`, which uses the victim’s cached logon credentials as the decryption key 

Windows stores Internet Explorer and Microsoft Edge credentials in Credential Lockers managed by the Windows Credential Manager

Adversaries may also acquire credentials by searching web browser process memory for patterns that commonly match credentials 
<br>

## Windows Credential Manager
**The Credential Manager:** Stores credentials for signing into websites, applications, and/or devices that request authentication through NTLM or Kerberos in Credential Lockers 

The Windows Credential Manager separates website credentials from application or network credentials in two lockers
* Credentials from web browsers are stored in the Web Credentials locker
* Application and network credentials are stored in the Windows Credentials locker

Credential Lockers store credentials in encrypted **.vcrd** files, located under `%Systemdrive%\Users\[Username]\AppData\Local\Microsoft\[Vault/Credentials]\`
* The encryption key can be found in a file named **Policy.vpol**, typically located in the same folder as the credentials 

Adversaries may list credentials managed by the Windows Credential Manager through several mechanisms

* **vaultcmd.exe:** A native Windows executable that can be used to enumerate credentials stored in the Credential Locker through a CLI
* Adversaries may gather credentials by reading files located inside of the Credential Lockers
* Adversaries may also abuse Windows APIs such as `CredEnumerateA` to list credentials managed by the Credential Manager 

Adversaries may use password recovery tools to obtain plain text passwords from the Credential Managers
<br>

## Password Managers
**Password Managers:** Applications designed to store user credentials, normally in an encrypted database
* Credentials are typically accessible after a user provides a master password that unlocks the database
* After the database is unlocked, these credentials may be copied to memory
  * These databases can be stored as files on disk 

Adversaries may acquire user credentials from password managers by extracting the master password and/or plain-text credentials from memory
* Adversaries may extract credentials from memory via **Exploitation for Credential Access**
* Adversaries may also try brute forcing via Password Guessing to obtain the master password of a password manager 
<hr>

# Exploitation for Credential Access
Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code

* Credentialing and authentication mechanisms may be targeted for exploitation by adversaries as a means to gain access to useful credentials or circumvent the process to gain access to systems
  * **MS14-068** Targets Kerberos and can be used to forge Kerberos tickets using domain user permissions
* Exploitation for credential access may also result in **Privilege Escalation** depending on the process targeted or credentials obtained
<hr>

# Forced Authentication
Adversaries may gather credential material by invoking or forcing a user to automatically provide authentication information through a mechanism in which they can intercept

**SMB:**) Used in Windows networks for authentication and communication between systems for access to resources and file sharing
* When a Windows system attempts to connect to an SMB resource it will automatically attempt to authenticate and send credential information for the current user to the remote system

**Web Distributed Authoring and Versioning (WebDAV):** Typically used by Windows systems as a backup protocol when SMB is blocked or fails
* WebDAV is an extension of HTTP and will typically operate over TCP ports 80 and 443

Adversaries may take advantage of this behavior to gain access to user account hashes through forced SMB/WebDAV authentication
* An adversary can send an attachment to a user through spearphishing that contains a resource link to an external server controlled by the adversary, or place a specially crafted file on navigation path for privileged accounts (e.g. .SCF file placed on desktop) or on a publicly accessible share to be accessed by victims
* When the user's system accesses the untrusted resource it will attempt authentication and send information, including the user's hashed credentials, over SMB to the adversary controlled server
* With access to the credential hash, an adversary can perform off-line **Brute Force** cracking to gain access to plaintext credentials

There are several different ways this can occur:

* A spearphishing attachment containing a document with a resource that is automatically loaded when the document is opened (**Template Injection**)
  * The document can include a request similar to `file[:]//[remote address]/Normal.dotm` to trigger the SMB request
* A modified **.LNK or .SCF** file with the icon filename pointing to an external reference such as `\[remote address]\pic.png` that will force the system to load the resource when the icon is rendered to repeatedly gather credentials
<hr>

# Forge Web Credentials
Adversaries may forge credential materials that can be used to gain access to web applications or Internet services
* Web applications and services often use session cookies, tokens, or other materials to authenticate and authorize user access

Adversaries may generate these credential materials in order to gain access to web resources
* **NOTE::** This differs from *Steal Web Session Cookie, Steal Application Access Token*, and other similar behaviors in that the credentials are new and forged by the adversary, rather than stolen or intercepted from legitimate users
* The generation of web credentials often requires secret values, such as passwords, Private Keys, or other cryptographic seed values 

Once forged, adversaries may use these web credentials to access resources (ex: *Use Alternate Authentication Material*), which may bypass MFA and other mechanisms 

## Web Cookies
Adversaries may generate cookies in order to gain access to web resources
* Most common web applications have standardized and documented cookie values that can be generated using provided tools or interfaces
* The generation of web cookies often requires secret values, such as passwords, Private Keys, or other cryptographic seed values

Once forged, adversaries may use these web cookies to access resources (Web Session Cookie), which may bypass multi-factor and other authentication protection mechanisms 
<br>

## SAML Tokens
An adversary may forge SAML tokens with any permissions claims and lifetimes if they possess a valid SAML token-signing certificate
* The default lifetime of a SAML token is one hour, but the validity period can be specified in the `NotOnOrAfter` value of the `conditions ...` element in a token
  * This value can be changed using the `AccessTokenLifetime` in a `LifetimeTokenPolicy`
* Forged SAML tokens enable adversaries to authenticate across services that use SAML 2.0 as an SSO mechanism 

An adversary may utilize **Private Keys** to compromise an organization's token-signing certificate to create forged SAML tokens
* If the adversary has sufficient permissions to establish a new federation trust with their own Active Directory Federation Services (AD FS) server, they may instead generate their own trusted token-signing certificate
* **NOTE::** This differs from *Steal Application Access Token* and other similar behaviors in that the tokens are new and forged by the adversary, rather than stolen or intercepted from legitimate users

An adversary may gain administrative Azure AD privileges if a SAML token is forged which claims to represent a highly privileged account
<hr>

# Input Capture
Adversaries may use methods of capturing user input to obtain credentials or collect information
* During normal system usage, users often provide credentials to various different locations, such as login pages/portals or system dialog boxes
* Input capture mechanisms may be transparent to the user (e.g. **Credential API Hooking**) or rely on deceiving the user into providing input into what they believe to be a genuine service (e.g. **Web Portal Capture)**

## Keylogging
Adversaries may log user keystrokes to intercept credentials as the user types them
* Keylogging is likely to be used to acquire credentials for new access opportunities when **OS Credential Dumping** efforts are not effective, and may require an adversary to intercept keystrokes on a system for a substantial period of time before credentials can be successfully captured

Keylogging is the most prevalent type of input capture, with many different ways of intercepting keystrokes; Some methods include:

* Hooking API callbacks used for processing keystrokes
  * Unlike **Credential API Hooking**, this focuses solely on API functions intended for processing keystroke data
* Reading raw keystroke data from the hardware buffer
* Windows Registry modifications
* Custom drivers
* **Modify System Image** may provide adversaries with hooks into the operating system of network devices to read raw keystrokes for login sessions
<br>

## GUI Input Capture
When programs are executed that need additional privileges than are present in the current user context, it is common for the operating system to prompt the user for proper credentials to authorize the elevated privileges for the task (ex: **Bypass User Account Control**)

Adversaries may mimic this functionality to prompt users for credentials with a seemingly legitimate prompt for a number of reasons that mimic normal usage, such as a fake installer requiring additional access or a fake malware removal suite
* This type of prompt can be used to collect credentials via various languages such as AppleScript and PowerShell
* On Linux systems adversaries may launch dialog boxes prompting users for credentials from malicious shell scripts or the command line 
<br>

## Web Portal Capture
Adversaries may install code on externally facing portals, such as a VPN login page, to capture and transmit credentials of users who attempt to log into the service
* A compromised login page may log provided user credentials before logging the user in to the service

This variation on input capture may be conducted post-compromise using legitimate administrative access as a backup measure to maintain network access through *External Remote Services and Valid Accounts* or as part of the initial compromise by exploitation of the externally facing web service
<br>

## Credential API Hooking
Adversaries may hook into Windows API functions to collect user credentials
* Malicious hooking mechanisms may capture API calls that include parameters that reveal user authentication credentials
  * **NOTE::** Unlike Keylogging, this technique focuses specifically on API functions that include parameters that reveal user credentials
* Hooking involves redirecting calls to these functions and can be implemented via:

* **Hooks procedures**, which intercept and execute designated code in response to events such as messages, keystrokes, and mouse inputs
* **Import address table (IAT) hooking**, which use modifications to a process’s IAT, where pointers to imported API functions are stored
* **Inline hooking**, which overwrites the first bytes in an API function to redirect code flow

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
<hr>

# MFA Interception
Adversaries may target MFA mechanisms to gain access to credentials that can be used to access systems, services, and network resources

If a smart card is used for MFA, then a keylogger will need to be used to obtain the password associated with a smart card during normal use
* With both an inserted card and access to the smart card password, an adversary can connect to a network resource using the infected system to proxy the authentication with the inserted hardware token 

Adversaries may also employ a keylogger to similarly target other hardware tokens
* Capturing token input including PIN code may provide temporary access (i.e. replay the one-time passcode until the next value rollover) as well as possibly enabling adversaries to reliably predict future authentication values (given access to both the algorithm and any seed values used to generate appended temporary codes) 

Other methods of MFA may be intercepted and used by an adversary to authenticate. It is common for one-time codes to be sent via out-of-band communications (email, SMS). If the device and/or service is not secured, then it may be vulnerable to interception. Although primarily focused on by cyber criminals, these authentication mechanisms have been targeted by advanced actors 
<hr>

# MFA Request Generation
Adversaries in possession credentials to *Valid Accounts* may be unable to complete the login process if they lack access to the 2FA/MFA mechanisms required as an additional credential and security control
* To circumvent this, adversaries may abuse the automatic generation of push notifications to MFA services such as Duo Push, Microsoft Authenticator, Okta, or similar services to have the user grant access to their account

Attackers may continuously repeat login attempts in order to bombard users with MFA push notifications, SMS messages, and phone calls, potentially resulting in the user finally accepting the authentication request in response to *MFA fatigue*
<hr>

# Network Sniffing
**Network Sniffing:** Refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection
* An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data

Data captured via this technique may include user credentials, especially those sent over an insecure, unencrypted protocol
* Techniques for name service resolution poisoning, such as **LLMNR/NBT-NS Poisoning and SMB Relay**, can also be used to capture credentials to websites, proxies, and internal systems by redirecting traffic to an adversary

Network sniffing may also reveal configuration details, such as running services, version numbers, and other network characteristics necessary for *Lateral Movement and/or Defense Evasion* activities

In cloud-based environments, adversaries may still be able to use traffic mirroring services to sniff network traffic from virtual machines
* AWS Traffic Mirroring, GCP Packet Mirroring, and Azure vTap allow users to define specified instances to collect traffic from and specified targets to send collected traffic to
  * Often, much of this traffic will be in cleartext due to the use of TLS termination at the load balancer level to reduce the strain of encrypting and decrypting traffic
  * The adversary can then use exfiltration techniques such as *Transfer Data to Cloud Account* in order to access the sniffed traffic
<hr>

# OS Credential Dumping
Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password, from the operating system and software

## LSASS Memory
Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS)
* After a user logs on, the system generates and stores a variety of credential materials in LSASS process memory
  * These credential materials can be harvested by an administrative user or SYSTEM and used to conduct Lateral Movement using Use Alternate Authentication Material

LSASS process memory can be dumped from the target host and analyzed on a local system

**For example, on the target host use procdump:**

* `procdump -ma lsass.exe lsass_dump`

**Locally, mimikatz can be run using:**

* `sekurlsa::Minidump lsassdump.dmp`\
* `sekurlsa::logonPasswords`

**Built-in Windows tools such as comsvcs.dll can also be used:**

* `rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump PID lsass.dmp full`


Windows Security Support Provider (SSP) DLLs are loaded into LSSAS process at system start
* Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs
* **The SSP configuration is stored in two Registry keys:**
  * `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages and HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages`
    * Attackers may modify these Registry keys to add new SSPs, which will be loaded the next time the system boots, or when the `AddSecurityPackage` Windows API function is called

**The following SSPs can be used to access credentials:**

* **Msv:** Interactive logons, batch logons, and service logons are done through the MSV authentication package
* **Wdigest:** The Digest Authentication protocol is designed for use with HTTP and Simple Authentication Security Layer (SASL) exchanges
* **Kerberos:** Preferred for mutual client-server domain authentication in Windows 2000 and later
* **CredSSP:** Provides SSO and Network Level Authentication for Remote Desktop Services
<br>

## Security Account Manager (SAM)
**SAM:** A database file that contains local accounts for the host, typically those found with the net user command. Enumerating the SAM database requires SYSTEM level access
* Adversaries may attempt to extract credential material from the SAM database either through in-memory techniques or through the Windows Registry where the SAM database is stored

**Tools to retrieve the SAM file through in-memory techniques:**

* pwdumpx.exe
* gsecdump
* Mimikatz
* secretsdump.py


**Exstract the SAM from the Registry with Reg:**

* `reg save HKLM\sam sam`
* `reg save HKLM\system system`

**Creddump7** can then be used to process the SAM database locally to retrieve hashes

**NOTE::** `* RID 500` account is the local, built-in administrator 
* `* RID 501` is the guest account
* User accounts start with a RID of 1,000+
<br>

## NTDS
Attackers may attempt to access or create a copy of the Active Directory domain database in order to steal credential information, as well as obtain other information about domain members such as devices, users, and access rights
* By default, the NTDS file (`NTDS.dit`) is located in `%SystemRoot%\NTDS\Ntds.dit` of a domain controller

In addition to looking for NTDS files on active DCa, adversaries may search for backups that contain the same or similar information

Tools and techniques used to enumerate the NTDS file and the contents of the entire AD hashes
* Volume Shadow Copy
* secretsdump.py
* Using the in-built Windows tool, ntdsutil.exe
* Invoke-NinjaCopy
<br>

## LSA Secrets
Adversaries with SYSTEM access to a host may attempt to access Local Security Authority (LSA) secrets, which can contain a variety of different credential materials, such as credentials for service accounts
* LSA secrets are stored in the registry at `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets`
* LSA secrets can also be dumped from memory

**Reg** can be used to extract from the Registry
**Mimikatz** can be used to extract secrets from memory
<br>

## Cached Domain Credentials
Adversaries may attempt to access cached domain credentials used to allow authentication to occur in the event a domain controller is unavailable 

On Windows Vista and newer, the hash format is **DCC2** (Domain Cached Credentials version 2) hash, also known as **MS-Cache v2 hash**
* The number of default cached credentials varies and can be altered per system
* This hash does not allow PTH style attacks, and instead requires **Password Cracking** to recover the plaintext password 

With SYSTEM access, the tools/utilities such as Mimikatz, Reg, and secretsdump.py can be used to extract the cached credentials

**NOTE::** Cached credentials for Windows Vista are derived using **PBKDF2** 
<br>

## DCSync
Adversaries may attempt to access credentials and other sensitive information by abusing a Windows Domain Controller's API to simulate the replication process from a remote domain controller using a technique called **DCSync**

Members of the Administrators, Domain Admins, and Enterprise Admin groups or computer accounts on the domain controller are able to run DCSync to pull password data from AD, which may include current and historical hashes of potentially useful accounts such as **KRBTGT** and **Administrators**
* The hashes can then in turn be used to create a **Golden Ticket** for use in PTT or change an account's password as noted in **Account Manipulation**

**DCSync** functionality has been included in the "lsadump" module in Mimikatz
* Lsadump also includes *NetSync*, which performs DCSync over a legacy replication protocol
<br>

## Proc Filesystem
**Proc Filesystem:** Contains a great deal of information regarding the state of the running OS
* Processes running with root privileges can use this facility to scrape live memory of other running programs
* If any of these programs store passwords in clear text or password hashes in memory, these values can then be harvested for either usage or brute force attacks, respectively

**MimiPenguin:** An open source tool inspired by Mimikatz that dumps process memory, then harvests passwords and hashes by looking for text strings and regex patterns for how given applications such as Gnome Keyring, sshd, and Apache use memory to store such authentication artifacts
<br>

## /etc/passwd and /etc/shadow
Modern Linux OSs use a combination of `/etc/passwd` and `/etc/shadow` to store user account information including password hashes in `/etc/shadow`
* By default, `/etc/shadow` is only readable by the root user

The Linux utility, `unshadow`, can be used to combine the two files in a format suited for password cracking utilities such as John the Ripper:
* `/usr/bin/unshadow /etc/passwd /etc/shadow > /tmp/crack.password.db`

<hr>

# Steal Application Access Token
**Application Access Tokens:** Used to make authorized API requests on behalf of a user or service and are commonly used as a way to access resources in cloud and container-based applications and SaaS

**OAuth:** Commonly implemented framework that issues tokens to users for access to systems
* Adversaries who steal account API tokens in cloud and containerized environments may be able to access data and perform actions with the permissions of these accounts, which can lead to privilege escalation and further compromise of the environment

In Kubernetes environments, processes running inside a container communicate with the Kubernetes API server using service account tokens
* If a container is compromised, an attacker may be able to steal the container’s token and thereby gain access to Kubernetes API commands 

**Token Theft** can also occur through social engineering, in which case user action may be required to grant access
* An application desiring access to cloud-based services or protected APIs can gain entry using **OAuth 2.0** through a variety of authorization protocols
  * OAuth access token enables a third-party application to interact with resources containing user data in the ways requested by the application without obtaining user credentials

Adversaries can leverage OAuth authorization by constructing a malicious application designed to be granted access to resources with the target user's OAuth token
* The adversary will need to complete registration of their application with the authorization server, for example Microsoft Identity Platform using Azure Portal, the Visual Studio IDE, the command-line interface, PowerShell, or REST API calls
* Then, they can send a *Spearphishing Link* to the target user to entice them to grant access to the application
* Once the OAuth access token is granted, the application can gain potentially long-term access to features of the user account through Application Access Token

Application access tokens may function within a limited lifetime, limiting how long an adversary can utilize the stolen token
* Attackers can steal application refresh tokens, allowing them to obtain new access tokens without prompting the user
<hr>

# Steal or Forge Kerberos Tickets
**Kerberos:** An authentication protocol widely used in modern Windows domain environments
* In Kerberos environments, referred to as "*realms*", there are three basic participants: **client, service, and Key Distribution Center (KDC)**
  * Clients request access to a service and through the exchange of Kerberos tickets, originating from KDC, they are granted access after having successfully authenticated
  * The KDC is responsible for both authentication and ticket granting
* Adversaries may attempt to abuse Kerberos by stealing tickets or forging tickets to enable unauthorized access

### Windows

On Windows, the built-in **klist** utility can be used to list and analyze cached Kerberos tickets

### Linux

Linux systems on AD domains store Kerberos credentials locally in the credential cache file referred to as the `ccache`
* The credentials are stored in the **ccache** file while they remain valid and generally while a user's session lasts
  * On modern Redhat Enterprise Linux systems, and derivative distributions, the **System Security Services Daemon (SSSD)** handles Kerberos tickets
  * **SSSD:** Maintains a copy of the ticket database that can be found in `/var/lib/sss/secrets/secrets.ldb` as well as the corresponding key located in `/var/lib/sss/secrets/.secrets.mkey`
    * Both files require root access to read -- If an adversary is able to access the database and key, the credential cache Kerberos blob can be extracted and converted into a usable Kerberos ccache file that adversaries may use for PTT
    * The ccache file may also be converted into a Windows format using tools such as Kekeo

### macOS

Kerberos tickets on macOS are stored in a standard ccache format, similar to Linux
* Access to these **ccache** entries is federated through the KCM daemon process via the Mach RPC protocol -- which uses the caller's environment to determine access
* The storage location for these ccache entries is influenced by the `/etc/krb5.conf` configuration file and the **KRB5CCNAME** environment variable which can specify to save them to disk or keep them protected via the KCM daemon
* Users can interact with ticket storage using `kinit`, `klist`, `ktutil`, and `kcc built-in binaries` or via Apple's native Kerberos framework
* Adversaries can use open source tools to interact with the ccache files directly or to use the Kerberos framework to call lower-level APIs for extracting the user's TGT or Service Tickets

## Golden Ticket
Adversaries who have the KRBTGT account password hash may forge Kerberos ticket-granting tickets (TGT), aka **Golden Ticket**
* Golden tickets enable adversaries to generate authentication material for any account in AD

Using a golden ticket, adversaries are then able to request Ticket Granting Service (TGS) tickets, which enable access to specific resources
* Golden tickets require adversaries to interact with the Key Distribution Center (KDC) in order to obtain TGS

The KDC service runs all on DCs that are part of an AD domain
* **KRBTGT:** The Kerberos Key Distribution Center (KDC) service account and is responsible for encrypting and signing all Kerberos tickets
  * The KRBTGT password hash may be obtained using OS Credential Dumping and privileged access to a DC
<br>

## Silver Ticket
Adversaries who have the password hash of a target service account may forge Kerberos TGS tickets, aka **Silver Tickets**
* Kerberos TGS tickets are also known as Service Tickets

**Silver Tickets** are more limited in scope in than golden tickets in that they only enable adversaries to access a particular resource and the system that hosts the resource; however, unlike golden tickets, adversaries with the ability to forge silver tickets are able to create TGS tickets without interacting with the Key Distribution Center (KDC), potentially making detection more difficult

<br>

## Kerberoasting
Adversaries may abuse a valid Kerberos TGTs or sniff network traffic to obtain a TGS ticket that may be vulnerable to **Brute Force**

**Service Principal Names (SPNs):** Used to uniquely identify each instance of a Windows service
* To enable authentication, Kerberos requires that SPNs be associated with at least one service logon account (an account specifically tasked with running a service)

Adversaries possessing a valid Kerberos TGT may request one or more Kerberos TGS for any SPN from a DC
* Portions of these tickets may be encrypted with the RC4 algorithm, meaning the *Kerberos 5 TGS-REP etype 23 hash* of the service account associated with the SPN is used as the private key and is thus vulnerable to offline **Brute Force** attacks that may expose plaintext credentials

**NOTE::** This same behavior could be executed using service tickets captured from network traffic
<br>

## AS-REP Roasting
Adversaries may reveal credentials of accounts that have disabled Kerberos preauthentication by Password Cracking Kerberos messages 

**Preauthentication:** Offers protection against offline Password Cracking
* When enabled, a user requesting access to a resource initiates communication with the DC by sending an **Authentication Server Request (AS-REQ)** message with a timestamp that is encrypted with the hash of their password
* If and only if the DC is able to successfully decrypt the timestamp with the hash of the user’s password, it will then send an AS-REP message that contains the TGT to the user. Part of the AS-REP message is signed with the user’s password 

For each account found without preauthentication, an adversary may send an AS-REQ message without the encrypted timestamp and receive an AS-REP message with TGT data which may be encrypted with an insecure algorithm
* The recovered encrypted data may be vulnerable to offline Password Cracking attacks similarly to Kerberoasting and expose plaintext credentials 

An account registered to a domain, with or without special privileges, can be abused to list all domain accounts that have preauthentication disabled by utilizing Windows tools like PowerShell with an LDAP filter
* Alternatively, the adversary may send an AS-REQ message for each user
  * If the DC responds without errors, the account does not require preauthentication and the AS-REP message will already contain the encrypted data 
<hr>

# Steal Web Session Cookie
Web applications and services often use session cookies as an authentication token after a user has authenticated to a website
* An adversary may steal web application or service session cookies and use them to gain access to web applications or Internet services as an authenticated user without needing credentials

Cookies are often valid for an extended period of time, even if the web application is not actively used
* Cookies can be found on disk, in the process memory of the browser, and in network traffic to remote systems
* Additionally, other applications on the targets machine might store sensitive authentication cookies in memory (e.g. apps which authenticate to cloud services)
* Session cookies can be used to bypasses some multi-factor authentication protocols 

There are several examples of malware targeting cookies from web browsers on the local system
* There are also open source frameworks such as Evilginx 2 and Muraena that can gather session cookies through a malicious proxy (ex: Adversary-in-the-Middle) that can be set up by an adversary and used in phishing campaigns 
* After an adversary acquires a valid cookie, they can then perform a Web Session Cookie technique to login to the corresponding web application
<hr>

# Unsecured Credentials
Adversaries may search compromised systems to find and obtain insecurely stored credentials
* These credentials can be stored and/or misplaced in many locations on a system, including plaintext files Bash History, operating system or application-specific repositories (e.g. Credentials in Registry), or other specialized files/artifacts (e.g. Private Keys)

## Credentials In Files
Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials
* These can be files created by users to store their own credentials, shared credential stores for a group of individuals, configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords

It is possible to extract passwords from backups or saved virtual machines through OS Credential Dumping
* Passwords may also be obtained from Group Policy Preferences stored on the Windows DC

In cloud and/or containerized environments, authenticated user and service account credentials are often stored in local configuration and credential files
* They may also be found as parameters to deployment commands in container logs
* In some cases, these files can be copied and reused on another machine or the contents can be read and then used to authenticate without needing to copy any file
<br>

## Credentials in Registry
The Windows Registry stores configuration information that can be used by the system or other programs
* Adversaries may query the Registry looking for credentials and passwords that have been stored for use by other programs or services -- Sometimes these credentials are used for automatic logons

**Example commands to find Registry keys related to password information:**
* Local Machine Hive: `reg query HKLM /f password /t REG_SZ /s`
* Current User Hive: `reg query HKCU /f password /t REG_SZ /s`
<br>

## Bash History
Adversaries may search the bash command history on compromised systems for insecurely stored credentials
* Bash keeps track of the commands users type on the CLI with the "history" utility
* Once a user logs out, the history is flushed to the user’s `.bash_history` file
  * For each user, this file resides at the same location: `~/.bash_history`
* Typically, this file keeps track of the user’s last 500 commands
* Users often type usernames and passwords on the command-line as parameters to programs, which then get saved to this file when they log out
* Adversaries can abuse this by looking through the file for potential credentials
<br>

## Private Keys
Private cryptographic keys and certificates are used for authentication, encryption/decryption, and digital signatures
* Common key and certificate file extensions include: **.key, .pgp, .gpg, .ppk., .p12, .pem, .pfx, .cer, .p7b, .asc.**

Adversaries may search for private key certificate files on compromised systems for insecurely stored credentials
* Look in common key directories, such as `~/.ssh` for SSH keys on UNIX-based systems or `C:\Users\(username)\.ssh\` on Windows
* These private keys can be used to authenticate to Remote Services like SSH or for use in decrypting other collected files such as email
<br>

## Cloud Instance Metadata API
**Cloud Instance Metadata API:** A service provided to running virtual instances that allows applications to access information about the running virtual instance

Available information generally includes name, security group, and additional metadata including sensitive data such as credentials and UserData scripts that may contain additional secrets
* The Instance Metadata API is provided as a convenience to assist in managing applications and is accessible by anyone who can access the instance
* A cloud metadata API has been used in at least one high profile compromise

If adversaries have a presence on the running virtual instance, they may query the Instance Metadata API directly to identify credentials that grant access to additional resources
* Additionally, adversaries may exploit a Server-Side Request Forgery (SSRF) vulnerability in a public facing web proxy that allows them to gain access to the sensitive information via a request to the Instance Metadata API

**NOTE::** The de facto standard across cloud service providers is to host the Instance Metadata API at `http[:]//169.254.169.254`
<br>

## Group Policy Preferences
**GPP:** Tools that allow administrators to create domain policies with embedded credentials -- These policies allow administrators to set local accounts

These group policies are stored in SYSVOL on a DC
* This means that any domain user can view the SYSVOL share and decrypt the password (using the AES key that has been made public)

The following tools and scripts can be used to gather and decrypt the password file from Group Policy PrefAdversaries may sniff network traffic to capture information about an environment, including authentication material passed over the network. Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.

Data captured via this technique may include user credentials, especially those sent over an insecure, unencrypted protocol. Techniques for name service resolution poisoning, such as LLMNR/NBT-NS Poisoning and SMB Relay, can also be used to capture credentials to websites, proxies, and internal systems by redirecting traffic to an adversary.

Network sniffing may also reveal configuration details, such as running services, version numbers, and other network characteristics (e.g. IP addresses, hostnames, VLAN IDs) necessary for subsequent Lateral Movement and/or Defense Evasion activities.

In cloud-based environments, adversaries may still be able to use traffic mirroring services to sniff network traffic from virtual machines. For example, AWS Traffic Mirroring, GCP Packet Mirroring, and Azure vTap allow users to define specified instances to collect traffic from and specified targets to send collected traffic to.[1] [2] [3] Often, much of this traffic will be in cleartext due to the use of TLS termination at the load balancer level to reduce the strain of encrypting and decrypting traffic.[4] [5] The adversary can then use exfiltration techniques such as Transfer Data to Cloud Account in order to access the sniffed traffic. [4]erence XML files:

* Metasploit’s post exploitation module: `post/windows/gather/credentials/gpp Get-GPPPassword`
* `gpprefdecrypt.py`

**On the SYSVOL share, use the following command to enumerate potential GPP XML files:** `dir /s * .xml`
<br>

## Container API
Adversaries may gather credentials via APIs within a containers environment. APIs in these environments, such as the Docker API and Kubernetes APIs, allow a user to remotely manage their container resources and cluster components

An adversary may access the Docker API to collect logs that contain credentials to cloud, container, and various other resources in the environment
* An adversary with sufficient permissions, such as via a pod's service account, may also use the Kubernetes API to retrieve credentials from the Kubernetes API server
  * These credentials may include those needed for Docker API authentication or secrets from Kubernetes cluster components
<hr>

