# Impact

Impact consists of techniques that adversaries use to disrupt availability or compromise integrity by manipulating business and operational processes. Techniques used for impact can include destroying or tampering with data. In some cases, business processes can look fine, but may have been altered to benefit the adversaries’ goals. These techniques might be used by adversaries to follow through on their end goal or to provide cover for a confidentiality breach.
<br>

<hr>

# Table of Contents
- [Account Access Removal](#account-access-removal)
- [Data Destruction](#data-destruction)
- [Data Encrypted for Impact](#data-encrypted-for-impact)
- [Data Manipulation](#data-manipulation)
  - [Stored Data Manipulation](#stored-data-manipulation)
  - [Transmitted Data Manipulation](#transmitted-data-manipulation)
  - [Runtime Data Manipulation](#runtime-data-manipulation)
- [Defacement](#defacement)
  - [Internal Defacement](#internal-defacement)
  - [External Defacement](#external-defacement)
- [Disk Wipe](#disk-wipe)
  - [Disk Content Wipe](#disk-content-wipe)
  - [Disk Structure Wipe](#disk-structure-wipe)
- [Endpoint Denial of Service](#endpoint-denial-of-service)
  - [OS Exhaustion Flood](#os-exhaustion-flood)
  - [Service Exhaustion Flood](#service-exhaustion-flood)
  - [Application Exhaustion Flood](#application-exhaustion-flood)
  - [Application or System Exploitation](#application-or-system-exploitation)
- [Firmware Corruption](#firmware-corruption)
- [Inhibit System Recovery](#inhibit-system-recovery)
- [Network Denial of Service](#network-denial-of-service)
  - [Direct Network Flood](#direct-network-flood)
  - [Reflection Amplification](#reflection-amplification)
- [Resource Hijacking](#resource-hijacking)
- [Service Stop](#service-stop)
- [System Shutdown/Reboot](#system-shutdownreboot)
<br>

<hr>

# Account Access Removal
Accounts may be deleted, locked, or manipulated to remove access to accounts
* Adversaries may also log off and/or perform a *System Shutdown/Reboot* to set malicious changes into place

* **Windows:** `Set-LocalUser` and `Set-ADAccountPassword` may be used to modify user accounts
* **Linux:** `passwd` may be used to change passwords
* Accounts could also be disabled by Group Policy

**NOTE::** Adversaries who use ransomware may first perform this and other *Impact* behaviors, such as *Data Destruction* and *Defacement*, before completing the *Data Encrypted for Impact* objective
<br>
<hr>

# Data Destruction
Adversaries may destroy data and files on specific systems or in large numbers on a network to interrupt availability to systems, services, and network resources

Data destruction is likely to render stored data irrecoverable by forensic techniques through overwriting files or data on local and remote drives
* Common OS file deletion commands such as `del` and `rm` often only remove pointers to files without wiping the contents of the files themselves, making the files recoverable by proper forensic methodology
  * This is distinct from *Disk Content Wipe* and *Disk Structure Wipe* because individual files are destroyed rather than sections of a storage disk or the disk's logical structure

Adversaries may attempt to overwrite files and directories with randomly generated data to make it irrecoverable; In some cases politically oriented image files have been used to overwrite data

To maximize impact on the target organization in operations where network-wide availability interruption is the goal, malware designed for destroying data may have worm-like features to propagate across a network by leveraging additional techniques like *Valid Accounts, OS Credential Dumping, and SMB/Windows Admin Shares*

* In cloud environments, adversaries may leverage access to delete cloud storage, cloud storage accounts, machine images, and other infrastructure crucial to operations to damage an organization or their customers
<br>
<hr>

# Data Encrypted for Impact
Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources. They can attempt to render stored data inaccessible by encrypting files or data on local and remote drives and withholding access to a decryption key

In the case of ransomware, typically common user files like Office documents, PDFs, images, videos, audio, text, and source code files will be encrypted (and often renamed and/or tagged with specific file markers)
* Adversaries may need to first employ other behaviors, such as *File and Directory Permissions Modification* or *System Shutdown/Reboot*, in order to unlock and/or gain access to manipulate these files
  * In some cases, adversaries may encrypt critical system files, disk partitions, and the MBR   

To maximize impact on the target organization, malware designed for encrypting data may have worm-like features to propagate across a network by leveraging other attack techniques like *Valid Accounts, OS Credential Dumping, and SMB/Windows Admin Shares*

* Encryption malware may also leverage *Internal Defacement*, such as changing victim wallpapers, or otherwise intimidate victims by sending ransom notes or other messages to connected printers (Print Bombing)

<br>
<hr>

# Data Manipulation
Adversaries may insert, delete, or manipulate data in order to influence external outcomes or hide activity, thus threatening the integrity of the data; By manipulating data, adversaries may attempt to affect a business process, organizational understanding, or decision making.

The type of modification and the impact it will have depends on the target application and process as well as the goals and objectives of the adversary
* For complex systems, an adversary would likely need special expertise and possibly access to specialized software related to the system that would typically be gained through a prolonged information gathering campaign in order to have the desired impact
<br>

## Stored Data Manipulation
Stored data could include a variety of file formats, such as Office files, databases, stored emails, and custom file formats
* The type of modification and the impact it will have depends on the type of data as well as the goals and objectives of the adversary
<br>

## Transmitted Data Manipulation
Adversaries may alter data en route to storage or other systems in order to manipulate external outcomes or hide activity; threatening the integrity of the data
* By manipulating transmitted data, adversaries may attempt to affect a business process, organizational understanding, and decision making

Manipulation may be possible over a network connection or between system processes where there is an opportunity deploy a tool that will intercept and change information
* The type of modification and the impact it will have depends on the target transmission mechanism as well as the goals and objectives of the adversary
<br>

## Runtime Data Manipulation
Adversaries may modify systems in order to manipulate the data as it is accessed and displayed to an end user; threatening the integrity of the data
* By manipulating runtime data, adversaries may attempt to affect a business process, organizational understanding, and decision making

Adversaries may alter application binaries used to display data in order to cause runtime manipulations
* Adversaries may also conduct *Change Default File Association and Masquerading* to cause a similar effect
* The type of modification and the impact it will have depends on the target application and process as well as the goals and objectives of the adversary
<br>

# Defacement
Adversaries may modify visual content available internally or externally to an enterprise network; affecting the integrity of the original content
* *Reasons for Defacement* include delivering messaging, intimidation, or claiming credit for an intrusion
* Disturbing or offensive images may be used as a part of Defacement in order to cause user discomfort, or to pressure compliance with accompanying messages
<br>

## Internal Defacement
An adversary may deface systems internal to an organization in an attempt to intimidate or mislead users; discrediting the integrity of the systems
* This may take the form of modifications to internal websites, or directly to user systems with the replacement of the desktop wallpaper
* Disturbing or offensive images may be used as a part of *Internal Defacement* in order to cause user discomfort, or to pressure compliance with accompanying messages
* Since internally defacing systems exposes an adversary's presence, it often takes place after other intrusion goals have been accomplished
<br>

## External Defacement
An adversary may deface systems external to an organization in an attempt to deliver messaging, intimidate, or otherwise mislead an organization or users
* *External Defacement* may ultimately cause users to distrust the systems and to question/discredit the system’s integrity
* Externally-facing websites are a common victim of defacement; often targeted by adversary and hacktivist groups in order to push a political message or spread propaganda
* External Defacement may be used as a catalyst to trigger events, or as a response to actions taken by an organization or government
  * Similarly, website defacement may also be used as setup, or a precursor, for future attacks such as *Drive-by Compromise*
<br>
<hr>

# Disk Wipe
Adversaries may wipe or corrupt raw disk data on specific systems or in large numbers in a network to interrupt availability to system and network resources
* With direct write access to a disk, adversaries may attempt to overwrite portions of disk data
* Adversaries may opt to wipe arbitrary portions of disk data and/or wipe disk structures like the MBR; A complete wipe of all disk sectors may be attempted

To maximize impact on the target organization in operations where network-wide availability interruption is the goal, malware used for wiping disks may have worm-like features to propagate across a network by leveraging additional techniques like *Valid Accounts, OS Credential Dumping, and SMB/Windows Admin Shares*
<br>

## Disk Content Wipe
Adversaries may erase the contents of storage devices on specific systems or in large numbers in a network to interrupt availability to system and network resources

* Adversaries may partially or completely overwrite the contents of a storage device rendering the data irrecoverable through the storage interface
* Instead of wiping specific disk structures or files, adversaries with destructive intent may wipe arbitrary portions of disk content
  * To wipe disk content, adversaries may acquire direct access to the hard drive in order to overwrite arbitrarily sized portions of disk with random data
* Adversaries have been observed leveraging third-party drivers like `RawDisk` to directly access disk content
* **NOTE::** This behavior is distinct from *Data Destruction* because sections of the disk are erased instead of individual files
<br>

## Disk Structure Wipe
Adversaries may corrupt or wipe the disk data structures on a hard drive necessary to boot a system; targeting specific critical systems or in large numbers in a network to interrupt availability to system and network resources
* Adversaries may attempt to render the system unable to boot by overwriting critical data located in structures such as the MBR or partition table
* The data contained in disk structures may include the initial executable code for loading an operating system or the location of the file system partitions on disk
  * If this information is not present, the computer will not be able to load an operating system during the boot process, leaving the computer unavailable
* *Disk Structure Wipe* may be performed in isolation, or along with *Disk Content Wipe* if all sectors of a disk are wiped
<br>
<hr>

# Endpoint Denial of Service
**Endpoint DoS:** Denies the availability of a service without saturating the network used to provide access to the service
* Adversaries can target various layers of the application stack that is hosted on the system used to provide the service
  * These layers include the OS, server applications, DNS servers, databases, and the applications that sit on top of them
  * Attacking each layer requires different techniques that take advantage of bottlenecks that are unique to the respective component

Adversaries may use the original IP address of an attacking system, or spoof the source IP address to make the attack traffic more difficult to trace back to the attacking system or to enable reflection
* This can increase the difficulty defenders have in defending against the attack by reducing or eliminating the effectiveness of filtering by the source address on network defense devices

Botnets are commonly used to conduct DDoS attacks against networks and services
* Adversaries may have the resources to build out and control their own botnet infrastructure or may rent time on an existing botnet to conduct an attack

Where *Traffic Manipulation* is used, there may be points where packets can be altered and cause legitimate clients to execute code that directs network packets toward a target in high volume
* This type of capability was previously used for the purposes of web censorship where client HTTP traffic was modified to include a reference to JavaScript that generated the DDoS code to overwhelm target web servers

<br>

## OS Exhaustion Flood
**Operating System:** Responsible for managing the finite resources as well as preventing the entire system from being overwhelmed by excessive demands on its capacity
* Exhaustion Floos does not need to exhaust the actual resources on a system; the attacks may simply exhaust the limits and available resources that an OS self-imposes

* **TCP state-exhaustion** attacks -- SYN floods and ACK floods
  * With SYN floods, excessive amounts of SYN packets are sent, but the 3-way TCP handshake is never completed
    * Because each OS has a maximum number of concurrent TCP connections that it will allow, this can quickly exhaust the ability of the system to receive new requests for TCP connections; preventing access to any TCP service provided by the server
  * **ACK floods** leverage the stateful nature of the TCP protocol
    * A flood of ACK packets are sent to the target, forcing the OS to search its state table for a related TCP connection that has already been established
      * Because the ACK packets are for connections that do not exist, the OS will have to search the entire state table to confirm that no match exists
      * When it is necessary to do this for a large flood of packets, the computational requirements can cause the server to become sluggish and/or unresponsive, due to the work it must do to eliminate the rogue ACK packets
<br>

## Service Exhaustion Flood
Adversaries may target the different network services provided by systems to conduct a DoS attack, often targeting the availability of DNS and web services
* Web server software can be attacked through a variety of means;
  * **Simple HTTP Flood:** Sending a large number of HTTP requests to a web server to overwhelm it/ the application that runs on top of it
    * This flood relies on raw volume to accomplish the objective, exhausting any of the various resources required by the victim software to provide the service
  * **SSL Renegotiation Attack:** Takes advantage of a protocol feature in SSL/TLS
    * The SSL/TLS protocol suite includes mechanisms for the client and server to agree on an encryption algorithm to use for subsequent secure connections
      * If SSL renegotiation is enabled, a request can be made for renegotiation of the crypto algorithm
      * In a renegotiation attack, the adversary establishes a SSL/TLS connection and then proceeds to make a series of renegotiation requests
<br>

## Application Exhaustion Flood
Adversaries may target resource intensive features of applications to cause a DoS attack, denying availability to those applications
* Specific features in web applications may be highly resource intensive; Repeated requests to those features may be able to exhaust system resources and deny access to the application or the server itself
<br>

## Application or System Exploitation
Adversaries may exploit software vulnerabilities that can cause an application or system to crash and deny availability to users. Some systems may automatically restart critical applications and services when crashes occur, but they can likely be re-exploited to cause a persistent DoS condition
* Crashed or restarted applications or systems may also have other effects such as *Data Destruction, Firmware Corruption, Service Stop* etc. which may further cause a DoS condition and deny availability to critical information, applications and/or systems
<br>
<hr>

# Firmware Corruption
**Firmware:** Software that is loaded and executed from non-volatile memory on hardware devices in order to initialize and manage device functionality (motherboard, hard drive, video cards, etc.)

Adversaries may overwrite or corrupt the flash memory contents of system BIOS or other firmware in devices attached to a system in order to render them inoperable or unable to boot; denying the availability to use the devices and/or the system
<br>
<hr>

# Inhibit System Recovery
OS may contain features that can help fix corrupted systems, such as a backup catalog, volume shadow copies, and automatic repair features; Adversaries may disable or delete system recovery features to augment the effects of *Data Destruction and Data Encrypted for Impact*

**A number of native Windows utilities have been used by adversaries to disable or delete system recovery features:**

* **vssadmin.exe** 
  * `vssadmin.exe delete shadows /all /quiet` -- Delete all volume shadow copies on a system
* **Windows Management Instrumentation (WMI)**
  * `wmic shadowcopy delete` -- Delete volume shadow copies
* **wbadmin.exe** 
  * `wbadmin.exe delete catalog -quiet` -- Delete the Windows Backup Catalog
* **bcdedit.exe** 
  * `bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default}recoveryenabled no` -- Disable automatic Windows recovery features by modifying boot configuration data
<br>
<hr>

# Network Denial of Service
Adversaries may perform Network DoS attacks to degrade or block the availability of targeted resources to users

A Network DoS will occur when the bandwidth capacity of the network connection to a system is exhausted due to the volume of malicious traffic directed at the resource or the network connections and network devices the resource relies on

To perform Network DoS attacks several aspects apply to multiple methods, including IP address spoofing, and botnets
* Adversaries may use the original IP address of an attacking system
* Spoof the source IP address to make the attack traffic more difficult to trace back to the attacking system or to enable reflection
<br>

## Direct Network Flood
Direct Network Floods are when one or more systems are used to send a high-volume of network packets towards the targeted service's network
* Almost any network protocol may be used for flooding
* Stateless protocols such as UDP or ICMP are commonly used but stateful protocols such as TCP can be used as well

Botnets are commonly used to conduct network flooding attacks against networks and services
* In such circumstances, distinguishing DDoS traffic from legitimate clients becomes exceedingly difficult
<br>

## Reflection Amplification
Adversaries may attempt to cause a DoS) by reflecting a high-volume of network traffic to a target -- Takes advantage of a third-party server intermediary that hosts and will respond to a given spoofed source IP address
* An adversary accomplishes a reflection attack by sending packets to reflectors with the spoofed address of the victim

Reflection attacks often take advantage of protocols with larger responses than requests in order to amplify their traffic, commonly known as a Reflection Amplification attack
* Adversaries may be able to generate an increase in volume of attack traffic that is several orders of magnitude greater than the requests sent to the amplifiers
  * The extent of this increase will depending upon many variables, such as the protocol in question, the technique used, and the amplifying servers that actually produce the amplification in attack volume
  * Two prominent protocols that have enabled Reflection Amplification Floods are DNS and NTP
<br>
<hr>

# Resource Hijacking
One common purpose for Resource Hijacking is to validate transactions of cryptocurrency networks and earn virtual currency
* Adversaries may consume enough system resources to negatively impact and/or cause affected machines to become unresponsive
  * Servers and cloud-based systems are common targets because of the high potential for available resources, but user endpoint systems may also be compromised and used for Resource Hijacking and cryptocurrency mining
* Containerized environments may also be targeted due to the ease of deployment via exposed APIs and the potential for scaling mining activities by deploying or compromising multiple containers within an environment or cluster

Additionally, some cryptocurrency mining malware identify then kill off processes for competing malware to ensure it’s not competing for resources
<br>
<hr>

# Service Stop
Adversaries may stop or disable services on a system to render those services unavailable to legitimate users; Stopping critical services or processes can inhibit or stop response to an incident or aid in the adversary's overall objectives to cause damage to the environment

Adversaries may accomplish this by disabling individual services of high importance to an organization, such as **MSExchangeIS**, which will make Exchange content inaccessible
* In some cases, adversaries may stop or disable many or all services to render systems unusable
* Services or processes may not allow for modification of their data stores while running
* Adversaries may stop services or processes in order to conduct *Data Destruction or Data Encrypted for Impact* on the data stores of services like Exchange and SQL Server
<br>
<hr>

# System Shutdown/Reboot
Adversaries may shutdown/reboot systems to interrupt access to, or aid in the destruction of, those systems
* OS may contain commands to initiate a shutdown/reboot of a machine or network device
  * These commands may also be used to initiate a shutdown/reboot of a remote computer or network device 
* Shutting down or rebooting systems may disrupt access to computer resources for legitimate users

Adversaries may attempt to shutdown/reboot a system after impacting it in other ways, such as *Disk Structure Wipe* or *Inhibit System Recovery*, to hasten the intended effects on system availability


