# Command & Control (C2)

Command and Control consists of techniques that adversaries may use to communicate with systems under their control within a victim network. Adversaries commonly attempt to mimic normal, expected traffic to avoid detection. There are many ways an adversary can establish command and control with various levels of stealth depending on the victim’s network structure and defenses.

<br>
<hr>

# Table of Contents
- [Application Layer Protocol](#application-layer-protocol)
  - [Web Protocols](#web-protocols)
  - [File Transfer Protocols](#file-transfer-protocols)
  - [Mail Protocols](#mail-protocols)
  - [DNS](#dns)
- [Communication Through Removable Media](#communication-through-removable-media)
- [Data Encoding](#data-encoding)
  - [Standard Encoding](#standard-encoding)
  - [Non-Standard Encoding](#non-standard-encoding)
- [Data Obfuscation](#data-obfuscation)
  - [Junk Data](#junk-data)
  - [Steganography](#steganography)
  - [Protocol Impersonation](#protocol-impersonation)
- [Dynamic Resolution](#dynamic-resolution)
  - [Fast Flux DNS](#fast-flux-dns)
  - [Domain Generation Algorithms](#domain-generation-algorithms)
  - [DNS Calculation](#dns-calculation)
- [Encrypted Channel](#encrypted-channel)
  - [Symmetric Cryptography](#encrypted-channel)
  - [Asymmetric Cryptography](#asymmetric-cryptography)
- [Fallback Channels](#fallback-channels)
- [Ingress Tool Transfer](#ingress-tool-transfer)
- [Multi-Stage Channels](#multi-stage-channels)
- [Non-Application Layer Protocol](#non-application-layer-protocol)
- [Non-Standard Port](#non-standard-port)
- [Protocol Tunneling](#protocol-tunneling)
- [Proxy](#proxy)
  - [Internal Proxy](#internal-proxy)
  - [External Proxy](#external-proxy)
  - [Multi-Hop Proxy](#multi-hop-proxy)
  - [Domain Fronting](#domain-fronting)
- [Remote Access Software](#remote-access-software)
- [Traffic Signaling](#traffic-signaling)
  - [Port Knocking](#port-knocking)
- [Web Service](#web-service)
  - [Dead Drop Resolver](#dead-drop-resolver)
  - [Bidirectional Communication](#bidirectional-communication)
  - [One-Way Communication](#one-way-communication)

<br>
<hr>

# Application Layer Protocol
Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic
* Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server

* Packets produced from these protocols may have many fields and headers in which data can be concealed
* Data could also be concealed within the transferred files
  * An adversary may abuse these protocols to communicate with systems under their control within a victim network while also mimicking normal, expected traffic

<br>

## Web Protocols
**HTTP(S)** may be abused to communicate with systems under adversary's control within a victim network while also mimicking normal, expected traffic

<br>

## File Transfer Protocols
**FTP, FTPS, and TFTP** that transfer files may be abused to communicate with systems under adversary's control within a victim network while also mimicking normal, expected traffic

<br>

## Mail Protocols
SMTP(S), POP3(S), and IMAP that carry electronic mail may be abused to communicate with systems under adversary's control within a victim network while also mimicking normal, expected traffic

<br>

## DNS
The DNS protocol serves an administrative function in computer networking and thus may be very common in environments
* DNS traffic may also be allowed even before network authentication is completed
* **DNS Tunneling:** Routes DNS requests to the attacker's server, providing attackers a covert C2 channel, and data exfiltration path

<br>
<hr>

# Communication Through Removable Media
Adversaries can perform command and control between compromised hosts on potentially disconnected networks using removable media to transfer commands from system to system

* Both systems would need to be compromised, with the likelihood that an Internet-connected system was compromised first and the second through lateral movement by *Replication Through Removable Media*
* Commands and files would be relayed from the disconnected system to the Internet-connected system to which the adversary has direct access

<br>
<hr>

# Data Encoding
C2 information can be encoded using a standard data encoding system
* Use of data encoding may adhere to existing protocol specifications and includes use of *ASCII, Unicode, Base64, MIME*, or other binary-to-text and character encoding systems
* Some data encoding systems may also result in data compression, such as *gzip*

<br>

## Standard Encoding
Command and control (C2) information can be encoded using a standard data encoding system that adheres to existing protocol specifications
* Common data encoding schemes include *ASCII, Unicode, hexadecimal, Base64, and MIME*
* Some data encoding systems may also result in data compression, such as *gzip*

<br>

## Non-Standard Encoding
C2 information can be encoded using a non-standard data encoding system that diverges from existing protocol specifications
* Non-standard data encoding schemes may be based on or related to standard data encoding schemes, such as a modified *Base64* encoding for the message body of an HTTP request
  
<br>
<hr>

# Data Obfuscation
C2 communications are hidden in an attempt to make the content more difficult to discover or decipher and to make the communication less conspicuous and hide commands from being seen
* This encompasses many methods, such as adding junk data to protocol traffic, using steganography, or impersonating legitimate protocols

<br>

## Junk Data
Adversaries may add junk data to protocols used for C2 to make detection more difficult
* By adding random or meaningless data to the protocols used for C2, adversaries can prevent trivial methods for decoding, deciphering, or otherwise analyzing the traffic
  * Appending/prepending data with junk characters or writing junk characters between significant characters

<br>

## Steganography
Adversaries may use steganographic techniques to hide C2 traffic to make detection efforts more difficult
* Steganographic techniques can be used to hide data in digital messages that are transferred between systems
  * This hidden information can be used for command and control of compromised systems
  * In some cases, the passing of files embedded using steganography, such as image or document files, can be used for C2

<br>

## Protocol Impersonation
Adversaries may impersonate a fake SSL/TLS handshake to make it look like subsequent traffic is SSL/TLS encrypted, potentially interfering with some security tooling, or to make the traffic look like it is related with a trusted entity

<br>
<hr>

# Dynamic Resolution
Adversaries may dynamically establish connections to C2 infrastructure to evade common detections and remediations
* This may be achieved by using malware that shares a common algorithm with the infrastructure the adversary uses to receive the malware's communications
  * These calculations can be used to dynamically adjust parameters such as the domain name, IP address, or port number the malware uses for C2

Adversaries may use dynamic resolution for the purpose of *Fallback Channels*
* When contact is lost with the primary C2 server, malware may employ dynamic resolution as a means to reestablishing command and control

<br>

## Fast Flux DNS
Adversaries may use **Fast Flux DNS** to hide a C2 channel behind an array of rapidly changing IP addresses linked to a single domain resolution
* This technique uses a FQDN, with multiple IP addresses assigned to it which are swapped with high frequency, using a combination of round robin IP addressing and short TTL)for a DNS resource record

The "Single-Flux" method -- Involves registering and de-registering an addresses as part of the DNS A (address) record list for a single DNS name
* These registrations have a five-minute average lifespan, resulting in a constant shuffle of IP address resolution

The "Double-Flux" method -- Registers and de-registers an address as part of the DNS Name Server record list for the DNS zone, providing additional resilience for the connection
* With double-flux additional hosts can act as a proxy to the C2 host, further insulating the true source of the C2 channel

<br>

## Domain Generation Algorithms
Adversaries may make use of **Domain Generation Algorithms (DGAs)** to dynamically identify a destination domain for C2 traffic rather than relying on a list of static IP addresses or domains
* This has the advantage of making it much harder for defenders to block, track, or take over the command and control channel, as there potentially could be thousands of domains that malware can check for instructions

DGAs can take the form of apparently random or "gibberish" strings (ex: `istgmxdejdnxuyla.ru`) when they construct domain names by generating each letter
* Alternatively, some DGAs employ whole words as the unit by concatenating words together instead of letters (ex: `cityjulydish.net`)
* Many DGAs are time-based, generating a different domain for each time period (hourly, daily, monthly, etc)
  * Others incorporate a seed value as well to make predicting future domains more difficult for defenders

Adversaries may use DGAs for the purpose of *Fallback Channels*
* When contact is lost with the primary command and control server malware may employ a DGA as a means to reestablishing command and control

<br>

## DNS Calculation
Adversaries may perform calculations on addresses returned in DNS results to determine which port and IP address to use for command and control, rather than relying on a predetermined port number or the actual returned IP address
* An IP and/or port number calculation can be used to bypass egress filtering on a C2 channel
* One implementation of **DNS Calculation** is to take the first three octets of an IP address in a DNS response and use those values to calculate the port for C2 traffic

<br>
<hr>

# Encrypted Channel
Adversaries may employ a known encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol
* Despite the use of a secure algorithm, these implementations may be vulnerable to reverse engineering if secret keys are encoded and/or generated within malware samples/configuration files

<br>

## Symmetric Cryptography
Symmetric encryption algorithms use the same key for plaintext encryption and ciphertext decryption -- Common symmetric encryption algorithms include AES, DES, 3DES, Blowfish, and RC4
* Adversaries may employ a known symmetric encryption algorithm to conceal C2 traffic rather than relying on any inherent protections provided by a communication protocol

<br>

## Asymmetric Cryptography
**Asymmetric cryptography / Public Key Cryptography:** Uses public and private pairs per party; Common public key encryption algorithms include *RSA and ElGamal*
* Many protocols uses symmetric cryptography once a connection is established, but use asymmetric cryptography to establish or transmit a key

<br>
<hr>

# Fallback Channels
Attackers may use fallback or alternate communication channels if the primary channel is compromised or inaccessible in order to maintain reliable command and control and to avoid data transfer thresholds

<br>
<hr>

# Ingress Tool Transfer
Tools or files may be copied from an external adversary-controlled system to the victim network through the C2 channel or through alternate protocols such as `ftp`
* Once present, adversaries may also transfer/spread tools between victim devices within a compromised environment (*Lateral Tool Transfer*)

Files can also be transferred using various Web Services as well as native or otherwise present tools on the victim system

## Windows
Adversaries may use various utilities to download tools, such as `copy`, `finger`, and PowerShell commands such as `IEX(New-Object Net.WebClient).downloadString()` and `Invoke-WebRequest`

## UNIX
A variety of utilities exist, such as `curl`, `scp`, `sftp`, `tftp`, `rsync`, `finger`, and `wget`

<br>
<hr>

# Multi-Stage Channels
Adversaries may create multiple stages for command and control that are employed under different conditions or for certain functions; Use of multiple stages may obfuscate the C2 channel to make detection more difficult

1. Remote access tools will call back to the first-stage C2 server for instructions
* The first stage may have automated capabilities to collect basic host information, update tools, and upload additional files
  
2. A RAT could be uploaded at that point to redirect the host to the second-stage C2 server
* The second stage will likely be more fully featured and allow the adversary to interact with the system through a reverse shell and additional RAT features.

The different stages will likely be hosted separately with no overlapping infrastructure
* The loader may also have backup first-stage callbacks or *Fallback Channels* in case the original first-stage communication path is discovered and blocked

<br>
<hr>

# Non-Application Layer Protocol
Adversaries may use a non-application layer protocol for communication between host and C2 server or among infected hosts within a network

* Layer 3 Protocols -- ICMP
  * Since ICMP is part of the Internet Protocol Suite, it is required to be implemented by all IP-compatible hosts
  * It's not as commonly monitored as other Internet Protocols such as TCP or UDP and may be used by adversaries to hide communications
* Layer 4 Protocols -- UDP
* layer 5 Protocols -- Socket Secure (SOCKS)
* Redirected/Tunneled Protocols -- Serial over LAN (SOL)

<br>
<hr>

# Non-Standard Port
Adversaries may communicate using a protocol and port paring that are typically not associated
* HTTPS over port 8088 or port 587 as opposed to the traditional port 443
* Adversaries may make changes to the standard port used by a protocol to bypass filtering or muddle analysis/parsing of network data

<br>
<hr>

# Protocol Tunneling
Adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection/network filtering and/or enable access to otherwise unreachable systems
* **Tunneling** involves explicitly encapsulating a protocol within another
  * This behavior may conceal malicious traffic by blending in with existing traffic and/or provide an outer layer of encryption (similar to a VPN)
  * Tunneling could also enable routing of network packets that would otherwise not reach their intended destination, such as SMB, RDP, or other traffic that would be filtered by network appliances or not routed over the Internet

There are various means to encapsulate a protocol within another protocol
* Adversaries may perform SSH Tunneling (SSH Port Forwarding), which involves forwarding arbitrary data over an encrypted SSH tunnel

**Protocol Tunneling** may also be abused by adversaries during Dynamic Resolution
* **DNS over HTTPS (DoH):** Queries to resolve C2 infrastructure may be encapsulated within encrypted HTTPS packets

Adversaries may also leverage Protocol Tunneling in conjunction with *Proxy* and/or *Protocol Impersonation* to further conceal C2 communications and infrastructure

<br>
<hr>

# Proxy
Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary for network communications to a C2 server to avoid direct connections to their infrastructure

* Many tools exist that enable traffic redirection through proxies or port redirection, including `HTRAN`, `ZXProxy`, and `ZXPortMap`
  * Adversaries use these types of proxies to:
    * Manage C2 communications
    * Reduce the number of simultaneous outbound network connections
    * Provide resiliency in the face of connection loss
    * Ride over existing trusted communications paths between victims to avoid suspicion
    * Chain together multiple proxies to further disguise the source of malicious traffic

Adversaries can also take advantage of routing schemes in CDNs to proxy C2 traffic

<br>

## Internal Proxy
Adversaries may use an internal proxy to direct C2 traffic between two or more systems in a compromised environment
* Many tools exist that enable traffic redirection through proxies or port redirection, including `HTRAN`, `ZXProxy`, and `ZXPortMap`
* Adversaries use these types of proxies to:
  * Manage C2 communications
  * Reduce the number of simultaneous outbound network connections
  * Provide resiliency in the face of connection loss
  * Ride over existing trusted communications paths between victims to avoid suspicion
  * Chain together multiple proxies to further disguise the source of malicious traffic
* Internal proxy connections may use common P2P networking protocols (SMB) to better blend in with the environment

By using a compromised internal system as a proxy, adversaries may conceal the true destination of C2 traffic while reducing the need for numerous connections to external systems

<br>

## External Proxy
External connection proxies are used to mask the destination of C2 traffic and are typically implemented with port redirectors
* Compromised systems outside of the victim environment may be used for these purposes, as well as purchased infrastructure such as cloud-based resources or virtual private servers
* Proxies may be chosen based on the low likelihood that a connection to them from a compromised system would be investigated
* Victim systems would communicate directly with the external proxy on the Internet and then the proxy would forward communications to the C2 server

<br>

## Multi-hop Proxy
To disguise the source of malicious traffic, adversaries may chain together multiple proxies
* Typically, a defender will be able to identify the last proxy traffic traversed before it enters their network; the defender may or may not be able to identify any previous proxies before the last-hop proxy
  * This technique makes identifying the original source of the malicious traffic even more difficult by requiring the defender to trace malicious traffic through several proxies to identify its source

It's possible for attackers to leverage multiple compromised devices to create a multi-hop proxy chain within the WAN of the enterprise
* By leveraging *Patch System Image*, adversaries can add custom code to the affected network devices that will implement onion routing between those nodes
  * This custom onion routing network will transport the encrypted C2 traffic through the compromised population, allowing adversaries to communicate with any device within the onion routing network
  * This method is dependent upon the *Network Boundary Bridging* method in order to allow the adversaries to cross the protected network boundary of the Internet perimeter and into the organization’s WAN
  * Protocols such as ICMP may be used as a transport

<br>

## Domain Fronting
**Domain Fronting:** using different domain names in the SNI field of the TLS header and the *Host* field of the HTTP header
* If both domains are served from the same CDN, then the CDN may route to the address specified in the HTTP header after unwrapping the TLS header

* **Domainless Fronting:** Utilizes a *SNI* field that is left blank; this may allow the fronting to work even when the CDN attempts to validate that the SNI and HTTP Host fields match (if the blank SNI fields are ignored)

Adversaries may take advantage of routing schemes in CDNs and other services which host multiple domains to obfuscate the intended destination of HTTPS traffic or traffic tunneled through HTTPS
* If domain-x and domain-y are customers of the same CDN, it is possible to place domain-x in the TLS header and domain-y in the HTTP header
  * Traffic will appear to be going to domain-x, however the CDN may route it to domain-y

<br>
<hr>

# Remote Access Software
An adversary may use legitimate desktop support and remote access software, such as *Team Viewer*, *AnyDesk*, *Go2Assist*, *LogMein*, *AmmyyAdmin*, etc, to establish an interactive C2 channel to target systems within networks
* These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment
* Remote access tools like *VNC*, *Ammyy*, and *Teamviewer* are used frequently when compared with other legitimate software commonly used by adversaries

Remote access tools may be installed and used post-compromise as alternate communications channel for redundant access or as a way to establish an interactive remote desktop session with the target system
* They may also be used as a component of malware to establish a reverse connection or back-connect to a service or adversary controlled system
  * Installation of many remote access tools may also include persistence (ex: the tool's installation routine creates a Windows Service)

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
* Another method leverages raw sockets, which enables the malware to use ports that 
are already open for use by other programs

<br>
<hr>

# Web Service
Adversaries may use an existing, legitimate external Web service as a means for relaying data to/from a compromised system
* Popular websites and social media acting as a mechanism for C2 may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to a compromise
  * Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. Web service providers commonly use SSL/TLS encryption, giving adversaries an added level of protection

Use of Web services may also protect back-end C2 infrastructure from discovery through malware binary analysis while also enabling operational resiliency (since this infrastructure may be dynamically changed)

<br>

## Dead Drop Resolver
Adversaries may use an existing, legitimate external Web service to host information that points to additional C2 infrastructure
* Attackers may post content, known as a **dead drop resolver**, on Web services with embedded (and often obfuscated/encoded) domains or IP addresses
  * Once infected, victims will reach out to and be redirected by these resolvers

The use of a dead drop resolver may also protect back-end C2 infrastructure from discovery through malware binary analysis while also enabling operational resiliency (since this infrastructure may be dynamically changed)

<br>

## Bidirectional Communication
Adversaries may use an existing, legitimate external Web service as a means for sending commands to and receiving output from a compromised system over the Web service channel
* Those infected systems can then send the output from those commands back over that Web service channel
* The return traffic may occur in a variety of ways, depending on the Web service being utilized
  * Bot posting a comment on a forum
  * Issuing a pull request to development project
  * Updating a document hosted on a Web service
  * Sending a Tweet

<br>

## One-Way Communication 
Infected systems may opt to send the output from those commands back over a different C2 channel, including to another distinct Web service
* Compromised systems may return no output at all in cases where adversaries want to send instructions to systems and do not want a response