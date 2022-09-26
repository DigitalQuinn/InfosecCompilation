# Exfiltration

Exfiltration consists of techniques that adversaries may use to steal data from your network. Once they’ve collected data, adversaries often package it to avoid detection while removing it. This can include compression and encryption. Techniques for getting data out of a target network typically include transferring it over their command and control channel or an alternate channel and may also include putting size limits on the transmission.

<br>
<hr>

# Table of Contents
- [Automated Exfiltration](#automated-exfiltration)
  - [Traffic Duplication](#traffic-duplication)
- [Data Transfer Size Limits](#data-transfer-size-limits)
- [Exfiltration Over Alternative Protocol](#exfiltration-over-alternative-protocol)
  - [Exfiltration Over Symmetric Encrypted Non-C2 Protocol](#exfiltration-over-symmetric-encrypted-non-c2-protocol)
  - [Exfiltration Over Asymmetric Encrypted Non-C2 Protocol](#exfiltration-over-asymmetric-encrypted-non-c2-protocol)
  - [Exfiltration Over Unencrypted Non-C2 Protocol](#exfiltration-over-unencrypted-non-c2-protocol)
- [Exfiltration Over C2 Channel](#exfiltration-over-c2-channel)
- [Exfiltration Over Other Network Medium](#exfiltration-over-other-network-medium)
  - [Exfiltration Over Bluetooth](#exfiltration-over-bluetooth)
- [Exfiltration Over Physical Medium](#exfiltration-over-physical-medium)
  - [Exfiltration over USB](#exfiltration-over-usb)
- [Exfiltration Over Web Service](#exfiltration-over-web-service)
  - [Exfiltration to Code Repository](#exfiltration-to-code-repository)
  - [Exfiltration to Cloud Storage](#exfiltration-to-cloud-storage)
- [Scheduled Transfer](#scheduled-transfer)
- [Transfer Data to Cloud Account](#transfer-data-to-cloud-account)

<br>
<hr>

# Automated Exfiltration
Adversaries may exfiltrate data, such as sensitive documents, through the use of automated processing after being gathered during *Collection*

<br>

## Traffic Duplication
**Traffic Mirroring:** Native feature for some network devices and used for network analysis and may be configured to duplicate traffic and forward to one or more destinations for analysis by a network analyzer or other monitoring device


Adversaries may abuse traffic mirroring to mirror or redirect network traffic through other network infrastructure they control
* Malicious modifications to network devices to enable traffic redirection may be possible through *ROMMONkit* or *Patch System Image*
* Adversaries may use traffic duplication in conjunction with *Network Sniffing*, *Input Capture*, or *Adversary-in-the-Middle* depending on the goals and objectives of the adversary

<br>
<hr>

# Data Transfer Size Limits
An adversary may exfiltrate data in fixed size chunks instead of whole files or limit packet sizes below certain thresholds. This approach may be used to avoid triggering network data transfer threshold alerts.

<br>
<hr>

# Exfiltration Over Alternative Protocol
Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server

Alternate protocols include FTP, SMTP, HTTP/S, DNS, SMB, or any other network protocol not being used as the main command and control channel
* Different protocol channels could also include Web services such as cloud storage
* Adversaries may also opt to encrypt and/or obfuscate these alternate channels

*Exfiltration Over Alternative Protocol* can be done using various common operating system utilities such as **Net/SMB** or **FTP**
* On UNIX, `curl` may be used to invoke protocols such as HTTP(S) or FTP(S) to exfiltrate data from a system

<br>

## Exfiltration Over Symmetric Encrypted Non-C2 Protocol
Adversaries may steal data by exfiltrating it over a symmetrically encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server.

Symmetric encryption algorithms are those that use shared or the same keys/secrets on each end of the channel; This requires an exchange or pre-arranged agreement/possession of the value used to encrypt and decrypt data

Network protocols that use asymmetric encryption often utilize symmetric encryption once keys are exchanged, but adversaries may opt to manually share keys and implement symmetric cryptographic algorithms (RC4, AES) vice using mechanisms that are baked into a protocol
* This may result in multiple layers of encryption (in protocols that are natively encrypted such as HTTPS) or encryption in protocols that not typically encrypted (HTTP or FTP)

<br>

## Exfiltration Over Asymmetric Encrypted Non-C2 Protocol
Adversaries may steal data by exfiltrating it over an asymmetrically encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server.

Asymmetric encryption algorithms (Public-Key Cryptography) requires pairs of cryptographic keys that can encrypt/decrypt data from the corresponding key
* Each end of the communication channels requires a private key and the public key of the other entity
* The public keys of each entity are exchanged before encrypted communications begin

Network protocols that use asymmetric encryption (HTTPS/TLS/SSL) often utilize symmetric encryption once keys are exchanged
* Adversaries may opt to use these encrypted mechanisms that are baked into a protocol

<br>

## Exfiltration Over Unencrypted Non-C2 Protocol
Adversaries may steal data by exfiltrating it over an un-encrypted network protocol other than that of the existing C2 channel; The data may also be sent to an alternate network location from the main C2 server

Adversaries may opt to obfuscate this data, without the use of encryption, within network protocols that are natively unencrypted; This may include custom or publicly available encoding/compression algorithms (such as base64) as well as embedding data within protocol headers and fields

<br>
<hr>

# Exfiltration Over C2 Channel
Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel using the same protocol as command and control communications.

<br>
<hr>

# Exfiltration Over Other Network Medium
Adversaries may attempt to exfiltrate data over a different network medium than the C2 channel
* If the C2 network is a wired Internet connection, the exfiltration may occur over a WiFi connection, modem, cellular data connection, Bluetooth, or another RF channel

Adversaries may choose to do this if they have sufficient access or proximity, and the connection might not be secured or defended as well as the primary Internet-connected channel because it is not routed through the same enterprise network

<br>

## Exfiltration Over Bluetooth
Adversaries may attempt to exfiltrate data over Bluetooth rather than the C2 channel
* If the C2 network is a wired Internet connection, an adversary may opt to exfiltrate data using a Bluetooth communication channel 
  * Bluetooth connections might not be secured or defended as well as the primary Internet-connected channel because it is not routed through the same enterprise network

<br>
<hr>

# Exfiltration Over Physical Medium
Adversaries may attempt to exfiltrate data via a physical medium
* In certain circumstances, such as an air-gapped network compromise, exfiltration could occur via a physical medium or device introduced by a user
  * Such media could be an external hard drive, USB drive, cellular phone, MP3 player, or other removable storage and processing device
  * The physical medium or device could be used as the final exfiltration point or to hop between otherwise disconnected systems

<br>

## Exfiltration over USB
Adversaries may attempt to exfiltrate data over a USB connected physical device
* In certain circumstances, such as an air-gapped network compromise, exfiltration could occur via a USB device introduced by a user
* The USB device could be used as the final exfiltration point or to hop between otherwise disconnected systems

<br>
<hr>

# Exfiltration Over Web Service
Adversaries may use an existing, legitimate external Web service to exfiltrate data rather than their primary command and control channel
* Popular Web services acting as an exfiltration mechanism may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to compromise
* Firewall rules may also already exist to permit traffic to these services

<br>

## Exfiltration to Code Repository
Adversaries may exfiltrate data to a code repository rather than over their primary C2 channel
* Code repositories are often accessible via an API (ex: https[:]//ap.github.com)
  * Access to these APIs are often over HTTPS, which gives the adversary an additional level of protection
  * Exfiltration to a code repository can also provide a significant amount of cover to the adversary if it is a popular service already used by hosts within the network

<br>

## Exfiltration to Cloud Storage
Adversaries may exfiltrate data to a cloud storage service rather than over their primary C2 channel
* Cloud storage services allow for the storage, edit, and retrieval of data from a remote cloud storage server over the Internet
* Exfiltration to cloud storage services can provide a significant amount of cover to the adversary if hosts within the network are already communicating with the service

<br>
<hr>

# Scheduled Transfer
Adversaries may schedule data exfiltration to be performed only at certain times of day or at certain intervals; This could be done to blend traffic patterns with normal activity or availability
* When scheduled exfiltration is used, other exfiltration techniques likely apply as well to transfer the information out of the network, such as *Exfiltration Over C2 Channel* or *Exfiltration Over Alternative Protocol*

<br>
<hr>

# Transfer Data to Cloud Account
Adversaries may exfiltrate data by transferring the data, including backups of cloud environments, to another cloud account they control on the same service to avoid typical file transfers/downloads and network-based exfiltration detection

A defender who is monitoring for large transfers to outside the cloud environment through normal file transfers or over C2 channels may not be watching for data transfers to another account within the same cloud provider
* Such transfers may utilize existing cloud provider APIs and the internal address space of the cloud provider to blend into normal traffic or avoid data transfers over external network interfaces