# Resource Development

<br>

**Resource Development** consists of techniques that involve Attackers creating, purchasing, or compromising/stealing resources that can be used to support targeting. Such resources include infrastructure, accounts, or capabilities. These resources can be leveraged by the adversary to aid in other phases of the adversary lifecycle, such as using purchased domains to support C2, email accounts for phishing as a part of Initial Access, or stealing code signing certificates to help with Defense Evasion. 

<br>
<hr>

# Table of Contents
- [Acquire / Compromise Infrastructure](#acquire--compromise-infrastructure)
  - [Domains](#domains)
  - [DNS Server](#dns-server)
  - [Virtual Private Server](#virtual-private-server)
  - [Botnet](#botnet)
  - [Web Services](#web-services)
- [Compromise / Establish Accounts](#compromise--establish-accounts)
  - [Social Media Accounts](#social-media-accounts)
  - [Email Accounts](#email-accounts)
- [Develop / Obtain Capabilities](#develop--obtain-capabilities)
  - [Malware](#malware)
  - [Code Signing Certificates](#code-signing-certificates)
- [Stage Capabilities](#stage-capabilities)
  - [Upload Malware](#upload-malware)
  - [Upload Tools](#upload-tools)
  - [Platforms for Staging Capabilities](#platforms-for-staging-capabilities)
  - [Install Digital Certificate](#install-digital-certificates)
  - [Drive-by Target](#drive-by-target)
  - [Link Target](#link-target)

<br>
<hr>

# Acquire / Compromise Infrastructure 
Attackers may buy, lease, or rent infrastructure that can be used during targeting. A wide variety of infrastructure exists for hosting and orchestrating adversary operations such as physical or cloud servers, domains, and third-party web services.

Use of these infrastructure solutions allows an adversary to stage, launch, and execute an operation. Solutions may help adversary operations blend in with traffic that is seen as normal, such as contact to third-party web services. Depending on the implementation, Attackers may use infrastructure that makes it difficult to physically tie back to them as well as utilize infrastructure that can be rapidly provisioned, modified, and shut down.

<br>

## Domains ##
Domain names are the human readable names used to represent one or more IP addresses. They can be purchased or acquired for free. Attackers can use purchased domains for a variety of purposes, including for Phishing, Drive-by Compromise, and Command and Control.

**NOTE::** Attackers may choose domains that are similar to legitimate domains, including through use of homoglyphs or use of a different TLD. Typosquatting may be used to aid in delivery of payloads via Drive-by Compromise. Attackers can also use internationalized domain names (IDNs) to create visually similar lookalike domains for use in operations.

Attackers may use private WHOIS services to obscure information about who owns a purchased domain and may further interrupt efforts to track their infrastructure by using varied registration information and purchasing domains with different domain registrars.

<br>

## DNS Server ##
Attackers may set up their own DNS servers that can be used during targeting. During post-compromise activity, Attackers may utilize DNS traffic for various tasks, including for Command and Control. Instead of hijacking existing DNS servers, Attackers may opt to configure and run their own DNS servers in support of operations.

By running their own DNS servers, Attackers can have more control over how they administer server-side DNS C2 traffic. With control over a DNS server, Attackers can configure DNS applications to provide conditional responses to malware and, generally, have more flexibility in the structure of the DNS-based C2 channel.

<br>

## Virtual Private Server ##
Attackers can make it difficult to physically tie back operations to them by using VPS. The use of cloud infrastructure can also make it easier for attackers to rapidly provision, modify, and shut down their infrastructure.

Acquiring a VPS for use in later stages of the adversary lifecycle, such as Command and Control, can allow attackers to benefit from the ubiquity and trust associated with higher reputation cloud service providers. Attackers may also acquire infrastructure from VPS service providers that are known for renting VPSs with minimal registration information, allowing for more anonymous acquisitions of infrastructure.

<br>

## Botnet ##
A botnet is a network of compromised systems that can be instructed to perform coordinated tasks. Attackers may purchase a subscription to use an existing botnet from a booter/stresser service. With a botnet at their disposal, Attackers may perform follow-on activity such as large-scale Phishing or DDoS attacks.

<br>

## Web Services ##
A variety of popular websites exist for attackers to register for a web-based service that can be abused during later stages of the adversary lifecycle, such as during Command and Control (Web Service) or Exfiltration Over Web Service. Using common services, such as those offered by Google or Twitter, makes it easier for Attackers to hide in expected noise. By utilizing a web service, attackers can make it difficult to physically tie back operations to them.

<br>
<hr>

# Compromise / Establish Accounts 
Attackers may compromise accounts with services that can be used during targeting. For operations incorporating social engineering, the utilization of an online persona may be important. Rather than creating and cultivating accounts, attackers may compromise existing accounts. Utilizing an existing persona may engender a level of trust in a potential victim if they have a relationship, or knowledge of, the compromised persona.

<br>

## Social Media Accounts ##
Common methods for compromising accounts
* Gathering credentials via Phishing for Information
* Purchasing credentials from third-party sites
* Brute forcing credentials (ex: password reuse from breach credential dumps)
  
 <br> 

## Email Accounts ##
Attackers can use compromised email accounts to further their operations by leveraging them. Utilizing an existing persona with a compromised email account may engender a level of trust in a potential victim if they have a relationship, or knowledge of, the compromised persona. Compromised email accounts can also be used in the acquisition of infrastructure. Attackers can use a compromised email account to hijack existing email threads with targets of interest.

<br>
<hr>

# Develop / Obtain Capabilities 
Rather than purchasing, freely downloading, or stealing capabilities, attackers may develop their own capabilities in-house. This is the process of identifying development requirements and building solutions such as malware, exploits, and self-signed certificates. Attackers may develop capabilities to support their operations throughout numerous phases of the adversary lifecycle.

<br>

## Malware ##
Attackers may develop malware to support their operations, creating a means for maintaining control of remote machines, evading defenses, and executing post-compromise behaviors.
* Third-party entities can include technology companies that specialize in malware development, criminal marketplaces (Malware as a Service). In addition to purchasing malware, adversaries may steal and repurpose malware from third-party entities. 
* Some aspects of malware development, such as C2 protocol development, may require adversaries to obtain additional infrastructure.

<br>

## Code Signing Certificates ##
Code signing provides a level of authenticity for a program from the developer and a guarantee that the program has not been tampered with. Users/security tools may trust a signed piece of code more than an unsigned piece of code even if they don't know who issued the certificate or who the author is.

Prior to Code Signing, adversaries may purchase or steal code signing certificates for use in operations. The purchase of code signing certificates may be done using a front organization or using information stolen from a previously compromised entity that allows the adversary to validate to a certificate provider as that entity. Adversaries may also steal code signing materials directly from a compromised third-party.

### Misusing digital certificates
* MITM Attacks
  * Obtain a fake certificate from any CA and present it to the client during the connection phase to impersonate websites
* Cyber attacks based on signed malware
  * Sign the malware code; Install those software components (ex: drivers, software updates) that require signed code for their installation
* Install illegitimate certificates to trust them, avoiding security warnings
* CAs issued improper certificates
  * DigiCert mistakenly sold a certificate to a non-existent company allowing attackers to sign malware used in cyber attacks

### Stealing Digital Certificates
Program code often uses the `PFXExportCertStoreEx` function to export certificate store information and save the information with a .pfx file extension (the actual file format it uses is PKCS#12)
* `PFXExportCertStoreEx` function with the `EXPORT_PRIVATE_KEYS` option stores both digital certificates and the associated private keys -- **.pfx file is useful to attackers**
* `CertOpenSystemStoreA` could be used to open certificates stored, meanwhile the `PFXExportCertStoreEx` function exports the content of the following certificate stores:
  * MY: A certificate store that holds certificates with the associated private keys
  * CA: Certificate authority certificates
  * ROOT: Root certificates
  * SPC: Software Publisher Certificates

### Malware Code to Access Certificate Information**
Malware is used to steal certificate store information when the computer starts running
* After obtaining the victim’s private key from a stolen certificate, use a tool like the **Microsoft signing tool** bundled with Windows DDK, Platform SDK, and Visual Studio
  * Running Sign Tool (signtool.exe), it is possible to digitally sign every code, including malware source code

<br>
<hr>

# Stage Capabilities 
To support their operations, adversaries may need to take capabilities they developed or obtained and stage them on infrastructure under their control. These capabilities may be staged on infrastructure that was previously acquired or staged on web services, such as GitHub or Pastebin.

<br>

## Upload Malware ##
Attackres may upload backdoored files, such as application binaries, VM images, or container images, to third-party software stores or repositories (ex: GitHub, CNET, AWS Community AMIs, Docker Hub). 

<br>

## Upload Tools ##
Adversaries may upload tools to support their operations, such as making a tool available to a victim network to enable Ingress Tool Transfer by placing it on an Internet accessible web server
* Adversaries can avoid the need to upload a tool by having compromised victim machines download the tool directly from a third-party hosting location (ex: a non-adversary controlled GitHub repo), including the original hosting site of the tool

<br>

## Platforms for Staging Capabilities
- [Free for Dev Github](https://github.com/ripienaar/free-for-dev#domain)

<br>

## Install Digital Certificates ##
Adversaries may install SSL/TLS certificates that can be used to further their operations, such as encrypting C2 traffic or lending credibility to a credential harvesting site.

Adversaries can obtain digital certificates or create self-signed certificates. Digital certificates can then be installed on adversary controlled infrastructure that may have been acquired or previously compromised.

<br>

## Drive-By Target ##
Adversaries may prepare an operational environment to infect systems that visit a website over the normal course of browsing. User's web browser is typically targeted for exploitation, but adversaries may also set up websites for non-exploitation behavior such as Application Access Token. 

Prior to Drive-by Compromise, adversaries must stage resources needed to deliver that exploit to users who browse to an adversary controlled site. Drive-by content can be staged on adversary controlled infrastructure that has been acquired or previously compromised.

* Upload/inject malicious web content into websites
* Craft malicious web advertisements and purchase ad space on a website through legitimate ad providers
* Stage scripting content to profile the user's browser to ensure it is vulnerable prior to attempting exploitation
* Websites compromised by an adversary and used to stage a drive-by may be ones visited by a specific community, such as government, a particular industry, or region, where the goal is to compromise a specific user or set of users based on a shared interest

<br>

## Link Target ##
Adversaries may rely upon a user clicking a malicious link in order to divulge information or to gain execution. Links can be used for spearphishing, such as sending an email accompanied by social engineering text to coax the user to actively click or copy and paste a URL into a browser
* Prior to a phish, attakeres must set up the resources for a link target for the spearphishing link
*  Adversaries may clone legitimate sites to serve as the link target, this can include cloning of login pages of legitimate web services or organization login pages in an effort to harvest credentials.