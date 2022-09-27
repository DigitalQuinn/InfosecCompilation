# Resource Development
<br>

**Resource Development** consists of techniques that involve Attackers creating, purchasing, or compromising/stealing resources that can be used to support targeting. Such resources include infrastructure, accounts, or capabilities. These resources can be leveraged by the adversary to aid in other phases of the adversary lifecycle, such as using purchased domains to support Command and Control, email accounts for phishing as a part of Initial Access, or stealing code signing certificates to help with Defense Evasion. 

<br>
<hr>

# Table of Contents
- [Acquire / Compromise Infrastructure](#acquire--compromise-infrastructure)
  - [Domains](#domains)
  - [DNS Server](#dns-server)
  - [Virtual Private Server](#virtual-private-server)
  - [Server](#server)
  - [Botnet](#botnet)
  - [Web Services](#web-services)
- [Compromise / Establish Accounts](#compromise--establish-accounts)
  - [Social Media Accounts](#social-media-accounts)
  - [Email Accounts](#email-accounts)
- [Develop / Obtain Capabilities](#develop--obtain-capabilities)
  - [Malware](#malware)
  - [Code Signing Certificates](#code-signing-certificates)
  - [Digital Certificates](#digital-certificates)
  - [Exploits](#exploits)
  - [Vulnerabilities](#vulnerabilities)
- [Stage Capabilities](#stage-capabilities)
  - [Upload Tools](#upload-malware)
  - [Upload Tools](#upload-tools)
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
**Note:** Attackers may choose domains that are similar to legitimate domains, including through use of homoglyphs or use of a different top-level domain (TLD). Typosquatting may be used to aid in delivery of payloads via Drive-by Compromise. Attackers can also use internationalized domain names (IDNs) to create visually similar lookalike domains for use in operations.

Attackers may use private WHOIS services to obscure information about who owns a purchased domain and may further interrupt efforts to track their infrastructure by using varied registration information and purchasing domains with different domain registrars.

<br>

## DNS Server ##
Attackers may set up their own DNS servers that can be used during targeting. During post-compromise activity, Attackers may utilize DNS traffic for various tasks, including for Command and Control. Instead of hijacking existing DNS servers, Attackers may opt to configure and run their own DNS servers in support of operations.

By running their own DNS servers, Attackers can have more control over how they administer server-side DNS C2 traffic. With control over a DNS server, Attackers can configure DNS applications to provide conditional responses to malware and, generally, have more flexibility in the structure of the DNS-based C2 channel.

<br>

## Virtual Private Server ##
attackers can make it difficult to physically tie back operations to them by using VPS. The use of cloud infrastructure can also make it easier for Attackers to rapidly provision, modify, and shut down their infrastructure.

Acquiring a VPS for use in later stages of the adversary lifecycle, such as Command and Control, can allow Attackers to benefit from the ubiquity and trust associated with higher reputation cloud service providers. Attackers may also acquire infrastructure from VPS service providers that are known for renting VPSs with minimal registration information, allowing for more anonymous acquisitions of infrastructure.

<br>

## Server ##
Use of servers allows an adversary to stage, launch, and execute an operation. During post-compromise activity, Attackers may utilize servers for various tasks, including for Command and Control. Instead of compromising a third-party Server or renting a Virtual Private Server, Attackers may opt to configure and run their own servers in support of operations.

<br>

## Botnet ##
A botnet is a network of compromised systems that can be instructed to perform coordinated tasks. Attackers may purchase a subscription to use an existing botnet from a booter/stresser service. With a botnet at their disposal, Attackers may perform follow-on activity such as large-scale Phishing or DDoS attacks.

<br>

## Web Services ##
A variety of popular websites exist for attackers to register for a web-based service that can be abused during later stages of the adversary lifecycle, such as during Command and Control (Web Service) or Exfiltration Over Web Service. Using common services, such as those offered by Google or Twitter, makes it easier for Attackers to hide in expected noise. By utilizing a web service, Attackers can make it difficult to physically tie back operations to them.

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
Building malicious software can include the development of payloads, droppers, post-compromise tools, backdoors (including backdoored images), packers, C2 protocols, and the creation of infected removable media. Attackers may develop malware to support their operations, creating a means for maintaining control of remote machines, evading defenses, and executing post-compromise behaviors.
* Third-party entities can include technology companies that specialize in malware development, criminal marketplaces (including Malware-as-a-Service, or MaaS), or from individuals. In addition to purchasing malware, adversaries may steal and repurpose malware from third-party entities. 
* Some aspects of malware development, such as C2 protocol development, may require adversaries to obtain additional infrastructure. For example, malware developed that will communicate with Twitter for C2, may require use of Web Services.

<br>

## Code Signing Certificates ##
**Code Signing:** The process of digitally signing executables and scripts to confirm the software author and guarantee that the code has not been altered or corrupted. Code signing provides a level of authenticity for a program from the developer and a guarantee that the program has not been tampered with. Users/security tools may trust a signed piece of code more than an unsigned piece of code even if they don't know who issued the certificate or who the author is.

Prior to Code Signing, adversaries may purchase or steal code signing certificates for use in operations. The purchase of code signing certificates may be done using a front organization or using information stolen from a previously compromised entity that allows the adversary to validate to a certificate provider as that entity. Adversaries may also steal code signing materials directly from a compromised third-party.

<br>

## Digital Certificates ##
**SSL/TLS Certificates:** Certificates designed to instill trust, containing information about the key, its owner's identity, and the digital signature of an entity that has verified the certificate's contents are correct. 

Adversaries may purchase or steal SSL/TLS certificates to further their operations, such as encrypting C2 traffic or even enabling Man-In-The-Middle if the certificate is trusted or otherwise added to the root of trust. 
* The purchase of digital certificates may be done using a front organization or using information stolen from a previously compromised entity that allows the adversary to validate to a certificate provider as that entity.
* Adversaries may also steal certificate materials directly from a compromised third-party, including from certificate authorities.
* Adversaries may register or hijack domains that they will later purchase an SSL/TLS certificate for.

<br>

## Exploits ##
**Exploit:** Takes advantage of a bug or vulnerability in order to cause unintended or unanticipated behavior to occur on computer hardware or software.
* Adversaries may use information acquired via vulnerabilities to focus exploit development efforts. As part of the exploit development process, adversaries may uncover exploitable vulnerabilities through methods such as fuzzing and patch analysis
* An adversary may monitor exploit provider forums to understand the state of existing, as well as newly discovered, exploits. There is usually a delay between when an exploit is discovered and when it is made public. An adversary may target the systems of those known to conduct exploit research and development in order to gain that knowledge for use during a subsequent operation.

<br>

## Vulnerabilities ##
An adversary may monitor vulnerability disclosures/databases to understand the state of existing, as well as newly discovered, vulnerabilities. There is usually a delay between when a vulnerability is discovered and when it is made public. An adversary may target the systems of those known to conduct vulnerability research. Knowledge of a vulnerability may cause an adversary to search for an existing exploit (i.e. Exploits) or to attempt to develop one themselves.

<br>
<hr>

# Stage Capabilities 
Adversaries may upload, install, or otherwise set up capabilities that can be used during targeting. To support their operations, an adversary may need to take capabilities they developed (Develop Capabilities) or obtained (Obtain Capabilities) and stage them on infrastructure under their control. These capabilities may be staged on infrastructure that was previously purchased/rented by the adversary (Acquire Infrastructure) or was otherwise compromised by them (Compromise Infrastructure). Capabilities can also be staged on web services, such as GitHub or Pastebin.

<br>

## Upload Malware ##
Malware may be placed on infrastructure that was previously purchased/rented by the adversary or was otherwise compromised by them. Malware can also be staged on web services, such as GitHub or Pastebin.
* Upload backdoored files, such as application binaries, virtual machine images, or container images, to third-party software stores or repositories (ex: GitHub, CNET, AWS Community AMIs, Docker Hub). 

<br>

## Upload Tools ##
Adversaries may upload tools to support their operations, such as making a tool available to a victim network to enable Ingress Tool Transfer by placing it on an Internet accessible web server. Adversaries can avoid the need to upload a tool by having compromised victim machines download the tool directly from a third-party hosting location (ex: a non-adversary controlled GitHub repo), including the original hosting site of the tool.

<br>

## Install Digital Certificates ##
Adversaries may install SSL/TLS certificates that can be used to further their operations, such as encrypting C2 traffic or lending credibility to a credential harvesting site.

Adversaries can obtain digital certificates or create self-signed certificates. Digital certificates can then be installed on adversary controlled infrastructure that may have been acquired or previously compromised.

<br>

## Drive-By Target ##
Adversaries may prepare an operational environment to infect systems that visit a website over the normal course of browsing. User's web browser is typically targeted for exploitation, but adversaries may also set up websites for non-exploitation behavior such as Application Access Token. Prior to Drive-by Compromise, adversaries must stage resources needed to deliver that exploit to users who browse to an adversary controlled site. Drive-by content can be staged on adversary controlled infrastructure that has been acquired (Acquire Infrastructure) or previously compromised (Compromise Infrastructure).

* Adversaries may upload or inject malicious web content, such as JavaScript, into websites
* Craft malicious web advertisements and purchase ad space on a website through legitimate ad providers
* Stage scripting content to profile the user's browser to ensure it is vulnerable prior to attempting exploitation
* Websites compromised by an adversary and used to stage a drive-by may be ones visited by a specific community, such as government, a particular industry, or region, where the goal is to compromise a specific user or set of users based on a shared interest

<br>

## Link Target ##
Adversaries may rely upon a user clicking a malicious link in order to divulge information or to gain execution. Links can be used for spearphishing, such as sending an email accompanied by social engineering text to coax the user to actively click or copy and paste a URL into a browser
* Prior to a phish for information or a phish to gain initial access to a system, an adversary must set up the resources for a link target for the spearphishing link
*  Adversaries may clone legitimate sites to serve as the link target, this can include cloning of login pages of legitimate web services or organization login pages in an effort to harvest credentials 

<br>
<hr>

# Tools 

## Penetration Testing Frameworks
- [Metasploit](https://www.metasploit.com/)
- [Cobalt Strike](https://www.cobaltstrike.com/) — Adversary simulations & red team operations
- [Brute Ratel](https://bruteratel.com/) - A customized C2 center for Red Team and Adversary Simulation
- [Sn1per](https://github.com/1N3/Sn1per) — All in one pentesting framework
- [Covenant](https://github.com/cobbr/Covenant) — .NET C2 framework
- [Silver](https://github.com/BishopFox/sliver) — Open source cross-platform red team framework
- [Octopus](https://www.kitploit.com/2022/05/octopus-open-source-pre-operation-c2.html) — Pre-operation C2 server
- [SilentTrinity](https://github.com/byt3bl33d3r/SILENTTRINITY) — Asynchronous, multiplayer, & multiserver C2 framework
- [Recon-ng](https://github.com/lanmaster53/recon-ng) — Full reconnaissance framework to conduct open source web-based recon
- [Browser Exploitation Framework (BeEF)](https://beefproject.com/) — Recovering web session information and exploiting client-side scripting
- [Zed Attack Proxy (ZAP)](https://owasp.org/www-project-zap/) — Scanning tools and scripts for web application and mobile app security testing
- [Pacu](https://rhinosecuritylabs.com/aws/pacu-open-source-aws-exploitation-framework/) — Scanning and exploit tools for reconnaissance and exploitation of Amazon Web Service (AWS) accounts
- [HazProne](https://securityonline.info/hazprone-cloud-pentesting-framework/) — Cloud Pentesting Framework
- [Lockdoor Framework](https://github.com/SofianeHamlaoui/Lockdoor-Framework) — Framework that automates pentesting tools
- [Emp3R0R](https://github.com/jm33-m0/emp3r0r) - Linux post-exploitation framework 
- [GithubC2](https://github.com/D1rkMtr/githubC2/tree/main) - Using Github as a C2

## Compilation of Tools
- [Hacktricks](https://book.hacktricks.xyz/) - Hacking TTPs
- [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) - A list of useful payloads for bypassing systems
- [Pentest-Tools](https://github.com/S3cur3Th1sSh1t/Pentest-Tools) — Cybersecurity repository
- [EthHack](https://ethhack.com/category/security-tools/) — Repository security tool
- [FSociety Hacking Tools](https://github.com/Manisso/fsociety) — Contains all the tools used in Mr. Robot series
- [Red Team Resources](https://github.com/J0hnbX/RedTeam-Resources) - Compilation of Red Teaming resources
- [Kitploit’s Popular Hacking Tools](https://www.kitploit.com/2021/12/top-20-most-popular-hacking-tools-in.html)
- [Red Teaming Toolkit](https://github.com/infosecn1nja/Red-Teaming-Toolkit#Payload%20Development)

## Hardware

- [Flipper Zero](https://flipperzero.one/) 

## Packet Injection
- [Dsniff](https://monkey.org/~dugsong/dsniff/)
- [Ettercap](https://www.ettercap-project.org/)
- [Scapy](https://scapy.net/) — Packet manipulation program
- [hping](http://hping.org/) — TCP/IP packet assembler/analyzer