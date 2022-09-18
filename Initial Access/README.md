The adversary is trying to get into your network.

Initial Access consists of techniques that use various entry vectors to gain their initial foothold within a network. Techniques used to gain a foothold include targeted spearphishing and exploiting weaknesses on public-facing web servers. Footholds gained through initial access may allow for continued access, like valid accounts and use of external remote services, or may be limited-use due to changing passwords.

---------------------
# Tables of Content #
---------------------
- [Drive-By Compromise](#drive-by-compromise)
- [Exploit Public-Facing Aplications](#exploit-public-facing-applications)
- [External Remote Services](#external-remote-services)
- [Hardware Additions](#hardware-additions)
- [Phishing](#phishing)
- [Replication Through Removable Media](#replication-through-removable-media)
- [Supply Chain Compromise](#supply-chain-compromise)
- [Trusted Relationships](#trusted-relationships)
- [Valid Accounts](#valid-accounts)


# Drive-By Compromise #
Adversaries may gain access to a system through a user visiting a website over the normal course of browsing. With this technique, the user's web browser is typically targeted for exploitation, but adversaries may also use compromised websites for non-exploitation behavior such as acquiring Application Access Token.

**Multiple ways of delivering exploit code to a browser exist, including:**

* Injected malicious code such as JavaScript, iFrames, and cross-site scripting
  * Malicious ads are paid for and served through legitimate ad providers.
  * Built-in web application interfaces are leveraged for the insertion of any other kind of object that can be used to display web content or contain a script that executes on the visiting client 

**Typical drive-by compromise process:**

A user visits a website which contains scripts that automatically execute, typically searching versions of the browser and plugins for a potentially vulnerable version
* The user may be required to assist in this process by enabling scripting or active website components and ignoring warning dialog boxes
* Upon finding a vulnerable version, exploit code is delivered to the browser, giving remote code execution on the user's system 

Adversaries may also use compromised websites to deliver a user to a malicious application designed to Steal Application Access Tokens, like OAuth tokens, to gain access to protected applications and information. These malicious applications have been delivered through popups on legitimate websites.


# Exploit Public-Facing Applications #
Exploited applications are often websites, but can include databases, standard services, network device administration and management protocols, and any other applications with Internet accessible open sockets, such as web servers and related services.
**Note:** If an application is hosted on cloud-based infrastructure and/or is containerized, then exploiting it may lead to compromise of the underlying instance or container.
* This can allow an adversary a path to access the cloud or container APIs, exploit container host access via Escape to Host, or take advantage of weak identity and access management policies
* For websites and databases, the OWASP top 10 and CWE top 25 highlight the most common web-based vulnerabilities.


# External Remote Services #
Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations. There are often remote service gateways that manage connections and credential authentication for these services. Services such as Windows Remote Management and VNC can also be used externally.

Access to valid accounts to use the service is often a requirement, which could be obtained through credential pharming or by obtaining the credentials from users after compromising the enterprise network.



# Hardware Additions #
Rather than just connecting and distributing payloads via removable storage, more robust hardware additions can be used to introduce new functionalities and/or features into a system that can then be abused. Red teams leverage hardware additions for initial access. Commercial and open source products can be leveraged with capabilities such as passive network tapping, network traffic modification, keystroke injection, kernel memory reading via DMA, addition of new wireless access to an existing network, and others.


# Phishing #
Adversaries may send victims emails containing malicious attachments or links, typically to execute malicious code on victim systems. Phishing may also be conducted via third-party services, like social media platforms. Phishing may also involve social engineering techniques, such as posing as a trusted source.


# Replication Through Removable Media #
Adversaries may move onto systems, possibly those on disconnected or air-gapped networks, by copying malware to removable media and taking advantage of Autorun features when the media is inserted into a system and executes
* This may occur through modification of executable files stored on removable media or by copying malware and renaming it to look like a legitimate file to trick users into executing it on a separate system
* This may occur through manual manipulation of the media, modification of systems used to initially format the media, or modification to the media's firmware itself


# Supply Chain Compromise #
Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer for the purpose of data or system compromise.

Supply chain compromise can take place at any stage of the supply chain including:

*Manipulation of development tools
Manipulation of a development environment
Manipulation of source code repositories (public or private)
Manipulation of source code in open-source dependencies
Manipulation of software update/distribution mechanisms
Compromised/infected system images (multiple cases of removable media infected at the factory)[1][2]
Replacement of legitimate software with modified versions
Sales of modified/counterfeit products to legitimate distributors
Shipment interdiction*
While supply chain compromise can impact any component of hardware or software, adversaries looking to gain execution have often focused on malicious additions to legitimate software in software distribution or update channels.[3][4][5] Targeting may be specific to a desired victim set or malicious software may be distributed to a broad set of consumers but only move on to additional tactics on specific victims.[6][3][5] Popular open source projects that are used as dependencies in many applications may also be targeted as a means to add malicious code to users of the dependency.[7]


# Trusted Relationships #



# Valid Accounts #

