# Intial Access

**Initial Access** consists of techniques that use various entry vectors to gain their initial foothold within a network. Techniques used to gain a foothold include targeted spearphishing and exploiting weaknesses on public-facing web servers. Footholds gained through initial access may allow for continued access, like valid accounts and use of external remote services, or may be limited-use due to changing passwords.

<br>
<hr>

# Table of Contents
- [Drive-By Compromise](#drive-by-compromise)
- [Exploit Public-Facing Aplications](#exploit-public-facing-applications)
- [External Remote Services](#external-remote-services)
- [Hardware Additions](#hardware-additions)
- [Phishing](#phishing)
  - [Spearphishing Attachment](#spearphishing-attachment)
  - [Spearphishing Link](#spearphishing-link)
  - [Spearphishing via Service](#spearphishing-via-service)
  - [Phishing Tools](#phishing-tools)
- [Replication Through Removable Media](#replication-through-removable-media)
- [Supply Chain Compromise](#supply-chain-compromise)
  - [Compromise Software Dependencies and Development Tools](#compromise-software-dependencies--development-tools)
  - [Compromise Software Supply Chain](#compromise-software-supply-chain)
  - [Compromise Hardware Supply Chain](#compromise-hardware-supply-chain)
- [Trusted Relationships](#trusted-relationships)
- [Valid Accounts](#valid-accounts)
  - [Default Accounts](#default-accounts)
  - [Domain Accounts](#domain-accounts)
  - [Local Accounts](#local-accounts)
  - [Cloud Accounts](#cloud-accounts)

<br>
<hr>

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

<br>
<hr>

# Exploit Public-Facing Applications 
Exploited applications are often websites, but can include databases, standard services, network device administration and management protocols, and any other applications with Internet accessible open sockets, such as web servers and related services.
**Note:** If an application is hosted on cloud-based infrastructure and/or is containerized, then exploiting it may lead to compromise of the underlying instance or container.
* This can allow an adversary a path to access the cloud or container APIs, exploit container host access via Escape to Host, or take advantage of weak identity and access management policies
* For websites and databases, the OWASP top 10 and CWE top 25 highlight the most common web-based vulnerabilities.

<br>
<hr>

# External Remote Services #
Remote services and other access mechanisms allow users to connect to internal enterprise network resources from external locations. There are often remote service gateways that manage connections and credential authentication for these services. Services such as Windows Remote Management and VNC can also be used externally.

Access to valid accounts to use the service is often a requirement, which could be obtained through credential pharming or by obtaining the credentials from users after compromising the enterprise network.

<br>
<hr>

# Hardware Additions #
Rather than just connecting and distributing payloads via removable storage, more robust hardware additions can be used to introduce new functionalities and/or features into a system that can then be abused. Red teams leverage hardware additions for initial access. Commercial and open source products can be leveraged with capabilities such as passive network tapping, network traffic modification, keystroke injection, kernel memory reading via DMA, addition of new wireless access to an existing network, and others.

<br>
<hr>

# Phishing #
Adversaries may send victims emails containing malicious attachments or links, typically to execute malicious code on victim systems. Phishing may also be conducted via third-party services, like social media platforms. Phishing may also involve social engineering techniques, such as posing as a trusted source.
## Tools
- [LOTS Project](https://lots-project.com/) — Websites that allows attackers to use their domain when conducting phishing, C2, exfiltration, and downloading tools to evade detection
- [DarkSide](https://hakin9.org/darkside-tool-information-gathering-social-engineering/) — OSINT & Social Engineering Tool
- [mip22](https://github.com/makdosx/mip22) - Advanced phishing tool
- [CredSniper](https://github.com/ustayready/CredSniper) — Launch phishing site
- [PyPhisher](https://hakin9.org/pyphisher-easy-to-use-phishing-tool-with-65-website-templates/) — Phishing website templates
- [Fake-SMS](https://www-hackers--arise-com.cdn.ampproject.org/c/s/www.hackers-arise.com/amp/social-engineering-attacks-creating-a-fake-sms-message) — Create SMS messages
- [EvilNoVNC](https://github.com/JoelGMSec/EvilnoVNC) - Ready to go Phishing Platform
- [AdvPhishing] - This Is Advance Phishing Tool! OTP PHISHING
- [Zphishper](https://github.com/htr-tech/zphisher) - Automated phishing tool
<br>

## Spearphishing Attachment
Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems. Spearphishing attachment is a specific variant of spearphishing. Spearphishing attachment is different from other forms of spearphishing in that it employs the use of malware attached to an email. All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries attach a file to the spearphishing email and usually rely upon User Execution to gain execution. Spearphishing may also involve social engineering techniques, such as posing as a trusted source.

There are many options for the attachment such as Microsoft Office documents, executables, PDFs, or archived files. Upon opening the attachment (and potentially clicking past protections), the adversary's payload exploits a vulnerability or directly executes on the user's system. The text of the spearphishing email usually tries to give a plausible reason why the file should be opened, and may explain how to bypass system protections in order to do so. The email may also contain instructions on how to decrypt an attachment, such as a zip file password, in order to evade email boundary defenses. Adversaries frequently manipulate file extensions and icons in order to make attached executables appear to be document files, or files exploiting one application appear to be a file for a different one.

<br>

## Spearphishing Link
Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems. Spearphishing with a link is a specific variant of spearphishing. It is different from other forms of spearphishing in that it employs the use of links to download malware contained in email, instead of attaching malicious files to the email itself, to avoid defenses that may inspect email attachments. Spearphishing may also involve social engineering techniques, such as posing as a trusted source.

All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this case, the malicious emails contain links. Generally, the links will be accompanied by social engineering text and require the user to actively click or copy and paste a URL into a browser, leveraging User Execution. The visited website may compromise the web browser using an exploit, or the user will be prompted to download applications, documents, zip files, or even executables depending on the pretext for the email in the first place. Adversaries may also include links that are intended to interact directly with an email reader, including embedded images intended to exploit the end system directly or verify the receipt of an email (i.e. web bugs/web beacons).

Adversaries may also utilize links to perform consent phishing, typically with OAuth 2.0 request URLs that when accepted by the user provide permissions/access for malicious applications, allowing adversaries to Steal Application Access Tokens. These stolen access tokens allow the adversary to perform various actions on behalf of the user via API calls.

<br>

## Spearphishing via Service
Adversaries may send spearphishing messages via third-party services in an attempt to gain access to victim systems. Spearphishing via service is a specific variant of spearphishing. It is different from other forms of spearphishing in that it employs the use of third party services rather than directly via enterprise email channels.

All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries send messages through various social media services, personal webmail, and other non-enterprise controlled services. These services are more likely to have a less-strict security policy than an enterprise. As with most kinds of spearphishing, the goal is to generate rapport with the target or get the target's interest in some way. Adversaries will create fake social media accounts and message employees for potential job opportunities. Doing so allows a plausible reason for asking about services, policies, and software that's running in an environment. The adversary can then send malicious links or attachments through these services.

A common example is to build rapport with a target via social media, then send content to a personal webmail service that the target uses on their work computer. This allows an adversary to bypass some email restrictions on the work account, and the target is more likely to open the file since it's something they were expecting. If the payload doesn't work as expected, the adversary can continue normal communications and troubleshoot with the target on how to get it working.

## Phishing Tools
- [LOTS Project](https://lots-project.com/) — Websites that allows attackers to use their domain when conducting phishing, C2, exfiltration, and downloading tools to evade detection
- [DarkSide](https://hakin9.org/darkside-tool-information-gathering-social-engineering/) — OSINT & Social Engineering Tool
- [mip22](https://github.com/makdosx/mip22) - Advanced phishing tool
- [CredSniper](https://github.com/ustayready/CredSniper) — Launch phishing site
- [PyPhisher](https://hakin9.org/pyphisher-easy-to-use-phishing-tool-with-65-website-templates/) — Phishing website templates
- [Fake-SMS](https://www-hackers--arise-com.cdn.ampproject.org/c/s/www.hackers-arise.com/amp/social-engineering-attacks-creating-a-fake-sms-message) — Create SMS messages
- [EvilNoVNC](https://github.com/JoelGMSec/EvilnoVNC) - Ready to go Phishing Platform
- [AdvPhishing] - This Is Advance Phishing Tool! OTP PHISHING
- [Zphishper](https://github.com/htr-tech/zphisher) - Automated phishing tool

<br>
<hr>

# Replication Through Removable Media 
Adversaries may move onto systems, possibly those on disconnected or air-gapped networks, by copying malware to removable media and taking advantage of Autorun features when the media is inserted into a system and executes
* This may occur through modification of executable files stored on removable media or by copying malware and renaming it to look like a legitimate file to trick users into executing it on a separate system
* This may occur through manual manipulation of the media, modification of systems used to initially format the media, or modification to the media's firmware itself

<br>
<hr>

# Supply Chain Compromise #
Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer for the purpose of data or system compromise.

Supply chain compromise can take place at any stage of the supply chain. Adversaries looking to gain execution have often focused on malicious additions to legitimate software in software distribution or update channels. Targeting may be specific to a desired victim set or malicious software may be distributed to a broad set of consumers but only move on to additional tactics on specific victims.


## Compromise Software Dependencies & Development Tools ##
Adversaries may manipulate software dependencies and development tools prior to receipt by a final consumer for the purpose of data or system compromise -- Applications often depend on external software to function properly. Popular open source projects that are used as dependencies in many applications may be targeted as a means to add malicious code to users of the dependency.



## Compromise Software Supply Chain ##
Supply chain compromise of software can take place in a number of ways, including manipulation of the application source code, manipulation of the update/distribution mechanism for that software, or replacing compiled releases with a modified version.



## Compromise Hardware Supply Chain ##
By modifying hardware or firmware in the supply chain, adversaries can insert a backdoor into consumer networks that may be difficult to detect and give the adversary a high degree of control over the system. Hardware backdoors may be inserted into various devices, such as servers, workstations, network infrastructure, or peripherals.

<br>
<hr>

# Trusted Relationships #
Access through trusted third party relationship exploits an existing connection that may not be protected or receives less scrutiny than standard mechanisms of gaining access to a network.

Organizations often grant elevated access to second or third-party external providers in order to allow them to manage internal systems as well as cloud-based environments. The third-party provider's access may be intended to be limited to the infrastructure being maintained, but may exist on the same network as the rest of the enterprise. As such, valid accounts used by the other party for access to internal network systems may be compromised and used.

<br>
<hr>

# Valid Accounts #
Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services. Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network.

Attackers may abuse inactive accounts allowing them to evade detection, as the original account user will not be present to identify any anomalous activity taking place on their account.


## Default Accounts ##
Default accounts are those that are built-into an OS, such as the Guest or Administrator accounts on Windows systems, also including default factory/provider set accounts on other types of systems, software, or devices, including the root user account in AWS and the default service account in Kubernetes.

Appliances that come preset with a username and password combination pose a serious threat to organizations that do not change it post installation, as they are easy targets for an adversary. Similarly, adversaries may also utilize publicly disclosed or stolen private keys or credential materials to legitimately connect to remote environments via remote services.

## Domain Accounts ##
Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain. Domain accounts can cover users, administrators, and services.

Adversaries may compromise domain accounts, some with a high level of privileges, through various means such as OS Credential Dumping or password reuse, allowing access to privileged resources of the domain.

## Local Accounts ##
 Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service.

Local Accounts may also be abused to elevate privileges and harvest credentials through OS Credential Dumping. Password reuse may allow the abuse of local accounts across a set of machines on a network for the purposes of Privilege Escalation and Lateral Movement.

## Cloud Accounts ##
Cloud accounts are those created and configured by an organization for use by users, remote support, services, or for administration of resources within a cloud service provider or SaaS application. Cloud accounts may be federated with traditional identity management system, such as Window Active Directory.

Compromised credentials for cloud accounts can be used to harvest sensitive data from online storage accounts and databases. Access to cloud accounts can also be abused to gain Initial Access to a network by abusing a Trusted Relationship. Similar to Domain Accounts, compromise of federated cloud accounts may allow adversaries to more easily move laterally within an environment.

Once a cloud account is compromised, an adversary may perform Account Manipulation - for example, by adding Additional Cloud Roles - to maintain persistence and potentially escalate their privileges.
