The adversary is trying to establish resources they can use to support operations.

Resource Development consists of techniques that involve Attackers creating, purchasing, or compromising/stealing resources that can be used to support targeting. Such resources include infrastructure, accounts, or capabilities. These resources can be leveraged by the adversary to aid in other phases of the adversary lifecycle, such as using purchased domains to support Command and Control, email accounts for phishing as a part of Initial Access, or stealing code signing certificates to help with Defense Evasion. 

---------------------
# Tables of Content #
---------------------
- [Acquire Infrastructure](#acquire-infrastructure)
- [Compromise Accounts](#compromise-accounts)
- [Compromise Infrastructure](#compromise-infrastructure)
- [Obtain Capabilities](#Obtain-capabilities)
- [Establish Accounts](#establish-accounts)
- [Stage Capabilities](#stage-capabilities)


--------------------------
# Acquire Infrastructure #
Attackers may buy, lease, or rent infrastructure that can be used during targeting. A wide variety of infrastructure exists for hosting and orchestrating adversary operations such as physical or cloud servers, domains, and third-party web services.

Use of these infrastructure solutions allows an adversary to stage, launch, and execute an operation. Solutions may help adversary operations blend in with traffic that is seen as normal, such as contact to third-party web services. Depending on the implementation, Attackers may use infrastructure that makes it difficult to physically tie back to them as well as utilize infrastructure that can be rapidly provisioned, modified, and shut down.

## Domains ##
Domain names are the human readable names used to represent one or more IP addresses. They can be purchased or acquired for free. Attackers can use purchased domains for a variety of purposes, including for Phishing, Drive-by Compromise, and Command and Control.
**Note:** Attackers may choose domains that are similar to legitimate domains, including through use of homoglyphs or use of a different top-level domain (TLD). Typosquatting may be used to aid in delivery of payloads via Drive-by Compromise. Attackers can also use internationalized domain names (IDNs) to create visually similar lookalike domains for use in operations.

Attackers may use private WHOIS services to obscure information about who owns a purchased domain and may further interrupt efforts to track their infrastructure by using varied registration information and purchasing domains with different domain registrars.


## DNS Server ##
Attackers may set up their own DNS servers that can be used during targeting. During post-compromise activity, Attackers may utilize DNS traffic for various tasks, including for Command and Control. Instead of hijacking existing DNS servers, Attackers may opt to configure and run their own DNS servers in support of operations.

By running their own DNS servers, Attackers can have more control over how they administer server-side DNS C2 traffic. With control over a DNS server, Attackers can configure DNS applications to provide conditional responses to malware and, generally, have more flexibility in the structure of the DNS-based C2 channel.


## Virtual Private Server ##
attackers can make it difficult to physically tie back operations to them by using VPS. The use of cloud infrastructure can also make it easier for Attackers to rapidly provision, modify, and shut down their infrastructure.

Acquiring a VPS for use in later stages of the adversary lifecycle, such as Command and Control, can allow Attackers to benefit from the ubiquity and trust associated with higher reputation cloud service providers. Attackers may also acquire infrastructure from VPS service providers that are known for renting VPSs with minimal registration information, allowing for more anonymous acquisitions of infrastructure.


## Server ##
Use of servers allows an adversary to stage, launch, and execute an operation. During post-compromise activity, Attackers may utilize servers for various tasks, including for Command and Control. Instead of compromising a third-party Server or renting a Virtual Private Server, Attackers may opt to configure and run their own servers in support of operations.

## Botnet ##
A botnet is a network of compromised systems that can be instructed to perform coordinated tasks. Attackers may purchase a subscription to use an existing botnet from a booter/stresser service. With a botnet at their disposal, Attackers may perform follow-on activity such as large-scale Phishing or DDoS attacks.


## Web Services ##
A variety of popular websites exist for attackers to register for a web-based service that can be abused during later stages of the adversary lifecycle, such as during Command and Control (Web Service) or Exfiltration Over Web Service. Using common services, such as those offered by Google or Twitter, makes it easier for Attackers to hide in expected noise. By utilizing a web service, Attackers can make it difficult to physically tie back operations to them.






-----------------------
# Compromise Accounts #
Attackers may compromise accounts with services that can be used during targeting. For operations incorporating social engineering, the utilization of an online persona may be important. Rather than creating and cultivating accounts, attackers may compromise existing accounts. Utilizing an existing persona may engender a level of trust in a potential victim if they have a relationship, or knowledge of, the compromised persona.

## Social Media Accounts ##
Common methods for compromising accounts
* Gathering credentials via Phishing for Information
* Purchasing credentials from third-party sites
* Brute forcing credentials (ex: password reuse from breach credential dumps)
  
## Email Accounts ##
Attackers can use compromised email accounts to further their operations by leveraging them. Utilizing an existing persona with a compromised email account may engender a level of trust in a potential victim if they have a relationship, or knowledge of, the compromised persona. Compromised email accounts can also be used in the acquisition of infrastructure. Attackers can use a compromised email account to hijack existing email threads with targets of interest.



------------------------
# Obtain Capabilities #
Rather than purchasing, freely downloading, or stealing capabilities, attackers may develop their own capabilities in-house. This is the process of identifying development requirements and building solutions such as malware, exploits, and self-signed certificates. Attackers may develop capabilities to support their operations throughout numerous phases of the adversary lifecycle.


## Malware ##
Building malicious software can include the development of payloads, droppers, post-compromise tools, backdoors (including backdoored images), packers, C2 protocols, and the creation of infected removable media. Attackers may develop malware to support their operations, creating a means for maintaining control of remote machines, evading defenses, and executing post-compromise behaviors.
* Third-party entities can include technology companies that specialize in malware development, criminal marketplaces (including Malware-as-a-Service, or MaaS), or from individuals. In addition to purchasing malware, adversaries may steal and repurpose malware from third-party entities. 
* Some aspects of malware development, such as C2 protocol development, may require adversaries to obtain additional infrastructure. For example, malware developed that will communicate with Twitter for C2, may require use of Web Services.

## Code Signing Certificates ##
**Code Signing:** The process of digitally signing executables and scripts to confirm the software author and guarantee that the code has not been altered or corrupted. Code signing provides a level of authenticity for a program from the developer and a guarantee that the program has not been tampered with. Users/security tools may trust a signed piece of code more than an unsigned piece of code even if they don't know who issued the certificate or who the author is.

Prior to Code Signing, adversaries may purchase or steal code signing certificates for use in operations. The purchase of code signing certificates may be done using a front organization or using information stolen from a previously compromised entity that allows the adversary to validate to a certificate provider as that entity. Adversaries may also steal code signing materials directly from a compromised third-party.

## Digital Certificates ##
**SSL/TLS Certificates:** Certificates designed to instill trust, containing information about the key, its owner's identity, and the digital signature of an entity that has verified the certificate's contents are correct. 

Adversaries may purchase or steal SSL/TLS certificates to further their operations, such as encrypting C2 traffic or even enabling Man-In-The-Middle if the certificate is trusted or otherwise added to the root of trust. 
* The purchase of digital certificates may be done using a front organization or using information stolen from a previously compromised entity that allows the adversary to validate to a certificate provider as that entity.
* Adversaries may also steal certificate materials directly from a compromised third-party, including from certificate authorities.
* Adversaries may register or hijack domains that they will later purchase an SSL/TLS certificate for.


## Exploits ##
**Exploit:** Takes advantage of a bug or vulnerability in order to cause unintended or unanticipated behavior to occur on computer hardware or software.
* Adversaries may use information acquired via vulnerabilities to focus exploit development efforts. As part of the exploit development process, adversaries may uncover exploitable vulnerabilities through methods such as fuzzing and patch analysis
* An adversary may monitor exploit provider forums to understand the state of existing, as well as newly discovered, exploits. There is usually a delay between when an exploit is discovered and when it is made public. An adversary may target the systems of those known to conduct exploit research and development in order to gain that knowledge for use during a subsequent operation.

## Vulnerabilities ##
An adversary may monitor vulnerability disclosures/databases to understand the state of existing, as well as newly discovered, vulnerabilities. There is usually a delay between when a vulnerability is discovered and when it is made public. An adversary may target the systems of those known to conduct vulnerability research. Knowledge of a vulnerability may cause an adversary to search for an existing exploit (i.e. Exploits) or to attempt to develop one themselves.


----------------------
# Establish Accounts #
Attackers can create accounts that can be used to build a persona to further operations. Persona development consists of the development of public information, presence, history and appropriate affiliations. This development could be applied to social media, website, or other publicly available information that could be referenced and scrutinized for legitimacy over the course of an operation using that persona or identity.

When incorporating social engineering, the utilization of an online persona may be important. These personas may be fictitious or impersonate real people. The persona may exist on a single site or across multiple sites. Establishing a persona may require development of additional documentation to make them seem real. This could include filling out profile information, developing social networks, or incorporating photos.

Establishing accounts can also include the creation of accounts with email providers, which may be directly leveraged for Phishing for Information or Phishing.

## Social Media Accounts ##
Once a persona has been developed an adversary can use it to create connections to targets of interest. These connections may be direct or may include trying to connect through others. These accounts may be leveraged during other phases of the adversary lifecycle, such as during Initial Access.

## Email Accounts ##
Adversaries can use accounts created with email providers to further their operations and cultivate a persona around the email account, such as through use of social media accounts, to increase the chance of success of follow-on behaviors.
**Note:** To decrease the chance of physically tying back operations to themselves, adversaries may make use of disposable email services.




----------------------
# Stage Capabilities #
Adversaries may upload, install, or otherwise set up capabilities that can be used during targeting. To support their operations, an adversary may need to take capabilities they developed (Develop Capabilities) or obtained (Obtain Capabilities) and stage them on infrastructure under their control. These capabilities may be staged on infrastructure that was previously purchased/rented by the adversary (Acquire Infrastructure) or was otherwise compromised by them (Compromise Infrastructure). Capabilities can also be staged on web services, such as GitHub or Pastebin.[1]


## Upload Malware ##
Malware may be placed on infrastructure that was previously purchased/rented by the adversary or was otherwise compromised by them. Malware can also be staged on web services, such as GitHub or Pastebin.
* Upload backdoored files, such as application binaries, virtual machine images, or container images, to third-party software stores or repositories (ex: GitHub, CNET, AWS Community AMIs, Docker Hub). 

## Upload Tools ##
Adversaries may upload tools to support their operations, such as making a tool available to a victim network to enable Ingress Tool Transfer by placing it on an Internet accessible web server. Adversaries can avoid the need to upload a tool by having compromised victim machines download the tool directly from a third-party hosting location (ex: a non-adversary controlled GitHub repo), including the original hosting site of the tool.

## Install Digital Certificates ##
Adversaries may install SSL/TLS certificates that can be used to further their operations, such as encrypting C2 traffic or lending credibility to a credential harvesting site.

Adversaries can obtain digital certificates or create self-signed certificates. Digital certificates can then be installed on adversary controlled infrastructure that may have been acquired or previously compromised.

## Drive-By Target ##
Adversaries may prepare an operational environment to infect systems that visit a website over the normal course of browsing. Endpoint systems may be compromised through browsing to adversary controlled sites, as in Drive-by Compromise. In such cases, the user's web browser is typically targeted for exploitation (often not requiring any extra user interaction once landing on the site), but adversaries may also set up websites for non-exploitation behavior such as Application Access Token. Prior to Drive-by Compromise, adversaries must stage resources needed to deliver that exploit to users who browse to an adversary controlled site. Drive-by content can be staged on adversary controlled infrastructure that has been acquired (Acquire Infrastructure) or previously compromised (Compromise Infrastructure).

Adversaries may upload or inject malicious web content, such as JavaScript, into websites.[1][2] This may be done in a number of ways, including inserting malicious script into web pages or other user controllable web content such as forum posts. Adversaries may also craft malicious web advertisements and purchase ad space on a website through legitimate ad providers. In addition to staging content to exploit a user's web browser, adversaries may also stage scripting content to profile the user's browser (as in Gather Victim Host Information) to ensure it is vulnerable prior to attempting exploitation.[3]

Websites compromised by an adversary and used to stage a drive-by may be ones visited by a specific community, such as government, a particular industry, or region, where the goal is to compromise a specific user or set of users based on a shared interest. This kind of targeted campaign is referred to a strategic web compromise or watering hole attack.

Adversaries may purchase domains similar to legitimate domains (ex: homoglyphs, typosquatting, different top-level domain, etc.) during acquisition of infrastructure (Domains) to help facilitate Drive-by Compromise.

## Link Target ##
Adversaries may put in place resources that are referenced by a link that can be used during targeting. An adversary may rely upon a user clicking a malicious link in order to divulge information (including credentials) or to gain execution, as in Malicious Link. Links can be used for spearphishing, such as sending an email accompanied by social engineering text to coax the user to actively click or copy and paste a URL into a browser. Prior to a phish for information (as in Spearphishing Link) or a phish to gain initial access to a system (as in Spearphishing Link), an adversary must set up the resources for a link target for the spearphishing link.

Typically, the resources for a link target will be an HTML page that may include some client-side script such as JavaScript to decide what content to serve to the user. Adversaries may clone legitimate sites to serve as the link target, this can include cloning of login pages of legitimate web services or organization login pages in an effort to harvest credentials during Spearphishing Link.[1][2] Adversaries may also Upload Malware and have the link target point to malware for download/execution by the user.

Adversaries may purchase domains similar to legitimate domains (ex: homoglyphs, typosquatting, different top-level domain, etc.) during acquisition of infrastructure (Domains) to help facilitate Malicious Link. Link shortening services can also be emp

