# Reconnaissance

**Reconnaissance:** Consists of techniques that involve adversaries actively or passively gathering information that can be used to support targeting. Such information may include details of the victim organization, infrastructure, or staff/personnel. This information can be leveraged by the adversary to aid in other phases of the adversary lifecycle, such as using gathered information to plan and execute Initial Access, to scope and prioritize post-compromise objectives, or to drive and lead further Reconnaissance efforts.

<br>
<hr>

# Table of Contents
- [Sock Puppets](#Sock-Puppets)
- [Active Scanning](#Active-Scanning)
  - [Scanning IP Blocks](#scanning-ip-blocks)
  - [Vulnerability Scanning](#vulnerability-scanning)
  - [Wordlist Scanning](#wordlist-scanning)
  - [Active Enumeration Tools](#active-enumeration-tools)
- [Gathering Host Information](#Gathering-Host-Information)
  - [Hardware](#hardware)
  - [Software](#software)
  - [Firmware](#firmware)
  - [Client Configurations](#client-configuration)
  - [Credentials](#credentials)
  - [Email Addresses](#email-addressess)
  - [Employee Names](#employee-names)
  - [Tools](#host-enumeration-tools)
- [Gathering Victim Identity Information](#Gathering-Victim-Identity-Information)
  - [Credentials](#credentials)
  - [Email Addresses](#email-addressess)
  - [Employee Names](#employee-names)
  - [Tools](#identity-enumeration-tools)
- [Gathering Vitcim Network Information](#gathering-victim-network-information)
  - [DNS](#dns)
  - [Network Trust Dependencies](#network-trust-dependencies)
  - [Network Topology](#network-topology)
  - [IP Addresses](#ip-addresses)
  - [Network Security Appliances](#network-security-appliances)
  - [Network Enumeration Tools](#network-enumeration-tools)
- [Gathering Victim Organization Information](#Gathering-Victim-Organization-Information)
  - [Determine Physical Locations](#determine-physical-locations)
  - [Business Relationships](#business-relationships)
  - [Identify Business Tempo](#identify-business-tempo)
  - [Identify Roles](#identify-roles)
  - [Victim Enumeration Tools](#victim-enumeration-tools)
- [Phishing for Information](#Phishing-for-Information)
  - [Spearphishing Service](#spearphishing-service)
  - [Spearphishing Attachment](#spearphishing-attachment)
  - [Spearphishing Link](#spearphishing-link)
  - [Phishing Tools](#phishing-tools)
- [Searching Open Technical Databases](#Searching-Open-Technical-Databases)
  - [DNS/Passive DNS](#dns--passive-dns)
  - [WHOIS](#whois)
  - [Digital Certificates](#digital-certificates)
  - [CDNs](#cdns)
  - [Scan Databases](#scan-databases)
  - [Open Database Enumeration Tools](#open-database-enumeration-tools)
- [Searching Open Websites / Domains](#Searching-Open-Websites-/-Domains)
  - [Social Media](#social-media)
  - [Search Engines](#search-engines)
  - [Open Website / Domain Enumeration Tools](#open-website--domain-enumeration-tools)
- [Searching Victim-Owned Websites](#Searching-Victim-Owned-Websites)
  - [Vitcim-Owned Enumeration Tools](#vitcm-owned-enumeration-tools)
- [Searching Closed Sources](#Searching-Closed-Sources)
  - [Threat Intelligence Vendors](#threat-intelligence-vendors)
  - [Purchase Technical Data](#purchase-technical-data)
  - [Threat Intelligence Solutions](#threat-intelligence-solutions)

<br>
<hr>

# Sock Puppets
Sock Puppets are aliases, fictitious persona profiles created by someone else with specific goals in mind and is part of an OSINT Social Engineering technique. Sock puppets have a real name, real phone numbers, address, photographs, credit card number, various social media accounts, friends, etc.

## Creating Sock Puppets for OSINT Investigations
* [The Art Of The Sock](https://www.secjuice.com/the-art-of-the-sock-osint-humint/)
* [Process for Setting Up Anonymous Sockpuppet Accounts](https://www.reddit.com/r/OSINT/comments/dp70jr/my_process_for_setting_up_anonymous_sockpuppet/)
* [Fake Name Generator](https://www.fakenamegenerator.com/)
* [This Person Does not Exist](https://www.thispersondoesnotexist.com/)
* [Privacy.com](https://privacy.com/join/LADFC) — Create virtual payment cards for one-time purchases or subscriptions, directly from your browser. Set spend limits, pause, unpause, and close cards any time you want.

**NOTE::**
- Don’t tie fake identity to personal accounts and devices
- Buy burner devices
- Don’t conduct purchases on personal IPs

<br>
<hr>

# Active Scanning
Adversaries may execute active scans to gather information that can be used during targeting. The adversary probes victim infrastructure via network traffic

<br>

## Scanning IP Blocks ##
Adversaries may scan IP blocks in order to gather victim network information. Scans may range from simple pings to more nuanced scans that may reveal host software/versions via server banners or other network artifacts.

<br>

## Vulnerability Scanning ##
Adversaries may scan victims for vulnerabilities that can be used during targeting. Vulnerability scans typically check if the configuration of a target host/application (ex: software and version) potentially aligns with the target of a specific exploit the adversary may seek to use.

These scans may also include more broad attempts to identify more commonly known, exploitable vulnerabilities. Vulnerability scans typically harvest running software and version numbers via server banners, listening ports, or other network artifacts.

<br>

## Wordlist Scanning ##
Adversaries may iteratively probe infrastructure using brute-forcing and crawling techniques. While this technique employs similar methods to Brute Force, its goal is the identification of content and infrastructure rather than the discovery of valid credentials. Wordlists used in these scans may contain generic, commonly used names and file extensions or terms specific to a particular software. Adversaries may also create custom, target-specific wordlists using data gathered from other reconnaissance techniques.

<br>

## Active Enumeration Tools
### IP Scanning Tools
- [Nmap](https://nmap.org/) - Network discovery and security auditing
- [AngryIP](https://angryip.org/) - Fast and simple network scanner
- [PRTG](https://www.paessler.com/tools)
- [Spidex](https://github.com/alechilczenko/spidex) — Find Internet-connected devices
- [IP Neighboring](https://www.ip-neighbors.com/) — Discover Neighboring IP Hosts
- [Grey Noise](https://www.greynoise.io/) — Trace IPs, URLs, etc.
- [HaxUnit](https://github.com/Bandit-HaxUnit/haxunit) — Combines multiple active/passive subdomain enumeration tools and port scanning
- [scanless](https://github.com/vesche/scanless) — Websites that performs port scans on your behalf
- [Nrich](https://gitlab.com/shodan-public/nrich) - Quickly analyze IPs and determines open ports / vulnerabilities
- [Naabu](https://github.com/projectdiscovery/naabu) - Enumerate valid ports conducting a SYN/CONNECT scans on the host(s) ports that return a reply

### Vulnerability Scanning Tools
- [Nrich](https://gitlab.com/shodan-public/nrich) - Quickly analyze IPs and determines open ports / vulnerabilities
- Nessus
- OpenVas
- BurpSuite
- [Trend Micro Hybrid Cloud Security](https://www.g2.com/products/trend-micro-hybrid-cloud-security/reviews)
- Orca Security
- InsightVM
- Qualys
#### Application Vulnerability Scanning
  - Nikto

### Crawling Tools
- [GooFuzz](https://github.com/m3n0sd0n4ld/GooFuzz) — Perform fuzzing with an OSINT approach, managing to enumerate directories, files, subdomains or parameters without leaving evidence on the target's server and by means of advanced Google searches
- [Backlink Discovery](https://app.neilpatel.com/en/seo_analyzer/backlinks) — Find backlinks, Referring domains, Link history, etc.
- [HaxUnit](https://github.com/Bandit-HaxUnit/haxunit) — Combines multiple active/passive subdomain enumeration tools and port scanning
- [js-parse](https://github.com/l4yton/js-parse) — Looks through javascript files in a given directory and finds subdomains, URLs, parameters, custom headers, and API keys
- [Astra](https://github.com/Sachin-v3rma/Astra) — Finds API keys, URLs, AWS Buckets, etc.
- [breach-parse](https://github.com/hmaverickadams/breach-parse) - Tool for parsing breached passwords
- [SocialHunter](https://github.com/utkusen/socialhunter) — Crawls the given URL and finds broken social media links that can be hijacked
- [Meg](https://github.com/tomnomnom/meg) - Quickly find hidden paths/directories without flooding traffic

<br>
<hr>

# Gathering Host Information 
Adversaries may gather information about the victim's hosts that can be used during targeting. Information about hosts may include a variety of details, including administrative data (ex: name, assigned IP, functionality, etc.) as well as specifics regarding its configuration (ex: operating system, language, etc.).

<br>

## Hardware 
Adversaries may gather information about the victim's host hardware that can be used during targeting. Information about hardware infrastructure may include a variety of details such as types and versions on specific hosts, as well as the presence of additional components that might be indicative of added defensive protections (ex: card/biometric readers, dedicated encryption hardware, etc.)

<br>

## Software 
Adversaries may gather information about the victim's host software that can be used during targeting. Information about installed software may include a variety of details such as types and versions on specific hosts, as well as the presence of additional components that might be indicative of added defensive protections (ex: antivirus, SIEMs, etc.).

<br>

## Firmware ##
Adversaries may gather information about the victim's host firmware that can be used during targeting. Information about host firmware may include a variety of details such as type and versions on specific hosts, which may be used to infer more information about hosts in the environment (ex: configuration, purpose, age/patch level, etc.)

<br>

## Client Configuration ##
Adversaries may gather information about the victim's client configurations that can be used during targeting. Information about client configurations may include a variety of details and settings, including operating system/version, virtualization, architecture (ex: 32 or 64 bit), language, and/or time zone.

## Host Enumeration Tools
- [Investigator](https://abhijithb200.github.io/investigator/) — Quickly check & gather information about the target domain name
- [Domain Investigation Toolbox](https://cipher387.github.io/domain_investigation_toolbox/) — Gather information about the target domain name
- [Sarenka](https://hakin9.org/sarenka-an-osint-tool-that-gets-data-from-services-like-shodan-censys-etc-in-one-app/) — Gathers data from Shodan, censys, etc.
- [HaxUnit](https://github.com/Bandit-HaxUnit/haxunit) — Combines multiple active/passive subdomain enumeration tools and port scanning
- [scanless](https://github.com/vesche/scanless) — Websites that performs port scans on your behalf
- [Clickjacker](https://serene-agnesi-57a014.netlify.app/) — Discover secret API Keys
- [js-parse](https://github.com/l4yton/js-parse) — Looks through javascript files in a given directory and finds subdomains, URLs, parameters, custom headers, and API keys
- [Astra](https://github.com/Sachin-v3rma/Astra) — Finds API keys, URLs, AWS Buckets, etc.
- [securityheader.com](http://securityheader.com) — Reports headers that are missing; Exploitable
- [Nrich](https://gitlab.com/shodan-public/nrich) - Quickly analyze IPs and determines open ports / vulnerabilities
- [Naabu](https://github.com/projectdiscovery/naabu) - Enumerate valid ports conducting a SYN/CONNECT scans on the host(s) ports that return a reply
- LeakWatch - Scans the Internet to detect exposed information

<br>
<hr>

# Gathering Victim Identity Information #
Adversaries may gather information about the victim's identity that can be used during targeting. Information about identities may include a variety of details, including personal data (ex: employee names, email addresses, etc.) as well as sensitive details such as credentials.

<br>

## Credentials ##
Adversaries may gather credentials that can be used during targeting. Account credentials gathered by adversaries may be those directly associated with the target victim organization or attempt to take advantage of the tendency for users to use the same passwords across personal and business accounts.

Adversaries may gather credentials from potential victims in various ways, such as direct elicitation via Phishing for Information. Adversaries may also compromise sites then include malicious content designed to collect website authentication cookies from visitors.

Credential information may also be exposed to adversaries via leaks to online or other accessible data sets and may even purchase credentials from dark web or other black-markets. 

<br>

## Email Addressess ##
Adversaries may gather email addresses that can be used during targeting. Even if internal instances exist, organizations may have public-facing email infrastructure and addresses for employees. Email addresses could also be enumerated via more active means (i.e. Active Scanning), such as probing and analyzing responses from authentication services that may reveal valid usernames in a system.

<br>

## Employee Names ##
Adversaries may gather employee names that can be used during targeting. Employee names be used to derive email addresses as well as to help guide other reconnaissance efforts and/or craft more-believable lures.

## Identity Enumeration Tools
- Binary Edge - Scans the internet for threat intelligence
- Hunter - Search for email addresses belonging to a website
- Fofa - Search for various threat intelligence
- ZoomEye - Gather information about targets
- LeakIX - Search publicly indexed information
- IntelligenceX - Search Tor, I2P, data leaks, domains, and emails
- PublicWWW -  Marketing and affiliate marketing research
- Dehashed - Search for anything like username, email, passwords, address, or phone number.
- Have I Been Pwned? - Check whether personal data has been compromised by data breaches
- Snusbase - Indexes information from hacked websites and leaked databases
- LeakBase - Forum of leaked databases
- [Awesome Hacker Search Engines](https://github.com/edoardottt/awesome-hacker-search-engines) — CVEs, Domains, Addresses, Certifications, Credentials, etc.

<br>
<hr>

# Gathering Victim Network Information
Adversaries may gather information about the victim's networks that can be used during targeting. Information about networks may include a variety of details, including administrative data (ex: IP ranges, domain names, etc.) as well as specifics regarding its topology and operations.

Adversaries may gather this information in various ways, such as direct collection actions via *Active Scanning or Phishing for Information*
* Information about networks may also be exposed to adversaries via online or other accessible data sets 
* Gathering this information may reveal opportunities for other forms of reconnaissance, establishing operational resources, and/or initial access.

## Domain Properties
Adversaries may gather information about the victim's network domain that can be used during targeting
* Information about domains and their properties may include a variety of details, including what domain(s) the victim owns as well as administrative data (ex: name, registrar, etc.) and more directly actionable information such as contacts (email addresses and phone numbers), business addresses, and name servers.

Adversaries may gather this information in various ways, such as direct collection actions via *Active Scanning or Phishing for Information*
* Information about victim domains and their properties may also be exposed to adversaries via online or other accessible data sets (ex: WHOIS)

<br>

## DNS
Adversaries may gather information about the victim's DNS that can be used during targeting
* DNS information may include a variety of details, including registered name servers as well as records that outline addressing for a target’s subdomains, mail servers, and other hosts

Adversaries may gather this information in various ways, such as querying or otherwise collecting details via *DNS/Passive DNS*
* DNS information may also be exposed to adversaries via online or other accessible data sets (ex: Search Open Technical Databases)

<br>

## Network Trust Dependencies
Adversaries may gather information about the victim's network trust dependencies that can be used during targeting
* Information about network trusts may include a variety of details, including second or third-party organizations/domains (ex: managed service providers, contractors, etc.) that have connected (and potentially elevated) network access

Adversaries may gather this information in various ways, such as direct elicitation via *Phishing for Information*
* Information about network trusts may also be exposed to adversaries via online or other accessible data sets (ex: Search Open Technical Databases).

<br>

## Network Topology
Adversaries may gather information about the victim's network topology that can be used during targeting
* Information about network topologies may include a variety of details, including the physical and/or logical arrangement of both external-facing and internal network environments
* This information may also include specifics regarding network devices and other infrastructure.

Adversaries may gather this information in various ways, such as direct collection actions via *Active Scanning or Phishing for Information*
* Information about network topologies may also be exposed to adversaries via online or other accessible data sets (ex: Search Victim-Owned Websites)

<br>

## IP Addresses
Adversaries may gather the victim's IP addresses that can be used during targeting
* Public IP addresses may be allocated to organizations by block, or a range of sequential addresses
* Information about assigned IP addresses may include a variety of details, such as which IP addresses are in use
* IP addresses may also enable an adversary to derive other details about a victim, such as organizational size, physical location(s), Internet service provider, and or where/how their publicly-facing infrastructure is hosted

Adversaries may gather this information in various ways, such as direct collection actions via *Active Scanning or Phishing for Information*
* Information about assigned IP addresses may also be exposed to adversaries via online or other accessible data sets (ex: Search Open Technical Databases)

<br>

## Network Security Appliances
Adversaries may gather information about the victim's network security appliances that can be used during targeting
* Information about network security appliances may include a variety of details, such as the existence and specifics of deployed firewalls, content filters, and proxies/bastion hosts
* Adversaries may also target information about victim NIDS or other appliances related to defensive cybersecurity operations

Adversaries may gather this information in various ways, such as direct collection actions via *Active Scanning or Phishing for Information*
* Information about network security appliances may also be exposed to adversaries via online or other accessible data sets (ex: Search Victim-Owned Websites).

## Network Enumeration Tools
### Network / Port Scanners
- [Nmap](https://nmap.org/) - Network discovery and security auditing
- [AngryIP](https://angryip.org/) - Fast and simple network scanner
- [PRTG](https://www.paessler.com/tools)
- [Spidex](https://github.com/alechilczenko/spidex) — Find Internet-connected devices
- [IP Neighboring](https://www.ip-neighbors.com/) — Discover Neighboring IP Hosts
- [Grey Noise](https://www.greynoise.io/) — Trace IPs, URLs, etc.
- [HaxUnit](https://github.com/Bandit-HaxUnit/haxunit) — Combines multiple active/passive subdomain enumeration tools and port scanning
- [scanless](https://github.com/vesche/scanless) — Websites that performs port scans on your behalf
- [Nrich](https://gitlab.com/shodan-public/nrich) - Quickly analyze IPs and determines open ports / vulnerabilities
- [Naabu](https://github.com/projectdiscovery/naabu) - Enumerate valid ports conducting a SYN/CONNECT scans on the host(s) ports that return a reply

### Domain / DNS Scanners
- [Investigator](https://abhijithb200.github.io/investigator/) — Quickly check & gather information about the target domain name
- [Domain Investigation Toolbox](https://cipher387.github.io/domain_investigation_toolbox/) — Gather information about the target domain name
- [Sarenka](https://hakin9.org/sarenka-an-osint-tool-that-gets-data-from-services-like-shodan-censys-etc-in-one-app/) — Gathers data from Shodan, censys, etc.
- [HaxUnit](https://github.com/Bandit-HaxUnit/haxunit) — Combines multiple active/passive subdomain enumeration tools and port scanning
- [js-parse](https://github.com/l4yton/js-parse) — Looks through javascript files in a given directory and finds subdomains, URLs, parameters, custom headers, and API keys
- [Astra](https://github.com/Sachin-v3rma/Astra) — Finds API keys, URLs, AWS Buckets, etc.
- [IQ WHOIS](https://iqwhois.com/advanced-search) — Advanced WHOIS Search
- [Backlink Discovery](https://app.neilpatel.com/en/seo_analyzer/backlinks) — Find backlinks, Referring domains, Link history, etc.
- [WhoisFreaks](https://whoisfreaks.com/) — WHOIS Discovery
- [WhereGoes](https://wheregoes.com/) — URL Redirect Checker
- [Phonebook](https://phonebook.cz/) — Lists all domains, email addresses, URL for the target domain 
- [dnsenum](https://github.com/fwaeytens/dnsenum) — Script that enumerates DNS information
- [PowerMeta](https://github.com/dafthack/PowerMeta) — Searches for publicly available files hosted on webpages for a particular domain
- [DNSrr](https://github.com/A3h1nt/Dnsrr) — Enumerate all information from DNS records
- [assetfinder](https://github.com/tomnomnom/assetfinder): Find domains and subdomains potentially related to a given domain
- [Meg](https://github.com/tomnomnom/meg) - Quickly find hidden paths/directories without flooding traffic

<br>
<hr>

# Gathering Victim Organization Information #
Adversaries may gather information about the victim's organization that can be used during targeting. Information about an organization may include a variety of details, including the names of divisions/departments, specifics of business operations, as well as the roles and responsibilities of key employees.

<br>

## Determine Physical Locations ##
Adversaries may gather the victim's physical location(s) that can be used during targeting. Information about physical locations of a target organization may include a variety of details, including where key resources and infrastructure are housed. Physical locations may also indicate what legal jurisdiction and/or authorities the victim operates within.

<br>

## Business Relationships ##
Adversaries may gather information about the victim's business relationships that can be used during targeting. Information about an organization’s business relationships may include a variety of details, including second or third-party organizations/domains (ex: managed service providers, contractors, etc.) that have connected (and potentially elevated) network access. This information may also reveal supply chains and shipment paths for the victim’s hardware and software resources.

<br>

## Identify Business Tempo ##
Adversaries may gather information about the victim's business tempo that can be used during targeting. Information about an organization’s business tempo may include a variety of details, including operational hours/days of the week. This information may also reveal times/dates of purchases and shipments of the victim’s hardware and software resources.

<br>

## Identify Roles ##
Adversaries may gather information about identities and roles within the victim organization that can be used during targeting. Information about business roles may reveal a variety of targetable details, including identifiable information for key personnel as well as what data/resources they have access to.

## Victim Enumeration Tools
### Threat Intelligence
- Wigle - Database of wireless networks, with statistics
- Binary Edge - Scans the internet for threat intelligence
- ONYPHE - Collects cyber-threat intelligence data
- Fofa - Search for various threat intelligence
- ZoomEye - Gather information about targets
- LeakIX - Search publicly indexed information
- URL Scan - Free service to scan and analyse websites
- PublicWWW -  Marketing and affiliate marketing research
- CRT sh - Search for certs that have been logged by CT
- Pulsedive - Search for threat intelligence
- Dehashed - Search for anything like username, email, passwords, address, or phone number
- Have I Been Pwned? - Check whether personal data has been compromised by data breaches
- Snusbase - Indexes information from hacked websites and leaked databases
- LeakBase - Forum of leaked databases
- LeakCheck - Data breach search engine
- GhostProject.fr - Smart search engine
- SecurityTrails - Extensive DNS data
- DorkSearch - Really fast Google dorking
- PolySwarm - Scan files and URLs for threats
- DNSDumpster - Search for DNS records quickly
- AlienVault - Extensive threat intelligence feed
- Vulners - Search vulnerabilities in a large database
- WayBackMachine - View content from deleted websites
### Internet-Connected Devices / Attack Surfaces
- GreyNoise - Search for devices connected to the internet
- Censys - Assessing attack surface for internet connected devices
- Hunter - Search for email addresses belonging to a website
- Shodan - Search for devices connected to the internet
- IntelligenceX - Search Tor, I2P, data leaks, domains, and emails
- Netlas - Search and monitor internet connected assets
- FullHunt - Search and discovery attack surfaces
- GrayHatWarefare - Search public S3 buckets
- LeakWatch - Scans the Internet to detect exposed information
- FullHunt - Search and discovery attack surfaces
- [https://ipspy.net/](https://ipspy.net/) - IP Lookup, WHOIS, and DNS resolver
- [GeoTag](https://vsudo.net/tools/geotag) — Discover location of pictures
- [Sarenka](https://hakin9.org/sarenka-an-osint-tool-that-gets-data-from-services-like-shodan-censys-etc-in-one-app/) — Gathers data from Shodan, censys, etc.
- [Pushpin](https://github.com/DakotaNelson/pushpin-web) — Provides a web interface to keep track of geotagged social media activity
- [Awesome Hacker Search Engines](https://github.com/edoardottt/awesome-hacker-search-engines) — CVEs, Domains, Addresses, Certifications, Credentials, etc.
- [exitLooter](https://github.com/aydinnyunus/exifLooter) - Find geolocation on image URL and directories
- [FavFreak](https://github.com/devanshbatham/FavFreak) -  Fetches the favicon.ico and hash value and generates shodan dorks

<br>
<hr>

# Phishing for Information #
**Phishing for information** is an attempt to trick targets into divulging information, frequently credentials or other actionable information. All forms of phishing are electronically delivered social engineering. Adversaries may also try to obtain information directly through the exchange of emails, instant messages, or other electronic conversation means.

## Spearphishing Service ##
**Spearphishing for information** is an attempt to trick targets into divulging information, frequently credentials or other actionable information. Spearphishing for information frequently involves social engineering techniques, such as posing as a source with a reason to collect information (ex: Establish Accounts or Compromise Accounts) and/or sending multiple, seemingly urgent messages.

Adversaries send messages through various social media services, personal webmail, and other non-enterprise controlled services. Adversaries may create fake social media accounts and message employees for potential job opportunities. Doing so allows a plausible reason for asking about services, policies, and information about their environment. 

<br>

## Spearphishing Attachment ##
Adversaries may send spearphishing messages with a malicious attachment to elicit sensitive information that can be used during targeting. The text of the spearphishing email usually tries to give a plausible reason why the file should be filled-in, such as a request for information from a business associate.

<br>

## Spearphishing Link ##
Adversaries may send spearphishing messages with a malicious link to elicit sensitive information that can be used during targeting. The malicious emails contain links generally accompanied by social engineering text to coax the user to actively click or copy and paste a URL into a browser. The given website may closely resemble a legitimate site in appearance and have a URL containing elements from the real site. From the fake website, information is gathered in web forms and sent to the adversary. 

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

# Searching Open Technical Databases #
Adversaries may search freely available technical databases for information about victims that can be used during targeting. Information about victims may be available in online databases and repositories, such as registrations of domains/certificates as well as public collections of network data/artifacts gathered from traffic and/or scans. Adversaries may search in different open databases depending on what information they seek to gather. 

<br>

## DNS / Passive DNS ##
DNS information may include a variety of details, including registered name servers as well as records that outline addressing for a target’s subdomains, mail servers, and other hosts. Threat actors can query nameservers for a target organization directly, or search through centralized repositories of logged DNS query responses (known as passive DNS). Adversaries may also seek and target DNS misconfigurations/leaks that reveal information about internal networks. 

<br>

## WHOIS ##

WHOIS data is stored by regional Internet registries (RIR) responsible for allocating and assigning Internet resources such as domain names. Anyone can query WHOIS servers for information about a registered domain, such as assigned IP blocks, contact information, and DNS nameservers. Adversaries may search WHOIS data to gather actionable information. Threat actors can use online resources or command-line utilities to pillage through WHOIS data for information about potential victims.

<br>

## Digital Certificates ##
Digital certificates are issued by a certificate authority (CA) in order to cryptographically verify the origin of signed content. These certificates, such as those used for encrypted web traffic contain information about the registered organization such as name and location

Adversaries may search digital certificate data to gather actionable information. Threat actors can use online resources and lookup tools to harvest information about certificates
* Digital certificate data may also be available from artifacts signed by the organization (ex: certificates used from encrypted web traffic are served with content). 

<br>

## CDNs ##
CDNs allow an organization to host content from a distributed, load balanced array of servers. CDNs may also allow organizations to customize content delivery based on the requestor’s geographical region.

Adversaries may search CDN data to gather actionable information. Threat actors can use online resources and lookup tools to harvest information about content servers within a CDN. Adversaries may also seek and target CDN misconfigurations that leak sensitive information not intended to be hosted and/or do not have the same protection mechanisms (ex: login portals) as the content hosted on the organization’s website.

<br>

## Scan Databases ##
Various online services continuously publish the results of Internet scans/surveys, often harvesting information such as active IP addresses, hostnames, open ports, certificates, and even server banners

Adversaries may search scan databases to gather actionable information. Threat actors can use online resources and lookup tools to harvest information from these services. Adversaries may seek information about their already identified targets, or use these datasets to discover opportunities for successful breaches.

## Open Database Enumeration Tools
### Threat Intelligence / Search Engines
- Wigle - Database of wireless networks, with statistics
- Binary Edge - Scans the internet for threat intelligence
- ONYPHE - Collects cyber-threat intelligence data
- Fofa - Search for various threat intelligence
- ZoomEye - Gather information about targets
- LeakIX - Search publicly indexed information
- URL Scan - Free service to scan and analyse websites
- PublicWWW -  Marketing and affiliate marketing research
- Pulsedive - Search for threat intelligence
- Dehashed - Search for anything like username, email, passwords, address, or phone number
- Have I Been Pwned? - Check whether personal data has been compromised by data breaches
- Snusbase - Indexes information from hacked websites and leaked databases
- LeakBase - Forum of leaked databases
- LeakCheck - Data breach search engine
- GhostProject.fr - Smart search engine
- SecurityTrails - Extensive DNS data
- DorkSearch - Really fast Google dorking
- PolySwarm - Scan files and URLs for threats
- DNSDumpster - Search for DNS records quickly
- AlienVault - Extensive threat intelligence feed
- Vulners - Search vulnerabilities in a large database
- WayBackMachine - View content from deleted websites

#### Dorking
- [Catana-DS](https://github.com/TebbaaX/Katana) — Automates Google Dorking
### Internet-Connected Devices / Attack Surfaces
- GreyNoise - Search for devices connected to the internet
- Censys - Assessing attack surface for internet connected devices
- Hunter - Search for email addresses belonging to a website
- Shodan - Search for devices connected to the internet
- IntelligenceX - Search Tor, I2P, data leaks, domains, and emails
- Netlas - Search and monitor internet connected assets
- FullHunt - Search and discovery attack surfaces
- GrayHatWarefare - Search public S3 buckets
- LeakWatch - Scans the Internet to detect exposed information
- FullHunt - Search and discovery attack surfaces
- [https://ipspy.net/](https://ipspy.net/) - IP Lookup, WHOIS, and DNS resolver
- [GeoTag](https://vsudo.net/tools/geotag) — Discover location of pictures
- [Sarenka](https://hakin9.org/sarenka-an-osint-tool-that-gets-data-from-services-like-shodan-censys-etc-in-one-app/) — Gathers data from Shodan, censys, etc.
- [Pushpin](https://github.com/DakotaNelson/pushpin-web) — Provides a web interface to keep track of geotagged social media activity
- [Awesome Hacker Search Engines](https://github.com/edoardottt/awesome-hacker-search-engines) — CVEs, Domains, Addresses, Certifications, Credentials, etc.
- [exitLooter](https://github.com/aydinnyunus/exifLooter) - Find geolocation on image URL and directories
- [FavFreak](https://github.com/devanshbatham/FavFreak) -  Fetches the favicon.ico and hash value and generates shodan dorks
- [Dorksearch](https://dorksearch.com/) — Faster Google Dorking
- [GitHub Dork Helper](https://vsec7.github.io/)

### Domain / DNS / WHOIS
- [GooFuzz](https://github.com/m3n0sd0n4ld/GooFuzz) — Perform fuzzing with an OSINT approach, managing to enumerate directories, files, subdomains or parameters without leaving evidence on the target's server and by means of advanced Google searches
- [https://ipspy.net/](https://ipspy.net/) - IP Lookup, WHOIS, and DNS resolver
- [link-JS](https://github.com/ethicalhackingplayground/linkJS) — Fetch links from JS w/ Subfinder
- [Investigator](https://abhijithb200.github.io/investigator/) — Quickly check & gather information about the target domain name
- [Domain Investigation Toolbox](https://cipher387.github.io/domain_investigation_toolbox/) — Gather information about the target domain name
- [IQ WHOIS](https://iqwhois.com/advanced-search) — Advanced WHOIS Search
- [Backlink Discovery](https://app.neilpatel.com/en/seo_analyzer/backlinks) — Find backlinks, Referring domains, Link history, etc.
- [WhoisFreaks](https://whoisfreaks.com/) — WHOIS Discovery
- [WhereGoes](https://wheregoes.com/) — URL Redirect Checker
- [Grey Noise](https://www.greynoise.io/) — Trace IPs, URLs, etc.
- [Sarenka](https://hakin9.org/sarenka-an-osint-tool-that-gets-data-from-services-like-shodan-censys-etc-in-one-app/) — Gathers data from Shodan, censys, etc.
- [HaxUnit](https://github.com/Bandit-HaxUnit/haxunit) — Combines multiple active/passive subdomain enumeration tools and port scanning
- [Phonebook](https://phonebook.cz/) — Lists all domains, email addresses, URL for the target domain 
- [js-parse](https://github.com/l4yton/js-parse) — Looks through javascript files in a given directory and finds subdomains, URLs, parameters, custom headers, and API keys
- [dnsenum](https://github.com/fwaeytens/dnsenum) — Script that enumerates DNS information
- [PowerMeta](https://github.com/dafthack/PowerMeta) — Searches for publicly available files hosted on webpages for a particular domain
- [DNSrr](https://github.com/A3h1nt/Dnsrr) — Enumerate all information from DNS records
- [Awesome Hacker Search Engines](https://github.com/edoardottt/awesome-hacker-search-engines) — CVEs, Domains, Addresses, Certifications, Credentials, etc.
- [Astra](https://github.com/Sachin-v3rma/Astra) — Finds API keys, URLs, AWS Buckets, etc.
- [assetfinder](https://github.com/tomnomnom/assetfinder): Find domains and subdomains potentially related to a given domain



### Digital Certificates
- CRT sh - Search for certs that have been logged by CT

<br>
<hr>

# Searching Open Websites / Domains 
Information about victims may be available in various online sites, such as social media, new sites, or those hosting information about business operations such as hiring or requested/rewarded contracts. Adversaries may search in different online sites depending on what information they seek to gather.

<br>

## Social Media ##
Social media sites may contain various information about a victim organization, such as business announcements as well as information about the roles, locations, and interests of staff.

Adversaries may search in different social media sites depending on what information they seek to gather. Threat actors may passively harvest data from these sites, as well as use information gathered to create fake profiles/groups to elicit victim’s into revealing specific information

<br>

## Search Engines ##
Search engine services typical crawl online sites to index context and may provide users with specialized syntax to search for specific keywords or specific types of content

Adversaries may craft various search engine queries depending on what information they seek to gather. Threat actors may use search engines to harvest general information about victims, as well as use specialized queries to look for spillages/leaks of sensitive information such as network details or credentials.

## Open Website / Domain Enumeration Tools
### Domain / DNS / WHOIS
- [GooFuzz](https://github.com/m3n0sd0n4ld/GooFuzz) — Perform fuzzing with an OSINT approach, managing to enumerate directories, files, subdomains or parameters without leaving evidence on the target's server and by means of advanced Google searches
- [https://ipspy.net/](https://ipspy.net/) - IP Lookup, WHOIS, and DNS resolver
- [link-JS](https://github.com/ethicalhackingplayground/linkJS) — Fetch links from JS w/ Subfinder
- [Investigator](https://abhijithb200.github.io/investigator/) — Quickly check & gather information about the target domain name
- [Domain Investigation Toolbox](https://cipher387.github.io/domain_investigation_toolbox/) — Gather information about the target domain name
- [IQ WHOIS](https://iqwhois.com/advanced-search) — Advanced WHOIS Search
- [Backlink Discovery](https://app.neilpatel.com/en/seo_analyzer/backlinks) — Find backlinks, Referring domains, Link history, etc.
- [WhoisFreaks](https://whoisfreaks.com/) — WHOIS Discovery
- [WhereGoes](https://wheregoes.com/) — URL Redirect Checker
- [Grey Noise](https://www.greynoise.io/) — Trace IPs, URLs, etc.
- [Sarenka](https://hakin9.org/sarenka-an-osint-tool-that-gets-data-from-services-like-shodan-censys-etc-in-one-app/) — Gathers data from Shodan, censys, etc.
- [HaxUnit](https://github.com/Bandit-HaxUnit/haxunit) — Combines multiple active/passive subdomain enumeration tools and port scanning
- [Phonebook](https://phonebook.cz/) — Lists all domains, email addresses, URL for the target domain 
- [js-parse](https://github.com/l4yton/js-parse) — Looks through javascript files in a given directory and finds subdomains, URLs, parameters, custom headers, and API keys
- [dnsenum](https://github.com/fwaeytens/dnsenum) — Script that enumerates DNS information
- [PowerMeta](https://github.com/dafthack/PowerMeta) — Searches for publicly available files hosted on webpages for a particular domain
- [DNSrr](https://github.com/A3h1nt/Dnsrr) — Enumerate all information from DNS records
- [Awesome Hacker Search Engines](https://github.com/edoardottt/awesome-hacker-search-engines) — CVEs, Domains, Addresses, Certifications, Credentials, etc.
- [Astra](https://github.com/Sachin-v3rma/Astra) — Finds API keys, URLs, AWS Buckets, etc.
- [assetfinder](https://github.com/tomnomnom/assetfinder): Find domains and subdomains potentially related to a given domain
- IntelligenceX - Search Tor, I2P, data leaks, domains, and emails
- [IpSpy](https://ipspy.net/) - IP Lookup, WHOIS, and DNS resolver
- [Sarenka](https://hakin9.org/sarenka-an-osint-tool-that-gets-data-from-services-like-shodan-censys-etc-in-one-app/) — Gathers data from Shodan, censys, etc.

<br>
<hr>

# Searching Victim-Owned Websites #
Victim-owned websites may contain a variety of details, including names of departments/divisions, physical locations, and data about key employees such as names, roles, and contact info. These sites may also have details highlighting business operations and relationships. Adversaries may search victim-owned websites to gather actionable information.thats 

## Vitcm-Owned Enumeration Tools
### Domain / DNS / WHOIS
- [GooFuzz](https://github.com/m3n0sd0n4ld/GooFuzz) — Perform fuzzing with an OSINT approach, managing to enumerate directories, files, subdomains or parameters without leaving evidence on the target's server and by means of advanced Google searches
- [https://ipspy.net/](https://ipspy.net/) - IP Lookup, WHOIS, and DNS resolver
- [link-JS](https://github.com/ethicalhackingplayground/linkJS) — Fetch links from JS w/ Subfinder
- [Investigator](https://abhijithb200.github.io/investigator/) — Quickly check & gather information about the target domain name
- [Domain Investigation Toolbox](https://cipher387.github.io/domain_investigation_toolbox/) — Gather information about the target domain name
- [IQ WHOIS](https://iqwhois.com/advanced-search) — Advanced WHOIS Search
- [Backlink Discovery](https://app.neilpatel.com/en/seo_analyzer/backlinks) — Find backlinks, Referring domains, Link history, etc.
- [WhoisFreaks](https://whoisfreaks.com/) — WHOIS Discovery
- [WhereGoes](https://wheregoes.com/) — URL Redirect Checker
- [Grey Noise](https://www.greynoise.io/) — Trace IPs, URLs, etc.
- [Sarenka](https://hakin9.org/sarenka-an-osint-tool-that-gets-data-from-services-like-shodan-censys-etc-in-one-app/) — Gathers data from Shodan, censys, etc.
- [HaxUnit](https://github.com/Bandit-HaxUnit/haxunit) — Combines multiple active/passive subdomain enumeration tools and port scanning
- [Phonebook](https://phonebook.cz/) — Lists all domains, email addresses, URL for the target domain 
- [js-parse](https://github.com/l4yton/js-parse) — Looks through javascript files in a given directory and finds subdomains, URLs, parameters, custom headers, and API keys
- [dnsenum](https://github.com/fwaeytens/dnsenum) — Script that enumerates DNS information
- [PowerMeta](https://github.com/dafthack/PowerMeta) — Searches for publicly available files hosted on webpages for a particular domain
- [DNSrr](https://github.com/A3h1nt/Dnsrr) — Enumerate all information from DNS records
- [Awesome Hacker Search Engines](https://github.com/edoardottt/awesome-hacker-search-engines) — CVEs, Domains, Addresses, Certifications, Credentials, etc.
- [Astra](https://github.com/Sachin-v3rma/Astra) — Finds API keys, URLs, AWS Buckets, etc.
- [assetfinder](https://github.com/tomnomnom/assetfinder): Find domains and subdomains potentially related to a given domain
- IntelligenceX - Search Tor, I2P, data leaks, domains, and emails
- [IpSpy](https://ipspy.net/) - IP Lookup, WHOIS, and DNS resolver
- [Sarenka](https://hakin9.org/sarenka-an-osint-tool-that-gets-data-from-services-like-shodan-censys-etc-in-one-app/) — Gathers data from Shodan, censys, etc.

<br>
<hr>

# Searching Closed Sources #

Adversaries may search and gather information about victims from closed sources that can be used during targeting. Information about victims may be available for purchase from reputable private sources and databases, such as paid subscriptions to feeds of technical/threat intelligence data. Adversaries may also purchase information from less-reputable sources such as dark web or cybercrime blackmarkets. Adversaries may search in different closed databases depending on what information they seek to gather. 

<br>

## Threat Intelligence Vendors ##
Adversaries may search private data from threat intelligence vendors for information that can be used during targeting. Threat intelligence vendors may offer paid feeds or portals that offer more data than what is publicly reported. Although sensitive details (such as customer names and other identifiers) may be redacted, this information may contain trends regarding breaches such as target industries, attribution claims, and successful TTPs/countermeasures.

Adversaries may search in private threat intelligence vendor data to gather actionable information. Threat actors may seek information/indicators gathered about their own campaigns, as well as those conducted by other adversaries that may align with their target industries, capabilities/objectives, or other operational concerns.

<br>

## Purchase Technical Data ##
Adversaries may purchase technical information about victims that can be used during targeting. Information about victims may be available for purchase within reputable private sources and databases, such as paid subscriptions to feeds of scan databases or other data aggregation services. Adversaries may also purchase information from less-reputable sources such as dark web or cybercrime blackmarkets.

Adversaries may purchase information about their already identified targets, or use purchased data to discover opportunities for successful breaches. Threat actors may gather various technical details from purchased data, including but not limited to employee contact information, credentials, or specifics regarding a victim’s infrastructure

## Threat Intelligence Solutions
- Wigle - Database of wireless networks, with statistics
- Binary Edge - Scans the internet for threat intelligence
- ONYPHE - Collects cyber-threat intelligence data
- Fofa - Search for various threat intelligence
- ZoomEye - Gather information about targets
- LeakIX - Search publicly indexed information
- URL Scan - Free service to scan and analyse websites
- PublicWWW -  Marketing and affiliate marketing research
- CRT sh - Search for certs that have been logged by CT
- Pulsedive - Search for threat intelligence
- Dehashed - Search for anything like username, email, passwords, address, or phone number
- Have I Been Pwned? - Check whether personal data has been compromised by data breaches
- Snusbase - Indexes information from hacked websites and leaked databases
- LeakBase - Forum of leaked databases
- LeakCheck - Data breach search engine
- GhostProject.fr - Smart search engine
- SecurityTrails - Extensive DNS data
- DorkSearch - Really fast Google dorking
- PolySwarm - Scan files and URLs for threats
- AlienVault - Extensive threat intelligence feed
- Vulners - Search vulnerabilities in a large database
- WayBackMachine - View content from deleted websites
