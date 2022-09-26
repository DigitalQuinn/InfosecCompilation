# blAck0ps
**blAck0ps** is a repository designed for advanced penetration testing tactics, techniques, and procedures (TTPs) based on the MITRE framework


<br>
<hr>

# A Hacker's Methodology / å ˙å˚´®…ß µ´†˙ø∂ø¬ø©¥

<br>

* **Reconnaissance:** Gathering information that can be used to support targeting
  * Details of the victim organization, infrastructure, or staff/personnel
* **Resource Development:** Creating, purchasing, or compromising/stealing resources that can be used to support targeting
  * Infrastructure, accounts, or capabilities
* **Initial Access:** Various entry vectors to gain your initial foothold within a network
  * Targeted spearphishing and exploiting weaknesses on public-facing web servers
* **Execution:** Attacker-controlled code running on a local or remote system
  * Techniques that run malicious code are often paired with techniques from all other tactics to achieve broader goals, like exploring a network or stealing data
* **Persistence:** Maintaining access to systems across restarts, changed credentials, and other interruptions that could cut off adverdary's access
  * Aaccess, action, or configuration changes that allow attackers to maintain your
   foothold on systems
* **Privilege Escalation:** Gaining higher-level permissions on a system or network
* **Defense Evasion:** Avoiding detection throughout your compromise
  * Uninstalling/disabling security software or obfuscating/encrypting data and scripts, leverage and abuse trusted processes to hide and masquerade your malware
* **Credential Access:** Stealing credentials like account names and passwords
  * Legitimate credentials can give adversaries access to systems, make them harder to detect, and provide the opportunity to create more accounts to help achieve your goals
* **Discovery:** Observing what they can control and what’s around your entry point in order to discover how it could benefit your current objective
* **Lateral Movement:** Pivoting through multiple systems and accounts to gain additional access
* **Collection:** Gathering information relevant to following through on the adversary's objectives
  * Frequently, the next goal after collecting data is to exfiltrate the data
* **Command & Control (C2):** Communicating with systems under your control within a victim network
  * Adversaries commonly attempt to mimic normal, expected traffic to avoid detection
* **Exfiltration:** Stealing data from victim's infrastructure
  * Techniques for getting data out of a target network typically include transferring it over your C2 channel or an alternate channel and may also include putting size limits on the transmission
* **Impact:** Disrupting availability, compromising integrity by manipulating business and operational processes






# Homelab

## Repository

- [Blue Team Homelab](https://github.com/aboutsecurity/blueteam_homelabs) — Blue Team Environment
- [SecGen](https://github.com/cliffe/SecGen) — Creates vulnerable VMs, Lab Environments, & Hacking challenges
- [DetectionLab](https://github.com/clong/DetectionLab)

### **Sandbox**

- [Cuckoo](https://cuckoosandbox.org/)
- [DRAKVUF Sandbox](https://github.com/CERT-Polska/drakvuf-sandbox/)
- [PacketTotal](https://packettotal.com/) — Online PCAP Analysis Engine
- [Joe Sandbox Cloud](https://www.joesandbox.com/#windows)
- [CAPE](https://github.com/kevoreilly/CAPEv2/)

### **NAC**

- [Packet Fence](https://www.packetfence.org/) — Open source NAC

### **Vulnerable Images**

- [Exploit Education](https://exploit.education)
- [Docker Images](https://houdini.secsi.io/)
- [https://crackmes.one/](https://crackmes.one/) — Reverse Engineering

### **Malware**

- [VX-Underground](https://github.com/vxunderground/MalwareSourceCode) — Malware source code
- Malware Samples
    - [VX-Underground’s Samples](https://samples.vx-underground.org/samples/Families/)
    - [VXUnderground](https://github.com/vxunderground/MalwareSourceCode)
    - [Zeltser Resources](https://zeltser.com/malware-sample-sources/)
        - [ANY.RUN](https://app.any.run/submissions)
        - [Contagio Malware Dump](http://contagiodump.blogspot.com/)
        - [CAPE Sandbox](https://capesandbox.com/)
        - [Das Malwerk](http://dasmalwerk.eu/)
        - [Hatching Triage](https://tria.ge/)
        - [Hybrid Analysis](https://www.hybrid-analysis.com/)
        - [InQuest Labs](https://labs.inquest.net/)
        - [InQuest Malware Samples](https://github.com/InQuest/malware-samples)
        - [KernelMode.info](http://www.kernelmode.info/forum/viewforum.php?f=16)
        - [MalShare](http://malshare.com/)
        - [MalwareBazaar](https://bazaar.abuse.ch/browse/)
        - [MalwareSamples Malware-Feed](https://github.com/MalwareSamples/Malware-Feed/)
        - [Malware DB](http://ytisf.github.io/theZoo/)
        - [Objective-See Collection](https://objective-see.com/malware.html)
        - [PacketTotal](https://packettotal.com/malware-archive.html)
        - [PhishingKitTracker](https://github.com/marcoramilli/PhishingKitTracker)
        - [PolySwarm](https://polyswarm.network/)
        - [SNDBOX](https://app.sndbox.com/)
        - [SoReL-20M](https://github.com/sophos-ai/SOREL-20M)
        - [URLhaus](https://urlhaus.abuse.ch/browse/)
        - [VirusBay](https://beta.virusbay.io/)
        - [VirusShare](https://virusshare.com/)
        - [VirusSign](https://www.virussign.com/downloads.html)
        - [Virus and Malware Samples](https://www.virussamples.com/)
        - [Yomi](https://yomi.yoroi.company/)
    - [theZoo](https://github.com/ytisf/theZoo)
- Guides
    - [https://c3rb3ru5d3d53c.github.io/docs/malware-analysis-beginner-guide/](https://c3rb3ru5d3d53c.github.io/docs/malware-analysis-beginner-guide/)
- Malware Analysis Homelab Setup
    - [KVM Malware Lab](https://c3rb3ru5d3d53c.github.io/docs/kvm-malware-lab/)

### **EDR**

- [Intezer Protect](https://www.intezer.com/intezer-protect/) — EDR built for your cloud

### **SIEM**

- [https://wazuh.com](https://wazuh.com/)

## **Github Repositories (Need to Look Through)**

- [Ethical Hacking Playground (Repo)](https://github.com/ethicalhackingplayground?tab=repositories)
- [Saeid](https://github.com/saeidshirazi?tab=repositories)
- [ustayready](https://github.com/ustayready?tab=repositories)
- [infosecn1nja](https://github.com/infosecn1nja?tab=repositories)
- [https://github.com/13o-bbr-bbq/machine_learning_security/wiki](https://github.com/13o-bbr-bbq/machine_learning_security/wiki)

## Penetration Testing

**Methodology:** The steps taken during a penetration auditing, should consist of the follwing:

[**Planning:** Assessment goals are defined](https://www.notion.so/Planning-Assessment-goals-are-defined-910ef0108d2a41eaa7c2e9babd58a679)

[**Information Gathering:** Collect publicly-accessible information about the target](https://www.notion.so/Information-Gathering-Collect-publicly-accessible-information-about-the-target-d0f42d551cbe4c28aab7a20c3b2c46a6)

[**Enumeration / Scanning:** Discovering applications and services running on target systems](https://www.notion.so/Enumeration-Scanning-Discovering-applications-and-services-running-on-target-systems-1c46c36cd05b4df0b2103852f4d6493f)

[**Exploitation:** Leveraging vulnerabilities discovered on a system or application](https://www.notion.so/Exploitation-Leveraging-vulnerabilities-discovered-on-a-system-or-application-37376e5a2fe84640a7f1378b51069619)

[**Privilege Escalation:** Attempt to expand your access to a system to another account or to an admin level](https://www.notion.so/Privilege-Escalation-Attempt-to-expand-your-access-to-a-system-to-another-account-or-to-an-admin-le-7b31f435c5b142f4a8959f9bf747aebb)

[**Post-Exploitation:** Discover what hosts can be targeted, What additional information can be gathered from hosts, Covering your tracks, and Reporting](https://www.notion.so/Post-Exploitation-Discover-what-hosts-can-be-targeted-What-additional-information-can-be-gathered--d4c65921c77c466cb415aa6c1dd6951f)

- https://github.com/CyberSecurityUP/PenTest-Consulting-Creator

## **Tools**

### **OSINT**

- OSINT Framework
    - [ReconSpider](https://hakin9.org/reconspider-most-advanced-open-source-intelligence-osint-framework/)
- Search Engines
    - Shodan: Search for devices connected to the internet
    - Wigle: Database of wireless networks, with statistics
    - Grep App: Search across a half million git repos
    - Binary Edge: Scans the internet for threat intelligence
    - ONYPHE: Collects cyber-threat intelligence data
    - GreyNoise: Search for devices connected to the internet
    - Censys: Assessing attack surface for internet connected devices
    - Hunter: Search for email addresses belonging to a website
    - Fofa: Search for various threat intelligence
    - ZoomEye: Gather information about targets
    - LeakIX: Search publicly indexed information
    - IntelligenceX: Search Tor, I2P, data leaks, domains, and emails
    - Netlas: Search and monitor internet connected assets
    - URL Scan: Free service to scan and analyse websites
    - PublicWWW: Marketing and affiliate marketing research
    - FullHunt: Search and discovery attack surfaces
    - CRT sh: Search for certs that have been logged by CT
    - Vulners: Search vulnerabilities in a large database
    - Pulsedive: Search for threat intelligence
    - Packet Storm Security: Browse latest vulnerabilities and exploits
    - GrayHatWarefare: Search public S3 buckets
    - Dehashed: search for anything like username, email, passwords, address, or phone number.
    - Have I Been Pwned?
    - Snusbase
    - LeakBase
    - LeakWatch
    - Leaksify
    - We Leak Info
    - GhostProject.fr
    - Nuclear Leaks
    - SecurityTrails: Extensive DNS data
    - DorkSearch: Really fast Google dorking
    - ExploitDB: Archive of various exploits
    - PolySwarm: Scan files and URLs for threats
    - DNSDumpster: Search for DNS records quickly
    - FullHunt: Search and discovery attack surfaces
    - AlienVault: Extensive threat intelligence feed
    - Vulners: Search vulnerabilities in a large database
    - WayBackMachine: View content from deleted websites
    - SearchCode: Search 75 billion lines of code from 40 million projects
- [Catana-DS](https://github.com/TebbaaX/Katana) — Automates Google Dorking
- [Mitaka](https://hakin9.org/mitaka-a-browser-extension-for-osint/) — Browser extension for OSINT
- [https://infosecwriteups.com/osint-and-top-15-open-source-intelligence-tools-f5132bf9e40f](https://infosecwriteups.com/osint-and-top-15-open-source-intelligence-tools-f5132bf9e40f)
- [GooFuzz](https://github.com/m3n0sd0n4ld/GooFuzz) — tool to perform fuzzing with an OSINT approach, managing to enumerate directories, files, subdomains or parameters without leaving evidence on the target's server and by means of advanced Google searches
- [https://ipspy.net/](https://ipspy.net/)
- ‣
- [Fuxploiter](https://hakin9.org/fuxploider-a-file-upload-vulnerability-scanner/) — Detecting and exploiting file upload forms flaws
- [link-JS](https://github.com/ethicalhackingplayground/linkJS) — Fetch links from JS w/ Subfinder
- [LinPeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) — Linux Privilege Escalation
- [LinEnum](https://github.com/rebootuser/LinEnum) — Linux Enumeration
- [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester) — Assist in detecting security deficiencies for given Linux kernel/Linux-based machine
- [Linux Smart Enumeration](https://github.com/diego-treitos/linux-smart-enumeration) — Shows relevant information about the security of the local Linux system, helping to escalate privileges, etc.
- [Linux Priv Checker](https://github.com/linted/linuxprivchecker) — Enumerate basic system info and search for common privilege escalation vectors
- [Investigator](https://abhijithb200.github.io/investigator/) — Quickly check & gather information about the target domain name
- [Dorksearch](https://dorksearch.com/) — Faster Google Dorking
- [Domain Investigation Toolbox](https://cipher387.github.io/domain_investigation_toolbox/) — Gather information about the target domain name
- [GitHub Dork Helper](https://vsec7.github.io/)
- [IP Neighboring](https://www.ip-neighbors.com/) — Discover Neighboring IP Hosts
- [IQ WHOIS](https://iqwhois.com/advanced-search) — Advanced WHOIS Search
- [Backlink Discovery](https://app.neilpatel.com/en/seo_analyzer/backlinks) — Find backlinks, Referring domains, Link history, etc.
- [WhoisFreaks](https://whoisfreaks.com/) — WHOIS Discovery
- [Clickjacker](https://serene-agnesi-57a014.netlify.app/) — Discover secret API Keys
- [GeoTag](https://vsudo.net/tools/geotag) — Discover location of pictures
- [WhereGoes](https://wheregoes.com/) — URL Redirect Checker
- [CookieServe](https://www.cookieserve.com/) — Cookie Checker Tool for Websites
- [Grey Noise](https://www.greynoise.io/) — Trace IPs, URLs, etc.
- [Sherloq](https://github.com/GuidoBartoli/sherloq) — Open source forensic image analysis
- [reconFTW](https://github.com/six2dez/reconftw) — Automates the entire reconnaisance process
- [Sarenka](https://hakin9.org/sarenka-an-osint-tool-that-gets-data-from-services-like-shodan-censys-etc-in-one-app/) — Gathers data from Shodan, censys, etc.
- [HaxUnit](https://github.com/Bandit-HaxUnit/haxunit) — Combines multiple active/passive subdomain enumeration tools and port scanning
- [Phonebook](https://phonebook.cz/) — Lists all domains, email addresses, URL for the target domain
- [js-parse](https://github.com/l4yton/js-parse) — Looks through javascript files in a given directory and finds subdomains, URLs, parameters, custom headers, and API keys
- [dnsenum](https://github.com/fwaeytens/dnsenum) — Script that enumerates DNS information
- [scanless](https://github.com/vesche/scanless) — Websites that performs port scans on your behalf
- [PowerMeta](https://github.com/dafthack/PowerMeta) — Searches for publicly available files hosted on webpages for a particular domain
- [DNSrr](https://github.com/A3h1nt/Dnsrr) — Enumerate all information from DNS records
- [Pushpin](https://github.com/DakotaNelson/pushpin-web) — Provides a web interface to keep track of geotagged social media activity
- Octosuite — Gather OSINT on GitHub users
- [Awesome Hacker Search Engines](https://github.com/edoardottt/awesome-hacker-search-engines) — CVEs, Domains, Addresses, Certifications, Credentials, etc.
- [Astra](https://github.com/Sachin-v3rma/Astra) — Finds API keys, URLs, AWS Buckets, etc.
- [assetfinder](https://github.com/tomnomnom/assetfinder): Find domains and subdomains potentially related to a given domain
- [securityheader.com](http://securityheader.com) — Reports headers that are missing; Exploitable
- [breach-parse](https://github.com/hmaverickadams/breach-parse): Tool for parsing breached passwords
    - `./breach-parse.sh @tesla.com tesla.txt`
- [LOTS Project](https://lots-project.com/) — Websites that allows attackers to use their domain when conducting phishing, C2, exfiltration, and downloading tools to evade detection
- [OSINT Repository](https://cipher387.github.io/osint_stuff_tool_collection/)
- [DarkSide](https://hakin9.org/darkside-tool-information-gathering-social-engineering/) — OSINT & Social Engineering Tool
- [SocialHunter](https://hakin9.org/socialhunter-crawls-the-website-and-finds-broken-social-media-links-that-can-be-hijacked/) — Crawls the website and finds broken social media links that can be hijacked
- [IntelTechniques](https://inteltechniques.com/tools/index.html) — Resources hosted by IntelTechniques Podcast
- [exitLooter](https://github.com/aydinnyunus/exifLooter): Find geolocation on image URL and directories
- [AutoRecon](https://github.com/Tib3rius/AutoRecon): AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services. It is intended as a time-saving tool for use in CTFs and other penetration testing environments
- [https://infosecwriteups.com/cool-recon-techniques-every-hacker-misses-1c5e0e294e89](https://infosecwriteups.com/cool-recon-techniques-every-hacker-misses-1c5e0e294e89)
- [mip22](https://github.com/makdosx/mip22): Advanced phishing tool
- [Recon Cloud](https://recon.cloud/): Cloud asset scanner

### **Defense**

- [DarkTrace](https://www.darktrace.com/en/): Cyber AI detection
- [Active Countermeasures](https://www.activecountermeasures.com/free-tools/): Open source tools for countermeasure
- [The CredDefense Toolkit](https://github.com/CredDefense/CredDefense): Detect & Prevent Credential ABuse Attacks
- [DNS Blacklist](https://bitbucket.org/ethanr/dns-blacklists/src/master/): Detect Blacklisted IPs from your traffic
- [Spidertrap](https://bitbucket.org/ethanr/spidertrap/src/master/): Trap web crawlers and spiders in dynamically generated webpages
- [Live Forensicator](https://hakin9.org/live-forensicator-powershell-script-to-aid-incidence-response-and-live-forensics/): Powershell Script to aid Incidence Response and Live Forensics
- [https://threathunterplaybook.com/intro.html](https://threathunterplaybook.com/intro.html)

### **Offense**

- Penetration Testing Frameworks
    - [Metasploit](https://www.metasploit.com/)
    - [Cobalt Strike](https://www.cobaltstrike.com/) — Adversary simulations & red team operations
    - Brute Ratel
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
- Compilation of Tools
    - ‣
    - [Hacktricks](https://book.hacktricks.xyz/)
    - [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
    - [Pentest-Tools](https://github.com/S3cur3Th1sSh1t/Pentest-Tools) — Cyber repository
    - [EthHack](https://ethhack.com/category/security-tools/) — Repository security tool
    - [FSociety Hacking Tools](https://github.com/Manisso/fsociety) — Contains all the tools used in Mr. Robot series
    - [Red Team Resources](https://github.com/J0hnbX/RedTeam-Resources)
    - [Kitploit’s Popular Hacking Tools](https://www.kitploit.com/2021/12/top-20-most-popular-hacking-tools-in.html)
- IP Scanners
    - [Nmap](https://nmap.org/)
    - [AngryIP](https://angryip.org/)
    - [PRTG](https://www.paessler.com/tools)
    - [Pwndora](https://hakin9.org/pwndora-massive-ipv4-scanner-find-and-analyze-internet-connected-devices-in-minutes-create-your-own-iot-search-engine-at-home/) — Find Internet-connected devices
- Vulnerability Scan
    - Nessus
    - OpenVas
    - BurpSuite
    - **[Trend Micro Hybrid Cloud Security](https://www.g2.com/products/trend-micro-hybrid-cloud-security/reviews)**
    - Orca Security
    - InsightVM
    - Qualys
    - Application Vulnerability Scanning
        - Nikto
- Packet Injection
    - [Dsniff](https://monkey.org/~dugsong/dsniff/)
    - [Ettercap](https://www.ettercap-project.org/)
    - [Scapy](https://scapy.net/) — Packet manipulation program
    - [hping](http://hping.org/) — TCP/IP packet assembler/analyzer
- Password Attacks
    - [CredKing](https://github.com/ustayready/CredKing) — Launch Password Spraying using AWS Lamba across multiple regions, rotating IPs w/ each request
    - [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) — Perform password spraying against users in a domain
    
    [https://github.com/lkarlslund/ldapnomnom](https://github.com/lkarlslund/ldapnomnom)
    
- Phishing
    - [CredSniper](https://github.com/ustayready/CredSniper) — Launch phishing site
    - [PyPhisher](https://hakin9.org/pyphisher-easy-to-use-phishing-tool-with-65-website-templates/) — Phishing website templates
    - [Fake-SMS](https://www-hackers--arise-com.cdn.ampproject.org/c/s/www.hackers-arise.com/amp/social-engineering-attacks-creating-a-fake-sms-message) — Create SMS messages
- C2
    - [Tyk.io](https://shells.systems/oh-my-api-abusing-tyk-cloud-api-management-service-to-hide-your-malicious-c2-traffic/) — Route C2 traffic
- Cloud Testing
    - [AWS](https://github.com/RhinoSecurityLabs/pacu)
    - [GCP](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation)
    - [Azure](https://github.com/Azure/Stormspotter)
    - [Multi Cloud](https://github.com/nccgroup/ScoutSuite)
    - [Multi Cloud](https://github.com/aquasecurity/cloudsploit)
    - [https://rhinosecuritylabs.com/aws/cloud-container-attack-tool/](https://rhinosecuritylabs.com/aws/cloud-container-attack-tool/)
    - ‣
- Active Directory
    
    [𝐅𝐑𝐄𝐄 𝐑𝐄𝐒𝐎𝐔𝐑𝐂𝐄𝐒 - 𝐀𝐂𝐓𝐈𝐕𝐄 𝐃𝐈𝐑𝐄𝐂𝐓𝐎𝐑𝐘 𝐏𝐄𝐍𝐓𝐄𝐒𝐓]
    
    Whether you are preparing for a certification or need to sharpen your skills for your pentests.
    
    🤓Here is a list of resources 🤓:
    
    Need to practice?
    👉Set up and AD home lab with this blog post from spookysec: [https://lnkd.in/eN8V88kv](https://lnkd.in/eN8V88kv)
    👉You also have a script here to set up a Vulnerable AD lab by WazeHell
    [https://lnkd.in/evJZM_yv](https://lnkd.in/evJZM_yv)
    
    👉Here is a collection of various common attack scenarios on Azure Active Directory by Cloud-Architekt:
    [https://lnkd.in/eDb7JJAQ](https://lnkd.in/eDb7JJAQ)
    
    👉Julien Provenzano ☁  shared a great document full of resources here:
    [https://lnkd.in/ePgnhbUk](https://lnkd.in/ePgnhbUk)
    
    👉Finally here is an Active Directory Exploitation Cheat Sheet by Integration-IT
    [https://lnkd.in/eY2jD3nv](https://lnkd.in/eY2jD3nv)
    
    𝐒𝐇𝐀𝐑𝐄 - Do you know other resources? Please share them in the comment
    
    ➡️ 𝐅𝐎𝐋𝐋𝐎𝐖 𝐌𝐄 on github for more pentest tips: [https://github.com/CSbyGB](https://github.com/CSbyGB) ⬅️
    
- [Inceptor](https://github.com/klezVirus/inceptor) — Automate common AV/EDR bypasses
- [AutoScanWithBurp](https://bitbucket.org/clr2of8/autoscanwithburp/src/master/) — Extension to perform automated & authenticated scans against URLS
- [OAuthScan](https://github.com/PortSwigger/oauth-scan)
- ‣
- ‣
- ‣
- [GPU Poisoning](https://gitlab.com/ORCA000/gp) — Hide payload inside GPU memory
- [HostRecon](https://github.com/dafthack/HostRecon) — Provide situational awareness during reconnaissance of an engagement
- [MailSniper](https://github.com/dafthack/MailSniper) — Searches through email in a Microsoft Exchange environment for specific terms
- [fireELF](https://github.com/rek7/fireELF) — Inject fileless exploit payloads into a Linux host
- [RouterSploit](https://github.com/threat9/routersploit) — Vulnerability scanning and exploit modules targeting embedded systems
- https://github.com/JoelGMSec/EvilnoVNC
- https://github.com/Z4kSec/Masky
- [https://github.com/D1rkMtr/githubC2/tree/main](https://github.com/D1rkMtr/githubC2/tree/main)
- Notion
    - [Notion Term](https://github.com/ariary/notionterm) — Embed reverse shell in Notion pages
- Hash Database — Upload Hashes
    - [crackstation](https://crackstation.net/)
- [Red Teaming Toolkit](https://github.com/infosecn1nja/Red-Teaming-Toolkit#Payload%20Development): Open-source security tools (OST) that will help you during adversary simulation
- https://github.com/cepxeo/dll4shell
- ‣
- ‣

### **Malware**

- [Malware Analysis Tools](https://0x1.gitlab.io/security/Malware-Analysis-Tools-List/)
- [MalAPI](https://malapi.io/) — Catalog of Windows APIs commonly used in malware
- Wireless
    
    [https://youtu.be/f2BjFilLDqQ](https://youtu.be/f2BjFilLDqQ)
    

### **Auditing Tools**

- lansweeper: Asset inventory management — Scans network hosts and compiles an asset information database
- [Domain Password Audit Tool (DPAT)](https://github.com/clr2of8/DPAT) — Generate password statistics from hashes from a DC and a password crack file
- [Ping Castle](https://github.com/vletoux/pingcastle) — Assess the security level of the AD based on risk assessment and a maturity framework
- [Domain Audit](https://github.com/0xJs/domain_audit) — wrapper around PowerView, Impacket, PowerUpSQL and BloodHound to execute a lot of checks
- [https://www.udemy.com/course/information-security-for-beginners/?couponCode=LINKEDIN09](https://www.udemy.com/course/information-security-for-beginners/?couponCode=LINKEDIN09)

### GRC

- [Management Program](https://github.com/magoo/minimalist-risk-management)
- [GRC Resource List](https://github.com/Arudjreis/awesome-security-GRC)
- [Ultimate GRC](https://www.oceg.org/)

### **Networking**

- [Tailscale](https://tailscale.com/)

### **CLI Usability**

- [Bat](https://github.com/sharkdp/bat) — Advanced syntax highlighting
- [fzf](https://github.com/junegunn/fzf) — General purpose command-line fuzzy finder
- [exa](https://github.com/ogham/exa) — Advanced replacement for *ls* command

### **Active Directory Pentesting**

- [**Offensive AD 101**](https://owasp.org/www-pdf-archive/OWASP_FFM_41_OffensiveActiveDirectory_101_MichaelRitter.pdf)
- [**AD Exploitation Cheatsheet**](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet#active-directory-exploitation-cheat-sheet)
- [**IR Team](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse) — AD & Kerberos Abusing**
- [**AD Kill Chain Attack & Defense**](https://github.com/infosecn1nja/AD-Attack-Defense#discovery)
- [Vulnerable AD](https://github.com/WazeHell/vulnerable-AD) — Create a vulnerable AD allowing you to test most AD attacks in a local lab

### **Compilation of Tools**

- Python
    - [Python Tool List](https://hackersonlineclub.com/python-tools/)

### **Hardware**

- [Flipper Zero](https://flipperzero.one/)

### Reporting

- [PeTeReport](https://hakin9.org/petereport-open-source-application-vulnerability-reporting-tool/)

## **Books**

### **Red Team**

- RTFM
- Pentesting
    - Penetration Testing Essentials
    - Advanced Penetration Testing: Hacking the World’s Most Secure Networks
    - The Pentester BluePrint: Starting a Career as an Ethical Hacker
    - Penetration Testing: A Hands-On Introduction to Hacking
    - The Basics of Hacking & Penetration Testing: Ethical Hacking & Penetration Made Easy
    - Hands On Hacking
- Social Engineering
    - Social Engineering: The Science of Human Hacking
- Apps & Web
    - A Bug Hunter's Diary (Klein)
    - Exploiting Software: How to Break Code (Hoglund and McGraw)
    - Hands-on Web Penetration Testing with Metasploit (Singh and Sharma)
    - Hunting Security Bugs (Gallagher, Landauer, and Jeffries)
    - Professional Pen Testing for Web Applications: Programmer to Programmer (Andreu)
    - Read-World Bug Hunting: A Field Guide to Web Hacking (Yaworski)
    - Seven Deadliest Web Application Attacks (Shema)
    - SQL Injection Attacks and Defense (Clarke et al)
    - The Art of Software Security Assessment (Dowd, McDonald, and Schuh)
    - The Tangled Web: A Guide to Securing Modern Web Applications (Zalewski)
    - Web Penetration Testing with Kali Linux (Najera-Gutierrez and Ansari)
- Network
    - Aggressive Network Self-Defense (Wyler, Potter, and Hurley)
    - Hacking Exposed: Network Security Secrets & Solutions (McClure et al)
    - The Hacker's Handbook: Breaking Into & Defending Networks (Young and Aitel)
    - Silence on the Wire: A Field Guide to Passive Recon and Indirect Attacks (Zalewski)
- Specialized
    - Android Hacker's Handbook (Drake et al)
    - Google Hacking for Penetration Testers (Long, Gardner, and Brown)
    - Hacking Exposed Cisco Networks: Cisco Security (Vladimirov et al)
    - iOS Hacker's Handbook (Miller et al)
    - Practical IoT Hacking (Chantzis et al)
    - Securing the Smart Grid: Next Generation Power Grid Security (Flick and Morehouse)
    - Shellcoder's Handbook: Discovering and Exploiting Security Holes (Anley)
    - Social Engineering: The Art of Human Hacking (Hadnagy et al)
    - The Car Hacker's Handbook: A Guide for the Penetration Tester (Smith)
    - The Database Hacker's Handbook: Defending Database Servers (Litchfield et al)
    - The Hardware Hacker: Adventures in Making & Breaking Hardware (Huang)
    - The Mac Hacker's Handbook (Miller and Zovi)
    - The Mobile Application Hacker's Handbook (Chell)
    - Unauthorized Access: Physical Penetration Testing for IT Security Teams (Allsopp)
    - WarDriving and Wireless Penetration Testing (Hurley et al)
- Digging Deep
    - A Guide to Kernel Exploitation: Attacking the Core (Perla and Oldani)
    - Advanced Penetration Testing: Hacking the World's Most Secure Networks (Allsopp)
    - Advanced Penetration Testing for Highly-Secured Environments (Allen and Cardwell)
    - Advanced Persistent Threat Hacking: The Art & Science of Hacking (Wrightson)
    - Applied Machine Learning/Neural Networks: Offensive Security (Atkins)
    - Managed Code Rootkits: Hooking into Runtime Environments (Metula)
    - Ninja Hacking: Unconventional Penetration Testing (Wilhelm and Andress)
    - Rootkits and Bootkits (Matrosov, Rodionov, and Bratus)
    - Hacking: The Art of Exploitation , 1st or 2nd edition (Jon Erickson)

### **Cyber Intelligence**

- We Are  Bellingcat
- The Dark Net
- Dark Territory
- Cybersecurity & Cyberwar
- Cyber Intelligence
- Sandworm
- The Internet of Us
- The Cambridge Handbook of Surveillance Law
- Surveillance Studies
- Theorizing Surveillance
- Routledge Handbook of Surveillance Studies
- Countdown to Zero
- [Open Source Intelligence Techniques: Resources for Searching & Analyzing Online Information](https://inteltechniques.com/book1.html)

### **Tool Guide**

- Learning Nessus for Penetration Testing (Kumar)
- Metasploit: The Penetration Tester's Guide (Kennedy)
- Metasploit Penetration Testing Cookbook (Teixeira, Singh, and Agarwal)
- Nmap Network Scanning: The Official Nmap Project Guide (Fyodor)
- Nmap 6 Cookbook: The Fat-Free Guide to Network Security Scanning (Marsh)
- Penetration Tester's Open Source Toolkit (Faircloth)

### **Kali Linux**

- Digital Forensics With Kali Linux
- Linux Basics for Hackers: Getting Started with Networking, Scripting, & Security in Kali
- Hacking Exposed Linux (ISECOM)
- Kali Linux Revealed: Mastering the Penetration Testing Distro (Hertzog and O'Gorman)
- Linux Command Line and Shell Scripting Bible (Blum and Bresnahan)
- Linux Shell Scripting Cookbook (Flynt, Lakshman, and Tushar)
- The Linux Command Line: A Complete Introduction (Shotts)
- Wicked Cool Shell Scripts (Taylor and Perry)

### **Finance**

- The Simple Path to Wealth
- The Richest Man in Babylon
- The Psychology of Money
- I Will Teach You To Be Rich
- Rich Dad Poor Dad
- Your Money or Your Life
- 

### **Psychology**

- Dark Pyschology & Manipulation: 10 In 1
- Designing The Mind: The Principles of Psychitecture

### **Real-World**

- The Shadow Factory
- American Kingpin
- The Hacked World Order
- Black Software
- You Have A Very Soft Voice, Susan: A Shocking True Story of Internet Stalking

### **Python**

- Black Hat Python
- Violent Python
- Grey Hat Python
- Cryptography With Python

### **Dark Web**

- Tor & The Dark Web
- Burners & Black Markets
- Inside The Dark Web
- Dark Web Investiagtions (Security Informatics & Law Enforcement)

### **Fiction**

- The cuckoos egg
- CyberStorm: World War C

### **Story Telling**

- Countdown to Zero Day: Stuxnet (Zetter)
- Dark Territory: The Secret History of Cyber War (Kaplan)
- Dissecting the Hack: The F0rb1dd3n Network (Street, Nabors, and Baskin)
- Fatal System Error: Hunt for the New Crime Lords Bringing Down the Internet (Menn)
- Ghost in the Wires: My Adventures as the World's Most Wanted Hacker (Mitnick)
- Hackers & Painters: Big Ideas from the Computer Age (Graham)
- How to Hack Like a Pornstar: Breaking into a Bank (Sparc Flow)
- I, Robot (Asimov)
- Inside Cyber Warfare: Mapping the Cyber Underworld (Carr)
- Kingpin (Poulsen)
- Neuromancer (Gibson)
- Nineteen Eighty-Four (1984) (Orwell)
- No Place to Hide: Snowden, the NSA, and the U.S. Surveillance State (Greenwald)
- The Cuckoo's Egg: Tracking a Spy Through the Maze of Computer Espionage (Stoll)
- The Girl with the Dragon Tattoo (Larsson)
- The Hitchhiker's Guide to the Galaxy (Adams)
- The Lure (Schroeder)
- Zero Day: The Threat in Cyberspace (The Washington Post and O'Harrow)

### **Bug Hunting**

- A bug hunter’s diary
- Real-World Bug Hunting

### **IoT**

- Practical IoT Hacking

### **Quantum**

- Quantum Computing Fundamentals
- Quantum Physics and The Power of the Mind: 5 BOOKS IN 1

### **Cryptography**

- The Code Book: The Science of Secrecy from Ancient Egypt to Quantum Cryptography
- Cryptography Engineering: Design Principles and Practical Applications
- Real-World cryptography

### **Law**

- Damage Control: Cyber Insurance and Compliance
- The 2020 Cyber Security & Cyber Law Guide
- Cyberlaw: Software and Computer Networks

### **Cybersecurity**

- Cyber Mercenaries: The State, Hackers, and Power
- The hackers playbook (series)
- Stealing the network
- Little brother
- Find Me (series)
- Cybersecurity book at px
- Extreme Privacy: What It Takes to Disappear
- Cyber Breach Response That Actually Works
- We Are Anonymous
- The Tribe of Hacker (Series)
- Security Testing with Raspberry Pi
- The Smartest Person in the Room
- CyberStorm
- CyberSpace
- **The 8 Layers of the OSI Cake: A Forensic Taste of Each Layer (Cyber Secrets**

### **Recommended Books**

- Traction by Gino Wickman
- Extreme Ownership by Jocko Willink / Leif Babin
- How to Measure Anything in Cybersecurity
- Shellcoders Handbook
- Black Hat Go
- Security Warrior
- Adversarial Tradecraft in Cybersecurity
- Hacker Disassembling Uncovered

### **Malware**

- Learning Malware Analysis
- The Art of Memory Forensics: Detecting Malware and Threats in Windows, Linux, and Mac Memory
- Practical Malware Analysis
- Antivirus Bypass Techniques

### **Miscellaneous**

- 48 Laws of Power

## **Education / Bootcamps / Programs / Certification Material**

### **Bootcamps & Programs**

- [Global Knowledge](https://www.globalknowledge.com/us-en/)
- [Level Up In Tech](https://www.levelupintech.com/)
- [DFIR Diva](https://training.dfirdiva.com/) — Compilation of Training Resources
- [Perscholas](https://perscholas.org/courses/) — Misc IT Bootcamps
- [100Devs](https://www.youtube.com/playlist?list=PLBf-QcbaigsKwq3k2YEBQS17xUwfOA3O3)
- [NetworkChuck](https://www.youtube.com/c/NetworkChuck)
- [Whizlabs](https://www.whizlabs.com/pricing/?fbclid=IwAR3egmho_JrqqADw7QZ4CLah827tinr-M5ZB51Zc35pO49T9nXqxAo29nRY&fs=e&s=cl)

### **Threat Intelligence Platforms**

- Closed / Propietary: Threat research and CTI data is made available as a paid subscription to a commerical CTI platform
    - [IBM-X Force Exchange](https://exchange.xforce.ibmcloud.com/)
    - [Mandiant](https://www.mandiant.com/)
    - [Recorded Future](https://www.recordedfuture.com/)
    - Public / Private Information Sharing Centers: Information Sharing & Analysis Center (ISACs)
- OSINT
    - Malware Information Sharing Project (MISP)
    - Spamhaus
    - VirusTotal
- **Threat Hunting Training**
    - [https://www.activecountermeasures.com/cyber-threat-hunting-training-course/](https://www.activecountermeasures.com/cyber-threat-hunting-training-course/)

### **Pentesting**

- **Cloud Pentesting**
    - [FlAWS Cloud](http://flaws.cloud/) — AWS Security Training
    - [FLAWS 2 Cloud](http://flaws2.cloud/) — AWS Security Training
    - AWS Vulnerable
        - ‣
        - ‣
        - ‣
        - ‣
        - ‣
        - ‣
    - [DVCA](https://github.com/m6a-UdS/dvca) — Demo project to show how to do priv esc on AWS
    
    - [OWASP Serverless Goat](https://github.com/OWASP/Serverless-Goat) — Demonstrates common serverless security flaws
- Training
    - [Attack-Defense](https://attackdefense.com)
    - [Crackmes](https://crackmes.one/)
    - [Ring Zero Team](https://ringzer0ctf.com/)
    - [Black Hills Information Security — Cyber Range](https://www.blackhillsinfosec.com/services/cyber-range/)
    - [Alert To Win](https://alf.nu/alert1?world=alert&level=alert0)
    - [CTF Komodo Security](https://ctf.komodosec.com)
    - [CMD Challenge](https://cmdchallenge.com)
    - [Explotation Education](https://exploit.education)
    - [Google CTF](https://lnkd.in/e46drbz8)
    - [HackTheBox](https://www.hackthebox.com)
    - [Hackthis](https://defendtheweb.net/)
    - [Hacksplaining](https://www.hacksplaining.com/lessons)
    - [Hacker101](https://ctf.hacker101.com)
    - [Hacker Security](https://hackersec.com/)
    - [Hacking-Lab](https://hacking-lab.com/)
    - [ImmersiveLabs](https://www.immersivelabs.com/)
    - [OverTheWire](http://overthewire.org)
    - [Practical Pentest Labs](https://lnkd.in/esq9Yuv5)
    - [Pentestlab](https://pentesterlab.com)
    - [Penetration Testing Practice Labs](https://lnkd.in/e6wVANYd)
    - [PentestIT LAB](https://lab.pentestit.ru/)
    - [PicoCTF](https://picoctf.com)
    - [PWNABLE](https://lnkd.in/eMEwBJzn)
    - [Root Me](https://www.root-me.org/?lang=en)
    - [Root In Jail](https://rootinjail.com/)
    - [SmashTheStack](http://www.smashthestack.org/wargames.html)
    - [The Cryptopals Crypto Challenges](https://cryptopals.com/)
    - [Try Hack Me](https://tryhackme.com/)
    - [Vulnhub](https://www.vulnhub.com)
    - [W3Challs](https://w3challs.com)
    - [WeChall](http://www.wechall.net/)
    - [Alerted Security](https://www.alteredsecurity.com/)

https://github.com/cliffe/SecGen

- [Exploiting Tokens](https://jsecurity101.medium.com/exploring-token-members-part-1-48bce8004c6a)
- [Offensive Development](https://www.antisyphontraining.com/offensive-development-w-greg-hatcher-john-stigerwalt/)
- [Offensive Development](https://www.antisyphontraining.com/offensive-development-w-greg-hatcher-john-stigerwalt/)

### **Defense**

- [Windows Security Encyclopaedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)

https://github.com/clong/DetectionLab

- Azure
    - [Detect Azure AD Backdoors: Identity Federation](https://www.inversecos.com/2021/11/how-to-detect-azure-active-directory.html)
- Device Hardening
    - Department of Defense Cyber Exchange: Provides STIGs w/ hardening guidelines for a variety of software and hardware solutions
    - National Checklist Program (NCP): Provided by the NIST, checklists and benchmarks for OSs and applications
- [SimplyCyber](https://simplycyber.teachable.com/) — GRC

### **Operating Systems**

- [macOS Terminal (zsh) — The Beginner’s Guide](https://www.youtube.com/watch?v=ogWoUU2DXBU)

### **Methodologies**

- [Open Source Security Testing Methodology Manual (OSSTMM)](https://www.isecom.org/OSSTMM.3.pdf)

### **Documentary**

- [https://threadreaderapp.com/thread/1491830217471528962.html](https://threadreaderapp.com/thread/1491830217471528962.html)
- 

Best Cyber Security and Hacking Documentary #1

1. We Are Legion – The Story Of The Hacktivists ([https://lnkd.in/dEihGfAg](https://lnkd.in/dEihGfAg))
2. The Internet’s Own Boy: The Story Of Aaron Swartz ([https://lnkd.in/d3hQVxqp](https://lnkd.in/d3hQVxqp))
3. Hackers Wanted ([https://lnkd.in/du-pMY2R](https://lnkd.in/du-pMY2R))
4. Secret History Of Hacking ([https://lnkd.in/dnCWU-hp](https://lnkd.in/dnCWU-hp))
5. Def Con: The Documentary ([https://lnkd.in/dPE4jVVA](https://lnkd.in/dPE4jVVA))
6. Web Warriors ([https://lnkd.in/dip22djp](https://lnkd.in/dip22djp))
7. Risk (2016) ([https://lnkd.in/dMgWT-TN](https://lnkd.in/dMgWT-TN))
8. Zero Days (2016) ([https://lnkd.in/dq_gZA8z](https://lnkd.in/dq_gZA8z))
9. Guardians Of The New World (Hacking Documentary) | Real Stories  ([https://lnkd.in/dUPybtFd](https://lnkd.in/dUPybtFd))
10. A Origem dos Hackers ([https://lnkd.in/dUJgG-6J](https://lnkd.in/dUJgG-6J))
11. The Great Hack ([https://lnkd.in/dp-MsrQJ](https://lnkd.in/dp-MsrQJ))
12. The Networks Dilemma ([https://lnkd.in/dB6rC2RD](https://lnkd.in/dB6rC2RD))
13. 21st Century Hackers ([https://lnkd.in/dvdnZkg5](https://lnkd.in/dvdnZkg5))
14. Cyber War - Dot of Documentary ([https://lnkd.in/dhNTBbbx](https://lnkd.in/dhNTBbbx))
15. CyberWar Threat - Inside Worlds Deadliest Cyberattack ([https://lnkd.in/drmzKJDu](https://lnkd.in/drmzKJDu))
16. The Future of Cyberwarfare ([https://lnkd.in/dE6_rD5x](https://lnkd.in/dE6_rD5x))
17. Dark Web Fighting Cybercrime Full Hacking ([https://lnkd.in/dByEzTE9](https://lnkd.in/dByEzTE9))
18. Cyber Defense: Military Training for Cyber Warfare ([https://lnkd.in/dhA8c52h](https://lnkd.in/dhA8c52h))
19. Hacker Hunter: WannaCry The History Marcus Hutchin ([https://lnkd.in/dnPcnvSv](https://lnkd.in/dnPcnvSv))
20. The Life Hacker Documentary ([https://lnkd.in/djAqBhbw](https://lnkd.in/djAqBhbw))
21. Hacker The Realm and Electron - Hacker Group ([https://lnkd.in/dx_uyTuT](https://lnkd.in/dx_uyTuT))

### **Compilations**

- [Cybersecurity Documents, Certification Help, Books, etc.](https://drive.google.com/drive/u/0/folders/1xCCknZbUGhJQd8UKAwL_m9upJgmaQVBr?fbclid=IwAR2I99iLaHwgeyzEZeigh32gtrAIS1gUSC6Xo6ASaamJi3XRwip1zAtpH9k)
- [S0cm0nkey’s Security Reference Guide](https://s0cm0nkey.gitbook.io/s0cm0nkeys-security-reference-guide/)
- [Red Teaming Experiments](https://www.ired.team/) — Cheatsheets
- [Darkstar](https://darkstar7471.com/resources.html) — Infosec Training Resources
- **Offense Security**
    - OSCE3
        
        [https://github.com/CyberSecurityUP/OSCE-Complete-Guide](https://github.com/CyberSecurityUP/OSCE-Complete-Guide)
        

## **Resource Compilation**

### **Bug Hunting**

- [Bug Hunter Handbook](https://gowthams.gitbook.io/bughunter-handbook/)

### **Powershell Automation**

- [PowerShell Intune Samples](https://github.com/microsoftgraph/powershell-intune-samples) — Make HTTPS RESTful API requests
- [Mega Collection of PowerShell Scripts](https://github.com/fleschutz/PowerShell)

### **Privacy**

- [https://www.privacytools.io/](https://www.privacytools.io/)
- [S1ckB0y1337](https://github.com/S1ckB0y1337?tab=repositories)
- [Build Your Own X](https://github.com/codecrafters-io/build-your-own-x) — Repository Compilation Projects for Hackers
- [Cyber Security Repo](https://cyber-security.tk/categories/)
- [Computer Science Video Courses](https://github.com/Developer-Y/cs-video-courses)
- [Awesome Docker Security](https://github.com/myugan/awesome-docker-security) — Resources for Docker Security (Books, Blogs, Videos, Tools, etc.)
- [Microsoft Graph](https://github.com/microsoftgraph) — Access data, relationships and insights coming from the cloud
- [VX-Underground](https://github.com/vxunderground) — Collection of malware source code, amples, and PoCs
- [W3BS3C](https://www.w3bs3c.com/) — Web3 searchable curable repository of tools, CTFs, 101s, videos, and bounties
- [Hacker Arise](https://www.hackers-arise.com/post/the-cyberwar-vs-putin-what-we-are-doing-and-what-you-can-do-to-help)
- [Malware Development Repo](https://lookbook.cyberjungles.com/random-research-area/malware-analysis-and-development/malware-development)
- [Machine Learning](https://github.com/dair-ai/ML-Course-Notes)

## **Cybersecurity Maps, Domains, etc.**

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/087527b0-f437-4255-8b00-0bc69c7dcd73/Untitled.png)

- [Paul Jerimy — Cyber Certification Roadmap](https://pauljerimy.com/security-certification-roadmap/)

## **Security News — Stay Updated On Relevant Attacks & Other Infosec News**

- [Feedspot](https://blog.feedspot.com/cyber_security_rss_feeds/) — Top 100 Cybersecurity RSS Feeds
- [GBHackers on Security](https://gbhackers.com/)
- [Isaca](https://www.isaca.org/)
- Microsoft
- [PenTest Magazine](https://pentestmag.com/)
- [TDLR Magazine](https://tldr.tech/crypto)
- [Tripwire](https://www.tripwire.com/state-of-security/contributors/graham-cluley/)
- [Naked Security](https://nakedsecurity.sophos.com/)
- [ThreatPost](https://threatpost.com/)
- [Scheiner](https://www.schneier.com/)
- [DarkReading](https://www.darkreading.com/)
- [EFF](https://www.eff.org/deeplinks)
- [ZDNet](https://www.zdnet.com/blog/security/)
- [KrebsOnSecurity](https://krebsonsecurity.com/)
- [Talos Intelligence](https://blog.talosintelligence.com/)
- Specific Articles
    - [BendyBear](https://x-phy.com/advanced-shell-code-a-use-case-of-blacktech-associated-bendybear/)
- CVEs
    - Apple
        - [https://www.websecgeeks.com/2022/06/how-i-was-able-to-send-emails-on-behalf-of-any-apple-user-email.html](https://www.websecgeeks.com/2022/06/how-i-was-able-to-send-emails-on-behalf-of-any-apple-user-email.html)

## **Freelancing Sites**

- [Fiverr](https://www.fiverr.com/)
- [UpWork](https://www.upwork.com/)

## **Support Organizations**

### **Black Tech Organizations**

- [https://www.cio.com/article/191321/10-professional-organizations-for-black-it-pros.html](https://www.cio.com/article/191321/10-professional-organizations-for-black-it-pros.html)

[https://sites.temple.edu/care/dei/owl/](https://sites.temple.edu/care/dei/owl/)

## **Cybersecurity Apparel**

- [https://www.teepublic.com/user/djax120](https://www.teepublic.com/user/djax120)

## Blogging