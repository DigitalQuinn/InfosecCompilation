# Infosec Compilation

Infosec Compilation is an information security repository for offensive, defensive, and purple-teaming resources, along with  designed for advanced penetration testing tactics, techniques, and procedures (TTPs) based on the MITRE framework


# Table of Contents
* [A Hacker's Methodology](#a-hackers-methodology)
* [Homelab](#homelab)
  * [Repository](#repository)
  * [Active Directory](#active-directory)
  * [Reverse Engineering](#reverse-engineering)
  * [Sandbox](#sandbox)
  * [Network Access Control (NAC)](#network-access-control-nac)
  * [Vulnerable Images](#vulnerable-images)
  * [Malware Binaries](#malware-binaries)
  * [Reverse Engineering Guides](#reverse-engineering-guides)
  * [Malware Analysis Homelab Setup](#malware-analysis-homelab-setup)
  * [Malware Tools](#malware-tools)
  * [Endpoint Detection & Response (EDR)](#endpoint-detection--response-edr)
  * [Security Incident Event Monitoring (SIEM)](#security-incident-event-monitoring-siem)
* [Hacking References & Cheatsheets](#hacking-references--cheatsheets)
* [Offensive Security Tools](#offensive-security-tools)
  * [Reconnaissance Tools](#reconnaissance-tools)
    * [Anonymity Tools](#anonymity-tools)
    * [OSINT Frameworks](#osint-frameworks)
    * [Search Engines](#search-engines)
    * [Source Code Search](#source-code-search)
    * [Crypto OSINT](#crypto-osint)
    * [Government Record Search](#government-record-search)
    * [Social Media](#social-media)
    * [Credentials](#credentials)
    * [Email](#email)
    * [Personal Investigations](#personal-investigations)
    * [Phone Numbers](#phone-number)
    * [Company Research](#company-research)
    * [Location](#location)
    * [Image Search](#image-search)
    * [Dorking](#dorking)
    * [Web History](#web-history)
    * [Web Monitoring](#web-monitoring)
    * [Domain](#domain)
    * [Breached Credentials](#breached-credentials)
    * [Vulnerability / IP Scanners](#vulnerability--ip-scanners)
  * [Resource Development Tools](#resource-development-tools)
    * [Pentesting OS Distributions](#pentesting-os-distributions)
    * [Multi-Paradigm Frameworks](#multi-paradigm-frameworks)
    * [Hardware](#hardware)
    * [CLI Usability](#cli-usability)
  * [Initial Access Tools](#initial-access-tools)
    * [Phishing](#phishing)
  * [Execution Tools](#execution-tools)
  * [Persistence Tools](#persistence-tools)
  * [Privilege Escalation Tools](#privilege-escalation-tools)
  * [Defense Evasion Tools](#defense-evasion-tools)
    * [Evade AV / EDR](#evade-avedr)
    * [Packet Injection](#packet-injection)
    * [Wrappers](#wrappers)
  * [Credential Access Tools](#credential-access-tools)
    * [Password Attacks](#password-attacks)
    * [Hash Cracking](#hash-cracking)
  * [Discovery Tools](#discovery-tools)
    * [Protocol Analyzers & Sniffers](#protocol-analyzers--sniffers)
  * [Lateral Movement Tools](#lateral-movement-tools)
  * [Collection Tools](#collection-tools)
  * [Impact](#impact)
  * [Remediation / Reporting](#remediation--reporting)
  * [Cloud Pentesting](#cloud-pentesting)
  * [Active Directory](#active-directory)
  * [Compilation of Tools](#compilation-of-tools)
    * [Python](#python)
    * [Wireless Pentesting](#wireless-pentesting)
* [Defensive Security Tools](#defensive-security-tools)
  * [Governance Risk & Compliance (GRC)](#governance-risk--compliance-grc-tools)
    * [Device Hardening](#device-hardening)
    * [Auditing Tools](#auditing-tools)
* [Networking](#networking)
* [Books](#books)
  * [InfoSec Books](#infosec-books)
  * [Finance Books](#finance-books)
  * [Psychology Books](#psychology-books)
  * [Miscellaneous Books](#miscellaneous-books)
* [Education / Bootcamps / Programs / Certification Material](#education--bootcamps--programs--certification-material)
  * [Bootcamps & Programs](#bootcamps--programs)
  * [Threat Intelligence Platforms](#threat-intelligence-platforms)
    * [Propietary](#propietary)
    * [OSINT](#osint)
  * [Threat Hunting Training](#threat-hunting-training)
  * [Information Security Certifications](#information-security-certifications)
  * [Security Training Platforms](#security-training-platforms)
    * [Cloud Pentesting Training](#cloud-pentesting-training)
    * [Offensive Development](#offensive-development)
    * [Defensive Development](#defensive-development)
      * [Azure](#azure)
  * [Methodologies](#methodologies)
* [Documentaries](#documentaries)
* [Social Engineering Articles](#social-engineering-articles)
* [Resource Compilation](#resource-compilation)
  * [Bug Hunting](#bug-hunting)
  * [Powershell Automation](#powershell-automation)
  * [Privacy](#privacy)
* [Cybersecurity Road Maps, Domains, etc.](#cybersecurity-maps-domains-etc)
* [Security News](#security-news)
  * [Specific Articles](#specific-articles)
  * [CVEs](#cves)
* [Freelancing Sites](#freelancing-sites)
* [Support Organizations](#support-organizations)
  * [Black Tech Organizations](#black-tech-organizations)
  * [Conferences](#Conferences)
* [Cybersecurity Apparel](#cybersecurity-apparel)
* [Alpha Cyber Security](https://www.teepublic.com/user/djax120)
* [Blogging](#blogging)

<br>
<hr>

# A Hacker's Methodology

<br>

* **Reconnaissance:** Gathering information that can be used to support targeting
* **Resource Development:** Creating, purchasing, or compromising resources that can be used to support targeting
* **Initial Access:** Various entry vectors to gain your initial foothold within a network
* **Execution:** Attacker-controlled code running on a local or remote system
* **Persistence:** Maintaining access to systems across interruptions that could cut off adverdary's access
* **Privilege Escalation:** Gaining higher-level permissions on a system or network
* **Defense Evasion:** Avoiding detection throughout your compromise
* **Credential Access:** Stealing credentials like account names and passwords
* **Discovery:** Observing potential control and what’s around your entry point in order to discover how it could benefit your current objective
* **Lateral Movement:** Pivoting through multiple systems and accounts to gain additional access
* **Collection:** Gathering information relevant to following through on the adversary's objectives
* **Command & Control (C2):** Communicating with systems under your control within a victim network
* **Exfiltration:** Stealing data from victim's infrastructure
* **Impact:** Disrupting availability, compromising integrity by manipulating business and operational processes






# Homelab

## Repository
* [Blue Team Homelab](https://github.com/aboutsecurity/blueteam_homelabs) — Blue Team Environment
* [SecGen](https://github.com/cliffe/SecGen) — Creates vulnerable VMs, Lab Environments, & Hacking challenges
* [DetectionLab](https://github.com/clong/DetectionLab) - Quickly build a Windows domain with pre-loaded with security tooling and system logging configurations

## Active Directory
* [SpookySec](https://lnkd.in/eN8V88kv)
* [Vulnerable-AD](https://github.com/WazeHell/vulnerable-AD) - Set up a Vulnerable AD lab 

## Reverse Engineering
* [https://c3rb3ru5d3d53c.github.io/docs/malware-analysis-beginner-guide/](https://c3rb3ru5d3d53c.github.io/docs/malware-analysis-beginner-guide/) - Reverse Engineering Guide
* [Balbuzard](https://github.com/decalage2/balbuzard) - Malware analysis tool with reverse obfuscation.
* [binwalk](https://github.com/ReFirmLabs/binwalk) - Fast, easy to use tool for analyzing, reverse engineering, and extracting firmware images.
* [Capstone](https://www.capstone-engine.org/) - Lightweight multi-platform, multi-architecture disassembly framework.
* [Cuckoo Modified API](https://github.com/keithjjones/cuckoo-modified-api) - Python API for Cuckoo Modified.
* [Cuckoo Modified](https://github.com/brad-sp/cuckoo-modified) - Fork of Cuckoo Sandbox with multiple improvements.
* [Cuckoo Sandbox](https://cuckoosandbox.org/) - Online malware scanner.
* [de4dot](https://github.com/de4dot/de4dot) - .NET deobfuscator and unpacker.
* [dnSpy](https://github.com/dnSpy/dnSpy) - Tool to reverse engineer .NET assemblies.
* [Dovehawk] (https://github.com/tylabs/dovehawk) - Dovehawk is a Zeek module that automatically imports MISP indicators and reports Sightings
* [DRAKVUF](https://github.com/tklengyel/drakvuf) - Virtualization based agentless black-box binary analysis system.
* [Evan's Debugger](http://codef00.com/projects#debugger) - OllyDbg-like debugger for GNU/Linux.
* [FireEye Labs Obfuscated String Solver (FLOSS)](https://github.com/fireeye/flare-floss) - Malware deobfuscator.
* [firmware.re](http://firmware.re/) - Firmware analyzier.
* [HaboMalHunter](https://github.com/Tencent/HaboMalHunter) - Automated malware analysis tool for Linux ELF files.
* [Hybrid Analysis](https://www.hybrid-analysis.com/) - Online malware scanner.
* [Immunity Debugger](https://debugger.immunityinc.com/) - Powerful way to write exploits and analyze malware.
* [Interactive Disassembler (IDA Pro)](https://www.hex-rays.com/products/ida/) - Proprietary multi-processor disassembler and debugger for Windows, GNU/Linux, or macOS; also has a free version, [IDA Free](https://www.hex-rays.com/products/ida/support/download_freeware/).
* [Malaice.io](https://github.com/maliceio/malice) - Open source malware analyzer.
* [Malheur](https://github.com/rieck/malheur) - Automated sandbox analysis of malware behavior.
* [Medusa](https://github.com/wisk/medusa) - Open source, cross-platform interactive disassembler.
* [Metadefender](https://metadefender.opswat.com/#!/) - Online file and hash analyzer.
* [NoMoreXOR](https://github.com/hiddenillusion/NoMoreXOR) - Frequency analysis tool for trying to crack 256-bit XOR keys.
* [OllyDbg](http://www.ollydbg.de/) - x86 debugger for Windows binaries that emphasizes binary code analysis.
* [PackerAttacker](https://github.com/BromiumLabs/PackerAttacker) - Generic hidden code extractor for Windows malware.
* [PacketTotal](https://packettotal.com/) - Online pcap file analyzer.
* [peda](https://github.com/longld/peda) - Python Exploit Development Assistance for GDB.
* [plasma](https://github.com/plasma-disassembler/plasma) - Interactive disassembler for x86/ARM/MIPS. Generates indented pseudo-code with colored syntax code.
* [PyREBox](https://github.com/Cisco-Talos/pyrebox) - Python scriptable Reverse Engineering sandbox by Cisco-Talos.
* [Radare2](https://www.radare.org/r/index.html) - Open source, crossplatform reverse engineering framework.
* [Ragpicker](https://github.com/robbyFux/Ragpicker) - Malware analysis tool.
* [rVMI](https://github.com/fireeye/rVMI) - Debugger on steroids; inspect userspace processes, kernel drivers, and preboot environments in a single tool.
* [Sandboxed Execution Environment](https://github.com/F-Secure/see) - Framework for building sandboxed malware execution environments.
* [unXOR](https://github.com/tomchop/unxor/) - Tool that guesses XOR keys using known plaintext attacks.
* [VirtualDeobfuscator](https://github.com/jnraber/VirtualDeobfuscator) - Reverse engineering tool for virtualization wrappers.
* [VirusTotal](https://www.virustotal.com/gui/home/upload) - Online malware scanner.
* [Voltron](https://github.com/snare/voltron) - Extensible debugger UI toolkit written in Python.
* [WDK/WinDbg](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk) - Windows Driver Kit and WinDbg.
* [x64dbg](https://x64dbg.com/#start) - Open source x64/x32 debugger for windows.
* [xortool](https://github.com/hellman/xortool) - Tool for guessing XOR keys.

### Blacklisting Domains
* [AbuseIPDB](https://www.abuseipdb.com/) - Search engine for blacklisted IPs or domains.
* [AutoShun](https://riskanalytics.com/community/) - Public repository of malicious IPs and other resources.
* [BadIPs](https://www.badips.com/) - Online blacklist lookup.
* [Binary Defense IP Ban List](https://www.binarydefense.com/banlist.txt) - Public IP blacklist.
* [Blocklist Ipsets](https://github.com/firehol/blocklist-ipsets) - Public IP blacklist.
* [Exonera Tor](https://metrics.torproject.org/exonerator.html) - A database of IP addresses that have been part of the Tor network. It answers the question whether there was a Tor relay running on a given IP address on a given date.
* [Malware Domain List](http://www.malwaredomainlist.com/) - Search and share malicious URLs.
* [Spamcop](https://www.spamcop.net/bl.shtml) - IP based blacklist.
* [Spamhaus](https://www.spamhaus.org/lookup/) - Online blacklist lookup.
* [malc0de DNSSinkhole](http://malc0de.com/bl/) - List of domains that have been identified as distributing malware during the past 30 days.
* [malc0de DNSSinkhole](http://malc0de.com/bl/) - List of domains that have been identified as distributing malware during the past 30 days.
  
### Sandbox
* [Cuckoo](https://cuckoosandbox.org/) - open source automated malware analysis system
* [DRAKVUF Sandbox](https://github.com/CERT-Polska/drakvuf-sandbox/) - Automated black-box malware analysis system with DRAKVUF engine under the hood (Doesn't require an agent on guest OS)
* [PacketTotal](https://packettotal.com/) — Online PCAP Analysis Engine
* [Joe Sandbox Cloud](https://www.joesandbox.com/#windows) - Automated malware sandbox (Live interaction capabilities)
* [CAPE](https://github.com/kevoreilly/CAPEv2/) - Malware sandbox, derived from Cuckoo with the goal of adding automated malware unpacking and config extraction
- * [Cuckoo](https://github.com/cuckoosandbox) - Open Source Highly configurable sandboxing tool.
* [Cuckoo-modified](https://github.com/spender-sandbox/cuckoo-modified) - Heavily modified Cuckoo fork developed by community.
* [Cuckoo-modified-api](https://github.com/keithjjones/cuckoo-modified-api) - A Python library to control a cuckoo-modified sandbox.
* [Hybrid-Analysis](https://www.hybrid-analysis.com/) - Hybrid-Analysis is a free powerful online sandbox by Payload Security.
* [Malwr](https://malwr.ee/) - Malwr is a free online malware analysis service and community, which is powered by the Cuckoo Sandbox.
* [Mastiff](https://github.com/KoreLogicSecurity/mastiff) - MASTIFF is a static analysis framework that automates the process of extracting key characteristics from a number of different file formats.
* [Metadefender Cloud](https://metadefender.opswat.com/) - Metadefender is a free threat intelligence platform providing multiscanning, data sanitization and vulnerability assesment of files.
* [Viper](https://github.com/viper-framework/viper) - Viper is a python based binary analysis and management framework, that works well with Cuckoo and YARA
* [Virustotal](https://www.virustotal.com/gui/) - Virustotal, a subsidiary of Google, is a free online service that analyzes files and URLs enabling the identification of viruses, worms, trojans and other kinds of malicious content detected by antivirus engines and website scanners.
* [Visualize_Logs](https://github.com/keithjjones/visualize_logs) - Open source. Visualization library and command line tools for logs.

## Network Access Control (NAC)
* [Packet Fence](https://www.packetfence.org/) — Open source NAC

## Vulnerable Images
* [Exploit Education](https://exploit.education) - Variety of resources to learn about vulnerability analysis, exploit development, software debugging, binary analysis, and general cyber security issues
* [Docker Images](https://houdini.secsi.io/) - Hundreds of offensive and useful Docker images for penetration testing

## Malware Binaries

* [VX-Underground](https://github.com/vxunderground/MalwareSourceCode) — Malware source code
    * [VX-Underground’s Samples](https://samples.vx-underground.org/samples/Families/)
    * [VXUnderground](https://github.com/vxunderground/MalwareSourceCode)
* [Zeltser Resources](https://zeltser.com/malware-sample-sources/)
* [ANY.RUN](https://app.any.run/submissions)
* [https://crackmes.one/](https://crackmes.one/) — Binaries for Reverse Engineering
* [Contagio Malware Dump](http://contagiodump.blogspot.com/)
* [CAPE Sandbox](https://capesandbox.com/)
* [Das Malwerk](http://dasmalwerk.eu/)
* [Hatching Triage](https://tria.ge/)
* [Hybrid Analysis](https://www.hybrid-analysis.com/)
* [InQuest Labs](https://labs.inquest.net/)
* [InQuest Malware Samples](https://github.com/InQuest/malware-samples)
* [KernelMode.info](http://www.kernelmode.info/forum/viewforum.php?f=16)
* [MalShare](http://malshare.com/)
* [MalwareBazaar](https://bazaar.abuse.ch/browse/)
* [MalwareSamples Malware-Feed](https://github.com/MalwareSamples/Malware-Feed/)
* [Malware DB](http://ytisf.github.io/theZoo/)
* [Objective-See Collection](https://objective-see.com/malware.html)
* [PacketTotal](https://packettotal.com/malware-archive.html)
* [PhishingKitTracker](https://github.com/marcoramilli/PhishingKitTracker)
* [PolySwarm](https://polyswarm.network/)
* [SNDBOX](https://app.sndbox.com/)
* [SoReL-20M](https://github.com/sophos-ai/SOREL-20M)
* [URLhaus](https://urlhaus.abuse.ch/browse/)
* [VirusBay](https://beta.virusbay.io/)
* [VirusShare](https://virusshare.com/)
* [VirusSign](https://www.virussign.com/downloads.html)
* [Virus and Malware Samples](https://www.virussamples.com/)
* [Yomi](https://yomi.yoroi.company/)
* [theZoo](https://github.com/ytisf/theZoo)


## Malware Analysis Homelab Setup
* [KVM Malware Lab](https://c3rb3ru5d3d53c.github.io/docs/kvm-malware-lab/)

## Malware Tools
* [Malware Analysis Tools](https://0x1.gitlab.io/security/Malware-Analysis-Tools-List/)
* [MalAPI](https://malapi.io/) — Catalog of Windows APIs commonly used in malware
* [Qu1cksc0pe] - All-in-One Static Malware Analysis Tool

## Endpoint Detection & Response (EDR)
* [Intezer Protect](https://www.intezer.com/intezer-protect/) — EDR built for your cloud

## Security Incident Event Monitoring (SIEM)
* [https://wazuh.com](https://wazuh.com/)

# Hacking References & Cheatsheets

* [LFI Cheat Sheet](https://highon.coffee/blog/lfi-cheat-sheet/)
* [Local Linux Enumeration & Privilege Escalation Cheatsheet](https://github.com/rebootuser/LinEnum)
* [Metasploit Payload Cheatsheet](https://netsec.ws/?p=331)
* [Multiple Cheatsheets By Andrewjkerr](https://github.com/andrewjkerr/security-cheatsheets)
* [Nmap Cheat Sheet](https://highon.coffee/blog/nmap-cheat-sheet/)
* [Pentest Recon And Enu Cheatsheet](https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/#recon-and-enumeration)
* [Reverse Shell Cheat Sheet](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [SQL Injection Cheat Sheet](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/)
* [XSS Cheat Sheet](https://n0p.net/penguicon/php_app_sec/mirror/xss.html)
* [XSS Payload Cheatsheet](https://github.com/pgaijin66/XSS-Payloads/blob/master/payload/payload.txt)

## Showcasings
* ["Fileless" UAC Bypass Using sdclt.exe](https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/)
* [A Citrix Story](https://rastamouse.me/blog/a-citrix-story/)
* [A Guide to Attacking Domain Trusts](https://posts.specterops.io/a-guide-to-attacking-domain-trusts-971e52cb2944)
* [A Guide to Attacking Domain Trusts](https://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
* [A Pentester's Guide to Group Scoping](https://www.harmj0y.net/blog/activedirectory/a-pentesters-guide-to-group-scoping/)
* [A Read Teamer's Guide to GPOs and OUs](https://wald0.com/?p=179)
* [Abusing Active Directory Permissions with PowerView](https://www.harmj0y.net/blog/redteaming/abusing-active-directory-permissions-with-powerview/)
* [Abusing DCOM For Yet Another Lateral Movement Technique](https://bohops.com/2018/04/28/abusing-dcom-for-yet-another-lateral-movement-technique/)
* [Abusing DNSAdmins Privilege for Escalation in Active Directory](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
* [Abusing Exported Functions and Exposed DCOM Interfaces for Pass-Thru Command Execution and Lateral Movement](https://bohops.com/2018/03/17/abusing-exported-functions-and-exposed-dcom-interfaces-for-pass-thru-command-execution-and-lateral-movement/)
* [Abusing GPO Permissions](https://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
* [Abusing Microsoft Word Features for Phishing: "subDoc"](https://rhinosecuritylabs.com/research/abusing-microsoft-word-features-phishing-subdoc/)
* [Abusing the COM Registry Structure: CLSID, LocalServer32, & ImprocServer32](https://bohops.com/2018/06/28/abusing-com-registry-structure-clsid-localserver32-inprocserver32/)
* [Accessing Clipboard From the Lock Screen in Windows 10 Part 1](https://oddvar.moe/2017/01/24/accessing-clipboard-from-the-lock-screen-in-windows-10/)
* [Accessing Clipboard From the Lock Screen in Windows 10 Part 2](https://oddvar.moe/2017/01/27/access-clipboard-from-lock-screen-in-windows-10-2/)
* [Agentless Post-Exploitation](https://www.youtube.com/watch?v=QbjuO5IlpBU)
* [Aggressor PowerView](https://threat.tevora.com/aggressor-powerview/)
* [AppLocker - Case Study - How Insecure Is It Really? Part 1](https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/)
* [AppLocker - Case Study - How Insecure Is It Really? Part 2](https://oddvar.moe/2017/12/21/applocker-case-study-how-insecure-is-it-really-part-2/)
* [Are We Really Safe? Hacking Access Control Systems](https://www.slideshare.net/DennisMaldonado5/hacking-access-control-systems)
* [Automated Derivative Administrator Search](https://wald0.com/?p=14)
* [Awesome Bug Bounty](https://github.com/djadmin/awesome-bug-bounty)
* [Awesome CTF](https://github.com/apsdehal/awesome-ctf)
* [Awesome ICS Security](https://github.com/hslatman/awesome-industrial-control-system-security)
* [Awesome Lockpicking](https://github.com/fabacab/awesome-lockpicking)
* [Awesome Yara](https://github.com/InQuest/awesome-yara)
* [Bringing the Hashes Home With reGeorg & Empire](https://sensepost.com/blog/2016/bringing-the-hashes-home-with-regeorg-empire/)
* [Bypassing AMSI via COM Server Hijacking](https://posts.specterops.io/bypassing-amsi-via-com-server-hijacking-b8a3354d1aff)
* [Bypassing Application Whitelisting With BGinfo](https://oddvar.moe/2017/05/18/bypassing-application-whitelisting-with-bginfo/)
* [Bypassing Device Guard UMCI Using CHM - CVE-2017-8625](https://oddvar.moe/2017/08/13/bypassing-device-guard-umci-using-chm-cve-2017-8625/)
* [Bypassing UAC Using App Paths](https://enigma0x3.net/2017/03/14/bypassing-uac-using-app-paths/)
* [Cell Injection](http://blog.7elements.co.uk/2013/01/cell-injection.html)
* [ClickOnce, Twice or Thrice: A Technique for Social Engineering and Untrusted Command Execution](https://bohops.com/2017/12/02/clickonce-twice-or-thrice-a-technique-for-social-engineering-and-untrusted-command-execution/)
* [Cloning and Hosting Evil Captive Portals Using a Wi-Fi Pineapple](https://blog.inspired-sec.com/archive/2017/01/10/cloning-captive-portals.html)
* [CloudFront Hijacking](https://www.mindpointgroup.com/blog/pen-test/cloudfront-hijacking/)
* [Cobalt Strike - What's the go-to phishing technique or exploit?](https://blog.cobaltstrike.com/2014/12/17/whats-the-go-to-phishing-technique-or-exploit/)
* [Code Signing Certificate Cloning Attacks and Defenses](https://posts.specterops.io/code-signing-certificate-cloning-attacks-and-defenses-6f98657fc6ec)
* [Colbalt Strike - Spear Phishing documentation](https://www.cobaltstrike.com/help-spear-phish)
* [Comma Separated Vulnerabilities](https://www.contextis.com/en/blog/comma-separated-vulnerabilities)
* [DNS Data Exfiltration - What is This and How to Use?](https://cuongmx.medium.com/dns-data-exfiltration-what-is-this-and-how-to-use-2f6c69998822)
* [DNS Tunnelling](https://resources.infosecinstitute.com/topic/dns-tunnelling/)
* [Data Exfiltration Over DNS Request Covert Channel: DNSExfiltrator](https://www.kitploit.com/2018/01/dnsexfiltrator-data-exfiltration-over.html)
* [Data Exfiltration via Formula Injection](https://notsosecure.com/data-exfiltration-formula-injection/)
* [Defense In Depth](https://oddvar.moe/2017/09/13/defense-in-depth-writeup/)
* [DiskShadow: The Return of VSS Evasion, Persistence, and Active Directory Database Extraction](https://bohops.com/2018/03/26/diskshadow-the-return-of-vss-evasion-persistence-and-active-directory-database-extraction/)
* [Domain Fronting Via Cloudfront Alternate Domains](https://www.mdsec.co.uk/2017/02/domain-fronting-via-cloudfront-alternate-domains/)
* [Dump Clear-Text Passwords for All Admins in the Domain Using Mimikatz DCSync](https://adsecurity.org/?p=2053)
* [Dumping Domain Password Hashes](https://pentestlab.blog/2018/07/04/dumping-domain-password-hashes/)
* [Empire Domain Fronting](https://www.xorrior.com/Empire-Domain-Fronting/)
* [Empire Without PowerShell](https://isec.ne.jp/wp-content/uploads/2017/08/30Empire-without-Powershell.pdf)
* [Escape and Evasion Egressing Restricted Networks](https://www.optiv.com/explore-optiv-insights/blog/escape-and-evasion-egressing-restricted-networks)
* [Excel Macros With PowerShell](https://4sysops.com/archives/excel-macros-with-powershell/)
* [Executing Commands and Bypassing AppLocker with PowerShell Diagnostic Scripts](https://bohops.com/2018/01/07/executing-commands-and-bypassing-applocker-with-powershell-diagnostic-scripts/)
* [Exploiting Environment Variables in Scheduled Tasks for UAC Bypass](https://www.tiraniddo.dev/2017/05/exploiting-environment-variables-in.html)
* [Extending BloodHound for Red Teamers](https://www.youtube.com/watch?v=Pn7GWRXfgeI)
* [Finding Domain Frontable Azure Domains](https://theobsidiantower.com/2017/07/24/d0a7cfceedc42bdf3a36f2926bd52863ef28befc.html)
* [First Entry: Welcome and Fileless UAC Bypass](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/)
* [From Pass-the-Hash to Pass-the-Ticket with No Pain](https://resources.infosecinstitute.com/topic/pass-hash-pass-ticket-no-pain/)
* [Getting the Goods with CrackMapExec: Part 1](https://byt3bl33d3r.github.io/getting-the-goods-with-crackmapexec-part-1.html)
* [Getting the Goods with CrackMapExec: Part 2](https://byt3bl33d3r.github.io/getting-the-goods-with-crackmapexec-part-2.html)
* [Harden Windows With AppLocker - Based on Case Study Part 1](https://oddvar.moe/2017/12/13/harden-windows-with-applocker-based-on-case-study-part-1/)
* [Harden Windows With AppLocker - Based on Case Study Part 2](https://oddvar.moe/2017/12/21/harden-windows-with-applocker-based-on-case-study-part-2/)
* [Hiding Registry Keys with PSReflect](https://posts.specterops.io/hiding-registry-keys-with-psreflect-b18ec5ac8353)
* [How I Identified 93k Domain-Frontable CloudFront Domains](https://www.peew.pw/blog/2018/2/22/how-i-identified-93k-domain-frontable-cloudfront-domains)
* [How to Obfuscate JacaScript in Metasploit](https://github.com/rapid7/metasploit-framework/wiki/How-to-obfuscate-JavaScript-in-Metasploit)
* [In-Memory Evasion](https://blog.cobaltstrike.com/2018/02/08/in-memory-evasion/)
* [Intercepting Passwords With Empire and Winning](https://sensepost.com/blog/2016/intercepting-passwords-with-empire-and-winning/)
* [Intro to Using GScript for Red Teams](http://lockboxx.blogspot.com/2018/02/intro-to-using-gscript-for-red-teams.html)
* [Introducing BloodHound](https://wald0.com/?p=68)
* [Introduction to Metasploit: Exploiting Web Applications](https://www.slideshare.net/DennisMaldonado5/metasploit-for-web-workshop)
* [Jumping Network Segregation with RDP](https://rastamouse.me/blog/rdp-jump-boxes/)
* [Kerberoasting Without Mimikatz](https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/)
* [Kerberos Party Tricks: Weaponizing Kerberos Protocol Flaws](http://www.exumbraops.com/blog/2016/6/1/kerberos-party-tricks-weaponizing-kerberos-protocol-flaws)
* [Lateral Movement Using Excel Application and docm](https://enigma0x3.net/2017/09/11/lateral-movement-using-excel-application-and-dcom/)
* [Lay of the Land with Bloodhound](https://threat.tevora.com/lay-of-the-land-with-bloodhound/)
* [LethalHTA - A New Lateral Movement Technique Using DCOM and HTA](https://codewhitesec.blogspot.com/2018/07/lethalhta.html)
* [Leveraging INF-SCT Fetch & Execute Technique For Bypass, Evasion, & Persistence](https://bohops.com/2018/02/26/leveraging-inf-sct-fetch-execute-techniques-for-bypass-evasion-persistence/)
* [Leveraging INF-SCT Fetch & Execute Technique For Bypass, Evasion, & Persistence](https://bohops.com/2018/03/10/leveraging-inf-sct-fetch-execute-techniques-for-bypass-evasion-persistence-part-2/)
* [Loading Alternate Data Stream ADS DLL/CPL Binaries to Bypass AppLocker](https://bohops.com/2018/01/23/loading-alternate-data-stream-ads-dll-cpl-binaries-to-bypass-applocker/)
* [Local Administrator Password Solution (LAPS) - Part 1](https://rastamouse.me/blog/laps-pt1/)
* [Local Administrator Password Solution (LAPS) - Part 2](https://rastamouse.me/blog/laps-pt2/)
* [Local Group Enumeration](https://www.harmj0y.net/blog/redteaming/local-group-enumeration/)
* [Macro-less Code Exec in MSWord](https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/)
* [Microsoft LAPS Security & Active Directory LAPS Configuration Recon](https://adsecurity.org/?p=3164)
* [Microsoft Office - NTLM Hashes via Frameset](https://pentestlab.blog/2017/12/18/microsoft-office-ntlm-hashes-via-frameset/)
* [Multi-Platform Macro Phishing Payloads](https://malcomvetter.medium.com/multi-platform-macro-phishing-payloads-3b688e8eff68)
* [My First Go with BloodHound](https://blog.cobaltstrike.com/2016/12/14/my-first-go-with-bloodhound/)
* [OPSEC Considerations for Beacon Commands](https://blog.cobaltstrike.com/2017/06/23/opsec-considerations-for-beacon-commands/)
* [OWASP Social Engineering: The Art of Human Hacking](https://owasp.org/www-pdf-archive/Presentation_Social_Engineering.pdf)
* [Offensive Encrypted Data Storage](https://www.harmj0y.net/blog/redteaming/offensive-encrypted-data-storage/)
* [Office 365 Safe Links Bypass](https://oddvar.moe/2018/01/03/office-365-safe-links-bypass/)
* [Outlook Forms and Shells](https://sensepost.com/blog/2017/outlook-forms-and-shells/)
* [Outlook Home Page - Another Ruler Vector](https://sensepost.com/blog/2017/outlook-home-page-another-ruler-vector/)
* [Pass-the-Hash is Dead: Long Live LocalAccountTokenFilterPolicy](https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/)
* [Persistence Using Globalflags In Image File Execution Options - Hidden from Autoruns.exe](https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/)
* [Persistence Using RunOnceEx - Hidden from Autoruns.exe](https://oddvar.moe/2018/03/21/persistence-using-runonceex-hidden-from-autoruns-exe/)
* [Phishing Against Protected View](https://enigma0x3.net/2017/07/13/phishing-against-protected-view/)
* [PowerPoint and Custom Actions](https://cofense.com/powerpoint-and-custom-actions/)
* [PowerShell Empire Stagers 1: Phishing With an Office Macro and Evading AVs](https://fzuckerman.wordpress.com/2016/10/06/powershell-empire-stagers-1-phishing-with-an-office-macro-and-evading-avs/)
* [PowerShell Without PowerShell - How To Bypass Application Whitelisting, Environment Restrictions & AV](https://www.blackhillsinfosec.com/powershell-without-powershell-how-to-bypass-application-whitelisting-environment-restrictions-av/)
* [Practical Guide to NTLM Relaying in 2017](https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html)
* [Process Doppleganging - A New Way to Impersonate A Process](https://hshrzd.wordpress.com/2017/12/18/process-doppelganging-a-new-way-to-impersonate-a-process/)
* [Putting Data In Alternate Data Streams and How to Execute It](https://oddvar.moe/2018/04/11/putting-data-in-alternate-data-streams-and-how-to-execute-it-part-2/)
* [Putting Data in Alternate Data Streams and How to Execute It](https://oddvar.moe/2018/01/14/putting-data-in-alternate-data-streams-and-how-to-execute-it/)
* [Red Team Insights on HTTPS Domain Fronting Google Hosts Using Cobalt Strike](https://www.cyberark.com/resources/threat-research-blog/red-team-insights-on-https-domain-fronting-google-hosts-using-cobalt-strike)
* [Red Team Operating in a Modern Environment](https://owasp.org/www-pdf-archive/Red_Team_Operating_in_a_Modern_Environment.pdf)
* [Roasting AS-REPs](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/)
* [SPN Discovery](https://pentestlab.blog/2018/06/04/spn-discovery/)
* [Scanning for Active Directory Privileges & Privileged Accounts](https://adsecurity.org/?p=3658)
* [Simple Domain Fronting PoC with GAE C2 Server](https://www.securityartwork.es/2017/01/31/simple-domain-fronting-poc-with-gae-c2-server/)
* [Spear Phishing 101](https://blog.inspired-sec.com/archive/2017/05/07/Phishing.html)
* [Targeted Kerberoasting](https://www.harmj0y.net/blog/activedirectory/targeted-kerberoasting/)
* [The Absurdly Underestimated Dangers of CSV Injection](http://georgemauer.net/2017/10/07/csv-injection.html)
* [The Most Dangerous User Right You Probably Have Never Heard Of](https://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/)
* [The PowerView PowerUsage Series #1 - Mass User Profile Enumeration](http://www.harmj0y.net/blog/powershell/the-powerview-powerusage-series-1/)
* [The PowerView PowerUsage Series #2 - Mapping Computer Shortnames With the Global Catalog](http://www.harmj0y.net/blog/powershell/the-powerview-powerusage-series-2/)
* [The PowerView PowerUsage Series #3 - Enumerating GPO Edit Rights In a Foreign Domain](http://www.harmj0y.net/blog/powershell/the-powerview-powerusage-series-3/)
* [The PowerView PowerUsage Series #4 - Finding Cross-Trust ACEs](http://www.harmj0y.net/blog/powershell/the-powerview-powerusage-series-4/)
* [Trust Direction: An Enabler for Active Directory Enumeration and Trust Exploitation](https://bohops.com/2017/12/02/trust-direction-an-enabler-for-active-directory-enumeration-and-trust-exploitation/)
* [Ultimate AppLocker ByPass List](https://github.com/api0cradle/UltimateAppLockerByPassList)
* [Userland API Monitoring and Code Injection Detection](https://0x00sec.org/t/userland-api-monitoring-and-code-injection-detection/5565)
* [Using SQL Server for Attacking a Forest Trust](http://www.labofapenetrationtester.com/2017/03/using-sql-server-for-attacking-forest-trust.html)
* [Using a SCF File to Gather Hashes](https://1337red.wordpress.com/using-a-scf-file-to-gather-hashes/)
* [Using robots.txt to Locate Your Targets](http://www.behindthefirewalls.com/2013/07/using-robotstxt-to-locate-your-targets.html)
* [Validated CloudFront SSL Domains](https://medium.com/@vysec.private/validated-cloudfront-ssl-domains-27895822cea3)
* [Vshadow: Abusing the Volume Shadow Service for Evasion, Persistence, and Active Directory Database Extraction](https://bohops.com/2018/02/10/vshadow-abusing-the-volume-shadow-service-for-evasion-persistence-and-active-directory-database-extraction/)
* [WMI Persistence with Cobalt Strike](https://blog.inspired-sec.com/archive/2017/01/20/WMI-Persistence.html)
* [WSH Injection: A Case Study](https://posts.specterops.io/wsh-injection-a-case-study-fd35f79d29dd)
* [Weaponizing Data Science for Social Engineering: Automated E2E Spear Phishing on Twitter](https://www.blackhat.com/docs/us-16/materials/us-16-Seymour-Tully-Weaponizing-Data-Science-For-Social-Engineering-Automated-E2E-Spear-Phishing-On-Twitter.pdf)
* [Week of Evading Microsoft ATA](http://www.labofapenetrationtester.com/2017/08/week-of-evading-microsoft-ata-day1.html)
* [Windows Access Tokens and Alternate Credentials](https://blog.cobaltstrike.com/2015/12/16/windows-access-tokens-and-alternate-credentials/)
* [Windows Defender Attack Surface Reduction Rules Bypass](https://oddvar.moe/2018/03/15/windows-defender-attack-surface-reduction-rules-bypass/)
* [Windows Oneliners to Download Remote Payload and Execute Arbitrary Code](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
* [Windows Privilege Escalation checklist](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
* [android-security-awesome](https://github.com/ashishb/android-security-awesome)
* [harmj0y Presentations and Blogs - Windows and Active Directory Exploitation](https://www.harmj0y.net/blog/)
* [mavinject.exe Functionality Deconstructed](https://posts.specterops.io/mavinject-exe-functionality-deconstructed-c29ab2cf5c0e)
* [sg1: swiss army knife for data encryption, exfiltration & covert communication](https://securityonline.info/sg1-swiss-army-knife/)
  

# Github Repositories (Need to Look Through)

* [Ethical Hacking Playground (Repo)](https://github.com/ethicalhackingplayground?tab=repositories)
* [Saeid](https://github.com/saeidshirazi?tab=repositories)
* [ustayready](https://github.com/ustayready?tab=repositories)
* [infosecn1nja](https://github.com/infosecn1nja?tab=repositories)
* [https://github.com/13o-bbr-bbq/machine_learning_security/wiki](https://github.com/13o-bbr-bbq/machine_learning_security/wiki)
- https://github.com/CyberSecurityUP/PenTest-Consulting-Creator
* [Red Team Infrastructure](https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki)

# Offensive Security Tools 

## Reconnaissance Tools 
Gathering information that can be used to support targeting

<br>

### Anonymity Tools
* [Freenet](https://freenetproject.org/) - Freenet is a peer-to-peer platform for censorship-resistant communication and publishing.
* [I2P](https://geti2p.net/en/) - The Invisible Internet Project.
* [OnionScan](https://onionscan.org/) - Tool for investigating the Dark Web by finding operational security issues introduced by Tor hidden service operators.
* [Tor](https://www.torproject.org/) - Free software and onion routed overlay network that helps you defend against traffic analysis.
* [What Every Browser Knows About You](http://webkay.robinlinus.com/) - Comprehensive detection page to test your own Web browser's configuration for privacy and identity leaks.

<hr>
<br>

### OSINT Frameworks
* [ReconSpider](https://hakin9.org/reconspider-most-advanced-open-source-intelligence-osint-framework/)
* [HostRecon](https://github.com/dafthack/HostRecon) — Provide situational awareness during reconnaissance of an engagement
* [reconFTW](https://github.com/six2dez/reconftw) — Automates the entire reconnaisance process
* [OSINT Repository](https://cipher387.github.io/osint_stuff_tool_collection/)
* [DarkSide](https://hakin9.org/darkside-tool-information-gathering-social-engineering/) — OSINT & Social Engineering Tool
* [AutoRecon](https://github.com/Tib3rius/AutoRecon) - Performs automated enumeration of services
* [Belati](https://github.com/aancw/Belati) - The Traditional Swiss Army Knife For OSINT. Belati is tool for Collecting Public Data & Public Document from Website and other service for OSINT purpose.
* [Intrigue Core](https://github.com/intrigueio/intrigue-core) - Framework for attack surface discovery.
* [NetBootcamp OSINT Tools](https://netbootcamp.org/osinttools/)
* [OSINT Framework](https://osintframework.com/)
* [Recon-ng](https://github.com/lanmaster53/recon-ng) - Full-featured Web Reconnaissance framework written in Python.
* [sn0int](https://github.com/kpcyrd/sn0int) - Semi-automatic OSINT framework and package manager.

<br>

### Search Engines
* [Shodan](https://www.shodan.io/) - Database containing information on all accessible domains on the internet obtained from passive scanning
* [Wigle](https://wigle.net/) - Database of wireless networks, with statistics
* [Binary Edge](https://www.binaryedge.io/) - Scans the internet for threat intelligence
* [ONYPHE](https://www.onyphe.io/) - Collects cyber-threat intelligence data
* [GreyNoise](https://www.greynoise.io/) - Search for devices connected to the internet
* [Censys](https://censys.io/) - Assessing attack surface for internet connected devices
* [Hunter](https://hunter.io/) - Search for email addresses belonging to a website
* [ZoomEye](https://www.zoomeye.org/) - Gather information about targets
* [LeakIX](https://leakix.net/) - Search publicly indexed information
* [IntelligenceX](https://intelx.io/) - Search Tor, I2P, data leaks, domains, and emails
* [Netlas](https://netlas.io/) - Search and monitor internet connected assets
* [URL Scan](https://urlscan.io/) - Free service to scan and analyse websites
* [PublicWWW](https://publicwww.com/) -  Marketing and affiliate marketing research
* [FullHunt](https://fullhunt.io/) - Search and discovery attack surfaces
* [crt.sh](https://crt.sh/) - Search for certs that have been logged by CT
* [Vulners](https://vulners.com/) - Search vulnerabilities in a large database
* [Pulsedive](https://pulsedive.com/) - Search for threat intelligence
* [Packet Storm Security](https://packetstormsecurity.com/) - Browse latest vulnerabilities and exploits
* [GrayHatWarefare](https://grayhatwarfare.com/) - Search public S3 buckets and URL shorteners
* [Dehashed](https://www.dehashed.com/) - Search for anything like username, email, passwords, address, or phone number.
* [Have I Been Pwned?](https://haveibeenpwned.com/) - Check whether personal data has been compromised by data breaches
* [Snusbase](https://snusbase.com/) - Indexes information from hacked websites and leaked databases
* [LeakBase](https://leakbase.cc/) - Forum of leaked databases
* [LeakCheck](https://leakcheck.io/) - Data breach search engine
* [GhostProject.fr](https://ghostproject.fr/) - Smart search engine
* [SecurityTrails](https://securitytrails.com/) - Extensive DNS data
* [DorkSearch](https://dorksearch.com/) - Really fast Google dorking
* [ExploitDB](https://www.exploit-db.com/) - Archive of various exploits
* [PolySwarm](https://polyswarm.io/) - Scan files and URLs for threats
* [DNSDumpster](https://dnsdumpster.com/) - Search for DNS records quickly
* [FullHunt](https://fullhunt.io/) - Search and discovery attack surfaces
* [AlienVault](https://otx.alienvault.com/) - Extensive threat intelligence feed
* [Vulners](https://vulners.com/) - Search vulnerabilities in a large database
* [WayBackMachine](https://web.archive.org/) - View content from deleted websites
* [SearchCode](https://searchcode.com/) - Search 75 billion lines of code from 40 million projects
* [Sarenka](https://hakin9.org/sarenka-an-osint-tool-that-gets-data-from-services-like-shodan-censys-etc-in-one-app/) — Gathers data from Shodan, censys, etc.


#### National Search Engines
Localized search engines by country

* [Alleba (Philippines)](https://www.alleba.com/)
* [Baidu (China)](https://www.baidu.com/)
* [Eniro (Sweden)](https://www.eniro.se/)
* [Goo (Japan)](https://www.goo.ne.jp/)
* [Najdsi (Slovenia)](http://www.najdi.si)
* [Naver (South Korea)](https://www.naver.com/)
* [Onet.pl (Poland)](https://www.onet.pl/)
* [Orange (France)](https://www.orange.fr/portail)
* [Parseek (Iran)](https://www.parseek.com/)
* [SAPO (Portugal)](https://www.sapo.pt/)
* [Search.ch (Switzerland)](https://www.search.ch/)
* [Walla (Israel)](https://www.walla.co.il/)
* [Yandex (Russia)](https://yandex.com/)

<br>

### Source Code Search
Search by website source code

* [NerdyData](https://www.nerdydata.com/) - Search engine for source code.
* [SearchCode](https://searchcode.com) - Help find real world examples of functions, API's and libraries across 10+ sources
* [Grep App](https://grep.app/) - Search for source code across a half million git repos

<br>

### Crypto OSINT
* [Bitcoin Abuse](https://www.bitcoinabuse.com/) - Database of wallets associated with ransomware, blackmailers and fraud.
* [Bitcoin Who's Who](https://bitcoinwhoswho.com/) - Database of known ID information from bitcoin addresses.
* [Blockchair](https://blockchair.com/) - Multiple blockchain explorer.
* [Wallet Explorer](https://www.walletexplorer.com/) - Finds all known associated bitcoin addresses from a single known address.
* [Orbit](https://github.com/s0md3v/Orbit) - Draws relationships between crypto wallets with recursive crawling of transaction history.

<br>

### Government Record Search
* [Blackbook](https://www.blackbookonline.info/index.html) - Public Records Starting Point.
* [FOIA Search](https://www.foia.gov/search.html) - Government information request portal.
* [PACER](https://pacer.uscourts.gov/) - Public Access to Federal Court Records.
* [RECAP](https://www.courtlistener.com/recap/) - Free version of PACER. Includes browser extensions for Chrome & Firefox.
* [SSN Validator](https://www.ssnvalidator.com/index.aspx) - Confirms valid Social Security Numbers.
  
<br>

### Social Media

* [Audiense](https://audiense.com/)
* [Blazent](https://www.blazent.com/)
* [Brandwatch](https://www.brandwatch.com)
* [Buffer](https://buffer.com)
* [Buzz sumo](https://buzzsumo.com/)
* [Geocreepy](http://www.geocreepy.com)
* [Geofeedia](https://geofeedia.com)
* [Hootsuite](https://www.hootsuite.com/)
* [Hashtatit](https://www.hashatit.com/)
* [Klear](https://klear.com/)
* [Kred](https://www.home.kred/)
* [SproutSocial](https://sproutsocial.com/)
* [Netvibes](https://www.netvibes.com/en)
* [OpinionCrawl](http://www.opinioncrawl.com)
* [Rival IQ](https://www.rivaliq.com)
* [RSS Social Analyzer](https://chrome.google.com/webstore/detail/rss-social-analyzer/ncmajlpbfckecekfamgfkmckbpihjfdn?hl=en)
* [SocialBakers](https://www.socialbakers.com/)
* [SociaBlade](http://socialblade.com)
* [Social DownORNot](http://social.downornot.com)
* [Social Searcher](https://www.social-searcher.com/)
* [Tagboard](https://tagboard.com)
* [Reputation Refinery](https://reputationrefinery.com/)
* [UVRX](http://www.uvrx.com/social.html)
* [Pushpin](https://github.com/DakotaNelson/pushpin-web) — Provides a web interface to keep track of geotagged social media activity

#### Twitter

* [Backtweets](http://backtweets.com)
* [Fake Follower Check](https://fakers.statuspeople.com)
* [First Tweet](https://ctrlq.org/first)
* [FirstTweet](https://about.twitter.com/#i_intelligence)
* [Foller.me](https://foller.me/)
* [FollowCheck](http://followcheck.com)
* [Followerwonk](https://followerwonk.com/)
* [GeoSocial Footprint](http://geosocialfootprint.com)
* [Geochirp](http://www.geochirp.com)
* [Gigatweeter](http://gigatweeter.com)
* [Ground Signal](https://www.groundsignal.com)
* [HappyGrumpy](https://www.happygrumpy.com)
* [Harvard TweetMap](http://worldmap.harvard.edu/tweetmap)
* [Hashtagify](https://hashtagify.me/)
* [Hashtags.org](https://www.hashtags.org/)
* [ManageFlitter](https://www.manageflitter.com/)
* [Mentionmapp](https://mentionmapp.com/)
* [OneMillionTweetMap](https://onemilliontweetmap.com/)
* [Rank Speed](https://rankspeed.com/)
* [Riffle](https://crowdriff.com/)
* [RiteTag](https://ritetag.com)
* [Schedule Warble](https://warble.co)
* [Sentiment140](http://www.twittersentiment.appspot.com)
* [Sleeping Time](http://sleepingtime.org)
* [Social Bearing](https://socialbearing.com/)
* [TruFan](https://www.trufan.io/)
* [Spoonbill](http://spoonbill.io)
* [TWUBS Twitter Chat](http://twubs.com/twitter-chats)
* [Tagdef](https://tagdef.com/en/)
* [Tinfoleak](https://tinfoleak.com)
* [Trends24](https://trends24.in/)
* [TrendsMap](https://www.trendsmap.com/)
* [TwChat](http://twchat.com)
* [Twazzup](http://new.twazzup.com/)
* [Tweet Tag](https://www.tweet-tag.com/)
* [TweetArchivist](http://www.tweetarchivist.com)
* [TweetDeck](https://tweetdeck.twitter.com/)
* [TweetMap](https://www.omnisci.com/demos/tweetmap)
* [TweetMap](http://worldmap.harvard.edu/tweetmap)
* [TweetPsych](http://tweetpsych.com)
* [TweetStats](http://www.tweetstats.com)
* [TweetTunnel](http://tweettunnel.com)
* [Tweetreach](https://tweetreach.com/)
* [Twellow](https://www.twellow.com/)
* [Tweriod](https://www.tweriod.com/)
* [Twiangulate](http://www.twiangulate.com/search/)
* [Twicsy](https://twicsy.com/)
* [Twilert](https://www.twilert.com/)
* [Twipho](http://www.twipho.net)
* [TwitRSS](https://twitrss.me)
* [Twitonomy](http://www.twitonomy.com)
* [Twitter Advanced Search](https://twitter.com/search-advanced?lang=en)
* [Twitter Audit](https://www.twitteraudit.com)
* [Twitter Chat Schedule](https://www.tweetreports.com/twitter-chat-schedule/)
* [Twitter Search](https://twitter.com/explore)
* [Twitterfall](https://twitterfall.com/)
* [burrrd.](https://burrrd.com)
* [doesfollow](https://doesfollow.com)

#### Facebook

* [Agora Pulse](https://barometer.agorapulse.com/home)
* [Commun.it](https://commun.it/)
* [ExtractFace](https://le-tools.com/)
* [Fanpage Karma](https://www.fanpagekarma.com/)
* [Facebook Search](https://www.facebook.com/help/821153694683665/)
* [Facebook Search Tool](https://netbootcamp.org/facebook.html)
* [FaceLIVE](https://www.facelive.org)
* [Fb-sleep-stats](https://github.com/sqren/fb-sleep-stats)
* [Find my Facebook ID](https://findmyfbid.in)
* [Lookup-ID.com](https://lookup-id.com)
* [SearchIsBack](https://searchisback.com)
* [Wallfux](https://clearinghouse.wallflux.com/)
* [Wolfram Alpha Facebook Report](https://www.wolframalpha.com/input/?i=facebook+report)
* [Zesty Facebook Search](http://zesty.ca/facebook/)
* [OsintStalker](https://github.com/milo2012/osintstalker) - Python script for Facebook and geolocation OSINT.

#### Instagram

* [Hashtagify](https://hashtagify.me/hashtag/wandavision)
* [Iconosquare](https://pro.iconosquare.com/)
* [Picodash](https://www.picodash.com)
* [SnapMap](https://snapmap.knightlab.com/)
* [Social Rank](https://socialrank.com/)
* [Worldcam](http://worldc.am)

#### Pinterest

* [Pingroupie](https://pingroupie.com/)

#### Reddit
Tools to help discover more about a reddit user or subreddit

* [Imgur](https://imgur.com/search) - The most popular image hosting website used by redditors.
* [Mostly Harmless](http://kerrick.github.io/Mostly-Harmless/#features) - Mostly Harmless looks up the page you are currently viewing to see if it has been submitted to reddit.
* [Reddit Archive](https://www.redditinvestigator.com/) - Historical archives of reddit posts.
* [Reddit Comment Search](https://redditcommentsearch.com/) - Analyze a reddit users by comment history.
* [Reddit Investigator](http://www.redditinvestigator.com) - Investigate a reddit users history.
* [Reddit Suite](https://chrome.google.com/webstore/detail/reddit-enhancement-suite/kbmfpngjjgdllneeigpgjifpgocmfgmb) - Enhances your reddit experience.
* [Reddit User Analyser](https://atomiks.github.io/reddit-user-analyser/) - reddit user account analyzer.
* [Subreddits](http://subreddits.org) - Discover new subreddits.


#### GitHub
- Octosuite — Gather OSINT on GitHub users
* [Github-dorks](https://github.com/techgaun/github-dorks) - CLI tool to scan github repos/organizations for potential sensitive information leak.
* [Zen](https://github.com/s0md3v/Zen) - Find email addresses of Github users.

#### LinkedIn
* [Raven](https://github.com/0x09AL/raven) - LinkedIn information gathering tool.

#### VKontakte (Russian) Search
Perform various OSINT on Russian social media site VKontakte

* [Barkov.net](https://vk.barkov.net/)
* [Report Tree](http://dcpu.ru/vk_repost_tree.php)
* [Snradar](http://snradar.azurewebsites.net) - Search pictures by time and location they were taken
* [Social Stats](http://socialstats.ru)
* [Target Hunter](https://targethunter.ru/)
* [Target Log](https://targetolog.com/)
* [VK Community Search](https://vk.com/communities)
* [VK Parser](http://vkparser.ru) - A tool to search for a target audience and potential customers.
* [VK People Search](https://vk.com/people)
* [VK to RSS Appspot](http://vk-to-rss.appspot.com/)
* [VK5](http://vk5.city4me.com)
* [Дезертир](https://vk.com/app3046467)

<br>

### Credentials 

* [Check User Names](https://checkusernames.com/)
* [Knowem](https://knowem.com/) - Search for a username on over 500 popular social networks.
* [Linkedin2Username](https://gitlab.com/initstring/linkedin2username) - Web scraper that uses valid LinkedIn credentials to put together a list of employees for a specified company.
* [Name Checkr](https://www.namecheckr.com/)
* [Name Checkup](https://namecheckup.com)
* [Name Chk](https://www.namechk.com/)
* [User Search](https://usersearch.org/index.php)

#### Breached Credentials
* [breach-parse](https://github.com/hmaverickadams/breach-parse): Tool for parsing breached passwords
* [emagnet](https://github.com/wuseman/EMAGNET) - Automated hacking tool that will find leaked databases.


<br>

### Email
* [BriteVerify Email Verification](https://www.validity.com/products/briteverify/email-list-verification/)
* [Datasploit](https://github.com/DataSploit/datasploit) - Tool to perform various OSINT techniques on usernames, emails addresses, and domains.
* [Email Address Validator](https://www.email-validator.net/)
* [Email Format](https://www.email-format.com/)
* [Email Permutator+](http://metricsparrow.com/toolkit/email-permutator)
* [EmailHippo](https://tools.verifyemailaddress.io)
* [EmailSearch.net](http://www.email-search.org/search-emails/)
* [FindEmails.com](https://www.findemails.com/)
* [Have I Been Pwned](https://haveibeenpwned.com) - Search across multiple data breaches to see if your email address has been compromised.
* [Hunter](https://hunter.io) - Hunter lets you find email addresses in seconds and connect with the people that matter for your business.
* [MOSINT] - OSINT Tool For Emails
* [MailSniper](https://github.com/dafthack/MailSniper) — Searches through email in a Microsoft Exchange environment for specific terms
* [MailTester](https://mailtester.com/en/single-email-verification)
* [MyCleanList](https://www.mycleanlist.com/)
* [Peepmail](http://www.samy.pl/peepmail)
* [Pipl](https://pipl.com)
* [ReversePhoneCheck](https://www.reversephonecheck.com/)
* [ThatsThem](https://thatsthem.com/reverse-email-lookup)
* [Verify Email](https://verify-email.org/)
* [VoilaNorbert](https://www.voilanorbert.com) - Find anyone's contact information for lead research or talent acquisition.
* [Zen](https://github.com/s0md3v/Zen) - Find email addresses of Github users.
* [h8mail](https://github.com/khast3x/h8mail) - Password Breach Hunting and Email OSINT, locally or using premium services. Supports chasing down related email
* [theHarvester](https://github.com/laramies/theHarvester) - E-mail, subdomain and people names harvester.

<br>

### Personal Investigations

* [192 (UK)](https://www.192.com/)
* [411 (US)](https://www.411.com/)
* [Alumni.net](https://www.alumni.net/)
* [Ancestry](https://www.ancestry.com/)
* [Been Verified](https://www.beenverified.com/) - Good accuracy, paid person search.
* [CVGadget](https://www.cvgadget.com/)
* [Canada411](https://www.canada411.ca/)
* [Cedar](https://cedar.buffalo.edu/AdServ/person-search.html)
* [Charlie App](https://www.detective.io/)
* [Classmates](https://www.classmates.com/)
* [CrunchBase](https://www.crunchbase.com/)
* [Data 24-7](https://www.data247.com/)
* [Family Search](https://www.familysearch.org/en/)
* [Family Tree Now](https://www.familytreenow.com/)
* [Federal Bureau of Prisons Inmate Locator (US)](https://www.bop.gov/inmateloc/) - Find an inmate that's in Federal prisons
* [Fold3 (US Military Records)](https://www.fold3.com/) - Browse records of US Military members.
* [Genealogy Bank](https://www.genealogybank.com/)
* [Genealogy Links](https://www.genealogylinks.net/)
* [Go Find Who](https://gofindwho.com/) - Multiple handy search tools.
* [Homemetry](https://homemetry.com)
* [Infobel](https://www.infobel.com/)
* [Infospace White Pages](https://infospace.com/home/white-pages)
* [Interment](http://www.interment.net/data/search.htm)
* [International White and Yellow Pages](http://www.wayp.com)
* [Itools](http://itools.com/search/people-search)
* [Kompass](https://us.kompass.com/)
* [Locate Family](https://www.locatefamily.com/) - Basicly a worldwide phonebook that can be manually searched. This site shows up as results on google.com so searches based on name, address, or phone number.
* [LookUpUK](http://www.lookupuk.com/main.html)
* [Lullar](https://com.lullar.com/)
* [MelissaDATA](https://www.melissa.com/v2/lookups/)
* [My Life People Search](https://www.mylife.com/reverse-people-search)
* [My Life](https://www.mylife.com/) - Paid people search with lots of results.
* [PeekYou](https://www.peekyou.com/)
* [People Search (Australia)](https://www.peoplesearch.com.au/)
* [PeopleSearch.net](http://www.peoplesearch.net)
* [Pipl](https://pipl.com)
* [Rapportive](https://business.linkedin.com/sales-solutions)
* [RecordsPedia](http://recordspedia.com)
* [Recruitem](http://recruitin.net)
* [Reunion](https://www.reunion.com/)
* [Rootsweb](https://home.rootsweb.com/)
* [SearchBug](https://www.searchbug.com/)
* [Skip Ease](https://www.skipease.com/)
* [SnoopStation](https://snoopstation.com/)
* [Sowdust Facebook Search](https://sowdust.github.io/fb-search/) - Facebook search tool.
* [Spokeo](https://www.spokeo.com/)
* [That's Them](https://thatsthem.com/) - Good accuracy, paid person search.
* [The National Archives (UK)](https://www.nationalarchives.gov.uk/)
* [USSearch](https://www.ussearch.com/)
* [WebMiii](https://webmii.com/)
* [White Pages (US)](https://www.whitepages.com/)
* [Wink](http://itools.com/tool/wink-people-search)
* [Yasni](http://www.yasni.com)
* [Zabasearch](https://www.zabasearch.com/)
* [Zoominfo](https://www.zoominfo.com/)
* [facesearch](http://facesaerch.com) - Search for images of a person by name.
* [snitch.name](http://www.snitch.name)
* [theHarvester](https://github.com/laramies/theHarvester) - E-mail, subdomain and people names harvester.

<br>

### Phone Number Research

* [National Cellular Directory](https://www.nationalcellulardirectory.com/) - Cell phone lookups. The lookup products including billions of records
* [Reverse Phone Lookup](https://www.reversephonelookup.com/) - Detailed information about phone carrier, region, service provider, and switch information.
* [Spy Dialer](https://spydialer.com/default.aspx) - Get the voicemail of a cell phone & owner name lookup.
* [Twilio](https://www.twilio.com/lookup) - Look up a phone numbers carrier type, location, etc.
* [Phone Validator](https://www.phonevalidator.com/index.aspx) - Pretty accurate phone lookup service, particularly good against Google Voice numbers.

<br>

### Company Research

* [AllStocksLinks](http://www.allstocks.com/links)
* [Battle of the Internet Giants](https://influencermarketinghub.com/battle-of-internet-giants)
* [Better Business Bureau](https://www.bbb.org/)
* [Bizeurope](http://www.bizeurope.com)
* [Bloomberg](https://www.bloomberg.com/markets/stocks)
* [Business Source](https://www.ebsco.com/products/research-databases/business-source-complete)
* [Bureau Van Dijk](https://www.bvdinfo.com/en-gb/)
* [Canadian Business Research](https://www.canada.ca/en/services/business/research.html)
* [Canadian Business Resource](http://www.cbr.ca)
* [Central and Eastern European Business Directory](https://globaledge.msu.edu/global-resources/resource/1274)
* [Company Registration Round the World](https://www.sg.ch/recht/handelsregister-notariate.html)
* [Company Research Resources by Country Comparably](https://www.comparably.com)
* [CompeteShark](https://competeshark.com/)
* [Corporate Information](https://www.corporateinformation.com/)
* [CrunchBase](https://www.crunchbase.com)
* [EDGAR Online](https://www.dfinsolutions.com/products/edgar-online)
* [Europages](https://www.europages.co.uk/)
* [European Business Register](https://ebra.be/)
* [Ezilon](http://www.ezilon.com)
* [Factiva](https://global.factiva.com)
* [Glassdoor](https://www.glassdoor.com/index.htm)
* [globalEdge](https://globaledge.msu.edu/)
* [GuideStar](https://www.guidestar.org/)
* [Hoovers](https://www.dnb.com/products/marketing-sales/dnb-hoovers.html)
* [Inc. 5000](https://www.inc.com/inc5000)
* [InstantLogoSearch](http://instantlogosearch.com)
* [iSpionage](https://www.ispionage.com/)
* [Knowledge guide to international company registration](https://www.icaew.com/library/subject-gateways/business-management/knowledge-guide-international-company-registration)
* [Linkedin](https://www.linkedin.com)
* [National Company Registers](https://en.wikipedia.org/wiki/List_of_official_business_registers)
* [Mergent Intellect](https://www.mergentintellect.com/)
* [Mergent Online](https://www.mergentonline.com/login.php)
* [Morningstar Research](http://library.morningstar.com)
* [Notablist](https://www.notablist.com)
* [Orbis directory](https://orbisdirectory.bvdinfo.com/version-20181213/OrbisDirectory/Companies/Login)
* [opencorporates](https://opencorporates.com)
* [Owler](https://corp.owler.com/)
* [Overseas Company Registers](https://www.gov.uk/government/publications/overseas-registries/overseas-registries)
* [Plunkett Research](http://www.plunkettresearchonline.com/Login.aspx)
* [Scoot](https://www.scoot.co.uk/)
* [SEMrush](https://www.semrush.com)
* [Serpstat](https://serpstat.com)
* [SpyFu](https://www.spyfu.com/)
* [Forbes Global 2000](https://www.forbes.com/global2000/)
* [Vault](https://www.vault.com/)
* [Xing](https://www.xing.com/)

<br>
<hr>

### Location
* [Creepy](https://github.com/ilektrojohn/creepy) - Geolocation OSINT tool.
* [OsintStalker](https://github.com/milo2012/osintstalker) - Python script for Facebook and geolocation OSINT.
* [Infosniper](https://www.infosniper.net/)
* [IP Location](https://www.iplocation.net/)
* [IP 2 Geolocation](http://ip2geolocation.com)
* [IP 2 Location](http://www.ip2location.com/demo.aspx)
* [IP Fingerprints](https://www.ipfingerprints.com/)

#### Wireless
- [ExifLooter](https://github.com/aydinnyunus/exifLooter) - Find geolocation on image URL and directories
- [Mozilla Stumbler](https://location.services.mozilla.com/)
- [Open Wifi Map](openwifimap.net)
- [WiGLE](https://wigle.net/) - Find wireless networks


#### Satellite Images
- [Bhuvan Indian Geo-Platform of ISRO](https://bhuvan-app3.nrsc.gov.in/data/download/index.php)
- [DigitalGlobe Open Data Program](https://www.maxar.com/open-data)
- [Geo-Airbus Defense](https://www.intelligence-airbusds.com/)
- [JAXA’s Global ALOS 3D World](https://www.eorc.jaxa.jp/ALOS/en/dataset/aw3d_e.htm)
- [NASA Earthdata Search](https://search.earthdata.nasa.gov/search)
- [NASA Worldview](https://www.intelligence-airbusds.com/)
- [NOAA CLASS](https://www.avl.class.noaa.gov/saa/products/welcome;jsessionid=17337A27F6C7E8333F05035A18C26DA6)
- [NOAA Data Access Viewer](https://coast.noaa.gov/dataviewer/#/)
- [NOAA Digital Coast](https://coast.noaa.gov/digitalcoast/)
- [National Institute for Space Research (INPE)](https://landsat.usgs.gov/CUB)
- [Sentinel Open Access Hub](https://scihub.copernicus.eu/dhus/#/home)
- [USGS Earth Explorer](https://earthexplorer.usgs.gov/)
- [VITO Vision](https://www.vito-eodata.be/PDF/portal/Application.html#Home)

<br>

### Image Search
* [GeoTag](https://vsudo.net/tools/geotag) — Discover location of pictures
* [Sherloq](https://github.com/GuidoBartoli/sherloq) — Open source forensic image analysis
* [exitLooter](https://github.com/aydinnyunus/exifLooter) - Find geolocation on image URL and directories
* [Baidu Images](https://image.baidu.com/)
* [Bing Images](https://www.bing.com/images/)
* [Flickr](https://flickr.com/)
* [Google Image](https://images.google.com)
* [Gramfeed](http://www.gramfeed.com/)
* [Image Identification Project](https://www.imageidentify.com/)
* [Image Raider](https://infringement.report/api/raider-reverse-image-search/)
* [KarmaDecay](http://karmadecay.com/)
* [Lycos Image Search](https://search.lycos.com/)
* [PhotoBucket](https://app.photobucket.com/explore)
* [PicTriev](http://www.pictriev.com/)
* [Picsearch](https://www.picsearch.com/)
* [TinEye](https://tineye.com) - Reverse image search engine.
* [Websta](https://websta.me/)
* [Worldcam](http://www.worldc.am)
* [Yahoo Image Search](https://images.search.yahoo.com)
* [Yandex Images](https://www.yandex.com/images)

<br>

### Dorking

* [BlogSearchEngine](http://www.blogsearchengine.org)
* [Catana-DS](https://github.com/TebbaaX/Katana) — Automates Google Dorking
* [GooDork](https://github.com/k3170makan/GooDork) - Command line Google dorking tool.
* [Google Adwords](https://ads.google.com/home/#!/) - Get monthly keyword volume data and stats.
* [Google Hacking Database](https://www.exploit-db.com/google-hacking-database) - Database of Google dorks; can be used for recon.
* [Google Trends](https://trends.google.com/trends/?geo=US) - See how many users are searching for specific keywords.
* [Keyword Discovery](https://www.keyworddiscovery.com/)
* [KeywordTool](https://keywordtool.io/)
* [Keyword Spy](https://www.keywordspy.com/)
* [Notey](https://www.notey.com/) - Blog post search engine.
* [Outbrain](https://www.outbrain.com/publishers/)
* [One Look Reverse Dictionary](https://www.onelook.com/reverse-dictionary.shtml)
* [Soovle](https://soovle.com/)
* [Twingly](https://www.twingly.com/)
* [Ubersuggest](https://neilpatel.com/ubersuggest/)
* [Dorksearch](https://dorksearch.com/) — Faster Google Dorking
* [GitHub Dork Helper](https://vsec7.github.io/)
* [Dork-cli](https://github.com/jgor/dork-cli) - Command line Google dork tool.
* [PaGoDo](https://github.com/opsdisk/pagodo) - Passive, automated Google dorking tool.
* [Word Tracker](https://www.wordtracker.com/)

#### Document & Slides Search

Search for data located on PDFs, Word documents, presentation slides, and more

* [Authorstream](http://www.authorstream.com)
* [Find-pdf-doc](http://www.findpdfdoc.com)
* [Free Full PDF](http://www.freefullpdf.com)
* [Offshore Leak Database](https://offshoreleaks.icij.org)
* [PDF Search Engine](http://www.pdfsearchengine.info)
* [RECAP](https://www.courtlistener.com/recap/)
* [Scribd](https://www.scribd.com/)
* [SlideShare](https://www.slideshare.net/)
* [Slideworld](http://www.slideworld.com)
* [soPDF.com](http://www.sopdf.com)

<br>

### Web History
* [Archive.is](https://archive.is/)
* [BlackWidow](https://softbytelabs.com/wp/blackwidow/)
* [CachedView](https://cachedview.com/)
* [CashedPages](http://www.cachedpages.com)
* [DNS History](http://dnshistory.org/) - DNS) Historical Record Archive
* [DomainTools](https://account.domaintools.com/log-in/)
* [Wayback Machine Archiver](https://github.com/jsvine/waybackpack)
* [Wayback Machine](https://archive.org/web/web.php) - Explore the history of a website.
<br>

### Web Monitoring
* [Alltop](https://alltop.com/)
* [Awasu](https://awasu.com/)
* [Bridge.Leslibres](https://bridge.leslibres.org/)
* [Bridge.Suumitsu](https://bridge.suumitsu.eu/)
* [ChangeDetect](https://www.changedetect.com/)
* [Deltafeed](https://bitreading.com/deltafeed/)
* [Feed43](https://feed43.com/)
* [FeedBooster](https://www.qsensei.com/)
* [Feed Exileed](http://feed.exileed.com/)
* [Feed Filter Maker](https://feed.janicek.co/)
* [Feedly](https://feedly.com/)
* [FeedReader](https://www.feedreader.com/)
* [FetchRSS](https://fetchrss.com/)
* [Flipboard](https://flipboard.com/)
* [FollowThatPage](https://www.followthatpage.com/)
* [Google Alerts](https://www.google.com/alerts) - A content change detection and notification service.
* [InfoMinder](https://app.infominder.com/webminder/)
* [Mention](https://mention.com/en/)
* [Netvibes](https://www.netvibes.com/en)
* [Newsblur](https://newsblur.com/)
* [OmeaReader](https://www.jetbrains.com/omea/reader/)
* [OnWebChange](https://onwebchange.com/)
* [Reeder](https://reederapp.com/)
* [RSS Bridge](https://bridge.suumitsu.eu)
* [RSS Feed Reader](https://chrome.google.com/webstore/detail/rss-feed-reader/pnjaodmkngahhkoihejjehlcdlnohgmp)
* [RSS Micro](http://www.rssmicro.com/)
* [RSS Search Engine](https://ctrlq.org/rss/)
* [RSS Search Hub](https://www.rsssearchhub.com/)
* [RSSOwl](https://www.rssowl.org/)
* [Selfoss](https://selfoss.aditu.de/)
* [Silobreaker](https://www.silobreaker.com/)
* [Talkwalker](https://www.talkwalker.com/)
* [The Old Reader](https://theoldreader.com/home)
* [versionista](https://versionista.com/)
* [visualping](https://visualping.io)
* [WebSite Watcher](https://www.aignes.com/index.htm)
* [Winds](https://winds.getstream.io/create-account)




#### Social Network Analysis

* [Gephi](https://gephi.org)
* [ORA](http://www.casos.cs.cmu.edu/projects/ora/software.php)
* [Sentinel Visualizer](https://fmsasg.com/)
* [Visual Investigative Scenarios](https://vis.occrp.org)
* [Wynyard Group](https://www.wynyardgroup.com/)


#### Network Reconnaissance Tools

* [ACLight](https://github.com/cyberark/ACLight) - Script for advanced discovery of sensitive Privileged Accounts - includes Shadow Admins.
* [BuiltWith](https://builtwith.com/) - Technology lookup tool for websites.
* [CloudFail](https://github.com/m0rtem/CloudFail) - Unmask server IP addresses hidden behind Cloudflare by searching old database records and detecting misconfigured DNS.
* [LdapMiner](https://sourceforge.net/projects/ldapminer/) - Multiplatform LDAP enumeration utility.
* [Mass Scan](https://github.com/robertdavidgraham/masscan) - TCP port scanner, spews SYN packets asynchronously, scanning entire Internet in under 5 minutes.
* [Netdiscover](https://github.com/alexxy/netdiscover) - Simple and quick network scanning tool.
* [Pentest-Tools](https://pentest-tools.com/home) - Online suite of various different pentest related tools.
* [Ruler](https://github.com/sensepost/ruler) - Tool for remotely interacting with Exchange servers.
* [Shodan](https://www.shodan.io/) - Database containing information on all accessible domains on the internet obtained from passive scanning.
* [Spyse](https://spyse.com/) - Web research services that scan the entire internet using OSINT, to simplify the investigation of infrastructure and attack surfaces.
* [Spyse.py](https://github.com/zeropwn/spyse.py) - Python API wrapper and command-line client for the tools hosted on spyse.com.
* [Sublist3r](https://github.com/aboul3la/Sublist3r) - Subdomain enumeration tool for penetration testers.
* [ldapsearch](https://linux.die.net/man/1/ldapsearch) - Linux command line utility for querying LDAP servers.
* [nmap](https://nmap.org/) - Free security scanner for network exploration & security audits.
* [pyShodan](https://github.com/GoVanguard/pyShodan) - Python 3 script for interacting with Shodan API (requires valid API key).
* [smbmap](https://github.com/ShawnDEvans/smbmap) - Handy SMB enumeration tool.
* [xprobe2](https://linux.die.net/man/1/xprobe2) - Open source operating system fingerprinting tool.
* [zmap](https://zmap.io/) - Open source network scanner that enables researchers to easily perform Internet-wide network studies.
  



### Domain
* [Ahrefs](https://ahrefs.com) - A tool for backlink research, organic traffic research, keyword research, content marketing & more.
* [Amass](https://github.com/caffix/amass) - Performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
* [Backlink Discovery](https://app.neilpatel.com/en/seo_analyzer/backlinks) — Find backlinks, Referring domains, Link history, etc.
* [Central Ops](https://centralops.net/co/)
* [Datasploit](https://github.com/DataSploit/datasploit) - Tool to perform various OSINT techniques on usernames, emails addresses, and domains.
* [Domain Dossier](https://centralops.net/co/DomainDossier.aspx)
* [Domain Investigation Toolbox](https://cipher387.github.io/domain_investigation_toolbox/) — Gather information about the target domain name
* [Domain Tools](https://whois.domaintools.com/) - Whois lookup and domain/ip historical data.
* [Easy whois](https://www.easywhois.com)
* [Exonera Tor](https://metrics.torproject.org/exonerator.html) - A database of IP addresses that have been part of the Tor network. It answers the question whether there was a Tor relay running on a given IP address on a given date.
* [FindFrontableDomains](https://github.com/rvrsh3ll/FindFrontableDomains) - Multithreaded tool for finding frontable domains.
* [GooFuzz](https://github.com/m3n0sd0n4ld/GooFuzz) — Perform fuzzing with an OSINT approach, managing to enumerate directories, files, subdomains or parameters without leaving evidence on the target's server and by means of advanced Google searches
* [HaxUnit](https://github.com/Bandit-HaxUnit/haxunit) — Combines multiple active/passive subdomain enumeration tools and port scanning
* [IP Address.com](https://www.ipaddress.com/)
* [IP Neighboring](https://www.ip-neighbors.com/) — Discover Neighboring IP Hosts
* [IP Void](https://www.ipvoid.com/)
* [InfoByIp](https://www.infobyip.com/ipbulklookup.php) - Domain and IP bulk lookup tool.
* [Investigator](https://abhijithb200.github.io/investigator/) — Quickly check & gather information about the target domain name
* [Link-JS](https://github.com/ethicalhackingplayground/linkJS) — Fetch links from JS w/ Subfinder
* [Meg](https://github.com/tomnomnom/meg) - Quickly find hidden paths/directories without flooding traffic
* [Squatm3gator](https://github.com/david3107/squatm3gator) - Enumerate available domains generated modifying the original domain name through different cybersquatting techniques
* [Verisign](https://dnssec-analyzer.verisignlabs.com/)
* [Website Informer](https://website.informer.com/)
* [w3snoop](https://webboar.com.w3snoop.com/)


#### Blacklisting
* [AbuseIPDB](https://www.abuseipdb.com/) - Search engine for blacklisted IPs or domains.
* [AutoShun](https://riskanalytics.com/community/) - Public repository of malicious IPs and other resources.
* [BadIPs](https://www.badips.com/) - Online blacklist lookup.
* [Binary Defense IP Ban List](https://www.binarydefense.com/banlist.txt) - Public IP blacklist.
* [Blocklist Ipsets](https://github.com/firehol/blocklist-ipsets) - Public IP blacklist.
* [Malc0de DNSSinkhole](http://malc0de.com/bl/) - List of domains that have been identified as distributing malware during the past 30 days.
* [Spamcop](https://www.spamcop.net/bl.shtml) - IP based blacklist.
* [Spamhaus](https://www.spamhaus.org/lookup/) - Online blacklist lookup.
  


#### URL

* [Assetfinder](https://github.com/tomnomnom/assetfinder): Find domains and subdomains potentially related to a given domain
* [Astra](https://github.com/Sachin-v3rma/Astra) — Finds API keys, URLs, AWS Buckets, etc.
* [Awesome Hacker Search Engines](https://github.com/edoardottt/awesome-hacker-search-engines) — CVEs, Domains, Addresses, Certifications, Credentials, etc.
* [Censys](https://censys.io/) - Collects data on hosts and websites through daily ZMap and ZGrab scans.
* [ExitLooter](https://github.com/aydinnyunus/exifLooter) - Find geolocation on image URL and directories
* [Grey Noise](https://www.greynoise.io/) — Trace IPs, URLs, etc.
* [Js-parse](https://github.com/l4yton/js-parse) — Looks through javascript files in a given directory and finds subdomains, URLs, parameters, custom headers, and API keys
* [Majestic](https://majestic.com) - Find out who links to your website
* [Phonebook](https://phonebook.cz/) — Lists all domains, email addresses, URL for the target domain
* [PowerMeta](https://github.com/dafthack/PowerMeta) — Searches for publicly available files hosted on webpages for a particular domain
* [URLVoid](https://www.urlvoid.com/) - Analyzes a website through multiple blacklist engines and online reputation tools to facilitate the detection of fraudulent and malicious websites.
* [WhereGoes](https://wheregoes.com/) — URL Redirect Checker


**Backlinks**
* [Link Explorer](https://moz.com/link-explorer)
* [Open Link Profiler](https://www.openlinkprofiler.org/)
* [WebMeUp](https://webmeup.com/)

**Finding Broken Links**

* [SocialHunter](https://github.com/utkusen/socialhunter) — Crawls the given URL and finds broken social media links that can be hijacked
* [Redirect Detective](https://redirectdetective.com/)



#### DNS / WHOIS
* [DNS Dumpster](https://dnsdumpster.com/) - Search for DNS records quickly
* [DNS History](http://dnshistory.org/) - DNS) Historical Record Archive
* [DNSrr](https://github.com/A3h1nt/Dnsrr) — Enumerate all information from DNS records
* [DNSenum](https://github.com/fwaeytens/dnsenum/) - Perl script that enumerates DNS information from a domain, attempts zone transfers, performs a brute force dictionary style attack, and then performs reverse look-ups on the results.
* [DNSmap](https://github.com/makefu/dnsmap/) - Passive DNS network mapper.
* [DNSrecon](https://github.com/darkoperator/dnsrecon/) - DNS enumeration script.
* [DNStracer](http://www.mavetju.org/unix/dnstracer.php) - Determines where a given DNS server gets its information from, and follows the chain of DNS servers.
* [DNSviz](https://dnsviz.net/)
* [IP Spy](https://ipspy.net/) - IP Lookup, WHOIS, and DNS resolver
* [IQ WHOIS](https://iqwhois.com/advanced-search) — Advanced WHOIS Search
* [Passivedns-client](https://github.com/chrislee35/passivedns-client) - Library and query tool for querying several passive DNS providers.
* [Passivedns](https://github.com/gamelinux/passivedns) - Network sniffer that logs all DNS server replies for use in a passive DNS setup.
* [WhoisFreaks](https://whoisfreaks.com/) — WHOIS Discovery
* [dnsenum](https://github.com/fwaeytens/dnsenum) — Script that enumerates DNS information
* [Into DNS](https://intodns.com/)
* [IP Checking](https://www.ipchecking.com/)
* [Kloth](http://www.kloth.net/services/)
* [Network Tools](https://network-tools.com/)
* [MXToolbox](https://mxtoolbox.com/) - MX record lookup tool.
* [Remote DNS Lookup](https://remote.12dt.com)
* [Robtex](https://www.robtex.com/)
* [SecurityTrails](https://securitytrails.com/dns-trails) - API to search current and historical DNS records, current and historical WHOIS, technologies used by sites and whois search for phone, email, address, IPs etc.
* [Who.is](https://who.is/) - Domain whois information.
* [Whois Arin Online](https://whois.arin.net/ui/)
* [WhoIsHostingThis](https://www.whoishostingthis.com/)
* [Whoisology](https://whoisology.com)
* [WhoIsRequest](https://whoisrequest.com/)


#### Favicon
* [FavFreak](https://github.com/devanshbatham/FavFreak) -  Fetches the favicon.ico and hash value and generates shodan dorks

#### Cloud
* [CloudFrunt](https://github.com/MindPointGroup/cloudfrunt) - Tool for identifying misconfigured CloudFront domains.
  
<br>

### Vulnerability Scanners
* [Nmap](https://nmap.org/)
* [AngryIP](https://angryip.org/)
* [PRTG](https://www.paessler.com/tools)
* [Spidex](https://github.com/alechilczenko/spidex) — Find Internet-connected devices
* [BurpSuite](https://portswigger.net/burp)
* [Trend Micro Hybrid Cloud Security](https://www.g2.com/products/trend-micro-hybrid-cloud-security/reviews)
* [Orca Security](https://orca.security/)
* [InsightVM](https://www.rapid7.com/products/insightvm/?utm_source=google&utm_medium=cpc&utm_campaign=NA_Brand_BOF_GSN_EN&utm_term=insightvm&_bt=600185603260&_bm=e&_bn=g&gclid=CjwKCAjwvsqZBhAlEiwAqAHElXcGdtMkjJdBeeSLPL-Sox66izRyW1oy0EP3tYBAh7-Rgte3_yzQVRoCZhEQAvD_BwE)
* [Qualys](https://www.qualys.com/)
* [Nginxpwner] - Tool to look for common Nginx misconfigurations and vulnerabilities
* [Nikto](https://cirt.net/Nikto2)
* [Nrich](https://gitlab.com/shodan-public/nrich) - Quickly analyze IPs and determines open ports / vulnerabilities
* [Uncover](https://github.com/projectdiscovery/uncover) - Quickly discover exposed hosts on the internet using shodan, censys and fofa
* [scanless](https://github.com/vesche/scanless) — Websites that performs port scans on your behalf
* [Naabu](https://github.com/projectdiscovery/naabu) - Enumerate valid ports conducting a SYN/CONNECT scans on the host(s) ports that return a reply

#### Web Scanners
* [BurpSuite](https://portswigger.net/burp)
* [ACSTIS](https://github.com/tijme/angularjs-csti-scanner) - Automated client-side template injection (sandbox escape/bypass) detection for AngularJS.
* [BuiltWith](https://builtwith.com/)
* [Burp Suite](https://portswigger.net/burp) - Commercial web vulnerability scanner, with limited community edition.
* [cms-explorer](https://code.google.com/archive/p/cms-explorer/) - Reveal the specific modules, plugins, components and themes that various websites powered by content management systems are running.
* [Netsparker Web Application Security Scanner](https://www.netsparker.com/) - Commercial web application security scanner to automatically find many different types of security flaws.
* [Nikto](https://cirt.net/nikto2) - Noisy but fast black box web server and web application vulnerability scanner.
* [Observatory](https://observatory.mozilla.org/) - Free online web scanning utility.
* [OWASP Zed Attack Proxy (ZAP)](https://owasp.org/www-project-zap/) - Feature-rich, scriptable HTTP intercepting proxy and fuzzer for penetration testing web applications.
* [Security Headers](https://securityheaders.com/) - Free online utility for checking a website's HTTP headers for security vulnerabilities.
* [SQLmate](https://github.com/s0md3v/sqlmate) - A friend of sqlmap that identifies sqli vulnerabilities based on a given dork and website (optional).
* [WPScan](https://wpscan.com/wordpress-security-scanner) - Black box WordPress vulnerability scanner.
* [Follow.net](https://follow.net/)
* [HypeStat](https://hypestat.com/)
* [StatsCrop](https://www.statscrop.com/)
* [Netcraft Site Report](https://sitereport.netcraft.com/)
* [Wappalyzer](https://www.wappalyzer.com/)


**API Keys**
* [Clickjacker](https://serene-agnesi-57a014.netlify.app/) — Discover secret API Keys
* [js-parse](https://github.com/l4yton/js-parse) — Looks through javascript files in a given directory and finds subdomains, URLs, parameters, custom headers, and API keys
* [Astra](https://github.com/Sachin-v3rma/Astra) — Finds API keys, URLs, AWS Buckets, etc.



**Web Cookies**
* [CookieServe](https://www.cookieserve.com/) — Cookie Checker Tool for Websites


**Missing Headers**
* [securityheader.com](http://securityheader.com) — Reports headers that are missing; Exploitable



#### Web Exploitation
* [Browser Exploitation Framework (BeEF)](https://github.com/beefproject/beef) - Command and control server for delivering exploits to commandeered Web browsers.
* [Commix](https://github.com/commixproject/commix) - Automated all-in-one operating system command injection and exploitation tool.
* [Drupwn](https://github.com/immunIT/drupwn/) - Drupal web application exploitation tool.
* [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness) - Tool to take screenshots of websites, provide some server header info, and identify default credentials if possible.
* [fimap](https://github.com/kurobeats/fimap) - Find, prepare, audit, exploit and even Google automatically for LFI/RFI bugs.
* [FuzzDB](https://github.com/fuzzdb-project/fuzzdb) - Dictionary of attack patterns and primitives for black-box application fault injection and resource discovery.
* [IIS-Shortname-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner) - Command line tool to exploit the Windows IIS tilde information disclosure vulnerability.
* [Kadabra](https://github.com/D35m0nd142/Kadabra) - Automatic LFI exploiter and scanner.
* [Kadimus](https://github.com/P0cL4bs/Kadimus) - LFI scan and exploit tool.
* [LFISuite](https://github.com/D35m0nd142/LFISuite) - A tool designed to exploit Local File Include vulnerabilities.
* [libformatstr](https://github.com/hellman/libformatstr) - Python script designed to simplify format string exploits.
* [liffy](https://github.com/hvqzao/liffy) - LFI exploitation tool.
* [lyncsmash](https://github.com/nyxgeek/lyncsmash) - A collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations
* [NoSQLmap](https://github.com/codingo/NoSQLMap) - Automatic NoSQL injection and database takeover tool.
* [SQLmap](http://sqlmap.org/) - Automated SQL injection and database takeover tool.
* [sqlninja](http://sqlninja.sourceforge.net/) - Automated SQL injection and database takeover tool.
* [sslstrip2](https://github.com/LeonardoNve/sslstrip2) - SSLStrip version to defeat HSTS.
* [sslstrip](https://github.com/moxie0/sslstrip) - Demonstration of the HTTPS stripping attacks.
* [tplmap](https://github.com/epinna/tplmap) - Automatic server-side template injection and Web server takeover tool.
* [VHostScan](https://github.com/codingo/VHostScan) - A virtual host scanner that performs reverse lookups, can be used with pivot tools, detect catch-all scenarios, aliases and dynamic default pages.
* [wafw00f](https://github.com/EnableSecurity/wafw00f) - Identifies and fingerprints Web Application Firewall (WAF) products.
* [webscreenshot](https://github.com/maaaaz/webscreenshot) - A simple script to take screenshots from a list of websites.
* [weevely3](https://github.com/epinna/weevely3) - Weaponized web shell.
* [Wordpress Exploit Framework](https://github.com/rastating/wordpress-exploit-framework) - Ruby framework for developing and using modules which aid in the penetration testing of WordPress powered websites and systems.
* [WPSploit](https://github.com/espreto/wpsploit) - Exploit WordPress-powered websites with Metasploit.
* [Fuxploiter](https://hakin9.org/fuxploider-a-file-upload-vulnerability-scanner/) — Detecting and exploiting file upload forms flaws


#### Extensions
* [AutoScanWithBurp](https://bitbucket.org/clr2of8/autoscanwithburp/src/master/) — Extension to perform automated & authenticated scans against URLS
* [OAuthScan](https://github.com/PortSwigger/oauth-scan) - Burp Suite Extension written in Java with the aim to provide some automatic security checks
* [Mitaka](https://hakin9.org/mitaka-a-browser-extension-for-osint/) — Browser extension for OSINT






## Resource Development Tools
Creating, purchasing, or compromising resources that can be used to support targeting

### Pentesting OS Distributions
* [ArchStrike](https://archstrike.org/) - Arch GNU/Linux repository for security professionals and enthusiasts.
* [AttifyOS](https://github.com/adi0x90/attifyos) - GNU/Linux distribution focused on tools useful during Internet of Things (IoT) security assessments.
* [BackBox](https://www.backbox.org/) - Ubuntu-based distribution for penetration tests and security assessments.
* [BlackArch](https://www.blackarch.org/) - Arch GNU/Linux-based distribution for penetration testers and security researchers.
* [Buscador](https://inteltechniques.com/buscador/) - GNU/Linux virtual machine that is pre-configured for online investigators.
* [Fedora Security Lab](https://labs.fedoraproject.org/en/security/) - Provides a safe test environment to work on security auditing, forensics, system rescue and teaching security testing methodologies.
* [Kali](https://www.kali.org/) - GNU/Linux distribution designed for digital forensics and penetration testing.
* [Network Security Toolkit (NST)](https://networksecuritytoolkit.org/nst/index.html) - Fedora-based bootable live operating system designed to provide easy access to best-of-breed open source network security applications.
* [Parrot Security OS](https://www.parrotsec.org/) - Distribution similar to Kali using the same repositories, but with additional features such as Tor and I2P integration.
* [The Pentesters Framework](https://github.com/trustedsec/ptf) - Distro organized around the Penetration Testing Execution Standard (PTES), providing a curated collection of utilities that eliminates often unused toolchains.


* [LOTS Project](https://lots-project.com/) — Websites that allows attackers to use their domain when conducting phishing, C2, exfiltration, and downloading tools to evade detection






### Hardware
* [Flipper Zero](https://flipperzero.one/)
* [LAN Turtle](https://shop.hak5.org/products/lan-turtle) - Covert "USB Ethernet Adapter" that provides remote access, network intelligence gathering, and MITM capabilities when installed in a local network.
* [PCILeech](https://github.com/ufrisk/pcileech) - Uses PCIe hardware devices to read and write from the target system memory via Direct Memory Access (DMA) over PCIe.
* [Poisontap](https://samy.pl/poisontap/) - Siphons cookies, exposes internal (LAN-side) router and installs web backdoor on locked computers.
* [Proxmark3](https://proxmark3.com/) - RFID/NFC cloning, replay, and spoofing toolkit often used for analyzing and attacking proximity cards/readers, wireless keys/keyfobs, and more.
* [USB Rubber Ducky](https://shop.hak5.org/products/usb-rubber-ducky-deluxe) - Customizable keystroke injection attack platform masquerading as a USB thumbdrive.
* [WiFi Pineapple](https://shop.hak5.org/products/wifi-pineapple) - Wireless auditing and penetration testing platform.

#### Lockpicking Resources
* [/r/lockpicking Subreddit](https://www.reddit.com/r/lockpicking/) - Subreddit dedicated to the sport of lockpicking.
* [Keypicking.com](https://keypicking.com/) - Bustling online forum for the discussion of lockpicking and locksport.
* [LockWiki](http://lockwiki.com/index.php/Main_Page) - Community-driven reference for both beginners and professionals in the security industry.
* [Lockpicking Forensics](http://www.lockpickingforensics.com/) - Website "dedicated to the science and study of forensic locksmithing."
* [Lockpicking101.com](https://www.lockpicking101.com/) - One of the longest-running online communities "dedicated to the fun and ethical hobby of lock picking."
* [The Amazing King's Lockpicking pages](http://theamazingking.com/lockpicking.php) - Hobbyist's website with detailed pages about locks, tools, and picking techniques.

### CLI Usability
* [Bat](https://github.com/sharkdp/bat) — Advanced syntax highlighting
* [fzf](https://github.com/junegunn/fzf) — General purpose command-line fuzzy finder
* [exa](https://github.com/ogham/exa) — Advanced replacement for `ls`
* [macOS Terminal (zsh) — The Beginner’s Guide](https://www.youtube.com/watch?v=ogWoUU2DXBU)



## Initial Access Tools
Various entry vectors to gain your initial foothold within a network

### Phishing
* [CredSniper](https://github.com/ustayready/CredSniper) — Launch phishing site
* [PyPhisher](https://hakin9.org/pyphisher-easy-to-use-phishing-tool-with-65-website-templates/) — Phishing website templates
* [Fake-SMS](https://www-hackers--arise-com.cdn.ampproject.org/c/s/www.hackers-arise.com/amp/social-engineering-attacks-creating-a-fake-sms-message) — Create SMS messages
- C2
    * [Tyk.io](https://shells.systems/oh-my-api-abusing-tyk-cloud-api-management-service-to-hide-your-malicious-c2-traffic/) — Route C2 traffic
* [EvilNoVNC](https://github.com/JoelGMSec/EvilnoVNC) - Ready to go Phishing Platform
* [Zphishper](https://github.com/htr-tech/zphisher) - Automated phishing tool
* [AdvPhishing] - This Is Advance Phishing Tool! OTP PHISHING
* [DarkSide](https://hakin9.org/darkside-tool-information-gathering-social-engineering/) — OSINT & Social Engineering Tool
* [mip22](https://github.com/makdosx/mip22) - Advanced phishing tool
* [PhishStats](https://phishstats.info/#) - gathering, enhancing and sharing phishing information with the infosec community.

* [CiLocks] - Android LockScreen Bypass
* [Android-PIN-Bruteforce] - Unlock An Android Phone (Or Device) By Bruteforcing The Lockscreen PIN

### Social Engineering Tools
* [Beelogger](https://github.com/4w4k3/BeeLogger) - Tool for generating keylooger.
* [Catphish](https://github.com/ring0lab/catphish) - Tool for phishing and corporate espionage written in Ruby.
* [Evilginx](https://github.com/kgretzky/evilginx2) - MITM attack framework used for phishing credentials and session cookies from any Web service
* [Gophish](https://getgophish.com/) - Open-Source Phishing Framework
* [King Phisher](https://github.com/rsmusllp/king-phisher) - Phishing campaign toolkit used for creating and managing multiple simultaneous phishing attacks with custom email and server content.
* [Lucy Phishing Server](https://lucysecurity.com/) - (commercial) tool to perform security awareness trainings for employees including custom phishing campaigns, malware attacks etc. Includes many useful attack templates as well as training materials to raise security awareness.
* [PhishingFrenzy](https://www.phishingfrenzy.com/) - Phishing Frenzy is an Open Source Ruby on Rails application that is leveraged by penetration testers to manage email phishing campaigns.
* [SET](https://github.com/trustedsec/social-engineer-toolkit) - The Social-Engineer Toolkit from TrustedSec
* [wifiphisher](https://github.com/wifiphisher/wifiphisher) - Automated phishing attacks against Wi-Fi networks
* [Canary Tokens](https://canarytokens.org/generate#) - Generate tokens to automatically alert users when triggered. 


## Execution Tools
Attacker-controlled code running on a local or remote system

### C2 Frameworks
Communicating with systems under your control within a victim network


* [Browser Exploitation Framework (BeEF)](https://beefproject.com/) — Recovering web session information and exploiting client-side scripting
* [Brute Ratel](https://bruteratel.com/) - A customized C2 center for Red Team and Adversary Simulation
* [Cobalt Strike](https://www.cobaltstrike.com/) — Adversary simulations & red team operations
* [Covenant](https://github.com/cobbr/Covenant) — .NET C2 framework
* [Emp3R0R](https://github.com/jm33-m0/emp3r0r) - Linux post-exploitation framework 
* [GithubC2](https://github.com/D1rkMtr/githubC2/tree/main) - Using Github as a C2
* [HazProne](https://securityonline.info/hazprone-cloud-pentesting-framework/) — Cloud Pentesting Framework
* [Lockdoor Framework](https://github.com/SofianeHamlaoui/Lockdoor-Framework) — Framework that automates pentesting tools
* [Metasploit](https://www.metasploit.com/)
* [Notion Term](https://github.com/ariary/notionterm) — Embed reverse shell in Notion pages
* [Octopus](https://www.kitploit.com/2022/05/octopus-open-source-pre-operation-c2.html) — Pre-operation C2 server
* [Pacu](https://rhinosecuritylabs.com/aws/pacu-open-source-aws-exploitation-framework/) — Scanning and exploit tools for reconnaissance and exploitation of Amazon Web Service (AWS) accounts
* [Recon-ng](https://github.com/lanmaster53/recon-ng) — Full reconnaissance framework to conduct open source web-based recon
* [SilentTrinity](https://github.com/byt3bl33d3r/SILENTTRINITY) — Asynchronous, multiplayer, & multiserver C2 framework
* [Silver](https://github.com/BishopFox/sliver) — Open source cross-platform red team framework
* [Sn1per](https://github.com/1N3/Sn1per) — All in one pentesting framework
* [Zed Attack Proxy (ZAP)](https://owasp.org/www-project-zap/) — Scanning tools and scripts for web application and mobile app security testing
Exfiltration Tools -- Stealing data from victim's infrastructure

### Multi-Paradigm Frameworks
  * [Armitage](http://www.fastandeasyhacking.com/) - Java-based GUI front-end for the Metasploit Framework.
  * [AutoSploit](https://github.com/NullArray/AutoSploit) - Automated mass exploiter, which collects target by employing the Shodan.io API and programmatically chooses Metasploit exploit modules based on the Shodan query.
  * [Faraday](https://github.com/infobyte/faraday) - Multiuser integrated pentesting environment for red teams performing cooperative penetration tests, security audits, and risk assessments.
  * [Habu Hacking Toolkit](https://github.com/fportantier/habu) - Unified set of tools spanning passive reconnaissance, network attacks, social media monitoring, and website fingerprinting.
  * [Mad-Metasploit](https://www.hahwul.com/p/mad-metasploit.html) - Additional scripts for Metasploit.
  * [Metasploit](https://www.metasploit.com/) - Software for offensive security teams to help verify vulnerabilities and manage security assessments.
  * [Mobile Security Framework (MobSF)](https://github.com/MobSF/Mobile-Security-Framework-MobSF/) - Automated mobile application pentesting framework capable of static analysis, dynamic analysis, malware analysis, and web API testing.
  * [Pupy](https://github.com/n1nj4sec/pupy) - Cross-platform (Windows, Linux, macOS, Android) remote administration and post-exploitation tool.
  * [Rupture](https://github.com/dionyziz/rupture) - Multipurpose tool capable of man-in-the-middle attacks, BREACH attacks and other compression-based crypto attacks.


### Post-Exploitation
* [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec/) - Multipurpose post-exploitation suite containing many plugins.
* [DBC2](https://github.com/Arno0x/DBC2/) - Multipurpose post-exploitation tool.
* [Empire](https://github.com/EmpireProject/Empire/) - PowerShell based (Windows) and Python based (Linux/OS X) post-exploitation framework.
* [EvilOSX](https://github.com/Marten4n6/EvilOSX/) - macOS backdoor with docker support.
* [Fathomless](https://github.com/xor-function/fathomless) - A collection of post-exploitation tools for both Linux and Windows systems.
* [FruityC2](https://github.com/xtr4nge/FruityC2/) - Open source, agent-based post-exploitation framework with a web UI for management.
* [Koadic](https://github.com/zerosum0x0/koadic) - Windows post-exploitation rootkit, primarily utilizing Windows Script Host.
* [PlugBot](https://www.redteamsecure.com/research/plugbot-hardware-botnet-research) - Can be installed onto an ARM device for Command & Control use and more.
* [Portia](https://github.com/milo2012/portia) - Automated post-exploitation tool for lateral movement and privilege escalation.
* [ProcessHider](https://github.com/M00nRise/ProcessHider/) - Post-exploitation tool for hiding processes.
* [Pupy](https://github.com/n1nj4sec/pupy/) - Open source cross-platform post-exploitation tool, mostly written in Python.
* [RemoteRecon](https://github.com/xorrior/RemoteRecon/) - Post-exploitation utility making use of multiple agents to perform different tasks.
* [TheFatRat](https://github.com/Exploit-install/TheFatRat) - Tool designed to generate remote access trojans (backdoors) with msfvenom.arch-project/) - Can be installed onto an ARM device for Command & Control use and more.
* [p0wnedShell](https://github.com/Cn33liz/p0wnedShell) - PowerShell based post-exploitation utility utilizing .NET.
* [poet](https://github.com/offlinemark/poet) - Simple but multipurpose post-exploitation tool.

#### Side-channel Tools
* [ChipWhisperer](https://rtfm.newae.com/) - Complete open-source toolchain for side-channel power analysis and glitching attacks

### Persistence Tools
* [SillyRAT] - A Cross Platform Multifunctional (Windows/Linux/Mac) RAT
* [Byp4Xx] - Simple Bash Script To Bypass "403 Forbidden" Messages With Well-Known Methods 
* [Arbitrium-RAT] - A Cross-Platform, Fully Undetectable Remote Access Trojan, To Control Android, Windows And Linux


## Privilege Escalation Tools
Gaining higher-level permissions on a system or network

#### Windows Utilities
* [Bloodhound](https://github.com/BloodHoundAD/BloodHound/wiki) - Graphical Active Directory trust relationship explorer.
* [Commentator](https://github.com/clr2of8/Commentator) - PowerShell script for adding comments to MS Office documents, and these comments can contain code to be executed.
* [DeathStar](https://github.com/byt3bl33d3r/DeathStar) - Python script that uses Empire's RESTful API to automate gaining Domain Admin rights in Active Directory environments.
* [Empire](https://www.powershellempire.com/) - Pure PowerShell post-exploitation agent.
* [Fibratus](https://github.com/rabbitstack/fibratus) - Tool for exploration and tracing of the Windows kernel.
* [GetVulnerableGPO](https://github.com/gpoguy/GetVulnerableGPO/) - PowerShell based utility for finding vulnerable GPOs.
* [Headstart](https://github.com/GoVanguard/script-win-privescalate-headstart) - Lazy man's Windows privilege escalation tool utilizing PowerSploit.
* [Hyena](https://www.systemtools.com/hyena/download.htm) - NetBIOS exploitation.
* [Luckystrike](https://github.com/curi0usJack/luckystrike) - PowerShell based utility for the creation of malicious Office macro documents.
* [Magic Unicorn](https://github.com/trustedsec/unicorn) - Shellcode generator for numerous attack vectors, including Microsoft Office macros, PowerShell, HTML applications (HTA), or `certutil` (using fake certificates).
* [Mimikatz](https://blog.gentilkiwi.com/mimikatz) - Credentials extraction tool for Windows operating system.
* [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) - PowerShell Post-Exploitation Framework.
* [PSKernel-Primitives](https://github.com/FuzzySecurity/PSKernel-Primitives/) - Exploiting primitives for PowerShell.
* [Redsnarf](https://github.com/nccgroup/redsnarf) - Post-exploitation tool for retrieving password hashes and credentials from Windows workstations, servers, and domain controllers.
* [Rubeus](https://github.com/GhostPack/Rubeus) - Rubeus is a C# toolset for raw Kerberos interaction and abuses.
* [Sysinternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) - The Sysinternals Troubleshooting Utilities.
* [Windows Credentials Editor](https://www.ampliasecurity.com/research/windows-credentials-editor/) - Inspect logon sessions and add, change, list, and delete associated credentials, including Kerberos tickets.
* [Windows Exploit Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester) - Suggests Windows exploits based on patch levels.

#### Linux Utilities
* [Bella](https://github.com/khaleds-brain/Bella) - Bella is a pure python post-exploitation data mining tool & remote administration tool for macOS.
* [Linus](https://cisofy.com/lynis/) - Security auditing tool for Linux and macOS.
#### macOS Utilities
* [LinPeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) — Linux Privilege Escalation
* [Linus](https://cisofy.com/lynis/) - Security auditing tool for Linux and macOS.
* [Linux Exploit Suggester](https://github.com/InteliSecureLabs/Linux_Exploit_Suggester) - Heuristic reporting on potentially viable exploits for a given GNU/Linux system.
* [Mempodipper](https://www.exploit-db.com/exploits/18411/) - Linux Kernel 2.6.39 < 3.2.2 local privilege escalation script.
* [vuls](https://github.com/future-architect/vuls) - Linux/FreeBSD agentless vulnerability scanner.
* [Linux Priv Checker](https://github.com/linted/linuxprivchecker) — Enumerate basic system info and search for common privilege escalation vectors

## Defense Evasion Tools
Avoiding detection throughout your compromise

* [LOTS Project](https://lots-project.com/) — Websites that allows attackers to use their domain when conducting phishing, C2, exfiltration, and downloading tools to evade detection

### Evade AV/EDR  
* [Inceptor](https://github.com/klezVirus/inceptor) — Automate common AV/EDR bypasses
* [GPU Poisoning](https://gitlab.com/ORCA000/gp) — Hide payload inside GPU memory
* [AntiVirus Evasion Tool (AVET)](https://github.com/govolution/avet) - Post-process exploits containing executable files targeted for Windows machines to avoid being recognized by antivirus software.
* [Hyperion](https://nullsecurity.net/tools/binary.html) - Runtime encryptor for 32-bit portable executables ("PE `.exe`s").
* [peCloak.py](https://www.securitysift.com/pecloak-py-an-experiment-in-av-evasion/) - Automates the process of hiding a malicious Windows executable from antivirus (AV) detection.
* [peCloakCapstone](https://github.com/v-p-b/peCloakCapstone) - Multi-platform fork of the peCloak.py automated malware antivirus evasion tool.
* [Shellter](https://www.shellterproject.com/) - Dynamic shellcode injection tool, and the first truly dynamic PE infector ever created.
* [SigThief](https://github.com/secretsquirrel/SigThief) - Stealing signatures to evade AV.
* [UniByAv](https://github.com/Mr-Un1k0d3r/UniByAv) - Simple obfuscator that takes raw shellcode and generates Anti-Virus friendly executables by using a brute-forcable, 32-bit XOR key.
* [Windows-SignedBinary](https://github.com/vysecurity/Windows-SignedBinary) - AV evasion tool for binary files.

### Packet Injection
* [Dsniff](https://monkey.org/~dugsong/dsniff/)
* [Ettercap](https://www.ettercap-project.org/)
* [hping](http://hping.org/) — TCP/IP packet assembler/analyzer
* [Scapy](https://scapy.net/) — Packet manipulation program

### Wrappers
* [dll4shell](https://github.com/cepxeo/dll4shell) - A collection of DLL wrappers around various shellcode injection and obfuscation techniques

## Credential Access Tools
Stealing credentials like account names and passwords

### Password Attacks
* [CredKing](https://github.com/ustayready/CredKing) — Launch Password Spraying using AWS Lamba across multiple regions, rotating IPs w/ each request
* [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) — Perform password spraying against users in a domain
* [LDAP Nom Nom](https://github.com/lkarlslund/ldapnomnom) - Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)
* [Masky](https://github.com/Z4kSec/Masky) - Python library providing an alternative way to remotely dump domain users' credentials thanks to an ADCS
* [SharpML] - Machine Learning Network Share Password Hunting Toolkit  




### Hash Cracking
* [CeWL](https://digi.ninja/projects/cewl.php) - Generates custom wordlists by spidering a target's website and collecting unique words.
* [CrackStation](https://crackstation.net/) - Online password cracker.
* [Hashcat](http://hashcat.net/hashcat/) - Fast hash cracking utility with support for most known hashes as well as OpenCL and CUDA acceleration.
* [JPassword Recovery Tool](https://sourceforge.net/projects/jpassrecovery/) - RAR bruteforce cracker. Formery named RAR Crack.
* [JWT Cracker](https://github.com/lmammino/jwt-cracker) - Simple HS256 JWT token brute force cracker.
* [John the Ripper Jumbo edition](https://github.com/openwall/john) - Community enhanced version of John the Ripper.
* [John the Ripper](https://www.openwall.com/john/) - Fast password cracker.
* [Mentalist](https://github.com/sc0tfree/mentalist) - Unique GUI based password wordlist generator compatible with CeWL and John the Ripper.
- Hash Database — Upload Hashes

  
## Discovery Tools
Observing potential control and what’s around your entry point in order to discover how it could benefit your current objective

* [Barcode Reader](https://online-barcode-reader.inliteresearch.com/) - Decode barcodes in C#, VB, Java, C\C++, Delphi, PHP and other languages.
* [LinEnum](https://github.com/rebootuser/LinEnum) — Linux Enumeration
* [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester) — Assist in detecting security deficiencies for given Linux kernel/Linux-based machine

### Network Tools
  * [dnstwist](https://github.com/elceef/dnstwist) - Domain name permutation engine for detecting typo squatting, phishing and corporate espionage.
  * [dsniff](https://www.monkey.org/~dugsong/dsniff/) - Collection of tools for network auditing and pentesting.
  * [enumdb](https://github.com/m8r0wn/enumdb) - MySQL and MSSQL bruteforce utility
  * [FireAway](https://github.com/tcstool/Fireaway/) - Firewall audit and security bypass tool.
  * [impacket](https://github.com/SecureAuthCorp/impacket) - Collection of Python classes for working with network protocols.
  * [Intercepter-NG](http://sniff.su/) - Multifunctional network toolkit.
  * [kerbrute](https://github.com/ropnop/kerbrute) - A tool to perform Kerberos pre-auth bruteforcing.
  * [Low Orbit Ion Cannon (LOIC)](https://github.com/NewEraCracker/LOIC/) - Open source network stress testing tool.
  * [Ncat](https://nmap.org/ncat/) - TCP/IP command line utility supporting multiple protocols.
  * [netcut](https://arcai.com/netcut/) - ARP based utility for discovering and spoofing MAC addresses and enabling/disabling network connectivity on network devices.
  * [Network-Tools.com](https://network-tools.com/) - Website offering an interface to numerous basic network utilities like `ping`, `traceroute`, `whois`, and more.
  * [patator](https://github.com/lanjelot/patator) - Patator is a multi-purpose brute-forcer, with a modular design and a flexible usage.
  * [pig](https://github.com/rafael-santiago/pig) - GNU/Linux packet crafting tool.
  * [Praeda](http://h.foofus.net/?page_id=218) - Automated multi-function printer data harvester for gathering usable data during security assessments.
  * [Printer Exploitation Toolkit (PRET)](https://github.com/RUB-NDS/PRET) - Tool for printer security testing capable of IP and USB connectivity, fuzzing, and exploitation of PostScript, PJL, and PCL printer language features.
  * [routersploit](https://github.com/threat9/routersploit) - Open source exploitation framework similar to Metasploit but dedicated to embedded devices.
  * [scapy](https://github.com/secdev/scapy) - Python-based interactive packet manipulation program & library.
  * [Sockstress](https://github.com/defuse/sockstress) - TCP based DoS utility.
  * [SPARTA](https://sparta.secforce.com/) - Graphical interface offering scriptable, configurable access to existing network infrastructure scanning and enumeration tools.
  * [Spyse](https://spyse.com/) - Web research services that scan the entire internet using OSINT, to simplify the investigation of infrastructure and attack surfaces.
  * [Spyse.py](https://github.com/zeropwn/spyse.py) - Python API wrapper and command-line client for the tools hosted on spyse.com.
  * [THC Hydra](https://github.com/vanhauser-thc/thc-hydra) - Online password cracking tool with built-in support for many network protocols, including HTTP, SMB, FTP, telnet, ICQ, MySQL, LDAP, IMAP, VNC, and more.
  * [UFONet](https://github.com/epsylon/ufonet/) - Layer 7 DDoS/DoS tool.
  * [Zarp](https://github.com/hatRiot/zarp/) - Multipurpose network attack tool, both wired and wireless.








### Protocol Analyzers & Sniffers
* [Chaosreader](http://chaosreader.sourceforge.net/) - Universal TCP/UDP snarfing tool that dumps session data from various protocols.
* [Dshell](https://github.com/USArmyResearchLab/Dshell) - Network forensic analysis framework.
* [Fiddler](https://www.telerik.com/fiddler) - Cross platform packet capturing tool for capturing HTTP/HTTPS traffic.
* [netsniff-ng](https://github.com/netsniff-ng/netsniff-ng) - Swiss army knife for Linux network sniffing.
* [tcpdump/libpcap](https://www.tcpdump.org/) - Common packet analyzer that runs under the command line.
* [Wireshark](https://www.wireshark.org/) - Widely-used graphical, cross-platform network protocol analyzer.
* [Yersinia](https://tools.kali.org/vulnerability-analysis/yersinia) - Packet and protocol analyzer with MITM capability.



### Proxies & MITM Tools
* [BetterCAP](https://www.bettercap.org/) - Modular, portable and easily extensible MITM framework.
* [dnschef](https://github.com/iphelix/dnschef) - Highly configurable DNS proxy for pentesters.
* [Ettercap](https://www.ettercap-project.org/) - Comprehensive, mature suite for machine-in-the-middle attacks.
* [evilgrade](https://github.com/infobyte/evilgrade) - Modular framework to take advantage of poor upgrade implementations by injecting fake updates.
* [mallory](https://github.com/justmao945/mallory) - HTTP/HTTPS proxy over SSH
* [MITMf](https://github.com/byt3bl33d3r/MITMf) - Multipurpose man-in-the-middle framework.
* [mitmproxy](https://github.com/mitmproxy/mitmproxy) - Interactive TLS-capable intercepting HTTP proxy for penetration testers and software developers.
* [Morpheus](https://github.com/r00t-3xp10it/morpheus) - Automated ettercap TCP/IP Hijacking tool.
* [Responder-Windows](https://github.com/lgandx/Responder-Windows) - Windows version of the above NBT-NS/LLMNR/MDNS poisoner.
* [Responder](https://github.com/lgandx/Responder) - Open source NBT-NS, LLMNR, and MDNS poisoner.
* [SSH MITM](https://github.com/jtesta/ssh-mitm) - Intercept SSH connections with a proxy; all plaintext passwords and sessions are logged to disk.

### Wireless Network Tools
* [Aircrack-ng](https://www.aircrack-ng.org/) - Set of tools for auditing wireless networks.
* [BetterCAP](https://www.bettercap.org/) - Wifi, Bluetooth LE, and HID reconnaissance and MITM attack framework, written in Go.
* [Fluxion](https://github.com/FluxionNetwork/fluxion) - Suite of automated social engineering based WPA attacks.
* [Kismet](https://www.patreon.com/kismetwireless) - Wireless network discovery tool.
* [MANA Toolkit](https://github.com/sensepost/mana) - Rogue AP and man-in-the-middle utility.
* [NetStumbler](https://www.netstumbler.com/downloads/) - WLAN scanning tool.
* [WiFi Pumpkin](https://github.com/P0cL4bs/wifipumpkin3) - All in one Wi-Fi exploitation and spoofing utility.
* [wifi-pickle](https://github.com/GoVanguard/wifi-pickle) - Fake access point attacks.
* [Wifite](https://github.com/derv82/wifite) - Automated wireless attack tool.

### TLS Tools
* [SMTP TLS Checker](https://luxsci.com/smtp-tls-checker) - Online TLS/SSL testing suite for SMTP servers.
* [SSL Labs](https://www.ssllabs.com/ssltest/) - Online TLS/SSL testing suite for revealing supported TLS/SSL versions and ciphers.
* [SSLscan](https://github.com/rbsec/sslscan) - Quick command line SSL/TLS analyzer.
* [SSLyze](https://github.com/nabla-c0d3/sslyze) - Fast and comprehensive TLS/SSL configuration analyzer to help identify security mis-configurations.
* [crackpkcs12](https://github.com/crackpkcs12/crackpkcs12) - Multithreaded program to crack PKCS#12 files (`.p12` and `.pfx` extensions), such as TLS/SSL certificates.
* [spoodle](https://github.com/avicoder/spoodle) - Mass subdomain + POODLE vulnerability scanner.
* [tlssled](https://tools.kali.org/information-gathering/tlssled) - Comprehensive TLS/SSL testing suite.

### Cryptography
  * [FeatherDuster](https://github.com/nccgroup/featherduster) - Analysis tool for discovering flaws in cryptography.
  * [rsatool](https://github.com/ius/rsatool) - Tool for calculating RSA and RSA-CRT parameters.
  * [xortool](https://github.com/hellman/xortool/) - XOR cipher analysis tool.

## Lateral Movement Tools
Pivoting through multiple systems and accounts to gain additional access

* [Forbidden] - Bypass 4Xx HTTP Response Status Codes
* [Neo-reGeorg](https://github.com/L-codes/Neo-reGeorg/blob/master/README-en.md) -- Used for HTTP(S) Tunneling

## Collection Tools
Gathering information relevant to following through on the adversary's objectives

* [ICMPDoor](https://github.com/krabelize/icmpdoor) - Open-source reverse-shell written in Python3 and scapy
* [iodined](https://github.com/yarrick/iodine) - DNS Tunneling
  * [Data Exfiltration Toolkit (DET)](https://github.com/PaulSec/DET) - Proof of concept to perform data exfiltration using either single or multiple channel(s) at the same time.
  * [dnsteal](https://github.com/m57/dnsteal/) - Fake DNS server for stealthily extracting files.
  * [HTTPTunnel](https://github.com/larsbrinkhoff/httptunnel) - Tunnel data over pure HTTP GET/POST requests.
  * [Iodine](https://github.com/yarrick/iodine) - Tunnel IPv4 data through a DNS server; useful for exfiltration from networks where Internet access is firewalled, but DNS queries are allowed.
  * [MailSniper](https://github.com/dafthack/MailSniper) - Search through email in a Microsoft Exchange environment for specific terms (passwords, insider intel, network architecture information, etc.).
  * [mallory](https://github.com/justmao945/mallory) - HTTP/HTTPS proxy over SSH.
  * [mimikatz](https://blog.gentilkiwi.com/mimikatz) - Credentials extraction tool for Windows operating system.
  * [mimikittenz](https://github.com/orlyjamie/mimikittenz) - Post-exploitation PowerShell tool for extracting data from process memory.
  * [PANHunt](https://github.com/Dionach/PANhunt) - Search file systems for credit cards.
  * [PassHunt](https://github.com/Dionach/PassHunt) - Search file systems for passwords.
  * [ptunnel-ng](https://github.com/lnslbrty/ptunnel-ng) - Tunnel IPv4 traffic through ICMP pings; slow but stealthy when normal IP exfiltration traffic is blocked.
  * [pwnat](https://github.com/samyk/pwnat) - Punches holes in firewalls and NATs.
  * [spYDyishai](https://github.com/Night46/spYDyishai/) - Local Google credentials exfiltration tool, written in Python.
  * [tgcd](http://tgcd.sourceforge.net/) - Simple Unix network utility to extend the accessibility of TCP/IP based network services beyond firewalls.




## Impact 
Disrupting availability, compromising integrity by manipulating business and operational processes

## Remediation / Reporting
* [PeTeReport] - An Open-Source Application Vulnerability Reporting Tool


## Miscellaneous
* [Dockerized Android](https://github.com/cybersecsi/dockerized-android) - A Container-Based framework to enable the integration of mobile components in security training platforms
* [Viper] - Intranet pentesting tool with Webui
* [AzureHunter] - A Cloud Forensics Powershell Module To Run Threat Hunting Playbooks On Data From Azure And O365
* [403Bypasser] - Automates The Techniques Used To Circumvent Access Control Restrictions On Target Pages
* [Smuggler] - An HTTP Request Smuggling / Desync Testing Tool

## Malicious
* [fireELF](https://github.com/rek7/fireELF) — Inject fileless exploit payloads into a Linux host
* [RouterSploit](https://github.com/threat9/routersploit) — Vulnerability scanning and exploit modules targeting embedded systems


## Cloud Pentesting

### AWS
* [Pacu](https://github.com/RhinoSecurityLabs/pacu)
* [https://rhinosecuritylabs.com/aws/cloud-container-attack-tool/](https://rhinosecuritylabs.com/aws/cloud-container-attack-tool/)
* [CloudFrunt](https://github.com/MindPointGroup/cloudfrunt) - Tool for identifying misconfigured CloudFront domains.

### GCP
* [GCP IAM Privilege Escalation](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation)

### Azure
* [Azure](https://github.com/Azure/Stormspotter)

### Misc.
* [Multi Cloud](https://github.com/nccgroup/ScoutSuite)
* [Multi Cloud](https://github.com/aquasecurity/cloudsploit)
* [Recon Cloud](https://recon.cloud/) - Cloud asset scanner

## Active Directory
* [AzureAD-Attack-Defense](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense) - Various common attack scenarios on Azure AD
* [AD-Attack-Defense](https://lnkd.in/ePgnhbUk)
* [AD Exploitation Cheat Sheet](https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet)
* [Offensive AD 101](https://owasp.org/www-pdf-archive/OWASP_FFM_41_OffensiveActiveDirectory_101_MichaelRitter.pdf) - Offense AD Guide
* [AD Exploitation Cheatsheet](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet#active-directory-exploitation-cheat-sheet) - Common TTPs for pentesting AD
* [IR Team](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse) — AD & Kerberos Abusing
* [AD Kill Chain Attack & Defense](https://github.com/infosecn1nja/AD-Attack-Defense#discovery) - Specific TTPs to compromise AD and guidance to mitigation, detection, and prevention


## Compilation of Tools
* [Hacktricks](https://book.hacktricks.xyz/) - Hacking TTPs
* [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) - A list of useful payloads for bypassing systems
* [Pentest-Tools](https://github.com/S3cur3Th1sSh1t/Pentest-Tools) — Cybersecurity repository
* [EthHack](https://ethhack.com/category/security-tools/) — Repository security tool
* [FSociety Hacking Tools](https://github.com/Manisso/fsociety) — Contains all the tools used in Mr. Robot series
* [Red Team Resources](https://github.com/J0hnbX/RedTeam-Resources) - Compilation of Red Teaming resources
* [Kitploit’s Popular Hacking Tools](https://www.kitploit.com/2021/12/top-20-most-popular-hacking-tools-in.html)
* [Red Teaming Toolkit](https://github.com/infosecn1nja/Red-Teaming-Toolkit#Payload%20Development)

### Python
* [Python Tool List](https://hackersonlineclub.com/python-tools/) - Compilation of security Python tools

## Wireless Pentesting
* [Best Wifi Hacking Tools](https://youtu.be/f2BjFilLDqQ)

## Adversary Emulation
* [APTSimulator](https://github.com/NextronSystems/APTSimulator) - A Windows Batch script that uses a set of tools and output files to make a system look as if it was compromised.
* [Atomic Red Team](ART)](https://github.com/redcanaryco/atomic-red-team) - Small and highly portable detection tests mapped to the Mitre ATT&CK Framework.
* [AutoTTP](https://github.com/jymcheong/AutoTTP) - Automated Tactics Techniques & Procedures. Re-running complex sequences manually for regression tests, product evaluations, generate data for researchers.
* [Blue Team Training Toolkit](BT3)](https://www.bt3.no/) - Software for defensive security training, which will bring your network analysis training sessions, incident response drills and red team engagements to a new level. 
* [Caldera](https://github.com/mitre/caldera) - an automated adversary emulation system that performs post-compromise adversarial behavior within Windows Enterprise networks. It generates plans during operation using a planning system and a pre-configured adversary model based on the Adversarial Tactics, Techniques & Common Knowledge](ATT&CK™) project.
* [DumpsterFire](https://github.com/TryCatchHCF/DumpsterFire) - The DumpsterFire Toolset is a modular, menu-driven, cross-platform tool for building repeatable, time-delayed, distributed security events. Easily create custom event chains for Blue Team drills and sensor /   alert mapping. Red Teams can create decoy incidents, distractions, and lures to support and scale their operations.
* [Metta](https://github.com/uber-common/metta) - An information security preparedness tool to do adversarial simulation.
* [Network Flight Simulator](https://github.com/alphasoc/flightsim) - flightsim is a lightweight utility used to generate malicious network traffic and help security teams to evaluate security controls and network visibility.
* [Red Team Automation ](RTA)](https://github.com/endgameinc/RTA) - RTA provides a framework of scripts designed to allow blue teams to test their detection capabilities against malicious tradecraft, modeled after MITRE ATT&CK.
* [RedHunt-OS](https://github.com/redhuntlabs/RedHunt-OS) - A virtual machine for adversary emulation and threat hunting.

# Misc 
#### Other
  * [BruteX Wordlists](https://github.com/coreb1t/BruteX/tree/master/wordlists) - Wordlist repo.
  * [Cortex](https://thehive-project.org) - Cortex allows you to analyze observables such as IP and email addresses, URLs, domain names, files or hashes one by one or in bulk mode using a Web interface. Analysts can also automate these operations using its REST API.
  * [Crits](https://crits.github.io/) - a web-based tool which combines an analytic engine with a cyber threat database .
  * [Diffy](https://github.com/Netflix-Skunkworks/diffy) - a DFIR tool developed by Netflix's SIRT that allows an investigator to quickly scope a compromise across cloud instances (Linux instances on AWS, currently) during an incident and efficiently triaging those instances for followup actions by showing differences against a baseline. 
  * [domfind](https://github.com/diogo-fernan/domfind) - domfind is a Python DNS crawler for finding identical domain names under different TLDs.
  * [Fenrir](https://github.com/Neo23x0/Fenrir) - Fenrir is a simple IOC scanner. It allows scanning any UNIX system for IOCs in plain bash. Created by the creators of THOR and LOKI.
  * [Fileintel](https://github.com/keithjjones/fileintel) - Pull intelligence per file hash.
  * [fuzzbox](https://github.com/iSECPartners/fuzzbox/) - Multi-codec media fuzzing tool.
  * [Google Hacking Master List](https://gist.github.com/cmartinbaughman/5877945)
  * [HELK](https://github.com/Cyb3rWard0g/HELK) - Threat Hunting platform.
  * [Hindsight](https://github.com/obsidianforensics/hindsight) - Internet history forensics for Google Chrome/Chromium.
  * [honggfuzz](https://github.com/google/honggfuzz/) - Security orientated fuzzing tool.
  * [Hostintel](https://github.com/keithjjones/hostintel) - Pull intelligence per host.
  * [imagemounter](https://github.com/ralphje/imagemounter) - Command line utility and Python package to ease the (un)mounting of forensic disk images.
  * [Kansa](https://github.com/davehull/Kansa/) - Kansa is a modular incident response framework in Powershell.
  * [Kayak Car Hacking Tool](https://github.com/ParrotSec/car-hacking-tools) - Tool for Kayak car hacking.
  * [melkor-android](https://github.com/anestisb/melkor-android/) - Android fuzzing tool for ELF file formats.
  * [Netzob](https://github.com/netzob/netzob/) - Multipurpose tool for reverse engineering, modeling, and fuzzing communciation protocols.
  * [radamsa](https://gitlab.com/akihe/radamsa) - General purpose fuzzing tool.
  * [RaQet](https://www.raqet.org/) - RaQet is an unconventional remote acquisition and triaging tool that allows triage a disk of a remote computer (client) that is restarted with a purposely built forensic operating system.
  * [rastrea2r](https://github.com/aboutsecurity/rastrea2r) - allows one to scan disks and memory for IOCs using YARA on Windows, Linux and OS X.
  * [ROPgadget](https://github.com/JonathanSalwan/ROPgadget/) - Python based tool to aid in ROP exploitation.
  * [Shellen](https://github.com/merrychap/shellen) - Interactive shellcoding environment.
  * [sqhunter](https://github.com/0x4d31/sqhunter) - a threat hunter based on osquery and Salt Open (SaltStack) that can issue ad-hoc or distributed queries without the need for osquery's tls plugin. sqhunter allows you to query open network sockets and check them against threat intelligence sources. 
  * [Stalk](https://www.percona.com/doc/percona-toolkit/2.2/pt-stalk.html) - Collect forensic data about MySQL when problems occur.
  * [Stenographer](https://github.com/google/stenographer) - Stenographer is a packet capture solution which aims to quickly spool all packets to disk, then provide simple, fast access to subsets of those packets. It stores as much history as it possible, managing disk usage, and deleting when disk limits are hit. It's ideal for capturing the traffic just before and during an incident, without the need explicit need to store all of the network traffic.
  * [Sulley](https://github.com/OpenRCE/sulley/) - Fuzzing engine and framework.
  * [traceroute-circl](https://github.com/CIRCL/traceroute-circl) - traceroute-circl is an extended traceroute to support the activities of CSIRT (or CERT) operators. Usually CSIRT team have to handle incidents based on IP addresses received. Created by Computer Emergency Responce Center Luxembourg.
  * [Zulu](https://github.com/nccgroup/Zulu/) - Interactive fuzzer.
  
### Our Open Source Tools
  * [Legion](https://github.com/GoVanguard/legion) - Legion is an open source, easy-to-use, super-extensible and semi-automated network penetration testing tool that aids in discovery, reconnaissance and exploitation of information systems.
  * [SecretScanner](https://github.com/GoVanguard/SecretScanner) - Searches for common keys and secrets in a stupidly simple way.
  * [SecretSearcher](https://github.com/GoVanguard/SecretSearcher) - Python re-implementation of the classic SecretScanner shell script.
  * [log4jShell Scanner](https://github.com/GoVanguard/Log4jShell_Scanner) - This shell script scans a vulnerable web application that is using a version of apache-log4j < 2.15.0.
  * [WinPrivHeadStart](https://github.com/GoVanguard/script-win-privescalate-headstart) - The lazy mans local Windows privilege escalation script.

 <br> 

# Defensive Security Tools
* [DarkTrace](https://www.darktrace.com/en/) - Cyber AI detection
* [Active Countermeasures](https://www.activecountermeasures.com/free-tools/) - Open source tools for countermeasure
* [The CredDefense Toolkit](https://github.com/CredDefense/CredDefense/) - Detect & Prevent Brute Force attacks
* [DNS Blacklist](https://bitbucket.org/ethanr/dns-blacklists/src/master/) - Detect Blacklisted IPs from your traffic
* [Spidertrap](https://bitbucket.org/ethanr/spidertrap/src/master/) - Trap web crawlers and spiders in dynamically generated webpages
* [Live Forensicator](https://github.com/Johnng007/Live-Forensicator) - Powershell script to aid Incidence Response and Live Forensics
* [https://threathunterplaybook.com/intro.html](https://threathunterplaybook.com/intro.html) - Open source project to share detection logic, adversary tradecraft and resources to make detection development more efficient


## Static Analyzers
* [Androbugs-Framework](https://github.com/AndroBugs/AndroBugs_Framework/) - Android program vulnerability analysis tool.
* [Androwarn](https://github.com/maaaaz/androwarn/) - Android static code analysis tool.
* [APKinspector](https://github.com/honeynet/apkinspector/) - Android APK analysis tool with GUI.
* [bandit](https://pypi.org/project/bandit/) - Security oriented static analyser for python code.
* [Brakeman](https://github.com/presidentbeef/brakeman) - Static analysis security vulnerability scanner for Ruby on Rails applications.
* [Codebeat (open source)](https://codebeat.co/open-source/) - Open source implementation of commercial static code analysis tool with GitHub integration.
* [Codelyzer](https://github.com/mgechev/codelyzer) - A set of tslint rules for static code analysis of Angular TypeScript projects. You can run the static code analyzer over web apps, NativeScript, Ionic, etc.
* [cppcheck](http://cppcheck.sourceforge.net/) - Extensible C/C++ static analyzer focused on finding bugs.
* [FindBugs](http://findbugs.sourceforge.net/) - Free software static analyzer to look for bugs in Java code.
* [Icewater](https://github.com/SupportIntelligence/Icewater) - 16,432 free Yara rules.
* [Joint Advanced Defense Assessment for Android Applications (JAADAS)](https://github.com/flankerhqd/JAADAS/) - Multipurpose Android static analysis tool.
* [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/) - Open source static analysis tool that enumerates dependencies used by Java and .NET software code (with experimental support for Python, Ruby, Node.js, C, and C++) and lists security vulnerabilities associated with the depedencies. 
* [pefile](https://github.com/erocarrera/pefile) - Static portable executable file inspector.
* [Progpilot](https://github.com/designsecurity/progpilot) - Static security analysis tool for PHP code.
* [Quick Android Review Kit (Qark)](https://github.com/linkedin/qark/) - Tool for finding security related Android application vulnerabilities.
* [ShellCheck](https://github.com/koalaman/shellcheck) - Static code analysis tool for shell script.
* [smalisca](https://github.com/dorneanu/smalisca) - Android static code analysis tool.
* [sobelow](https://github.com/nccgroup/sobelow) - Security-focused static analysis for the Phoenix Framework.
* [truffleHog](https://github.com/dxa4481/truffleHog) - Git repo scanner.
* [Veracode](https://www.veracode.com/) - Commercial cloud platform for static code analysis, dynamic code analysis, dependency/plugin analysis, and more.
* [VisualCodeGrepper](https://github.com/nccgroup/VCG) - Open source static code analysis tool with support for Java, C, C++, C#, PL/SQL, VB, and PHP. VisualCodeGrepper also conforms to OWASP best practices.
* [Yara](https://github.com/VirusTotal/yara) - Static pattern analysis tool for malware researchers.

## Dynamic Analyzers
* [AndroidHooker](https://github.com/AndroidHooker/hooker/) - Dynamic Android application analysis tool.
* [Androl4b](https://github.com/sh4hin/Androl4b/) - Android security virtual machine based on Ubuntu-MATE for reverse engineering and malware analysis.
* [Cheat Engine](https://www.cheatengine.org/) - Memory debugger and hex editor for running applications.
* [ConDroid](https://github.com/JulianSchuette/ConDroid) - Android dynamic application analysis tool.
* [Cuckoo](https://github.com/cuckoosandbox) - Automated dynamic malware analysis tool.
* [DECAF](https://github.com/decaf-project/DECAF) - Dynamic code analysis tool.
* [droidbox](https://github.com/pjlantz/droidbox) - Dynamic malware analysis tool for Android, extension to DECAF.
* [drozer](https://github.com/FSecureLABS/drozer) - Android platform dynamic vulnerability assessment tool.
* [idb](https://www.idbtool.com/) - iOS app security analyzer.
* [Inspeckage](https://github.com/ac-pm/Inspeckage) - Dynamic Android package analysis tool.

#### Hex Editors
* [Cheat Engine](https://www.cheatengine.org/) - Memory debugger and hex editor for running applications.
* [Frhed](http://frhed.sourceforge.net/en/) - Binary file editor for Windows.
* [HexEdit.js](https://hexed.it/) - Browser-based hex editing.
* [Hexinator](https://hexinator.com/) - World's finest (proprietary, commercial) Hex Editor.

#### File Format Analysis Tools
* [Hachoir](https://hachoir.readthedocs.io/en/latest/index.html) - Python library to view and edit a binary stream as tree of fields and tools for metadata extraction.
* [Kaitai Struct](https://kaitai.io/) - File formats and network protocols dissection language and web IDE, generating parsers in C++, C#, Java, JavaScript, Perl, PHP, Python, Ruby.
* [Veles](https://codisec.com/veles/) - Binary data visualization and analysis tool.


### Forensic Tools
* [Appliance for Digital Investigation and Analysis (ADIA)](https://forensics.cert.org/#ADIA) - VMware virtual appliance for digital forensics.
* [Autopsy](https://www.sleuthkit.org/autopsy/) - Graphical interface to The Sleuth Kit.
* [binwalk](https://github.com/ReFirmLabs/binwalk) - Firmware analysis tool.
* [bulk_extractor](https://github.com/simsong/bulk_extractor/) - Command line tool for extracting email addresses, credit card numbers, URLs, and other types of information from many types of files, including compressed files and images.
* [CAINE](https://www.caine-live.net/index.html) - Italian live Linux distro for digital forensics.
* [chkrootkit](http://www.chkrootkit.org/) - Checks local Linux systems for rootkits.
* [Chrome URL Dumper](https://github.com/eLoopWoo/chrome-url-dumper) - Python based agent that gathers and dumps Chrome history (URLs).
* [DEFT Linux](http://na.mirror.garr.it/mirrors/deft/) - Linux distro for digital forensics analysis.
* [Digital Forensics Framework (DFF)](https://tools.kali.org/forensics/dff) - Open source digital forensics framework with GUI.
* [docker-explorer](https://github.com/google/docker-explorer) - Docker file system forensic tool.
* [Dumpzilla](https://www.dumpzilla.org/) - Python based application for dumping information from Firefox, Iceweasel, and Seamonkey browsers.
* [extundelete](http://extundelete.sourceforge.net/) - ext3 and ext4 file recovery tool.
* [Fast Evidence Collector Toolkit (FECT)](https://github.com/jipegit/FECT) - Lightweight digital forensics tool.
* [FireEye Labs Obfuscated String Solver (FLOSS)](https://github.com/fireeye/flare-floss/) - Extract obfuscated strings from malware.
* [Foremost](http://foremost.sourceforge.net/) - File recovery tool.
* [GRR Rapid Response](https://github.com/google/grr) - Incident response framework focused on remote live forensics.
* [Hindsight](https://github.com/obsidianforensics/hindsight) - Chrome/Chromium browser forensics tool.
* [IREC](https://binalyze.com/irec/) - All in one evidence collector.
* [Linux Expl0rer](https://github.com/intezer/linux-explorer) - Easy-to-use live forensics toolbox for Linux endpoints written in Python & Flask.
* [magneto-malware-scanner](https://github.com/gwillem/magento-malware-scanner) - Malware scanning platform.
* [nightHawk](https://github.com/biggiesmallsAG/nightHawkResponse) - Platform for digital forensics presentation, using Elasticsearch.
* [PALADIN](https://sumuri.com/software/paladin/) - Linux distro for digital forensics.
* [pdf-parser](https://blog.didierstevens.com/my-software/#pdf-parser) - PDF digital forensics software.
* [pdfid](https://blog.didierstevens.com/my-software/#pdfid) - PDF digital forensics software.
* [pdfminer](https://github.com/euske/pdfminer/) - Tool for extracting information from the text of PDF documents.
* [peepdf](https://github.com/jesparza/peepdf) - Python PDF analysis tool.
* [PowerForensics](https://github.com/Invoke-IR/PowerForensics) - PowerShell based digital forensics suite.
* [PSRecon](https://github.com/gfoss/PSRecon/) - Windows based data gathering tool using PowerShell.
* [Regripper](https://forensicswiki.xyz/wiki/index.php?title=Regripper) - Windows Registry data extraction tool.
* [Rekall](http://www.rekall-forensic.com/) - Incident response and forensics tool.
* [SANS Investigative Forensics Toolkit (SIFT)](https://github.com/teamdfir/sift) - Linux VM for digital forensics.
* [SIFT Workstation](https://digital-forensics.sans.org/community/downloads) - Linux distro (with optional VM) for digital forensics.
* [The Sleuth Kit](https://www.sleuthkit.org/sleuthkit/) - Collection of command line digital forensic utilities for investigating disk images, volume and file system data, and more.


#### Memory Analysis
* [Evolve](https://github.com/JamesHabben/evolve) - Web interface for Volatility advanced memory forensics framework.
* [inVtero.net](https://github.com/ShaneK2/inVtero.net) - Windows x64 memory analysis tool.
* [Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME) - A Loadable Kernel Module (LKM) allowing for volatile memory extraction of Linux-based systems.
* [Memoryze](https://www.fireeye.com/services/freeware/memoryze.html) - Memory forensics software.
* [Microsoft User Mode Process Dumping](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/user-mode-dump-files) - Dumps any running Win32 processes memory image on the fly.
* [PMDump](https://vidstromlabs.com/freetools/pmdump/) - Tool for dumping memory contents of a process without stopping the process.
* [Rekall](http://www.rekall-forensic.com/) - Open source tool and library for the extraction of digital artifacts from volatile memory, RAM, samples.
* [Responder PRO](https://www.gosecure.net/responder-pro) - Commercial memory analysis software.
* [Volatility](https://github.com/volatilityfoundation/volatility) - Advanced memory forensics framework.
* [VolatilityBot](https://github.com/mkorman90/VolatilityBot) - Automation tool utilizing Volatility.
* [VolDiff](https://github.com/aim4r/VolDiff) - Malware Memory Footprint Analysis based on Volatility.
* [WindowsSCOPE](https://www.windowsscope.com/) - Commercial memory forensics software for Windows systems.

#### Memory Imaging Tools

* [Belkasoft Live RAM Capturer](https://belkasoft.com/ram-capturer) - A tiny free forensic tool to reliably extract the entire content of the computer’s volatile memory – even if protected by an active anti-debugging or anti-dumping system.
* [Linux Memory Grabber](https://github.com/halpomeranz/lmg/) - A script for dumping Linux memory and creating Volatility profiles.
* [Magnet RAM Capture](https://www.magnetforensics.com/resources/magnet-ram-capture/) - Magnet RAM Capture is a free imaging tool designed to capture the physical memory of a suspect’s computer. Supports recent versions of Windows.
* [OSForensics](https://www.osforensics.com/) - OSForensics can acquire live memory on 32bit and 64bit systems. A dump of an individual process’s memory space or physical memory dump can be done.

#### Incident Response
* [APT Simulator](https://github.com/NextronSystems/APTSimulator) - Windows Batch Script that makes a system appear compromised.
* [Atomic Red Team](https://atomicredteam.io/) - Set of premade tests to evaluate security posture.
* [AutoTTP](https://github.com/jymcheong/AutoTTP) - Automated Tactics Techniques & Procedures, for re-issuing complex tasks.
* [Belkasoft Evidence Center](https://belkasoft.com/x) - Commercial incident response suite.
* [Blue Team Training Toolkit](https://www.bt3.no/) - Toolkit for preparing blue teams for defensive security.
* [Caldera](https://github.com/mitre/caldera) - Automated adversary emulation system.
* [CIRTKit](https://github.com/opensourcesec/CIRTKit) - Open source incident response framework.
* [Cyber Triage](https://www.cybertriage.com/) - Commercial incident response suite.
* [Doorman](https://github.com/mwielgoszewski/doorman) - Osquery fleet manager.
* [DumpsterFire Toolset](https://github.com/TryCatchHCF/DumpsterFire) - Security event simulator.
* [Falcon Orchestrator](https://github.com/CrowdStrike/falcon-orchestrator) - Windows based incident management framework.
* [GRR Rapid Response](https://github.com/google/grr) - Python based incident mangement framework.
* [Kolide Fleet](https://github.com/kolide/fleet) - Open source osquery manager.
* [LimaCharlie](https://github.com/refractionpoint/limacharlie) - Cross-platform open source endpoint detection and response solution.
* [Metta](https://github.com/uber-common/metta) - Open source adversary simulation.
* [MIG - Mozilla InvestiGator](http://mozilla.github.io/mig/) - Endpoint inspection.
* [MozDef](https://github.com/mozilla/MozDef) - Mozilla defense platform.
* [Network Flight Simulator](https://github.com/alphasoc/flightsim) - Utility for generating malicious network traffic.
* [Osquery](https://osquery.io/) - Multiplatform framework for querying operating systems similar to SQL queries.
* [Red Team Automation (RTA)](https://github.com/endgameinc/RTA) - Adversary simulation framework.
* [RedHunt OS](https://github.com/redhuntlabs/RedHunt-OS) - Purposely vulnerable Linux VM.
* [Redline](https://www.fireeye.com/services/freeware/redline.html) - Investigative tool able to scan processes, memory, file system metadata, and more.
* [Zentral](https://github.com/zentralopensource/zentral) - Monitors system events using osquery.



#### All in one Incident Response Tools

* [Belkasoft Evidence Center](https://belkasoft.com/x) -  The toolkit will quickly extract digital evidence from multiple sources by analyzing hard drives, drive images, memory dumps, iOS, Blackberry and Android backups, UFED, JTAG and chip-off dumps.
* [CimSweep](https://github.com/PowerShellMafia/CimSweep) - CimSweep is a suite of CIM/WMI-based tools that enable the ability to perform incident response and hunting operations remotely across all versions of Windows.
* [CIRTkit](https://github.com/opensourcesec/CIRTKit) - CIRTKit is not just a collection of tools, but also a framework to aid in the ongoing unification of Incident Response and Forensics investigation processes.
* [Cyber Triage](https://www.cybertriage.com/) - Cyber Triage remotely collects and analyzes endpoint data to help determine if it is compromised.  It’s agentless approach and focus on ease of use and automation allows companies to respond without major infrastructure changes and without a team of forensics experts.  Its results are used to decide if the system should be erased or investigated further. 
* [Digital Forensics Framework](https://github.com/arxsys/dff) - DFF is an Open Source computer forensics platform built on top of a dedicated Application Programming Interface. DFF proposes an alternative to the aging digital forensics solutions used today. Designed for simple use and automation, the DFF interface guides the user through the main steps of a digital investigation so it can be used by both professional and non-expert to quickly and easily conduct a digital investigations and perform incident response.
* [Doorman](https://github.com/mwielgoszewski/doorman) - Doorman is an osquery fleet manager that allows remote management of osquery configurations retrieved by nodes. It takes advantage of osquery's TLS configuration, logger, and distributed read/write endpoints, to give administrators visibility across a fleet of devices with minimal overhead and intrusiveness.
* [Envdb](https://github.com/mephux/envdb) - Envdb turns your production, dev, cloud, etc environments into a database cluster you can search using osquery as the foundation. It wraps the osquery process with a cluster node agent that can communicate back to a central location.
* [Falcon Orchestrator](https://github.com/CrowdStrike/falcon-orchestrator) - Falcon Orchestrator by CrowdStrike is an extendable Windows-based application that provides workflow automation, case management and security response functionality.
* [GRR Rapid Response](https://github.com/google/grr) - GRR Rapid Response is an incident response framework focused on remote live forensics. It consists of a python agent client that is installed on target systems, and a python server infrastructure that can manage and talk to the agent.
* [Kolide Fleet](https://github.com/kolide/fleet) - Kolide Fleet is a state of the art host monitoring platform tailored for security experts. Leveraging Facebook's battle-tested osquery project, Kolide delivers fast answers to big questions.
* [Limacharlie](https://github.com/refractionpoint/limacharlie) - an endpoint security platform. It is itself a collection of small projects all working together, and gives you a cross-platform, Windows, OSX, Linux, Android and iOS, low-level environment allowing you to manage and push additional modules into memory to extend its functionality.
* [MIG](http://mozilla.github.io/mig/) - Mozilla Investigator, MIG, is a platform to perform investigative surgery on remote endpoints. It enables investigators to obtain information from large numbers of systems in parallel, thus accelerating investigation of incidents and day-to-day operations security.
* [MozDef](https://github.com/mozilla/MozDef) - The Mozilla Defense Platform, MozDef, seeks to automate the security incident handling process and facilitate the real-time activities of incident handlers.
* [nightHawk](https://github.com/biggiesmallsAG/nightHawkResponse) - the nightHawk Response Platform is an application built for asynchronus forensic data presentation using ElasticSearch as the backend. It's designed to ingest Redline collections.
* [Open Computer Forensics Architecture](https://sourceforge.net/projects/ocfa/) - Open Computer Forensics Architecture, OCFA, is another popular distributed open-source computer forensics framework. This framework was built on Linux platform and uses postgreSQL database for storing data.
* [Osquery](https://osquery.io/) - with osquery you can easily ask questions about your Linux and OSX infrastructure. Whether your goal is intrusion detection, infrastructure reliability, or compliance, osquery gives you the ability to empower and inform a broad set of organizations within your company. Queries in the   -incident-response pack - help you detect and respond to breaches.
* [Redline](https://www.fireeye.com/services/freeware/redline.html) - provides host investigative capabilities to users to find signs of malicious activity through memory and file analysis, and the development of a threat assessment profile.
* [The Sleuth Kit & Autopsy](https://www.sleuthkit.org/) - The Sleuth Kit is a Unix and Windows based tool which helps in forensic analysis of computers. It comes with various tools which helps in digital forensics. These tools help in analyzing disk images, performing in-depth analysis of file systems, and various other things.
* [TheHive](https://thehive-project.org/) - TheHive is a scalable 3-in-1 open source and free solution designed to make life easier for SOCs, CSIRTs, CERTs and any information security practitioner dealing with security incidents that need to be investigated and acted upon swiftly.
* [X-Ways Forensics](https://www.x-ways.net/forensics/) - X-Ways is a forensics tool for Disk cloning and imaging. It can be used to find deleted files and disk analysis.
* [Zentral](https://github.com/zentralopensource/zentral) - combines osquery's powerful endpoint inventory features with a flexible notification and action framework. This enables one to identify and react to changes on OS X and Linux clients.


#### Disk Image Creation Tools

  * [AccessData FTK Imager](https://accessdata.com/product-download/?/support/adownloads#FTKImager) - AccessData FTK Imager is a forensics tool whose main purpose is to preview recoverable data from a disk of any kind. FTK Imager can also acquire live memory and paging file on 32bit and 64bit systems.
  * [Bitscout](https://github.com/vitaly-kamluk/bitscout) - Bitscout by Vitaly Kamluk helps you build your fully-trusted customizable LiveCD/LiveUSB image to be used for remote digital forensics, or perhaps any other task of your choice. It is meant to be transparent and monitorable by the owner of the system, forensically sound, customizable and compact.
  * [GetData Forensic Imager](https://getdataforensics.com/product/fex-imager/) - GetData Forensic Imager is a Windows based program that will acquire, convert, or verify a forensic image in one of the following common forensic file formats.
  * [Guymager](https://guymager.sourceforge.io/) - Guymager is a free forensic imager for media acquisition on Linux.
  * [Magnet ACQUIRE](https://www.magnetforensics.com/resources/magnet-acquire/) - ACQUIRE by Magnet Forensics allows various types of disk acquisitions to be performed on Windows, Linux, and OS X as well as mobile operating systems.

#### Evidence Collection Tools

  * [Bulk_extractor](https://github.com/simsong/bulk_extractor) - bulk_extractor is a computer forensics tool that scans a disk image, a file, or a directory of files and extracts useful information without parsing the file system or file system structures. Because of ignoring the file system structure, the program distinguishes itself in terms of speed and thoroughness.
  * [Cold Disk Quick Response](https://github.com/orlikoski/CDQR) - uses a streamlined list of parsers to quickly analyze a forenisic image file, dd, E01, .vmdk, etc, and output nine reports.
  * [Ir-rescue](https://github.com/diogo-fernan/ir-rescue) -   -ir-rescue - is a Windows Batch script and a Unix Bash script to comprehensively collect host forensic data during incident response.
  * [Live Response Collection](https://www.brimorlabs.com/tools/) - The Live Response collection by BriMor Labs is an automated tool that collects volatile data from Windows, OSX, and   -nix based operating systems.

#### Incident Management Tools

  * [Cortex XSOAR](https://www.paloaltonetworks.com/cortex/xsoar) - Security orchestration tool. Formerly Demisto community edition. Offers full Incident lifecycle management, Incident Closure Reports, team assignments and collaboration, and many integrations to enhance automations, like Active Directory, PagerDuty, Jira and much more.
  * [CyberCPR](https://www.cybercpr.com) - A community and commercial incident management tool with Need-to-Know built in to support GDPR compliance while handling sensitive incidents.
  * [Cyphon](https://www.cyphon.io/) - Cyphon eliminates the headaches of incident management by streamlining a multitude of related tasks through a single platform. It receives, processes and triages events to provide an all-encompassing solution for your analytic workflow — aggregating data, bundling and prioritizing alerts, and empowering analysts to investigate and document incidents.
  * [FIR](https://github.com/certsocietegenerale/FIR/) - Fast Incident Response, FIR, is an cybersecurity incident management platform designed with agility and speed in mind. It allows for easy creation, tracking, and reporting of cybersecurity incidents and is useful for CSIRTs, CERTs and SOCs alike.
  * [RTIR](https://bestpractical.com/rtir/) - Request Tracker for Incident Response, RTIR, is the premier open source incident handling system targeted for computer security teams. We worked with over a dozen CERT and CSIRT teams around the world to help you handle the ever-increasing volume of incident reports. RTIR builds on all the features of Request Tracker.
  * [SCOT](https://getscot.sandia.gov/) - Sandia Cyber Omni Tracker, SCOT, is an Incident Response collaboration and knowledge capture tool focused on flexibility and ease of use. Our goal is to add value to the incident response process without burdening the user.
  * [Threat_note](https://github.com/DefensePointSecurity/threat_note) - A lightweight investigation notebook that allows security researchers the ability to register and retrieve indicators related to their research.

#### Linux Forensics Distributions

  * [ADIA](https://forensics.cert.org/#ADIA) - The Appliance for Digital Investigation and Analysis, ADIA, is a VMware-based appliance used for digital investigation and acquisition and is built entirely from public domain software. Among the tools contained in ADIA are Autopsy, the Sleuth Kit, the Digital Forensics Framework, log2timeline, Xplico, and Wireshark. Most of the system maintenance uses Webmin. It is designed for small-to-medium sized digital investigations and acquisitions. The appliance runs under Linux, Windows, and Mac OS. Both i386 32-bit and x86_64 versions are available.
  * [CAINE](https://www.caine-live.net/index.html) - The Computer Aided Investigative Environment, CAINE, contains numerous tools that help investigators during their analysis, including forensic evidence collection.
  * [CCF-VM](https://github.com/orlikoski/Skadi) - CyLR CDQR Forensics Virtual Machine, CCF-VM: An all-in-one solution to parsing collected data, making it easily searchable with built-in common searches, enable searching of single and multiple hosts simultaneously.
  * [DEFT](http://na.mirror.garr.it/mirrors/deft/) - The Digital Evidence & Forensics Toolkit, DEFT, is a Linux distribution made for computer forensic evidence collection. It comes bundled with the Digital Advanced Response Toolkit, DART, for Windows. A light version of DEFT, called DEFT Zero, is also available, which is focused primarily on forensically sound evidence collection.
  * [NST - Network Security Toolkit](https://sourceforge.net/projects/nst/files/latest/download?source=files) - Linux distribution that includes a vast collection of best-of-breed open source network security applications useful to the network security professional.
  * [PALADIN](https://sumuri.com/software/paladin/) - PALADIN is a modified Linux distribution to perform various forenics task in a forensically sound manner. It comes with many open source forensics tools included.
  * [Security Onion](https://github.com/Security-Onion-Solutions/security-onion) - Security Onion is a special Linux distro aimed at network security monitoring featuring advanced analysis tools.
  * [SIFT Workstation](http://digital-forensics.sans.org/community/downloads) - The SANS Investigative Forensic Toolkit, SIFT, Workstation demonstrates that advanced incident response capabilities and deep dive digital forensic techniques to intrusions can be accomplished using cutting-edge open-source tools that are freely available and frequently updated.

#### Linux Evidence Collection

  * [FastIR Collector Linux](https://github.com/SekoiaLab/Fastir_Collector_Linux) - FastIR for Linux collects different artefacts on live Linux and records the results in csv files.

#### Log Analysis Tools

  * [Logdissect](https://github.com/dogoncouch/logdissect) - A CLI utility and Python API for analyzing log files and other data.
  * [Lorg](https://github.com/jensvoid/lorg) - a tool for advanced HTTPD logfile security analysis and forensics.

#### OSX Evidence Collection

  * [Knockknock](https://wiert.me/2020/02/10/github-synack-knockknock-whos-there/) - Displays persistent items, scripts, commands, binaries, etc., that are set to execute automatically on OSX.
  * [Mac_apt - macOS Artifact Parsing Tool](https://github.com/ydkhatri/mac_apt) - Plugin based forensics framework for quick mac triage that works on live machines, disk images or individual artifact files.
  * [OSX Auditor](https://github.com/jipegit/OSXAuditor) - OSX Auditor is a free Mac OS X computer forensics tool.
  * [OSX Collector](https://github.com/yelp/osxcollector) - An OSX Auditor offshoot for live response.

#### Incident Response Playbooks

  * [IR Workflow Gallery](https://www.incidentresponse.com/playbooks/) - Different generic incident response workflows, e.g. for malware outbreak, data theft, unauthorized access,... Every workflow constists of seven steps: prepare, detect, analyze, contain, eradicate, recover, post-incident handling.
  * [IRM](https://github.com/certsocietegenerale/IRM) - Incident Response Methodologies by CERT Societe Generale.
  * [PagerDuty Incident Response Documentation](https://github.com/PagerDuty/incident-response-docs) - Documents that describe parts of the PagerDuty Incident Response process. It provides information not only on preparing for an incident, but also what to do during and after.

#### Process Dump Tools

  * [Microsoft User Mode Process Dumping](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/user-mode-dump-files) - User mode process dumping guide.
  * [PMDump](https://vidstromlabs.com/freetools/pmdump/) - PMDump is a tool that lets you dump the memory contents of a process to a file without stopping the process.



#### Honeypot Tools
* [bap - Basic Authentication honeyPot](https://github.com/bjeborn/basic-auth-pot/) - HTTP basic authentication web service honeypot.
* [conpot](https://github.com/mushorg/conpot/) - ICS/SCADA honeypot.
* [Cowrie Docker](https://github.com/cowrie/docker-cowrie) - Docker version of Cowrie, SSH/Telnet honeypot.
* [Cowrie](https://github.com/cowrie/cowrie/) - SSH/Telnet honeypot.
* [dionaea](https://github.com/DinoTools/dionaea) - Multipurpose honeypot.
* [elastichoney](https://github.com/jordan-wright/elastichoney/) - Elasticsearch honeypot.
* [glastopf](https://github.com/mushorg/glastopf/) - Python based web application honeypot.
* [glutton](https://github.com/mushorg/glutton/) - Multipurpose honeypot.
* [Modern Honey Network (mhn)](https://github.com/pwnlandia/mhn) - Multipurpose honeypot with centralized management and many integrations.
* [MongoDB-HoneyProxy](https://github.com/Plazmaz/MongoDB-HoneyProxy/) - MongoDB honeypot.
* [MysqlPot](https://github.com/schmalle/MysqlPot/) - MySQL honeypot.
* [Nodepot](https://github.com/schmalle/Nodepot/) - NodeJS web application honeypot.
* [Nosqlpot](https://github.com/torque59/nosqlpot/) - NoSQL honeypot.
* [phpmyadmin_honeypot](https://github.com/gfoss/phpmyadmin_honeypot/) - PHPMyAdmin honeypot.
* [Servletpot](https://github.com/schmalle/Servletpot/) - Web application honeypot written in Java, making use of Apache HttpClient libraries, MySQL connector, Cassandra connector.
* [Shadow Daemon](https://github.com/zecure/shadowd/) - Collection of tools to detect, record, and prevent attacks on web applications.
* [smart-honeypot](https://github.com/freak3dot/smart-honeypot/) - PHP based honeypot.
* [SpamScope](https://github.com/SpamScope/spamscope/) - Spam analysis tool.
* [Thug](https://github.com/buffer/thug/) - Python based honeyclient tool.
* [Wordpot](https://github.com/gbrindisi/wordpot) - WordPress honeypot.
* [wp-smart-honeypot](https://github.com/freak3dot/wp-smart-honeypot/) - WordPress plugin and honeypot designed to reduce comment spam.

#### Monitoring and IDS-IPS
* [AIEngine](https://bitbucket.org/camp0/aiengine/src/master/) - Very advanced NIDS.
* [Elastic Stack](https://www.elastic.co/products/) - Also known as the ELK stack, the combination of Elasticsearch, Logstash, and Kibana, for monitoring and logging.
* [OSSEC](https://www.ossec.net/) - Open source HIDS.
* [Security Onion](https://github.com/Security-Onion-Solutions/security-onion) - Linux distro for monitoring.
* [Snort](https://www.snort.org/) - Open source NIPS/NIDS.
* [SSHWATCH](https://github.com/marshyski/sshwatch) - SSH IPS.
* [Suricata](https://suricata-ids.org/) - Open source NIPS/NIDS.



#### Timeline tools

  * [Highlighter](https://www.fireeye.com/services/freeware/highlighter.html) - Free Tool available from Fire/Mandiant that will depict log/text file that can highlight areas on the graphic, that corresponded to a key word or phrase. Good for time lining an infection and what was done post compromise.
  * [Morgue](https://github.com/etsy/morgue) - A PHP Web app by Etsy for managing postmortems.
  * [Plaso](https://github.com/log2timeline/plaso) -  a Python-based backend engine for the tool log2timeline.
  * [Timesketch](https://github.com/google/timesketch) - open source tool for collaborative forensic timeline analysis.

#### Windows Evidence Collection

  * [AChoir](https://github.com/OMENScan/AChoir) - Achoir is a framework/scripting tool to standardize and simplify the process of scripting live acquisition utilities for Windows.
  * [Binaryforay](https://binaryforay.blogspot.com/p/software.html) - list of free tools for win forensics.
  * [Crowd Response](https://www.crowdstrike.com/resources/community-tools/) - Crowd Response by CrowdStrike is a lightweight Windows console application designed to aid in the gathering of system information for incident response and security engagements. It features numerous modules and output formats.
  * [FastIR Collector](https://github.com/SekoiaLab/Fastir_Collector) - FastIR Collector is a tool that collects different artefacts on live Windows systems and records the results in csv files. With the analyses of these artefacts, an early compromise can be detected.
  * [FECT](https://github.com/jipegit/FECT) - Fast Evidence Collector Toolkit, FECT, is a light incident response toolkit to collect evidences on a suspicious Windows computer. Basically it is intended to be used by non-tech savvy people working with a journeyman Incident Handler.
  * [Fibratus](https://github.com/rabbitstack/fibratus) - tool for exploration and tracing of the Windows kernel.
  * [IREC](https://binalyze.com/irec/) - All-in-one IR Evidence Collector which captures RAM Image, $MFT, EventLogs, WMI Scripts, Registry Hives, System Restore Points and much more. It is FREE, lightning fast and easy to use.
  * [IOC Finder](https://www.fireeye.com/services/freeware/ioc-finder.html) - IOC Finder is a free tool from Mandiant for collecting host system data and reporting the presence of Indicators of Compromise. Support for Windows only.
  * [LOKI](https://github.com/Neo23x0/Loki) - Loki is a free IR scanner for scanning endpoint with yara rules and other indicators.
  * [Panorama](https://github.com/AlmCo/Panorama) - Fast incident overview on live Windows systems.
  * [PowerForensics](https://github.com/Invoke-IR/PowerForensics) - Live disk forensics platform, using PowerShell.
  * [PSRecon](https://github.com/gfoss/PSRecon/) - PSRecon gathers data from a remote Windows host using PowerShell](v2 or later), organizes the data into folders, hashes all extracted data, hashes PowerShell and various system properties, and sends the data off to the security team. The data can be pushed to a share, sent over email, or retained locally.
  * [RegRipper](https://github.com/keydet89/RegRipper3.0) - Regripper is an open source tool, written in Perl, for extracting/parsing information, keys, values, and data from the Registry and presenting it for analysis.
  * [TRIAGE-IR](https://code.google.com/archive/p/triage-ir/) - Triage-IR is a IR collector for Windows.


<br>


# Governance Risk & Compliance (GRC) Tools
* [Management Program](https://github.com/magoo/minimalist-risk-management)
* [GRC Resource List](https://github.com/Arudjreis/awesome-security-GRC)
* [Ultimate GRC](https://www.oceg.org/)
* [ISO 27001 Implementation](https://www.udemy.com/course/information-security-for-beginners/?couponCode=LINKEDIN09)
* [Windows Security Encyclopaedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)

## Device Hardening
- Department of Defense Cyber Exchange: Provides STIGs w/ hardening guidelines for a variety of software and hardware solutions
- National Checklist Program (NCP): Provided by the NIST, checklists and benchmarks for OSs and applications
* [SimplyCyber](https://simplycyber.teachable.com/) — GRC

## Auditing Tools
* [lansweeper](https://www.lansweeper.com/) — Scan hosts and compiles an asset information database (Asset inventory management)
* [Domain Password Audit Tool (DPAT)](https://github.com/clr2of8/DPAT) — Generate password statistics from hashes from a DC and a password crack file
* [Ping Castle](https://github.com/vletoux/pingcastle) — Assess the security level of the AD based on risk assessment and a maturity framework
* [Domain Audit](https://github.com/0xJs/domain_audit) — Wrapper around PowerView, Impacket, PowerUpSQL and BloodHound to execute a lot of checks

**Cloud**
* [Recon Cloud](https://recon.cloud/) - Cloud asset scanner

# Networking
* [Tailscale](https://tailscale.com/)

<hr>

# Books 

# Need to Go Through
* A Bug Hunter's Diary: A Guided Tour Through the Wilds of Software Security
* A Short Course on Computer Viruses
* AVIEN Malware Defense Guide for the Enterprise
* Advanced Penetration Testing: Hacking the World's Most Secure Networks
* Applied Cryptography: Protocols, Algorithms and Source Code in C
* Applied Network Security Monitoring: Collection, Detection, and Analysis
* Black Hat Python: Python Programming for Hackers and Pentesters
* Bug Bounty Bootcamp By Vickie Li
* Blue Team Handbook: Incident Response Edition: A condensed field guide for the Cyber Security Incident Responder
* Bulletproof SSL and TLS: Understanding and Deploying SSL/TLS and PKI to Secure Servers and Web Applications
* CEH Certified Ethical Hacker All-in-One Exam Guide
* CISSP All-in-One Exam Guide
* CISSP: Certified Information Systems Security Professional Study Guide
* CISSP](ISC)2 Certified Information Systems Security Professional Official Study Guide
* Countdown to Zero Day: Stuxnet and the Launch of the World's First Digital Weapon
* Cryptography Engineering: Design Principles and Practical Applications
* Cyber War: The Next Threat to National Security and What to Do About It
* Cybersecurity - Protecting Critical Infrastructures from Cyber Attack and Cyber Warfare
* Cybersecurity and Cyberwar: What Everyone Needs to Know
* Cybersecurity and Human Rights in the Age of Cyberveillance
* Cyberspies: The Secret History of Surveillance, Hacking, and Digital Espionage
* Essentials of Cybersecurity
* Future Crimes: Inside the Digital Underground and the Battle for Our Connected World
* Ghost in the Wires: My Adventures as the World's Most Wanted Hacker
* Hacked Again
* Hacking Exposed 7
* Hacking: The Art of Exploitation
* How Linux Works: What every superuser should know 
* Information Assurance Handbook: Effective Computer Security and Risk Management Strategies
* Linux Shell Scripting Cookbook
* Network Forensics: Tracking Hackers through Cyberspace
* Network Security Through Data Analysis: Building Situational Awareness
* Penetration Testing: A Hands-On Introduction to Hacking
* Practical Malware Analysis: A Hands-On Guide to Dissecting Malicious Software
* Practice of Network Security Monitoring
* Protecting Your Internet Identity: Are You Naked Online?
* Protection and Security on the Information Superhighway
* Reversing: Secrets of Reverse Engineering
* Rtfm: Red Team Field Manual
* Security Metrics, A Beginner's Guide
* Spam Nation: The Inside Story of Organized Cybercrime-from Global Epidemic to Your Front Door
* Surreptitious Software: Obfuscation, Watermarking, and Tamperproofing for Software Protection
* TCP/IP Illustrated
* The Art of Computer Virus Research and Defense
* The Art of Deception: Controlling the Human Element of Security
* The Art of Memory Forensics
* The Beginner's Guide to Information Security
* The Code Book: The Science of Secrecy from Ancient Egypt to Quantum Cryptography
* The Computer Incident Response Planning Handbook: Executable Plans for Protecting Information at Risk
* The Cyber Skill Gap
* The Hacker Playbook: Practical Guide To Penetration Testing
* The IDA Pro Book: The Unofficial Guide to the World's Most Popular Disassembler
* The Ncsa Guide to PC and Lan Security
* The Shellcoder's Handbook: Discovering and Exploiting Security Holes
* The Tao of Network Security Monitoring: Beyond Intrusion Detection
* The Web Application Hacker's Handbook: Finding and Exploiting Security Flaws
* Thinking Security: Stopping Next Year's Hackers
* Understanding Cryptography: A Textbook for Students and Practitioners
* We Are Anonymous: Inside the Hacker World of LulzSec, Anonymous, and the Global Cyber Insurgency
* Web Application Vulnerabilities: Detect, Exploit, Prevent
* Windows Internals
* Worm: The First Digital World War
* [A Search Engine Backed by Internet-Wide Scanning - Ariana Mirian](https://censys.io/static/censys.pdf)
* [Advanced Penetration Testing by Wil Allsopp, 2017](https://www.amazon.com/dp/1119367689/)
* [Advanced Penetration Testing for Highly-Secured Environments by Lee Allen, 2012](https://www.packtpub.com/product/advanced-penetration-testing-for-highly-secured-environments-the-ultimate-security-guide/9781849517744)
* [Advanced Persistent Threat Hacking: The Art and Science of Hacking Any Organization by Tyler Wrightson, 2014](https://www.amazon.com/dp/0071828362)
* [Android Hackers Handbook by Joshua J. Drake et al., 2014](https://www.wiley.com/en-us/Android+Hacker%27s+Handbook-p-9781118608647)
* [Black Hat Python: Python Programming for Hackers and Pentesters by Justin Seitz, 2014](https://www.amazon.com/dp/1593275900)
* [Btfm: Blue Team Field Manual by Alan White and Ben Clark](https://www.amazon.com/dp/154101636X)
* [Bug Hunter's Diary by Tobias Klein, 2011](https://nostarch.com/bughunter)
* [CIA Lock Picking Field Operative Training Manual](https://www.scribd.com/doc/7207/CIA-Lock-Picking-Field-Operative-Training-Manual)
* [Car Hacker's Handbook by Craig Smith, 2016]( https://nostarch.com/carhacking)
* [CompTIA Security+ SY0-501 Certification Study Guide](https://www.comptia.org/training/books/security-sy0-501-study-guide)
* [Complete Guide to Shodan](https://leanpub.com/shodan)
* [Dfir intro](https://sroberts.medium.com/introduction-to-dfir-d35d5de4c180)
* [Eddie the Wire books](https://www.thriftbooks.com/a/eddie-the-wire/397834/)
* [Essentials of Enterprise Network Security](https://res.cloudinary.com/peerlyst/image/upload/v1499385854/post-attachments/Essentials_of_Enterprise_Network_Security_wiqsvc.pdf)
* [Fuzzing: Brute Force Vulnerability Discovery by Michael Sutton et al., 2007](http://www.fuzzing.org/)
* [Ghost in the Wires by Kevin D. Mitnick & William L. Simon, 2011](https://www.hachettebookgroup.com/titles/kevin-mitnick/ghost-in-the-wires/9780316134477/)
* [Gray Hat Hacking The Ethical Hacker's Handbook by Daniel Regalado et al., 2015](https://www.amazon.com/dp/0071832386)
* [Hacking the Xbox by Andrew Huang, 2003](https://nostarch.com/xbox)
* [Holistic Info-Sec for Web Developers](bundle)](https://leanpub.com/b/holisticinfosecforwebdevelopers)
* [Kali Linux Revealed](https://kali.training/downloads/Kali-Linux-Revealed-1st-edition.pdf)
* [Keys to the Kingdom by Deviant Ollam, 2012](https://www.elsevier.com/books/keys-to-the-kingdom/ollam/978-1-59749-983-5)
* [Lock Picking: Detail Overkill by Solomon](https://www.dropbox.com/s/y39ix9u9qpqffct/Lockpicking%20Detail%20Overkill.pdf?dl=0)
* [Malware Analyst's Cookbook and DVD by Michael Hale Ligh et al., 2010](https://www.wiley.com/en-us/Malware+Analyst%27s+Cookbook+and+DVD%3A+Tools+and+Techniques+for+Fighting+Malicious+Code-p-9780470613030)
* [Metasploit: The Penetration Tester's Guide by David Kennedy et al., 2011](https://nostarch.com/metasploit)
* [Network Forensics: Tracking Hackers through Cyberspace by Sherri Davidoff & Jonathan Ham, 2012](https://www.amazon.com/dp/B008CG8CYU/)
* [Network Security Assessment by Chris McNab](https://www.amazon.com/dp/B0043EWUR0)
* [Nmap Network Scanning by Gordon Fyodor Lyon, 2009](https://nmap.org/book/)
* [No Tech Hacking by Johnny Long & Jack Wiles, 2008](https://www.elsevier.com/books/no-tech-hacking/mitnick/978-1-59749-215-7)
* [Open Source Intelligence Techniques - 8th Edition by Michael Bazell, 2021](https://www.amazon.com/dp/B08RRDTFF9/)
* [Penetration Testing: A Hands-On Introduction to Hacking by Georgia Weidman, 2014](https://nostarch.com/pentesting)
* [Penetration Testing: Procedures & Methodologies by EC-Council, 2010](https://www.amazon.com/dp/1435483677)
* [Practical Lock Picking by Deviant Ollam, 2012](https://www.elsevier.com/books/practical-lock-picking/ollam/978-1-59749-989-7)
* [Practical Malware Analysis by Michael Sikorski & Andrew Honig, 2012](https://nostarch.com/malware)
* [Practical Packet Analysis by Chris Sanders, 2017](https://nostarch.com/packetanalysis3)
* [Practical Reverse Engineering by Bruce Dang et al., 2014](https://www.wiley.com/en-us/Practical+Reverse+Engineering%3A+x86%2C+x64%2C+ARM%2C+Windows+Kernel%2C+Reversing+Tools%2C+and+Obfuscation-p-9781118787311)
* [Professional Penetration Testing by Thomas Wilhelm, 2013](https://www.elsevier.com/books/professional-penetration-testing/wilhelm/978-1-59749-993-4)
* [Reverse Engineering for Beginners by Dennis Yurichev](https://beginners.re/main.html)
* [Rtfm: Red Team Field Manual by Ben Clark, 2014](https://www.amazon.com/dp/1494295504/)
* [Secure Programming HOWTO](https://dwheeler.com/secure-programs/Secure-Programs-HOWTO/index.html)
* [Social Engineering in IT Security: Tools, Tactics, and Techniques by Sharon Conheady, 2014](https://www.mhprofessional.com/9780071818469-usa-social-engineering-in-it-security-tools-tactics-and-techniques-group)
* [Social Engineering: The Art of Human Hacking by Christopher Hadnagy, 2010](https://www.wiley.com/en-us/Social+Engineering%3A+The+Art+of+Human+Hacking-p-9780470639535)
* [The Art of Deception by Kevin D. Mitnick & William L. Simon, 2002](https://www.wiley.com/en-us/The+Art+of+Deception%3A+Controlling+the+Human+Element+of+Security-p-9780471237129)
* [The Art of Exploitation by Jon Erickson, 2008](https://nostarch.com/hacking2.htm)
* [The Art of Intrusion by Kevin D. Mitnick & William L. Simon, 2005](https://www.wiley.com/en-us/The+Art+of+Intrusion%3A+The+Real+Stories+Behind+the+Exploits+of+Hackers%2C+Intruders+and+Deceivers-p-9780764569593)
* [The Art of Memory Forensics by Michael Hale Ligh et al., 2014](https://www.wiley.com/en-us/The+Art+of+Memory+Forensics%3A+Detecting+Malware+and+Threats+in+Windows%2C+Linux%2C+and+Mac+Memory-p-9781118825099)
* [The Basics of Hacking and Penetration Testing by Patrick Engebretson, 2013](https://www.elsevier.com/books/the-basics-of-hacking-and-penetration-testing/engebretson/978-1-59749-655-1)
* [The Browser Hackers Handbook by Wade Alcorn et al., 2014](https://www.wiley.com/en-us/The+Browser+Hacker%27s+Handbook-p-9781118662090)
* [The Database Hacker's Handbook, David Litchfield et al., 2005](https://www.wiley.com/en-us/The+Database+Hacker%27s+Handbook%3A+Defending+Database+Servers-p-9780764578014)
* [The Hacker Playbook by Peter Kim, 2014](https://www.amazon.com/dp/1494932636/)
* [The IDA Pro Book by Chris Eagle, 2011](https://nostarch.com/idapro2.htm)
* [The Mac Hacker's Handbook by Charlie Miller & Dino Dai Zovi, 2009](https://www.wiley.com/en-us/The+Mac+Hacker%27s+Handbook-p-9780470395363)
* [The Mobile Application Hackers Handbook by Dominic Chell et al., 2015](https://www.wiley.com/en-us/The+Mobile+Application+Hacker%27s+Handbook-p-9781118958506)
* [The Practice of Network Security Monitoring: Understanding Incident Detection and Response 9](https://www.amazon.com/gp/product/1593275099)
* [The Shellcoders Handbook by Chris Anley et al., 2007](https://www.wiley.com/en-us/The+Shellcoder%27s+Handbook%3A+Discovering+and+Exploiting+Security+Holes%2C+2nd+Edition-p-9780470080238)
* [The Web Application Hackers Handbook by D. Stuttard, M. Pinto, 2011](https://www.wiley.com/en-us/The+Web+Application+Hacker%27s+Handbook%3A+Finding+and+Exploiting+Security+Flaws%2C+2nd+Edition-p-9781118026472)
* [Unauthorised Access: Physical Penetration Testing For IT Security Teams by Wil Allsopp, 2010](https://www.amazon.com/dp/B005DIAPKE)
* [Unmasking the Social Engineer: The Human Element of Security by Christopher Hadnagy, 2014](https://www.wiley.com/en-us/Unmasking+the+Social+Engineer%3A+The+Human+Element+of+Security-p-9781118608579)
* [Violent Python by TJ O'Connor, 2012](https://www.elsevier.com/books/violent-python/unknown/978-1-59749-957-6)
* [Windows Internals by Mark Russinovich et al., 2012](https://www.amazon.com/dp/0735648735/)
* [Wireshark Network Analysis by Laura Chappell & Gerald Combs, 2012](https://www.amazon.com/dp/1893939944)
* [iOS Hackers Handbook by Charlie Miller et al., 2012](https://www.wiley.com/en-us/iOS+Hacker%27s+Handbook-p-9781118204122)

## InfoSec Books

<br>

## Red Teaming
- Red Team Field Manual

<br>  

### Penetration Testing
- Penetration Testing Essentials
- Advanced Penetration Testing: Hacking the World’s Most Secure Networks
- The Pentester BluePrint: Starting a Career as an Ethical Hacker
- Penetration Testing: A Hands-On Introduction to Hacking
- The Basics of Hacking & Penetration Testing: Ethical Hacking & Penetration Made Easy
- Hands On Hacking
  
<br>

### Social Engineering
- Social Engineering: The Science of Human Hacking

<br>

### Web Applications
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

<br>

### Networking
- Aggressive Network Self-Defense (Wyler, Potter, and Hurley)
- Hacking Exposed: Network Security Secrets & Solutions (McClure et al)
- The Hacker's Handbook: Breaking Into & Defending Networks (Young and Aitel)
- Silence on the Wire: A Field Guide to Passive Recon and Indirect Attacks (Zalewski)

<br>

### Specialized
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

<br>

### Digging Deep
- A Guide to Kernel Exploitation: Attacking the Core (Perla and Oldani)
- Advanced Penetration Testing: Hacking the World's Most Secure Networks (Allsopp)
- Advanced Penetration Testing for Highly-Secured Environments (Allen and Cardwell)
- Advanced Persistent Threat Hacking: The Art & Science of Hacking (Wrightson)
- Applied Machine Learning/Neural Networks: Offensive Security (Atkins)
- Managed Code Rootkits: Hooking into Runtime Environments (Metula)
- Ninja Hacking: Unconventional Penetration Testing (Wilhelm and Andress)
- Rootkits and Bootkits (Matrosov, Rodionov, and Bratus)
- Hacking: The Art of Exploitation , 1st or 2nd edition (Jon Erickson)

<br>

## Cyber Intelligence
- We Are Bellingcat
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
* [Open Source Intelligence Techniques: Resources for Searching & Analyzing Online Information](https://inteltechniques.com/book1.html)

<br>

## Tool Guide
- Learning Nessus for Penetration Testing (Kumar)
- Metasploit: The Penetration Tester's Guide (Kennedy)
- Metasploit Penetration Testing Cookbook (Teixeira, Singh, and Agarwal)
- Nmap Network Scanning: The Official Nmap Project Guide (Fyodor)
- Nmap 6 Cookbook: The Fat-Free Guide to Network Security Scanning (Marsh)
- Penetration Tester's Open Source Toolkit (Faircloth)

## Kali Linux
- Digital Forensics With Kali Linux
- Linux Basics for Hackers: Getting Started with Networking, Scripting, & Security in Kali
- Hacking Exposed Linux (ISECOM)
- Kali Linux Revealed: Mastering the Penetration Testing Distro (Hertzog and O'Gorman)
- Linux Command Line and Shell Scripting Bible (Blum and Bresnahan)
- Linux Shell Scripting Cookbook (Flynt, Lakshman, and Tushar)
- The Linux Command Line: A Complete Introduction (Shotts)
- Wicked Cool Shell Scripts (Taylor and Perry)

<br>

## Real-World

- The Shadow Factory
- American Kingpin
- The Hacked World Order
- Black Software
- You Have A Very Soft Voice, Susan: A Shocking True Story of Internet Stalking

<br>

## Python
- Black Hat Python
- Violent Python
- Grey Hat Python
- Cryptography With Python

<br>

## Dark Web
- Tor & The Dark Web
- Burners & Black Markets
- Inside The Dark Web
- Dark Web Investiagtions (Security Informatics & Law Enforcement)

<br>

## Fiction
- The cuckoos egg
- CyberStorm: World War C

<br>

## Story Telling
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

<br>

## Bug Hunting
- A bug hunter’s diary
- Real-World Bug Hunting

<br>

## IoT
- Practical IoT Hacking

<br>

## Quantum
- Quantum Computing Fundamentals
- Quantum Physics and The Power of the Mind: 5 BOOKS IN 1

<br>

## Cryptography
- The Code Book: The Science of Secrecy from Ancient Egypt to Quantum Cryptography
- Cryptography Engineering: Design Principles and Practical Applications
- Real-World cryptography

<br>

## Law
- Damage Control: Cyber Insurance and Compliance
- The 2020 Cyber Security & Cyber Law Guide
- Cyberlaw: Software and Computer Networks

<br>

## Cybersecurity
- Cyber Mercenaries: The State, Hackers, and Power
- The hackers playbook (series)
- Stealing the network
- Little brother
- Find Me (series)
- Extreme Privacy: What It Takes to Disappear
- Cyber Breach Response That Actually Works
- We Are Anonymous
- The Tribe of Hacker (Series)
- Security Testing with Raspberry Pi
- The Smartest Person in the Room
- CyberStorm
- CyberSpace
- The 8 Layers of the OSI Cake: A Forensic Taste of Each Layer (Cyber Secrets)

<br>

## Malware
- Learning Malware Analysis
- The Art of Memory Forensics: Detecting Malware & Threats in Windows, Linux & Mac Memory
- Practical Malware Analysis
- Antivirus Bypass Techniques

<br>

## Finance Books
- The Simple Path to Wealth
- The Richest Man in Babylon
- The Psychology of Money
- I Will Teach You To Be Rich
- Rich Dad Poor Dad
- Your Money or Your Life
- 

## Psychology Books
- Dark Pyschology & Manipulation: 10 In 1
- Designing The Mind: The Principles of Psychitecture
- 48 Laws of Power

## Miscellaneous Books
- Traction by Gino Wickman
- Extreme Ownership by Jocko Willink / Leif Babin
- How to Measure Anything in Cybersecurity
- Shellcoders Handbook
- Black Hat Go
- Security Warrior
- Adversarial Tradecraft in Cybersecurity
- Hacker Disassembling Uncovered

<br>
<hr>

# Education / Bootcamps / Programs / Certification Material

## Bootcamps & Programs
* [Global Knowledge](https://www.globalknowledge.com/us-en/)
* [Level Up In Tech](https://www.levelupintech.com/)
* [DFIR Diva](https://training.dfirdiva.com/) — Compilation of Training Resources
* [Perscholas](https://perscholas.org/courses/) — Misc IT Bootcamps
* [100Devs](https://www.youtube.com/playlist?list=PLBf-QcbaigsKwq3k2YEBQS17xUwfOA3O3)
* [NetworkChuck](https://www.youtube.com/c/NetworkChuck)
* [Whizlabs](https://www.whizlabs.com/pricing/?fbclid=IwAR3egmho_JrqqADw7QZ4CLah827tinr-M5ZB51Zc35pO49T9nXqxAo29nRY&fs=e&s=cl)

## Threat Intelligence Platforms

- Closed / Propietary: Threat research and CTI data is made available as a paid subscription to a commerical CTI platform
    * [IBM-X Force Exchange](https://exchange.xforce.ibmcloud.com/)
    * [Mandiant](https://www.mandiant.com/)
    * [Recorded Future](https://www.recordedfuture.com/)
    - Public / Private Information Sharing Centers: Information Sharing & Analysis Center (ISACs)
- OSINT
    - Malware Information Sharing Project (MISP)
    - Spamhaus
    - VirusTotal
- **Threat Hunting Training**
    * [https://www.activecountermeasures.com/cyber-threat-hunting-training-course/](https://www.activecountermeasures.com/cyber-threat-hunting-training-course/)

#### Cloud Pentesting
* [FlAWS Cloud](http://flaws.cloud/) — AWS Security Training
* [FLAWS 2 Cloud](http://flaws2.cloud/) — AWS Security Training
- AWS Vulnerable
* [DVCA](https://github.com/m6a-UdS/dvca) — Demonstrate priv esc on AWS
* [OWASP Serverless Goat](https://github.com/OWASP/Serverless-Goat) — Demonstrates common serverless security flaws

<br>

## Information Security Certifications

* [Certified Ethical Hacker](https://www.eccouncil.org/programs/certified-ethical-hacker-ceh/)
* [Certified Information Systems Security Professional (CISSP)](https://www.isc2.org/Certifications/CISSP)
* [Certified Penetration Testing Engineer (CPTE)](https://www.mile2.com/penetration-testing-engineer-outline/)
* [CompTIA Security+](https://www.comptia.org/certifications/security)
* [GIAC Security Essentials (GSEC)](https://www.giac.org/certification/security-essentials-gsec)
* [Kali Linux Certified Professional (KLCP)](https://home.pearsonvue.com/kali)
* [Offensive Security Certified Expert (OSCE)](https://www.offensive-security.com/ctp-osce/)
* [Offensive Security Certified Professional (OSCP)](https://www.offensive-security.com/pwk-oscp/)
* [Offensive Security Exploitation Expert (OSEE)](https://www.offensive-security.com/awe-osee/)
* [Offensive Security Web Expert (OSWE)](https://www.offensive-security.com/awae-oswe/)
* [Offensive Security Wireless Professional (OSWP)](https://www.offensive-security.com/wifu-oswp/)
* [Practical Network Penetration Tester (PNPT)](https://certifications.tcm-sec.com/pnpt/)
* [HTB Certified Bug Bounty Hunter (HTB BBH)](https://academy.hackthebox.com/preview/certifications/htb-certified-bug-bounty-hunter/)
* [HTB Certified Penetration Testing Specialist (HTB CPTS)](https://academy.hackthebox.com/preview/certifications/htb-certified-penetration-testing-specialist/)
* [eLearnSecurity Junior Penetration Tester (eJPT)](https://elearnsecurity.com/product/ejpt-certification/)



## Security Training Platforms
* [Attack-Defense](https://attackdefense.com)
* [Crackmes](https://crackmes.one/)
* [Ring Zero Team](https://ringzer0ctf.com/)
* [Black Hills Information Security — Cyber Range](https://www.blackhillsinfosec.com/services/cyber-range/)
* [Alert To Win](https://alf.nu/alert1?world=alert&level=alert0)
* [CTF Komodo Security](https://ctf.komodosec.com)
* [CMD Challenge](https://cmdchallenge.com)
* [Explotation Education](https://exploit.education)
* [Google CTF](https://lnkd.in/e46drbz8)
* [HackTheBox](https://www.hackthebox.com)
* [Hackthis](https://defendtheweb.net/)
* [Hacksplaining](https://www.hacksplaining.com/lessons)
* [Hacker101](https://ctf.hacker101.com)
* [Hacker Security](https://hackersec.com/)
* [Hacking-Lab](https://hacking-lab.com/)
* [ImmersiveLabs](https://www.immersivelabs.com/)
* [OverTheWire](http://overthewire.org)
* [Practical Pentest Labs](https://lnkd.in/esq9Yuv5)
* [Pentestlab](https://pentesterlab.com)
* [Penetration Testing Practice Labs](https://lnkd.in/e6wVANYd)
* [PentestIT LAB](https://lab.pentestit.ru/)
* [PicoCTF](https://picoctf.com)
* [PWNABLE](https://lnkd.in/eMEwBJzn)
* [Root Me](https://www.root-me.org/?lang=en)
* [Root In Jail](https://rootinjail.com/)
* [SmashTheStack](http://www.smashthestack.org/wargames.html)
* [The Cryptopals Crypto Challenges](https://cryptopals.com/)
* [Try Hack Me](https://tryhackme.com/)
* [Vulnhub](https://www.vulnhub.com)
* [W3Challs](https://w3challs.com)
* [WeChall](http://www.wechall.net/)
* [Alerted Security](https://www.alteredsecurity.com/)

### Offensive Development
* [Offensive Development](https://www.antisyphontraining.com/offensive-development-w-greg-hatcher-john-stigerwalt/)

* [Exploiting Tokens (Write-Up)](https://jsecurity101.medium.com/exploring-token-members-part-1-48bce8004c6a)


### Defense
#### Azure
* [Detect Azure AD Backdoors: Identity Federation](https://www.inversecos.com/2021/11/how-to-detect-azure-active-directory.html)




### Methodologies
* [Open Source Security Testing Methodology Manual (OSSTMM)](https://www.isecom.org/OSSTMM.3.pdf)

## Documentaries
* [https://threadreaderapp.com/thread/1491830217471528962.html](https://threadreaderapp.com/thread/1491830217471528962.html)
- Best Cyber Security and Hacking Documentary #1
- We Are Legion – The Story Of The Hacktivists ([https://lnkd.in/dEihGfAg](https://lnkd.in/dEihGfAg))
- The Internet’s Own Boy: The Story Of Aaron Swartz ([https://lnkd.in/d3hQVxqp](https://lnkd.in/d3hQVxqp))
* [Hackers Wanted](https://www.youtube.com/watch?v=Mn3ooBnShtY)
* [Secret History Of Hacking](https://www.youtube.com/watch?v=PUf1d-GuK0Q)
* [Def Con: The Full Documentary](https://www.youtube.com/watch?v=3ctQOmjQyYg)
* [Web Warriors (Documentary Over Cyber Warfare)](https://www.youtube.com/watch?v=0IY7DL0ihYI)
* [Risk (2016)](https://www.imdb.com/title/tt4964772/)
* [Zero Days (2016)](https://www.imdb.com/title/tt5446858/)
* [Guardians Of The New World (Hacking Documentary) | Real Stories](https://www.youtube.com/watch?v=jUFEeuWqFPE)
* [A Origem dos Hackers](https://www.youtube.com/watch?v=LPqXNGcwlxo&t=2s)
* [The Great Hack](https://lnkd.in/dp-MsrQJ)
* [The Networks Dilemma](https://lnkd.in/dB6rC2RD)
* [21st Century Hackers](https://www.youtube.com/watch?v=nsKIADw7TEM)
* [Cyber War - Dot of Documentary](https://www.youtube.com/watch?v=UaZw9mQu7xg)
* [CyberWar Threat - Inside Worlds Deadliest Cyberattack](https://lnkd.in/drmzKJDu)
* [The Future of Cyberwarfare: The Journey of Humankind](https://www.youtube.com/watch?v=L78r7YD-kNw)
* [Dark Web Fighting Cybercrime Full Hacking](https://lnkd.in/dByEzTE9)
* [Cyber Defense: Military Training for Cyber Warfare](https://lnkd.in/dhA8c52h)
* [Hacker Hunter: WannaCry The History Marcus Hutchin](https://lnkd.in/dnPcnvSv)
* [The Life Hacker Documentary](https://lnkd.in/djAqBhbw)
* [Hacker The Realm and Electron - Hacker Group](https://lnkd.in/dx_uyTuT])

### Social Engineering Articles
* [How I Socially Engineer Myself Into High Security Facilities](https://www.vice.com/en/article/qv34zb/how-i-socially-engineer-myself-into-high-security-facilities) - Sophie Daniel
* [Social Engineering: Compromising Users with an Office Document](https://resources.infosecinstitute.com/certification/social-engineering-compromising-users-using-office-document/) - Infosec Institute
* [The 7 Best Social Engineering Attacks Ever](https://www.darkreading.com/the-7-best-social-engineering-attacks-ever/d/d-id/1319411) - DarkReading
* [The Limits of Social Engineering](https://www.technologyreview.com/2014/04/16/173156/the-limits-of-social-engineering/) - MIT, Technology Review
* [The Persuasion Reading List](https://www.scottadamssays.com/2018/01/24/persuasion-reading-list-updated-1-18/) - Scott Adams' Blog


## Resource Compilation

* [Cybersecurity Documents, Certification Help, Books, etc.](https://drive.google.com/drive/u/0/folders/1xCCknZbUGhJQd8UKAwL_m9upJgmaQVBr?fbclid=IwAR2I99iLaHwgeyzEZeigh32gtrAIS1gUSC6Xo6ASaamJi3XRwip1zAtpH9k)
* [S0cm0nkey’s Security Reference Guide](https://s0cm0nkey.gitbook.io/s0cm0nkeys-security-reference-guide/)
* [Red Teaming Experiments](https://www.ired.team/) — Cheatsheets
* [Darkstar](https://darkstar7471.com/resources.html) — Infosec Training Resources



### Offense Security
* [OSCE3](https://github.com/CyberSecurityUP/OSCE-Complete-Guide)
        

### Bug Hunting
* [Bug Hunter Handbook](https://gowthams.gitbook.io/bughunter-handbook/)

### Powershell Automation
* [PowerShell Intune Samples](https://github.com/microsoftgraph/powershell-intune-samples) — Make HTTPS RESTful API requests
* [Mega Collection of PowerShell Scripts](https://github.com/fleschutz/PowerShell)

### Privacy

* [https://www.privacytools.io/](https://www.privacytools.io/)
* [S1ckB0y1337](https://github.com/S1ckB0y1337?tab=repositories)
* [Build Your Own X](https://github.com/codecrafters-io/build-your-own-x) — Repository Compilation Projects for Hackers
* [Cyber Security Repo](https://cyber-security.tk/categories/)
* [Computer Science Video Courses](https://github.com/Developer-Y/cs-video-courses)
* [Awesome Docker Security](https://github.com/myugan/awesome-docker-security) — Resources for Docker Security (Books, Blogs, Videos, Tools, etc.)
* [Microsoft Graph](https://github.com/microsoftgraph) — Access data, relationships and insights coming from the cloud
* [VX-Underground](https://github.com/vxunderground) — Collection of malware source code, amples, and PoCs
* [W3BS3C](https://www.w3bs3c.com/) — Web3 searchable curable repository of tools, CTFs, 101s, videos, and bounties
* [Hacker Arise](https://www.hackers-arise.com/post/the-cyberwar-vs-putin-what-we-are-doing-and-what-you-can-do-to-help)
* [Malware Development Repo](https://lookbook.cyberjungles.com/random-research-area/malware-analysis-and-development/malware-development)
* [Machine Learning](https://github.com/dair-ai/ML-Course-Notes)

## Cybersecurity Maps, Domains, etc
(https://s3-us-west-2.amazonaws.com/secure.notion-static.com/087527b0-f437-4255-8b00-0bc69c7dcd73/Untitled.png)
* [Paul Jerimy — Cyber Certification Roadmap](https://pauljerimy.com/security-certification-roadmap/)

## Security News — Stay Updated On Relevant Attacks & Other Infosec News**

* [Feedspot](https://blog.feedspot.com/cyber_security_rss_feeds/) — Top 100 Cybersecurity RSS Feeds
* [GBHackers on Security](https://gbhackers.com/)
* [Isaca](https://www.isaca.org/)
- Microsoft
* [PenTest Magazine](https://pentestmag.com/)
* [TDLR Magazine](https://tldr.tech/crypto)
* [Tripwire](https://www.tripwire.com/state-of-security/contributors/graham-cluley/)
* [Naked Security](https://nakedsecurity.sophos.com/)
* [ThreatPost](https://threatpost.com/)
* [Scheiner](https://www.schneier.com/)
* [DarkReading](https://www.darkreading.com/)
* [EFF](https://www.eff.org/deeplinks)
* [ZDNet](https://www.zdnet.com/blog/security/)
* [KrebsOnSecurity](https://krebsonsecurity.com/)
* [Talos Intelligence](https://blog.talosintelligence.com/)
### Specific Articles
* [BendyBear](https://x-phy.com/advanced-shell-code-a-use-case-of-blacktech-associated-bendybear/)

### CVEs
#### Apple
* [https://www.websecgeeks.com/2022/06/how-i-was-able-to-send-emails-on-behalf-of-any-apple-user-email.html](https://www.websecgeeks.com/2022/06/how-i-was-able-to-send-emails-on-behalf-of-any-apple-user-email.html)

## Freelancing Sites
* [Fiverr](https://www.fiverr.com/)
* [UpWork](https://www.upwork.com/)

## Support Organizations

### Black Tech Organizations
* [10 Professional Organizations for Black IT Professionals](https://www.cio.com/article/191321/10-professional-organizations-for-black-it-pros.html)
* [Organizations We Love (OWL)](https://sites.temple.edu/care/dei/owl/)

### Conferences
* (ISC)2 Secure Event Series
* 44CON London
* 44Con
* AFCEA Defensive Cyber Operations Symposium
* AppSec United States](OWASP National Conference)
* AppSecUSA
* Atlantic Security Conference](AtlSecCon)
* BSides
* BSides Event Series
* BalCCon
* Black Hat
* Black Hat United States
* BruCON
* CCC
* CISO Executive Summit Series](Invite-only)
* CSO50 Conference
* CanSecWest
* CarolinaCon
* Cyber Threat Intelligence Summit
* DEF CON
* DeepSec
* DefCamp
* DerbyCon
* DerbyCon 8.0
* Ekoparty
* FIRST Conference
* FSec
* HACKMIAMI
* HITB
* HOPE
* Hack.lu
* Hack3rCon
* Hacker Halted - Optionally includes certification-specific training
* IANS Information Security Forums
* IAPP Global Privacy Summit
* IEEE Symposium on Security & Privacy
* ISACA Cyber Security Nexus
* ISF Annual World Congress
* ISSA CISO Executive Forum Series
* ISSA International Conference
* Ignite
* Infiltrate
* InfoSec Southwest
* InfoSec World
* Infosecurity Europe
* Infosecurity Europe
* Infosecurity North America
* LayerOne
* Nullcon
* Nullcon Conference
* Open Security Summit
* PhreakNIC
* RSA Conference United States
* SANS Annual Conference
* SANS Pen Test Annual Conferences
* SANS Security Annual Conferences
* SECUINSIDE
* SOURCE Annual Conferences
* SecTor Canada
* Secure360 Conference
* SecureWorld
* Securi-Tay
* Security Operations Summit & Training
* ShmooCon
* SkyDogCon
* SummerCon
* Swiss Cyber Storm
* ThotCon
* USENIX Security Symposium
* Virus Bulletin Conference
* conINT
* secureCISO

## **Cybersecurity Apparel**
* [Alpha Cyber Security](https://www.teepublic.com/user/djax120)

## Blogging



