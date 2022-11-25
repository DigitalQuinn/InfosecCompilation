# blAck0ps
**blAck0ps** is a repository designed for advanced penetration testing tactics, techniques, and procedures (TTPs) based on the MITRE framework


# Table of Contents
- [A Hacker's Methodology / å ˙å˚´®…ß µ´†˙ø∂ø¬ø©¥](#a-hackers-methodology--å-˙å˚´®ß-µ´†˙ø∂ø¬ø©¥)
- [Homelab](#homelab)
  - [Repository](#repository)
  - [AD Homelab](#ad-homelab)
  - [Sandbox](#sandbox)
  - [Network Access Control (NAC)](#network-access-control-nac)
  - [Vulnerable Images](#vulnerable-images)
  - [Malware](#malware)
  - [Reverse Engineering Guides](#reverse-engineering-guides)
  - [Malware Analysis Homelab Setup](#malware-analysis-homelab-setup)
  - [Malware Tools](#malware-tools)
  - [Endpoint Detection & Response (EDR)](#endpoint-detection--response-edr)
  - [Security Incident Event Monitoring (SIEM)](#security-incident-event-monitoring-siem)
- [Hacking References & Cheatsheets](#hacking-references--cheatsheets)
  - [Showcasings](#showcasings)
- [Tools](#tools)
  - [Offensive Security](#offense-security)
    - [Planning](#planning)
    - [Reconnaissance Tools](#reconnaissance-tools)
      - [OSINT Frameworks](#osint-frameworks)
      - [Search Engines](#search-engines)
        - [National Search Engines](#national-search-engines)
      - [OSINT Tools](#osint-tools)
        - [Document & Slides Search](#document--slides-search)
        - [Source Code Search](#source-code-search)
        - [Crypto OSINT Search](#crypto-osint-search)
        - [Government Record Search](#government-record-search)
        - [National Search Engines](#national-search-engines)
        - [Real-Time, Social Media Search](#real-time-social-media-search)
        - [Personal Investigations](#personal-investigations)
        - [Email Search](#email-search)
        - [Phone Number Research](#phone-number-research)
        - [Company Research](#company-research)
        - [Domain & IP Research](#domain--ip-research)
        - [Keywords Discovery](#keywords-discovery)
        - [Web History](#web-history)
        - [Image Search](#image-search)
        - [Web Monitoring](#web-monitoring)
        - [Social Network Analysis](#social-network-analysis)
        - [DNS Enumeration](#dns-enumeration)
        - [Network Reconnaissance Tools](#network-reconnaissance-tools)
      - [IP Scanners](#ip-scanners)
        - [Extensions](#extensions)
      - [Vulnerability Scanners](#vulnerability-scanners)
    - [Resource Development Tools](#resource-development-tools)
      - [Hardware](#hardware)
        - [Lockpicking](#lockpicking)
      - [CLI Usability](#cli-usability)
    - [Initial Access Tools](#initial-access-tools)
      - [Phishing](#phishing)
    - [Execution Tools](#execution-tools)
    - [Persistence Tools](#persistence-tools)
    - [Privilege Escalation Tools](#privilege-escalation-tools)
    - [Defense Evasion Tools](#defense-evasion-tools)
      - [Evade AV / EDR](#evade-avedr)
      - [Packet Injection](#packet-injection)
      - [Wrappers](#wrappers)
    - [Credential Access Tools](#credential-access-tools)
      - [Password Attacks](#password-attacks)
      - [Hash Cracking](#hash-cracking)
    - [Discovery Tools](#discovery-tools)
    - [Lateral Movement Tools](#lateral-movement-tools)
    - [Collection Tools](#collection-tools)
    - [C2 Tools](#c2-tools)
      - [Penetration Testing / C2 Frameworks](#penetration-testing--c2-frameworks)
    - [Impact](#impact)
    - [Remediation / Reporting](#remediation--reporting)
    - [Cloud Pentesting](#cloud-pentesting)
      - [AWS](#aws)
      - [GCP](#gcp)
      - [Azure](#azure)
      - [Misc.](#misc)
    - [Active Directory](#active-directory)
    - [Compilation of Tools](#compilation-of-tools)
      - [Python](#python)
      - [Wireless Pentesting](#wireless-pentesting)
- [Defensive Security](#defensive-security)
  - [Governance Risk & Compliance (GRC)](#governance-risk--compliance-grc)
    - [Device Hardening](#device-hardening)
    - [Auditing Tools](#auditing-tools)
- [Networking](#networking)
- [Books](#books)
  - [InfoSec Books](#infosec-books)
    - [Red Teaming](#red-teaming)
    - [Penetration Testing](#penetration-testing)
    - [Social Engineering](#social-engineering)
    - [Web Applications](#web-applications)
    - [Networking](#networking)
    - [Specialized / Digging Deep](#specialized--digging-deep)
    - [Cyber Intelligence](#cyber-intelligence)
    - [Tool Guide](#tool-guide)
    - [Kali Linux](#kali-linux)
    - [Real-World](#real-world)
    - [Python](#python)
    - [Dark Web](#dark-web)
    - [Fiction](#fiction)
    - [Story Telling](#story-telling)
    - [Bug Hunting](#bug-hunting)
    - [IoT](#iot)
    - [Quantum](#quantum)
    - [Cryptography](#cryptography)
    - [Law](#law)
    - [Cybersecurity](#cybersecurity)
    - [Malware](#malware-1)
  - [Finance Books](#finance-books)
  - [Psychology Books](#psychology-books)
  - [Miscellaneous Books](#miscellaneous-books)
- [Education / Bootcamps / Programs / Certification Material](#education--bootcamps--programs--certification-material)
  - [Bootcamps & Programs](#bootcamps--programs)
  - [Threat Intelligence Platforms](#threat-intelligence-platforms)
    - [Propietary](#propietary)
    - [OSINT](#osint)
  - [Threat Hunting Training](#threat-hunting-training)
  - [Information Security Certifications](#information-security-certifications)
  - [Security Training Platforms](#security-training-platforms)
    - [Cloud Pentesting Training](#cloud-pentesting-training)
    - [Offensive Development](#offensive-development)
    - [Defensive Development](#defensive-development)
      - [Azure](#azure)
  - [Methodologies](#methodologies)
- [Documentaries](#documentaries)
- [Social Engineering Articles](#social-engineering-articles)
- [Resource Compilation](#resource-compilation)
  - [Bug Hunting](#bug-hunting)
  - [Powershell Automation](#powershell-automation)
  - [Privacy](#privacy)
- [Cybersecurity Road Maps, Domains, etc.](#cybersecurity-maps-domains-etc)
- [Security News](#security-news)
  - [Specific Articles](#specific-articles)
  - [CVEs](#cves)
- [Freelancing Sites](#freelancing-sites)
- [Support Organizations](#support-organizations)
  - [Black Tech Organizations](#black-tech-organizations)
  - [Conferences](#Conferences)
- [Cybersecurity Apparel](#cybersecurity-apparel)
- [Alpha Cyber Security](https://www.teepublic.com/user/djax120)
- [Blogging](#blogging)

<br>
<hr>

# A Hacker's Methodology / å ˙å˚´®…ß µ´†˙ø∂ø¬ø©¥

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
- [Blue Team Homelab](https://github.com/aboutsecurity/blueteam_homelabs) — Blue Team Environment
- [SecGen](https://github.com/cliffe/SecGen) — Creates vulnerable VMs, Lab Environments, & Hacking challenges
- [DetectionLab](https://github.com/clong/DetectionLab) - Quickly build a Windows domain with pre-loaded with security tooling and system logging configurations

## AD Homelab
- [SpookySec](https://lnkd.in/eN8V88kv)
- [Vulnerable-AD](https://github.com/WazeHell/vulnerable-AD) - Set up a Vulnerable AD lab 

## Sandbox
- [Cuckoo](https://cuckoosandbox.org/) - open source automated malware analysis system
- [DRAKVUF Sandbox](https://github.com/CERT-Polska/drakvuf-sandbox/) - Automated black-box malware analysis system with DRAKVUF engine under the hood (Doesn't require an agent on guest OS)
- [PacketTotal](https://packettotal.com/) — Online PCAP Analysis Engine
- [Joe Sandbox Cloud](https://www.joesandbox.com/#windows) - Automated malware sandbox (Live interaction capabilities)
- [CAPE](https://github.com/kevoreilly/CAPEv2/) - Malware sandbox, derived from Cuckoo with the goal of adding automated malware unpacking and config extraction

## Network Access Control (NAC)
- [Packet Fence](https://www.packetfence.org/) — Open source NAC

## Vulnerable Images
- [Exploit Education](https://exploit.education) - Variety of resources to learn about vulnerability analysis, exploit development, software debugging, binary analysis, and general cyber security issues
- [Docker Images](https://houdini.secsi.io/) - Hundreds of offensive and useful Docker images for penetration testing
- [https://crackmes.one/](https://crackmes.one/) — Binaries for Reverse Engineering

## Malware 

- [VX-Underground](https://github.com/vxunderground/MalwareSourceCode) — Malware source code
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

## Reverse Engineering Guides
- [https://c3rb3ru5d3d53c.github.io/docs/malware-analysis-beginner-guide/](https://c3rb3ru5d3d53c.github.io/docs/malware-analysis-beginner-guide/)

## Malware Analysis Homelab Setup
- [KVM Malware Lab](https://c3rb3ru5d3d53c.github.io/docs/kvm-malware-lab/)

## Malware Tools
- [Malware Analysis Tools](https://0x1.gitlab.io/security/Malware-Analysis-Tools-List/)
- [MalAPI](https://malapi.io/) — Catalog of Windows APIs commonly used in malware
- [Qu1cksc0pe] - All-in-One Static Malware Analysis Tool

## Endpoint Detection & Response (EDR)
- [Intezer Protect](https://www.intezer.com/intezer-protect/) — EDR built for your cloud

## Security Incident Event Monitoring (SIEM)
- [https://wazuh.com](https://wazuh.com/)

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

- [Ethical Hacking Playground (Repo)](https://github.com/ethicalhackingplayground?tab=repositories)
- [Saeid](https://github.com/saeidshirazi?tab=repositories)
- [ustayready](https://github.com/ustayready?tab=repositories)
- [infosecn1nja](https://github.com/infosecn1nja?tab=repositories)
- [https://github.com/13o-bbr-bbq/machine_learning_security/wiki](https://github.com/13o-bbr-bbq/machine_learning_security/wiki)

- https://github.com/CyberSecurityUP/PenTest-Consulting-Creator
- [Red Team Infrastructure](https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki)

# Offensive Security Tools 
## Planning 

## Reconnaissance Tools 

### OSINT Frameworks
- [ReconSpider](https://hakin9.org/reconspider-most-advanced-open-source-intelligence-osint-framework/)
- [HostRecon](https://github.com/dafthack/HostRecon) — Provide situational awareness during reconnaissance of an engagement
  
### Search Engines
- [Shodan](https://www.shodan.io/) - Database containing information on all accessible domains on the internet obtained from passive scanning
- [Wigle](https://wigle.net/) - Database of wireless networks, with statistics
- [Binary Edge](https://www.binaryedge.io/) - Scans the internet for threat intelligence
- [ONYPHE](https://www.onyphe.io/) - Collects cyber-threat intelligence data
- [GreyNoise](https://www.greynoise.io/) - Search for devices connected to the internet
- [Censys](https://censys.io/) - Assessing attack surface for internet connected devices
- [Hunter](https://hunter.io/) - Search for email addresses belonging to a website
- [ZoomEye](https://www.zoomeye.org/) - Gather information about targets
- [LeakIX](https://leakix.net/) - Search publicly indexed information
- [IntelligenceX](https://intelx.io/) - Search Tor, I2P, data leaks, domains, and emails
- [Netlas](https://netlas.io/) - Search and monitor internet connected assets
- [URL Scan](https://urlscan.io/) - Free service to scan and analyse websites
- [PublicWWW](https://publicwww.com/) -  Marketing and affiliate marketing research
- [FullHunt](https://fullhunt.io/) - Search and discovery attack surfaces
- [crt.sh](https://crt.sh/) - Search for certs that have been logged by CT
- [Vulners](https://vulners.com/) - Search vulnerabilities in a large database
- [Pulsedive](https://pulsedive.com/) - Search for threat intelligence
- [Packet Storm Security](https://packetstormsecurity.com/) - Browse latest vulnerabilities and exploits
- [GrayHatWarefare](https://grayhatwarfare.com/) - Search public S3 buckets and URL shorteners
- [Dehashed](https://www.dehashed.com/) - Search for anything like username, email, passwords, address, or phone number.
- [Have I Been Pwned?](https://haveibeenpwned.com/) - Check whether personal data has been compromised by data breaches
- [Snusbase](https://snusbase.com/) - Indexes information from hacked websites and leaked databases
- [LeakBase](https://leakbase.cc/) - Forum of leaked databases
- [LeakCheck](https://leakcheck.io/) - Data breach search engine
- [GhostProject.fr](https://ghostproject.fr/) - Smart search engine
- [SecurityTrails](https://securitytrails.com/) - Extensive DNS data
- [DorkSearch](https://dorksearch.com/) - Really fast Google dorking
- [ExploitDB](https://www.exploit-db.com/) - Archive of various exploits
- [PolySwarm](https://polyswarm.io/) - Scan files and URLs for threats
- [DNSDumpster](https://dnsdumpster.com/) - Search for DNS records quickly
- [FullHunt](https://fullhunt.io/) - Search and discovery attack surfaces
- [AlienVault](https://otx.alienvault.com/) - Extensive threat intelligence feed
- [Vulners](https://vulners.com/) - Search vulnerabilities in a large database
- [WayBackMachine](https://web.archive.org/) - View content from deleted websites
- [SearchCode](https://searchcode.com/) - Search 75 billion lines of code from 40 million projects

### OSINT Tools
- [Catana-DS](https://github.com/TebbaaX/Katana) — Automates Google Dorking
- [Mitaka](https://hakin9.org/mitaka-a-browser-extension-for-osint/) — Browser extension for OSINT
- [https://infosecwriteups.com/osint-and-top-15-open-source-intelligence-tools-f5132bf9e40f](https://infosecwriteups.com/osint-and-top-15-open-source-intelligence-tools-f5132bf9e40f)
- [GooFuzz](https://github.com/m3n0sd0n4ld/GooFuzz) — Perform fuzzing with an OSINT approach, managing to enumerate directories, files, subdomains or parameters without leaving evidence on the target's server and by means of advanced Google searches
- [https://ipspy.net/](https://ipspy.net/) - IP Lookup, WHOIS, and DNS resolver
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
- [LOTS Project](https://lots-project.com/) — Websites that allows attackers to use their domain when conducting phishing, C2, exfiltration, and downloading tools to evade detection
- [OSINT Repository](https://cipher387.github.io/osint_stuff_tool_collection/)
- [DarkSide](https://hakin9.org/darkside-tool-information-gathering-social-engineering/) — OSINT & Social Engineering Tool
- [SocialHunter](https://github.com/utkusen/socialhunter) — Crawls the given URL and finds broken social media links that can be hijacked
- [IntelTechniques](https://inteltechniques.com/tools/index.html) — Resources hosted by IntelTechniques Podcast
- [exitLooter](https://github.com/aydinnyunus/exifLooter) - Find geolocation on image URL and directories
- [AutoRecon](https://github.com/Tib3rius/AutoRecon) - Performs automated enumeration of services
  - [FavFreak](https://github.com/devanshbatham/FavFreak) -  Fetches the favicon.ico and hash value and generates shodan dorks 
  - [Nrich](https://gitlab.com/shodan-public/nrich) - Quickly analyze IPs and determines open ports / vulnerabilities
  - [Uncover](https://github.com/projectdiscovery/uncover) - Quickly discover exposed hosts on the internet using shodan, censys and fofa
  - [Meg](https://github.com/tomnomnom/meg) - Quickly find hidden paths/directories without flooding traffic
  - [Naabu](https://github.com/projectdiscovery/naabu) - Enumerate valid ports conducting a SYN/CONNECT scans on the host(s) ports that return a reply
- [mip22](https://github.com/makdosx/mip22) - Advanced phishing tool
- [Recon Cloud](https://recon.cloud/) - Cloud asset scanner
- [MailSniper](https://github.com/dafthack/MailSniper) — Searches through email in a Microsoft Exchange environment for specific terms
- [MOSINT] - OSINT Tool For Emails
- [SharpML] - Machine Learning Network Share Password Hunting Toolkit
* [AbuseIPDB](https://www.abuseipdb.com/) - Search engine for blacklisted IPs or domains.
* [AutoShun](https://riskanalytics.com/community/) - Public repository of malicious IPs and other resources.
* [BadIPs](https://www.badips.com/) - Online blacklist lookup.
* [Barcode Reader](https://online-barcode-reader.inliteresearch.com/) - Decode barcodes in C#, VB, Java, C\C++, Delphi, PHP and other languages.
* [Belati](https://github.com/aancw/Belati) - The Traditional Swiss Army Knife For OSINT. Belati is tool for Collecting Public Data & Public Document from Website and other service for OSINT purpose.
* [Binary Defense IP Ban List](https://www.binarydefense.com/banlist.txt) - Public IP blacklist.
* [Blocklist Ipsets](https://github.com/firehol/blocklist-ipsets) - Public IP blacklist.
* [Censys](https://censys.io/) - Collects data on hosts and websites through daily ZMap and ZGrab scans.
* [CloudFrunt](https://github.com/MindPointGroup/cloudfrunt) - Tool for identifying misconfigured CloudFront domains.
* [Combine](https://github.com/mlsecproject/combine) - Open source threat intelligence feed gathering tool.
* [Creepy](https://github.com/ilektrojohn/creepy) - Geolocation OSINT tool.
* [Datasploit](https://github.com/DataSploit/datasploit) - Tool to perform various OSINT techniques on usernames, emails addresses, and domains.
* [Dnsenum](https://github.com/fwaeytens/dnsenum/) - Perl script that enumerates DNS information from a domain, attempts zone transfers, performs a brute force dictionary style attack, and then performs reverse look-ups on the results.
* [Dnsmap](https://github.com/makefu/dnsmap/) - Passive DNS network mapper.
* [Dnsrecon](https://github.com/darkoperator/dnsrecon/) - DNS enumeration script.
* [Dnstracer](http://www.mavetju.org/unix/dnstracer.php) - Determines where a given DNS server gets its information from, and follows the chain of DNS servers.
* [Dork-cli](https://github.com/jgor/dork-cli) - Command line Google dork tool.
* [emagnet](https://github.com/wuseman/EMAGNET) - Automated hacking tool that will find leaked databases.
* [FindFrontableDomains](https://github.com/rvrsh3ll/FindFrontableDomains) - Multithreaded tool for finding frontable domains.
* [GOSINT](https://github.com/Nhoya/gOSINT) - OSINT tool with multiple modules and a telegram scraper.
* [Github-dorks](https://github.com/techgaun/github-dorks) - CLI tool to scan github repos/organizations for potential sensitive information leak.
* [GooDork](https://github.com/k3170makan/GooDork) - Command line Google dorking tool.
* [Google Hacking Database](https://www.exploit-db.com/google-hacking-database) - Database of Google dorks; can be used for recon.
* [InfoByIp](https://www.infobyip.com/ipbulklookup.php) - Domain and IP bulk lookup tool.
* [Intrigue Core](https://github.com/intrigueio/intrigue-core) - Framework for attack surface discovery.
* [Machinae](https://github.com/hurricanelabs/machinae) - Multipurpose OSINT tool using threat intelligence feeds.
* [Maltego](https://www.maltego.com/) - Proprietary software for open source intelligence and forensics, from Paterva.
* [Malware Domain List](http://www.malwaredomainlist.com/) - Search and share malicious URLs.
* [NetBootcamp OSINT Tools](https://netbootcamp.org/osinttools/)
* [OSINT Framework](https://osintframework.com/)
* [OpenRefine](https://github.com/OpenRefine) - Free & open source power tool for working with messy data and improving it.
* [Orbit](https://github.com/s0md3v/Orbit) - Draws relationships between crypto wallets with recursive crawling of transaction history.
* [OsintStalker](https://github.com/milo2012/osintstalker) - Python script for Facebook and geolocation OSINT.
* [Outwit](http://www.outwit.com) - Find, grab and organize all kinds of data and media from online sources.
* [PaGoDo](https://github.com/opsdisk/pagodo) - Passive, automated Google dorking tool.
* [Passivedns-client](https://github.com/chrislee35/passivedns-client) - Library and query tool for querying several passive DNS providers.
* [Passivedns](https://github.com/gamelinux/passivedns) - Network sniffer that logs all DNS server replies for use in a passive DNS setup.
* [Photon](https://github.com/s0md3v/Photon) - Crawler designed for OSINT.
* [Pown Recon](https://github.com/pownjs/recon) - Target reconnaissance framework powered by graph theory.
* [QuickCode](https://quickcode.io/) - Python and R data analysis environment.
* [Raven](https://github.com/0x09AL/raven) - LinkedIn information gathering tool.
* [Recon-ng](https://github.com/lanmaster53/recon-ng) - Full-featured Web Reconnaissance framework written in Python.
* [SecApps Recon](https://secapps.com/tools/recon/) - Information gathering and target reconnaissance tool and UI.
* [Spamcop](https://www.spamcop.net/bl.shtml) - IP based blacklist.
* [Spamhaus](https://www.spamhaus.org/lookup/) - Online blacklist lookup.
* [Spiderfoot](https://www.spiderfoot.net/) - Open source OSINT automation tool with a Web UI and report visualizations
* [ThreatCrowd](https://www.threatcrowd.org/) - Threat search engine.
* [ThreatTracker](https://github.com/michael-yip/ThreatTracker) - Python based IOC tracker.
* [Vcsmap](https://github.com/melvinsh/vcsmap) - Plugin-based tool to scan public version control systems for sensitive information.
* [XRay](https://github.com/evilsocket/xray) - XRay is a tool for recon, mapping and OSINT gathering from public networks.
* [Zen](https://github.com/s0md3v/Zen) - Find email addresses of Github users.
* [malc0de DNSSinkhole](http://malc0de.com/bl/) - List of domains that have been identified as distributing malware during the past 30 days.
* [malc0de Database](http://malc0de.com/database/) - Searchable incident database.
* [pygreynoise](https://github.com/GreyNoise-Intelligence/pygreynoise) - Greynoise Python Library
* [sn0int](https://github.com/kpcyrd/sn0int) - Semi-automatic OSINT framework and package manager.
* [theHarvester](https://github.com/laramies/theHarvester) - E-mail, subdomain and people names harvester.
* [All-in-One](https://all-io.net/)
* [AllTheInternet](https://www.alltheinternet.com/)
* [Etools](https://www.etools.ch/)
* [FaganFinder](https://www.faganfinder.com/)
* [Goofram](http://www.goofram.com)
* [Myallsearch](http://www.myallsearch.com)
* [Qwant](https://www.qwant.com/)
* [Sputtr](http://www.sputtr.com)
* [Trovando](http://www.trovando.it)
* [WebOasis](https://weboas.is/)
* [Zapmeta](https://www.zapmeta.com/)
* [iZito](https://www.izito.com/)
  
### Document & Slides Search
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

### Source Code Search
Search by website source code

* [NerdyData](https://www.nerdydata.com/) - Search engine for source code.
* [SearchCode](https://searchcode.com) - Help find real world examples of functions, API's and libraries across 10+ sources
* [Grep App](https://grep.app/) - Search for source code across a half million git repos

### Crypto OSINT Search
* [Bitcoin Abuse](https://www.bitcoinabuse.com/) - Database of wallets associated with ransomware, blackmailers and fraud.
* [Bitcoin Who's Who](https://bitcoinwhoswho.com/) - Database of known ID information from bitcoin addresses.
* [Blockchair](https://blockchair.com/) - Multiple blockchain explorer.
* [Wallet Explorer](https://www.walletexplorer.com/) - Finds all known associated bitcoin addresses from a single known address.

### Government Record Search
* [Blackbook](https://www.blackbookonline.info/index.html) - Public Records Starting Point.
* [FOIA Search](https://www.foia.gov/search.html) - Government information request portal.
* [PACER](https://pacer.uscourts.gov/) - Public Access to Federal Court Records.
* [RECAP](https://www.courtlistener.com/recap/) - Free version of PACER. Includes browser extensions for Chrome & Firefox.
* [SSN Validator](https://www.ssnvalidator.com/index.aspx) - Confirms valid Social Security Numbers.
  
### National Search Engines
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
  

### Real-Time, Social Media Search

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

#### Twitter Search

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

#### Facebook Search

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

#### Instagram Search

* [Hashtagify](https://hashtagify.me/hashtag/wandavision)
* [Iconosquare](https://pro.iconosquare.com/)
* [Picodash](https://www.picodash.com)
* [SnapMap](https://snapmap.knightlab.com/)
* [Social Rank](https://socialrank.com/)
* [Worldcam](http://worldc.am)

#### Pinterest Search

* [Pingroupie](https://pingroupie.com/)

#### Reddit Search
Tools to help discover more about a reddit user or subreddit

* [Imgur](https://imgur.com/search) - The most popular image hosting website used by redditors.
* [Mostly Harmless](http://kerrick.github.io/Mostly-Harmless/#features) - Mostly Harmless looks up the page you are currently viewing to see if it has been submitted to reddit.
* [Reddit Archive](https://www.redditinvestigator.com/) - Historical archives of reddit posts.
* [Reddit Comment Search](https://redditcommentsearch.com/) - Analyze a reddit users by comment history.
* [Reddit Investigator](http://www.redditinvestigator.com) - Investigate a reddit users history.
* [Reddit Suite](https://chrome.google.com/webstore/detail/reddit-enhancement-suite/kbmfpngjjgdllneeigpgjifpgocmfgmb) - Enhances your reddit experience.
* [Reddit User Analyser](https://atomiks.github.io/reddit-user-analyser/) - reddit user account analyzer.
* [Subreddits](http://subreddits.org) - Discover new subreddits.

#### VKontakte Search
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

#### Blog Search

* [BlogSearchEngine](http://www.blogsearchengine.org)
* [Notey](https://www.notey.com/) - Blog post search engine.
* [Outbrain](https://www.outbrain.com/publishers/)
* [Twingly](https://www.twingly.com/)

#### Username Check

* [Check User Names](https://checkusernames.com/)
* [Knowem](https://knowem.com/) - Search for a username on over 500 popular social networks.
* [Linkedin2Username](https://gitlab.com/initstring/linkedin2username) - Web scraper that uses valid LinkedIn credentials to put together a list of employees for a specified company.
* [Name Checkr](https://www.namecheckr.com/)
* [Name Checkup](https://namecheckup.com)
* [Name Chk](https://www.namechk.com/)
* [User Search](https://usersearch.org/index.php)



#### Personal Investigations

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
* [Federal Bureau of Prisons Inmate Locator (US)](https://www.bop.gov/inmateloc/) - Find an inmate that is in the Federal Bureau of Prisons system.
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

#### Email Search
* [BriteVerify Email Verification](https://www.validity.com/products/briteverify/email-list-verification/)
* [Email Address Validator](https://www.email-validator.net/)
* [Email Format](https://www.email-format.com/)
* [Email Permutator+](http://metricsparrow.com/toolkit/email-permutator)
* [EmailHippo](https://tools.verifyemailaddress.io)
* [EmailSearch.net](http://www.email-search.org/search-emails/)
* [Have I Been Pwned](https://haveibeenpwned.com) - Search across multiple data breaches to see if your email address has been compromised.
* [Hunter](https://hunter.io) - Hunter lets you find email addresses in seconds and connect with the people that matter for your business.
* [MailTester](https://mailtester.com/en/single-email-verification)
* [MyCleanList](https://www.mycleanlist.com/)
* [Peepmail](http://www.samy.pl/peepmail)
* [Pipl](https://pipl.com)
* [ReversePhoneCheck](https://www.reversephonecheck.com/)
* [ThatsThem](https://thatsthem.com/reverse-email-lookup)
* [FindEmails.com](https://www.findemails.com/)
* [Verify Email](https://verify-email.org/)
* [VoilaNorbert](https://www.voilanorbert.com) - Find anyone's contact information for lead research or talent acquisition.
* [h8mail](https://github.com/khast3x/h8mail) - Password Breach Hunting and Email OSINT, locally or using premium services. Supports chasing down related email

#### Phone Number Research

* [National Cellular Directory](https://www.nationalcellulardirectory.com/) - Cell phone lookups. The lookup products including billions of records
* [Reverse Phone Lookup](https://www.reversephonelookup.com/) - Detailed information about phone carrier, region, service provider, and switch information.
* [Spy Dialer](https://spydialer.com/default.aspx) - Get the voicemail of a cell phone & owner name lookup.
* [Twilio](https://www.twilio.com/lookup) - Look up a phone numbers carrier type, location, etc.
* [Phone Validator](https://www.phonevalidator.com/index.aspx) - Pretty accurate phone lookup service, particularly good against Google Voice numbers.


#### Company Research

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

#### Domain and IP Research

* [Accuranker](https://www.accuranker.com)
* [ahrefs](https://ahrefs.com) - A tool for backlink research, organic traffic research, keyword research, content marketing & more.
* [Alexa](http://www.alexa.com)
* [Bing Webmaster Tools](https://www.bing.com/webmasters/about)
* [BuiltWith](https://builtwith.com/)
* [Central Ops](https://centralops.net/co/)
* [Dedicated or Not](http://dedicatedornot.com)
* [DNSDumpster](https://dnsdumpster.com)
* [DNS History](http://dnshistory.org)
* [DNSStuff](https://www.dnsstuff.com/)
* [DNSViz](https://dnsviz.net/)
* [Domain Big Data](https://domainbigdata.com/)
* [Domain Crawler](https://domaincrawler.com/)
* [Domain Dossier](https://centralops.net/co/DomainDossier.aspx)
* [Domain Tools](https://whois.domaintools.com/) - Whois lookup and domain/ip historical data.
* [Easy whois](https://www.easywhois.com)
* [Exonera Tor](https://metrics.torproject.org/exonerator.html) - A database of IP addresses that have been part of the Tor network. It answers the question whether there was a Tor relay running on a given IP address on a given date.
* [Follow.net](https://follow.net/)
* [GraphyStories](https://app.graphystories.com/)
* [HypeStat](https://hypestat.com/)
* [Infosniper](https://www.infosniper.net/)
* [intoDNS](https://intodns.com/)
* [IP Checking](http://www.ipchecking.com)
* [IP Location](https://www.iplocation.net/)
* [IP 2 Geolocation](http://ip2geolocation.com)
* [IP 2 Location](http://www.ip2location.com/demo.aspx)
* [IPFingerprints](https://www.ipfingerprints.com/)
* [IPVoid](https://www.ipvoid.com/) - IP address toolset.
* [IntelliTamper](https://www.softpedia.com/get/Internet/Other-Internet-Related/IntelliTamper.shtml)
* [Kloth](http://www.kloth.net/services/)
* [NetworkTools](https://network-tools.com/)
* [Majestic](https://majestic.com)
* [MaxMind](https://www.maxmind.com/en/home)
* [MXToolbox](https://mxtoolbox.com/) - MX record lookup tool.
* [Netcraft Site Report](https://sitereport.netcraft.com/)
* [OpenLinkProfiler](https://www.openlinkprofiler.org/)
* [Link Explorer](https://moz.com/link-explorer)
* [PageGlimpse](http://www.pageglimpse.com)
* [Pentest-Tools.com](https://pentest-tools.com/information-gathering/google-hacking)
* [PhishStats](https://phishstats.info/)
* [Pulsedive](https://pulsedive.com)
* [Quantcast](https://www.quantcast.com)
* [Quick Sprout](https://www.quicksprout.com)
* [RedirectDetective](https://redirectdetective.com/)
* [Remote DNS Lookup](https://remote.12dt.com)
* [Robtex](https://www.robtex.com)
* [SecurityTrails](https://securitytrails.com/dns-trails) - API to search current and historical DNS records, current and historical WHOIS, technologies used by sites and whois search for phone, email, address, IPs etc.
* [SEMrush](https://www.semrush.com)
* [SEOTools for Excel](https://seotoolsforexcel.com/)
* [Similar Web](https://www.similarweb.com) - Compare any website traffic statistics & analytics.
* [SmallSEOTools](https://smallseotools.com/)
* [StatsCrop](https://www.statscrop.com/)
* [Squatm3gator](https://github.com/david3107/squatm3gator) - Enumerate available domains generated modifying the original domain name through different cybersquatting techniques
* [URLVoid](https://www.urlvoid.com/) - Analyzes a website through multiple blacklist engines and online reputation tools to facilitate the detection of fraudulent and malicious websites.
* [Wappalyzer](https://www.wappalyzer.com/)
* [WebMeUp](https://webmeup.com/)
* [Website Informer](https://website.informer.com/)
* [WhatIsMyIPAddress](https://whatismyipaddress.com/)
* [Who.is](https://who.is/) - Domain whois information.
* [Whois Arin Online](https://whois.arin.net/ui/)
* [WhoIsHostingThis](https://www.whoishostingthis.com/)
* [Whoisology](https://whoisology.com)
* [WhoIsRequest](https://whoisrequest.com/)
* [w3snoop](https://webboar.com.w3snoop.com/)
* [Verisign](https://dnssec-analyzer.verisignlabs.com/)
* [ViewDNS.info](https://viewdns.info/)
* [You Get Signal](https://www.yougetsignal.com/)

#### Keywords Research
* [Google Adwords](https://ads.google.com/home/#!/) - Get monthly keyword volume data and stats.
* [Google Trends](https://trends.google.com/trends/?geo=US) - See how many users are searching for specific keywords.
* [Keyword Discovery](https://www.keyworddiscovery.com/)
* [Keyword Spy](https://www.keywordspy.com/)
* [KeywordTool](https://keywordtool.io/)
* [One Look Reverse Dictionary](https://www.onelook.com/reverse-dictionary.shtml)
* [Soovle](https://soovle.com/)
* [Ubersuggest](https://neilpatel.com/ubersuggest/)
* [Word Tracker](https://www.wordtracker.com/)

#### Web History
  * [Archive.is](https://archive.is/)
  * [BlackWidow](https://softbytelabs.com/wp/blackwidow/)
  * [CashedPages](http://www.cachedpages.com)
  * [CachedView](https://cachedview.com/)
  * [DomainTools](https://account.domaintools.com/log-in/)
  * [Wayback Machine](https://archive.org/web/web.php) - Explore the history of a website.
  * [Wayback Machine Archiver](https://github.com/jsvine/waybackpack)

#### Image Search
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
* [Picsearch](https://www.picsearch.com/)
* [PicTriev](http://www.pictriev.com/)
* [TinEye](https://tineye.com) - Reverse image search engine.
* [Websta](https://websta.me/)
* [Worldcam](http://www.worldc.am)
* [Yahoo Image Search](https://images.search.yahoo.com)
* [Yandex Images](https://www.yandex.com/images)

#### Web Monitoring
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

#### DNS Enumeration
* [Amass](https://github.com/caffix/amass) - The amass tool searches Internet data sources, performs brute force subdomain enumeration, searches web archives, and uses machine learning to generate additional subdomain name guesses. DNS name resolution is performed across many public servers so the authoritative server will see the traffic coming from different locations. Written in Go.

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
  







### IP Scanners
- [Nmap](https://nmap.org/)
- [AngryIP](https://angryip.org/)
- [PRTG](https://www.paessler.com/tools)
- [Spidex](https://github.com/alechilczenko/spidex) — Find Internet-connected devices
### Extensions
- [AutoScanWithBurp](https://bitbucket.org/clr2of8/autoscanwithburp/src/master/) — Extension to perform automated & authenticated scans against URLS
- [OAuthScan](https://github.com/PortSwigger/oauth-scan) - Burp Suite Extension written in Java with the aim to provide some automatic security checks
  
### Vulnerability Scanners

- [Nessus](https://www.tenable.com/products/nessus)
- [OpenVas](https://www.openvas.org/)
- [BurpSuite](https://portswigger.net/burp)
- [Trend Micro Hybrid Cloud Security](https://www.g2.com/products/trend-micro-hybrid-cloud-security/reviews)
- [Orca Security](https://orca.security/)
- [InsightVM](https://www.rapid7.com/products/insightvm/?utm_source=google&utm_medium=cpc&utm_campaign=NA_Brand_BOF_GSN_EN&utm_term=insightvm&_bt=600185603260&_bm=e&_bn=g&gclid=CjwKCAjwvsqZBhAlEiwAqAHElXcGdtMkjJdBeeSLPL-Sox66izRyW1oy0EP3tYBAh7-Rgte3_yzQVRoCZhEQAvD_BwE)
- [Qualys](https://www.qualys.com/)
- [Nginxpwner] - Tool to look for common Nginx misconfigurations and vulnerabilities
- [Nikto](https://cirt.net/Nikto2)
- [BurpSuite](https://portswigger.net/burp)


## Resource Development Tools

### Hardware
- [Flipper Zero](https://flipperzero.one/)

#### Lockpicking Resources
* [/r/lockpicking Subreddit](https://www.reddit.com/r/lockpicking/) - Subreddit dedicated to the sport of lockpicking.
* [Keypicking.com](https://keypicking.com/) - Bustling online forum for the discussion of lockpicking and locksport.
* [LockWiki](http://lockwiki.com/index.php/Main_Page) - Community-driven reference for both beginners and professionals in the security industry.
* [Lockpicking Forensics](http://www.lockpickingforensics.com/) - Website "dedicated to the science and study of forensic locksmithing."
* [Lockpicking101.com](https://www.lockpicking101.com/) - One of the longest-running online communities "dedicated to the fun and ethical hobby of lock picking."
* [The Amazing King's Lockpicking pages](http://theamazingking.com/lockpicking.php) - Hobbyist's website with detailed pages about locks, tools, and picking techniques.

### CLI Usability
- [Bat](https://github.com/sharkdp/bat) — Advanced syntax highlighting
- [fzf](https://github.com/junegunn/fzf) — General purpose command-line fuzzy finder
- [exa](https://github.com/ogham/exa) — Advanced replacement for `ls`
- [macOS Terminal (zsh) — The Beginner’s Guide](https://www.youtube.com/watch?v=ogWoUU2DXBU)



## Initial Access Tools

### Phishing
- [CredSniper](https://github.com/ustayready/CredSniper) — Launch phishing site
- [PyPhisher](https://hakin9.org/pyphisher-easy-to-use-phishing-tool-with-65-website-templates/) — Phishing website templates
- [Fake-SMS](https://www-hackers--arise-com.cdn.ampproject.org/c/s/www.hackers-arise.com/amp/social-engineering-attacks-creating-a-fake-sms-message) — Create SMS messages
- C2
    - [Tyk.io](https://shells.systems/oh-my-api-abusing-tyk-cloud-api-management-service-to-hide-your-malicious-c2-traffic/) — Route C2 traffic
- [EvilNoVNC](https://github.com/JoelGMSec/EvilnoVNC) - Ready to go Phishing Platform
- [Zphishper](https://github.com/htr-tech/zphisher) - Automated phishing tool
- [AdvPhishing] - This Is Advance Phishing Tool! OTP PHISHING


- [CiLocks] - Android LockScreen Bypass
- [Android-PIN-Bruteforce] - Unlock An Android Phone (Or Device) By Bruteforcing The Lockscreen PIN


## Execution Tools

## Persistence Tools
- [SillyRAT] - A Cross Platform Multifunctional (Windows/Linux/Mac) RAT
- [Byp4Xx] - Simple Bash Script To Bypass "403 Forbidden" Messages With Well-Known Methods 
- [Arbitrium-RAT] - A Cross-Platform, Fully Undetectable Remote Access Trojan, To Control Android, Windows And Linux


## Privilege Escalation Tools


## Defense Evasion Tools


### Evade AV/EDR  
- [Inceptor](https://github.com/klezVirus/inceptor) — Automate common AV/EDR bypasses
- [GPU Poisoning](https://gitlab.com/ORCA000/gp) — Hide payload inside GPU memory

### Packet Injection
- [Dsniff](https://monkey.org/~dugsong/dsniff/)
- [Ettercap](https://www.ettercap-project.org/)
- [Scapy](https://scapy.net/) — Packet manipulation program
- [hping](http://hping.org/) — TCP/IP packet assembler/analyzer

### Wrappers
- [dll4shell](https://github.com/cepxeo/dll4shell) - A collection of DLL wrappers around various shellcode injection and obfuscation techniques

## Credential Access Tools

### Password Attacks
- [CredKing](https://github.com/ustayready/CredKing) — Launch Password Spraying using AWS Lamba across multiple regions, rotating IPs w/ each request
- [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) — Perform password spraying against users in a domain
- [LDAP Nom Nom](https://github.com/lkarlslund/ldapnomnom) - Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)
- [Masky](https://github.com/Z4kSec/Masky) - Python library providing an alternative way to remotely dump domain users' credentials thanks to an ADCS
  
### Hash Cracking
- Hash Database — Upload Hashes
  - [crackstation](https://crackstation.net/)
  
## Discovery Tools

## Lateral Movement Tools
- [Forbidden] - Bypass 4Xx HTTP Response Status Codes
- [Neo-reGeorg](https://github.com/L-codes/Neo-reGeorg/blob/master/README-en.md) -- Used for HTTP(S) Tunneling

## Collection Tools 
- [ICMPDoor](https://github.com/krabelize/icmpdoor) - Open-source reverse-shell written in Python3 and scapy
- [iodined](https://github.com/yarrick/iodine) - DNS Tunneling


## C2 Tools 
### Penetration Testing / C2 Frameworks 
- [Metasploit](https://www.metasploit.com/)
- [Cobalt Strike](https://www.cobaltstrike.com/) — Adversary simulations & red team operations
- [Brute Ratel](https://bruteratel.com/) - A customized C2 center for Red Team and Adversary Simulation
- [Sn1per](https://github.com/1N3/Sn1per) — All in one pentesting framework
- [Covenant](https://github.com/cobbr/Covenant) — .NET C2 framework
- [Silver](https://github.com/BishopFox/sliver) — Open source cross-platform red team framework
- [Octopus](https://www.kitploit.com/2022/05/octopus-open-source-pre-operation-c2.html) — Pre-operation C2 server
- [SilentTrinity](https://github.com/byt3bl33d3r/SILENTTRINITY) — Asynchronous, multiplayer, & multiserver C2 framework
- [HazProne](https://securityonline.info/hazprone-cloud-pentesting-framework/) — Cloud Pentesting Framework
- [Lockdoor Framework](https://github.com/SofianeHamlaoui/Lockdoor-Framework) — Framework that automates pentesting tools
- [Emp3R0R](https://github.com/jm33-m0/emp3r0r) - Linux post-exploitation framework 
- [GithubC2](https://github.com/D1rkMtr/githubC2/tree/main) - Using Github as a C2
- [Recon-ng](https://github.com/lanmaster53/recon-ng) — Full reconnaissance framework to conduct open source web-based recon
- [Browser Exploitation Framework (BeEF)](https://beefproject.com/) — Recovering web session information and exploiting client-side scripting
- [Zed Attack Proxy (ZAP)](https://owasp.org/www-project-zap/) — Scanning tools and scripts for web application and mobile app security testing
- [Pacu](https://rhinosecuritylabs.com/aws/pacu-open-source-aws-exploitation-framework/) — Scanning and exploit tools for reconnaissance and exploitation of Amazon Web Service (AWS) accounts
Exfiltration Tools -- Stealing data from victim's infrastructure
- [Notion Term](https://github.com/ariary/notionterm) — Embed reverse shell in Notion pages


## Impact 

## Remediation / Reporting
- [PeTeReport] - An Open-Source Application Vulnerability Reporting Tool


## Miscellaneous
- [Dockerized Android](https://github.com/cybersecsi/dockerized-android) - A Container-Based framework to enable the integration of mobile components in security training platforms
- [Viper] - Intranet pentesting tool with Webui
- [AzureHunter] - A Cloud Forensics Powershell Module To Run Threat Hunting Playbooks On Data From Azure And O365
- [403Bypasser] - Automates The Techniques Used To Circumvent Access Control Restrictions On Target Pages
- [Smuggler] - An HTTP Request Smuggling / Desync Testing Tool

## Malicious
- [fireELF](https://github.com/rek7/fireELF) — Inject fileless exploit payloads into a Linux host
- [RouterSploit](https://github.com/threat9/routersploit) — Vulnerability scanning and exploit modules targeting embedded systems


## Cloud Pentesting

### AWS
- [Pacu](https://github.com/RhinoSecurityLabs/pacu)
- [https://rhinosecuritylabs.com/aws/cloud-container-attack-tool/](https://rhinosecuritylabs.com/aws/cloud-container-attack-tool/)

### GCP
- [GCP IAM Privilege Escalation](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation)

### Azure
- [Azure](https://github.com/Azure/Stormspotter)

### Misc.
- [Multi Cloud](https://github.com/nccgroup/ScoutSuite)
- [Multi Cloud](https://github.com/aquasecurity/cloudsploit)

## Active Directory
- [AzureAD-Attack-Defense](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense) - Various common attack scenarios on Azure AD
- [AD-Attack-Defense](https://lnkd.in/ePgnhbUk)
- [AD Exploitation Cheat Sheet](https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet)
- [Offensive AD 101](https://owasp.org/www-pdf-archive/OWASP_FFM_41_OffensiveActiveDirectory_101_MichaelRitter.pdf) - Offense AD Guide
- [AD Exploitation Cheatsheet](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet#active-directory-exploitation-cheat-sheet) - Common TTPs for pentesting AD
- [IR Team](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse) — AD & Kerberos Abusing
- [AD Kill Chain Attack & Defense](https://github.com/infosecn1nja/AD-Attack-Defense#discovery) - Specific TTPs to compromise AD and guidance to mitigation, detection, and prevention


## Compilation of Tools
- [Hacktricks](https://book.hacktricks.xyz/) - Hacking TTPs
- [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) - A list of useful payloads for bypassing systems
- [Pentest-Tools](https://github.com/S3cur3Th1sSh1t/Pentest-Tools) — Cybersecurity repository
- [EthHack](https://ethhack.com/category/security-tools/) — Repository security tool
- [FSociety Hacking Tools](https://github.com/Manisso/fsociety) — Contains all the tools used in Mr. Robot series
- [Red Team Resources](https://github.com/J0hnbX/RedTeam-Resources) - Compilation of Red Teaming resources
- [Kitploit’s Popular Hacking Tools](https://www.kitploit.com/2021/12/top-20-most-popular-hacking-tools-in.html)
- [Red Teaming Toolkit](https://github.com/infosecn1nja/Red-Teaming-Toolkit#Payload%20Development)

### Python
- [Python Tool List](https://hackersonlineclub.com/python-tools/) - Compilation of security Python tools

## Wireless Pentesting
- [Best Wifi Hacking Tools](https://youtu.be/f2BjFilLDqQ)




# Defensive Security Tools
- [DarkTrace](https://www.darktrace.com/en/) - Cyber AI detection
- [Active Countermeasures](https://www.activecountermeasures.com/free-tools/) - Open source tools for countermeasure
- [The CredDefense Toolkit](https://github.com/CredDefense/CredDefense/) - Detect & Prevent Brute Force attacks
- [DNS Blacklist](https://bitbucket.org/ethanr/dns-blacklists/src/master/) - Detect Blacklisted IPs from your traffic
- [Spidertrap](https://bitbucket.org/ethanr/spidertrap/src/master/) - Trap web crawlers and spiders in dynamically generated webpages
- [Live Forensicator](https://github.com/Johnng007/Live-Forensicator) - Powershell script to aid Incidence Response and Live Forensics
- [https://threathunterplaybook.com/intro.html](https://threathunterplaybook.com/intro.html) - Open source project to share detection logic, adversary tradecraft and resources to make detection development more efficient


# Governance Risk & Compliance (GRC) Tools
- [Management Program](https://github.com/magoo/minimalist-risk-management)
- [GRC Resource List](https://github.com/Arudjreis/awesome-security-GRC)
- [Ultimate GRC](https://www.oceg.org/)
- [ISO 27001 Implementation](https://www.udemy.com/course/information-security-for-beginners/?couponCode=LINKEDIN09)
- [Windows Security Encyclopaedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)

## Device Hardening
- Department of Defense Cyber Exchange: Provides STIGs w/ hardening guidelines for a variety of software and hardware solutions
- National Checklist Program (NCP): Provided by the NIST, checklists and benchmarks for OSs and applications
- [SimplyCyber](https://simplycyber.teachable.com/) — GRC

## Auditing Tools
- [lansweeper](https://www.lansweeper.com/) — Scan hosts and compiles an asset information database (Asset inventory management)
- [Domain Password Audit Tool (DPAT)](https://github.com/clr2of8/DPAT) — Generate password statistics from hashes from a DC and a password crack file
- [Ping Castle](https://github.com/vletoux/pingcastle) — Assess the security level of the AD based on risk assessment and a maturity framework
- [Domain Audit](https://github.com/0xJs/domain_audit) — Wrapper around PowerView, Impacket, PowerUpSQL and BloodHound to execute a lot of checks

# Networking
- [Tailscale](https://tailscale.com/)

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
- [Open Source Intelligence Techniques: Resources for Searching & Analyzing Online Information](https://inteltechniques.com/book1.html)

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
- [Global Knowledge](https://www.globalknowledge.com/us-en/)
- [Level Up In Tech](https://www.levelupintech.com/)
- [DFIR Diva](https://training.dfirdiva.com/) — Compilation of Training Resources
- [Perscholas](https://perscholas.org/courses/) — Misc IT Bootcamps
- [100Devs](https://www.youtube.com/playlist?list=PLBf-QcbaigsKwq3k2YEBQS17xUwfOA3O3)
- [NetworkChuck](https://www.youtube.com/c/NetworkChuck)
- [Whizlabs](https://www.whizlabs.com/pricing/?fbclid=IwAR3egmho_JrqqADw7QZ4CLah827tinr-M5ZB51Zc35pO49T9nXqxAo29nRY&fs=e&s=cl)

## Threat Intelligence Platforms

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

#### Cloud Pentesting
- [FlAWS Cloud](http://flaws.cloud/) — AWS Security Training
- [FLAWS 2 Cloud](http://flaws2.cloud/) — AWS Security Training
- AWS Vulnerable
- [DVCA](https://github.com/m6a-UdS/dvca) — Demonstrate priv esc on AWS
- [OWASP Serverless Goat](https://github.com/OWASP/Serverless-Goat) — Demonstrates common serverless security flaws

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

### Offensive Development
- [Offensive Development](https://www.antisyphontraining.com/offensive-development-w-greg-hatcher-john-stigerwalt/)

- [Exploiting Tokens (Write-Up)](https://jsecurity101.medium.com/exploring-token-members-part-1-48bce8004c6a)


### Defense
#### Azure
- [Detect Azure AD Backdoors: Identity Federation](https://www.inversecos.com/2021/11/how-to-detect-azure-active-directory.html)




### Methodologies
- [Open Source Security Testing Methodology Manual (OSSTMM)](https://www.isecom.org/OSSTMM.3.pdf)

## Documentaries
- [https://threadreaderapp.com/thread/1491830217471528962.html](https://threadreaderapp.com/thread/1491830217471528962.html)
- Best Cyber Security and Hacking Documentary #1
- We Are Legion – The Story Of The Hacktivists ([https://lnkd.in/dEihGfAg](https://lnkd.in/dEihGfAg))
- The Internet’s Own Boy: The Story Of Aaron Swartz ([https://lnkd.in/d3hQVxqp](https://lnkd.in/d3hQVxqp))
- [Hackers Wanted](https://www.youtube.com/watch?v=Mn3ooBnShtY)
- [Secret History Of Hacking](https://www.youtube.com/watch?v=PUf1d-GuK0Q)
- [Def Con: The Full Documentary](https://www.youtube.com/watch?v=3ctQOmjQyYg)
- [Web Warriors (Documentary Over Cyber Warfare)](https://www.youtube.com/watch?v=0IY7DL0ihYI)
- [Risk (2016)](https://www.imdb.com/title/tt4964772/)
- [Zero Days (2016)](https://www.imdb.com/title/tt5446858/)
- [Guardians Of The New World (Hacking Documentary) | Real Stories](https://www.youtube.com/watch?v=jUFEeuWqFPE)
- [A Origem dos Hackers](https://www.youtube.com/watch?v=LPqXNGcwlxo&t=2s)
- [The Great Hack](https://lnkd.in/dp-MsrQJ)
- [The Networks Dilemma](https://lnkd.in/dB6rC2RD)
- [21st Century Hackers](https://www.youtube.com/watch?v=nsKIADw7TEM)
- [Cyber War - Dot of Documentary](https://www.youtube.com/watch?v=UaZw9mQu7xg)
- [CyberWar Threat - Inside Worlds Deadliest Cyberattack](https://lnkd.in/drmzKJDu)
- [The Future of Cyberwarfare: The Journey of Humankind](https://www.youtube.com/watch?v=L78r7YD-kNw)
- [Dark Web Fighting Cybercrime Full Hacking](https://lnkd.in/dByEzTE9)
- [Cyber Defense: Military Training for Cyber Warfare](https://lnkd.in/dhA8c52h)
- [Hacker Hunter: WannaCry The History Marcus Hutchin](https://lnkd.in/dnPcnvSv)
- [The Life Hacker Documentary](https://lnkd.in/djAqBhbw)
- [Hacker The Realm and Electron - Hacker Group](https://lnkd.in/dx_uyTuT])

### Social Engineering Articles
* [How I Socially Engineer Myself Into High Security Facilities](https://www.vice.com/en/article/qv34zb/how-i-socially-engineer-myself-into-high-security-facilities) - Sophie Daniel
* [Social Engineering: Compromising Users with an Office Document](https://resources.infosecinstitute.com/certification/social-engineering-compromising-users-using-office-document/) - Infosec Institute
* [The 7 Best Social Engineering Attacks Ever](https://www.darkreading.com/the-7-best-social-engineering-attacks-ever/d/d-id/1319411) - DarkReading
* [The Limits of Social Engineering](https://www.technologyreview.com/2014/04/16/173156/the-limits-of-social-engineering/) - MIT, Technology Review
* [The Persuasion Reading List](https://www.scottadamssays.com/2018/01/24/persuasion-reading-list-updated-1-18/) - Scott Adams' Blog


## Resource Compilation

- [Cybersecurity Documents, Certification Help, Books, etc.](https://drive.google.com/drive/u/0/folders/1xCCknZbUGhJQd8UKAwL_m9upJgmaQVBr?fbclid=IwAR2I99iLaHwgeyzEZeigh32gtrAIS1gUSC6Xo6ASaamJi3XRwip1zAtpH9k)
- [S0cm0nkey’s Security Reference Guide](https://s0cm0nkey.gitbook.io/s0cm0nkeys-security-reference-guide/)
- [Red Teaming Experiments](https://www.ired.team/) — Cheatsheets
- [Darkstar](https://darkstar7471.com/resources.html) — Infosec Training Resources
### Offense Security
- [OSCE3](https://github.com/CyberSecurityUP/OSCE-Complete-Guide)
        

### Bug Hunting
- [Bug Hunter Handbook](https://gowthams.gitbook.io/bughunter-handbook/)

### Powershell Automation
- [PowerShell Intune Samples](https://github.com/microsoftgraph/powershell-intune-samples) — Make HTTPS RESTful API requests
- [Mega Collection of PowerShell Scripts](https://github.com/fleschutz/PowerShell)

### Privacy

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

## Cybersecurity Maps, Domains, etc
(https://s3-us-west-2.amazonaws.com/secure.notion-static.com/087527b0-f437-4255-8b00-0bc69c7dcd73/Untitled.png)
- [Paul Jerimy — Cyber Certification Roadmap](https://pauljerimy.com/security-certification-roadmap/)

## Security News — Stay Updated On Relevant Attacks & Other Infosec News**

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
### Specific Articles
- [BendyBear](https://x-phy.com/advanced-shell-code-a-use-case-of-blacktech-associated-bendybear/)

### CVEs
#### Apple
- [https://www.websecgeeks.com/2022/06/how-i-was-able-to-send-emails-on-behalf-of-any-apple-user-email.html](https://www.websecgeeks.com/2022/06/how-i-was-able-to-send-emails-on-behalf-of-any-apple-user-email.html)

## Freelancing Sites
- [Fiverr](https://www.fiverr.com/)
- [UpWork](https://www.upwork.com/)

## Support Organizations

### Black Tech Organizations
- [10 Professional Organizations for Black IT Professionals](https://www.cio.com/article/191321/10-professional-organizations-for-black-it-pros.html)
- [Organizations We Love (OWL)](https://sites.temple.edu/care/dei/owl/)

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
- [Alpha Cyber Security](https://www.teepublic.com/user/djax120)

## Blogging



