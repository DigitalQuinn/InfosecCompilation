# Reconnaissance

**Reconnaissance:** Consists of techniques that involve adversaries actively or passively gathering information that can be used to support targeting. Such information may include details of the victim organization, infrastructure, or staff/personnel. This information can be leveraged by the adversary to aid in other phases of the adversary lifecycle, such as using gathered information to plan and execute Initial Access, to scope and prioritize post-compromise objectives, or to drive and lead further Reconnaissance efforts.

<br>
<hr>

# Table of Contents
- [Sock Puppets](#sock-puppets)
- [Passive Scanning](#passive-scanning)
  - [Passive Organization Information](#passive-organization-information)
    - [Passive Business Relationships](#passive-business-relationships)
    - [Passive Business Tempo](#passive-identify-business-tempo)
    - [Passively Identify Roles](#passively-identify-roles)
    - [Passive Location Information](#passive-location-information)
    - [Passive Search Engines](#passive-search-engines)
    - [Passive Threat Intelligence](#passive-threat-intelligence)
  - [Passive Social Information](#passive-social-information)
    - [Passively Identity Information](#passively-identity-information)
    - [Passive Credentials](#passive-credentials)
    - [Passive Email Addressess](#passive-email-addressess)
    - [Passive Employee Names](#passive-employee-names)
  - [Passive Website / Host Information](#passive-website--host-information)
    - [Passive Target Validation](#passive-target-validation)
    - [Passively Finding Subdomains](#passively-finding-subdomains)
    - [Passive Fingerprinting](#passive-fingerprinting)
    - [Passive DNS](#passive-dns)
    - [Passive WHOIS](#passive-whois)
    - [Passive Digital Certificates](#passive-digital-certificates)
    - [Passive CDNs](#passive-cdns)
    - [Passively Scan Databases](#passively-scan-databases)
- [Active Scanning](#Active-Scanning)
  - [Active Organization Information](#active-organization-information)
    - [Active DNS](#dns)
    - [Active Network Trust Dependencies](#network-trust-dependencies)
    - [Active Network Topology](#network-topology)
    - [Active IP Addresses](#ip-addresses)
    - [Active Network Security Appliances](#network-security-appliances)
    - [Actively Searching Victim-Owned Websites](#Searching-Victim-Owned-Websites)
    - [Actively Searching Closed Sources](#Searching-Closed-Sources)
    - [Purchase Technical Data](#purchase-technical-data)
  - [Active Social Information](#active-social-information)
    - [Active Credentials](#credentials)
    - [Active Email Addresses](#email-addressess)
    - [Active Employee Names](#employee-names)
  - [Host Information]
    - [Scanning IP Blocks](#scanning-ip-blocks)
    - [Vulnerability Scanning](#vulnerability-scanning)
    - [Wordlist Scanning](#wordlist-scanning)
    - [Active Enumeration Tools](#active-enumeration-tools)
    - [Hardware](#hardware)
    - [Software](#software)
    - [Firmware](#firmware)

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

# Passive Scanning
Passive Scanning is the action of extract information related to the target without interacting with the target -- That means no request has been sent directly to the target. Generally, public resource is used to gather information. This is typically the first step in the pentesting process attackers use to try to get open source information (OSINT).

## Passive Organization Information 
Passively Scanning for Organization Information, you're looking for details about an organization, such as the names of its divisions and departments, the way it runs its business, where it is located, and etc.

<br>

### Passive Business Relationships 
Information on Business Relationships includes a variety of information, such as second or third-party organizations/domains (like managed service providers, contractors, etc.) that have connected (and possibly elevated) network access. This information could also show how the victim's hardware and software resources are made and shipped.

<br>

### Passively Identify Business Tempo 
Information about an organization’s Business Tempo may include a variety of details, including operational hours/days of the week. This information may also reveal times/dates of purchases and shipments of the victim’s hardware and software resources.

<br>

### Passively Identify Roles 
Information about business roles may reveal a variety of targetable details, including identifiable information for key personnel as well as what data/resources they have access to.

<br>

## Tools
- [Open Corporates](https://opencorporates.com/) — Largest open database of companies in the world
- [AI HIT](https://www.aihitdata.com/) - AI/ML system trained to build and update company information from the web

**Threat Intelligence**
- [Wigle](https://wigle.net/) - Database of wireless networks, with statistics
- [Binary Edge](https://www.binaryedge.io) - Scans the internet for threat intelligence
- [ONYPHE](https://www.onyphe.io) - Collects cyber-threat intelligence data
- [Fofa](https://webintmaster.com/blog/webint-tool/fofa/) - Search for various threat intelligence
- [ZoomEye](https://www.zoomeye.org/) - Gather information about targets
- [LeakIX](https://leakix.net/) - Search publicly indexed information
- [URL Scan](https://urlscan.io/) - Free service to scan and analyse websites
- [PublicWWW](https://publicwww.com/) - Source code search engine
- [CRT.sh](https://crt.sh/) - Search for certs that have been logged by CT
- [Pulsedive](https://pulsedive.com/) - Search for threat intelligence
- [Dehashed](https://www.dehashed.com/) - Search for usernames, emails, passwords, addresses, numbers, etc.
- [Have I Been Pwned?](https://haveibeenpwned.com/) - Check whether personal data has been compromised by data breaches
- [Snusbase](https://snusbase.com/) - Indexes information from breached websites and leaked databases
- [LeakBase](https://leakbase.cc/) - Forum of leaked databases
- [LeakCheck](https://leakcheck.net/) - Data breach search engine
- [GhostProject.fr](https://ghostproject.fr/) - Smart search engine
- [SecurityTrails](https://securitytrails.com/) - Attack surface and data intel
- [DorkSearch](https://dorksearch.com/) - Really fast Google dorking
- [PolySwarm](https://polyswarm.io/) - Scan files and URLs for threats
- [DNSDumpster](https://dnsdumpster.com/) - Dns recon & research, find & lookup dns records
- [AlienVault](https://otx.alienvault.com/) - Open source threat intelligence community
- [Vulners](https://vulners.com/) - Search vulnerabilities in a large database
- [WayBackMachine](https://archive.org/web/) - View content from deleted websites
- [Hunter](https://hunter.io/) - Search for email addresses belonging to a website
  
**Internet-Connected Devices / Attack Surfaces**
- [GreyNoise](https://www.greynoise.io/) - Search for devices connected to the internet
- [Censys](https://censys.io/) - Assessing attack surface for internet connected devices
- [Shodan](https://www.shodan.io/) - Search for devices connected to the internet
- [IntelligenceX](https://intelx.io/) - Search Tor, I2P, data leaks, domains, and emails
- [Netlas](https://netlas.io/) - Search and monitor internet connected assets
- [FullHunt](https://fullhunt.io/) - Search and discovery attack surfaces
- [GrayHatWarfare](https://grayhatwarfare.com/) - Search public S3 buckets
  - [GrayHatWarfare Buckets](https://buckets.grayhatwarfare.com/) - Search public S3 buckets
  - [GrayHatWarfare Shorteners](https://shorteners.grayhatwarfare.com/) - Search for exposed URL shorteners
- [LeakWatch](https://leak.watch/) - Scans the Internet to detect exposed information
- FullHunt - Search and discovery attack surfaces
- [https://ipspy.net/](https://ipspy.net/) - IP Lookup, WHOIS, and DNS resolver
- [GeoTag](https://vsudo.net/tools/geotag) — Discover location of pictures
- [Sarenka](https://github.com/pawlaczyk/sarenka) — Gathers data from Shodan, censys, etc.
- [Pushpin](https://github.com/DakotaNelson/pushpin-web) — Provides a web interface to keep track of geotagged social media activity
- [Awesome Hacker Search Engines](https://github.com/edoardottt/awesome-hacker-search-engines) — CVEs, Domains, Addresses, Certifications, Credentials, etc.
- [exitLooter](https://github.com/aydinnyunus/exifLooter) - Find geolocation on image URL and directories
- [FavFreak](https://github.com/devanshbatham/FavFreak) -  Fetches the favicon.ico and hash value and generates shodan dorks

<br>

### Passive Location Information
Information about physical locations of a target may include a variety of details, including where key resources and infrastructure are housed. Physical locations may also indicate what legal jurisdiction and/or authorities the victim operates within.

To assist with this, look for the following:
* Satellite images
* Drone reconnaissance
* Building layout (Badge readers, break areas, security, fencing, etc)

## Tools
**Images**
- EXIF Tool
  - `exiftool [img file]`
**Wireless**
- [WiGLE](https://wigle.net/) - Find wireless networks
- [Open Wifi Map](openwifimap.net)
- [Mozilla Stumbler](https://location.services.mozilla.com/)

**Satellite Images**
- [USGS Earth Explorer](https://earthexplorer.usgs.gov/)
- [Sentinel Open Access Hub](https://scihub.copernicus.eu/dhus/#/home)
- [NASA Earthdata Search](https://search.earthdata.nasa.gov/search)
- [NOAA Data Access Viewer](https://coast.noaa.gov/dataviewer/#/)
- [DigitalGlobe Open Data Program](https://www.maxar.com/open-data)
- [Geo-Airbus Defense](https://www.intelligence-airbusds.com/)
- [NASA Worldview](https://www.intelligence-airbusds.com/)
- [NOAA CLASS](https://www.avl.class.noaa.gov/saa/products/welcome;jsessionid=17337A27F6C7E8333F05035A18C26DA6)
- [National Institute for Space Research (INPE)](https://landsat.usgs.gov/CUB)
- [Bhuvan Indian Geo-Platform of ISRO](https://bhuvan-app3.nrsc.gov.in/data/download/index.php)
- [JAXA’s Global ALOS 3D World](https://www.eorc.jaxa.jp/ALOS/en/dataset/aw3d_e.htm)
- [VITO Vision](https://www.vito-eodata.be/PDF/portal/Application.html#Home)
- [NOAA Digital Coast](https://coast.noaa.gov/digitalcoast/)

### Passive Search Engines 
Search engine services typical crawl online sites to index context and may provide users with specialized syntax to search for specific keywords or specific types of content

**Goal:** Harvest general information about victims and use specialized queries to look for spillages/leaks of sensitive information such as network details or credentials

### Passive Threat Intelligence 
Threat intelligence vendors may offer paid feeds or portals that offer more data than what is publicly reported. Although sensitive details (such as customer names and other identifiers) may be redacted, this information may contain trends regarding breaches such as target industries, attribution claims, and successful TTPs/countermeasures.

**Goal:** Seek information/indicators gathered about personal campaigns, as well as those conducted by other adversaries that may align with their target industries, capabilities/objectives, or other operational concerns

**Threat Intelligence Solutions**
- [Wigle](https://wigle.net/) - Database of wireless networks, with statistics
- [Binary Edge](https://www.binaryedge.io) - Scans the internet for threat intelligence
- [ONYPHE](https://www.onyphe.io) - Collects cyber-threat intelligence data
- [Fofa](https://webintmaster.com/blog/webint-tool/fofa/) - Search for various threat intelligence
- [ZoomEye](https://www.zoomeye.org/) - Gather information about targets
- [LeakIX](https://leakix.net/) - Search publicly indexed information
- [URL Scan](https://urlscan.io/) - Free service to scan and analyse websites
- [PublicWWW](https://publicwww.com/) - Source code search engine
- [CRT.sh](https://crt.sh/) - Search for certs that have been logged by CT
- [Pulsedive](https://pulsedive.com/) - Search for threat intelligence
- [Dehashed](https://www.dehashed.com/) - Search for usernames, emails, passwords, addresses, numbers, etc.
- [Have I Been Pwned?](https://haveibeenpwned.com/) - Check whether personal data has been compromised by data breaches
- [Snusbase](https://snusbase.com/) - Indexes information from breached websites and leaked databases
- [LeakBase](https://leakbase.cc/) - Forum of leaked databases
- [LeakCheck](https://leakcheck.net/) - Data breach search engine
- [GhostProject.fr](https://ghostproject.fr/) - Smart search engine
- [SecurityTrails](https://securitytrails.com/) - Attack surface and data intel
- [DorkSearch](https://dorksearch.com/) - Really fast Google dorking
- [PolySwarm](https://polyswarm.io/) - Scan files and URLs for threats
- [DNSDumpster](https://dnsdumpster.com/) - Dns recon & research, find & lookup dns records
- [AlienVault](https://otx.alienvault.com/) - Open source threat intelligence community
- [Vulners](https://vulners.com/) - Search vulnerabilities in a large database
- [WayBackMachine](https://archive.org/web/) - View content from deleted websites
- [Hunter](https://hunter.io/) - Search for email addresses belonging to a website

<br>
<hr>

## Passive Social Information 

### Passive Identity Information 
Information about identities may include a variety of details, including personal data (ex: employee names, email addresses, badge photos, etc.)


### Passive Credentials 
Passively collect account credentials directly related with the intended victim organization with the inclination to reuse passwords across personal and commercial accounts. Credentials may be leaked online or in other accessible data sets, or purchased on the dark web or other black-markets.

## Tools

**Searching for Hashes**
- [dehashed.com](http://dehashed.com) : Search email, username, IP, Phone, VIN, etc.
- [hashes.org](http://hashes.org) : Search for hashes — Determine if hashes has already been cracked
- [LeakCheck](https://leakcheck.io/)
- [SnusBase](https://snusbase.com/)
- [Scylla.sh](https://scylla.sh/)
- [HaveIBeenPwned](https://haveibeenpwned.com/)
- [NameChk](https://namechk.com/)
- [WhatsMyName](https://whatsmyname.app/)
- [NameCheckup](https://namecheckup.com/)
  
**CLI Methods** 

- [What's My Name?](https://whatsmyname.app/) - Enumerate usernames across various websites
  - `whatsmyname -u digitalquinn`
- [Sherlock](https://github.com/sherlock-project/sherlock)
  - `sherlock digitalquinn`
- [h8mail](https://github.com/khast3x/h8mail) - Email OSINT and breach hunting tool
  - `h8mail -t [shark@tesla.com](mailto:shark@tesla.com) -bc "/opt/breach-parse/BreachCompilation/" -sk`
- [Breach Parse](https://github.com/hmaverickadams/breach-parse) - Tool for parsing breached passwords
  - `./breach-parse.sh @tesla.com tesla.txt`
- [The Harvester](https://github.com/laramies/theHarvester) - Performs OSINT gathering to help determine a domain's external threat landscape by using multiple resources
  - `theHarvester -d [tesla.com](http://tesla.com/) -b google -l 500`
  - `theHarvester -d [tesla.com](http://tesla.com/) -b all -l 500`

<br>

### Passive Email Addressess
Remember to passively gather email addresses because organizations may have public-facing email infrastructure and addresses for employees.

## Tools
- [phonebook.cz](http://phonebook.cz) - Lists all domains, email addresses, or URLs for the given input domain
- [https://www.voilanorbert.com/](https://www.voilanorbert.com/) - Find verified email addresses
- Clearbit Connect (Extension) - Find email addresses; Has to be used in Google Chrome 
- [emailhippo](https://tools.emailhippo.com/) — Ensure email addresses in real time
- [email-checker.net/validate](http://email-checker.net/validate) — Ensure emails are valid
- - [Pulsedive](https://pulsedive.com/) - Search for threat intelligence
- [Dehashed](https://www.dehashed.com/) - Search for usernames, emails, passwords, addresses, numbers, etc.
- [Have I Been Pwned?](https://haveibeenpwned.com/) - Check whether personal data has been compromised by data breaches
- [Hunter](https://hunter.io/) - Search for email addresses belonging to a website
- [IntelligenceX](https://intelx.io/) - Search Tor, I2P, data leaks, domains, and emails
- [Sarenka](https://github.com/pawlaczyk/sarenka) — Gathers data from Shodan, censys, etc.
- [Awesome Hacker Search Engines](https://github.com/edoardottt/awesome-hacker-search-engines) — CVEs, Domains, Addresses, Certifications, Credentials, etc.

<br>

### Passive Employee Names 
Employee names be used to derive email addresses as well as to help guide other reconnaissance efforts and/or craft more-believable lures.

## Tools

**NOTE::**
- Search through images
- Find people; Take names and put them into the email formats

**Top Social Media**
- LinkedIn, Twitter, Facebook, Instagram, Snapchat, Reddit, TikTok, Reddit, Pinterest, Messenger, Ello
- Medium, Quora, SoundCloud, Discord, YouTube, Whatsapp, WeChat, QQ, Qzone, Sina Weibo
- Flickr, Baidu Tieba, Viber, Line, Telegram, Douyin, Douban, Discord, Foursquare, Badoo
- Mix, Next Door, Deviantart, Meetup, VK, Kwai, Clubhouse, Hootsuite, Vimeo, BizSugar
- Digg, Skype, YY, Taringa, Renren, Triller, Tagged, Academia, Myspace, Periscope
- The-Dots, Valence, Kiwibox, Untappd, Skyrock, Alpha, Delicious, Yubo, Snapfish, Peanut, WT Social
- ReverbNation, Houseparty, Flixster, Caffeine, Care2, Steemit, CafeMom, 23snaps, Ravelry, Likee, Tout
- Wayne, 8tracks, Cellufun, Amikumu, Upstream, aNobii, Classmates, ASMALLWORLD, MyHeritage, Athlinks, Vero
- Viadeo, BAND, Xing, beBee, LiveJournal, Blind, Funny or Die, Diaspora, Gaia Online, Fark, We Heart It, Giphy
- MeWe, Twitch, CaringBridge, Wattpad, Crunchyroll, Bubbly, Influenster, FilmAffinity, Tribe, Imgur

**Searching for People**
- [WhitePages](https://www.whitepages.com/)
- [TruePeopleSearch](https://www.truepeoplesearch.com/)
- [FastPeopleSearch](https://www.fastpeoplesearch.com/)
- [FastBackgroundCheck](https://www.fastbackgroundcheck.com/)
- [WebMii](https://webmii.com/)
- [PeekYou](https://peekyou.com/)
- [411](https://www.411.com/)
- [Spokeo](https://www.spokeo.com/)
- [That's Them](https://thatsthem.com/)
- [People Auto-Search](http://consumer-sos.com/Generic-Auto/People-Search/public-records.htm#TheirTrailofPublicRecords) - Find Or Background People By Their: Criminal records, relationships, articles, assets, and much more
- Pipl Search
- Google
  - Google Groups
- TruePeopleSearch
- Find People Search
- PeekYou
- Classmates
- FamilyTreeNow
- TinEye
- Zaba Search
- USA.gov
- Facebook
- LinkedIn
- [SocialCatfish](https://socialcatfish.com/) - Find people by name, number, and address, etc.
- [CTI & OSINT Online Resources](https://docs.google.com/spreadsheets/d/1klugQqw6POlBtuzon8S0b18-gpsDwX-5OYRrB7TyNEw/edit?usp=sharing) - Spreadsheet of online resources


**Voter Records**
- [Voter Records](https://www.voterrecords.com/)

**Hunting Phone Numbers**
- [TrueCaller](https://www.truecaller.com/)
- [CallerID Test](https://calleridtest.com/)
- [Infobel](https://infobel.com/)
- `phoneinfoga scan -n 12408084535`
- `phoneinfoga serve -p 8080` — Spin up web server to see visual output
  - `[http://localhost:8080](http://localhost:8080)` — View output

**Misc. Threat Intelligence**
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

## Passive Website / Host Information
Passively search for information on websites/hosts may including administrative data (ex: name, assigned IP, functionality, etc.) as well as specifics regarding its configuration (ex: operating system, language, etc)

### Passive Target Validation
Target validation is the process of verifying that a scanned asset is actually "up/active", even though a specific tool may say its available or isn't really available. This should be a more hands-on, manual approach, but some of these tools are good at validating this;
 
## Tools
- [WhoisFreaks](https://whoisfreaks.com/) — WHOIS Discovery
- [nslookup](https://www.nslookup.io/)
- [dnsrecon](https://github.com/darkoperator/dnsrecon)

### Passively Finding Subdomains
Subdomains act as an extension of your domain name to help organize and navigate to different sections of your website. Subdomains are used to send visitors to a completely different web address or point to a specific IP address or directory 

## Tools
- Google Fu
- dig
- Nmap
- Sublist3r
- Bluto
- crt.sh
- [HaxUnit](https://github.com/Bandit-HaxUnit/haxunit) — Combines multiple active/passive subdomain enumeration tools and port scanning

### Fingerprinting
Fingerprinting is the technique to gather as much of a system's configuration information as possible. Some information in a fingerprint includes application software technology, network topology, cluster architecture, host OS platform, and database version.

## Tools
- Nmap
- Wappalyzer
- BuiltWith
- Netcat
  - [Built With Technology Lookup](https://builtwith.com) — Determine the website’s framework
  - whatweb: CLI tool
    - Syntax: `whatweb [https://tesla.com](https://tesla.com)`
- Data Breaches
  - HaveIBeenPwned
  - Breach-Parse
  - WeLeakInfo
- [BuiltWith](https://builtwith.com/) — Find what websites are built with
- [Domain Dossier](https://centralops.net/co/) — Investigate domains / IPs
    - Look at MX records to determine where email is being held
- [DNSlytics](https://dnslytics.com/reverse-ip) — Find domains that use a specific IP
- [SpyOnWeb](https://spyonweb.com/)
- [Virus Total](https://www.virustotal.com/) — Put URL into website to find additonal info
    - Take UA and put it into SpyOnWeb — look for analytic code for the website
- [Visual Ping](https://visualping.io/) — Track a website to detect if anything on the site changes
- [BackLink Watch](http://backlinkwatch.com/index.php) — Backlinks ; Find where else the website is posted at
- [View DNS](https://viewdns.info/)
- [Shodan](https://shodan.io) — Search Engine for the Internet of Everything
    - `city:atlanta port:3389`
- [Wayback Machine](https://web.archive.org/) — Archive websites
- [Wappalyzer](https://www.wappalyzer.com/) — Find out what websites are built with
- [Subfinder](https://github.com/projectdiscovery/subfinder) — Subdomain discovery tool that discovers valid subdomains for websites by using passive online source
- [Assetfinder](https://github.com/tomnomnom/assetfinder) — Find domains and subdomains potentially related to a given domain
- [httprobe](https://github.com/tomnomnom/httprobe) — Take a list of domains and probe for working http and https servers
- [Amass](https://github.com/OWASP/Amass) — Performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
- [GoWitness](https://github.com/sensepost/gowitness/wiki/Installation) — Website screenshot utility written

### Passive DNS 
DNS information may include a variety of details, including registered name servers as well as records that outline addressing for a target’s subdomains, mail servers, and other hosts. Threat actors can query nameservers for a target organization directly, or search through centralized repositories of logged DNS query responses (known as passive DNS). Adversaries may also seek and target DNS misconfigurations/leaks that reveal information about internal networks. 

### Passive WHOIS 
WHOIS data is stored by Regional Internet Registries (RIR) responsible for allocating and assigning Internet resources such as domain names

* Query WHOIS servers for information about a registered domain, such as assigned IP blocks, contact information, and DNS nameservers
* Use online resources or CLI utilities to pillage through WHOIS data for information about potential victims


### Passive Digital Certificates
Search for digital certificate data to gather actionable information
* Digital certificate data may also be available from artifacts signed by the organization (ex: certificates used from encrypted web traffic are served with content). 

## Tools

<br>

### CDNs 
CDNs allow an organization to host content from a distributed, load balanced array of servers. CDNs may also allow organizations to customize content delivery based on the requestor’s geographical region.

* Search CDN data to gather actionable information
* Use online resources and lookup tools to harvest information about content servers within a CDN
* Target CDN misconfigurations that leak sensitive information not intended to be hosted and/or do not have the same protection mechanisms (ex: login portals) as the content hosted on the organization’s website

<br>

### Passively Scan Databases 
Various online services continuously publish the results of Internet scans/surveys, often harvesting information such as active IP addresses, hostnames, open ports, certificates, and even server banners

* Use online resources and lookup tools to harvest information from these services
* Seek information about their already identified targets; Use these datasets to discover opportunities for successful breaches

## Tools
**Threat Intelligence**
- [Wigle](https://wigle.net/) - Database of wireless networks, with statistics
- [Binary Edge](https://www.binaryedge.io) - Scans the internet for threat intelligence
- [ONYPHE](https://www.onyphe.io) - Collects cyber-threat intelligence data
- [Fofa](https://webintmaster.com/blog/webint-tool/fofa/) - Search for various threat intelligence
- [ZoomEye](https://www.zoomeye.org/) - Gather information about targets
- [LeakIX](https://leakix.net/) - Search publicly indexed information
- [URL Scan](https://urlscan.io/) - Free service to scan and analyse websites
- [PublicWWW](https://publicwww.com/) - Source code search engine
- [CRT.sh](https://crt.sh/) - Search for certs that have been logged by CT
- [Pulsedive](https://pulsedive.com/) - Search for threat intelligence
- [Dehashed](https://www.dehashed.com/) - Search for usernames, emails, passwords, addresses, numbers, etc.
- [Have I Been Pwned?](https://haveibeenpwned.com/) - Check whether personal data has been compromised by data breaches
- [Snusbase](https://snusbase.com/) - Indexes information from breached websites and leaked databases
- [LeakBase](https://leakbase.cc/) - Forum of leaked databases
- [LeakCheck](https://leakcheck.net/) - Data breach search engine
- [GhostProject.fr](https://ghostproject.fr/) - Smart search engine
- [SecurityTrails](https://securitytrails.com/) - Attack surface and data intel
- [DorkSearch](https://dorksearch.com/) - Really fast Google dorking
- [PolySwarm](https://polyswarm.io/) - Scan files and URLs for threats
- [DNSDumpster](https://dnsdumpster.com/) - Dns recon & research, find & lookup dns records
- [AlienVault](https://otx.alienvault.com/) - Open source threat intelligence community
- [Vulners](https://vulners.com/) - Search vulnerabilities in a large database
- [WayBackMachine](https://archive.org/web/) - View content from deleted websites
- [Hunter](https://hunter.io/) - Search for email addresses belonging to a website
  
**Internet-Connected Devices / Attack Surfaces**
- [GreyNoise](https://www.greynoise.io/) - Search for devices connected to the internet
- [Censys](https://censys.io/) - Assessing attack surface for internet connected devices
- [Shodan](https://www.shodan.io/) - Search for devices connected to the internet
- [IntelligenceX](https://intelx.io/) - Search Tor, I2P, data leaks, domains, and emails
- [Netlas](https://netlas.io/) - Search and monitor internet connected assets
- [FullHunt](https://fullhunt.io/) - Search and discovery attack surfaces
- [GrayHatWarfare](https://grayhatwarfare.com/) - Search public S3 buckets
  - [GrayHatWarfare Buckets](https://buckets.grayhatwarfare.com/) - Search public S3 buckets
  - [GrayHatWarfare Shorteners](https://shorteners.grayhatwarfare.com/) - Search for exposed URL shorteners
- [LeakWatch](https://leak.watch/) - Scans the Internet to detect exposed information
- FullHunt - Search and discovery attack surfaces
- [https://ipspy.net/](https://ipspy.net/) - IP Lookup, WHOIS, and DNS resolver
- [GeoTag](https://vsudo.net/tools/geotag) — Discover location of pictures
- [Sarenka](https://github.com/pawlaczyk/sarenka) — Gathers data from Shodan, censys, etc.
- [Pushpin](https://github.com/DakotaNelson/pushpin-web) — Provides a web interface to keep track of geotagged social media activity
- [Awesome Hacker Search Engines](https://github.com/edoardottt/awesome-hacker-search-engines) — CVEs, Domains, Addresses, Certifications, Credentials, etc.
- [exitLooter](https://github.com/aydinnyunus/exifLooter) - Find geolocation on image URL and directories
- [FavFreak](https://github.com/devanshbatham/FavFreak) -  Fetches the favicon.ico and hash value and generates shodan dorks

**Domain / DNS**
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

### Passive Digital Certificates
Digital certificates are critical component of a PKI. It is an electronic document that associates the individual identity of a person to the public key associated with it. A certificate can then be associated with a natural person, a private company or a web service as a portal. 


The structure of an X.509 digital certificate includes the following information:

version
serial number
ID algorithm
body emitter
validity
subject
information on the public key of the subject
signature algorithm of the certificate
signature of certificate
It is likely you’ll come across the extensions used for files containing X.509 certificates, the most common are:

CER – Certified with DER encoded, sometimes sequences of certificates.
DER – DER encoded certificate.
PEM – Base64-encoded certificate to a file. PEM may contain certificates or private keys.
P12 – PKCS # 12 certificates and may contain public and private keys (password protected).
Another classification of digital certificates is the intended use. It is useful to distinguish authentication certificates and subscription certificates.

A subscription Digital Certificate is used to define the correspondence between an individual applying for the certificate and its public key. These certificates are the ones used for the affixing of digital signatures that are legally valid.

A Certificate of Authentication is mainly used for accessing web sites that implement authentication via certificate, or sign up for e-mail messages in order to ensure the identity of the sender. An authentication certificate is usually associated with an email address in a unique way.


The principal malicious uses related to the digital certificates are:
* Improve malware diffusion
  * Steal a digital certificate associated with a trusted vendor and signing malicious code with it, it reduces the possibility that a malware will be detected as quickly
* Economic frauds

A digital signature gives a warranty on who signed a document and you can decide if you trust the person or company who signed the file and the organization who issued the certificate. If a digital certificate is stolen, victims will suffer an identity theft and related implications.

Malware authors could design a specific malicious agent that could be spread to steal digital certificates. In the case of certificates associated with a web browser, it is possible to trick victims into thinking that a phishing site is legitimate.

Cyber warfare

Cyber espionage conducted by cyber criminals or state sponsored hackers are the activities most frequently carried out with stolen certificates. Digital certificates are used by attackers to conduct “man-in-the-middle” attacks over the secure connections, tricking users into thinking they were on a legitimate site when in fact their SSL/TLS traffic was being secretly tampered with and intercepted.

One of the most blatant case was the DigiNotar one, when different companies like Facebook, Twitter, Skype, Google and also intelligence agencies like CIA, Mossad, and MI6 were targeted in the Dutch government certificate hack.

In 2011, Fox-IT security firm discovered that the extent and duration of the breach were much more severe than had previously been disclosed. The attackers could have used the stolen certificates to spy on users of popular websites for weeks, without their being able to detect it.

“It’s at least as bad as many of us thought … DigiNotar appears to have been totally owned for over a month without taking action, and they waited another month to take necessary steps to notify the public,” said Chester Wisniewski, a senior security advisor at Sophos Canada, in a blog post.

Fox-IT was commissioned by Diginotar to conduct an audit, dubbed “Operation Black Tulip,” and discovered that the servers of the company were compromised.

Another clamorous case was discovered in December 2013 by Google, which notices the use of digital certificates issued by an intermediate certificate authority linked to ANSSI for several Google domains.

ANSSI is the French Cyber Security agency that operates with French intelligence agencies. The organization declares that an intermediate CA is generating fake certificates to conduct MITM attacks and inspect SSL traffic. Be aware that an intermediate CA certificate carries the full authority of the CA, and attackers can use it to create a certificate for any website they wish to hack.

“ANSSI has found that the intermediate CA certificate was used in a commercial device, on a private network, to inspect encrypted traffic with the knowledge of the users on that network.”

Google discovered the ongoing MITM attack and blocked it. Google also declared that ANSSI has requested to block an intermediate CA certificate.



Figure – Digital certificate warning

“As a result of a human error which was made during a process aimed at strengthening the overall IT security of the French Ministry of Finance, digital certificates related to third-party domains which do not belong to the French administration have been signed by a certification authority of the DGTrésor (Treasury) which is attached to the IGC/A.

“The mistake has had no consequences on the overall network security, either for the French administration or the general public. The aforementioned branch of the IGC/A has been revoked preventively. The reinforcement of the whole IGC/A process is currently under supervision to make sure no incident of this kind will ever happen again,” stated the ANSSI advisory.

The ANSSI attributed the incident to “Human Error” made by someone at the Finance Ministry, sustaining that the intermediate CA certificate was used in a commercial device, on a private network, to inspect encrypted traffic with the knowledge of the users on that network.

Misusing digital certificates

Digital certificates have been misused many times during recent years. Bad actors abused them to conduct cyber attacks against private entities, individuals and government organizations. The principal abuses of digital certificates observed by security experts:

Man-in-the-middle (MITM) attacks

Bad actors use digital certificates to eavesdrop on SSL/TLS traffic. Usually these attacks exploit the lack of strict controls by client applications when a server presents them with an SSL/TLS certificate signed by a trusted but unexpected Certification Authority.

SSL certificates are the privileged mechanism for ensuring that secure web sites really are who they say they are. Typically, when we access a secure website, a padlock is displayed in the address bar. Before the icon appears, the site first presents a digital certificate, signed by a trusted “root” authority, that attests to its identity and encryption keys.

Unfortunately web browsers, due to improper design and lack of efficient verification processes, accept the certificates issued by the trusted CA, even if it is an unexpected one.

An attacker that is able to obtain a fake certificate from any certification authority and present it to the client during the connection phase can impersonate every encrypted web site the victim visits.

“Most browsers will happily (and silently) accept new certificates from any valid authority, even for web sites for which certificates had already been obtained. An eavesdropper with fake certificates and access to a target’s internet connection can thus quietly interpose itself as a ‘man-in-the-middle’, observing and recording all encrypted web traffic traffic, with the user none the wiser.”



Figure – MITM handshake

Cyber attacks based on signed malware

Another common cyber attack is based on malware signed with stolen code-signing certificates. The techniques allow attackers to improve avoidance techniques for their malicious codes. Once the private key associated with a trusted entity is compromised, it could be used to sign the malicious code of the malware. This trick allows an attacker to also install those software components (e.g. drivers, software updates) that require signed code for their installation/execution. One of the most popular cases was related to the data breach suffered by security firm Bit9. Attackers stole one of the company’s certs and used it to sign malware and serve it. The certificate was used to sign a malicious Java Applet that exploited a flaw in the browser of targeted browser.

Malware installed illegitimate certificates

Attackers could use also malware to install illegitimate certificates to trust them, avoiding security warnings. Malicious code could for example operate as a local proxy for SSL/TLS traffic, and the installed illegitimate digital certificates could allow attackers to eavesdrop on traffic without triggering any warning. The installation of a fake root CA certificate on the compromised system could allow attackers to arrange a phishing campaign. The bad actor just needs to set up a fake domain that uses SSL/TLS and passes certificate validation steps. Recently, Trend Micro has published a report on a hacking campaign dubbed “Operation Emmental”, which targeted Swiss bank accounts with a multi-faceted attack that is able to bypass two factor authentication implemented by the organization to secure its customers. The attackers, in order to improve the efficiency of their phishing schema, used a malware that installs a new root Secure Sockets Layer (SSL) certificate, which prevents the browser from warning victims when they land on these websites.



Figure – Certificate installed by malware in MS store

CAs issued improper certificates

Improper certificates are issued by the CAs and hackers use them for cyber attacks. In one of the most blatant cases, DigiCert mistakenly sold a certificate to a non-existent company. the digital certificate was then used to sign malware used in cyber attacks.

How to steal a digital certificate

Malware is the privileged instrument for stealing a digital certificate and the private key associated with the victims. Experts at Symantec tracked different strains of malware which have the capability to steal both private keys and digital certificates from Windows certificate stores. This malicious code exploits the operating system’s functionality. Windows OS archives digital certificates in a certificate store.

“Program code often uses the PFXExportCertStoreEx function to export certificate store information and save the information with a .pfx file extension (the actual file format it uses is PKCS#12).The PFXExportCertStoreEx function with the EXPORT_PRIVATE_KEYS option stores both digital certificates and the associated private keys, so the .pfx file is useful to the attacker,” states a blog post from Symantec.

The CertOpenSystemStoreA function could be used to open certificates stored, meanwhile the PFXExportCertStoreEx function exports the content of the following certificate stores:

MY: A certificate store that holds certificates with the associated private keys
CA: Certificate authority certificates
ROOT: Root certificates
SPC: Software Publisher Certificates
Invoking the PFXExportCertStoreEx function with the EXPORT_PRIVATE_KEYS option, it is possible to export both digital certificates and the associated private key.

The code in the following image performs the following actions:

Opens the MY certificate store
Allocates 3C245h bytes of memory
Calculates the actual data size
Frees the allocated memory
Allocates memory for the actual data size
The PFXExportCertStoreEx function writes data to the CRYPT_DATA_BLOB area that pPFX points to
Writes content of the certificate store.


Figure – Malware code to access certificates info

The experts noticed that a similar process is implemented by almost every malware used to steal digital certificates. Malicious code is used to steal certificate store information when the computer starts running.

Once an an attacker has obtained the victim’s private key from a stolen certificate, it could use a tool like the Microsoft signing tool bundled with Windows DDK, Platform SDK, and Visual Studio. Running Sign Tool (signtool.exe), it is possible to digitally sign every code, including malware source code.

Abuse prevention

I desire to close this post introducing a couple of initiatives started to prevent the abuse of digital certificates. The first one is started by a security researcher at Abuse.ch, which has launched the SSL Black List, a project to create an archive of all the digital certificates used for illicit activities. Abuse.ch is a Swiss organization that was involved in the last years in many investigations on the principal major banker Trojan families and botnets.

“The goal of SSLBL is to provide a list of bad SHA1 fingerprints of SSL certificates that are associated with malware and botnet activities. Currently, SSLBL provides an IP based and a SHA1 fingerprint based blacklist in CSV and Suricata rule format. SSLBL helps you in detecting potential botnet C&C traffic that relies on SSL, such as KINS (aka VMZeuS) and Shylock,” wrote the researcher in a blog post which introduces the initiative.

The need to track abuse of certificates has emerged in recent years, after security experts discovered many cases in which bad actors abused digital certificates for illicit activities, ranging from malware distribution to Internet surveillance.

Authors of malware are exploiting new methods to avoid detection by defense systems and security experts. For example, many attackers are using SSL to protect malicious traffic between C&C and infected machines.

Each item in the list associates a certificate to the malicious operations in which attackers used it. The abuses include botnets, malware campaigns, and banking malware.

The archive behind the SSL Black List, which actually includes more than 125 digital certificates, comprises SHA-1 fingerprints of each certificate with a description of the abuse. Many entries are associated with popular botnets and malware-based attacks, including Zeus, Shylock and Kins.



The SSL Black List is another project that could help the security community to prevent cyber attacks. When the database matures, it will represent a precious resource for security experts dealing with malware and botnet operators that are using certificates in their operations.

Abuse.ch isn’t the only entity active in the prevention of illicit activities of certificates. Google is very active in the prevention of any abuse of stolen or unauthorized digital certificates. Earlier this year, the company has its Certificate Transparency Project, a sort of a public register of digital certificates that have been issued.



- [CRT.sh](https://crt.sh/) - Search for certs that have been logged by CT

<br>
<hr>

# Active Scanning
Adversaries may execute active scans to gather information that can be used during targeting. The adversary probes victim infrastructure via network traffic

## Active Organization Information

### Scanning IP Blocks 
Adversaries may scan IP blocks in order to gather victim network information. Scans may range from simple pings to more nuanced scans that may reveal host software/versions via server banners or other network artifacts.

## Tools
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

<br>

## Vulnerability Scanning ##
Vulnerability scans checks if the configuration of a target host potentially aligns with the target of a specific exploit. Vulnerability scans typically harvest running software and version numbers via server banners, listening ports, or other network artifacts.

## Tools
- [Nrich](https://gitlab.com/shodan-public/nrich) - Quickly analyze IPs and determines open ports / vulnerabilities
- Nessus
- OpenVas
- BurpSuite
- [Trend Micro Hybrid Cloud Security](https://www.g2.com/products/trend-micro-hybrid-cloud-security/reviews)
- Orca Security
- InsightVM
- Qualys

<br>

## Wordlist Scanning ##
Adversaries may iteratively probe infrastructure using brute-forcing and crawling techniques. While this technique employs similar methods to Brute Force, its goal is the identification of content and infrastructure rather than the discovery of valid credentials. Wordlists used in these scans may contain generic, commonly used names and file extensions or terms specific to a particular software. Adversaries may also create custom, target-specific wordlists using data gathered from other reconnaissance techniques.

## Tools
**Application Vulnerability Scanning**
- [Nikto](https://github.com/sullo/nikto)

**Crawling Tools**
- [GooFuzz](https://github.com/m3n0sd0n4ld/GooFuzz) — Perform fuzzing with an OSINT approach, managing to enumerate directories, files, subdomains or parameters without leaving evidence on the target's server and by means of advanced Google searches
- [Backlink Discovery](https://app.neilpatel.com/en/seo_analyzer/backlinks) — Find backlinks, Referring domains, Link history, etc.
- [HaxUnit](https://github.com/Bandit-HaxUnit/haxunit) — Combines multiple active/passive subdomain enumeration tools and port scanning
- [js-parse](https://github.com/l4yton/js-parse) — Looks through javascript files in a given directory and finds subdomains, URLs, parameters, custom headers, and API keys
- [Astra](https://github.com/Sachin-v3rma/Astra) — Finds API keys, URLs, AWS Buckets, etc.
- [Breach Parse](https://github.com/hmaverickadams/breach-parse) - Tool for parsing breached passwords
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

## Tools
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

## Tools
**Network / Port Scanners**
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

**Domain / DNS Scanners**
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

# Searching Open Technical Databases #
Adversaries may search freely available technical databases for information about victims that can be used during targeting. Information about victims may be available in online databases and repositories, such as registrations of domains/certificates as well as public collections of network data/artifacts gathered from traffic and/or scans. Adversaries may search in different open databases depending on what information they seek to gather. 

<br>
<hr>

# Searching Open Websites / Domains 
Information about victims may be available in various online sites, such as social media, new sites, or those hosting information about business operations such as hiring or requested/rewarded contracts. Adversaries may search in different online sites depending on what information they seek to gather.

<br>

## Social Media ##
Social media sites may contain various information about a victim organization, such as business announcements as well as information about the roles, locations, and interests of staff.

Adversaries may search in different social media sites depending on what information they seek to gather. Threat actors may passively harvest data from these sites, as well as use information gathered to create fake profiles/groups to elicit victim’s into revealing specific information

<br>

## Tools
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

## Tools
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

## Purchase Technical Data ##
Adversaries may purchase technical information about victims that can be used during targeting. Information about victims may be available for purchase within reputable private sources and databases, such as paid subscriptions to feeds of scan databases or other data aggregation services. Adversaries may also purchase information from less-reputable sources such as dark web or cybercrime blackmarkets.

Adversaries may purchase information about their already identified targets, or use purchased data to discover opportunities for successful breaches. Threat actors may gather various technical details from purchased data, including but not limited to employee contact information, credentials, or specifics regarding a victim’s infrastructure