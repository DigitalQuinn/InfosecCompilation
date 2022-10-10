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
    - [Active DNS](#active-dns)
    - [IP / Network Scanning](#ip--network-scanning)
    - [Network Security Appliances](#network-security-appliances)
    - [Actively Searching Victim-Owned Websites](#Searching-Victim-Owned-Websites)
    - [Actively Searching Closed Sources](#Searching-Closed-Sources)
    - [Purchase Technical Data](#purchase-technical-data)
  - [Active Social Information](#active-social-information)
    - [Active Credentials](#credentials)
    - [Active Email Addresses](#email-addressess)
    - [Active Employee Names](#employee-names)
- [Actively Find Host Information](#actively-find-host-information)
    - [Scanning IP Blocks](#scanning-ip-blocks)
    - [Vulnerability Scanning](#vulnerability-scanning)
    - [Wordlist Scanning](#wordlist-scanning)
    - [Hardware](#hardware)
    - [Software](#software)
      - [Digital Certificates](#digital-certificates)
    - [Firmware](#firmware)
    - [Client Configuration](#client-configuration)






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
Digital certificates are electronic documents that associates the individual identity of a person to the public key associated with it. A certificate can then be associated with a natural person, a private company or a web service as a portal. 

## Tools
- [CRT.sh](https://crt.sh/) - Search for certs that have been logged by CT

<br>
<hr>

# Active Scanning
Adversaries may execute active scans to gather information that can be used during targeting. The adversary probes victim infrastructure via network traffic

## Active Organization Information

### Active DNS
Adversaries may gather information about the victim's DNS that can be used during targeting
* DNS information may include a variety of details, including registered name servers as well as records that outline addressing for a target’s subdomains, mail servers, and other hosts

Adversaries may gather this information in various ways, such as querying or otherwise collecting details via *DNS/Passive DNS*
* DNS information may also be exposed to adversaries via online or other accessible data sets (ex: Search Open Technical Databases)

### IP / Network Scanning
The physical and/or logical layout of both external-facing and internal network environments can be included in network topology information. An adversary may be able to deduce further information about a target from IP addresses, such as organizational size, physical location(s), ISPs, and/or where/how their publicly-facing infrastructure is housed.

### Network Security Appliances
Information about network security appliances may include a variety of details, such as the existence and specifics of deployed firewalls, content filters, and proxies/bastion hosts
* Adversaries may also target information about NIDs or other appliances related to defensive cybersecurity operations

### Actively Searching Victim-Owned Websites


### Actively Searching Closed Sources


### Purchasing Technical Data

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


# Actively Find Host Information
Adversaries may gather information about the victim's hosts that can be used during targeting. Information about hosts may include a variety of details, including administrative data (ex: name, assigned IP, functionality, etc.) as well as specifics regarding its configuration (ex: operating system, language, etc.)


## Scanning IP Blocks 
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

## Vulnerability Scanning
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

## Wordlist Scanning
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

## Hardware 
Adversaries may gather information about the victim's host hardware that can be used during targeting. Information about hardware infrastructure may include a variety of details such as types and versions on specific hosts, as well as the presence of additional components that might be indicative of added defensive protections (ex: card/biometric readers, dedicated encryption hardware, etc.)

<br>

## Software 
Adversaries may gather information about the victim's host software that can be used during targeting. Information about installed software may include a variety of details such as types and versions on specific hosts, as well as the presence of additional components that might be indicative of added defensive protections (ex: antivirus, SIEMs, etc.).

### Digital Certificates
SSL Enumeration

#### ssl-cert
`Nmap –script ssl-cert [ip address]` -- Retrieves a server’s SSL certificate
* The amount of information printed about the certificate depends on the verbosity level
* With no extra verbosity, the script prints the validity period and the common name, organization Name, state Or Province Name, and country Name of the subject

#### ssl-cert-intaddr
`Nmap –script ssl-cert-intaddr` -- Reports any private IPv4 addresses found in the various fields of an SSL service’s certificate
* These will only be reported if the target address itself is not private

#### ssl-date
`Nmap –script ssl-date` -- Retrieves a target host’s time and date from its `TLS ServerHello` response


#### ssl-enum-ciphers
`Nmap –script ssl-enum-ciphers` -- Repeatedly initiates SSLv3/TLS connections, each time trying a new cipher or compressor while recording whether a host accepts or rejects it
* The end result is a list of all the ciphersuites and compressors that a server accepts
* Each ciphersuite is shown with a letter grade (A through F) indicating the strength of the connection
  * The grade is based on the cryptographic strength of the key exchange and of the stream cipher
* SSLv3/TLSv1 requires more effort to determine which ciphers and compression methods a server supports than SSLv2
* A client lists the ciphers and compressors that it is capable of supporting, and the server will respond with a single cipher and compressor chosen, or a rejection notice
* Some servers use the client’s cipher suite


#### ssl-known-key
`Nmap –script ssl-known-key` -- Checks whether the SSL certificate used by a host has a fingerprint that matches an included database of problematic keys

#### sslv2
`Nmap –script sslv2` -- Determines whether the server supports obsolete and less secure SSLv2, and discovers which ciphers it supports


#### tls-alpn
`Nmap –script tls-alpn` -- Enumerates a TLS server’s supported application-layer protocols using the ALPN protocol

#### tls-nextprotoneg
`Nmap –script tls-nextprotoneg` -- Enumerates a TLS server’s supported protocols by using the next protocol negotiation extension
* This works by adding the next protocol negotiation extension in the client Hello packet and parsing the returned server hello’s NPN extension data

## Tools 
- [Digicert](https://www.digicert.com/support/tools/certificate-utility-for-windows) - Install, inspect, renew and delegate digital certificates

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