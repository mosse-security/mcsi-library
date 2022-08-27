:orphan:
(what-are-zero-day-vulnerabilities-and-who-uses-them)=

# What are Zero-Day Vulnerabilities and Who Uses Them?

A zero-day vulnerability is a computer security flaw that is unknown to the general public and vendors until it is actively exploited and caught in the wild. Zero-days or 0-days are highly sought after by threat actors because they are highly effective at obtaining initial access on a target system.

## Who finds and/or uses zero-day vulnerabilities

**1. Penetration Testers and Red Teamers**

While testing business or government apps, penetration testers and Red Teamers occasionally discover zero days. In some situations, they may even use zero-day vulnerabilities to get access to systems and data in order to meet an engagement's objectives.

As a result of years of testing, many penetration testers have accumulated 0days in common business software. Because software vendors can be antagonistic to security researchers, not all researchers are interested in disclosing their 0days. Many bug bounty hunters, vulnerability researchers, and professional penetration testers have been sued, dismissed, or otherwise retaliated against by software vendors for reporting flaws in their products.

It's debatable whether or not zero-day exploits should be used in penetration testing projects. Some people believe it is acceptable, while others do not. The ideal method, in our opinion, is to ask the client if they are interested in 0day testing taking place.

If this topic interests you, then we recommend you read more about how [Randori](https://www.zdnet.com/article/security-company-faces-backlash-for-waiting-12-months-to-disclose-palo-alto-0-day/) kept an 0day for 12 months to carry out advanced red teaming services before disclosing the vulnerability to Palo Alto.

**2. Vulnerability Researchers**

Vulnerability researchers are always on the lookout for new zero days. Some researchers even sell their zero days on the black market, where prices can vary depending on the demand for the particular zero day.

Vulnerability research is one of the most prestigious areas to work in within cyber security. It is also one of the most challenging and rewarding, as researchers are constantly finding new ways to improve security for everyone. The work can be difficult and tedious at times, but the sense of satisfaction that comes from finding and exploiting a zero-day is worth it.

**3. Government Agencies**

Zero-day vulnerabilities are an important component in the development of cyber warfare weapons or for cyber espionage purposes; both of which are of great interest to government intelligence agencies. Defense and intelligence agencies spend heavily in finding vulnerabilities and exploits to stay on the frontlines of security research and compete with adversaries in cyberspace. The zero day exploits allow them to access systems and spy on their targets.

## Commonly targeted software

The following lists categories of software that zero-day guys are commonly interested in:

- Operating systems (i.e, Windows, Linux, OSX, iOS)
- Web browsers (i.e, Chrome, Edge, Firefox, Safari)
- Microsoft Office (i.e, Word, Excel, PowerPoint)
- Web servers (i.e, Apache, IIS, nginx)
- Email servers (i.e, MS Exchange, Dovecot, Postfix, Exim, Sendmail)
- Web applications (i.e, cPanel, Webmin, Wordpress, Joomla, Drupal)

### Buyers

Here's a list of well-known buyers:

- [Exodus Intelligence](https://www.exodusintel.com/)
- [SSD Disclosure](https://ssd-disclosure.com/)
- [Zerodium](https://zerodium.com/program.html)
- [Zero Day Initiative](https://www.zerodayinitiative.com/)

## Examples of zero-day vulnerabilities

**1. Operation Aurora/CVE-2010-0249**

In 2009, Google, Adobe, Yahoo, Symantec, Morgan Stanley, Rackspace, and Dow Chemicals were all targets of Operation Aurora, a sophisticated cyberattack campaign.

The spear-phishing technique was used to launch this cyber-espionage operation. Initially, the targeted users were sent a malicious URL via email or instant message, which set off a chain of events. When users clicked the URL, they were taken to a website that executed more malicious JavaScript code. 

When a user manually loaded/navigated to a malicious web page from a vulnerable Microsoft Windows system, JavaScript code exploited a zero-day vulnerability in Internet Explorer. The exploit was designed to download and run an executable from a now-defunct website once a system had been successfully compromised. This executable configured a remote access tool (RAT) to run at boot time. As a result, remote attackers were able to view, create, and modify data on the compromised system.

[Click here to see a public exploit](https://www.exploit-db.com/exploits/11167)

**2. Stuxnet Malware**

Stuxnet is a computer worm that was designed to attack Iran's nuclear facilities but has now evolved and spread to other industrial and energy-generating sites. The first Stuxnet malware attack was aimed at PLCs, which are used to automate industrial processes.

Stuxnet employed multiple zero-days:

- <u>CVE-2010-2772</u>

A hard-coded password is used by Siemens Simatic WinCC and PCS 7 SCADA systems to allow local users to access a back-end database and gain privileges. Stuxnet, once fully installed, exploits the Siemens SIMATIC WinCC Default Password Security Bypass Vulnerability to gain access to the WinCC SQL server's back-end SQL database. 

- <u>CVE-2010-2729</u>

When printer sharing is enabled, the Print Spooler service in Microsoft Windows XP SP2 and SP3, Windows Server 2003 SP2, Windows Vista SP1 and SP2, Windows Server 2008 Gold, SP2, and R2, and Windows 7 does not properly validate spooler access permissions, allowing remote attackers to create files in a system directory and thus execute arbitrary code by sending a crafted print request over RPC. Stuxnet malware exploited this vulnerability to spread via networks, if a system shared a printer over the network.

- <u>CVE-2010-2568</u>

CVE-2010-2568 is a Windows shortcut processing flaw that allows attackers to load any DLL without the user's awareness. Windows XP, Vista, and Windows 7, as well as Windows Server 2003 and 2008, were all vulnerable.

**5. Bluekeep/CVE-2019-0708**

A BlueKeep Zero-Day exploit was discovered, which could allow attackers to take control of unpatched Windows XP, Windows Server 2003, and Windows Vista systems. The exploit, which takes advantage of a Remote Desktop Protocol (RDP) vulnerability, and allows attackers to execute arbitrary code or install malware on the targeted systems.

[Click here to see a public exploit](https://www.exploit-db.com/exploits/47416)

**8. Danderspritz Malware**

The Shadow Brokers published a report titled "Lost in Translation" on April 14, 2017, which led to the discovery of DanderSpritz. With dozens of plugins, the tool is a modular, covert, and fully functional framework for post-exploitation activities on Windows and Linux hosts.

- <u>Eternal Blue</u>

Eternal Blue, is a cyberattack exploit developed by the U.S. National Security Agency (NSA) according to leaked NSA documents. It was released on April 14, 2017, by a group calling itself the Shadow Brokers. The EternalBlue exploit exploits SMBv1 vulnerabilities found in older versions of Microsoft operating systems. SMBv1 was created in early 1983 as a network communication protocol to allow for shared access to files, printers, and ports. It was essentially a method for Windows machines to communicate with one another as well as other devices for remote services. This exploit made it possible for any attacker to send a malicious packet to a vulnerable server that had not yet been patched to address MS17-010. All the attacker has to do is send a maliciously crafted packet to the target server, and the malware spreads, resulting in a cyberattack. EternalBlue was commonly used to spread the ransomware WannaCry and Petya, but can also be used to launch any type of cyberattack, including cryptojacking and worm-like malware. Microsoft has released the security patch MS17-10 for this exploit.

[Click here to see a public exploit](https://www.exploit-db.com/exploits/41891)

- <u>Eternal Romance/CVE-2017-0145</u>

Eternal Romance is a remote code execution (RCE) exploit for the SMBv1 file sharing protocol. It exploits CVE-2017-0145, which was patched with the MS17-010 security bulletin.

It is worth noting that SMB file sharing is typically used only within local networks, and that SMB ports are typically blocked from the internet at the firewall. However, if an attacker gains access to a vulnerable SMB endpoint, the ability to run arbitrary code in kernel context from a remote location is a serious risk.

[Click here to see a public exploit](https://www.exploit-db.com/exploits/43970)

## Project-Zero - 0days in the Wild

Project Zero (P0) tracks a list of zero-days discovered in the wild. The information is presented in a Google Spreadsheet.

[Click here to open spreadsheet](https://docs.google.com/spreadsheets/d/1lkNJ0uQwbeC1ZTRrxdtuPLCIl7mlUreoKfSIgajnSyY)

If you're interested in vulnerability research then we recommend you also read their [Root Cause Analysis](https://googleprojectzero.github.io/0days-in-the-wild/rca.html).

> **Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)!**