:orphan:
(reconnaissance-phase-in-penetration-testing-engagements)=

# The Reconnaissance Phase in Penetration Testing Engagements

Reconnaissance is the gathering of information about a target prior to launching an attack. Most attacks begin by gathering as much information as possible about the target. A wealth of useful information can be gathered using today's vast array of information sources. This information may include specifics about the target's network, systems, and users that can be used to plan an attack and assess risk. The internet is an excellent resource for locating any kind of information that can assist an attacker in planning an attack.

Several type of reconnaissance techniques have been adopted as discussed below.

## 1. Whois Lookup:

The whois databases are a set of tools that can be used for reconnaissance, and are one of the best sets of tools available. They can be used to get detailed information about a domain, and can help you gather information about a target.

By registering a domain name, you are giving away a lot of detailed information about your organization that can be used by attackers.Y our registration information also includes the IP addresses of your authoritative domain name servers. All of this information can be used to launch an attack against your company in several ways- names of contact people for carrying out social engineering attacks,contact numbers for war dialing(finding unsecure modems to infiltrate an internal network), and IP addresses for scanning open ports or unsecure wireless access points to attack.

The whois database is a great place to start when conducting reconnaissance on a target. This high-level database contains information about the particular registrar used for .aero, .arpa, .biz, .com, .coop, .edu, .info, .int, .museum, .net, and .org. Researchers can use this information to determine which registrar the target used and then go to the whois database of that particular registrar to get detailed registration information.

By using the whois databases, an attacker can also discover the IP address blocks assigned to their target organization. For this the commonly accessed whois databases are as follows:

- ARIN(American Registry for Internet Numbers)
- RIPE NCC (Roseaux IP Europeans Network Coordination Centre)
- APNIC (Asia Pacific Network Information Centre)
- LACNIC (Latin American and Caribbean NIC)
- AFRINIC (Africa’s NIC)
- DoDNIC (Department of Defense NIC)
- uwhois.com (assists with domain name registration lookups for more than 246 countries)

While these tools can be effective for gathering information, their usefulness is limited if the organization does not have its own IP address allocation and instead relies on its ISP for one.

## 2. DNS Interrogation

By using a variety of methods, the attacker can use the Domain Name System to their advantage and discover a large number of IP addresses associated with the target domain. nslookup and dig are two commonly used tools in this regard.

- **nslookup**:

nslookup is a command that is used to test and query the Domain Name System (DNS) for information about hostnames and IP addresses. It can be used to troubleshoot DNS issues, as well as to determine the IP addresses of servers. The nslookup command is supported by both modern Windows and UNIX systems.

A zone transfer is a process that allows an attacker to connect with your DNS server and download all of the records associated with a particular domain. This can provide the attacker with valuable information about your organization, including website addresses, contact information, and other sensitive data.

To perform a zone transfer on Windows, simply enter the following commands:

    C:\> nslookup
       > server [authoritative server I? or name]
       > set type=any
       > is -d [target domain]

The "set type>any" directive indicates that we want any type of DNS record, such as Address (A) records, Mail Exchanger (MX) records, Host Info (HINFO) records, and nameserver (NS) records. These commands should be run against the target organization's primary, secondary, and any other domain name servers.

However, for some UNIX and LINUX machines, this command is deprecated and cannot be used for zone transfers. So the 'dig command comes into context.

- **dig**:

Dig (Domain Information Groper) is a network administration command-line tool used to query Domain Name System (DNS) name servers. It is a powerful alternative tool for querying specific information about a domain or troubleshooting DNS issues.

To carry out a zone transfer using dig on LINUX, following command can be used:

    $ dig @[DNS server IP] [target domain] t AXFR

While there are several zone transfer methods, the most common one uses the AXFR protocol as shown above.

## 3. Corporate Websites

After gathering information from whois databases and DNS servers, interrogating the target's corporate websites is the next step.

These web servers provide much information about target's computing platforms and architecture on their website. Some of the common searches can include the following related to the target:

- Press releases
- White papers
- Design documents
- Sample deliverables
- Open positions on job sites
- Key people
- Contacts

Amongst these, the last three : open positions, key people and contacts are especially useful for gathering valuable data. The acquired information can also be used in war dialing and social engineering attacks. Newspapers, magazines, blogs, social networking sites, newsgroups, and other websites may also contain the information needed to launch a more targeted attack on the organization. Sites like <u>'namechk'</u> can further be used to find out which social networking sites a target user account is using, in order to create more believable pretexts for social engineering attacks.

<u>Recon-ng Pushpin</u> is also great tool that can help attackers find physical locations tied to cyber profiles. By pulling Flicker, Twitter, and Picasa posts from a specific location and radius, Pushpin can help attackers find vulnerable spots in security. Additionally, attackers can use geotagged pictures taken at work to find sensitive information.

It is recommended to keep an eye out for users who frequently post social-media posts and pictures from work. They may be easier to target, as they regularly interact with many people online.

## 4. Search Engines

Search engines are often the first choice for detailed recon activities during a computer attack. Since, every search engine produces different results, by using results from multiple search engines, you can uncover different vulnerabilities and issues on your target domain. Google Hacking Database (GIIDB) is a great resource, with more than 1,000 different useful searches to locate many problems on target domains. Google Maps now has satellite imagery that can be accessed through maps.google.com – which can be useful especially when planning for physical attacks.

Below, we will explore some of the some useful directives for the Reconnaissance phase.

- <u>“site:”</u> - searches only within the given domain
- <u>“link:”</u> - shows all sites linked to a given site
- <u>“intitle:”</u> - shows pages whose title matches the search criteria
- <u>“inurl:”</u> - shows pages whose UPI matches the search criteria
- <u>“related:”</u> - shows similar pages
- <u>“info:”</u> - finds cached, linked or related pages that contain the term
- <u>“cache:"</u> - useful for finding recently removed pages
- <u>"filetype:"</u> - finds specified filetypes such as asp, jsp, php, cgi, xis and ppt (You can also add these filetypes as a suffix with the "site:" directive)

In addition to the directives listed, you can use some advanced search features to refine your search results.

If you want to search for a phrase exactly as it is written, use **double quotes(" ")**, for example "Mossé Security". Google is always case insensitive, so you don’t need to worry about capitalization.

You can use **" - "** to find results that don't include a certain word. This is helpful for narrowing down a search to only relevant content. For example "site:mosse-institute.com - www.mosse-institute.com" will show any associated domain for mosse-institute except for the mosse-institute.com.

Aside from Google, the **Wayback Machine** at www.archive.org has more comprehensive archives that contains cached pages from billions of web pages over the last several years, and can be used to gather information about the target website has evolved over time.

It is also possible to directly look for potentially vulnerable systems in following ways:

- Available remote desktop systems through this command - **ext:rdp rdp**
- Default web material- **Apache, ITS, Coldfusion, and others**
- Web-based FileMaker Pro databases: ** “Select a database to view” **
- Indexable directories: **intitle:index.of “parent directory”**
- User IDs and passwords (look for **“password”** and **“userid”**)
- Shell history (look for common shell names and commands)
- Video cameras (example: search for **inurl:’Viewerframe?Mode=”**)

## Streamlining the process with automated tools:

However, reconnaissance can be time-consuming and challenging, especially when targeting a large organization. To help streamline the reconnaissance process, testers can use automated tools and techniques. These tools can gather information about the target organization, including its IP address ranges, DNS servers, and web servers. Testers can also use these tools to identify potential vulnerabilities, such as open ports and weak passwords. By using automated reconnaissance tools, testers can quickly gather information about the target organization and identify

**1. SearchDiggity** - It consists of different modules like SearchDiggity for pulling data from search engines like Google, Bing, and Shodan in one framework, Malware Diggity to check if site is hosting any malware, Data Loss Prevention Diggity to check for any data leakage environment, Flash Diggity to check for any flash vulnerabilities surrounding sensitive data.

**2. Recon-ng** - Along with search engine modules, it can also query data from third party data services, check for target's compromised accounts and separate working and reporting module.

**3. FOCA** - Some files store metadata such as usernames, versions of vulnerable software, and directory paths that can be extremely helpful for conducting future targeted attacks. FOCA is a great tool for identifying such files and can automate the process of discovering, downloading, and extracting the metadata from these files. It also has some helpful vulnerability discovery modules.

**4. Maltego** - Maltego is a reconnaissance tool that helps researchers and attackers gather detailed information about a target. It uses transforms, a series of lookups into public sources of information, to convert one piece of information to another. Maltego is available on a variety of platforms, including Linux, Windows, and Mac OS X. The commercial edition of Maltego costs around 999 euros per year, while the free Community Edition has some limitations.

**5. Shodan** - Shodan is one of the numerous websites that offer the capability to research or even attack other sites. It is capable of performing DNS lookups, reverse lookups, traceroutes, and a variety of other valuable services.

This article has provided a detailed examination of the reconnaissance phase of penetration testing engagements. The reconnaissance phase has been demonstrated to be a critical step that should not be rushed or overlooked. By spending time gathering detailed information about the target environment, testers can drastically reduce the time and effort required to successfully compromise any systems within that environment.

## Final Words

There are many reconnaissance tools and techniques available, and this article provides a few examples. We encourage you to try out as many of these tools as you can to determine which ones work best for your needs.

:::{seealso}
Looking to expand your knowledge of penetration testing? Check out our online course, [MPT - Certified Penetration Tester](https://www.mosse-institute.com/certifications/mpt-certified-penetration-tester.html) In this course, you'll learn about the different aspects of penetration testing and how to put them into practice.
:::
