:orphan:
(dont-overlook-dns-in-your-threat-hunting-arsenal)=
# Don't Overlook DNS in your Threat Hunting Arsenal

DNS is a service that may provide valuable information on whether an organization has been compromised.  In order for it to be used to aid in threat hunting, it must be configured to log the queries and the IP of the host performing the query.  Once the logging is enabled, some questions can be asked which can be answered by using a SIEM or scripting.

## Non-existing Domains

If there are numerous queries for non-existent domains being queried by a host within a network, it may be an indicator that the host is infected.  That may be due to malware authors that use a Dynamic Generator Algorithm (DGA).  DGAs will generate a random set of domains that are used by the threat actor and then assign an IP address to it.  That is done via A records which convert hostnames to IP addresses.  The malware will query the DNS server for these domains in an attempt to reach a command and control server.  However, since the domain that is generated may be out of sync with the one used by a threat actor at any given time, it creates a lot of noise by logging non-existent domain errors.

Another reason for non-existent domains queries is because the servers hosted by the threat actors were seized or moved to a different server and the malware is no longer able to query the rogue DNS server.

**Detection:** Analyze DNS logs for  queries that return a non-existent domain (NXDOMAIN) response for a large number of unique queries over a short period of time.  These could be potential indicators of malware Beaconing.

## Fast-Flux DNS

Fast-flux is where a threat actor creates an A record and sets a low TTL and will generally rotate out compromised IP addresses when the TTL expires. This can throw off analysts when they resolve the host to an IP address and analyze their Netflow or system logs. However, by the time the attack has occurred, the IP returned by the rogue DNS server would not be in their event logs.

When resolving hostnames or performing reverse lookups of suspect IPs, perform the query from a host outside of the targeted  organization.  Since the attackers may control the DNS server, they can also enable logging and see that a query occurred that is not expected and may tip them off that their activity has been detected.  They may change some of their IPs, domain names, or login to the infected systems and perform whatever their goals may be.

**Detection:** When performing lookups on domains and IP addresses, pay attention to the TTL values.  If a low TTL is observed this may indicate that the IP address returned may not be in any event logs and makes the investigation more difficult.  That is why it is important to log the client that performed the DNS query so the infected host can quickly be found.

## Data exfiltration

DNS can also be used for data exfiltration since it uses UDP port 53 by default.  Since DNS port 53/UDP is generally allowed outbound, data can be sent out in smaller chunks and reassembled on the remote server that is ingesting the UDP traffic.  Another name for this method is DNS tunneling

**Detection:** Analyze network flows that show which clients are sending UDP or TCP data on port 53 to a host that is bypassing the default DNS server used within the organization.  One mitigation is to drop, log, AND alert on any outbound UDP traffic that is attempting to connect to port 53 on any hosts besides the organization's local or external DNS forwarders.

## High-Entropy domain names

Some threat actors use high entropy domain names random letters and non-sensical. There are sometimes numbers in the domain, as well.  It is common to see fast-flux used with these types of domains as well.  High entropy domain names stand out in DNS logs.  Additionally, the second-level name for the domain may be quite long such as: swersddquqwreqweqer.com.  

**Detection:** Sort domain names by the length and examine the ones with long domain names. Also, sorting in alphabetical order can help high-entropy domain names stand out from ones with low-entropy like google.com.

## Multiple subdomains

Domain names with multiple subdomains should be considered suspect because it is not a standard method of naming for a domain name.  A domain such as:  x.yyz.aaj.aay.com should be considered suspect.  Also, the domain name may end with a top-level domain that is not standard.  Some malware authors will use the name of well-known organizations within the multiple subdomains to trick someone. For example, mosse-institute.learn.somedomain.com is not a real domain used by the Mossé Institute.  However, an unsuspecting analyst may see only "mosse-institute" and believe it is legit.  *Note:* read the entire line of all DNS logs and do not skip over a domain that looks legit based on the first part of the domain name or the second-level domain.

**Detection:** Perform a search that finds multiple dots in the domain name. Aggregate the number of TLDs queried by hosts within the organization's network and investigate the TLDs with the fewest queries by determining which client's queried the domain.  Examine each TLD and investigate others that are not familiar and determine the frequency in which it is used by hosts within the organization.

## Known bad domains

Sites such as [malwaredomainlist.com](https://www.malwaredomainlist.com) maintain an updated list of known bad domains or domains used in cyberattacks. A detection service of known bad domains could be built into an EDR or proxy server and bad domains are blocked and an alert generated that requires investigating. DNS has several record types and some may not be used often.  The TXT record could contain information, but it can also be used to send commands to malware that queries it on a frequent basis.  The malware may use a rogue DNS server's TXT record to store commands that cause the malware to take a given action.  

**Detection:** Check for DNS queries that occur on a routine interval which is indicative of beaconing.  That will require performing some statistical analysis, but is worth it to detect possible c2 communication.

## Monitoring servers and other devices

Servers, for the most part, should not be able to initiate traffic outbound to the Internet unless performing updates or retrieving data from a known external source.  The same is true for devices like printers, scanners, phones, etc.

**Detection:** Search through the DNS records and analyze the domains being queried by servers and other devices.

## Summary

By understanding how DNS works, it can quickly narrow down which hosts may be compromised when performing a hunt. Using DNS in this way can help an organization identify malicious activity that may have otherwise gone undetected.  DNS can be a powerful tool in a threat hunting arsenal and should not be overlooked.

> **Want to learn practical Threat Hunting tactics and strategies? Enrol in [MTH - Certified Threat Hunter Certification](https://www.mosse-institute.com/certifications/mth-certified-threat-hunter.html).**