:orphan:
(dns-arp-poisoning)=

# Network Attacks: DNS and ARP Poisoning

In the realm of computer networks and cybersecurity, DNS (Domain Name System) and ARP (Address Resolution Protocol) poisoning are two tactics that can be employed by malicious actors to compromise the integrity, confidentiality, and availability of network services. This article aims to shed light on these concepts, explaining what DNS and ARP poisoning are, how they work, the potential consequences of these attacks, and measures to mitigate them.

## What is DNS Poisoning?

**DNS Poisoning**, also known as DNS Spoofing or DNS Cache Poisoning, is a form of cyber attack that manipulates the DNS resolution process. DNS is the system responsible for translating human-readable domain names (like www.example.com) into IP addresses (like 192.168.1.1). It plays a fundamental role in how we navigate the internet, ensuring that we can reach websites using their friendly names instead of numerical IP addresses.

### How DNS Resolution Works

Before diving into DNS poisoning, it's important to understand how DNS resolution works:

1. **User Input**: A user enters a domain name (e.g., www.example.com) into a web browser.
2. **Local DNS Cache**: The computer checks its local DNS cache to see if it already knows the corresponding IP address for the domain.
3. **Recursive Query**: If the IP address is not found in the cache, the computer sends a DNS query to a DNS server (often provided by an ISP).
4. **Authoritative DNS Server**: The DNS server forwards the query to an authoritative DNS server responsible for the domain (e.g., example.com).
5. **Response**: The authoritative DNS server replies with the IP address, which is then cached locally for future use.
6. **Website Access**: The user's browser connects to the webserver's IP address, and the website loads.

### DNS Poisoning Explained

DNS poisoning occurs when an attacker injects malicious data into the DNS cache, leading to incorrect mappings between domain names and IP addresses. The goal of DNS poisoning can vary, but it often involves redirecting users to malicious websites or intercepting their traffic for nefarious purposes.

#### Example of DNS Poisoning

Suppose a cybercriminal wants to perform DNS poisoning to steal login credentials from an online banking website. Here's how it might work:

1. The attacker tricks a DNS server into believing that their malicious server's IP address is associated with the legitimate banking website's domain name.
2. When users attempt to access the banking website, their requests are directed to the attacker's server instead.
3. The attacker's server presents a convincing fake login page to users, capturing their usernames and passwords.

This example illustrates how DNS poisoning can be used for phishing attacks, where users unknowingly provide their sensitive information to malicious actors.

### Consequences of DNS Poisoning

DNS poisoning can have severe consequences, including:

- **Phishing Attacks**: Attackers can redirect users to fake login pages to steal sensitive information like login credentials, credit card numbers, or personal data.

- **Malware Distribution**: Malicious software can be distributed by directing users to compromised websites or delivering malicious payloads through poisoned DNS responses.

- **Denial of Service (DoS)**: By corrupting DNS cache entries, attackers can render websites and services unavailable, leading to a DoS condition.

### Mitigating DNS Poisoning

- **DNSSEC (DNS Security Extensions)**: DNSSEC is a set of extensions to DNS that adds an additional layer of security by digitally signing DNS data. This helps ensure the authenticity and integrity of DNS responses, making it difficult for attackers to tamper with DNS data.

- **Use a Trusted DNS Resolver**: Configure your network to use DNS resolvers provided by reputable organizations or use DNS-over-HTTPS (DoH) to encrypt DNS queries. This can help protect against DNS poisoning attempts.

- **Regularly Clear DNS Cache**: Flush your local DNS cache regularly to remove potentially poisoned entries. This can be done using commands like "ipconfig /flushdns" on Windows or "sudo dscacheutil -flushcache" on macOS.

- **Network Segmentation**: Implement network segmentation to isolate critical systems and services from less trusted parts of the network. This can limit the impact of DNS poisoning attacks.

## What is ARP Poisoning?

**ARP Poisoning**, also known as ARP Spoofing or ARP Cache Poisoning, is a technique used to manipulate the Address Resolution Protocol. ARP is responsible for mapping IP addresses to physical MAC (Media Access Control) addresses on a local network. ARP poisoning attacks aim to disrupt this mapping, potentially leading to unauthorized access and data interception.

### How ARP Resolution Works

To understand ARP poisoning, it's essential to grasp the ARP resolution process:

1. **Need for IP-to-MAC Mapping**: When a device on a local network wants to communicate with another device, it needs to know the target device's MAC address to construct Ethernet frames.
2. **ARP Request**: The device sends an ARP request packet broadcast on the local network, asking for the MAC address associated with a specific IP address.
3. **ARP Response**: The device with the corresponding IP address replies with its MAC address.
4. **MAC Address Table**: The requesting device caches the IP-to-MAC mapping in an ARP table to expedite future communication.

### ARP Poisoning Explained

ARP poisoning occurs when a malicious actor manipulates the ARP table of a device on the local network. The attacker typically impersonates another device on the network, making other devices believe they are communicating with a legitimate entity when, in reality, they are interacting with the attacker.

#### Example of ARP Poisoning

Let's consider a scenario where an attacker wants to intercept network traffic between two devices, A and B:

1. The attacker sends forged ARP responses to both devices A and B, claiming to be the legitimate gateway router on the network.
2. Device A updates its ARP table, associating the attacker's MAC address with the gateway's IP address.
3. Device B does the same, believing it's communicating with the legitimate gateway.
4. All traffic between devices A and B now passes through the attacker, allowing them to intercept, modify, or eavesdrop on the data.

ARP poisoning can enable various attacks, such as Man-in-the-Middle (MitM) attacks, where an attacker intercepts communication between two parties, often with malicious intent.

### Consequences of ARP Poisoning

ARP poisoning can have significant consequences on a local network, including:

- **Data Interception**: Attackers can intercept and eavesdrop on network traffic, potentially stealing sensitive information like login credentials or confidential data.

- **Session Hijacking**: By intercepting traffic, attackers can take control of existing sessions, allowing them to impersonate users and carry out unauthorized actions.

- **Denial of Service (DoS)**: ARP poisoning can disrupt network communication, leading to network outages or degraded performance.

### Mitigating ARP Poisoning

- **ARP Spoofing Detection Tools**: Deploy network monitoring tools that can detect ARP spoofing activities. These tools can send alerts when they detect unusual ARP traffic patterns.

- **Static ARP Entries**: On critical devices, consider configuring static ARP entries. This ensures that the ARP cache is not susceptible to manipulation since it contains fixed IP-to-MAC mappings.

- **Network Intrusion Detection/Prevention Systems (NIDS/NIPS)**: Use intrusion detection and prevention systems that can identify and block ARP poisoning attempts in real-time.

- **Implement Port Security**: For Ethernet switches, enable port security features to restrict MAC addresses allowed on each port. This prevents unauthorized devices from connecting to the network.


## Final Words

DNS poisoning can lead to fraudulent websites and data theft, while ARP poisoning can facilitate unauthorized access and data interception on local networks. The importance of DNS and ARP poisoning awareness cannot be overstated. These attacks have the potential to compromise both individual users and entire networks. By implementing robust security measures and staying informed about evolving threats, individuals and organizations can minimize their exposure to these types of cyberattacks, ensuring the reliability and security of their network services.