:orphan:
(dns-security)=

# DNS (Domain Name System) - Attacks and Defences

The Domain Name System (DNS) is a foundational component of the modern internet, acting as a virtual phonebook that translates human-readable domain names into IP addresses computers can understand. DNS enables users to access websites, send emails, and interact with online services using easily recognizable domain names, such as [www.example.com](http://www.example.com). Securing DNS is critical to implementing a secure network, both in public and private settings.



## DNS Resolution and Hierarchical Structure

DNS resolution is the process by which domain names are translated into IP addresses. When a user enters a domain name into their browser, the system queries a DNS resolver, usually provided by their ISP or another service. The resolver begins a hierarchical search starting from the root domain, then moving through top-level domains (TLDs), second-level domains, and subdomains. This process ultimately leads to the retrieval of the corresponding IP address, allowing the user's device to connect to the desired web server.

For instance, imagine a user entering "[www.example.com](http://www.example.com)" in their browser. The DNS resolver follows the hierarchy, identifying the ".com" TLD, then moving to "example.com," and finally resolving the IP address associated with the "www" subdomain. This IP address enables the browser to establish a connection to the appropriate server hosting the website.

 

## Protecting Against Threats

DNS plays a pivotal role in the functionality of the internet, making it a prime target for cyber attacks. The vulnerabilities within the DNS infrastructure can be exploited to redirect users to malicious websites, intercept communication, and initiate Distributed Denial of Service (DDoS) attacks. As such, implementing DNS security measures is crucial to maintaining the integrity, availability, and confidentiality of online services. First, let’s look at some common attacks: 



### DNS Cache Poisoning

DNS cache poisoning involves injecting fraudulent DNS records into a DNS resolver's cache. When users query the compromised resolver, they are directed to malicious websites instead of legitimate ones. To mitigate cache poisoning attacks, DNS administrators can implement Source Port Randomization, which ensures that DNS responses are sent from different source ports, making it harder for attackers to predict and spoof the responses.

### DNS Amplification Attacks

DNS amplification attacks involve exploiting misconfigured DNS servers to amplify a small query into a much larger response, overwhelming the target with traffic. To counter these attacks, organizations can implement Rate Limiting on DNS servers to restrict the number of queries from a single IP address within a specific time frame, reducing the potential for amplification.

### Man-in-the-Middle (MitM) Attacks

MitM attacks occur when an attacker intercepts communication between the user and the DNS server, allowing them to manipulate DNS responses. DNSSEC (DNS Security Extensions) are powerful mitigation against MitM attacks, as it cryptographically signs DNS records, ensuring the authenticity and integrity of the data. Users can verify the DNSSEC signatures to ensure they are interacting with legitimate servers.

### DNS Tunnelling

DNS tunnelling involves using DNS queries and responses to transmit data covertly. Attackers can use this technique to bypass firewalls and exfiltrate data. Network administrators can monitor DNS traffic for suspicious patterns and implement DNS filtering solutions that detect and block unauthorized tunnelling attempts.

Thankfully we now have some powerful strategies which can be implemented to protect the DNS system, these include:

 

### DNSSEC (DNS Security Extensions)

DNSSEC is a suite of security extensions designed to authenticate the integrity of DNS data. It employs digital signatures to ensure that the DNS responses received by users are authentic and untampered. By validating DNS data from the source to the destination, DNSSEC prevents DNS cache poisoning, where malicious actors manipulate DNS records to redirect users to rogue websites. For instance, a banking website's domain name could be compromised, redirecting users to a fake login page aimed at stealing their credentials. DNSSEC mitigates this risk by verifying the authenticity of DNS responses, reducing the effectiveness of such attacks.

### DDoS Protection

DNS is vulnerable to DDoS attacks, which flood the DNS servers with an overwhelming volume of requests, rendering them unresponsive. To counter this threat, organizations can employ various strategies, such as Anycast DNS, which disperses traffic across multiple geographically distributed DNS servers. Additionally, some DNS service providers offer built-in DDoS protection mechanisms that automatically detect and mitigate excessive traffic, ensuring the continued availability of DNS services.

### DNS Filtering

DNS filtering involves blocking access to certain websites based on predefined criteria. This practice is commonly used to prevent users from accessing malicious or inappropriate content. Organizations can configure DNS filters to block known malicious domains, phishing websites, or sites with explicit content. By doing so, they create an additional layer of defence against cyber threats and enforce acceptable usage policies.

# Final Words

DNS is a fundamental technology that facilitates seamless internet interactions. Its role in translating domain names to IP addresses is critical, making it a prime target for cyber attacks. By understanding the potential threats, such as DNS cache poisoning, DNS amplification attacks, MitM attacks, and DNS tunnelling, organizations can implement effective mitigations such as DNSSEC, DDoS protection and DNS Filtering.

 

 

 
