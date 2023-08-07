:orphan:
(network-security-appliances)=

# Network Security Appliances

Network appliances are a critical aspect of network security – without network devices, it’s hard to have a network! In this article, we’ll be concentrating on network devices which are primarily responsible for security functions.

## Jump Servers

Jump servers, also known as bastion hosts, are specialized computers used as intermediary access points for administrators to connect to other systems securely within a network. The primary purpose of a jump server is to enhance security by minimizing the attack surface and reducing direct access to critical systems. 

For someone outside the protected network or network segment to access protected resources they first connect to the jump host, and their activities to the internal services are performed via that connection. Jump servers are often used between sensitive network segments, such as a development subnet or a DMZ (screened subnet). Jump servers (usually termed bastion hosts in this context) are also quite common in cloud deployments. 

### Best Practices for Jump Servers

- Jump servers should be isolated from the regular network and accessible only through a secure VPN or other encrypted channels.
  
- Access to jump servers should be restricted to authorized administrators, or those who have a specific need to access resources in the protected network.
  
- Wherever possible, enforce strong authentication methods such as multi-factor authentication (MFA) to ensure only authorized personnel can connect.
  
- Implement detailed logging and monitoring on the jump server to track access and detect suspicious activities.

## Proxy Servers

Proxy servers act as intermediaries between client devices and the internet. They can enhance security by providing an additional layer of anonymity and filtering requests before they reach the destination server. The proxy itself is not usually viewed as a security feature, rather the actions it takes (for example, filtering possibly malicious content or blocking known-dangerous websites) are the active security component. 

Proxies can be configured either at the Layer 2 (Data Link) or Layer 3 (Network) layers of the OSI model. If a Layer 2 proxy is used, it’s usually required for systems or applications to be configured to route traffic through the proxy.

### Types of Proxy Servers

- **Forward Proxy:** Used by clients to access resources on the internet indirectly, allowing the proxy server to cache content and provide anonymity for users. Caching content also has the benefit of speeding up access to resources which are accessed by more than one system within a network.
  
- **Reverse Proxy:** Sits between internet clients and web servers, forwarding requests to the appropriate backend servers. It can also offload SSL decryption and load balancing, enhancing security and performance.

### Benefits of Proxy Servers

**- Anonymity:** Proxy servers hide client IP addresses from the destination servers, offering a degree of anonymity.
  
**- Content Filtering:** Proxy servers can filter web traffic, blocking malicious websites and inappropriate content.
  
**- Bandwidth Optimization:** By caching content, proxy servers can reduce bandwidth usage and speed up page loading times.
  
**- Policy enforcement:** Proxy servers can help to enforce company policies such as acceptable use.

In an attack scenario, the presence of a proxy can also be an advantage. Proxies for web traffic are often used in organisations for the reasons discussed above – meaning that all traffic destined for ports 80 (HTTP) or 443 (HTTPS) (and possibly other common web ports, such as 8080, 8000 etc.) *should* be directed to the proxy server. If an attacker attempts to perform a reverse connection over a web port (a common tactic) but fails to take account of the proxy server, the traffic will probably be dropped. At the very least, the traffic should look unusual and alert network defenders.  

## Network-based Intrusion Detection System (NIDS) and Network-based Intrusion Prevention System (NIPS)

NIDS and NIPS are security appliances designed to monitor network traffic and detect/prevent suspicious or malicious activities. NIDS detects potential threats and generates alerts, while NIPS goes a step further by taking active measures to block or mitigate threats.

To avoid getting confused here, focus on the keywords “Detection” and “Prevention”. A NIDS system *detects* suspicious or malicious activities but does not actively stop them – this is left to the network defence team. NIPS *protects* the network by identifying suspicious or malicious activities *and* taking actions, such as dropping the traffic.

You might be asking why NIDS would be chosen over NIPS, surely prevention is better? One key aspect of NIDS/NIPS deployment is network structure. For NIPS to be effective, it must sit in the forwarding path of the traffic – that is to say, to protect the organisation against any malicious traffic arriving from the internet, *all* internet traffic must pass through the NIPS. This can be a problem from a performance point of view, and (unless a redundant configuration is used) the NIPS can become a single point of failure. 

By contrast, a NIDS is typically not included in the forwarding path – NIDS are often located off of a router or switch, receiving a copy of the traffic passing through. This means traffic flow is not slowed down, nor can the NIDS become a single point of failure – however, this also means that possible malicious traffic cannot actually be stopped by the device. 

In reality, many organisations use a combination of both approaches in different areas of the network, based on their risk profile.

### Types of NIDS/NIPS

There are several main types of NIDS/NIPS systems which you should be familiar with, these are:

- **Signature-based:** Uses predefined patterns or signatures to identify known threats. Signatures must be regularly updated - services to provide these updates are often offered by vendors.
  
- **Heuristic/Behaviour-based:** Analyzes traffic behaviour and identifies anomalies that may indicate potential threats. Does not rely on signatures, so has a chance of catching a zero-day threat, but can also result in false positives.
  
- **Anomaly-based:** Establishes a baseline of normal behaviour and flags any deviations as potential threats. This approach can also detect threats without having to have a signature for them, but there is a “burn in” or “learning” period during which the device must establish what “normal” looks like for your environment. This approach also tends to lead to high levels of false positives during periods of unusual but harmless traffic (perhaps during the setup of a new system).

### Benefits of NIDS/NIPS

At a high level, remember that the key benefits of NIDS/NIPS are:

- NIDS/NIPS continuously monitors network traffic for potential threats, allowing for quick detection and response.

- NIPS can actively block malicious traffic, preventing attacks from reaching their targets.

- NIDS/NIPS provides valuable insights into network traffic patterns and potential security weaknesses.

## Hardware Security Modules (HSM)

HSMs are specialized hardware devices designed to manage cryptographic keys securely. They primarily provide a secure environment for key storage, protecting sensitive data from unauthorized access, however, most HSMs can also assist in cryptographic operations such as encryption, hashing, or the application of digital signatures. HSMs are typically peripheral devices, connected via USB or a network connection. Don’t confuse an HSM with a TPM (Trusted platform module) which has a similar function but is an integral system component, rather than a removable one.

### Use Cases for HSMs

- HSMs can generate, store, and manage cryptographic keys used for encryption and decryption.

- HSMs can sign digital certificates and documents to ensure their authenticity and integrity.

- HSMs are used in payment processing and secure communication protocols like SSL/TLS to protect sensitive data.

### Benefits of HSMs

- HSMs keep cryptographic keys secure from external threats and unauthorized access.

- HSMs help organizations meet regulatory requirements for key management and data protection.

- HSMs are optimized for cryptographic operations, providing faster processing times compared to software-based solutions.

## Firewalls

Firewalls are essential network security appliances that control incoming and outgoing network traffic based on predetermined security rules. They act as barriers between trusted internal networks and untrusted external networks, filtering traffic and protecting against unauthorized access. It’s worth mentioning that firewalls can be both hardware and software in nature – most operating systems today include their own software-based firewall, but in the context of network devices we mean a *hardware* firewall, a dedicated security device which sits in the traffic forwarding path. 

Whether a firewall is hardware or software-based, the fundamental function is the same – the firewall administrator designs security policies, which are rules that define what traffic is permissible and what traffic is to be blocked or denied. These security policies often take the form of Access Control Lists, which themselves are comprised of Acess Control Entries. An ACE is essentially a line in the access control list, for example, “allow port 80” or “block port 1337”.  

The content of the rules will depend upon the traffic that should or should not need to pass through the firewall. For example, a firewall sitting in front of a web server connected to the Internet may be configured to allow traffic only on port 80 for HTTP, 443 for HTTPS and have all other ports blocked. If the protected subnet also contains an e-mail server, the firewall would also need to allow those ports. 

Today, firewalls are also often deployed as virtual devices in a cloud environment – there are often some limitations vs. a physical device (and as with any cloud instance, its power will depend upon the resources paid for) but modern virtual firewalls can perform most of the core functions a hardware firewall can perform. Many vendor's hardware firewalls can now also interoperate with virtual devices in the cloud to give an organisation even better control and visibility. 

### Types of Firewalls

There are several major types of firewalls you should be aware of, these are: 

- **Stateful Firewalls:** Keep track of the state of active connections and only allow incoming traffic that is part of an established connection.
  
- **Stateless Firewalls:** Examine each packet in isolation without considering its relationship with other packets, making decisions based on preset rules.
  
- **Next-Generation Firewalls (NGFW):** Incorporate advanced features like deep packet inspection, intrusion prevention, application-aware filtering, and more.

### Benefits of Firewalls

For the exam, remember that:

- Firewalls prevent unauthorized access to network resources, reducing the risk of data breaches.

- Firewalls enable network segmentation, limiting the impact of a security breach to specific areas.

- NGFWs can identify and control specific applications, reducing the attack surface and enhancing security.

- Firewalls depend upon well-written and appropriate access control rules

## Web Application Firewalls (WAF)

Web Application Firewalls (WAFs) are specialized security appliances or software designed to protect web applications from various types of cyber threats, including SQL injection, cross-site scripting (XSS), and other web-based attacks. 

WAFs can be deployed as physical devices providing dedicated protection for web applications – this would be most common inside a hosting provider where a large number of servers and applications need to be covered. More commonly, WAFs are Host-based, meaning they are software installed directly on the web application server. WAF services are also provided by cloud service providers and can often offer additional functions which integrate with other cloud services.

### Benefits of WAFs

- WAFs defend against web-based attacks, safeguarding sensitive data and preventing website defacement.
  
- WAFs monitor web traffic and generate real-time alerts for suspicious activities.
  
- Cloud-based WAFs offer scalability and easy deployment for cloud-hosted applications.

*Tip: While installing a WAF is one of the best steps the development or operations team can take to safeguard a web application, WAFs are not a complete solution and should never become an excuse for lax development processes or a failure to test for vulnerabilities. WAFs can be bypassed by skilled attackers!*

## Unified Threat Management (UTM)

Unified Threat Management (UTM) appliances integrate multiple security functions into a single platform, providing comprehensive protection against various threats. UTM devices typically provide a wide range of services, including switching, firewall, IDS/IPS, anti-malware, anti-spam, content filtering, and traffic shaping.

### Typical UTM Features

- **Firewall:** Controls network traffic and access based on security policies.
  
- **Antivirus:** Scans files and incoming traffic for known malware and viruses.
  
- **Intrusion Detection/Prevention:** Monitors network activity for potential attacks and takes actions to block or mitigate threats.
  
- **Virtual Private Network (VPN):** Allows secure remote access to the internal network.
  
- **Content Filtering:** Filters web content to prevent access to malicious or inappropriate websites.

### Benefits of UTM

UTM is something of a marketing term, since in reality, all systems are slightly different – it’s also the case that UTM solutions rarely offer solutions which are not available to purchase separately - they *do* however have some significant benefits as a result of their integration. These include: 

**- Simplified Management -** UTM consolidates multiple security functions, reducing complexity and easing management.

**- Improved Visibility –** Integrated services can more easily feed data to a common dashboard, giving network defenders an excellent understanding of what is happening in the network.

**- Cost-Effectiveness -**  Instead of purchasing and maintaining separate appliances, UTM can provide cost savings.

**- Comprehensive Protection -** UTM offers a wide range of security measures, covering multiple attack vectors.

## Network Address Translation (NAT) Gateway

A NAT Gateway is a network appliance that translates private IP addresses to a public IP address when communicating with external networks. The primary reason for NAT was originally to address the lack of IPv4 addresses, and even today many security professionals argue about whether NAT should be considered a security feature. The primary security value of NAT is to hide internal network addresses from an external attacker, but NAT devices can also be configured with an Access Control List to specify which internal addresses should be permitted to use NAT. In this sense, it’s possible to control traffic which can cross a NAT boundary. 

### NAT Types

There are three NAT types to be aware of, these are:

- **Static NAT:** Maps a specific private IP address to a corresponding public IP address.

- **Dynamic NAT:** Maps multiple private IP addresses to a pool of public IP addresses on a first-come, first-served basis. (When all the addresses in the pool are handed out, other hosts have to wait!)

- **Port Address Translation (PAT):** Maps *multiple* private IP addresses to a single public IP address, using different port numbers to distinguish between connections. Most NAT systems today use PAT.

## Content/URL Filters

Content/URL filters are security appliances or software that control access to websites and content based on pre-defined policies. They are commonly used in organizations to enforce acceptable use policies and protect against malicious websites.

There are three main approaches to content filtering to be aware of, these are: 

- **Whitelisting:** Allows access only to a predefined list of approved websites or content. The most secure, but also the most labour intensive to manage. 
  
- **Blacklisting:** Blocks access to specific websites or content based on predefined criteria. Allows access to a resource unless blocked, which is more convenient but not an effective way to manage the hundreds of new malicious websites which are created every day! Blacklisting is, however, good for preventing access to social media for example.
   
- **Keyword Filtering:** Blocks content containing specific keywords or phrases.

### Benefits of Content/URL Filters

**- Web Security:** Content filters prevent access to malicious websites and inappropriate content, reducing the risk of malware infections and data breaches.

**- Productivity Enhancement:** Content filters can reduce non-work-related web browsing, increasing productivity in the workplace.

**- Compliance:** Content filters help organizations comply with industry regulations and prevent legal liabilities related to inappropriate web access.

## Open-Source vs. Proprietary Network Appliances

Network appliances can be based on open-source or proprietary software. Each approach has its advantages and considerations. 

Open source software is software for which the source code is publically available – anyone can read through the code and see how a program works. You can often find open-source projects on GitHub or GitLab. This approach is associated with greater transparency, community support, customization options and cost-effectiveness. Anyone can find a bug in open-source software, and most well-organised projects are very efficient in fixing errors which are reported to them. 

Open-source software is not the same as free software – some open-source projects can and do charge for licencing, however, open-source projects are often community driven and less expensive (or free!). Because of this, they may require more technical expertise for setup and maintenance and they often offer limited official support.

Proprietary software is private, and the source code is not made available to the public – only the final product. Proprietary software usually comes from an established business with a revenue stream to allow professional support and vendor reliability. Often Proprietary software has greater financial backing, and therefore more money can be spent on user interface design, which might make using the software more intuitive. 

The issues with proprietary software are higher costs, limited customization options, and a dependency on the vendor's roadmap. Furthermore, many security experts feel that Proprietary software suffers from having fewer people able to view the source code (usually just the employees of the business developing the software) and therefore able to spot possible vulnerabilities and weaknesses. 

*Tip: Proprietary software is also often called “closed-source”*

## Hardware vs. Software Network Appliances

In the era of cloud and virtualisation, many network appliances can be implemented using dedicated hardware or as software-based solutions running on general-purpose hardware (which may be a virtual machine). 

Hardware network appliances offer high performance and are purpose-built for security tasks. They are typically tuned for their specific purpose, meaning there is minimal resource contention on the device itself. By contrast, they also have higher costs, limited scalability, and physical space requirements.

By contrast, a software network appliance can offer lower costs and flexibility (especially if cloud-deployed), easier updates and upgrades, and virtualization support. However, they also may face resource contention (multiple functions on a single device trying to use the available processing power) and performance limitations in heavy traffic scenarios.

## Appliance vs. Host-based vs. Virtual Network Appliances

Finally, remember that network appliances can be deployed in various ways depending on the specific use case and organizational requirements.

To take a firewall as an example, a deployment could be:

- Located on a host, either as a separate application or part of the operating system itself. 
  
- In software-defined networking (SDN) networks, instantiated virtual network functions.
  
- As a physical appliance, acting as a network segregation device, separating portions of a network based on firewall rules. 
  
- Deployed as a virtual machine in a cloud environment. 

## Final Words

Network appliances play a crucial role in modern cybersecurity, providing essential protection against various threats and enhancing network security. Understanding the different types of network appliances, their functionalities, and deployment options is essential for designing robust security architectures and safeguarding critical assets from cyber attacks.