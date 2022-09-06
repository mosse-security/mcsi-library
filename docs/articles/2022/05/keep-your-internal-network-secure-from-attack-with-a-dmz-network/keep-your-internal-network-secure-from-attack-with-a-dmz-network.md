:orphan:
(keep-your-internal-network-secure-from-attack-with-a-dmz-network)=

# Keep Your Internal Network Secure From Attack With a DMZ Network

A DMZ network connects a company's secure perimeter to unsecured external networks like the internet. Web servers and other externally facing systems can be located in the DMZ without jeopardizing the security of internal resources. This blog post will explain what DMZs are and why they are important components of traditional network security architectures. Even if best practices are followed, DMZs are not perfect security solutions. We will demonstrate how modern security solutions based on Zero Trust are better suited to the way businesses operate today.

## What is a DMZ network?

A demilitarized zone, or DMZ, is a concept that describes methods for connecting internal, protected networks with untrusted external networks. DMZs have been critical components of the traditional secure perimeter paradigm for decades. They provide more secure data paths between the protected network and the internet.

The DMZ, also known as a perimeter network, is a sub-network that exists outside the secure perimeter's defenses but is still under network administrators' control. External-facing resources are placed within the DMZ for internet access. Traffic between the DMZ and the internal network is restricted by network access control systems.

DMZs provide separation and control, making it easier to protect internal resources, provide access, and reduce the risks of cyber-attacks. A DMZ has several advantages:

**Minimize security breach impacts:**

The scope of successful security breaches is limited by DMZs. If hackers breach a DMZ, they will only have access to the resources within that DMZ. Network access controls limit their ability to move laterally and keep them from spying on the internal network. At the same time, the extra security measures of a DMZ give administrators a better chance of detecting unusual network traffic and quickly closing the breach.

**Decoupling services from databases:**

Externally facing systems frequently require access to proprietary databases and other resources:

- Web servers require customer information;
- Email servers require access to company directories; and
- API servers require access to backend databases.

However, putting these confidential resources on a publicly accessible server is too risky. By hosting the front-end server in a DMZ while keeping sensitive back-end resources on the protected internal network, those risks are avoided.

**Isolate less secure services:**

FTP and other services with few security controls can be used to launch cyber-attacks. Putting FTP servers in their own DMZ reduces the possibility of a successful attack spreading to the internal network.

**Internet access for internal users:**

Access control rules can force all internal internet access through a dedicated proxy server located in a DMZ. Administrators now have greater visibility and control over the company's internet usage.

**Improve internal network performance:**

Web servers that are frequently accessed place heavy demands on networks. Placing these servers in a DMZ removes them from the internal network. To handle those loads more efficiently, administrators can optimize the DMZ subnet.

## How do DMZ networks work?

A single firewall is one approach to creating a business DMZ network. What traffic enters the DMZ, accesses the DMZ's resources, and may enter the internal network is determined by access control rules. This architecture is simple to build and manage, but it is not the most secure. Hackers breach the secure perimeter if they breach the single firewall.

A dual-firewall architecture improves security while increasing administrative complexity. An external firewall controls access between the internet and the DMZ's resources in this approach. The DMZ's resources and the internal network are controlled by an internal firewall, ideally from a different provider. Hackers who breach the external firewall do not have immediate access to the internal network.

It is worth noting that consumer-grade internet routers that small businesses may use frequently include a DMZ feature. Any traffic that is not destined for specific hosts on the LAN is routed to a host with a specific IP address. This consumer feature does not provide the same level of security as a true DMZ. The host is not on a separate subnet, and no firewall controls access between the host and the LAN.

## Security risks of using a DMZ network?

A DMZ is only as safe as its configuration, policies, and administration. Even so, resources within the DMZ may compromise the network's defenses. The following are some of the threats that DMZ networks may face:

**Internet visibility:**

A DMZ's resources must be publicly visible so that external users can access them. However, visibility comes with discoverability. Simple scanning tools can be used by hackers to locate resources in a company's DMZ, identify vulnerabilities, and plan attacks.

**DMZ network vulnerabilities:**

The infrastructure used to create the DMZ subnetwork must be correctly configured and maintained. Overly permissive access control rules or unpatched firewalls can create attack vectors. This is especially true for DMZ architectures with a single firewall.

**DMZ resource vulnerabilities:**

Many of the resources in a DMZ can introduce security flaws. Remote access technologies, such as VPN and RDP, have become popular targets for cyberattacks. Unsecured web or email servers can allow hackers to move laterally through the DMZ and eventually into the protected network.

**DMZ's declining relevance:**

The entire concept of a DMZ is based on the assumption of a secure perimeter surrounding on-premises resources. However, that is an outmoded computing model that is no longer relevant to the way businesses operate today. SD-WAN technologies, for example, completely avoid DMZs by connecting offices via the internet. Furthermore, DMZs are ineffective at protecting resources hosted on cloud platforms or outsourced to cloud-based X-as-a-Service providers.

## Best practices for securing DMZ networks

To provide both security and access, DMZ networks must be designed in such a way that any successful breach is difficult to move laterally. The following are some best practices to follow:

**Segment DMZs:**

The use of a single DMZ to host all externally facing systems increases the likelihood of a successful breach. It provides more opportunities for lateral movement for hackers. With enough time, they can gather enough information to gain access to the protected network. And they might have that time because the complex traffic patterns of a multi-purpose DMZ make detecting unusual behavior more difficult.

Each externally facing system should ideally be contained within its own DMZ. Access control rules will be simpler to define. The traffic patterns will be easier to track. And hackers will have no other option.

**Lockdown DMZs in dual-firewall architectures:**

To provide the most protection for internal networks, use firewalls from two different vendors. They are less likely to share vulnerabilities, making it more difficult for hackers to breach the internal network.

Set the minimum configuration required for firewalls, routers, servers, and other DMZ systems to function. For example, unless specifically required to pass DMZ traffic, all ports should be closed. Locking down the DMZ restricts hackers' options and makes their activity more visible.

**Limit what hackers can learn:**

When defining DMZ policies, do not use the internal network's policies. Whatever hackers learn from observing how traffic is routed and secured in the DMZ should not provide them with insights into the internal network's operations.

**Monitor and audit:**

The earlier a security breach is detected, the less damage hackers can cause. Make certain that all traffic is inspected and recorded. In addition to the security features of each firewall, use intrusion detection systems.
The fact that the DMZ was set up securely does not guarantee that it will remain secure. Audit access control rules, ports, and other potential vulnerabilities on a regular basis.

## Alternative solutions for securing company resources other than DMZ networks

DMZs are no longer the security panacea they once were. Physical, on-premises assets accessed by employees at their desks are no longer the focus of network architectures. Third-party providers may host mission-critical resources in the cloud or deliver them over the internet. Work-from-home and BYOD policies complicate matters even more by allowing more users to access company resources away from the office.

Zero Trust Network Access (ZTNA) is a modern approach to securing proprietary resources in today's more distributed environment. Instead of defending a secure perimeter, ZTNA defends each resource as if every device, network, and user is already compromised. Explicit verification and least privilege access policies ensure that authorized users only have the access they need to complete their tasks.

For their time, DMZ networks were effective solutions. By putting a more secure subnet between the internet and a secure perimeter, administrators can concentrate their security efforts on the most likely attack vectors. However, modern network architectures are not so simple. As more resources migrate to the cloud and more users work remotely, secure perimeters are fading.

## Final words

Security is a critical concern when designing and configuring a DMZ. In order to keep the internal network secure, it is important to carefully consider the type and location of the DMZ components. By understanding the risks and potential threats, you can create a DMZ that will protect your internal network from attack.

A DMZ can be a very effective security measure for an organization, but it is important to remember that it is not a panacea. It is important to have a well-thought-out security plan that takes into account the needs of the organization and the specific threats it faces. The DMZ should be just one part of that plan.

> **Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)!**
