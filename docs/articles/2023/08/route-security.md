:orphan:
(route-security)=

# Route Security

If you are studying route security you hopefully already have a good grasp of networking basics, so the concept of dynamic routing should not be new to you. What you may not have thought about is the security of routing protocols themselves – could an attacker interfere with routes to manipulate traffic or execute a man-in-the-middle attack? They certainly could! 

Before reading this article, you should understand that the key protocols used to connect networks include Internet Protocol (IP), Border Gateway Protocol (BGP), Intermediate System to Intermediate System (IS-IS), Open Shortest Path First (OSPF), Enhanced Interior Gateway Routing Protocol (EIGRP), and (now to a lesser extent) then Routing Information Protocol version 2 (RIPv2). These protocols have some security features we can utilise to protect them in addition to securing the devices they run on. Let's learn about them now.

## The Importance of Route Security

Route security is an often overlooked, but crucial aspect of network protection, as it directly impacts the integrity, confidentiality, and availability of data. Attackers may exploit vulnerabilities in routing protocols or configurations to redirect or intercept traffic, leading to unauthorized access, data theft, or denial of service. By securing routes, organizations can prevent potential security breaches and maintain the trust of their users and customers. As importantly, by ensuring that routing infrastructure is protected, an organisation can equip itself to properly respond to a cyberattack – after all, if an attacker poisons a route table so that the network operations team is no longer even able to reach an IPS device to update a rule or define an action your options for response are severely limited! 

### Common Threats to Route Security

Some of the most common threats to route security include: 

1. **Routing Protocol Attacks:** Attackers may attempt to compromise the integrity of routing protocols by injecting false routing information or manipulating routing tables. This could lead to traffic being redirected to malicious destinations.

2. **Route Hijacking:** In route hijacking attacks, attackers announce false routes to internet routers, causing traffic to be redirected to their systems. This is often done to intercept sensitive data. (A man in the middle attack)

3. **Denial of Service (DoS) Attacks:** By overwhelming a router or its resources, DoS attacks disrupt normal routing operations, leading to service disruptions.

4. **Route Flapping:** Route flapping occurs when a route's status changes rapidly and frequently, potentially affecting the stability and performance of the network.

5. **Unauthorized Configuration Changes:** Misconfigurations in routing devices can lead to unintended consequences, such as traffic blackholing or exposure of sensitive information.

   

### Mitigating Route Security Risks

Unless you're specialising in network device security you do not need to understand the details of how to mitigate these threats - you should however, have a high-level understanding of the countermeasures which can be applied. These include: 

1. **Router Access Control:** Apply strong access controls to routers to prevent unauthorized access and configuration changes. Routers and network devices are often overlooked during security audits, but are critical devices and should be treated as such! 
   
2. **Secure protocols:** Wherever possible, connections to network devices should only be made using SSH. Avoid telnet or clear text protocols wherever possible to prevent sensitive data from being intercepted.
   
3. **Authentication and Encryption:** Implement authentication and encryption mechanisms for routing protocols to ensure the integrity of routing information.
   
4. **Route Filtering:** Use route filters and access control lists (ACLs) to restrict the advertisements and acceptance of routes from untrusted sources. Some routing platforms do this by default (for example, Cisco IOS XR will not accept routes from eBGP peers by default) but many do not. 
   
5. **Routing Protocol Security Features:** Many routing protocols offer security features, such as BGP's TTL Security or OSPF's authentication, which help prevent route hijacking and unauthorized changes.
   
6. **Monitoring and Logging:** Continuously monitor the network for unusual routing behavior and log routing-related events for analysis and incident response.


## BGP Security

Border Gateway Protocol (BGP) is the protocol used for the vast majority of internet routing and is, therefore, an appealing target for attackers. BGP route security is crucial to prevent route leaks and hijacks. Organizations can implement the following BGP security measures:

1. **Route Origin Validation (ROV):** ROV helps verify the legitimacy of route announcements, preventing the propagation of incorrect or malicious routes.

2. **TTL Security:** TTL security is an additional layer of protection against BGP route leaks and hijacks. By configuring a maximum Time-to-Live (TTL) value on BGP updates received from external peers (this has the effect of specifying from how many hops away an update may be considered valid), network operators can prevent routes with inappropriate or unauthorized TTL values from being accepted. This helps mitigate the risk of malicious actors injecting unauthorized routes into the network.

3. **BGP Flowspec:** BGP Flowspec allows the specification of traffic filtering rules directly within BGP updates, enabling quick mitigation of DDoS attacks.

4. **BGP Route Dampening:** BGP route dampening helps mitigate the impact of route flapping by suppressing unstable routes.

5. **BGP Communities:** Using BGP communities, network operators can control how routes are propagated within their Autonomous System (AS).

   

## OSPF, EIGRP and IS-IS Security

Open Shortest Path First (OSPF) and Intermediate System to Intermediate System (IS-IS) are link-state interior gateway routing protocols commonly used within large organizations. EIGRP is a hybrid protocol which shares some components of link-state protocols and some of a distance-vector protocol. Together, these three make up the majority of interior routing today. (IS-IS is not heavily used in enterprises but is very popular with service providers!). 

While they operate within the internal network, securing these protocols is also vital to maintaining overall route security. Some security measures for OSPF, IS-IS and EIGRP include:

1. **OSPF Authentication:** Enable OSPF authentication to verify the authenticity of OSPF routing updates.
   
2. **IS-IS Authentication:** Implement IS-IS authentication to ensure that only authorized devices exchange routing information. IS-IS allows for the configuration of a password for a specified link, an area, or a domain.
   
3. **EIGRP Authentication:** Enable EIGRP authentication wherever possible. This prevents unauthorized routers from participating in the EIGRP routing process.
   
4. **Routing Area Design:** Partition the network into OSPF or IS-IS areas to limit the propagation of routing information.

```
router1(config)#key chain cisco
router1(config-keychain)#key 1
router1(config-keychain-key)#key-string cisco1
router1(config-keychain-key)#exit
router1(config-keychain)#exit
router1(config)#int ethernet0/0
router1(config-if)#ip ospf Authentication message-digest
router1(config-if)#ip ospf authentication-key cisco1
```

 *An example of configuring MD5 Authentication for OSPF on Cisco IOS*

## RIP and Legacy Protocols

The routing information Protocol (RIP) Version 2 supports authentication, but the earlier RIP version 1 does not support any security features. Few environments are still using RIP version 1, however, at this point in time, even RIP version 2 is becoming dated. Where possible, it is probably advisable to upgrade to a newer more secure protocol. 

## Routing Protocol Authentication Options

Different routing protocols also support different authentication mechanisms – while plain text authentication is an option (and can be used to help prevent accidental changes within a network) it has little value for security. Wherever possible, a high-strength hashing algorithm should be used, SHA and HMAC-MD5 are good choices. 

| **Routing Protocol** | **Supported Authentication Protocols**           |
| -------------------- | ------------------------------------------------ |
| IS-IS                | Plain Text Password                              |
|                      | HMAC-MD5 (Key-chain authentication in Cisco IOS) |
| EIGRP                | MD5 (Message Digest 5)                           |
|                      | SHA (Secure Hash Algorithm)                      |
| OSPF                 | Null (No Authentication)                         |
|                      | Plain Text Password                              |
|                      | MD5 (Message Digest 5)                           |
| RIPv2                | Plain Text Password                              |
|                      | MD5 (Message Digest 5)                           |

 

*Tip: In this section, we’ve focused on OSPFv2 (OSPF for IPv4) The newer OSPv3 runs on IPv6 and utilises IPSec to perform its authentication. This is much more secure!* 

## Route Security Audits

Regular route security audits can also help identify potential vulnerabilities and misconfigurations. It’s tempting to treat routes and routing protocol configurations as “set and forget” items, however, network administrators should conduct thorough reviews of routing protocols, configurations, and access controls on a rolling basis. Additionally, they should verify that route advertisements are legitimate and consistent with organizational policies.

## Final Words

Route security plays a pivotal role in protecting the integrity and reliability of data as it traverses networks. Implementing best practices, securing routing protocols, and continually monitoring for potential threats are essential steps to ensure robust route security. By taking proactive measures to safeguard routes, organizations can enhance their overall cybersecurity posture and maintain the stability of their networks.