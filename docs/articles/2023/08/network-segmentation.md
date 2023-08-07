:orphan:
(network-segmentation)=

# Network Segmentation

## What is Network Segmentation? 

Network segmentation is a key aspect of secure network design. This approach involves dividing a network into smaller, distinct segments to control and limit access between different parts of the network. From a security perspective, Network Segmentation helps to reduce the number of devices on a network which can communicate with each other by default and can play a major role in preventing attackers from moving throughout a network once a system has been compromised. 

Network segmentation can also improve network performance – especially in an IPv4 environment where broadcast traffic can consume significant resources if not properly 

Let’s take a look at some of the most important approaches to network segmentation -  DMZs, Virtual Local Area Networks (VLANs), Intranets, Extranets, East-West Traffic, and Zero Trust.

## Virtual Local Area Networks (VLANs)

A VLAN is a virtual network that allows network administrators to logically segment a physical network into multiple isolated networks, each operating as if they were on separate physical switches. VLANs exist at layer 2 of the OSI model (Datalink).

VLANs are created by assigning specific ports on network devices (usually switches) to a specific VLAN ID. Devices within the same VLAN can communicate with each other directly, while devices in different VLANs act as if they are not connected at Layer 2 – they, therefore, need to go through a router or a Layer 3 switch for communication. This segregation ensures that traffic from one VLAN cannot directly reach devices in another VLAN, providing a level of isolation and security. 

VLANs are typically assigned based on factors such as functional department, user groups, or security requirements (perhaps clearance levels, for example). VLANs allow network administrators to control traffic flow between segments and enforce security policies – for example, a host in the marketing department on the marketing VLAN probably never needs to access a sensitive development server in the development VLAN. An administrator can configure an Access Control List on a switch or router to deny the marketing VLAN access to the development VLAN. Now, if an attacker was to compromise the marketing host and attempt to access the development server their traffic would just be dropped!

```
Switch# show vlan

VLAN Name                             Status    Ports

---- -------------------------------- ---------

1    default                          active    Fa0/1
2    VLAN0002                         active    Fa0/2
3    VLAN0003                         active    Fa0/3
4    VLAN0004                         active    Fa0/4
5    VLAN0005                         active    Fa0/5
5    VLAN0005                         active    Fa0/6
```

 *An example of the "show vlan" command on a Cisco switch, each port is in it's own VLAN and could not communicate with the others, except ports 5 and 6, who are both in VLAN 5, and could communicate normally*.

## Screened Subnet or Demilitarized Zone (DMZ)

A Screened Subnet, or DMZ, is an intermediate network zone situated between the internal trusted network and the untrusted external network, such as the Internet. The purpose of implementing a Screened Subnet is to create a buffer zone that separates public-facing services (e.g., web servers, email servers, and FTP servers) from critical internal resources and data.

The security rationale behind the Screened Subnet lies in the idea that public services are often targeted by attackers seeking vulnerabilities. By placing these services in a separate network segment, any successful breach of a public service will be contained within the Screened Subnet, preventing direct access to the sensitive internal network. Consequently, sensitive data, proprietary information, and critical systems remain safeguarded even in the event of a breach.

A firewall (or other network security device) typically exists between the internal and Screened subnet, acting as another layer of defence. 

*Tip: Here, we use the term Screened Subnet -- the terms DMZ and Perimeter network are also common, but mean exactly the same thing.* 

## Intranet

An intranet is a private network used within an organization to share information, resources, and services among employees. It serves as a secure and controlled platform for collaboration and data exchange, typically accessible only to authorized personnel within the organization's premises or through secure remote access (Perhaps a VPN). Intranets can be quite complex, some have their own internal websites, services and collaboration tools. For practical purposes, you can think of an intranet as a private mini-internet. 

The purpose of an intranet for security is to maintain confidentiality and control over sensitive information – by allowing only users from within an internal network to access services and resources the attack surface is significantly reduced.  

*Tip: Web servers, file servers or other systems running on an intranet still need to be patched for vulnerabilities and included in security updates and scans. If an attacker is able to compromise a host within your network any vulnerabilities on an internal web server are just as easy to exploit as an external server!* 

## Extranet

An extranet is an extension of the intranet that allows external parties, such as business partners, suppliers, and customers, to access specific resources and collaborate with the organization. It provides a secure and controlled means of sharing selected information and services with authorized external users.

The purpose of an extranet for security is to facilitate secure collaboration while maintaining a clear boundary between the organization's internal network and the external entities. By carefully controlling access and employing encryption and authentication measures, the organization can protect its sensitive data and maintain trust and interoperability with external stakeholders.

*Tip: You may see an example or diagram which defines an extranet as being two intranets (belonging to different organisations) linked together. The fact they are linked makes this an example of an extranet, watch out for this one as it can be confusing!*

## East-West Traffic

East-west traffic refers to the communication that occurs between devices within the same network segment or between different segments within the internal network. Traditionally, network security focused more on protecting the perimeter or north-south traffic (communication between the internal network and external networks). However, the increasing number of sophisticated threats and insider attacks have highlighted the need to secure east-west traffic as well.

The purpose of securing east-west traffic is to prevent lateral movement within the network in case a malicious actor gains access to a single segment. By employing network segmentation techniques, such as VLANs, Host-based Intrusion detection systems and micro-segmentation, an organization can significantly reduce the attack surface and limit the potential impact of a breach. 

*Tip: North-South traffic is also an important term. North-South traffic is simply traffic coming into, or leaving your network. North-South traffic is usually inspected by a Firewall, IPS or IDS system.* 

## Zero Trust

Zero Trust is not a security implementation, but rather a security framework that assumes no implicit trust for any user, device, or network segment. In this model, all access requests, regardless of their source (North-South or East-West), are verified and authorized explicitly based on factors like user identity, device health, location, and other contextual information.

The purpose of Zero Trust for security is to eliminate the concept of a trusted internal network and to implement a "never trust, always verify" approach. Network segmentation plays a crucial role in the Zero Trust model, as it allows organizations to define granular access policies for different segments and enforce strict controls on data flow. With Zero Trust, even if an attacker gains access to a specific segment, their movement within the network will be severely limited due to the segmented nature of the network and the need for continuous authentication and authorization.

## Final words

Network segmentation is a fundamental strategy for enhancing network security. By dividing the network into smaller, more manageable segments, organizations can limit the potential impact of security breaches, prevent unauthorized access, and control data flow effectively. Components such as VLANs, Screened Subnets, east-west traffic security, Extranets, Intranets, and the Zero Trust model all play vital roles in bolstering the overall security posture of an organization. As always, adopting a "defence in depth" approach which leverages several of these options is the best way forward.