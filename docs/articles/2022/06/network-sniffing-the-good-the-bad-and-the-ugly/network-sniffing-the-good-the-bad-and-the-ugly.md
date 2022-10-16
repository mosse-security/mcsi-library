:orphan:
(network-sniffing-the-good-the-bad-and-the-ugly)=
# Network Sniffing: the Good, the Bad, and the Ugly
 
Network sniffing is the act of monitoring and capturing data packets as they travel across a network. A network sniffer is a type of software or hardware designed to do just that. It can be used for legitimate purposes, such as troubleshooting network issues or monitoring network traffic, or it can be used for malicious purposes, such as stealing data or eavesdropping on conversations. In this blog post, we'll take a look at what network sniffing is, how it works.

## Introduction

In hub-based networks, sniffing is simple since traffic on a segment flows through all of the hosts linked with that segment. However, most modern networks rely on switches. A switch is a smart component of computer networking equipment.

The primary distinction between a hub and a switch is that a hub distributes line data to each port on the system and has no line mapping, whereas a switch examines the Media Access Control (MAC) address associated with each frame traveling through it and sends data to the appropriate port. A MAC address is a hardware address that identifies each network node. 

Sensitive data that packet sniffers can gather involves passwords, account information, Syslog traffic,  DNS traffic, email traffic, web traffic, chat sessions, and FTP credentials. By analyzing intercepted data packets, an attacker can gain a large amount of information, which then, the attacker can use to break into the network. An attacker carries out more effective attacks by combining these techniques with active transmission 

## Types of sniffing 

A computer connected to a local area network (LAN) has two addresses: a mac address and an IP address. A MAC address is a hardware address that identifies each network node stored on NIC (Network interface card). The data link layer of the OSI model uses a MAC address whereas the network layer is responsible for mapping the IP address with the MAC address. 

There are two types of sniffing each uses a different type of network.

### Passive sniffing 

No packets are sent during passive sniffing. It simply captures and monitors the network's packets. Because it only works in a common collision domain. A common collision domain is the sector of the network that does not use a switch or bridge. Passive sniffing can be used in hub-connected network systems, where all hosts on the network can view all traffic, making it simple to capture traffic. 

### Active sniffing

In active sniffing, attackers send out multiple network probes to identify access points. In active sniffing, attackers can deliberately inject ARP traffic into a LAN to sniff around and capture communications on a switched network. Some of the different active sniffing techniques are MAC flooding, DNS poisoning, ARP poisoning, DHCP attacks, etc. 

Attackers use sniffing tools to sniff packets and monitor network on a target network:

**Step 1:**  An attacker who wishes to hack a network first locates the relevant network switch and attaches a system or laptop to one of the switch's ports.

**Step 2:** After successfully connecting to the network, the attacker tries to gather information such as network topology by using network discovery tools.

**Step 3:** Attacker then identifies the victim's machine to attack by analyzing the network topology

**Step 4:** An attacker who has identified a target system sends fake (spoofed) Address Resolution Protocol (ARP) messages.

**Step 5:** The previous step assists the attacker in redirecting all traffic from the victim's computer to the attacker's computer. This is a typical person-in-the-middle (PITM) attack.
 
**Step 6:** The attacker now has access to all data packets transmitted and received by the victim. Passwords, usernames, credit card information, and PINs can now be extracted from the packets by the attacker.

## Summary: 

Network sniffing is a powerful method that can be used for both good and malicious reasons. Network sniffing, on the other hand, can be used to eavesdrop on communications, steal important information, and launch attacks. It is critical to be aware of the risks of network sniffing and to take precautions to protect yourself and your network.

:::{seealso}
Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)
:::