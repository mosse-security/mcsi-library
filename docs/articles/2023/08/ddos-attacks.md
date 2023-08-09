:orphan:
(ddos-attacks)=

# DDoS Attacks 

In today's interconnected digital landscape, the availability and stability of online services have become indispensable for companies worldwide. Denial of Service (Dos) and Distributed Denial of Service (DDoS) attacks serve as a class of attacks that have the potential to cripple online services, websites, and critical technology infrastructure. These attacks represent a severe threat to organizations and can lead to the disruption of crucial business functions. This article explores the mechanics of DDoS attacks, their different types, and the various strategies that can be employed to defend against them.

## What is DoS and DDoS Attack?

In a DoS attack, a single attacker attempts to flood the target system with an excessive amount of traffic or requests. This can be accomplished by sending a large volume of data, exploiting vulnerabilities in the system, or using other techniques to exhaust its resources. As a result, the targeted system becomes unresponsive, denying access to legitimate users.

A distributed denial-of-service (DDoS) attack is identical to a DoS attack except the volume is much greater. In a DDoS attack, multiple compromised computers are used to flood the target system simultaneously. These compromised systems form a network controlled by the attacker, who remotely commands them to send massive amounts of traffic or requests to the target. This coordinated attack from multiple sources makes it even more challenging to defend against it.

## How does the DDoS attack take place?

A Distributed Denial-of-Service attack involves several key components working in concert to overwhelm the target system. The attacker chooses the flooding technique they want to employ and then instructs an army of hijacked or zombie computers to attack at a specific time. Where do these computers come from? 

Every day, tens of thousands of computers are infected with malware, typically when their users click a link to a malicious website or open an attachment on an e-mail message. As part of the infection, and after the cybercriminals extract any useful information like banking information and passwords, the computer is told to execute a program that connects it to a command and control (C&C) network. At this point, cybercriminals can issue commands to it and to thousands of other similarly infected machines on the same C&C network. Each of these computers is called a zombie or a bot, and the network they form is called a botnet. This botnet is then leveraged to flood a target system or network causing it to become inaccessible.

## Types of DDoS attacks

This section covers three main types of DDoS attacks.

### Network Attacks

Network attacks occur specifically at the network layer (layer 3) and transport layer (layer 4) of the OSI(Open Systems Interconnection) model. These attacks represent the most prevalent form of DDoS attacks and are characterized by their massive volume and aim to overwhelm the network or application servers' capacity. By exploiting vulnerabilities in these layers, attackers flood the target with an excessive amount of traffic, leading to service unavailability and effectively denying access to legitimate users. The purpose of this type of DDoS attack is to prevent access to the target system by blocking network connections to the target. Some of the network DDoS attacks include the following.

**<u>SYN Flood Attack</u>**

A SYN flood attack is a type of Denial-of-Service (DoS) attack that targets the three-way handshake process in the Transmission Control Protocol (TCP).

The three-way handshake is a key process used by the Transmission Control Protocol to establish a connection between a client (typically a user's device) and a server (a remote system or service) on a computer network. It is an essential part of TCP's reliable and connection-oriented communication.

The three steps in the handshake process are as follows:

**Step 1: SYN (Synchronize) -** The client sends a SYN packet to the server, indicating its desire to establish a connection. This packet contains a sequence number that helps keep track of the data exchanged during the communication.

**Step 2: SYN/ACK (Synchronize/Acknowledge) -** Upon receiving the SYN packet, the server acknowledges the request by sending back a SYN/ACK packet. The server also includes its own sequence number and acknowledges the client's sequence number from the previous step.

**Step 3: ACK (Acknowledge) -** In the final step, the client responds with an ACK packet, confirming that it received the server's SYN/ACK packet. The ACK packet contains the server's sequence number, incremented by one, to acknowledge the server's response.

In a SYN flood attack, the attacker sends a large number of SYN packets to the target system, pretending to initiate a connection. However, the attacker deliberately refrains from completing the handshake process by withholding responses to the server's SYN-ACK packets. This leaves the server waiting for the final ACK packet to complete the connection.

The target system has a limited number of half-open connections it can handle simultaneously, and as the attacker continues to send SYN packets without completing the handshake, the target's resources get exhausted. This can lead to a situation where the server is overwhelmed, unable to accept legitimate connection requests, and ultimately becomes unresponsive to normal traffic.

**<u> Ping-of-Death Attack </u>**

The ping of death is a type of Denial-of-Service (DoS) attack that exploits a vulnerability in the Internet Control Message Protocol (ICMP). ICMP is used for diagnostic purposes and to send error messages related to network communication.

In a ping of death attack, the attacker sends an ICMP echo request (ping) packet to the target system but manipulates the packet to be larger than the maximum size allowed by the protocol (usually 64 KB). When the target system receives this oversized ICMP packet, it may not be able to handle it properly.

Due to the packet's excessive size, the target system's buffer overflows, leading to system instability, crashes, or even the entire system becoming unresponsive. In some cases, the ping of death attack can also cause network disruption and impact other systems connected to the target.

**<u> CLDAP Attack </u>**

CLDAP is a type of reflection attack that utilizes the Connectionless Lightweight Directory Access Protocol. In this attack, the attacker sends requests to various publicly accessible LDAP servers, asking for information on all accounts in the Active Directory. However, the attacker spoofs their source IP address to make it appear as if the request is coming from a legitimate user.

When the LDAP servers respond to the requests, they send the requested information to the victim machine instead of the attacker's actual location. This way, the attacker can amplify the attack by having the victim machine receive much larger responses than the original request.

## Application Attacks

Application layer DDoS attacks are a type of Distributed Denial-of-Service (DDoS) attack that targets the application layer (layer 7) of the OSI model. This layer is the uppermost layer where applications run. Unlike other DDoS attacks that focus on flooding network infrastructure, application layer attacks specifically aim to overwhelm the resources of web servers, APIs, and other software that handle user interactions and data processing.

In application layer DDoS attacks, the attackers exploit vulnerabilities in the way applications process requests and data. They may send a large number of seemingly legitimate requests to exhaust the target's computing resources, such as CPU and memory, or exploit specific weaknesses in the application code to cause it to malfunction or crash. Application layer DDoS attacks are particularly effective because they directly impact the services and applications users interact with. They can also be harder to detect and mitigate due to their sophistication and the similarity of attack traffic to legitimate requests.  

### How Does the Application DDoS Attack Work?

The success of this type of attack lies in the imbalance between the resources required to execute the attack and the resources needed to defend against it. These attacks primarily focus on overwhelming the processing power of the target system rather than saturating its network bandwidth.

Imagine an application-level DDoS attack targeted at a popular online shopping website during a major sale event. The attacker floods the website with a massive number of seemingly legitimate requests, each requiring minimal resources to create on the attacker's end. However, the targeted website, which handles complex tasks like inventory management, user authentication, and payment processing, faces an overwhelming demand for its processing power. The attacker's ability to generate a large volume of requests with minimal effort creates an imbalance between the attacker's resources and the website's capacity to handle the traffic. Consequently, the website struggles to process the volume of incoming requests, resulting in slow loading times, transaction failures, and ultimately, a degraded user experience or service outage.

## Operational Technology Attacks

Operational Technology (OT) refers to the technology used to control and monitor physical devices and processes in various industries, such as manufacturing, energy, transportation, and infrastructure. Unlike traditional IT (Information Technology) which focuses on data processing and communication, OT deals with the direct management of industrial machinery, systems, and processes to ensure smooth and efficient operations. It involves specialized hardware, software, and networks designed for real-time control, monitoring, and automation of industrial equipment, providing the foundation for essential functions like manufacturing, power generation, and critical infrastructure management. The security of these systems is of paramount importance to prevent potential cyber-physical attacks resulting in significant real-world consequences.

Operational Technology DDoS attacks are specifically targeted at industrial control systems and critical infrastructure that rely on OT. In these attacks, malicious actors overwhelm the OT systems with a massive volume of traffic, causing them to become unresponsive or non-functional. The objective of OT DDoS attacks is to disrupt the physical processes controlled by these systems, leading to operational disruptions, production halts, or safety concerns.

## Mitigating DDoS Attacks

Mitigating DDoS attacks requires a multi-layered and proactive approach to protect networks and applications from overwhelming traffic. Here are some effective strategies to mitigate DDoS attacks:

**- DDoS Protection Services:** Consider seeking the expertise of DDoS protection service providers that specialize in detecting and mitigating DDoS attacks. These services can absorb and filter attack traffic before it reaches your network or application.

**- Traffic Analysis and Anomaly Detection:** Employ traffic analysis tools and anomaly detection systems to identify abnormal patterns of traffic and behavior, allowing quick identification of potential DDoS attacks.

**- Rate Limiting and Traffic Shaping:** Implement rate limiting and traffic shaping to control the amount of traffic allowed from individual IP addresses or subnets, preventing attackers from overwhelming your resources.

**- Web Application Firewalls (WAFs):** Deploy WAFs to filter and block malicious requests targeting your web applications. 

**- Load Balancing and Scaling:** Distribute incoming traffic across multiple servers using load balancers to avoid overloading a single target and to increase overall capacity.

**- CAPTCHA and Challenge-Response Mechanisms:** Implement CAPTCHA challenges or other challenge-response mechanisms to verify legitimate users and block automated bot traffic.

**- Regular Security Assessments:** Conduct regular security assessments to identify and address vulnerabilities in your network and applications, making it harder for attackers to exploit weaknesses.

## Conclusion

DDoS attacks remain a significant threat to the digital ecosystem, capable of causing widespread disruption and damage. Understanding the various types of DDoS attacks and their consequences is essential for developing effective defense strategies. Implementing a multi-layered defense approach using various security measures and mitigation techniques can effectively thwart DDoS attacks or reduce their impact.