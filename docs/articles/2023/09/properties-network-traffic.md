:orphan:
(properties-network-traffic)=

# Properties of Network Traffic

Network traffic refers to the data packets that flow across a network, carrying information from one device to another. Understanding the properties of network traffic is essential for designing, managing, and troubleshooting networks effectively. In this article, let's take a look at some of the most important aspects you'll need to understand.

 

## Broadcast Domains

A broadcast domain is a logical division of a computer network where all devices can receive each other's broadcast messages. Broadcast messages are typically used for tasks like ARP (Address Resolution Protocol) resolution, DHCP (Dynamic Host Configuration Protocol) requests, and network discovery in IPv4 (in IPv6 broadcasts don’t exist). A broadcast domain can be defined by a physical boundary or by a networking device, such as a router or Layer 3 switch, which separates it from other broadcast domains. VLANs also enforce broadcast domains at the logical level.

Creating smaller broadcast domains is crucial in network design because it helps mitigate congestion and minimizes unnecessary processing of packets. In larger broadcast domains, such as those encompassing an entire network, broadcast traffic can quickly accumulate, leading to network congestion. This congestion can slow down network performance and result in delays in the delivery of critical data. Moreover, devices within larger broadcast domains must process and evaluate each broadcast packet, even if the packet is not relevant to them, consuming valuable processing resources. By segmenting networks into smaller broadcast domains through techniques like subnetting, physical separation or VLANs, organizations can confine broadcast traffic to specific segments, reducing congestion and preventing devices from expending resources processing irrelevant packets, ultimately optimizing network efficiency and reliability.

 

## Collision Domains

A collision domain is a segment of a network where collisions can occur. In Ethernet networks, collisions happen when multiple devices attempt to transmit data simultaneously on a shared medium, such as a hub-based network. Reducing the number of collision domains can improve network performance. Modern Ethernet switches, which operate at Layer 2 (Data Link layer) of the OSI model, create separate collision domains for each port, effectively eliminating collisions on a per-port basis.

 

## CSMA/CD (Carrier Sense Multiple Access with Collision Detection)

CSMA/CD is a network protocol used in Ethernet networks to manage access to the network medium and detect collisions. In CSMA/CD, devices listen for a carrier signal (indicating network activity) before attempting to transmit data on the wite.. If two devices transmit data simultaneously and a collision occurs the data is unusable - CSMA/CD helps detect the collision and initiates a backoff algorithm, which schedules retransmission attempts to minimize collisions and maximize network efficiency.

CSMA/CD played a critical role in the early days of Ethernet networks when shared media and half-duplex communication were the norm. However, with advancements in Ethernet technology, including the widespread adoption of full-duplex communication and the replacement of hubs with Ethernet switches, the relevance of CSMA/CD has significantly diminished.

Full-duplex communication allows devices to transmit and receive data simultaneously, effectively eliminating the possibility of collisions on a single network segment. This technological shift has made CSMA/CD unnecessary in many modern Ethernet networks, as devices can communicate without the need for collision detection.

Ethernet switches on the other hand, have revolutionized network architecture by segmenting network traffic into *individual* collision domains on a per-port basis. Unlike hubs, which propagate data to all connected devices in a shared collision domain, switches direct data only to the specific port where the recipient device is located. This segmentation drastically reduces the chances of collisions, making CSMA/CD redundant in switch-based networks.

 

## CSMA/CA (Carrier Sense Multiple Access with Collision Avoidance)

CSMA/CA is a protocol used in wireless networks, such as Wi-Fi, to manage access to the shared wireless medium and avoid collisions. In CSMA/CA, devices listen for the presence of other devices on the network and employ strategies to minimize the chances of simultaneous transmissions, which can lead to interference and collisions. CSMA/CA is crucial in wireless networks to ensure reliable communication.

Wireless networks, in contrast to their wired counterparts, still rely on a shared wireless medium for communication. This shared nature poses unique challenges, particularly regarding collision detection. Unlike wired networks, where collisions are easily detectable due to electrical interference, wireless collisions may go unnoticed as radio signals can overlap and interfere with each other in a more complex manner. There are two main issues to overcome – these are:

1. **Hidden Node Problem**: CSMA/CA addresses the "hidden node problem," a common issue in wireless networks. In this scenario, two or more devices cannot directly sense each other's transmissions due to physical obstructions or distance. Without CSMA/CA, these devices might simultaneously transmit data, leading to interference and collisions, which can degrade network performance.
2. **Exposed Node Problem**: Conversely, the "exposed node problem" occurs when one device refrains from transmitting data, assuming another nearby device is active, even though it is not. CSMA/CA helps devices avoid such unnecessary delays and ensures efficient use of the wireless medium.

CSMA/CA incorporates several techniques to facilitate efficient communication in wireless networks:

1. **Request-to-Send (RTS)**: When a device wishes to transmit data, it sends an RTS frame to the intended recipient. The RTS frame includes information about the sender's intention to transmit, the duration of the transmission, and the intended recipient's identity. This preliminary step allows other devices within range to recognize the ongoing transmission attempt and defer their own transmissions to avoid collisions.
2. **Clear-to-Send (CTS)**: Upon receiving an RTS frame, the intended recipient responds with a CTS frame. The CTS frame acknowledges the RTS and essentially reserves the wireless medium for the upcoming data transmission. Other devices that hear the CTS frame understand that the wireless medium will be occupied during that period and, therefore, refrain from transmitting, reducing the likelihood of collisions.

 

**Examples of CSMA/CA in Wi-Fi Networks**

Understanding CSMA/CA in wireless networks is crucial for efficient communication. Here are some practical examples:

- **Wi-Fi VoIP Call**: When making a Voice over IP (VoIP) call over Wi-Fi, CSMA/CA ensures that devices take turns transmitting voice data. Devices "listen" for a clear channel before transmitting, preventing interference and ensuring smooth communication.
- **Wi-Fi Gaming**: In online gaming, latency is critical. CSMA/CA helps avoid collisions among gamers' devices by coordinating data transmissions. This ensures that game commands and responses are sent without interference.

 

## Protocol Data Units (PDUs)

Protocol Data Units are the data packets used in network communication. While we often tend to use the word “packet” as a generic expression of information transiting within a network, PDUs have names which correspond to the OSI model. PDUs themselves are structured according to the rules and standards of the network protocol in use. For example, in Ethernet networks, frames are the PDUs, while in IP networks, packets are the PDUs. Understanding the concept of PDUs is crucial for troubleshooting network issues and ensuring data is correctly encapsulated and transmitted. The PDU’s to know are:

 

| **PDU** | **OSI Layer**          | **Description**                                              |
| ------- | ---------------------- | ------------------------------------------------------------ |
| Bit     | Physical Layer (1)     | Represents the smallest unit of data, 0 or 1.                |
| Frame   | Data Link Layer (2)    | Combines bits into a structured format, often including header and  trailer information for error checking. |
| Packet  | Network Layer (3)      | Contains data and routing information, like IP addresses.    |
| Segment | Transport Layer (4)    | Breaks data into smaller units for transport, often including port  numbers. |
| Message | Session Layer (5)      | Manages communication sessions and dialogue control.         |
| Data    | Presentation Layer (6) | Responsible for data translation, encryption, and compression. |
| Data    | Application Layer (7)  | Represents the end-user data or application-specific information. |

 

## MTU (Maximum Transmission Unit)

MTU represents the maximum size of a data packet that can be transmitted over a network. It's important to configure the MTU appropriately to avoid fragmentation and reassembly of packets, which can impact network performance. Different network technologies and protocols may have varying MTU values. For example, Ethernet typically has an MTU of 1500 bytes, while IPv6 networks often use a larger MTU of 1280 bytes.

*Tip: Fragmentation occurs when a packet's size exceeds the MTU of a network segment, and the packet must be broken into smaller fragments for transmission.*

Here are some examples of common MTU values: 

| **Network Technology/Protocol** | **MTU (Bytes)**                                          |
| ------------------------------- | -------------------------------------------------------- |
| Ethernet (standard)             | 1500                                                     |
| Ethernet (jumbo frame)          | 9000                                                     |
| IPv4                            | 576                                                      |
| IPv6                            | 1280                                                     |
| Point-to-Point Protocol (PPP)   | 1500                                                     |
| Internet Service Provider (ISP) | Varies by provider, commonly 1500 or higher              |
| Virtual Private Network (VPN)   | Varies depending on the VPN technology and configuration |



**Packet Size and MTU in Data Transmission**

The Maximum Transmission Unit (MTU) plays a critical role in data transmission efficiency. Consider the impact of MTU on a file transfer:

- **Large File Transfer**: When transferring a large file over a network with a low MTU (e.g., 1500 bytes), the file may need to be divided into smaller packets. If any of these packets encounter a network segment with a lower MTU, they must be further fragmented, leading to additional overhead and potential performance degradation.
- **Optimal MTU Configuration**: To optimize the transfer, network administrators should set the MTU to match the network's characteristics. This ensures that packets are transmitted without fragmentation, minimizing overhead and reducing the risk of dropped or delayed packets.

 

## Broadcast, Multicast, and Unicast

These are three fundamental methods for addressing IPv4 network traffic:

- **Broadcast**: Broadcast traffic is sent to all devices within a broadcast domain. It's often used for tasks like ARP resolution, where a device needs to discover the MAC address of another device on the same network.
- **Multicast**: Multicast traffic is sent to a specific group of devices within a network. It's used for applications like video streaming or delivering data to multiple recipients who have expressed interest in the data.
- **Unicast**: Unicast traffic is addressed to a single destination device. It's the most common form of network communication and is used for point-to-point communication.

*Tip: Broadcast is not used in IPv6, alternative protocols such as multicast perform tasks for which broadcast was used in IPv4 more efficiently (See below).* 

 

**Real-World Applications** 

Understanding how broadcast, multicast, and unicast are used in real-world applications can provide context:

- **Broadcast**: In a local area network (LAN), when a device needs to discover network printers, it may send a broadcast message asking for responses from all printers. This ensures that the requesting device can discover and connect to the nearest available printer.
- **Multicast**: In the context of Internet Protocol (IP), multicast is used for live video streaming. Multiple users interested in the same live stream subscribe to a multicast group, and the server sends a single stream that is distributed to all subscribers efficiently.
- **Unicast**: Most everyday internet browsing, email, and file transfers use unicast. For instance, when you visit a website, your web browser sends a unicast request to the web server for the specific page you want to view.

Incorporating these real-world examples helps learners grasp the practical applications of these addressing methods.



**Broadcast Storms**

A broadcast storm is a network issue you may often hear about. Broadcast occur when broadcast packets multiply exponentially due to network loops or excessive broadcast traffic. They can severely impact network performance and lead to network instability.

The primary catalyst for broadcast storms is network loops, where a data packet, often a broadcast packet, circulates endlessly between network devices. These loops can occur unintentionally, such as when redundant network connections are not properly managed or when a device malfunctions, generating excessive broadcast traffic.

As broadcast packets traverse network loops, they get replicated at each juncture. This replication leads to a significant increase in broadcast traffic, consuming network bandwidth and causing congestion. When network devices receive multiple copies of the same broadcast packet, they may become overwhelmed and respond with their own broadcasts, exacerbating the storm.

mitigate broadcast storms and prevent network loops, network administrators rely on technologies like the Spanning Tree Protocol (STP). STP is a network protocol that operates at the data link layer (Layer 2) of the OSI model. Its primary function is to identify and disable redundant network paths, which could otherwise create network loops. STP accomplishes this by designating one switch as the root bridge and then determining the most efficient path to reach the root bridge for each network segment. It then places non-root bridges and redundant links into a blocking state, preventing loops from forming.

STP continuously monitors the network for any changes in the topology. If it detects a potential loop due to a device or link failure, it rapidly recalculates the network's spanning tree to reestablish a loop-free topology. This dynamic behaviour ensures that even in the face of network changes, the network remains resilient and loop-free.



**Subnetting and Broadcast Domains**

Subnetting is a technique used to further divide a network into smaller, more manageable segments. Each subnet constitutes its own broadcast domain, allowing for better control over network traffic and security. Subnetting also helps reduce broadcast traffic by confining it to specific subnets, preventing it from inundating the entire network.

This table provides examples of different subnet masks and their corresponding subnet ranges for a given IP address – if you need more information on subnetting just search on the library!

| **IP Address** | **Subnet Mask** | **Network Address** | **Usable IP Range**           | **Broadcast Address** |
| -------------- | --------------- | ------------------- | ----------------------------- | --------------------- |
| 192.168.1.0    | 255.255.255.0   | 192.168.1.0         | 192.168.1.1 to 192.168.1.254  | 192.168.1.255         |
| 10.0.0.0       | 255.255.255.128 | 10.0.0.0            | 10.0.0.1 to 10.0.0.126        | 10.0.0.127            |
| 172.16.0.0     | 255.255.255.240 | 172.16.0.0          | 172.16.0.1 to 172.16.0.14     | 172.16.0.15           |
| 192.168.10.0   | 255.255.255.192 | 192.168.10.0        | 192.168.10.1 to 192.168.10.62 | 192.168.10.63         |

In this table:

- **IP Address** - This column represents the base IP address for a given network.
- **Subnet Mask -** The subnet mask determines how many bits are reserved for the network portion and how many are available for host addresses.
- **Network Address -** This is the first address in the subnet, reserved for the network itself.
- **Usable IP Range -** These are the IP addresses available for assignment to devices within the subnet. The range excludes the network address and the broadcast address.
- **Broadcast Address -** This is the last address in the subnet and is used to send data to all devices in the subnet.

 

**IPv6 - Goodbye to Broadcast!**

In IPv6, the concept of broadcast, which was prevalent in IPv4, has been replaced with more efficient and targeted mechanisms due to several key reasons:

1. **Inefficient Use of Network Resources**: Broadcast packets in IPv4 were sent to all devices within a network segment, regardless of whether they needed the information. This resulted in inefficient use of network resources, as devices had to process and potentially discard irrelevant broadcast traffic.
2. **Network Scalability**: IPv6 was developed with the goal of accommodating a significantly larger number of devices and addressing the exhaustion of IPv4 addresses. Broadcasting to all devices in a segment becomes increasingly impractical as network sizes grow.
3. **Security Concerns**: Broadcast packets are inherently less secure, as they are accessible to all devices within the broadcast domain. This openness can be exploited by malicious actors for various types of attacks, such as ARP (Address Resolution Protocol) spoofing.

IPv6 introduced more refined and efficient methods of communication to replace broadcast. These include:

1. **Unicast**: Unicast communication is similar to the traditional one-to-one communication in IPv4. In IPv6, devices can send packets directly to specific destinations using unicast addresses. This approach is highly efficient as it ensures that only the intended recipient processes the packet.
2. **Multicast**: IPv6 multicast allows a single packet to be sent to a select group of devices, rather than to all devices in a segment. This targeted approach reduces network traffic and optimizes data delivery to recipients who have expressed interest in the information.
3. **Anycast**: Anycast is another mechanism in IPv6 where a packet is sent to the nearest of multiple devices with the same anycast address. It is commonly used for load balancing and high availability scenarios, such as distributing traffic to the closest content delivery server.

By replacing broadcast with these more precise communication methods, IPv6 significantly improves network efficiency, scalability, and security. Unicast, multicast, and anycast are tailored to the specific needs of modern networks, ensuring that data is delivered precisely to the devices that require it, while minimizing unnecessary network traffic and potential security risks. 

# Final Words

In this article, we looked at network traffic properties, including broadcast domains, collision domains and addressing methods (broadcast, multicast, unicast) – there’s a lot of content here, all of which you can certainly learn more about as you continue your journey – this level of detail should serve as a good introduction or refresher however. Do feel free to browse the library for more content!

 
