:orphan:
(segmentation-network-properties)=

# Segmentation and interface properties 

Segmentation and interface properties in networking refer to fundamental principles and configurations that enable the efficient and organized operation of computer networks. At a high level, segmentation involves the partitioning of a network into smaller, isolated segments or virtual networks, each serving a distinct purpose. This division enhances security, manages traffic flow, and simplifies network administration. Segmentation is often achieved through technologies like VLANs (Virtual LANs) and subnetting.

On the other hand, interface properties encompass various characteristics and settings associated with network interfaces, such as those found in switches, routers, and network devices. These properties determine how devices communicate within the network. Interface properties include VLAN tagging, trunking to carry traffic for multiple VLANs over a single link, port mirroring for traffic analysis, and the configuration of PoE (Power over Ethernet) to power network devices like IP cameras and phones through Ethernet cables.

Interface properties can also involve managing MAC (Media Access Control) address tables, which associate MAC addresses with physical switch ports, ensuring accurate data forwarding. Additionally, ARP (Address Resolution Protocol) tables are crucial for mapping IP addresses to MAC addresses within a network. In this article, we explore some key aspects of these important topics.

 

## VLANs (Virtual LANs)

VLANs (Virtual LANs) are a fundamental concept in network segmentation. They allow network administrators to logically divide a physical network into multiple isolated broadcast domains or subnetworks. Each VLAN operates as if it were a separate physical network, enabling enhanced network security, traffic management, and isolation.

VLANs provide several benefits, including improved network performance, enhanced security, and simplified network management. They allow network administrators to group devices logically, regardless of their physical location, and control traffic flow between VLANs, reducing broadcast traffic. VLANS do add some complexity to the environment, but the benefits almost always outweigh this small drawback. 

VLANs are commonly used in large and medium organizations to separate departments, secure sensitive data, and isolate broadcast domains. Even in a small network, using VLANs can help to enhance security and improve the performance of the network. VLANs are also instrumental in VoIP (Voice over IP) deployments, where voice and data traffic need separation for quality of service (QoS) reasons.

 

## Trunking (802.1q)

Trunking (802.1q) is a technology used to carry traffic for multiple VLANs over a single network link, typically between switches. It involves adding a VLAN tag to each Ethernet frame, which indicates the VLAN to which the frame belongs. Trunking allows for the efficient use of network resources and simplifies VLAN deployment. Trunking has some advantages and disadvantages to consider – these include: 

**Advantages of Trunking (802.1q):**

- **Efficient Network Utilization**: Trunking enables the efficient use of network resources by consolidating multiple VLANs over a single physical link. This reduces the number of physical connections needed between switches, resulting in simplified network topology and cost savings.
- **Simplified VLAN Deployment**: Trunking simplifies VLAN deployment, making it easier to extend VLANs across multiple switches in larger networks. It allows for the seamless communication of devices in different VLANs without the need for separate physical connections.
- **Scalability**: As network requirements grow, trunking provides scalability by accommodating additional VLANs and their associated traffic. This scalability is crucial in larger enterprise networks with diverse traffic requirements.
- **Improved Network Resilience**: Trunking enhances network resilience by offering redundancy. If one trunk link fails, traffic can automatically reroute through alternate paths, minimizing network downtime.

**Disadvantages of Trunking:**

- **Complex Configuration**: Configuring and managing trunk links can be complex, especially in networks with numerous VLANs and complex traffic requirements. Mistakes in trunk configuration can lead to network issues, such as traffic leakage between VLANs or network loops.
- **Security Risks**: If not configured correctly, trunk links can potentially pose security risks. Misconfigured trunk ports might allow unauthorized access to VLANs, leading to unauthorized data access or disruptions in network security.
- **Potential for Broadcast Storms**: While trunking helps segment broadcast domains, it can also propagate broadcast traffic across VLANs if not adequately controlled. Excessive broadcast traffic can lead to network congestion and reduced performance.
- **Limited Bandwidth Sharing**: In a trunk link, all VLANs share the same bandwidth. If one VLAN generates excessive traffic, it can impact the performance of other VLANs sharing the same trunk, potentially leading to bottlenecks.
- **Vendor Compatibility**: Trunking may not always be seamlessly interoperable between different network equipment vendors. Network administrators should ensure that their switches and routers support the same trunking standards (e.g., 802.1q) to avoid compatibility issues.

Trunking is essential in scenarios where multiple VLANs need to traverse the same network segment, such as interconnecting switches in large enterprise networks or connecting routers to switches.

 

## Tagging and Untagging Ports

Tagging and untagging ports are configurations made on network switches to specify how traffic should be treated as it enters or exits a VLAN.

When traffic enters a port configured for tagging, the switch adds a VLAN tag to the frame to indicate the VLAN membership. This is used for trunk links between switches, ensuring that frames are associated with the correct VLAN on the receiving switch.

Ports configured for untagging remove the VLAN tag when traffic exits the VLAN. Devices connected to untagged ports are typically unaware of VLAN tagging, as they operate within a single VLAN.

 

## Port Mirroring

Port mirroring is a network feature that allows a switch to copy traffic from one or more source ports and send it to a destination port for analysis, monitoring, or troubleshooting. Port mirroring is valuable for network troubleshooting, security monitoring, and performance analysis. Network administrators can use it to monitor traffic for anomalies, detect security threats, or diagnose network issues – there are two main types to be familiar with:    



**SPAN (Switched Port Analyzer)**

SPAN (Switched Port Analyzer) also known as port mirroring or port monitoring, is a network feature that allows a network switch to copy traffic from one or more source ports and send it to a designated destination port for analysis, monitoring, or troubleshooting purposes. SPAN is typically employed within a single switch or within a physically close switch cluster.

SPAN is widely used for network troubleshooting, security monitoring, and performance analysis. Network administrators can use it to monitor traffic for anomalies, detect security threats, or diagnose network issues. To configure SPAN, administrators specify source ports (the ports from which traffic should be copied), a destination port (where the copied traffic should be sent), and optionally, a monitoring session type (e.g., ingress or egress traffic monitoring). 

 One limitation of SPAN is that it operates within a single switch or switch cluster, which means it may not be suitable for monitoring traffic that traverses multiple switches or is located in geographically dispersed locations.



### RSPAN (Remote SPAN)

RSPAN (Remote SPAN) is an extension of SPAN that addresses the limitations of SPAN by allowing network traffic to be monitored remotely across different switches in the network. RSPAN is particularly useful when the source and destination ports are not physically located on the same switch.

RSPAN is beneficial when monitoring network traffic in scenarios where the source and destination ports are geographically separated or when monitoring traffic that traverses multiple switches. Configuring RSPAN involves creating an RSPAN VLAN that spans multiple switches. The source ports, as well as the destination port (usually located in the same VLAN as the source ports), are designated. Traffic copied from source ports is encapsulated and transmitted over the RSPAN VLAN to the destination port. RSPAN extends the capabilities of traditional SPAN by allowing network administrators to monitor traffic across larger and more complex network infrastructures. On the other hand, implementing RSPAN may require more configuration and planning compared to standard SPAN, as it involves setting up VLANs and coordinating across multiple switches.

 

## Switching Loops and Spanning Tree

Switching loops occur when there are redundant links in a network, potentially causing broadcast storms and network instability. The Spanning Tree Protocol (STP) is a network protocol designed to prevent switching loops by identifying and disabling redundant paths while maintaining network redundancy for failover.

Switching loops, also known as network loops, occur when there are multiple paths between switches or segments in a network. These loops can form in various ways – commonly, they result from:

- **Redundant Links**: Network administrators often introduce redundancy by connecting multiple paths between switches to enhance network reliability. However, if not properly managed, these redundant links can create loops.

- **Broadcast Storms**: When a switch receives broadcast traffic, it typically forwards it to all ports except the one it was received on. If multiple paths exist between switches and a broadcast packet circulates endlessly due to a loop, it can lead to a broadcast storm.

  

Switching loops can have severe consequences for network performance and stability, they include:

1. **Broadcast Storms**: As broadcast packets multiply within the loop, they consume network bandwidth and cause congestion, leading to a broadcast storm. This can result in network slowdowns, packet loss, and service disruptions.

2. **MAC Address Table Instability**: Switches may continually update their MAC address tables due to rapidly changing looped traffic, leading to excessive processing overhead.

3. **Unpredictable Behavior**: Loops can cause unpredictable and erratic network behavior, making it challenging for network administrators to diagnose and resolve issues.

   

**STP's Role in Loop Prevention**

Spanning Tree Protocol (STP) is a network protocol designed to prevent switching loops while maintaining network redundancy. Here's how it works:

1. **Root Bridge Election**: STP selects one switch as the "root bridge" for the network. All other switches determine the shortest path to the root bridge and disable redundant links to prevent loops.

2. **Loop-Free Topology**: STP calculates and maintains a loop-free topology by selectively blocking certain ports on switches. These blocked ports prevent traffic from traversing redundant links and causing loops.

3. **Loop Detection and Recovery**: If network changes, such as link failures or additions, occur, STP rapidly recalculates the network's spanning tree to reestablish a loop-free topology. This dynamic behavior ensures network resilience.

   

**Improvements to STP - RSTP**

Rapid Spanning Tree Protocol (RSTP) is an enhancement of STP designed to provide faster convergence and improved network resiliency. It provides:

1. **Faster Convergence**: RSTP offers quicker network convergence by reducing the time it takes to transition a port from blocking to forwarding state when a failure or network change occurs.
2. **Backward Compatibility**: RSTP is backward compatible with STP, allowing it to coexist with older STP devices in the same network. This makes it a suitable upgrade path for existing networks.
3. **Topology Changes**: RSTP introduces "edge ports" that immediately transition to the forwarding state when a device is connected. This eliminates delays caused by unnecessary STP calculations for end devices.

 

## PoE and PoE+ (802.3af, 802.3at)

PoE (Power over Ethernet) and PoE+ (802.3af and 802.3at) are technologies that enable the transmission of electrical power alongside data over Ethernet cables. These technologies simplify the deployment of network devices like IP cameras, phones, and wireless access points by eliminating the need for separate power sources.

There are two versions of PoE – Regular PoE provides up to 15.4 watts of power per port, while PoE+ offers up to 30 watts. PoE+ is suitable for devices with higher power requirements.

Here's an example of what the output of the `show power inline` command on a Cisco switch or router with Power over Ethernet (PoE) capabilities might look like:

```shell
Switch# show power inline
Available:370.0(w)  Used:30.0(w)  Remaining:340.0(w)

Interface Admin  Oper       Power   Device              Class Max
                            (Watts)
--------- ------ ---------- ------- ------------------- ----- ----
Gi0/1     auto   off        0.0     n/a                 n/a   15.4
Gi0/2     auto   off        0.0     n/a                 n/a   15.4
Gi0/3     auto   on         6.5     IP Phone            3     15.4
Gi0/4     auto   off        0.0     n/a                 n/a   15.4
Gi0/5     auto   off        0.0     n/a                 n/a   15.4
Gi0/6     auto   off        0.0     n/a                 n/a   15.4
Gi0/7     auto   on         7.0     IP Camera           2     15.4
Gi0/8     auto   off        0.0     n/a                 n/a   15.4
```

In this example output:

- `Available` shows the total available power budget for PoE on the device (in this case, 370.0 watts).
- `Used` displays the amount of power currently being used by powered devices (in this case, 30.0 watts).
- `Remaining` indicates the remaining power budget (in this case, 340.0 watts).
- The table below provides information about individual Ethernet interfaces:
  - `Interface` lists the interface name (e.g., Gi0/1, Gi0/2).
  - `Admin` shows the administrative PoE status (auto means PoE is enabled).
  - `Oper` indicates the operational PoE status (on means PoE is active).
  - `Power` displays the amount of power allocated to the device connected to the interface (in watts).
  - `Device` identifies the type of powered device (e.g., IP Phone, IP Camera).
  - `Class` specifies the PoE class of the device.
  - `Max` represents the maximum power available for the interface.



## DMZ (Demilitarized Zone)

A DMZ is a network segment that is isolated from the internal network but partially accessible from the external network, such as the internet. It is used to host public-facing servers like web servers or email servers, providing an additional layer of security by segregating them from the internal network.

DMZs are a crucial security measure as they minimize the risk of external attacks on internal systems. Network security appliances, such as firewalls, are often placed at the DMZ perimeter to filter and protect incoming traffic.

*Tip: Search the library for more information on DMZ's in a security context!*



## MAC Address Table

A MAC (Media Access Control) address table, also known as a CAM (Content-Addressable Memory) table, is a database maintained by network switches to associate MAC addresses with their corresponding physical switch ports. This table helps switches forward frames to the correct destination ports within the LAN. Modern switches dynamically populate the MAC address table by learning the MAC addresses of devices connected to their ports as frames pass through. Here's an example from a Cisco switch:

```shell
Switch# show mac-address-table
          Mac Address Table
-------------------------------------------

Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
  1     0180.c200.0000    STATIC      CPU
  1     0180.c200.0001    STATIC      CPU
  1     0180.c200.0002    STATIC      CPU
  10    0012.3456.7890    DYNAMIC     Fa0/1
  10    00a1.b2c3.d4e5    DYNAMIC     Fa0/2
  20    00ab.cdef.0123    DYNAMIC     Fa0/3
  20    00fe.dcba.9876    DYNAMIC     Fa0/4
  30    00aa.bbbb.cccc    STATIC      Gi1/1
  30    00bb.dddd.eeee    DYNAMIC     Gi1/2
```

In this example:

- `Vlan` indicates the VLAN ID associated with the MAC address entry.
- `Mac Address` displays the MAC address learned or configured in the MAC address table.
- `Type` specifies the type of MAC address entry, which can be DYNAMIC (learned dynamically) or STATIC (manually configured).
- `Ports` lists the ports associated with the MAC address entry. For dynamic entries, this indicates the port through which the MAC address was learned.
- Entries like `0180.c200.0000`, `0180.c200.0001`, and `0180.c200.0002` are default MAC address entries that typically represent various multicast and broadcast functions within the router or switch.
- `CPU` in the "Ports" column indicates that these entries are associated with the router or switch's internal CPU for handling specific types of traffic.





## ARP Table

An ARP (Address Resolution Protocol) table is a database used by network devices to map IP addresses to MAC addresses within a local network. ARP is essential for devices to determine how to encapsulate data for delivery within the same network. ARP tables are dynamic and are updated as devices communicate on the network. They help devices make efficient forwarding decisions by associating IP addresses with MAC addresses. Network devices, hosts, servers and most other computer systems maintain an ARP table of some sort.

Understanding these segmentation and interface properties is crucial for network administrators, as they play a vital role in network design, management, and optimization. Each of these components contributes to the efficient operation and security of modern computer networks.

In this example, we view the ARP table on a Cisco router

```shell
Router> enable
Router# show arp
Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  192.168.1.1              0   ab:cd:ef:01:23:45  ARPA   GigabitEthernet0/0
Internet  192.168.1.10             4   00:12:34:56:78:90  ARPA   GigabitEthernet0/1
Internet  192.168.1.20             -   aa:bb:cc:dd:ee:ff  ARPA   GigabitEthernet0/2
Internet  192.168.1.100           10   ff:ee:dd:cc:bb:aa  ARPA   GigabitEthernet0/3
```

In this example:

- `Protocol` indicates the network protocol being used (Internet for IPv4).
- `Address` displays the IP addresses that the router has ARP entries for.
- `Age (min)` shows how long the ARP entry has been in the table, in minutes.
- `Hardware Addr` represents the MAC (Media Access Control) address associated with the IP address.
- `Type` specifies the address resolution protocol type (ARPA for ARP).
- `Interface` identifies the network interface through which the ARP entry was learned.

 
