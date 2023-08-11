:orphan:
(port-security)=

# Port Security 

Switches are essential network devices which are primarily responsible for moving packets from one port to another – while they are busy performing this essential function, however, modern switches are also capable of inspecting packet headers to enforce security policies at the network level. Port security operates at level 2 using MAC addresses – this isn’t a *perfect* approach since mac addresses can be spoofed, but operating lower down the OSI stack also has the benefit of being able to enforce security policies (and block violating traffic) very early on in in the transmission process. Today, port security is a critical aspect of network infrastructure that focuses no only on port protection, but which is also leveraged to prevent broadcast storms and empower features such as Bridge Protocol Data Unit (BPDU) guard, loop prevention, DHCP snooping and MAC filtering.

 

## Port Security Learning Types

Port security employs different learning types to regulate network access. There are three to be familiar with:

**1. Static:** port security involves manually configuring specific MAC addresses to be allowed on a port. While this is straightforward, it lacks adaptability for dynamic environments. 

**2. Dynamic:** port security, on the other hand, permits a switch to learn MAC addresses as devices connect, automatically updating the MAC address table. This is suitable for scenarios with frequent device changes but might pose a risk if unauthorized devices are connected. 

**3. Sticky:** port security combines the best of both worlds by dynamically learning MAC addresses and then saving them in the configuration, offering resilience against reboots and improving security.

In addition to the learning type, a network engineer can configure a maximum number of mac addresses which cane be permitted to use a port (which can prevent the attachment of rogue network devices) as well as the duration for which a mac address will be saved and associated with the port. 

Port security configuration varies by device and manufacturer, although the process is usually similar. This example shows enabling port security on a Cisco switch

```
Switch(config)#interface fa0/1
Switch(config-if)#switchport port-security
Switch(config-if)#switchport port-security maximum 1
Switch(config)#interface fa0/1
Switch(config-if)#switchport port-security mac-address aaaa.bbbb.cccc

SwitchA#
%PM-4-ERR_DISABLE: psecure-violation error detected on Fa0/1, putting Fa0/1 in err-disable state
%PORT_SECURITY-2-PSECURE_VIOLATION: Security violation occurred, caused by MAC address 0090.cc0e.5023 on port FastEthernet0/1.
%LINEPROTO-5-UPDOWN: Line protocol on Interface FastEthernet0/1, changed state to down
%LINK-3-UPDOWN: Interface FastEthernet0/1, changed state to down
```

Here, we configured port security to permit one (and only one) mac address on the port - and specified that that mac address should be aaaa.bbcb.cccc - in the second block of code a device which was not aaaa.bbbb.cccc connected to the port, as a result of which the port was shut down and the device connected was blocked from communicating on the network. This configuration also stipulates that only *one* mac address (aaaa.bbcb.cccc) should be allowed to connect - the port would again be shut down if any other mac address was seen on the port. 

The action taken when a port security violation as well as weather the port will try to re-enable itself after a period of time (as opposed to having to have an administrator do this manually) can all be configured. On a Cisco switch, the available options are:

**- Shutdown:** When a port security violation occurs, the switch automatically shuts down the violating port, effectively disabling network access for the unauthorized device. The switch also sends a log and/or SNMP message to a management station to alert them to the violation.

**- Restrict:** Instead of completely shutting down the port, the switch discards the offending frames and sends a log and/or SNMP message to a management station to alert them to the violation. 

**- Protect:** The switch drops frames from unauthorized MAC addresses while still allowing other devices to transmit data. No notification is made. 



## Broadcast Storm Prevention

A broadcast storm is a disruptive network phenomenon where an excessive volume of broadcast (and sometimes multicast) traffic floods the network, overwhelming its capacity and impeding normal communication. Broadcast storms occur when a network device, such as a switch or router, continuously forwards broadcast frames - causing each device on the network to repeat and propagate these broadcasts. As the cycle repeats, network resources become saturated, leading to degraded performance, slowed data transmission, and even network outages. Broadcast storms often result from misconfigurations, network loops, or malfunctioning devices. If you study networking in any depth, you’ll certainly learn more about avoiding Broadcast storms! 

Port security addresses this concern by limiting the number of MAC addresses permitted on a given port. This limitation curbs the propagation of broadcast traffic that could lead to storms. By setting a maximum limit, network administrators ensure that a malicious or malfunctioning device cannot overwhelm the network with an excessive number of broadcasts. More advanced systems, such as storm control can also drop a specific type of traffic when more than a certain number of any one type of packet are seen on a link.



## Flood attack prevention

In the same way that broadcast storms can disrupt a network, malicious actors can also send excessive traffic onto a network as part of a deliberate denial of service attack. There are numerous types of flooding attacks which could be attempted - ping floods, SYN floods, ICMP floods (Smurf attacks), and traffic flooding can all be mitigated in part by using port security and storm control.



## Bridge Protocol Data Unit (BPDU) Guard

A Bridge Protocol Data Unit (BPDU) is a fundamental element of the Spanning Tree Protocol (STP) and its variants, which are used to prevent network loops in Ethernet networks. A BPDU is a special type of frame that network switches exchange to exchange information about the network's topology and to collectively determine the best path for forwarding traffic. BPDU frames contain information such as the sending switch's identity, priority, cost to reach the root switch, and the path cost from the sending switch to the root switch.

The primary purpose of BPDU exchange is to establish a loop-free topology by electing a root bridge and logically blocking redundant paths. The root bridge becomes the central reference point, and switches exchange BPDUs to calculate the shortest path back to the root. This calculation helps the switches identify which ports should be designated as forwarding ports (ports that can pass traffic) and which should be placed in a blocking state (ports which will not forward traffic), thereby preventing the formation of network loops that can severely disrupt network operations.

*BPDU guard* is a safety mechanism which is instrumental in maintaining network integrity. When a port unexpectedly receives BPDU frames, it triggers BPDU guard to disable the port. This precautionary measure prevents the accidental introduction of rogue switches that could lead to network loops. BPDU guard operates on ports designated as access ports, providing a crucial safeguard against accidental misconfigurations or deliberate attacks on network stability.

 

## **Dynamic Host Configuration Protocol (DHCP) Snooping**

DHCP snooping plays a pivotal role in securing IP address allocation within a network. It operates by distinguishing between trusted and untrusted ports. Trusted ports are those connected to DHCP servers, while untrusted ports are those which should not be connected to a DHCP server. If a DHCP response is received on an untrusted port, the switch can assume that it is likely to connect to rogue DHCP server. By validating DHCP responses on trusted ports and discarding unauthorized ones, DHCP snooping prevents potential IP address conflicts, unauthorized access, and potential security breaches.



## Loop Prevention

Loop prevention mechanisms are vital to preventing disruptions caused by network loops. Port security contributes to this objective by monitoring the movement of MAC addresses within the network. When a port detects a sudden surge in MAC address changes or an unusual pattern, it indicates a possible loop. To prevent such scenarios, the port can be shut down automatically, mitigating the loop's impact and maintaining network availability.

 

## Media Access Control (MAC) Filtering

MAC filtering involves permitting only specific MAC addresses to access a port, mitigating the risk of unauthorized devices gaining network access. MAC filtering is an effective approach assuming that devices are using their true MAC address – the problem is that spoofing a mac address is easily done and indeed, this is the default action for many modern devices (Especially phones). MAC address filtering can still be effective – an administrator can stipulate that MAC address spoofing be turned off when connecting to a corporate network, and opt for a “whitelist” approach to allowing devices. This would continue to ensure that only devices with permitted MAC addresses could access the network, but requires quite a lot of manual configuration to maintain. An attacker who is able to spoof a legitimate “allowed” MAC address can also still bypass this control. 

 

## Benefits of Port Security

Port security offers several advantages that contribute to a more secure and stable network environment:

**- Enhanced Security:** Port security prevents unauthorized devices from gaining network access, reducing the risk of unauthorized data access, information theft, or malicious activities.
  
**- Reduced Attack Surface:** By limiting the number of active devices on a port, port security minimizes the potential targets available to attackers, making it more challenging for them to infiltrate the network.
  
**- Improved Network Performance:** Port security helps prevent broadcast storms and network loops, ensuring better network performance and responsiveness by minimizing unnecessary traffic and disruptions.
  
**- Ease of Management:** Port security provides network administrators with granular control over connected devices. This facilitates more efficient network administration, troubleshooting, and device management.
  
**- Compliance and Regulatory Requirements:** Many industries have regulatory standards that mandate strong security practices. Port security helps organizations meet these requirements by controlling access and mitigating risks.
  
**- Protection Against Rogue Devices:** Port security prevents rogue devices from connecting to the network, reducing the likelihood of unauthorized access, data breaches, or malware propagation.

 

## Drawbacks of Port Security

While port security offers numerous benefits, it also comes with certain drawbacks that also need to be considered:

**- Complex Configuration:** Implementing and managing port security on a large scale can be complex and time-consuming. Configuring and maintaining individual port settings, especially in dynamic environments, requires careful planning and continuous oversight.
  
**- Limited Flexibility:** Port security's strict access controls can impede the flexibility needed in rapidly changing network environments. Frequent device changes or the addition of new devices may necessitate constant reconfiguration.
  
**- MAC Spoofing:** Port security primarily relies on MAC addresses for authentication, which can be susceptible to MAC spoofing attacks. Skilled attackers can forge legitimate MAC addresses to bypass port security measures.
  
**- Potential False Positives:** In certain scenarios, legitimate network changes or maintenance activities might trigger port security mechanisms, causing temporary disruptions or false alarms.
  
**- Resource Overhead:** Port security can consume network resources, including memory and processing power, especially when maintaining a large MAC address table for dynamic learning or sticky MACs.
  
**- Complex Troubleshooting:** When issues arise, diagnosing problems related to port security can be intricate and time-consuming, requiring a deep understanding of the configuration and potential interactions with other network components.

 

## Alternatives to Port Security

There are also several alternative approaches to port security, some of which could be combined for better defence in depth. 

### 802.1X Port-Based Authentication

802.1X Port-Based Authentication mandates devices to authenticate before gaining network access, significantly enhancing security by validating user or device identities through mechanisms like RADIUS (Remote Authentication Dial-In User Service). It’s possible to connect an 802.1X system to an LDAP directory which can be an excellent approach in an enterprise environment. 

### Network Access Control (NAC)

More generically, Network access control solutions enforce security policies based on device health, identity, and compliance. 802.1X Port-Based Authentication may also be a step in a broader NAC system. This approach offers dynamic and context-aware network access, making it adaptable to diverse network environments.

### VLAN Segmentation

Isolating network traffic into separate VLANs restricts communication between segments, limiting the potential impact of security breaches or unauthorized access within a particular VLAN. This approach combines very well with traditional port security to provide an additional layer of defence. 



## Physical Port Security

Physical port security is also an essential aspect of overall network protection, focusing on securing the physical access points through which devices connect to a network. It involves strategies, technologies, and practices aimed at preventing unauthorized physical access to network ports and ensuring the integrity of the network infrastructure. Physical port security is often overlooked, but, if done right, physical port security can make life very hard for a would be attacker! 

### Importance of Physical Port Security

Physical access to network ports can provide unauthorized individuals with the opportunity to compromise network security, potentially leading to data breaches, network disruptions, and unauthorized data access. Usually, we think about normal access ports in a wall which are eventually connected to a switch port – but in poorly secured environments and attacker might even be able to access a network cabinet and the all-important console port of the switch itself. As security professionals, it’s very easy to focus entirely on technical solutions – however physical access to a device is critical to consider.

*Tip: Network cabinets should always be locked and properly secured as well as subject to rigorous access control. Treat them as an extension of the central network room (because they are!).* 

 

### Physical Port Security Measures

Some example measures which can contribute to robust physical port security might include:

**- Port Locks and Covers:** Physical locks and protective covers prevent unauthorized individuals from directly connecting devices to network ports. These measures are particularly effective in areas where physical access is difficult to monitor closely.

**- Secure Cabinets and Enclosures:** Placing network equipment within locked cabinets or enclosures adds an additional layer of protection. Access to these cabinets can be restricted to authorized personnel only.

**- Video Surveillance:** Deploying video surveillance cameras in areas with network ports can deter unauthorized access attempts and provide a record of any suspicious activities.

**- Access Control:** Implementing access control mechanisms such as card-based or biometric authentication restricts physical access to authorized personnel. This ensures that only individuals with proper credentials can connect devices to network ports.

**- Physical Auditing:**  Regular physical audits of network ports and connected devices help identify unauthorized or rogue connections. Auditing also ensures that devices are properly labeled and accounted for.

**- Visitor Access Policies:**  Organizations can establish policies that regulate visitor access to networked areas. Guest devices can be connected to isolated guest networks rather than main networks to minimize potential security risks.

**- Cable Management:** Properly managing and labeling network cables reduces the likelihood of accidental or unauthorized connections. Clear cable organization also simplifies troubleshooting and maintenance.

**- Tamper Detection:** Utilizing tamper-evident stickers, seals, or sensors can help detect any unauthorized attempts to access or manipulate network ports or equipment.

  

### Challenges and Considerations

Despite its importance, physical port security poses certain challenges which are very important to consider, especially during risk management exercises.

**- Balancing Security and Convenience:** Striking a balance between stringent security measures and the convenience of authorized personnel is crucial. Overly restrictive measures can impede operational efficiency.

**- Vulnerable Remote Sites:** Remote sites with limited physical security can pose challenges. Implementing remote monitoring, security cameras, and secure enclosures can help address these vulnerabilities.

**- Physical Social Engineering:** Even with technological safeguards, individuals with malicious intent can attempt to manipulate personnel to gain unauthorized access. Training staff to recognize social engineering tactics is essential.

**- Integration with Cybersecurity:** Physical port security should be integrated with broader cybersecurity strategies. The physical layer can impact network security, and the two aspects need to be coordinated.

# Final Words

Port security (including physical port security) remains a critical component of network security, offering protection against unauthorized access and network disruptions. By employing various techniques such as port security learning types, broadcast storm prevention, BPDU guard, loop prevention, DHCP snooping, and MAC filtering, organizations can bolster their network's security posture. While port security has its benefits and drawbacks, considering alternatives like 802.1X authentication and NAC can provide additional layers of security to meet evolving network demands. As always, any form of port security is far superior to no port security at all! 
