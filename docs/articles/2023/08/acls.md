:orphan:
(acls)=

# Access Control Lists (ACLs)

Access Control Lists (ACLs) are a fundamental security mechanism used to control and manage network traffic. Fundamentally, ACLs are sets of rules or filters that define what traffic is allowed or denied to pass through a network device, such as a router or a firewall. They play a vital role in securing networks by enforcing policies that regulate the flow of data and restrict unauthorized access to network resources.

## How ACLs Work

ACLs operate based on the source and destination addresses and other specific criteria of network traffic. When a packet arrives at a network device, such as a router, the device examines the packet against the ACL rules to determine whether the packet should be allowed or denied. If a packet matches a rule in the ACL, the device applies the corresponding action defined in the rule. If the device reaches the end of the ACL, and no match is found, the device will follow a default behaviour, which is typically either allowing or denying the packet.

*Tip: On most systems, all ACLs include an “implicit deny” statement – often this is not shown by the system, so for a default behaviour of “allow” it’s necessary to insert a “permit all” statement as the last entry in your ACL. This has the effect of matching all traffic before the ACL reaches the implicit denial.* 

## Access Control Entries

Access control lists are themselves made up of Access Control Entries. Each line in an ACL is an ACE. 

The specifics of an ACE depend on the system and its function, but in general, each ACE will consist of the following components:

1. **Rule Sequence Number -** An identifier assigned to each rule, used to determine the order in which rules are evaluated. Lower sequence numbers are processed first.
   
2. **Source Address -**  The source IP address or range of addresses from which the packet originates.
   
3. **Destination Address -**  The destination IP address or range of addresses to which the packet is being sent.
   
4. **Protocol -**  The network protocol used in the packet, such as TCP, UDP, ICMP, etc.
   
5. **Source Port -**  For TCP and UDP traffic, the source port number associated with the packet.
   
6. **Destination Port -**  For TCP and UDP traffic, the destination port number associated with the packet.
   
7. **Action -**  The action to be taken when a packet matches the rule, typically "permit" (allow) or "deny" (block).

## Types of ACLs

There are two main types of ACLs – standard and extended. Standard ACLs were the original implementation, with Extended ACLs being added later to facilitate additional features. 

Standard ACLs use only the source IP address for filtering. They are simple to configure but provide limited granularity. Standard ACLs are best used when you need to control access based on the source IP address.

Extended ACLs use multiple criteria for filtering, including source and destination IP addresses, protocols, and port numbers. Extended ACLs offer more granular control over network traffic and are used for most applications today. 

*Tip: If you are studying networking in more detail, ACL’s are worth spending some time learning about – they will be used in almost all advanced areas of networking!* 

## Inbound and Outbound ACLs

ACLs can be applied to both inbound and outbound traffic on a network interface. The placement of the ACL determines which direction of traffic it will affect.

Inbound ACLs are applied to traffic entering the interface, such as traffic arriving from the internet to a router's WAN interface or from a user's device to a switch's port.

Outbound ACLs, on the other hand, are applied to traffic leaving the interface, such as traffic going from a router's LAN interface to the internet or from a server's interface to the internal network.

## ACL Processing

It’s important to understand the way that an ACL will be processed in order for it to have the desired impact. 

When a packet arrives at a network device, it is compared against each ACL rule in sequence until a match is found. The device evaluates the packet against the rules based on the rule sequence number – this is to say the ACL is read from the top down. Once a match is found, the corresponding action is applied, and no further evaluation takes place. If no rule matches the packet, the device follows the default behaviour, which is typically to deny the packet.

### An Example Scenario

Let's consider a simple ACL scenario for a router – we have to ACE’s on our ACL:

**Rule 10 (Standard ACL):** Permit traffic from a specific source IP address (192.168.1.10) to any destination.

**Rule 20 (Extended ACL):** Deny all traffic from a specific source IP address (192.168.1.20) to a specific destination IP address (10.10.10.5) on TCP port 80.

Now, suppose a packet arrives at the router with the source IP address 192.168.1.10 and the destination IP address 10.10.10.5 on TCP port 80:

The router first evaluates the packet against Rule 10. As the source IP address (192.168.1.10) matches the rule, the router permits the packet to continue its journey without further evaluation. The packet is allowed to pass through the router. 

If the packet had a source IP address of 192.168.1.20 and a destination IP address of 10.10.10.5 on TCP port 80, the router would match Rule 20. Since Rule 20 specifies to deny such traffic, the router would block the packet, and it would not pass through the router.

If a packet had matched neither of the ACL it would have been dropped, since the final entry on the ACL is the implicit deny. 

### A Real Configuration 

Below is an example ACL configuration from a Cisco Router – this is a common ACL configuration which permits TCP traffic with destination port values that match WWW (port 80), Telnet (port 23), SMTP (port 25), POP3 (port 110), FTP (port 21), or FTP data (port 20).  You might find an ACL like this protecting a subnet with web servers and email servers. Notice an implicit deny all clause at the end of an ACL denies all other traffic, which does not match the permit clauses.

```
hostname R1
!
interface ethernet0
 ip access-group 102 in
!
access-list 102 permit tcp any any eq www
access-list 102 permit tcp any any eq telnet
access-list 102 permit tcp any any eq smtp
access-list 102 permit tcp any any eq pop3
access-list 102 permit tcp any any eq 21
access-list 102 permit tcp any any eq 20
```

Note the `ip access-group 102 in` command applied to the ethernet0 interface, this tells the router to apply access-list 102 in the "in" direction. 

## Best Practices for Using ACLs

When working with ACLs, it's advisable to consider the following best practices:

- Only allow the necessary traffic and deny everything else. Follow the principle of least privilege to minimize attack surfaces.
  
- Arrange ACL rules in the correct order, with more specific rules preceding general rules (Remember, once a match is found, processing stops!)
  
- Always test ACLs in a controlled environment and validate their behaviour before deploying them in a production network.
  
- Document the purpose and logic of each ACL rule for easy reference and troubleshooting.
  
- Periodically review and update ACLs to accommodate changes in network requirements and security policies.

*Tip: When writing ACLs, do not use concurrent sequence numbers (ID's) - rather, leave a gap so that you can insert rules in the future if need be. Do not use the numbers 1,2,3 and 4, rather opt for 5,10,15 and 20.* 

## Final Words

Access Control Lists are an essential tool in network security that allows administrators to enforce security policies, control network traffic, and protect critical resources from unauthorized access. By carefully designing and implementing ACLs, organizations can enhance the security posture of their networks and safeguard against potential cyber threats.