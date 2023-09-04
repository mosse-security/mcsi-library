:orphan:
(public-vs-private-addressing)=

 

# Public vs Private Addressing 

IPv4 (Internet Protocol version 4) is the foundation of modern internet communication. It uses 32-bit addresses to identify devices on a network. However, with the exponential growth of the internet and connected devices, the depletion of IPv4 addresses became a significant issue. To address this problem, various solutions, including private addressing, were proposed.



## IPv4  - Quick Review

IPv4 addresses are still the most commonly used addresses used globally – and usually still the addresses of choice within private networks. Although this is now starting to change as IPV6 becomes more popular, IPv4 will be with us for a long time yet! IPv4 addresses are typically represented in four octets separated by periods, like 192.168.1.1. Each octet can have values from 0 to 255 – which means that the entire address space allows for approximately 4.3 billion unique addresses.

 

## The Problem: Depletion of IPv4 Addresses

While 4.3 billion unique addresses seem like an awful lot (and seemed like an awful lot more back in 1981 when ipv4 was standardised!) it really isn't! - With approximately 7.8 billion people on Earth and only about 4.3 billion unique IPv4 addresses available, IPv4 provides less than one unique address per person. As the interntet grew exponentially it soon became clear this would be an issue. 

To further complicate the issue, initially at least, the assignment of IPv4 addresses was a relatively unregulated process, which led to inefficient allocation practices. Many companies and organizations were granted disproportionately large blocks of IPv4 addresses, often much more than they actually needed. This inequitable distribution resulted in a scarcity of available addresses for others, including smaller businesses, emerging internet service providers, and new entrants into the online world. As the demand for IP addresses surged with the rapid growth of the internet and the proliferation of connected devices, this imbalance became increasingly unsustainable, highlighting the need for more structured and equitable address allocation mechanisms like the ones eventually established in the form of RFC 1918 private addressing and other address conservation strategies.



## Proposed Solutions

By the end of the 1990’s it was clear that IPv4 Addresses would quickly run out – various solutions were therefore quickly proposed to stop the lack of addresses becoming a major hindrance to the further growth of the internet. Some of the options included:

- **IPv6 Adoption –** Although IPv6 is only now starting to gain considerable traction it was actually fully standardised by 1998. IPv6 uses 128-bit addresses, providing an astronomical number of unique addresses, making address scarcity essentially a non-issue. With approximately 7.8 billion people on Earth, IPv6 offers approximately 340 undecillion unique addresses. To put it in perspective, that's more than enough to allocate billions of unique addresses to every person on the planet, with an abundance of addresses left over for other devices and purposes. IPv6's address space is so vast that it is virtually limitless for practical purposes.
- **Private Addressing -** Proposed in RFC 1918, private addressing is a crucial solution that enables organizations to use a block of designated non-routable IP addresses within their internal networks. By introducing private addressing, the requirement for IPv4 addresses was hugely reduced – prior to the implementation of private addresses a glablly routable ipv4 address was required for each device. 
- **Class E Addresses -** Originally, IPv4 had five classes of addresses (A, B, C, D, and E). Class E addresses (240.0.0.0 to 255.255.255.255) were reserved for experimental purposes. Some early attempts to alleviate address depletion involved repurposing Class E addresses for private use. However, this approach was not widely adopted or standardized.
- **Variable Length Subnet Masking (VLSM) -** VLSM is a technique that allows more efficient allocation of IP addresses by using subnets of different sizes within a single address space. While VLSM is a valuable network management tool, it does not create new addresses and is not a direct solution to address depletion – it did however make it more possible to manage the remaining IPv4 address space.
- **Classless Inter-Domain Routing (CIDR) -** CIDR was introduced to improve the allocation of IP addresses by allowing the creation of smaller subnets. It is a more flexible addressing scheme that helps optimize address utilization, but it does not create new addresses.
- **Network Address Translation (NAT):** NAT was a significant solution that gained popularity before RFC 1918 private addressing. NAT allows multiple devices within a private network to share a single public IPv4 address. This approach effectively extends the life of the IPv4 address space by enabling many devices to communicate through a smaller pool of public addresses. Today, NAT is usually combined with private addressing to significantly reduce the number of IPv4 addresses actually required. 

 

## Private Addresses (RFC 1918)

As we have seen above, private addressing as defined in RFC 1918 therefore defines address ranges reserved for private use. These addresses are *not* routable on the public internet, making them ideal for internal network use. There are three primary private address ranges specified by RFC 1918, and you’re almost certainly familiar with them - they are:

1. **Class A (10.0.0.0 - 10.255.255.255):** This range provides 16,777,216 private IP addresses and is commonly used in large enterprises.
2. **Class B (172.16.0.0 - 172.31.255.255):** This range offers 1,048,576 private IP addresses and is often used in medium-sized networks.
3. **Class C (192.168.0.0 - 192.168.255.255):** This range provides 65,536 private IP addresses and is popular in small home networks and businesses.

These private addresses can be freely used within an organization's network without any conflicts with public addresses. In modern deployments, NAT is typically used to allow these devices to access the internet through a single public IPv4 address.

When a device within the private network initiates an outgoing internet connection, the NAT device (usually a router or firewall) assigns a unique port number to the communication session. This combination of the private IP address, port number, and the public IP address forms a unique translation entry in the NAT table. As data packets from the internal device traverse the NAT device, the device rewrites the source address of these packets to match the public IP address and port number assigned by NAT. When responses from the internet arrive, the NAT device uses the NAT table to determine which internal device the response should be forwarded to, translating the destination address back to the private IP address and port number.

 

## Public addresses

Public addresses are therefore all addresses that are not part of the private address ranges defined in RFC 1918. These addresses are globally unique and routable on the public internet. Unlike private addresses, which are used for internal networks and are not accessible directly from the internet, public addresses are assigned to devices and servers that need to be reachable from anywhere on the global network. Public addresses are essential for internet-facing services, websites, email servers, and any device or service that requires direct communication over the internet. They form the backbone of the internet's addressing system, enabling seamless connectivity and data exchange between devices worldwide.

 

## Private addressing – A security feature? 

As we have seen in this article, private addressing was never intended to be a security feature, nor was NAT or any of the other solutions proposed to overcome the depletion of the IPv4 address space. This being said, private addressing *can* be considered a security feature in networking for several reasons. It can provide: 

1. **Network Isolation -** Private addressing allows organizations to create isolated, internal networks with non-routable IP addresses. This isolation provides a level of inherent security by making it more challenging for external threats to directly access devices within the private network. It acts as a kind of "security by obscurity."
2. **Intrusion Prevention -** With private addressing, external entities cannot easily discern the internal network's structure or the number of devices connected. This makes it more challenging for attackers to target specific devices, reducing the risk of intrusion.
3. **Access Control -** Private networks often use Network Address Translation (NAT) in conjunction with private addressing. NAT can restrict inbound traffic to only responses related to outbound connections initiated by internal devices. This access control limits the exposure of internal resources to unsolicited external access attempts.
4. **Reduced Attack Surface -** By using private addresses, organizations can segment their networks into smaller, manageable subnets. This segmentation minimizes the attack surface and the potential impact of security breaches. If one subnet is compromised, it doesn't necessarily compromise the entire network.
5. **Logging and Monitoring -** Private addressing allows network administrators to focus their security efforts on monitoring and securing the perimeter where the network connects to the public internet. This centralized approach simplifies security management and allows for more effective monitoring of potential threats.
6. **IP Spoofing Mitigation-** Private addressing helps prevent IP address spoofing attacks. Devices on the internet cannot (or at least should not) impersonate a private IP address, making it harder for attackers to manipulate network traffic. It’s common to see edge routers with ACL’s designed to block RFC 1918 private addresses from entering or exiting the network as they should never do this!  

```
access-list 100 deny ip 10.0.0.0 0.255.255.255 any
access-list 100 deny ip 172.16.0.0 0.15.255.255 any
access-list 100 deny ip 192.168.0.0 0.0.255.255 any
```

*An example of an access list to identify RFC1918 traffic*

# Final words

Today, private addresses are usable only within a private network. Public addresses are globally routable. While private addressing contributes to network security, it's important to note that it is just one component of a comprehensive security strategy and the feature was not designed specifically with security in mind. Organizations should complement private addressing with other security measures such as firewalls, intrusion detection systems, encryption, access controls, and regular security audits to maximise their defences. 
