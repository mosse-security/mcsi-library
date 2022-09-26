:orphan:
(basic-components-of-a-secure-network-architecture-in-the-cloud)=

# Basic Components of a Secure Network Architecture in the Cloud

Cloud apps will need to operate in a secure network architecture. Before we can protect our applications, we must first grasp the primary networking techniques we employ in the cloud. In this blog, we are going to discuss primary networking concepts in a secure cloud data center.

## A virtual local area network (VLAN)

A virtual local area network is a logical method of separating specific sections or sectors of a network, even though the computers are interconnected physically. A VLAN's nodes or members can establish a connection directly only with other VLAN members.

## Dynamic Host Configuration Protocol (DHCP)

We may allocate IP addresses in two ways: statically or dynamically. When allocating IP addresses to devices on a network, we can use a fixed, unique address for each device. This method is known as static addressing.

There is also another method of IP allocation which is known as dynamic addressing. An alternative to static addressing is temporarily allocating an IP address to a certain machine. We utilize the Dynamic Host Configuration Protocol for this purpose.

## How does a DHCP server allocate IP address?

A DHCP server chooses an IP address from the available address pool, allocates it to a specific device, and keeps track of which devices have which addresses. When the address is no longer in use, the device returns it to the pool of IP addresses, and the DHCP server can assign it to other devices later if they need.

## Domain Name System (DNS)

A Domain Name System is a protocol that allows devices to connect to servers, and machines over the Internet utilizing name resolutions of IP addresses.

When there is a change in how a domain name corresponds to a particular Ip address, the modification is registered at the top domain of the DNS hierarchy and then employed by all other DNS servers. Whenever you wish to interact with some other machine, your device makes a query to another machine, which is usually your ISP to obtain the right information.

## Virtual Private Network (VPN)

Although the communication is over an insecure channel such as the Internet, a distant user can be permitted access to another system. This is performed by utilizing a virtual private network.

A VPN channel encapsulates communications nesting protocols within another. The communication is therefore encrypted to prevent middlemen from monitoring the conversation.

## Summary

We need to run cloud-based applications or software in a securely designed network. In this blog, we have learned fundamental networking principles for designing safe environments in the cloud such as VLAN, DHCP, DNS, and VPN.

:::{seealso}
Want to learn practical cloud skills? Enroll in MCSI’s - [MCSF Cloud Services Fundamentals ](https://www.mosse-institute.com/certifications/mcsf-cloud-services-fundamentals.html)
:::
