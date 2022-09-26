:orphan:
(block-malicious-packets-with-packet-filtering-firewalls)=

# Block Malicious Packets with Packet Filtering Firewalls

Packet filtering firewalls are an important part of network security. They can block malicious packets from entering the network, and can also help to identify and track down the source of attacks. packet filtering firewalls work by examining each packet that comes into the network and comparing it to a set of rules. In the simple terms, if the packet matches a rule, it is allowed through, if it does not match a rule, it is blocked. In this blog, we are going to explore the network layer firewall mechanism and its pros and cons.

## What is a firewall?

The most common technology used to defend an internal network from outside attackers is a firewall. When correctly designed, a firewall prevents unauthorized access to an internal network and prevents internal network users from accessing potentially harmful external networks or ports. There are three types of firewalls:

- Packet filtering
- Application layer gateways
- Stateful inspection firewalls

A packet-filtering firewall operates at the network level of the Open Systems OSI. It either permits or refuses packets as quickly as possible.

## Network layer firewalls

This type of firewall is also referred to as a packet-filtering firewall. It operates at the OSI model's network layer. You can design it in a way to deny or allow access to set ports or specific IP addresses. When designing packet-filtering firewall rules, you can follow these two policies:

**allow by default**: Allow by default passes all communications across the firewall excluding explicitly denied traffic.

**deny by default**: Deny by default prevents any traffic from flowing through the firewall, excluding specifically permitted communications.

### How does a firewall filters?

A firewall operates in both ways:

- It keeps invaders under control.
- It restricts internal access to an external network.

By blocking access to specific external ports in the firewall settings, you may help avoid programs from endangering the internal network.

## What is a port?

A port is a logical point at which network communications begin and stop. We can categorize ports into 3 groups:

- System or well-known ports 0–1023
- Ports 1024–49151 are either the user or registered ports.
- Ephemeral/private/dynamic ports 49152–65535

### Port security best practices

- You may want to allow traffic only in the 0-1023 range through the firewall.
- You should consider any application requesting network communication outside of the 0-1023 range as a suspect.
- Exclude specific applications, if there are any, as an opt-out, not a rule.
- Stick to the best practice of refusing by default. When applying this policy, you can reference a list of popular services that operate on computers, together with their well-known ports, to open the precise port required for the program to function.
- Only allow the ports required for specific requirements, when necessary.
- Determine which port number any specified program is utilizing.

## Packet filtering pros and cons

- Packet filtering is very quick since it merely examines the header of a packet and checks a short set of rules.
- Packet filtering is convenient. Rules are simple to establish, and ports may be opened and closed rapidly.
- Packet-filtering firewalls are invisible to devices in the network.

Along with these benefits, packet filtering has two primary disadvantages:

- A port has only two states: open or closed. You can’t open and close a port at some point in the process.
- Packet filtering firewalls can’t comprehend the contents of any packet. It can only understand the header. You can exploit a system with a malicious payload as long as the header is valid.
- Network layer firewalls inspect IP packets’ source and destination IP addresses, and source and destination port.
- Ports for some network services need to be either closed or open. With packet filtering firewalls, you need to decide between using these types of services (such as rsh, rcp UNIX commands) and not utilizing them.

### How does a packet-filtering firewall work?

**1-)** Connection starts at the client-side and goes down to the bottom layer of the OSI model, which is a physical layer.

**2-)** The packet is subsequently transferred to the packet-filtering system.

**3-)** The firewall starts inspecting only the header of the transmitted packet.

**4-)** If the packet is intended for an allowed port on the server-side, the firewall routes the packet to the server from the bottom to the top which is the application layer.

## Summary

A packet filtering firewall is a network security system tool that filters and blocks packets based on their header. It is also called a packet filter or simply a firewall. You can configure them to allow or deny packets based on their source, destination, port number, or protocol type.

Although there is not much logic behind the scenes packet-filtering firewalls help you protect your network in various appliances such as setting up a DMZ or limiting all access to the bare minimum to help with your security needs. Whether this kind of firewall is your choice, keep your network always secure.

:::{seealso}
Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)
:::
