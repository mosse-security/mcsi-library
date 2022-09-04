:orphan:
(understanding-the-different-types-of-scan-you-can-perform-with-nmap)=
# Understanding the different types of scan you can perform with Nmap
 

Port scanning is the method of enumerating open ports and services by delivering a series of messages. Port scanners identify active hosts and scan their ports by manipulating transport layer protocol flags. Administrators and users may accidentally keep unnecessary open ports on their computers. An attacker can take advantage of such open ports for malicious purposes.

A port number provided within the transport layer protocol header (TCP or UDP) indicates which upper-layer protocol should receive the data contained inside the packet. The port numbers range from 0 to 65,535 and these are split into three separate groups, Well-known ports range from `0 - to 1,023`, and Registered ports range from `1,024 - to 49,151`. Dynamic and/or private ports range from `49,152 - 65,535`.

Some of the most common ports are ``Port 21 TCP - FTP`` - file transfer protocol. `Port 22 TCP - SSH` - secure shell for secure logins `Port 23 TCP - telnet` - Unencrypted text communications.` Port 53 UDP - DNS` - Domain name system for resolving the IP address. `Port 80 TCP - HTTP` - world wide web.

*Different types of port scanning methods:*

## Full connect Scan

This type of scan attempts to scan all 65,356 ports at once. The method used by the scanner to know whether a port is open or closed is similar to that of a three-way handshake, Where the client sends an `SYN` packet, the receiver acknowledges an `SYN+ACK` packet, and The client then acknowledges the `SYN+ACK` message with an ACK packet, completing the connection. By delivering the `RST` packet, the scanner terminates the connection. This type of scan is the easiest to detect and is logged by firewalls.

`nmap -T4 -sT Your_IP_Address`

## Stealth Scan

A stealth scan only sends `SYN` packets to ports to determine whether the port is open or closed. It terminates the TCP connection between the client and server before the three-way handshake process is completed. This scan supplies a single packet and expects a single reply. Because there is no connection to be made, attackers utilize this approach to bypass firewalls and hide their scans.

A client sends a single `SYN` packet to the server on an appropriate port. The server responds with an `SYN/ACK` message if the port is open. If the port is closed, the server responds with an `RST` packet. Before attempting to create a connection, the client sends the `RST` packet to close the connection.

`nmap -sS -P0 Your_IP_Address`

## XMAS Scan

The Xmas scan is an Inverse TCP scan that includes the `FIN`, `PUSH`, and `URG` flags. If the target system has opened a port, the attacker will receive no response. The attacker will receive an `RST` response if the remote system has a closed port. This type of scan will only work on RFC 793-compliant TCP/IP implementations and will not work on any Windows version.

`nmap -sX -T2 Your_IP_Address`

## ACK Probe Scan

In this scan, the received `RST` packet headers are analyzed to check whether the port is open by sending TCP probe packets to the remote machine with the `ACK` flag set. If the TTL value of the `RST` packet is less than 64, the port is open. If the window value of an `RST` packet on a given port is greater than zero, the port is open. This type of scan is extremely stealthy and avoids many IDS and logging systems.

`nmap -sA -T4 Your_IP_Address`


## Final words

Port scanning provides the attacker with a variety of useful information, including IP addresses, hostnames, open ports, and services running on ports. The following are some port scanning countermeasures.

- Configure firewall and intrusion detection (IDS) rules to identify and block probes.
- Ensure that the firmware on the router, IDS, and firewall is up to date with the most recent releases/versions.
- Unwanted services on the ports should be blocked, and service versions should be updated.

> **Looking to expand your knowledge of penetration testing? Check out our online course, [MPT - Certified Penetration Tester](https://www.mosse-institute.com/certifications/mpt-certified-penetration-tester.html). In this course, you'll learn about the different aspects of penetration testing and how to put them into practice.**