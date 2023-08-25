:orphan:
(network-tools)=

# Common Network Tools

Network reconnaissance and discovery are essential processes in the realm of cybersecurity and networking. They involve the systematic exploration and gathering of information about a target network, its devices, and their interconnections. Understanding these processes is crucial for network administrators, security professionals, and anyone interested in comprehending the anatomy of computer networks. This article delves into various tools and commands commonly used for network reconnaissance and discovery, shedding light on their functionalities and significance.

## Ping

**Ping** is a basic utility that tests the reachability of a host (device) in an IP network. It operates by sending an Internet Control Message Protocol (ICMP) Echo Request to the target host and waiting for an Echo Reply. If the host responds, it indicates that the host is online and reachable.

Example:
```bash
ping 192.168.1.1
```
Sample Output:
```
Pinging 192.168.1.1 with 32 bytes of data:
Reply from 192.168.1.1: bytes=32 time<1ms TTL=64
Reply from 192.168.1.1: bytes=32 time<1ms TTL=64
Reply from 192.168.1.1: bytes=32 time<1ms TTL=64
Reply from 192.168.1.1: bytes=32 time<1ms TTL=64

Ping statistics for 192.168.1.1:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 0ms, Average = 0ms
```

## Ipconfig

**Ipconfig** (Windows) or **ifconfig** (Unix-like systems) is a command-line tool that displays the IP configuration of network interfaces on a host. It provides information about the IP address, subnet mask, default gateway, and other relevant network details.

Example:
```bash
ipconfig /all (on Windows)
ifconfig (on Linux)
```
Sample Output (Windows):
```
Ethernet adapter Local Area Connection:
   Connection-specific DNS Suffix  . : example.com
   IPv4 Address. . . . . . . . . . . : 192.168.1.2
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1
```

## Arp

**ARP** (Address Resolution Protocol) resolves IP addresses to MAC addresses in a local network. It maps an IP address to a physical hardware address, enabling devices to communicate at the data link layer.

Example:
```bash
arp -a
```
Sample Output:
```
Interface: 192.168.1.2 --- 0x7
  Internet Address      Physical Address      Type
  192.168.1.1           00-11-22-33-44-55     dynamic
  192.168.1.10          0a-1b-2c-3d-4e-5f     dynamic
```

## Netstat

**Netstat** (Network Statistics) is a command-line utility that provides information about active network connections, listening ports, routing tables, interface statistics, masquerade connections, and more. It's useful for diagnosing network-related issues and monitoring network activities.

Example:
```bash
netstat -an
```
Sample Output:
```
Proto  Local Address          Foreign Address        State
TCP    192.168.1.2:56789      151.101.65.69:443     ESTABLISHED
TCP    192.168.1.2:3389       192.168.1.10:51234    TIME_WAIT
UDP    0.0.0.0:68             0.0.0.0:0
```

## Route

The **route** command displays and manipulates the IP routing table, which determines how network traffic is directed. It shows the routing paths packets take to reach their destinations.

Example:
```bash
route print (on Windows)
route -n (on Linux)
```
Sample Output (Windows):
```
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         192.168.1.1     0.0.0.0         UG    0      0        0 eth0
192.168.1.0     0.0.0.0         255.255.255.0   U     0      0        0 eth0
```

## Netcat

**Netcat**, often referred to as the "Swiss Army Knife" of networking, is a versatile utility for reading and writing data across network connections. It can be used for port scanning, banner grabbing, transferring files, and establishing reverse shells.

Example:
```bash
nc -v 192.168.1.2 80
```
Sample Output:
```
Connection to 192.168.1.2 80 port [tcp/http] succeeded!
```

## Tracert/Traceroute

**Tracert** (Windows) and **traceroute** (Unix-like systems) are tools that trace the route that packets take from the source to the destination host. They display the IP addresses of intermediate hops and the time it takes for packets to travel to each hop.

Example:
```bash
tracert google.com
```
Sample Output:
```
Tracing route to google.com [172.217.12.206]
over a maximum of 30 hops:

  1    <1 ms    <1 ms    <1 ms  192.168.1.1
  2     5 ms     5 ms     5 ms  10.20.30.40
  3    10 ms     8 ms     9 ms  20.30.40.50
  ...
 30    15 ms    14 ms    14 ms  172.217.12.206

Trace complete.
```

## Pathping

**Pathping** is a Windows command that combines the features of **ping** and **tracert**. It not only shows the round-trip time for each hop but also provides additional statistics about packet loss at each router or hop along the path.

Example:
```bash
pathping microsoft.com
```
Sample Output:
```
Tracing route to microsoft.com [13.107.4.52]
over a maximum of 30 hops:
  0  Your_Computer [192.168.1.2]
  1  Router [192.168.1.1]
  2  10.20.30.40
  3  20.30.40.50
  ...
Computing statistics for 150 seconds...
    Source to Here   This Node/Link
Hop  RTT    Lost/Sent = Pct  Lost/Sent = Pct 

 Address
...
...
...
```

## TCPView

**TCPView** is a Windows graphical utility that displays detailed information about all active TCP and UDP connections on a system. It shows the local and remote addresses, connection state, process IDs, and more.

Sample Output:
```
Proto  Local Address          Foreign Address        State
TCP    192.168.1.2:56789      151.101.65.69:443     ESTABLISHED
TCP    192.168.1.2:3389       192.168.1.10:51234    TIME_WAIT
UDP    0.0.0.0:68             0.0.0.0:0
```

## PingPlotter

**PingPlotter** is a network diagnostic tool that visualizes network performance and identifies connectivity issues. It continuously pings a target and generates graphs and reports that help in identifying packet loss, latency, and route changes.


## Nslookup

**Nslookup** (Name Server Lookup) is a command-line tool used for querying DNS (Domain Name System) records. It helps in resolving domain names to IP addresses and vice versa.

Example:
```bash
nslookup google.com
```
Sample Output:
```
Server:  UnKnown
Address:  192.168.1.1

Non-authoritative answer:
Name:    google.com
Addresses:  2607:f8b0:4004:811::200e
          172.217.12.206
```

## Dig

**Dig** (Domain Information Groper) is a command-line tool similar to **nslookup** but offers more advanced querying capabilities. It provides detailed information about DNS records, name servers, and other related data.

Example:
```bash
dig example.com
```
Sample Output:
```
; <<>> DiG 9.10.6 <<>> example.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 55776
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; QUESTION SECTION:
;example.com.          IN    A

;; ANSWER SECTION:
example.com.        1749  IN    A     93.184.216.34

;; Query time: 20 msec
;; SERVER: 192.168.1.1#53(192.168.1.1)
;; WHEN: Wed Aug 25 00:00:00 EDT 2023
;; MSG SIZE  rcvd: 58
```

## Final Insights

Network reconnaissance and discovery tools play a vital role in understanding the structure and functionality of computer networks. By utilizing these tools, network administrators can diagnose issues, security professionals can identify potential vulnerabilities, and enthusiasts can gain a deeper insight into how data traverses the vast landscape of interconnected devices. While these tools are invaluable for network analysis, it's important to use them responsibly and ethically, as improper usage could potentially disrupt network operations or violate privacy and security policies. In a rapidly evolving digital landscape, where networks expand in complexity, the knowledge and skills related to network reconnaissance and discovery remain a cornerstone of effective network management and cybersecurity.