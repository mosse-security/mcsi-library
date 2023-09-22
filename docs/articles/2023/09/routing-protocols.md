:orphan:
(routing-protocols)=

# Routing Protocols

Routing protocols are the kind of topic which you may never have considered until you sit down to study how networking really works - the fact is (at least when things are working correctly!) they do their job quietly in the background and we never have to think about them. For a network engineer however, routing protocols are critical to understand and master. In this article, we cover some of the most important ones!

 

## Routing Information Protocol (RIP)

The Routing Information Protocol (RIP) is one of the oldest distance-vector routing protocols developed for IPv4. It was initially defined in 1988 as RIP version 1 (RIPv1) and later updated to RIP version 2 (RIPv2) in 1993. RIP is considered a legacy protocol, and its usage has significantly declined in modern networks due to its limitations and the availability of more advanced routing protocols.

At a high level, RIP routers periodically exchange routing tables containing information about network destinations and associated metrics (hop counts). RIP routers use these routing tables to make routing decisions. RIP employs distance-vector routing, where each router advertises its routing table to its neighboring routers. Routers continue to exchange routing updates until the network converges, and all routers have the same routing information.

**Advantages**

- Simplicity: RIP is straightforward to configure and understand.
- Low resource requirements: RIP has low CPU and memory requirements, making it suitable for resource-constrained devices.

**Disadvantages**

- Limited scalability: RIP is not suitable for large networks due to its slow convergence and hop-count metric, which can lead to routing loops.

- Lack of support for modern network features: RIP lacks support for features like VLSM (Variable Length Subnet Masks) and route summarization.

- Convergence time: RIP's slow convergence can result in temporary network instability during topology changes.

  

**Configuration Example and Verification Output**

Here's a basic configuration example for enabling RIP on a Cisco router

```
Router(config)# router rip
Router(config-router)# network 192.168.0.0
Router(config-router)# version 2
Router(config-router)# no auto-summary
```

Verification output for checking the RIP configuration

```
show ip rip database
show ip rip interface
show ip route rip
```

These commands display various aspects of the RIP configuration and routing behavior, allowing network administrators to verify the setup and monitor RIP's operation.

```
Router# show ip rip database

10.0.0.0/8, metric 1
   via 192.168.1.2, GigabitEthernet0/1.1
   via 192.168.1.3, GigabitEthernet0/1.1
   via 192.168.1.4, GigabitEthernet0/1.1
   via 192.168.1.5, GigabitEthernet0/1.1
   via 192.168.1.6, GigabitEthernet0/1.1
192.168.1.0/24, metric 1
   directly connected, GigabitEthernet0/1.1
192.168.2.0/24, metric 2
   via 192.168.1.2, GigabitEthernet0/1.1
192.168.3.0/24, metric 3
   via 192.168.1.3, GigabitEthernet0/1.1
192.168.4.0/24, metric 4
   via 192.168.1.4, GigabitEthernet0/1.1

Router# show ip rip interface

GigabitEthernet0/1.1 is up, line protocol is up
  Internet Address 192.168.1.1/24, Area 0
  Process ID 1, Router ID 192.168.1.1, Network Type BROADCAST, Cost: 1
  Transmit Delay is 1 sec, State DR, Priority 1
  Designated Router (ID) 192.168.1.1, Interface address 192.168.1.1
  Backup Designated Router (ID) 192.168.1.2, Interface address 192.168.1.2

Router# show ip route rip

Gateway of last resort is not set

      10.0.0.0/8 is variably subnetted, 5 subnets, 5 masks
C        10.0.0.0/8 is directly connected, GigabitEthernet0/0
R        192.168.1.0/24 [120/1] via 192.168.1.2, 00:00:20, GigabitEthernet0/1.1
C        192.168.1.0/24 is directly connected, GigabitEthernet0/1.1
R        192.168.2.0/24 [120/2] via 192.168.1.2, 00:00:20, GigabitEthernet0/1.1
R        192.168.3.0/24 [120/3] via 192.168.1.3, 00:00:20, GigabitEthernet0/1.1
R        192.168.4.0/24 [120/4] via 192.168.1.4, 00:00:20, GigabitEthernet0/1.1
```

In this example:

- `show ip rip database` displays the RIP database, including network destinations, metrics, and next-hop routers. It shows how routes are learned and propagated within the RIP domain.
- `show ip rip interface` provides detailed information about the RIP-enabled interface, including IP address, area, process ID, router ID, and interface state.
- `show ip route rip` shows the routing table entries learned via RIP, including network destinations, RIP metrics, next-hop routers, and outgoing interfaces. The `[120/1]` format indicates the RIP metric and hop count.



## Enhanced Interior Gateway Routing Protocol (EIGRP)

The Enhanced Interior Gateway Routing Protocol (EIGRP) is an advanced distance-vector routing protocol. EIGRP was introduced in the 1990s and has become a widely used routing protocol in enterprise networks, particularly those with Cisco infrastructure. EIGRP was originally Cisco-proprietary, however it has now been released for other vendors to implement. EIGRP is known for its rapid convergence and efficient use of bandwidth.

EIGRP uses a more sophisticated approach than traditional distance-vector protocols. It uses the Diffusing Update Algorithm (DUAL) to calculate the best path to reach a destination. EIGRP routers maintain a topology table and a routing table, allowing them to adapt quickly to network changes. EIGRP updates are sent only when topology changes occur, reducing bandwidth consumption.

**Advantages**

- Rapid Convergence: EIGRP's DUAL algorithm enables fast network convergence by immediately adapting to topology changes.
- Efficient Bandwidth Usage: EIGRP minimizes unnecessary updates, conserving network bandwidth.
- Supports VLSM and CIDR: EIGRP supports Variable Length Subnet Masks (VLSM) and Classless Inter-Domain Routing (CIDR), allowing for efficient address allocation and route summarization.

**Disadvantages**

- Proprietary: EIGRP was Cisco-proprietary protocol, which has limited its adoption outside of Cisco products.

- Complex Configuration: EIGRP configuration can be complex, particularly in large networks.

- Limited Non-Cisco Support: While Cisco has made some information about EIGRP available to the public, its full functionality may not be supported by non-Cisco devices.

  

**Configuration Example and Verification Output**

Here's a basic configuration example for enabling EIGRP on a Cisco router

```
Router(config)# router eigrp 100
Router(config-router)# network 192.168.0.0
Router(config-router)# auto-summary
```

Verification output for checking the EIGRP configuration

```
Router# show ip route
Router# show ip protocols
Router# show ip eigrp neighbors
Router# show ip eigrp topology
```

These commands display various aspects of the EIGRP configuration and routing behavior, allowing network administrators to verify the setup and monitor EIGRP's operation.

```
Router# show ip protocols

Routing Protocol is "eigrp 100"
  Outgoing update filter list for all interfaces is not set
  Incoming update filter list for all interfaces is not set
  Default networks flagged in outgoing updates
  Default networks accepted from incoming updates
  EIGRP metric weight K1=1, K2=0, K3=1, K4=0, K5=0
  EIGRP maximum hopcount 100
  EIGRP maximum metric variance 1

Router# show ip eigrp neighbors

IP-EIGRP neighbors for process 100
H   Address                 Interface       Hold Uptime   SRTT   RTO  Q  Seq
                                   (sec)         (ms)       Cnt Num
0   192.168.0.2             GigabitEthernet0/1  12   00:01:45   2  100  0  4

Router# show ip eigrp topology

IP-EIGRP Topology Table for AS(100)/ID(192.168.0.1)
Codes: P - Passive, A - Active, U - Update, Q - Query, R - Reply,
       r - reply Status, s - sia Status

P 192.168.0.0/24, 1 successors, FD is 409600
        via 192.168.0.2 (409600/204800), GigabitEthernet0/1
P 192.168.1.0/24, 1 successors, FD is 409600
        via 192.168.0.2 (409600/204800), GigabitEthernet0/1
P 192.168.2.0/24, 1 successors, FD is 409600
        via 192.168.0.2 (409600/204800), GigabitEthernet0/1
```

In this example:

- `show ip protocols` provides information about the EIGRP configuration, including the process number, metric weights, and maximum hop count.
- `show ip eigrp neighbors` displays a list of EIGRP neighbors along with their IP addresses, interfaces, and other relevant details.
- `show ip eigrp topology` shows the EIGRP topology table, which lists network destinations, successors, and the routes to reach them.

These commands help network administrators verify the EIGRP configuration, check the status of EIGRP neighbors, and examine the EIGRP topology table to ensure that routing information is correct and up-to-date.



## **Open Shortest Path First (OSPF)**

Open Shortest Path First (OSPF) is a widely used, open-standard link-state routing protocol for IP networks. If you have any interest in networking, you'll quickly get to know OSPF! OSPF was developed in the late 1980s as an alternative to distance-vector protocols and has since become a cornerstone of IP routing in enterprise and service provider networks. OSPF is known for its scalability and efficient handling of large networks.

OSPF routers exchange link-state advertisements (LSAs) to build a detailed and accurate representation of the network's topology. Each router constructs a link-state database containing LSAs received from neighboring routers. OSPF routers then run the Dijkstra SPF (Shortest Path First) algorithm to compute the shortest path to each network destination. The result is a routing table with the best path to reach each destination.

**Advantages**

- Scalability: OSPF is highly scalable and suitable for large and complex networks.
- Rapid Convergence: OSPF reacts quickly to topology changes, leading to fast network convergence.
- Support for Hierarchical Design: OSPF allows for hierarchical network design using areas, improving network manageability.
- Fine-Grained Control: Administrators have granular control over route summarization, filtering, and authentication.

**Disadvantages**

- Complexity: OSPF configuration and troubleshooting can be complex, particularly in larger networks.
- Resource Intensive: OSPF routers may require more CPU and memory resources compared to other routing protocols.
- Proprietary Implementations: While OSPF itself is an open standard, vendors often implement it with proprietary extensions, which can affect interoperability.

**Configuration Example and Verification Output**

Here's a basic configuration example for enabling OSPF on a Cisco router:

```
Router(config)# router ospf 1
Router(config-router)# network 192.168.0.0 0.0.0.255 area 0
Router(config-router)# network 10.0.0.0 0.255.255.255 area 0
```

Verification output for checking the OSPF configuration:

```
Router# show ip ospf neighbor
Router# show ip ospf interface
Router# show ip route ospf
Router# show ip ospf database
```

These commands allow network administrators to verify the OSPF configuration, check OSPF neighbors, examine OSPF interface information, view OSPF routing table entries, and inspect the OSPF link-state database, which stores detailed network topology information.

```
Router# show ip ospf neighbor

Neighbor ID     Pri   State           Dead Time   Address         Interface
192.168.0.2     1     FULL/DR         00:00:35    192.168.0.2     GigabitEthernet0/1
192.168.0.3     1     FULL/BDR        00:00:31    192.168.0.3     GigabitEthernet0/1

Router# show ip ospf interface

GigabitEthernet0/0 is up, line protocol is up
  Internet Address 192.168.1.1/24, Area 0
  Process ID 1, Router ID 192.168.1.1, Network Type BROADCAST, Cost: 1
  Transmit Delay is 1 sec, State BDR, Priority 1
  Designated Router (ID) 192.168.0.2, Interface address 192.168.1.2
  Backup Designated Router (ID) 192.168.0.3, Interface address 192.168.1.3

GigabitEthernet0/1 is up, line protocol is up
  Internet Address 192.168.0.1/24, Area 0
  Process ID 1, Router ID 192.168.0.1, Network Type BROADCAST, Cost: 1
  Transmit Delay is 1 sec, State DR, Priority 1
  Designated Router (ID) 192.168.0.1, Interface address 192.168.0.1
  Backup Designated Router (ID) 192.168.0.3, Interface address 192.168.0.3

Router# show ip route ospf

O    192.168.2.0/24 [110/2] via 192.168.0.2, 00:00:40, GigabitEthernet0/1
O    192.168.3.0/24 [110/2] via 192.168.0.3, 00:00:40, GigabitEthernet0/1
O    192.168.4.0/24 [110/2] via 192.168.0.2, 00:00:40, GigabitEthernet0/1
O    192.168.5.0/24 [110/2] via 192.168.0.3, 00:00:40, GigabitEthernet0/1

Router# show ip ospf database

            OSPF Router with ID (192.168.0.1) (Process ID 1)

                Router Link States (Area 0)

Link ID         ADV Router      Age         Seq#       Checksum Link count
192.168.0.1     192.168.0.1     1434        0x80000002 0x0075D9 2
192.168.0.2     192.168.0.2     1434        0x80000002 0x00BA70 2
192.168.0.3     192.168.0.3     1434        0x80000002 0x004FD9 2
192.168.1.1     192.168.0.1     1275        0x80000001 0x004EFA 1
192.168.1.2     192.168.0.2     1275        0x80000001 0x0098A6 1
192.168.1.3     192.168.0.3     1275        0x80000001 0x00E2ED 1
```

In this example:

- `show ip ospf neighbor` displays information about OSPF neighbors, including their IDs, states, and the interfaces through which they are reachable.
- `show ip ospf interface` provides details about OSPF-enabled interfaces, including IP addresses, area assignments, priorities, and more.
- `show ip route ospf` shows the routing table entries learned via OSPF, including network destinations, OSPF cost metrics, next-hop routers, and outgoing interfaces.
- `show ip ospf database` reveals the contents of the OSPF link-state database, listing information about routers, links, and associated LSAs. This database is crucial for OSPF routers to construct the network's topology.



## **Intermediate System to Intermediate System (ISIS)**

Intermediate System to Intermediate System (ISIS) is an Interior Gateway Protocol (IGP) designed for routing within large and complex networks, especially in service provider environments. Developed in the 1980s as an OSI protocol, ISIS has been adapted for routing IP traffic. It is widely used in ISP networks and certain enterprise scenarios.

ISIS operates as a link-state routing protocol, similar to OSPF. Routers within an ISIS domain exchange link-state advertisements (LSAs) to build a comprehensive topology database. The Dijkstra SPF algorithm is used to calculate the shortest path to network destinations. ISIS supports multiple routing levels, known as routing domains, which can be useful in complex networks.

**Advantages**

- Scalability: ISIS is highly scalable and well-suited for large and hierarchical networks.
- Support for Multiple Address Families: ISIS can route multiple address families, including IPv4 and IPv6.
- Stability: ISIS networks are known for their stability and robustness.

**Disadvantages**

- Complexity: ISIS configuration and operation can be complex, particularly for those less familiar with the protocol.
- Lack of Widespread Adoption: ISIS is more commonly used in service provider networks and is not as prevalent in enterprise networks.
- Proprietary Variants: While ISIS is an open standard, vendors often implement their own variants, potentially leading to interoperability issues.

**Configuration Example and Verification Output**

Here's a basic configuration example for enabling ISIS on a Cisco router

```
Router(config)# router isis
Router(config-router)# net 49.0001.0000.0000.0001.00
Router(config-router)# is-type level-2-only
```

Verification output for checking the ISIS configuration

```
Router# show isis neighbors
Router# show isis interface
Router# show isis database
Router# show ip route isis
```

These commands allow network administrators to verify the ISIS configuration, check ISIS neighbors, inspect ISIS interface information, view ISIS routing table entries, and examine the ISIS link-state database containing detailed network topology information.

```
Router# show isis neighbors

System Id      Type Interface   IP Address      State Holdtime Circuit Id
R1            L2   GigabitEthernet0/1.1 192.168.1.1    UP    23       00
R2            L2   GigabitEthernet0/1.1 192.168.1.2    UP    26       01
R3            L2   GigabitEthernet0/1.1 192.168.1.3    UP    27       02

Router# show isis interface

GigabitEthernet0/1.1 is UP, line protocol is UP
  L2 Circuit to GigabitEthernet0/1.1
    Circuit Type: LAN IIHs 2, Hellos 11, DRs 1
    BFD enabled, interval 1000ms, minimum interval 1000ms

Router# show isis database

IS-IS Level-2 Link State Database
LSPID                 LSP Seq Num  LSP Checksum  LSP Holdtime  ATT/P/OL
R1.00-00              0x00000005   0x0B74        1070          0/0/0
R2.00-00              0x00000005   0x0B74        1095          0/0/0
R3.00-00              0x00000005   0x0B74        1098          0/0/0

Router# show ip route isis

Gateway of last resort is not set

      192.168.2.0/24 is variably subnetted, 2 subnets, 2 masks
C        192.168.2.0/24 is directly connected, GigabitEthernet0/2.1
L        192.168.2.1/32 is directly connected, GigabitEthernet0/2.1
```

In this example:

- `show isis neighbors` displays information about ISIS neighbors, including their System IDs, types, interfaces, IP addresses, state, holdtime, and circuit IDs.
- `show isis interface` provides details about ISIS-enabled interfaces, including their states, circuit types, hello intervals, and other relevant information.
- `show isis database` shows the ISIS link-state database, listing LSP (Link-State PDU) entries with information about routers, their sequence numbers, checksums, and more.
- `show ip route isis` displays the routing table entries learned via ISIS, including network destinations, routes, and outgoing interfaces.

These commands help network administrators verify the ISIS configuration, monitor ISIS neighbors and interfaces, inspect the ISIS link-state database, and check the routing table for ISIS-learned routes.



## **Border Gateway Protocol (BGP)**

Border Gateway Protocol (BGP) is an advanced exterior gateway protocol designed for routing between autonomous systems (ASes) on the Internet. It was initially defined in RFC 1105 in 1989 and has since undergone several revisions. BGP is the protocol that controls the core routing of the global Internet. It is considered a path vector protocol.

BGP routers exchange routing information in the form of route updates, called BGP updates or BGP messages. Unlike interior gateway protocols like OSPF or EIGRP, BGP is focused on policy-based routing and path selection. It uses the AS path attribute to avoid routing loops and to influence route selection. BGP routers build a routing table containing the best routes to reach various IP prefixes.

**Advantages**

- Internet Scale: BGP is designed to handle the massive scale of the global Internet, making it suitable for large networks.
- Policy Control: Network administrators can exert fine-grained control over route selection using BGP attributes.
- Path Diversity: BGP allows for path diversity, enabling traffic engineering and redundancy.
- Route Aggregation: BGP supports route aggregation, reducing the size of the global routing table.

**Disadvantages**

- Complexity: BGP is complex and requires careful configuration to avoid misconfigurations and routing issues.
- Slow Convergence: BGP's focus on stability can lead to slow convergence in the event of network changes.
- Security Concerns: BGP is vulnerable to various security threats, including route hijacking and prefix leakage.

**Configuration Example and Verification Output**

Here's a basic configuration example for enabling BGP on a Cisco router:

```
bash
Router(config)# router bgp 65000
Router(config-router)# neighbor 192.168.0.2 remote-as 65001
Router(config-router)# network 192.168.1.0 mask 255.255.255.0
```

Verification output for checking the BGP configuration:

```
bash
Router# show ip bgp neighbors
Router# show ip bgp summary
Router# show ip bgp
Router# show ip route bgp
```

These commands allow network administrators to verify the BGP configuration, check BGP neighbors, view BGP summary information, inspect BGP routing table entries, and examine the BGP-learned routes.

```
plaintext
Router# show ip bgp neighbors

BGP neighbor is 192.168.0.2, remote AS 65001, external link
  BGP version 4, remote router ID 192.168.0.2
  BGP state = Established, up for 00:03:45
  Last read 00:00:10, last write 00:00:05, hold time is 180, keepalive interval is 60 seconds
  Neighbor capabilities:
    4-byte AS Numbers: advertised and received
    Route refresh: advertised and received
    Address family IPv4 Unicast: advertised and received
  Message statistics:
    InQ depth is 0
    OutQ depth is 0
  Route refresh request: received 0, sent 0, inQ 0, outQ 0
  Route refresh thresholds: received 0, sent 0
  Connections established 1; dropped 0
  Last reset 00:03:45, due to BGP Notification received
  Local host: 192.168.0.1, Local port: 179
  Foreign host: 192.168.0.2, Foreign port: 179

Router# show ip bgp summary

BGP router identifier 192.168.0.1, local AS number 65000
BGP table version is 3, main routing table version 3
3 network entries using 372 bytes of memory
3 path entries using 372 bytes of memory
1/1 BGP path/bestpath attribute entries using 124 bytes of memory
0 BGP route-map cache entries using 0 bytes of memory
0 BGP filter-list cache entries using 0 bytes of memory
BGP using 868 total bytes of memory
BGP activity 3/0 prefixes, 3/0 paths, scan interval 60 secs

Router# show ip bgp

BGP table version is 3, local router ID is 192.168.0.1
Status codes: s suppressed, d damped, h history, * valid, > best, = multipath,
              i internal, r RIB-failure, S Stale, m multipath, b backup-path,
              f RT-Filter, x best-external, a additional-path, c RIB-compressed,
              t secondary path, l long-lived-stale, p prefix-override
Origin codes: i - IGP, e - EGP, ? - incomplete
RPKI validation codes: V valid, I invalid, N Not found

     Network          Next Hop            Metric LocPrf Weight Path
 *>  192.168.1.0      0.0.0.0                  0         32768 i
 *>  192.168.2.0      192.168.0.2              0             0 65001 i
 *>  192.168.3.0      192.168.0.2              0             0 65001 i
```

In this example:

- `show ip bgp neighbors` displays information about BGP neighbors, including their IP addresses, AS numbers, BGP version, state, timers, and capabilities.
- `show ip bgp summary` provides a summary of BGP routing information, including the BGP router identifier, AS number, BGP table version, and statistics on network entries and memory usage.
- `show ip bgp` shows the BGP routing table, including network destinations, next-hop IP addresses, metrics, and AS paths. The `*>` symbol indicates the best route for each network.



## Routing Types

Routing is a fundamental function in computer networking, involving the forwarding of data packets from source to destination across a network. Routing decisions are based on routing tables that contain information about available routes and their associated metrics. Different routing types exist to meet various network design and management requirements. Three common routing types are static routing, dynamic routing, and default routing.

**Static Routing**

Static routing is a straightforward method for configuring routing tables manually. In static routing, network administrators define specific routes by specifying the destination network or host, the next-hop router's IP address, and an associated metric or cost. Static routes are typically used in small to medium-sized networks or for specific cases where routing stability and predictability are essential. One advantage of static routing is its predictability, as administrators have full control over route selection. Additionally, static routes require minimal CPU and memory resources, making them suitable for resource-constrained devices. However, they lack scalability in large networks, require manual configuration and updates, and may not provide automatic failover in case of link or router failures.

**Dynamic Routing**

Dynamic routing protocols, such as OSPF, EIGRP, and BGP, automate the process of populating routing tables by exchanging routing information among routers. These protocols use various algorithms and metrics to calculate optimal paths and adapt to network changes dynamically. Dynamic routing is well-suited for medium to large networks where scalability and adaptability are crucial. Dynamic routing offers advantages such as scalability, automatic updates, and redundancy. However, it can be complex to configure, may consume more CPU and memory resources than static routing, and may take time to converge after network changes.

**Default Routing**

Default routing is a special case of static routing that directs all traffic with no matching specific route to a predefined next-hop router, known as the default gateway or default route. Default routes are commonly used at the network edge to provide a path for traffic that does not match any specific destination in the routing table. Default routing simplifies configurations by reducing the need for extensive routing table entries and is often used to funnel traffic through security appliances or enforce traffic policies. However, it limits control and granularity as it sends unmatched traffic to a single destination and can, in some cases, result in suboptimal routing paths for specific traffic.

# Final Words

In this article we have covered a high level introduction to some of the most common routing protocols, and had a quick look at different types of routing. You can, of course, go into a huge amount of depth on each of these topics - but we hope this was a good primer! 
