:orphan:
(business-continuity-through-high-availability)=

# Business Continuity Through High Availability: Key Concepts for Network Resilience and Performance

High availability concepts play a pivotal role in ensuring business continuity and act as a preemptive safeguard against potential failures. When network services are built with resilience to handle failures, they contribute to the seamless operation of a business, even during minor or major component failures. Some of these concepts also bolster network services when they face heavy loads. This type of availability allows for the scalability of servers to accommodate increased demand. Failing to plan for this kind of high availability can result in network service failures under heavy loads. In tis blog we will delve into high availability concepts and their importance for business continuity.


## Availability and High availability

Availability is the measure of how consistently and reliably you can access a connection, system, or network resource. This measure is often expressed as a percentage. On the other side, high availability (HA) is a term used to describe systems that function with remarkable reliability, nearly all the time. 

**How to rate high availability**

Rating high availability is typically done by expressing it as a percentage, often referred to as "nines." Each nine represents one decimal place, and the more nines, the higher the availability. Here's how to rate high availability:

* Three Nines (99.9%): This represents 99.9% uptime or availability. It allows for approximately 8 hours and 45 minutes of downtime per year. This level is common for many business-critical applications.

* Four Nines (99.99%): This signifies 99.99% uptime or availability, allowing for about 52 minutes of downtime per year. It's often sought after for applications where minimal downtime is essential.

Various cloud services and ISPs offer three nines, four nines, five nines, or better availability, depending on what’s defined in their SLAs (service-level agreements). Consider a cloud service provider offering a four nines (99.99%) availability guarantee in their SLA. This means they commit to ensuring that their service is operational for at least 99.99% of the time during the year.

## Fault tolerance

Fault tolerance is a system's ability to keep working even when some parts fail. Unlike systems that can completely break down with even minor issues, fault-tolerant systems continue to work, though sometimes at a reduced level. Fault tolerance is particularly important in systems where reliability is crucial. Having multiple paths for data to travel between different points improves fault tolerance. So, if one connection or component fails, the system can use another route for data transmission.

## Multipathing

Multipathing is all about efficiently managing and using multiple available data transmission routes simultaneously. This concept helps minimize the risk of a single path failure disrupting your operations by introducing redundancy. It's widely employed to establish redundant connections between servers and storage units in Storage Area Networks (SANs). You might also hear it referred to as Multipath IO (MPIO), and some vendors offer licensed features to prevent network congestion.

**How does multipathing work?**

In a standard multipath setup, a server is equipped with a network controller card known as a Host Bus Adapter (HBA), which boasts two network connections. While dedicated HBAs are the best choice for high availability, practical space limitations often lead to the use of dual-port HBA cards. Each port of this HBA card connects to a separate network switch. This clever design ensures that even if one switch fails completely, your system can keep running. Meanwhile, the storage unit itself is designed with two separate storage processors that can step in to maintain high availability in case one encounters a problem. Each storage processor also has two connections, each linked to one of the switches.

The goal here is to enhance fault tolerance and ensure high availability. To set up this kind of redundancy for a SAN, you need at least two network interface adapters in your server, each connected to a different switch. These switches are then linked to the drive array, which should also have its own redundant network interfaces.

The more redundancy you build into the pathway from the server to its storage, the stronger your SAN's fault tolerance becomes.

## NIC Teaming

Network Interface Card (NIC) teaming, also known as NIC bonding, is a mechanism that enables multiple network cards to work collaboratively, offering either bandwidth aggregation or connection redundancy. When configured for bandwidth aggregation, NIC teaming combines the capacity of two connections to the switching equipment. For instance, a server equipped with two 10 Gbps cards can aggregate bandwidth to achieve a total of 20 Gbps.

When setting up NIC teaming, you're presented with two primary operational modes:

1. **Active-Active Mode:** In this mode, both NICs remain active, each with its own unique MAC address and connection to a switch. While it's possible to connect both NICs to the same switch, for enhanced fault tolerance, it's advisable to link them to different switches. This configuration not only allows the system to withstand switch failures, NIC malfunctions, or cable issues but also aggregates the bandwidth of the adapters, delivering superior performance.

2. **Active-Passive Mode:** In this operational mode, one NIC remains in continuous operation, while the other remains in a passive standby state. In redundancy configurations, should one network card fail, the other card promptly detects the failure and resumes operations on behalf of the failed card. This redundancy often relies on a heartbeat mechanism between the cards to detect failures, which entails broadcasting or multicasting between the NIC teaming members, ensuring uninterrupted network connectivity.

NIC teaming consolidates multiple physical network adapters into a virtual NIC, presenting it to the operating system as a single entity. All outgoing traffic from the OS is distributed across the assigned physical network connections, offering load balancing and optimizing network resource utilization. This, in turn, ensures server availability, enhances bandwidth, and simplifies network configuration.

## Load balancing

Load balancing is distributing incoming service requests across multiple servers. Its primary purpose is to prevent any single server from becoming overwhelmed by requests, ensuring the continuity of business operations. A common use case for load balancing is when a web server experiences high CPU utilization due to a surge in incoming requests. You simply put your servers behind a load balancer so that it can act as a traffic distributor, evenly spreading incoming requests across the web servers. As demand increases, you can manually add more instances or scale out -ideally automate this process using a launch template and target tracking scaling policy.

**load balancer forms**

Load balancers come in various forms and configurations to meet the diverse needs of modern computing environments:

* Physical Devices: Physical load balancers are dedicated hardware appliances specifically designed for load balancing. They are standalone devices that can efficiently distribute incoming traffic to multiple servers. These devices are often used in data centers and enterprise networks to manage network traffic effectively.

* Virtualized Instances: Virtualized load balancers are software-based solutions that run on virtual machines (VMs) or cloud-based instances. They provide the flexibility to scale and adapt load balancing capabilities as needed. Virtual load balancers are commonly used in virtualized and cloud environments such as Amazon Elastic Load Balancer (ELB), Google Cloud Load Balancing (GCLB), Azure Load Balancer.

* Software Processes: Load balancing can also be achieved through software processes running on standard servers or hosts. These software-based load balancers leverage the server's processing power and can be configured to distribute traffic across multiple server instances. This approach is cost-effective and suitable for smaller-scale deployments.

Application Delivery Controllers (ADCs): Some load balancers are integrated into Application Delivery Controllers, which are comprehensive devices or software solutions designed to enhance the performance, security, and availability of three-tier web and microservices-based applications. ADCs not only balance traffic but also provide features like SSL offloading, content caching, and application firewall protection. They can be deployed across various hosting environments, including on-premises data centers and cloud platforms.


**Load Balancing Algorithms**

Load balancers are equipped with various load balancing algorithms to intelligently distribute traffic based on specific requirements. Common static and dynamic algorithms include:

* **Round Robin**: Traffic is distributed sequentially to each server in a rotation. 

* **Server Response Time**: Servers with faster response times receive more traffic.

* **Least Connection Method**: New connections are sent to the server with the fewest active connections, distributing the load evenly.

These different forms, algorithms and capabilities of load balancers allow you to choose the most suitable solution based on the infrastructure, scalability needs, and application requirements. Whether it's a physical appliance, virtual instance, or software process, load balancers significantly boost network performance, reliability, redundancy and data availability.


## Port aggregation

Port aggregation, also known as link aggregation or bonding, is merging multiple network connections into a single logical connection. This unified connection appears as a single, higher-capacity link to network devices and operating systems. Port aggregation offers several significant advantages:

1. **Increased Throughput**: By consolidating multiple network connections, port aggregation significantly boosts the available bandwidth for data transfer. Data can be transmitted and received concurrently across the aggregated links, effectively multiplying the accessible bandwidth.

2. **Redundancy**: Port aggregation provides built-in redundancy to safeguard against link or port failures. In the event that one of the aggregated links experiences a hardware issue or becomes unavailable, traffic is automatically and seamlessly redirected to the remaining operational links, ensuring uninterrupted network connectivity.

3. **Automatic Failover**: With port aggregation, there is automatic failover between the aggregated Network Interface Cards (NICs), ensuring continuity of network operations in case of a link or NIC failure.

4. **Load Balancing**: Port aggregation enables load balancing, distributing traffic across multiple links or components to optimize performance and enhance fault tolerance. This ensures that network resources are utilized efficiently.

**LACP and LAG**:

LACP, which stands for Link Aggregation Control Protocol, is a networking protocol used to dynamically manage and negotiate port aggregation. It operates by allowing network devices, such as switches and network interface cards (NICs), to communicate and coordinate the creation of link aggregation groups (LAGs). 

LAGs are logical interfaces composed of multiple physical links that act as a single, higher-capacity connection. LACP ensures that the links within a LAG are compatible and operational. If any link within the group fails, LACP can automatically redistribute the traffic to the remaining active links, providing seamless failover and load balancing.

## Clustering

Clustering is a strategy used to enhance the availability, performance, and scalability of services running on a cluster of interconnected hosts. It involves grouping redundant resources, like servers, to present them as a single entity to the network. Clustering can be applied to various entities such as servers, routers, or applications, and it often works in tandem with load balancing.

In practical terms, clustering connects servers in a way that makes them appear as a unified system to the operating environment. This approach harnesses the combined processing power of multiple servers to efficiently handle demanding technical applications and takes advantage of parallel processing. Shared resources within a cluster can range from physical hardware devices like disk drives and network cards to TCP/IP addresses, entire applications, and databases.

The cluster service, a software component on each node, manages all cluster-specific activities, including traffic management and load balancing. Nodes are connected through standard network connections like Ethernet, FDDI, ATM, or Fibre Channel.

Clustering offers scalability,improved throughput and response times, high availability and performance.


## Final Words

To summarize, this article has explored essential concepts for business continuity and network availability. We've covered high availability ratings, fault tolerance, multipathing, NIC teaming, port aggregation, clustering and load balancing, crucial for maintaining resilience and performance. These principles empower you to handle various challenges, from hardware failures to surges in demand, ensuring sustained success in the ever-evolving digital landscape.