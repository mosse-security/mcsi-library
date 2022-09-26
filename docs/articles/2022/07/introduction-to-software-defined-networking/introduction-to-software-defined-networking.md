:orphan:
(introduction-to-software-defined-networking)=
# Introduction to Software-Defined Networking
 
The foundation of conventional networks is based on hardware devices that are used to route data between various nodes in a network. Malicious adversaries, on the other hand, take advantage of these network devices' security misconfigurations to launch various network attacks, such as Distributed Denial of Service attacks. With the introduction of software-based networking, organizations have been able to lower the network attack surface through the use of automated security provisioning, improved network visibility, scalability of resources, and centralized control over the enterprise network. This article discusses the essential concepts of Software-Defined Networking, how it differs from the traditional networking approach, and how it can be leveraged to provide greater network security.

## What is a Software-Defined Network?

Software-Defined Networking is a networking method that employs software-based controllers or APIs to interface with underlying network devices in order to manage and route packets on a network. Network administrators can set up these application programming interfaces to control the network devices through the use of software-defined networking. The setup and management of network devices are centrally controlled via SDN controllers, which results in increased network agility. The advent of cloud computing is one of the key factors propelling software-defined networking. SDN makes it simple to route network traffic dynamically to and from the newly integrated servers in response to an increase in network requests. Thus SDN makes it easy to integrate new platforms or services and increases the ability of the network to adapt to the new traffic patterns.

The data plane, also known as the forwarding plane, and control plane are combined into a single device in typical network devices. By separating the data and control planes, software-defined networking enables the controlled, efficient, and centrally managed traversal of the data on the network.

## What are a control plane and a forwarding plane?

A control plane in networking is a virtual or abstract plane where all the network routing decisions are made. This plane is where different routing algorithms such as OSPF, RIP, BGP, etc. are running in order to decide the route that the packet will take in order to move between different nodes. This plane is responsible for discovering the overall network topology and maintaining the routing table for the entire network. As new network devices are constantly being discovered and paths keep on changing depending on network congestion, the control plane is responsible for controlling the network packets dynamically depending upon the overall picture of the network.

The forwarding plane or the data plane is where the data traverses through the network. It is the plane where actual packet forwarding decisions are taking place on the network. For example, if a packet arrives at one interface of the router, the forwarding plane is responsible for deciding where this packet will go next. The control is responsible for all overall routing decisions taking the bigger network picture into account. The forwarding plane is actually responsible for implementing and executing the routing decisions made previously by the control plane.

## Network Functions Virtualization vs Software-Defined Networking

Although they are two distinct concepts, Network Function Virtualization (NFV for short) and Software Defined Networking are quite often used interchangeably.

The term "network functions virtualization" (NFV) refers to a group of methods used to virtualize various network operations that are normally carried out by hardware platforms, such as routers, firewalls, load balancers, and other devices. Network Function Virtualization virtualizes the entire physical network through the use of a hypervisor, enabling it to grow without the need for additional hardware.

Software-Defined Networking, on the other hand, works in concert with with NFV to virtualize network services and abstract them from the underlying hardware. The role of SDN is to appropriately set up and configure the network functions in order to improve visibility and control over the entire network. Whereas the job of NFV is to virtualize these network services. 

## How does SDN differ from the traditional networking approach?

This section goes over how Software-defined networking differs from the traditional networking approach.

* Traditional networking devices combine the control plane and the forwarding plane into a single device. The physical network devices in this networking approach communicate with one another in a decentralized manner. The network configuration changes are more complicated and time-consuming in the traditional networking approach since each device has its own control plane and forwarding plane. As a result, each device must be configured separately in order to support the network changes. These changes are sometimes not configured properly that can lead to different network security vulnerabilities.

* The SDN approach, on the other hand, uses software-based controllers to centrally regulate the network devices, making it possible for changes to the network to be made in a way that is both seamless and effective. The abstraction of control and forwarding planes is the primary aspect of SDN based approach that promotes security and scalability. With a central controller in charge of managing and coordinating the actions of numerous network devices, network administrators may easily push more granular and frequent network changes rather than separately configuring each network device. In this method, the control plane is contained in a separate SDN controller while the forwarding plane is present on each device individually. Additionally, this enables the network devices—whether heterogeneous or not—to be detached from the applications that run on them. SDN keeps the hardware in charge of the data plane, which actually delivers the traffic, while moving the control plane, which decides where to send it, to software.

## Main components of a Software-defined network architecture

Some of the main components that are a part of the software-defined networking architecture are described in this section. These components may or may not be present in the same physical location in the network. These components are as follows:

**Applications:** The job of applications in SDN is to communicate or relay the information about the entire network, resource requests, or different actions. 

**Controllers:** The SDN controllers' job is to communicate with the applications in order to determine the routing path for the data packets on the network.

**Network devices:** The job of these hardware network devices is to receive the routing instructions provided by SDN controllers and route the packets accordingly.

In the SDN architecture, each of these elements works in concert to provide effective network traffic flow. These three components, or levels, are all integrated by the SDN controller. The integration between the controller and the application is referred to as the northbound interface, whereas the integration between the controller and networking devices is referred to as the southbound interface.

## Benefits of Software-defined networking

There are numerous advantages of software-defined networking that not only result in enhanced network performance but also cause the network security to become stronger. Some of the advantages of using SDN are as follows:

### Centralized Network Control and Improved Visibility

As mentioned previously, SDN allows you to manage your network from a centralized intuitive interface. This results in improved visibility into the network traffic and allows the network administrators to eliminate any blind spots in the network. It also causes network attack surfaces to be reduced by monitoring and blocking suspicious network traffic.

### Automated Security Provisioning

The majority of network attacks are caused due to security misconfigurations in network equipment brought on by human error. SDN makes it simpler for network administrators to automate the provisioning of additional resources in response to changes that are needed in the network environment. Using automated scripts is made easier with SDN, enabling the organization to configure, protect, and optimize resources as required. This automated provisioning enables network configuration changes to be readily implemented via the interface of the SDN controller. As a result, the error caused by manual changes made by administrators is significantly decreased. Access control list (ACL) modifications, traffic load balancing, and network address translation (NAT) rule creation are a few examples of these network reconfigurations that can be made easily using the SDN controller.

### Enforcement of Security Policies

The centralized SDN controller plays a significant role in boosting network security. It gives network managers the ability to develop and implement crucial security rules and policies throughout the whole network, guaranteeing that all devices and other essential components are protected from different attack vectors.

### Network Segmentation

The usage of SDN can also assist enterprises in implementing network segmentation, which is a critical network strategy for avoiding the propagation of malware in the network, DDOS attacks, lateral movement attacks and much more. SDN makes it possible for network administrators to design more compact subnetworks within the main corporate network. Network segmentation is made easier by software-defined by grouping and identifying network traffic. The segmentation policy is thus enforced directly on the network hardware via traffic tags, but without the complexity of conventional methods. From a security perspective, it helps to reduce an organization's attack surface, which restricts the ability of malware to proliferate throughout the network. This SDN based Network Segmentation thereby stops an infection from spreading to other parts of the company in the event of an attack that targets the entire enterprise network.

### Efficient Security Response

The efficient and timely response to numerous cyberattacks is one of the main advantages of security-defined networking. SDN controllers receive data about potential cyber threats from various network applications, intrusion detection systems, or network monitoring tools. Therefore, the targeted network devices can be reconfigured by the SDN controller to restrict malicious traffic. In order to increase network security, SDN controllers can either automatically reject harmful traffic or block suspicious network traffic based on various attack signatures.

### Scalability

A key advantage of the virtualized and software-defined networking is scalability. SDN's flexibility makes scaling business operations considerably simpler. It is because more devices that enable business expansion can be added to the network as needed without running the risk of a service interruption. Automated scaling with the SDN approach makes it simple to introduce new services or server instances based on the organizations' needs for more system resources.

### Open Source and Vendor neutral protocols

SDN allows for the use of open source standards and protocols that can easily be integrated with various network devices manufactured by different vendors. This eliminates the dependence of the company on specific vendor products.

## The security challenges associated with SDN

The usage of software-defined networks has many benefits for the company in terms of improved network performance and higher security. On the one hand, the centrally managed platform makes configuring the network environment very simple, but on the other, it acts as a single point of failure. A single point of failure is a design defect in a system that makes it possible for the entire system to fail if one of its components fails. A single point of failure issue poses a serious risk to a system or network, that may even lead to its unavailability.

SDN controllers are a crucial and essential part of the SDN architecture. In order to maintain a secure enterprise network, the role of these controllers is very important. The entire network or a significant portion of it may not function properly if these controllers are compromised or become unavailable. As a result, these SDN controllers represent a single point of failure in the network. By using redundant SDN controllers with fail-over functionality, this security issue can be mitigated. The use of fail-over technology assures system or network availability by automatically detecting the failure of the primary server and the backup or secondary server taking its place to ensure that the system/network stays available.

## Different Implementations of Software-Defined Networking

There have been different implementations of Software-Defined networking over the years. These versions have been developed by different communities through the use of specific technologies. The basic premise of network abstraction is the same in all these implementations. This section reviews these implementations one by one. 

### Open SDN model

The Open networking foundation (ONF) is the organization that created this SDN model. This is the most popular SDN strategy, and it makes use of open source standards to manage the virtual and physical equipment in charge of sending data packets across the network. The foundational communication protocol for the Open SDN model is OpenFlow. To appropriately route packets via the network, the SDN controllers must connect with the network devices using the OpenFlow protocol, and vice versa. On the other hand, applications use Java or RESTful APIs to interface with the SDN controllers.

### SDN by APIs

This SDN approach has been implemented by Cisco. This approach is built on the concept of using application programming interfaces or APIs to control how data moves through each network device instead of using open protocols. This strategy makes use of a robust API on proprietary Cisco switches to provide greater control over network traffic. An application programming interface allows two or more computer applications to communicate with one another. It is a form of software interface that provides a service to other software applications. This approach provides better deep packet inspection and manipulation capabilities as compared to the Open SDN approach.

### SDN Overlay model

The SDN Overlay model makes use of a virtualized model that is constructed on top of the standard physical network that serves as its foundation. This approach virtualizes each network node, including servers, switches, and routers, and manages them independently of the actual networks that support the virtualized architecture. SDN acts as a virtual overlay on the top of a physical (underlay) network.

### Hybrid SDN Model

A single network environment houses both software-defined networking and conventional networking protocols under the hybrid SDN approach. In order to enable various network operations, this SDN approach is used to provide appropriate protocols for the various types of network traffic. Using this technique, network administrators can gradually implement SDN into an existing network environment by continuing to use some of the normal networking protocols while delegating control of other traffic to SDN.

:::{seealso}
Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)
:::