:orphan:
(the-osi-model-a-framework-for-data-transmission)=

# The OSI Model: A Framework for Data Transmission

The electronic transfer of information (audio, video, or data) over vast distances between electronic equipment is known as telecommunication. Data can be transmitted using either wired (coaxial, ethernet, or fiber optic connections) or wireless techniques. Telecommunication and networking employ a variety of processes, devices, software, and protocols. Over time, different models have evolved to better describe data flow between devices utilizing various protocols. A protocol is a set of instructions or rules that govern data transmission between electronic devices. Most operating systems and protocols adhere to the OSI model as an abstract framework. The purpose of this article is to explore this model and how it may be used to visualize the process of data transmission over a network.

## What is the OSI Model?

In the early 1980s, ISO (International Standards Organization) established the OSI (Open Systems Interconnection) model. The ISO-7498 standard was created as a conceptual framework for standardizing information transmission between various systems.

The networking duties, protocols, and services are divided into seven different layers in this model. Each layer is responsible for the information flow between two interacting nodes in its own way. Vendors can utilize this model as a starting point for developing their own networking architecture and reducing interoperability issues between different devices.

The TCP/IP model is used in the majority of modern internet implementations. However, understanding the functionalities that occur at each tier of the OSI model, as well as the accompanying protocols, can help you truly comprehend the overall network communication process.

## How the OSI model can help achieve your security goals?

As described above, the OSI model is used to break down network communication into seven layers. This model can assist security professionals in understanding the types of attacks that can occur at each layer, as well as the appropriate security measures that can be used to assure network security.

## Layers of the OSI model:

Let's take a closer look at each of the OSI model's seven layers now that we've covered the basics. We will review these layers using the top-down approach.

### Application Layer:

The application layer is the 7th layer of the OSI model and is closest to the end-user. The application layer is the interface between the application and the network. This layer is used by the end-user application/software for functions including message exchange, file transmission, and much more.

This layer's job is to collect data from the application that needs to be delivered to the destination and send it along to the supporting protocol. An example will help you grasp this concept.

Let's suppose you are using your Outlook email account to send an important business email to a client. As a result, Outlook is the program that you use to deliver the data, which is the information contained in the email. The application layer's task now is to take this email and transfer it to a suitable protocol, such as SMTP (Simple Mail Transfer Protocol). Thus SMTP is the supporting protocol that will be used for the transmission of the data.

The application layer takes the data from the corresponding application, adds the necessary information for its communication, and passes it onto the layer directly underneath it. This process is repeated for each layer until it reaches the destination computer. Some of the protocols that are supported at this layer are:

<u>1. HTTP(Hypertext Transfer Protocol):</u>
HTTP is an application layer protocol used for transporting data (text, audio, video, etc.)
across the internet.

<u>2. FTP(File Transfer Protocol):</u> FTP is an application layer protocol used for file transfer between two nodes over a computer network.

<u>3. SMTP(Simple Mail Transfer Protocol):</u> SMTP is an standard protocol for email transmission.

<u>4. DNS(Domain Name System):</u> DNS protocol is used to resolve the Domain Name of a system to its IP address.

### Presentation Layer:

This is the 6th layer of the OSI model. This layer receives the data from the application layer. The presentation layer is not concerned with the data itself but with the syntax and format of the data. The purpose of this layer is to attach necessary format information with the data so that it can be easily viewed at the destination computer.
This can be understood with the example of image files.

Every day, we send and receive several images via the internet. PNG (Portable Network Graphics), JPEG (Joint Photographic Experts Group), TIFF (Tagged Picture File Format), or GIF (Graphics Interchange Format) are all examples of image formats. Each image file type has its own format. The presentation layer adds special format information to an image file transferred from the source computer to the destination computer, telling the destination computer how to process and present the image. The presentation layer ensures that file format information is transformed into a standard format that can be easily interpreted regardless of the program used at the destination.

Data compression and encryption are also handled by the presentation layer. If the sender's application requires that the data be encrypted or compressed before being sent over the network, the presentation layer delivers the necessary information, such as encryption algorithms and compression techniques. The application on the destination computer will use this information to determine which program/techniques should be used for decryption or decompression. The following protocols are used at this layer:

<u>1. MIME(Multipurpose Internet Mail Extension):</u>
MIME is an extension of the SMTP protocol and is used to exchange different types of files (audio, video, text, or image)
over email.

<u>2. AFP(Apple Filling Protocol):</u> AFP is a proprietary network protocol developed by Apple and is used to transfer files over a network.

<u>3. LPP(Light-Weight Presentation Protocol):</u> LPP protocol is used to provide ISO presentation services for the data transported over the network.

<u>4. NDR(Network Data Representation):</u> NDR is an implementation of the presentation layer. NDR is used with Distributed Computing Environment and Remote procedure calls on the internet.

### Session Layer:

The Session Layer is the 5th layer of the OSI model. The connection between the two programs is established, maintained, and terminated using this layer. This layer gets data from the presentation layer and is in charge of transferring it to end-user applications.

The processes occurring at the session layer are collectively called dialog management. Dialog management begins with connection establishment. In connection establishment, the requirements of communication transfer are imposed. After this phase, data transfer is initiated. Finally, after all the data is transferred the connection is released. The data transfer in the session layer can take place in one of the three modes:

<u>1. Simplex mode:</u>
In simplex mode the information transfer is unidirectional.

<u>2. Half Duplex mode:</u>
The information flow is bidirectional in half duplex mode, but only one entity can transfer data at a time.

<u>3. Full Duplex mode:</u>
The information flow is bidirectional in full duplex mode, with both entities able to send and receive data at the same time.

The information transfer occurring at the session layer takes place through RPC(Remote Procedure Calls). RPC occurs when an application on one computer end calls another application located on another computer without having to know the details of the application on the receiving system. In the entire communication process, the session layer protocols operate as a bridge between two separate applications.

Session layer protocols must provide authentication capabilities to ensure the security of the communication session. Network security administrators should configure the firewalls to only allow the connections that are from within the network. Some of the protocols that are used at this layer are:

<u>1. PAP(Password Authentication Protocol):</u> PAP is used to authenticate users using passwords in a point-to-point connection.

<u>2. PPTP(Point-to-point Tunneling Protocol):</u> PPTP is a secure communication protocol that is used to establish a VPN connection between two end points.

<u>3. NetBIOS(Network Basic Input Output System):</u>
NetBIOS protocol enables applications on different computers to communicate with each other and access shared resources over LAN(Local Area Network)

<u>4. RPC(Remote Procedure Call):</u> RPC protocol allows an application on one computer to call a procedure on another application without having to know the application details on the receiving end.

### Transport Layer:

The transport layer is the 4th layer of the OSI model. This layer is responsible for end-to-end communication between two computers. The main difference between session layer and transport layer communication is that session layer communication occurs between two applications, whereas transport layer communication occurs between two computers, independent of the applications running on both computers

The transport layer receives data from multiple applications and assembles it into a stream of packets before sending it across the network. On the receiving end, these packets are reassembled in the correct sequence using a numbering mechanism. Data transfer reliability, error detection and repair, data recovery, and flow control management are also handled by this layer. There are two main protocols used at the transport layer:

<u>1. TCP(Transmission Control Protocol):</u> TCP is a connection-oriented transport layer protocol that ensures packets arrive at their intended destination. During transmission, the TCP protocol can detect lost or damaged packets. Thus it signals the source to resend packets that are missing or damaged. This protocol also has the capacity to detect packet congestion and adjust the packet flow accordingly.

Before establishing a connection between two computers, TCP performs a three-way handshake. The amount of data that will be shared between the two nodes, data integrity verification, and data loss discovery techniques are all negotiated via a TCP three-way handshake.

<u>2. UDP(User Datagram Protocol):</u> The UDP protocol is a connectionless transport layer protocol, which means it does not ensure packet delivery to the intended destination. It also lacks advanced features like packet sequencing and flow management. In comparison to TCP, UDP is a faster transport layer protocol.

### Network Layer:

The 3rd OSI layer is the network layer. This layer receives packets from the transport layer and is in charge of routing them to their intended destinations. The delivery of network datagrams to the destination is not guaranteed by the network layer. This is the responsibility of the transport layer.

To generate a map of the network, the protocols at the network layer create, use, and update routing tables. The best path for delivering datagrams to their destination is then determined using these tables. The most often used protocol at this layer is IP (Internet protocol). The Internet Protocol is in charge of sending and receiving datagrams across the internet. Some other protocols at this layer are:

<u>1. RIP(Routing Information Protocol):</u> The RIP protocol is an outdated protocol that employs the distance-vector routing approach. The shortest distance between the sender and receiving computer is calculated using hop count.

<u>2. OSPF(Open Shortest Path First):</u> The OSPF protocol calculates the shortest path from the sender to the recipient computer using the link-state algorithm. This protocol enables the routing database to be updated frequently in order to determine end-to-end pathways.

<u>3. BGP(Border Gateway Protocol):</u> The BGP is an exterior gateway protocol that enables the global routing of information between edge routers.

<u>4. ICMP(Internet Control Message Protocol):</u> The ICMP protocol is used to exchange network-related errors and operational messages between different devices.

### Data Link Layer:

The Data Link Layer is the 2nd layer of the OSI model. This layer receives network datagrams from the network layer above it and converts them into LAN(Local Area Network) or WAN(Wide Area Network) frames.

A local area network (LAN) is a computer network that connects devices in a small area using Ethernet or WiFi.

A WAN is a large computer network that interconnects computing devices over greater distances.

The data link layer specifies how the communication devices will interact with the underlying network. Ethernet, Token Ring, ATM (Asynchronous Transfer Mode), and FDDI(Fiber Distributed Data Interface) are the most common network technologies. This layer will take data from the layer above it and convert it into a format (frames) that the underlying network can understand. The Ethernet network has a different frame format and length than the Token Ring network. Thus it is the responsibility of this layer to convert the format of the data according to the network type.

LLC (Logical Link Control) and MAC (Media Access Control) are the two functional sublayers of this layer.

The network layer and the LLC layer communicate directly. This layer is in charge of flow control and error detection. The data arriving at the data link layer is acknowledged by the LLC sublayer, which also detects errors during transmission. If a frame is lost, the source is notified and the frame is retransmitted.

The MAC layer receives frames from the LLC layer, adds headers and trailers, and forwards them to the physical layer for transmission. This layer gives a frame, a source and destination address, so that it can be sent to a specific network device. The MAC layer directly interfaces with the physical layer below it and controls the access to the physical transmission channel. Some of the protocols at the data link layer are:

<u>1. ARP(Address Resolution Protocol):</u>
ARP protocol is used to convert the IP address(on the datagram from the network layer)
to the physical MAC address of the destination device.

<u>2. RARP(Reverse Address Resolution Protocol):</u> RARP protocol is used for the translation of the device's physical MAC address to the IP address.

<u>3. PPP(Point-to-Point Protocol):</u> PPP protocol is used for direct communication between the two communicating devices.

<u>4. HDLC(High-Level Data Link Control):</u> HDLC is a synchronous data communication protocol, which is used for serial device-to-device communication in WAN networks.

### Physical Layer:

The Physical Layer is the 1st layer of the OSI model. This layer deals with the physical medium connecting the computing devices. The frames from the data link layer are converted into data bits by network interface cards or drivers at the physical layer. After that, the data bits are transformed into electrical voltage signals that may be conveyed through physical media.

Physical features of transmission, including synchronization, data speeds, line noise, and transmission mechanisms, are controlled by protocols at this layer. The transmission medium can be guided, such as coaxial cables, twisted pair cables, fiber optic cables, and so on, or it can be an unguided wireless medium, such as air. Some of the protocols used at this layer are:

<u>
1. DSL(Digital Subscriber Line)
</u> DSL is a communication technology that is used for data transmission over telephone lines.

<u>
2. ISDN(Integrated Services Digital Network)
</u> ISDN is a set of communication protocols for sending voice, data, and other types of traffic over the public switched telephone network circuits in a digital format.

<u>
3. SONET(Synchronous Optical Networking)
</u> SONET is a telecommunication standard for data transmission over fiber-optic cables

:::{seealso}
Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)
:::
