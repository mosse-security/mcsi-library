:orphan:
(network-protocols-the-foundation-of-digital-communication-tcp-udp)=

# Network protocols: The Foundation of Digital Communication - TCP & UDP

Network protocols are the foundation of digital communication. Without them, we would not be able to communicate with each other or with computers. In the world of digital communication, two main protocols manage nearly all traffic: TCP and UDP. At a high level, these protocols are responsible for ensuring that packets are delivered reliably and in order between devices. TCP is responsible for ensuring that data is transferred correctly and in the correct order. UDP is responsible for ensuring that data is transferred quickly. Both have their own advantages and disadvantages, so it's important to understand the difference between the two.

Let's take a closer look at them!

## Introduction

Why is knowledge of network protocols also important for cyber security specialists and not just system administrators and network engineers?

Because cyber security specialists help businesses guard against security breaches based on exploiting vulnerabilities in network protocols. The Simple Mail Transfer Protocol (SMTP), for example, is used by e-mail clients for outgoing e-mail messages. The protocol itself does not provide security, making it vulnerable to data leakage, spam, phishing, malware, DDoS attacks, and other attacks. When organisations use SMTP, they need to implement other measures to ensure SMTP works securely. Cyber security specialists assist businesses in adopting the best security strategies and measures for their specific situation. By doing so, they have to understand the protocols used that affect the organisation.

This blog series provides an overview of the most important network protocols. It starts with explaining TCP, IP, and UDP. These protocols, also known as the TCP/IP suite, are considered the foundational network protocols that other protocols rely on for their functioning. Other network protocols will be discussed in subsequent blog posts, what they do and whether they rely on TCP/IP or UDP or both.

## Transmission Control Protocol / Internet Protocol (TCP/IP)

TCP and IP are two separate protocols that work closely as a team. IP is responsible for obtaining the IP address as the destination address for the data. TCP is responsible for data delivery (including error correction) after locating the IP address. TCP/IP was designed to function regardless of network architecture. It is unaffected by the access method (operating system, network interface), frame format (the "envelop" used for sending the data), or media (the physical path such as cable type and airwaves).

TCP/IP transmits information in small pieces called packets. These packets are sent in sequential order to the destination device and are routed along the network by routers. TCP/IP is connection-oriented. That means that it is a reliable protocol. A connection is established between the devices to ensure the delivery of the packets without data loss. Devices send acknowledgments to each other about the data received. When a device needs to send data, it sends an opening acknowledgment. The transmitter sends a closing acknowledgment when finished with the transmission.

Many other protocols rely on TCP/IP to get their data across networks. One example is when a user requests a page from a server through a web browser. The browser sends an HTTP request to the web server. The web server also uses HTTP to send the requested webpage. The entire communication takes place via TCP. IP also plays a significant role because the sender and receiver need IP addresses to know where to send the requests and replies.
Examples of other protocols that use TCP/IP include Simple Mail Transfer Protocol (SMTP) for e-mail, Telnet for terminal emulation, and File Transfer Protocol (FTP) for file exchange.

## User Datagram Protocol (UDP)

UDP is, like TCP/IP, also a transport protocol, but there is a significant difference. While TCP is connection-oriented, UDP is a connectionless protocol. That means that UDP is faster than TCP; TCP traffic moves slower than UDP because of its function to establish a connection. The use of TCP/IP or UDP depends on what is important: speed or reliable data transfer?

Various important services and protocols use UDP. Examples are the Domain Name System (DNS), Simple Network Management Protocol (SNMP), and Dynamic Host Configuration Protocol (DHCP). Real-time activities, such as computer gaming and voice and video communication, are also sent through UDP. When watching a video, the glitches that you sometimes experience are data losses in the UDP transmission. There is no need to resend the lost data because the video continues to play. Resending the lost data would make your video images appear out of order.

## Final Words

Nowadays, almost all digital communication networks are based on the Internet Protocol (IP), and practically all applications use TCP or UDP (or both). In the next blog post, you can read about other network protocols with different functions, but remember, most rely on TCP/IP or UDP to perform their role.

:::{seealso}
Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)
:::
