:orphan:
(connectionless-vs-connection-oriented-protocols)=

# Connectionless vs Connection Oriented Protocols

Both connectionless protocols and a connection-oriented protocols have a valuable place in modern networking. The key difference between the two lies in how they handle data transmission. In a connection-oriented protocol, such as TCP (Transmission Control Protocol), a connection is established between the sender and receiver before data transfer, ensuring reliability, ordered delivery, and flow control. On the other hand, a connectionless protocol, like UDP (User Datagram Protocol), does not establish a connection before sending data; it simply sends packets without guaranteeing reliability, ordering, or flow control. This fundamental distinction makes connection-oriented protocols ideal for applications requiring data accuracy and completeness, while connectionless protocols are well-suited for real-time applications where low latency is crucial, despite the trade-off of reliability. Let’s look at TCP and UDP in some more detail. 

 

## TCP (Transmission Control Protocol) 

TCP (Transmission Control Protocol) is a communication method used in computer networks to ensure reliable and orderly data transmission between devices. It is part of the TCP/IP suite, which underpins the Internet and most networked applications. TCP is a connection oriented protocol, which establishes an ongoing connection between the sender and receiver before data transfer,ensuring data integrity.

**How TCP Works:**

- **Three-Way Handshake:** When two devices wish to communicate using TCP, they go through a three-way handshake process to establish a connection. The sender (client) initiates the connection by sending a SYN packet to the receiver (server), which responds with a SYN-ACK packet. Finally, the client sends an ACK packet, completing the handshake.
- **Reliable and Ordered:** TCP ensures that data sent from one device reaches the other reliably and in the correct order. If a packet is lost or corrupted during transmission, TCP retransmits it.
- **Flow Control:** TCP manages the flow of data between sender and receiver. It prevents congestion by regulating the rate at which data is sent based on the receiver's capacity.

**The major advantages of TCP include:** 

1. **Reliability:** TCP guarantees data delivery. It's ideal for applications where accuracy and completeness of data are critical, such as file transfers and web pages.
2. **Ordered Delivery:** Data sent via TCP arrives in the same order it was sent, ensuring that, for example, the words of a text document are displayed in the correct sequence.
3. **Flow Control:** TCP prevents network congestion and ensures that data is sent at a manageable pace.

**Whereas the disadvantages include:** 

1. **Overhead:** TCP introduces additional data for reliability and ordering, which can slightly slow down data transfer and increase network overhead.
2. **Latency:** For very short messages, the three-way handshake and flow control mechanisms can introduce slight delays.

Many of the services we rely on day to day run on TCP, this makes sense since reliable data transmission is often critical! Common use cases include:

- Browsing the web (loading web pages with text and images).
- Sending emails.
- Transferring files between devices.
- Remote desktop access.
- Online shopping and banking transactions.



## UDP (User Datagram Protocol) 

UDP (User Datagram Protocol) is another communication method in the TCP/IP suite. Unlike TCP, UDP does not establish a connection before sending data. It is often described as "fire and forget" or “best effort” because it sends data without ensuring reliability.

**How UDP Works:**

- **No Connection Establishment:** UDP does not go through a connection setup process like TCP's three-way handshake. It immediately sends data packets to the recipient without confirmation.
- **No Reliability Guarantees:** UDP does not guarantee the delivery of data packets or their order. Lost or out-of-order packets may occur.
- **Minimal Overhead:** UDP is lightweight, which means it has less network overhead than TCP. This makes it suitable for real-time applications.

**Despite the lack of reliability, UDP has some significant benefits – these are:**

1. **Low Overhead:** UDP is efficient and has minimal network overhead, making it ideal for real-time applications where low latency is crucial, such as online gaming and video conferencing.
2. **Reduced Complexity:** The absence of connection setup and management simplifies the protocol, reducing latency and resource usage.

**Of course, the major issues are:**

1. **No Reliability:** UDP does not ensure data delivery or order, which may lead to data loss or out-of-sequence packets.
2. **No Flow Control:** UDP provides no congestion control mechanisms, making it susceptible to network congestion and packet loss during high traffic conditions.

While UDP does not provide a reliable connection, in some applications speed and simplicity is much more important than reliability. UDP is often used for streaming, for example – should one or two data packets go missing as part of a video stream, the user probably wont even notice, however, if a video needs to buffer for a period of time while network overhead is processed, users tend to get impatient! UDP services include: 

- Voice and video calls over the internet (VoIP).
- Streaming live video and audio.
- Online multiplayer gaming.
- DNS queries for website resolution.
- Sending small, time-sensitive messages (e.g., network discovery).

**Common Connection-Oriented and Connectionless Protocols**

Below is a quick reference table for some common connection-oriented and connectionless protocols. There are of course many more, but these are some of the ones you'll most often see in the field. 

| Connection-Oriented (TCP)               | Connectionless (UDP)                       |
| --------------------------------------- | ------------------------------------------ |
| HTTP (Hypertext Transfer Protocol)      | DNS (Domain Name System)                   |
| FTP (File Transfer Protocol)            | DHCP (Dynamic Host Configuration Protocol) |
| SMTP (Simple Mail Transfer Protocol)    | SNMP (Simple Network Management Protocol)  |
| IMAP (Internet Message Access Protocol) | TFTP (Trivial File Transfer Protocol)      |
| SSH (Secure Shell)                      | Syslog (System Logging Protocol)           |
| HTTPS (HTTP Secure)                     | NTP (Network Time Protocol)                |
| Telnet (Remote Terminal Access)         | RTP (Real-time Transport Protocol)         |
| MySQL (Database Access)                 | SIP (Session Initiation Protocol)          |



# Final Words

Connection-Oriented Protocols like TCP ensure reliable, ordered data transfer and are suitable for applications requiring accuracy and completeness. Connectionless Protocols like UDP offer low overhead and are ideal for real-time applications where low latency is crucial. The choice between the two depends on the specific needs of the application.

 
