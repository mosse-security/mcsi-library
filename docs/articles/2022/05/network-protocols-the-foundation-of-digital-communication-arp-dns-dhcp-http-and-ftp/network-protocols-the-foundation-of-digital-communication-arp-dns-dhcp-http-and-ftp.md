:orphan:
(network-protocols-the-foundation-of-digital-communication-arp-dns-dhcp-http-and-ftp)=

# Network protocols: The Foundation of Digital Communication - ARP, DNS, DHCP, HTTP and FTP

Our [previous blog post about network protocols](network-protocols-the-foundation-of-digital-communication-tcp-udp) covered the foundational protocols TCP/IP and UDP. In the additional parts of the Network protocols series, we will cover other protocols that almost all rely on TCP/IP or UDP to function. This article will continue with ARP, DNS, DHCP, HTTP and FTP.

## ARP

While packets are sent over long distances, the Address Resolution Protocol (ARP) is a layer two protocol. For more information about network layers, see our blog post about the OSI model on the 8th of May. As a layer two protocol, ARP only sends data locally and thus is limited to Local Area Networks (LAN). ARP locates the hardware or MAC addresses needed for this local communication. Whereas IP addresses are used to get data to the external networks via routers, MAC addresses are necessary to get the data to the intended device within the LAN. That device can be a router or another host on the same network. If a packet needs to be sent to another network, the sender will check to see if it has the MAC address of the gateway in its cache.

ARP has a cache that keeps track of bindings between IP addresses and layer two addresses. If the host does not have a binding in its cache, it will send an ARP broadcast to all devices in the LAN with the router's IP address and asks, 'who has this IP address, and can I have your MAC address?'. The gateway will send an ARP reply to the host with its MAC address. The host can now send the packet to the gateway for forwarding. The gateway will go through a similar ARP process before sending the packet to another router. It will first check the destination IP address and determine the next hop or next router and which interface is attached to this network. Then it checks whether it has the MAC address of the next-hop device. If not, it will send an ARP request too. If it gets the reply, it will forward the packet to the next hop. The destination MAC addresses thus constantly change in this process, while the destination IP address remains the same.

The ARP protocol is not dependent on TCP/IP or UDP. Rather, it is an essential component of the TCP/IP and UDP communications process. ARP is necessary for the TCP/IP and UDP suite to function.

## DNS

The Domain Name System (DNS) is like a phone directory for the internet and provides essential information about domains and IP addresses.

It converts domain names such as www.google.com to an IP address. Humans work with domain names, and computers work with IP addresses, so a constant translation process occurs. There is not just one DNS server because there are so many domains and IP addresses. DNS is a worldwide network that consists of thousands of DNS servers that work in a hierarchy. When your computer searches for the IP address associated with a domain name, it will first ask a local DNS server if it has this IP address. A local DNS server may be the server of the organisation you are working for or your ISP server. This DNS server is a recursive resolver, and it might have cached the DNS information. If this is not the case, it will reach out to one of the 13 root servers. These hundreds of servers are located worldwide that belong to 13 organisations. One of the root servers will provide your local DNS server with a referral to an authoritative DNS server. Authoritative DNS servers hold information about top-level domains such as .com, .edu, .edu.au, .net and provide your local server with a point of contact for the domain. Finally, when your local server has gotten the IP address of the authoritative server, it will receive the IP of another authoritative DNS server that serves the specific domain you are looking for, for example, google.com. This authoritative server, at its turn, will deliver you the needed IP address of the machine within the domain. DNS uses both TCP/IP and UDP but in very different circumstances. UDP is used when a user types in a web address and the computer sends a DNS query.

UDP is faster, and the loss of a packet is not critical. A client can send a new request again if necessary. TCP/IP is used between DNS servers, for instance, when certain servers have to update their records. This information must be correct. If these servers are queried and provide the wrong information, clients might not be able to reach the website or resource. Because TCP/IP is reliable and does error checking, these DNS processes use TCP/IP.

## DHCP

DHCP is an acronym for Dynamic Host Configuration Protocol.

It is a network protocol that assigns an IP address to each device connected to a network. DHCP is designed to provide dynamic addressing of IP addresses and is configured instead of assigning static IP addresses manually. Manually assigning IP addresses is a time-consuming task, especially in larger organisations. It also significantly increases the risk of IP address conflicts where devices receive the same IP address. When a client computer connects to a network it will request an IP address from the server. If there are addresses available in the dynamic pool, the server selects one and assigns it to the host, tying the logical IP address to the physical Mac address of the device for some time. That is referred to as a lease. The client attempts to extend the lease before it expires to maintain network access. IP addresses can also be reserved and excluded from the range for special purposes. The process of requesting and assigning IP addresses is also denoted with DORA. DORA is an abbreviation for four distinct DHCP message types: discover, offer, request, and acknowledge. A client that wants to get an IP address broadcasts a discover message to reach out to the DHCP server. It is a broadcast because it doesn't yet know the server's IP address. The DHCP server will send an offer back with an IP address and other information such as the netmask and IP of the gateway to connect to the internet and other remote networks. Then the client sends a request back to the server that it accepts this information, to which the DHCP server replies with an acknowledgment.

DHCP uses UDP as a transport protocol as messages have to be broadcasted by the client that has not yet got an IP address. TCP can only work when two end-points have an IP address to establish the connection.

## HTTP/S

HTTP is an acronym for Hypertext Transfer Protocol.

The protocol allows web servers to send files to web browsers to display them for users. When an SSL certificate secures a website, HTTPS is the used protocol. HTTP is vulnerable to person-in-the-middle and eavesdropping attacks since it is not encrypted. Attackers may be able to access web accounts and sensitive information. Attackers with access to a web account can change webpages and inject malware. HTTPS was developed to handle such attacks.

HTTPS provides authentication and encryption between the client and server. As users interact with web pages or other web applications, their browser generates HTTP requests. When a user clicks on a hyperlink, the browser sends a sequence of "HTTP GET" requests for the content on that website. The server that reaches the HTTP requests will generate an HTTP response. HTTP needs reliable message transport as errors may result in incorrect or incomplete information in HTTP responses. A client then may not be able to reach the desired website.

TCP is more reliable than UDP, and thus, HTTP uses TCP.

## FTP/S

File Transfer Protocol (FTP) is a protocol that is used to transfer files over a network.

The benefit of using FTP over other methods it that FTP can handle large file transfers. Administrators can control who can upload, download, remove, modify, and distribute files using FTP servers. An FTP connection requires two participants. Users must be granted access by submitting credentials to the FTP server. FTP was not designed to be secure. It is an unsafe protocol since it uses clear-text usernames and passwords for authentication as there is no encryption. That makes FTP vulnerable to sniffing, spoofing, and brute force assaults, among other attack methods. FTPS is FTP with SSL/TLS and provides extra security with encryption. FTPS works by authenticating clients and servers through certificates, which are used to encrypt connections and provide authentication and authorization.

Some public FTP sites may not need authentication to access their data. That is called anonymous FTP. When establishing an FTP connection, there are two separate communication channels. The first is known as the command channel, and it is responsible for initiating the instruction and response. The other is a data channel, where the actual data is distributed.

As you might have guessed, FTP solely employs the TCP transport protocol. It never uses UDP for transport as it is critical to transfer files correctly.

:::{seealso}
Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)
:::
