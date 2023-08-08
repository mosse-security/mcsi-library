:orphan:
(secure-network-protocols)=

# Secure Network Protocols

Network protocols have been around for as long as there have been networks – but most of the protocols we rely on today were developed in an age when security was at best an afterthought, and often not a consideration at all. Today, it’s essential that we utilise protocols which are designed with security in mind wherever possible. In this article, we look at some of the most common secure protocols which you *should* be using in your network today! 

## Insecure Network Protocols

Before we dive into secure protocols, let's take a moment to appreciate some of the problems with their older, *insecure* predecessors. Perhaps the biggest and most common issue is a lack of data confidentiality. Many older protocols were developed at a time when few people ever had access to a network, so the danger of an attacker “listening on the wire” was often not considered. Today, however, it’s trivial for an attacker to capture traffic on a link, and anything transiting in clear text exposes sensitive data - such as login credentials, personal information, and financial details.

Another critical issue is the absence of data integrity and authenticity. Insecure protocols do not offer mechanisms to verify the integrity of transmitted data or the authenticity of the sender. This leaves the communication vulnerable to tampering and impersonation attacks, where attackers can modify or forge data, leading to erroneous actions, unauthorized access, or malicious commands being executed.

Insecure protocols are also especially prone to man-in-the-middle attacks. Attackers can intercept communication between a client and a server and secretly relay messages between them, without either party being aware. This allows attackers to capture sensitive information or inject malicious content into the communication, leading to potential data breaches, financial loss, or unauthorized system access.

Finally, insecure protocols often lack robust authentication mechanisms. Without strong authentication, unauthorized users can gain access to systems, networks, or services, posing a significant security risk.

Hopefully, it’s already becoming clear why using secure protocols is important! Let’s now take a look at some key ones.

## Domain Name System Security Extensions (DNSSEC)

Domain Name System (DNS) is a crucial component of the internet that translates human-readable domain names (e.g., www.example.com) into machine-readable IP addresses (e.g., 192.168.0.1). Traditional DNS lacks inherent security measures, making it vulnerable to various attacks like DNS spoofing and DNS cache poisoning. In these attacks, malicious actors manipulate DNS data to redirect users to fraudulent websites or intercept their communications.

DNS Security Extensions (DNSSEC) is a secure protocol designed to address these vulnerabilities. It adds digital signatures to DNS data, ensuring the authenticity and integrity of DNS information. When a DNS resolver queries a DNSSEC-enabled domain, the response includes cryptographic signatures that can be verified against the domain's public key. This process prevents attackers from modifying DNS data without detection, providing assurance to users that the resolved IP addresses are legitimate.

DNSSEC protects users from being redirected to malicious websites and helps maintain the overall security and reliability of the DNS infrastructure. Despite its benefits, DNSSEC adoption has been gradual, and not all domains are DNSSEC-enabled. Nevertheless, DNSSEC continues to play a vital role in strengthening the security of the internet's domain name system.

*Tip: DNS does exactly the same job for IPv6 addresses!*

## Secure Shell (SSH)

Secure Shell (SSH) is a cryptographic network protocol used to securely access and manage network devices remotely. In the past, protocols like Telnet and rlogin were widely used for remote access, but they transmitted data in clear text, leaving it susceptible to interception and eavesdropping. This lack of encryption made it easy for attackers to capture sensitive information, including passwords and commands exchanged between the client and the server.

SSH replaced these insecure protocols by providing secure encrypted communication between the client and server. It uses public-key cryptography to authenticate the remote server and establish a secure connection. Once the connection is established, all data transmitted between the client and server is encrypted, ensuring confidentiality and integrity.

SSH is widely adopted across various operating systems and networking devices, making it the standard choice for secure remote access and secure file transfer. Its strong security features have made it a crucial component in the management and administration of IT systems. Unfortunately, many network administrators contribute to leave telnet enabled on a device as a backup – while this can be tempting from a “just in case” point of view, doing so significantly increases the attack surface.

## Secure/Multipurpose Internet Mail Extensions (S/MIME)

Email is a fundamental communication method in the digital world, but traditional email protocols like SMTP (Simple Mail Transfer Protocol) transmit messages in plain text, leaving them vulnerable to interception and tampering during transit. This lack of security exposes email communications to eavesdropping, impersonation, and modification by attackers.

Secure/Multipurpose Internet Mail Extensions (S/MIME) is a cryptographic protocol that adds security features to email communications. It provides encryption and digital signing of email messages, preventing unauthorized access to email content and verifying the authenticity of the sender. When an email is digitally signed, the recipient can verify the sender's identity and ensure that the message has not been altered during transit.

S/MIME uses public-key cryptography to encrypt the email content, ensuring that only the intended recipient can decrypt and read it. Additionally, digital signatures are based on the sender's private key, which can be verified using the sender's public key. This process ensures the integrity of the email and provides assurance that the message indeed came from the claimed sender.

By implementing S/MIME, organizations and individuals can significantly enhance the privacy and security of their email communications, protecting sensitive information from unauthorized access and maintaining the trustworthiness of email exchanges.

## Secure Real-time Transport Protocol (SRTP)

Real-time communication applications, such as voice and video conferencing, rely on the Real-time Transport Protocol (RTP) to transmit media streams. However, RTP does not include built-in security mechanisms, which can expose these sensitive communications to interception and eavesdropping.

Secure Real-time Transport Protocol (SRTP) was developed to address the security shortcomings of RTP and ensure the confidentiality and integrity of real-time multimedia data during transmission. SRTP adds encryption and authentication features, making it suitable for secure communication over untrusted networks, like the internet.

SRTP uses symmetric key cryptography to encrypt the media streams, and it includes mechanisms to verify the integrity of the data, detecting any tampering or alteration during transit. The encryption keys are typically exchanged during a separate handshake process, ensuring that only authorized parties can decrypt and access the media content.

By adopting SRTP, applications that rely on real-time communication can ensure the privacy and security of their multimedia data.

## Lightweight Directory Access Protocol Over SSL (LDAPS)

The Lightweight Directory Access Protocol (LDAP) is a widely used protocol for accessing and managing directory services containing user and network information. However, traditional LDAP operates over plain text connections, potentially exposing sensitive data, such as user credentials and other personal information, to interception and unauthorized access.

Lightweight Directory Access Protocol Over SSL (LDAPS) addresses these security concerns by adding a layer of encryption through SSL/TLS (Secure Sockets Layer/Transport Layer Security). LDAPS establishes a secure encrypted channel between the client and the LDAP server, ensuring that all data exchanged during the directory service operations is encrypted and protected from eavesdropping.

When a client connects to an LDAPS-enabled server, the SSL/TLS handshake process is initiated, allowing the client and server to negotiate encryption settings and exchange cryptographic keys. Once the secure channel is established, all subsequent LDAP operations are conducted within the encrypted tunnel, preventing unauthorized access to sensitive information.

LDAPS provides organizations with a secure and reliable means of managing directory services while safeguarding the privacy of user and network data. It is particularly essential when managing large-scale systems, such as enterprise networks or authentication and authorization services.

## File Transfer Protocol, Secure (FTPS)

File Transfer Protocol (FTP) is a widely used protocol for transferring files between a client and a server. However, traditional FTP operates over clear text connections, making it susceptible to interception and unauthorized access to sensitive data, including login credentials and file contents.

File Transfer Protocol, Secure (FTPS) addresses these security concerns by adding a layer of security through SSL/TLS (Secure Sockets Layer/Transport Layer Security). FTPS establishes a secure and encrypted channel between the client and the FTP server, ensuring that all data transmitted during file transfers is encrypted and protected from eavesdropping.

FTPS can operate in either an explicit or implicit mode. In explicit mode, the client explicitly requests SSL/TLS security before starting the FTP session, whereas, in implicit mode, the SSL/TLS connection is established immediately upon connecting to the FTP server.

*Tip: FTPS is less widely used today, more often than not a secure FTP implementation will be using SFTP (see next section)*

## SSH File Transfer Protocol (SFTP)

SSH File Transfer Protocol (SFTP) is often confused with FTPS due to their similar names, but they are entirely different protocols. SFTP does not rely on FTP but rather operates over the SSH protocol, taking advantage of its strong encryption and authentication capabilities.

Unlike traditional FTP, which operates over clear text connections, SFTP establishes a secure encrypted channel between the client and the server. It provides secure file transfer capabilities, ensuring confidentiality and integrity of data during transit.

SFTP uses the same port as SSH (port 22) and leverages SSH's user authentication mechanisms, making it straightforward to integrate into existing SSH infrastructures. Users can securely transfer files and manage remote file systems without exposing sensitive data to potential eavesdropping or unauthorized access.

Due to its strong security features and ease of integration with existing SSH implementations, SFTP has become the preferred choice for secure file transfers in a wide range of applications, including server administration, backup solutions, and content management systems.

## Simple Network Management Protocol, version 3 (SNMPv3)

Simple Network Management Protocol (SNMP) is a standard protocol used for monitoring and managing network devices and services. However, earlier versions of SNMP (v1 and v2c) had significant security shortcomings, such as transmitting data in clear text and lacking strong authentication and encryption mechanisms.

SNMPv3 addresses these security weaknesses by adding important security features. It introduces message integrity and authentication through the HMAC-MD5 or HMAC-SHA algorithms, ensuring that SNMP messages are not altered during transmission and that they come from legitimate sources.

Additionally, SNMPv3 supports data encryption using the DES (Data Encryption Standard), AES (Advanced Encryption Standard), or 3DES (Triple Data Encryption Standard) algorithms, providing confidentiality for sensitive information within SNMP messages.

## Hypertext Transfer Protocol over SSL/TLS (HTTPS)

Hypertext Transfer Protocol (HTTP) is the foundation of data communication on the World Wide Web. However, regular HTTP transmits data in clear text, making it susceptible to interception and man-in-the-middle attacks, where attackers can intercept sensitive data exchanged between clients and servers.

Hypertext Transfer Protocol over SSL/TLS (HTTPS) addresses these security concerns by adding encryption and data integrity through SSL/TLS. HTTPS uses a combination of asymmetric and symmetric encryption to secure the communication between a client's web browser and a web server.

During the SSL/TLS handshake process, the client and server exchange cryptographic keys, which are used to encrypt and decrypt data during the session. This ensures that all data transmitted between the client and server, including login credentials, financial information, and other sensitive data, is encrypted and protected from unauthorized access.

HTTPS is widely used for secure web browsing, online transactions, and protecting sensitive information on websites. Web browsers display a padlock icon and "https://" in the address bar to indicate a secure HTTPS connection, providing users with confidence that their data is being transmitted securely.

## IPSec (Authentication Header (AH)/Encapsulating Security Payloads (ESP))

IPSec (Internet Protocol Security) is a suite of protocols designed to secure data at the IP layer of the internet communication. It provides two main security services: Authentication Header (AH) and Encapsulating Security Payloads (ESP).

Authentication Header (AH) ensures the integrity and authenticity of IP packets by adding a digital signature to the packet's header. This signature is calculated using the packet's content and a shared secret key. The recipient can use the same key to verify the authenticity of the packet and detect any tampering.

Encapsulating Security Payloads (ESP) provides confidentiality by encrypting the entire IP packet, protecting the packet's payload from eavesdropping. It also includes a header to ensure the integrity and authenticity of the encrypted data.

IPSec can operate in two modes: Transport mode and Tunnel mode. In Transport mode, only the data payload is encrypted, making it suitable for securing communication between two end hosts. In Tunnel mode, the entire IP packet is encrypted and encapsulated within a new IP header, making it ideal for securing communication between two gateways.

IPSec is widely used for securing virtual private networks (VPNs) and establishing secure communication tunnels between networks or remote sites. It plays a crucial role in ensuring the privacy and integrity of data transmitted over the internet.

## IPSec (Tunnel/Transport)

As mentioned earlier, IPSec provides two modes of operation: Tunnel mode and Transport mode. These modes determine how IPSec secures data at the IP layer.

Tunnel mode encrypts the entire IP packet and adds a new IP header, making it suitable for securing communication between two gateways, such as VPN gateways or routers. The original IP header becomes the payload of the new IP header, ensuring that the original source and destination addresses are hidden from potential eavesdroppers.

Transport mode, on the other hand, only encrypts the data payload of the IP packet. It is used for securing communication between two end hosts, such as a client device and a server. In Transport mode, the original IP header remains intact, and only the data being transmitted between the end hosts is encrypted.

Both Tunnel and Transport modes of IPSec provide essential security features, ensuring the confidentiality, integrity, and authenticity of data at the IP layer. The choice of mode depends on the specific security requirements and the network architecture being deployed.

## Post Office Protocol (POP) and Internet Message Access Protocol (IMAP) over SSL/TLS

Post Office Protocol (POP) and Internet Message Access Protocol (IMAP) are email retrieval protocols used to access email from a mail server. In their original versions (POP3 and IMAP), these protocols transmitted data, including login credentials and email content, in plain text.

To address the security concerns associated with transmitting sensitive information in the clear, modern versions of POP and IMAP now support SSL/TLS encryption. When users connect to a mail server using POP3 or IMAP with SSL/TLS, the communication channel between the email client and the server is encrypted, protecting the data from eavesdropping and unauthorized access.

In the case of POP3, the secure version is commonly known as POP3S, while for IMAP, it is typically referred to as IMAPS. Both POP3S and IMAPS use well-known ports (995 for POP3S and 993 for IMAPS) to establish secure connections between the email client and the mail server.

By enabling SSL/TLS encryption for POP and IMAP, users can access their email securely and ensure that their login credentials and email content remain confidential during transmission. This extra layer of security significantly enhances the privacy and protection of email communications in modern email clients and servers.

## Ports

While some secure protocols can run on the same ports as the original version, more often than not the new protocols have been assigned separate ports. It’s advisable to know the following key ones: 

| **Insecure   Protocol** | **Original Port** | **Secure Protocol**     | **New Port**  |
| ----------------------- | ----------------- | ----------------------- | ------------- |
| DNS                     | 53 (TCP/UDP)      | DNSSEC                  | 53 (TCP/UDP)  |
| Telnet, rlogin          | 23 (TCP)          | SSH                     | 22 (TCP)      |
| SMTP                    | 25 (TCP)          | S/MIME                  | N/A           |
| RTP                     | N/A               | SRTP                    | N/A           |
| LDAP                    | 389 (TCP)         | LDAPS                   | 636 (TCP)     |
| FTP                     | 21 (TCP)          | FTPS                    | 990 (TCP)     |
| FTP                     | 21 (TCP)          | SFTP                    | 22 (TCP)      |
| SNMP (v1, v2c)          | 161 (UDP)         | SNMPv3                  | 161 (UDP)     |
| HTTP                    | 80 (TCP)          | HTTPS                   | 443 (TCP)     |
| POP3/IMAP               | 110/143 (TCP)     | POP/IMAP (over SSL/TLS) | 995/993 (TCP) |

## Final words

While there can be some complications and the process is sometimes time consuming, moving to secure protocols is crucial in today's digital landscape due to the increasing sophistication of cyber threats and the growing reliance on internet-based services. Secure protocols provide a robust defence against a wide range of security risks, such as eavesdropping, data tampering, identity impersonation, and information theft. By adopting secure protocols like DNSSEC, SSH, S/MIME, SRTP, LDAPS, FTPS, SFTP, SNMPv3, HTTPS, IPSec, and POP/IMAP over SSL/TLS, organizations and individuals can significantly improve their data protection and communication security.  Ultimately, the migration to secure protocols is a fundamental and necessary step in establishing a resilient defence against the ever-evolving threats we face today. 