:orphan:
(vpn)=

# Virtual Private Networks (VPNs)

With today's focus on technology-driven businesses and remote workforces, Virtual Private Networks (VPNs) have become a fundamental tool for ensuring secure communication and connectivity. VPNs serve as a powerful and cost-effective solution to protect sensitive data, maintain privacy, and facilitate seamless access to resources over the internet. 

Fundamentally, A Virtual Private Network (VPN) is nothing more than a secure and encrypted connection that allows users to access the internet or a private network from a remote location while ensuring the confidentiality and privacy of their data. By using encryption to create a secure tunnel between the user's device and the VPN endpoint, VPNs protect sensitive information from potential threats and unauthorized access. 

VPN’s bring a huge benefit in terms of mobility and security – however, they do have some common disadvantages. The first is that the encryption and tunnelling process of VPNs can add overhead, impacting network performance for resource-intensive applications. The second is that VPNs may result in reduced internet speed due to encryption and the additional routing process, particularly with lower-quality VPN services.

In the recent past (and still in some very large organisations) dedicated network devices known as VPN concentrators handled the work of encrypting and decrypting data which was passing over the VPN – however today many firewalls and even some routers have sufficient onboard processor capacity to handle this workload. 

## Remote Access vs. Site-to-Site VPN

VPN Solutions come in two major types – these are Remote Access VPNs and Site-to-Site VPNs. While the technology which underpins the VPN is similar, the intended use is different. 

### Remote Access VPN

Remote access VPN’s are designed to provide secure connectivity for individual users or devices over the internet to an organization's internal network. When remote employees, travelling workers, or mobile devices need access to internal resources such as files, applications, or intranet websites, a remote access VPN allows them to establish a secure tunnel to the organization's network. If you’ve used a VPN to access your work or school network, this was the type of VPN you were using. 

### Site-to-Site VPN

Site-to-Site VPNs, also known as router-to-router VPNs, create secure connections between multiple locations or networks, such as branch offices or data centres. The purpose of a site-to-site VPN is to enable seamless and secure communication between geographically dispersed networks as if they were part of the same local network.

Site-to-Site VPNs establish encrypted tunnels between the network gateways at each location, allowing data to traverse securely between them. Whereas in the past, businesses or organisations would need to approach a service provider and purchase a leased line to provide a physical connection between their two (or more) locations, modern VPN solutions use encryption to pass traffic over the internet. Sending traffic over a private leased line *is* more secure in theory (since no one but the line user should have access to the connection) however by using strong encryption to make the data unreadable to all but the authorised parties, data can be safely passed over a normal internet connection - this is *much* more cost-effective. 

## Always-on VPN

Always-on VPN, also known as persistent VPN or automatic VPN, isn’t exactly a type of VPN – rather it’s a configuration that ensures the VPN connection remains active and continuously secures network traffic, even when the device is not actively in use. The purpose of an Always-on VPN is to enforce a consistent level of security and privacy for devices that are authorized to connect to an organization's network.

The primary advantage of an Always-on VPN is that it prevents data leaks and unauthorized access. By maintaining an "always on" state, the device automatically connects to the VPN whenever it connects to the internet, safeguarding sensitive data from potential threats, such as man-in-the-middle attacks or unintended exposure when users forget to initiate the VPN connection.

## Split Tunnel vs. Full Tunnel

Split tunnelling and full tunnelling are two contrasting approaches to routing internet traffic through a VPN and apply mainly to remote access VPN connections. Each has distinct advantages and use cases:

- **Split  tunnelling:** In split tunnelling, only traffic destined for the organization's internal network is routed through the VPN. All other internet-bound traffic is directed to the user's regular internet connection. Split tunnelling improves internet performance by reducing the load on the VPN server, but it also raises security concerns. Any compromised device could expose internal resources to potential threats when accessing the internet.
  
- **Full Tunnelling:** Full tunnelling, on the other hand, routes all internet traffic through the VPN, regardless of its destination. This ensures that all communication, including internet browsing, is encrypted and passes through the organization's security infrastructure. While full tunnelling provides enhanced security, it can also result in increased VPN server load and potentially slower internet access due to the additional encryption overhead.

The choice between split tunnelling and full tunnelling depends on the organization's security requirements, available network resources, and the risk appetite for exposing internal traffic.

*Tip: Performance issues are not the only concern with Full Tunnelling – although this is the one you’re most likely to see mentioned. Full Tunnelling can also raise privacy concerns, as users can easily route private information or personally identifiable information through a company network without realising it (simply by forgetting to disconnect the VPN). This leaves a company holding information that it may have had no intention to collect and may not have proper procedures to identify and dispose of.* 

## IPSec (Internet Protocol Security)

IPSec is a suite of protocols used to establish secure and authenticated communication over IP networks, such as the Internet. It provides a robust framework for encryption, authentication, and integrity verification of IP packets. IPSec operates at the network layer (Layer 3) of the OSI model and can be used in both remote access and site-to-site VPN scenarios.

The purpose of IPSec in VPNs is to ensure that data transmitted between VPN endpoints remains confidential, tamper-proof, and authenticated. IPSec can be used in conjunction with various encryption algorithms and authentication methods to establish a secure tunnel and protect data during transit.

## SSL/TLS VPN

SSL (Secure Sockets Layer) and its successor TLS (Transport Layer Security) are cryptographic protocols used to secure communication over the internet. SSL has been deprecated, and TLS is now the standard for securing web traffic and other applications. SSL/TLS VPNs, also known as SSL VPNs or Web VPNs, allow users to access internal resources through a web browser without requiring the installation of dedicated client software.

SSL/TLS VPNs are an ideal tool to provide secure remote access to internal applications, web-based resources, and intranet services. SSL/TLS VPNs use the web browser's SSL/TLS capabilities to establish a secure connection between the user's device and the organization's internal network. This approach simplifies deployment and allows access from a wide range of devices without additional configuration.

## HTML5 VPN

HTML5 VPNs are a subset of SSL/TLS VPNs that leverage HTML5 capabilities to provide remote access to web-based applications and services. The purpose of HTML5 VPNs is to enable secure access to web applications without requiring the installation of any specific software on the user's device.

HTML5 VPNs are particularly useful for accessing web-based resources from various devices, including smartphones and tablets. They allow users to interact with web applications securely, regardless of the device's operating system or platform, while ensuring data privacy and protection.

## Layer 2 Tunnelling Protocol (L2TP)

Layer 2 Tunnelling Protocol (L2TP) is a tunnelling protocol used to establish virtual private connections over public networks. L2TP operates at the data link layer (Layer 2) of the OSI model and does not provide encryption or authentication on its own. To address this limitation, L2TP is often combined with IPSec for added security.

The purpose of L2TP in VPNs is to facilitate secure remote access to a corporate network or to connect remote networks in a site-to-site configuration. By encapsulating data packets in L2TP frames, it establishes a secure tunnel for data transmission.

## VPN Protocols

Selecting the right VPN protocol for your implementation is another key decision when designing a VPN Solution. We have looked at IPSec and L2TP which are highly popular, however, we would also recommend you become familiar with some of the advantages and disadvantages of the most common options. The information in this table should be more than enough. Don't attempt to memorise all the points, rather familiarise yourself with some of the trade-offs an administrator might need to consider. 


| **VPN Protocol**                              | **Advantages**                                               | **Disadvantages**                                            |
| --------------------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| **OpenVPN**                                   | - Highly configurable and customizable.                      | - Can be complex to set up and configure.                    |
|                                               | - Supports multiple encryption algorithms (e.g., AES, DES).  | - May require third-party software for some platforms.       |
|                                               | - Cross-platform compatibility (Windows, macOS, Linux).      | - Slightly higher overhead compared to some protocols.       |
|                                               | - Resistant to firewalls and NAT traversal.                  |                                                              |
| **IPSec (Internet Protocol Security)**        | - Widely supported and integrated into many devices.         | - Configuration can be challenging, especially for non-tech users. |
|                                               | - Strong security features, including encryption and authentication. | - Overhead can impact performance, especially on lower-end devices. |
|                                               | - Supports both remote access and site-to-site VPNs.         | - May require additional configuration for NAT traversal.    |
|                                               | - Suitable for high-security environments.                   |                                                              |
| **L2TP (Layer 2 Tunnelling Protocol)**        | - Easy to set up and configure.                              | - Lacks encryption and must be used with another protocol (e.g.,  IPSec). |
|                                               | - Widely supported on various platforms and devices.         | - Vulnerable to certain attacks when not used with encryption. |
|                                               | - Suitable for providing remote access.                      |                                                              |
| **PPTP (Point-to-Point Tunnelling Protocol)** | - Easy to set up and configure.                              | - Considered weak and not recommended for security-conscious  environments. |
|                                               | - Supported by many platforms and devices.                   | - Vulnerable to various security vulnerabilities.            |
|                                               | - Good for legacy or older systems.                          |                                                              |
| **IKEv2 (Internet Key Exchange version 2)**   | - Fast and reliable, designed for seamless mobility.         | - Limited support on some platforms.                         |
|                                               | - Supports strong encryption and authentication.             | - Not as widely used as some other protocols.                |
|                                               | - Resistant to unstable network connections.                 | - Configuration and troubleshooting can be complex.          |
| **SSTP (Secure Socket Tunnelling Protocol)**  | - Easy to configure and set up on Windows devices.           | - Limited support on non-Windows platforms.                  |
|                                               | - Utilizes SSL/TLS for encryption, highly secure.            | - Not as widely supported as other protocols.                |
|                                               | - Resistant to firewalls and port-blocking.                  |                                                              |

## Final Words

Virtual Private Networks (VPNs) are indispensable tools for enhancing security and connectivity in today's interconnected world. Always-on VPNs maintain a persistent connection for continuous protection, while split  tunnelling and full  tunnelling offer distinct routing strategies to balance security and performance. Remote access VPNs enable secure connections for individual users, while site-to-site VPNs facilitate secure communication between geographically dispersed networks.

The use of IPSec and SSL/TLS protocols strengthens data privacy and ensures authenticated communication, while HTML5 VPNs enable secure access to web applications without requiring specific client software. Lastly, Layer 2 Tunnelling Protocol (L2TP) provides a framework for establishing secure connections at the data link layer.

By making use of appropriate VPN solutions organizations and individuals can protect their data, maintain privacy, and enable seamless and secure communication across diverse networks and remote locations. At the same time, however, care must be taken to select the most appropriate type and configuration of VPN.