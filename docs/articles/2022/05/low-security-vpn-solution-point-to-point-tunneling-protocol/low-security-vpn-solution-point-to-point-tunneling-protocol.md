:orphan:
(low-security-vpn-solution-point-to-point-tunneling-protocol)=
# Low-security VPN solution: Point-to-Point Tunneling Protocol
 

If you want to set up a site-to-site VPN, you need to choose the protocol to employ based on functionality and security. In this blog post, we will look at what a point-to-point tunneling protocol (PPTP) is, how it works, and special security considerations.

## Point-to-Point Tunneling Protocol (PPTP)

The Point-to-Point Tunneling Protocol is one of the earliest protocols, but it doesn’t offer much security.
It simply encapsulates the Point-to-Point Protocol (PPP) over a TCP/IP connection.

- Microsoft developers created the first encapsulation protocol on the market, PPTP.
- It can be used on all Windows operating systems. By encapsulating the PPP packets being delivered, PPTP sets a means of communication for two devices.
- Although PPTP has helped to improve communications security, it has a number of flaws.
- PPTP is protocol-restricted, which means it can only be used on IP networks.

It establishes two connections:

**The control connection**: which is a TCP connection to port 1723.

**The IP tunnel connection**: that is carried using the Generic Routing Encapsulation (GRE) protocol, which transports the user's data.

## Establishing Communication

Let’s say, you, as a client, want to start communication with an underlying PPTP through a site-to-site VPN.

**StartConnection-Request**: You send a StartConnection-Request message.

**StartConnection-Reply**: Server sends back a StartConnection-Reply.

**Incoming-Call-Request**: You send an Incoming-Call-Request message that means you want to start a tunneling connection.

**Incoming-Call-Reply**: Server sends back an Incoming-Call-Reply message.

**Incoming-Call-Connect**: You send an Incoming-Call-Connect message to the server.

These incoming-call messages establish a pair of random Call ID numbers at either end of the connection. These Call IDs uniquely identify traffic in the GRE tunnel.

The GRE data traffic, which is just PPP packets enclosed in the GRE header, can then commence. Along with the packet's length, an optional sequence number, and an acknowledgment number, the Call-ID is contained in the key field of the GRE header.

**Stop-Connection-Request**: You send a Stop-Connection-Request to end this communication.

**Stop-Connection-Reply**: The server answers back with a Stop-Connection-Reply.

And TCP connection ends.

**keepalive/echo packet**

Keep-alive packets are delivered periodically to prevent resources from being consumed by an inactive session. If you or the server doesn’t reply or receive these echo packets in 60 seconds, you both may disconnect the TCP connection and discard all further communication over the GRE protocol for that connection.

## PPTP security issues

- PPTP is widely used, even in non-Microsoft operating systems like Mac OS X and Linux, because of its simplicity. It's appropriate for small, low-power devices.

- Microsoft's MCHAP (Microsoft Challenge Handshake Authentication Protocol) or the EAP-TLS protocol can be used to authenticate PPTP connections.

- The data being communicated is encrypted, but the information being exchanged during negotiation is not. The Microsoft Point-to-Point Encryption protocol is used to encrypt data in Microsoft implementations.

- Apart from passing security issues to the underlying PPP protocol, PPTP's major flaw is that GRE doesn't use TCP or UDP, which may be blocked by firewalls, NATs, and routers. GRE packets use the IP protocol type.

## Conclusion

PPTP has been around since the 1990s. In this blog post, we examined the oldest tunneling protocol, how you can establish a communication and major issues security issues you need to take into consideration.

Most remote locations enable PPTP packets to pass through their firewalls. You can consider PPTP as a tunneling option for networks with the least security needs.

> **Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)!**