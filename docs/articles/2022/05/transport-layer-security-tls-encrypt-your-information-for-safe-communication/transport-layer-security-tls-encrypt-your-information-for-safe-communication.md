:orphan:
(transport-layer-security-tls-encrypt-your-information-for-safe-communication)=

# Transport Layer Security (TLS): Encrypt Your Information for Safe Communication

Several approaches for creating a safe and authenticated channel between hosts have been presented. Finally, a better replacement to the SSL protocol was created which is TLS. In this blog we will make an introduction to Transport Layer Protection (TLS) protocol.

## What is Transport Layer Protection (TLS)?

Despite the fact that TLS has been around for more than a decade, many people still refer to it as SSL. They both perform similarly, but TLS utilizes better authentication and encryption mechanisms.

TLS is developed and maintained by the Internet Engineering Task Force (IETF). TLS included several security improvements and was subsequently accepted as a substitute for SSL. And the distinctions between SSL 3.0 and TLS are quite minor.

**Backward compatibility in TLS**

When both sides did not support TLS, early versions of TLS enabled degraded communications to SSL. TLS terminated this backward compatibility in 2011. Also, in 2014, an attack known as the Padding Oracle On Downgraded Legacy Encryption (POODLE) exposed a fundamental weakness in TLS's SSL 3.0 fallback mechanism. To address this problem, several companies abandoned SSL support and now rely only on TLS security.

## TLS protocols

TLS is made up of two protocols:

**The TLS Handshake Protocol**: The TLS Handshake Protocol establishes a connection by exchanging asymmetric encryption keys before establishing a symmetric encryption-based channel.

**The TLS Record Protocol**: It ensures the integrity of messages by employing a suitable hash function. The Open SSL102 is an open-source TLS implementation.

## HTTP over TLS

- HTTP over TLS is widely approved and acknowledged as a secure option, and it has become a de-facto standard for online shops of all types.

- TLS security is primarily used to prevent interception, although authentication still relies on username/password credentials. This makes it vulnerable to person-in-the-middle attacks.
- You should be careful with the certificates supplied by the servers. There may be a difference between a site's fully qualified domain name (FQDN) in DNS and that in the certificate.

## SSL and TLS common features

SSL and TLS both share some characteristics. These features are as follows:

- They can be used at the same port.
- Ensure safe client-server communications over an unsecured network while avoiding tampering, spoofing, and an interception.
- Allow for one-way authentication.
- Also, allow two-way authentication through the use of digital certificates.
- Can be implemented as a VPN at lower levels, such as the network layer.

## Summary

To review, TLS provides mutual server and client authentication and it is a better alternative to SSL. TLS encrypts information, preventing interception and tampering. It allows secure communication between web browsers, end-user-facing apps, and servers.

Despite its flaws, SSL is still used in many circumstances. But as we have covered, instead of SSL which has known security vulnerabilities, we should prefer TLS. Now we know, which protocol provides more security in our next e-commerce transaction.

:::{seealso}
Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)
:::
