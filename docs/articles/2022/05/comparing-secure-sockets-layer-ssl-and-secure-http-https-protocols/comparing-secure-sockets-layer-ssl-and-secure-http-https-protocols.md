:orphan:
(comparing-secure-sockets-layer-ssl-and-secure-http-https-protocols)=

# Comparing Secure Sockets Layer (SSL) and Secure-HTTP (HTTP-S) Protocols

In this blog post, we are going to explain what Secure Sockets Layer (SSL), and Secure-HTTP (HTTP-S) protocols are and how they differ from each other.

## Introduction to SSL

The Secure Sockets Layer was created to offer secrecy, integrity, and authenticity to the web traffic between client and server. Although SSL was created as a Netscape browser standard, Microsoft embraced it for the Internet Explorer browser and it became the de facto Internet standard.

SSL depends on the exchange of digital certificates between the browser and the web server to negotiate encryption and decryption settings. The purpose of SSL is to build secure communication channels that remain available during a web session. It is based on a mix of symmetric and asymmetric encryption.

### Appliance of SSL

SSL requires the server to transmit a digital certificate to the client in order to give a public key and authenticate the client's identity. After the client is satisfied with the certificate's authenticity, the two hosts can begin interacting by utilizing encrypted communications.

Let’s take a look at this communication in detail:

- When you visit a website, your client browser obtains the web server's certificate and extracts the public key from it.
- The browser then generates a random symmetric key, encrypts it with the web server's public key, and delivers the encrypted symmetric key to the server.
- The server then decrypts the symmetric key with its own private key, and your systems use the symmetric encryption key to exchange all future communications.

This strategy enables SSL to make use of asymmetric cryptography's sophisticated features while encrypting and decrypting the vast majority of data transferred using the quicker symmetric algorithm.

## SSL vulnerabilities

- SSL has security flaws caused by short key sizes, expired certificates, and other flaws that can afflict any public-key system.
- Many SSL servers on the Internet still use an older, faulty version (SSLv2) or 40-bit encryption, or their certificates are outdated or self-signed.
- SSL is vulnerable to the Padding Oracle On Downgraded Legacy Encryption (POODLE) exploit. As a result, numerous businesses have turned off SSL in their applications.

### SSL & HTTP/S

SSL encrypts transmissions between web application clients and servers. Rather than port 80, HTTP/S utilizes port 443. For client-to-server authentication, both HTTP/S and SSL employ an X.509 digital certificate.

### Secure-HTTP (S-HTTP )

The vocabulary used to explain safe Web protocols is difficult to understand. The Secure Sockets Layer (SSL) is recognized as HTTP over SSL and is abbreviated "https."

In contrast, the Secure-HTTP protocol is sometimes abbreviated as "HTTP-S or S-HTTP". S-HTTP is an HTTP 1.1 upgrade that intends to handle encryption exclusively at the application layer.

## Comparison of SSL and S-HTTP

HTTP-S, like SSL, offers secrecy, integrity, and authentication. Although they seem similar, they are two distinct protocols that serve different functions. Several significant differences are as follows:

- Secure HTTP is an HTTP protocol enhancement. It is a secure message-geared transmission protocol capable of securely transmitting messages.
- SSL is a session-oriented protocol, whereas HTTP-S is a connectionless protocol.
- SSL is built into the majority of popular Web browsers, but HTTP-S is only present in a few less popular browsers.
- SSL connects the Session and Transport levels, whereas HTTP-S connects the Application and Transport layers.
- S-HTTP, unlike SSL, does not require clients to hold public key certificates because it may allow private transactions using symmetric keys.
- S-HTTP is more robust than HTTP over TLS since it is integrated into client/server queries, and it is less vulnerable to attacks.

## Summary

In this blog, we took a brief look at SSL and S-HTTP and made a comparison between the two from a security perspective. S-HTTP has not gained the same level of acceptability and implementation support as HTTPS. RFC 2660 specifically notes that it specifies an "experimental protocol," and there has been no successor produced.

> **Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)!**
