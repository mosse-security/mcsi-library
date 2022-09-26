:orphan:
(remote-access-authentication-pap-and-chap)=

# Remote Access Authentication: PAP and CHAP

This blog article will discuss two username/password authentication protocols: Password Authentication Protocol and The Challenge Handshake Authentication Protocol. By the completion of this page, you'll know if you should use one of two methods for authentication of point-to-point packets.

## Introduction

Most networks need you to recognize with some sort of input such as a user name and a password. Depending on the network operating system, the specific technique of username/password authentication differs. Here is what it contains in general:

**Encryption**: This approach scrambles a password, making it unreadable to anybody who monitors storage or communications.

**Response and challenge**: Response and challenge demand you to verify your credentials at the start of the transaction.

When a user wants to access, CHAP creates a _problem_. If the user correctly replies to the challenge, the access request is approved. CHAP increases overall security by encrypting message exchanges.

## Password Authentication Protocol

Password Authentication Protocol (PAP) requires the user to provide a username and password, which are then compared to data recorded in a table to check if they match. PAP is quite similar to the traditional Unix login. It uses a two-way handshake.

PAP sends authentication credentials in plaintext. There is no encryption or extra protection for the data you submit using this Password Authentication Protocol.

## The Challenge Handshake Authentication Protocol

- CHAP was developed to enhance the security of the verification procedure. The Challenge Handshake Authentication Protocol is one approach for protecting information while utilizing remote access to a resource.

- CHAP is a remote access authentication protocol that works in combination with the PPP to offer security and authentication to distant resource users.

- CHAP works in tandem with PPP to safeguard the credentials supplied for authentication and to validate the connection to a legitimate resource.

- CHAP can also be set to use one-way reversible encryption, which employs the one-way hash, to store a password. The password is therefore safeguarded. However, CHAP is superior to Password Authentication Protocol since it broadcasts passwords over the network in cleartext.

## CHAP three-way handshake

CHAP uses a three-way handshake to authenticate the identity of the peer on a regular basis.

**1-)** The authenticator (generally a network server) transmits a note to the peer. This challenge contains an ID and a casual number. They also transfer a predetermined secret word, phrase, or value.

**2-)** The peer combines together the random value, the ID, and the secret creating a hash function. It transmits this new value to the authenticator server.

**3-)** The authenticator also generates a hash in the same way. Then it compares the answer to its own hash value. If the hashes correspond, the authentication is accepted; if not, the connection is closed.

To strengthen security, the authenticator can be programmed to repeat the authentication process throughout the conversation session, and repeat the challenge-response procedure. The authenticator sends a fresh challenge to the peer at random intervals and repeats steps one through three.

## Security considerations with PAP and CHAP

- It does not use encrypted password databases and hence provides less protection than other levels of authentication.

- The shared secrets may be kept as cleartext on both ends, leaving the secret subject to compromise or discovery.

- PAP sends unencrypted credentials during authentication, while CHAP has major security weaknesses that make obtaining the credentials uncomplicated.

- MS-CHAP v2 provides much greater security than PAP and CHAP, however, it is also known to be susceptible with no effort and should be avoided wherever feasible.

- With PPTP VPNs, PAP, CHAP, and MS-CHAP v2 are utilized. However, for increased protection, you can consider utilizing another VPN type. Unfortunately, MS-CHAP and MS-CHAP v-2 are also vulnerable. Many people have abandoned MS-CHAP in favor of L2TP, IPsec, or another sort of secure VPN connection.

:::{seealso}
Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)
:::
