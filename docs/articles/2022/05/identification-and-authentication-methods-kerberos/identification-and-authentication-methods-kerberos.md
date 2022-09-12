:orphan:
(identification-and-authentication-methods-kerberos)=

# Identification and Authentication Methods: Kerberos

Kerberos is an authentication protocol that is extremely valuable for ensuring secure communication between different systems. The Kerberos protocol uses a third-party authentication server in order to verify the identity of users and provide them with a secure token that can be used to access resources. Kerberos is often used in large organizations where there are many different systems that need to communicate with each other. In this blog post we are going to explore this network authentication protocol in depth. 

## What is Kerberos?

The Kerberos protocol is a network authentication method which provides the basis for the authentication and identification of users. It is used in ticket-based systems. It was created at MIT to authenticate Unix-based computer workstations. Kerberos also serves cross-platform authentication.

## Ticket-based network authentication

- When you want to utilize a certain service, first you contact the authentication server and ask for access: Can I talk with the mail server? Then the authentication server provides you with a ticket.

- A ticket is a block of encrypted data destined for the mail service. Tickets are encrypted using secret keys that are allocated to certain users, customers, and services.

- You contact the mail service and deliver a copy of the ticket.

- The mail service validates the ticket with its secret key to guarantee that you are the right client and using the right tickets.

- Kerberos uses timestamps of tickets to guarantee that they are not compromised.

## Active Directory

Kerberos is used as a means to centralize authentication information for the person or service that requests the resource.

Microsoft's "Active Directory" employs the Kerberos protocol to authenticate users, clients, and services inside a Microsoft "domain." When a user enters a domain workstation, the workstation contacts Active Directory to authenticate the user and obtain tickets that are required.

## What is Key Distribution Center (KDC)?

Kerberos utilizes secure, encrypted keys and tickets (authentication tokens) supplied by the authenticating KDC. It is built around the Key Distribution Center (which is abbreviated as "KDC"). All cryptographic keys for subjects and objects are stored in the KDC. It is in charge of keeping and distributing these keys, as well as providing authentication services.

## How does Kerberos work in detail?

When the KDC gets a request for object access, it contacts the Authentication Service (AS) to verify the subject and the request. If the subject's request is validated, the AS generates an access ticket with keys for both the subject and the object. The keys are subsequently distributed to both the subject and the object.
The following are the fundamental phases in a Kerberos access request cycle:

**1-)** You want to access an object. Your Kerberos program prompts for your ID. Your input is then sent to the KDC along with the request.

**2-)** The KDC requests that you and the object you want to access be authenticated by the Authentication Server.

**3-)** If you and the object are authorized, the KDC provides an encrypted session key to both of your devices.

**4-)** Your Kerberos client program requests a password, which is then used to decrypt the session key together with your secret key.

**5-)** You send the access request to the object along with the session key.

**6-)** The object decrypts the KDC session key and compares it to the session key received with the access request.

**7-)** Access is permitted if the two session keys match.

## Drawbacks of the Kerberos protocol

- The KDC's centralized form reveals one of Kerberos' primary flaws: it is a single point of failure. Failure of the KDC indicates an object access failure.

- On intensively used computers, the KDC can also present a performance bottleneck.

- The session key only exists on the client workstations for a short period. An attacker might steal this key and obtain illegal access to a resource.

## Conclusion

Kerberos is extremely valuable in today's dispersed computing settings since it centralizes the processing of authentication credentials.

Despite its flaws, Kerberos is an excellent example of a network authentication technology that has gained universal adoption.

> **Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)!**
