:orphan:
(secure-network-protocols-use-cases)=

# Secure Protocols – Use cases

In a [previous article](https://library.mosse-institute.com/articles/2023/08/secure-network-protocols.html), we learned about the secure protocols which are gradually (probably too gradually!) replacing their older, less secure counterparts. Here, we’ll take a look at some practical examples of how secure protocols can thwart attackers – and how easily information security can be compromised when insecure protocols are in place. 



## Domain Name System Security Extensions (DNSSEC)

**Insecure Scenario:** In a system without DNSSEC, an attacker successfully gains access to a corporate network. The plan is to plant ransomware and force the company into paying a bribe – but on inspection of the network, they find much less valuable data than they hoped. Nonetheless, the environment is large and comprises multiple DNS servers. Rather than ransom a company which appears to have little data of great value, the attacker instead exploits the vulnerable Domain Name System by launching a DNS cache poisoning attack. By manipulating DNS records, the attacker directs all users seeking to access a legitimate banking site to a malicious site that they control. Unsuspecting users provide personal and financial information to the fake site, which then forwards them back to the legitimate site. The users have surrendered their critical information and never knew it. The attacker can now sell the data, leading to identity theft and financial fraud.

**Secure Scenario (DNSSEC):** The integration of DNSSEC into the environment makes this attack impossible. DNSSEC employs cryptographic signatures to validate DNS responses, ensuring the authenticity and integrity of domain information. Even if attackers attempt to inject malicious DNS data, the cryptographic signatures act as a canary, detecting the tampering and preventing any redirection to counterfeit sites. The secure ecosystem created by DNSSEC averts identity theft and financial loss by preserving the sanctity of online transactions and interactions.

 

## Secure Shell (SSH)

**Insecure Scenario:** An attacker has managed to get a foothold into a single system inside an organisation – the system belongs to a low-privilege IT department user who seems to be responsible for network monitoring – there are no useful credentials, but the system does have a connection to a management network. The attacker is unable to move much further from this point, however, they *can* capture network traffic. Our attacker “lives off the land” and seizes the opportunity to intercept communication between administrators and some network devices. Unfortunately, communications on the management network take place using telnet, meaning they’re in plain text – our attacker simply starts a packet capture, waits for an administrator to log into a device, and sees the credentials, right there for the taking.

**Secure Scenario (SSH):** In a more secure network, Secure Shell (SSH) uses encryption to establish private connections between clients and servers. This time, our attacker can still *intercept* the communication, but the data they get is nothing more than encrypted bits and bytes. Without the proper keys, the data can’t be read!



## Secure/Multipurpose Internet Mail Extensions (S/MIME)

**Insecure Scenario:** In an unsecure email environment it’s also easy to intercept information transmitted using traditional SMTP. Let’s again assume that an attacker has compromised a network and is able to intercept packets on the wire. Without any encryption, it’s easy to intercept email exchanges - they gain access to confidential business strategies, financial details, and proprietary information. 

**Secure Scenario (S/MIME):** Secure/Multipurpose Internet Mail Extensions (S/MIME) adds encryption to email – as with secure shell, the use of S/MIME encrypts email content, transforming it into an unreadable code to anyone except a valid recipient possessing the correct decryption key. S/MIME also introduces a digital signature component, which guarantees the authenticity and integrity of the sender's identity and the message itself. With S/MIME, attackers attempting to intercept email communications are met with an impenetrable barrier - stolen emails become gibberish, and the sender's authenticity remains unchallenged. S/MIME erects a fortress around email exchanges, safeguarding sensitive data and cultivating an atmosphere of trust among business partners and individuals alike.

The use of a digital signature also helps to achieve a security goal known as non-repudiation. This is simply the idea that a person who takes an action cannot repudiate (deny) their involvement. The digital signature means that down the line it’s very difficult to claim you didn’t send a message! (so be nice!).

*Tip: While digital signatures help to provide authentication and non-repudiation, they are not totally flawless. A digital signature can authenticate that a given email account was the true originator of an email – however, this alone is not enough of a security control to definitively prove which person actually wrote and sent the mail. If a workstation is left unattended it’s possible that someone else simply sat down at the PC and sent the mail! If a password is compromised, it’s possible that an unauthorised individual accessed that account and sent whatever they liked. To achieve a higher level of trust in the system, a complementary control, such as a surveillance camera might be used – if we have a video record of a user being at their workstation as well as an email with a digital signature, it’s starting to get hard (but not impossible) to believe they didn’t send it!*

 

## Secure Real-time Transport Protocol (SRTP)

**Insecure Scenario:** Megacorp XYZ is running their yearly conference with thousands of people scheduled to attend. The event turned out to be more popular than expected, so management decided at the last moment to live-stream video from the main stage to other areas of the conference to avoid people trying to squeeze into a single room. Network technicians quickly set up some switches and stand up a simple network to link the IP cameras to the screens around the centre. Since time is short security is a low priority – the techs opt to use the older, unsecured Real-time Transport Protocol (RTP) for carrying the feed. After all, the conference is public, and it’s a closed network. 

Unfortunately, the network technicians have not been briefed on the location of all of the cameras – while most are in public areas, one is set up in a breakout room which will mostly be used for presentations but can also be used for meetings. Similarly, no attention is paid to securing the unused switch ports on the network switches. 

On the day of the conference, an attacker plans to gain an advantage against Megacorp XYZ by attempting to eavesdrop wherever possible. Looking around the conference from the point of view of an attacker, he spots the unattended unsecured network switch right away, walks over, and simply plugs in – he looks like a tech guy and has a laptop, so no one bats an eyelid. 

While people mill about the floor, our attacker quickly sets up port mirroring and starts intercepting RTP data. He’s able to acquire unrestricted access to sensitive conversations and strategic discussions taking place during the conference, all without leaving his seat. The ramifications of this intrusion extend beyond the immediate breach, potentially leading to reputational damage and intellectual property theft.

**Secure Scenario (SRTP):** Instead of using the insecure RTP, if SRTP had been used this scenario could not have played out. SRTP bolsters the security of real-time media streams by implementing encryption, ensuring that audio and video content remains confidential during transmission – even allowing for the rush to set up the network, the lack of port security and the miscommunication about the location of cameras, Intercepting SRTP-encrypted data offers attackers no actionable insights. Even if attackers successfully intercept the data, the encrypted content proves useless, preserving the privacy of sensitive conversations, business negotiations, and proprietary information. 



## Lightweight Directory Access Protocol Over SSL (LDAPS)

**Insecure Scenario:** Traditional Lightweight Directory Access Protocol (LDAP) is another unencrypted protocol which exposes an organization's user data to attackers. In this unencrypted environment, attackers intercept LDAP communication and gain access to user credentials, compromising network security and potentially exposing sensitive information.

This time our attacker isn’t really a bad guy, rather they’re a penetration tester taking part in a security assessment. Our tester has been given access to a machine in the network but has no credentials for the domain. 

Our pentester would like to obtain domain administrator credentials, but before they can begin escalating privileges they’ll need some valid credentials to work with. The first move is to enumerate the machines on the network – a simple Nmap scan identifies an LDAP server with unencrypted LDAP running.  

From here, the pentester monitors network traffic and eventually identifies unencrypted LDAP communication between an LDAP client and the server. Now, utilizing packet sniffing tools, the attacker intercepts the unencrypted LDAP traffic. This allows them to capture packets containing sensitive information, including user credentials.

More likely than not, any credentials captured will be user credentials, from here the Pentester can look to escalate privileges, or, they might simply wait to see if they can capture some administrator credentials. It might also be possible to cause an event which would cause an administrator to log in, thereby revealing their credentials – there are plenty of options when one can read all the traffic! 

**Secure Scenario (LDAPS):**  As is becoming a familiar trend by now, LDAPS establishes an encrypted channel between clients and LDAP servers, rendering intercepted data meaningless to attackers. Attempts to access user credentials and other sensitive information result in encrypted content that remains unintelligible. This won’t stop our pentester – but they’re likely to have to begin using more “noisy” methods like password spraying or brute forcing in an attempt to find a valid domain credential – this greatly increases the chances that either the blue team or a network-based intrusion detection system could notice their activity.

 

## File Transfer Protocol, Secure (FTPS) and SSH File Transfer Protocol (SFTP)

**Insecure Scenario:** Jim and Jenny have just finished setting up their new website – Jim and Jenny’s Jam Stand. They’re thrilled and ready to get to work – but within days, they wake to find that their website has been infected with malware and is redirecting users to a phishing page. What’s worse, within hours their web hosting account is suspended and their business is at a standstill. What happened? Was the web host at fault? Unfortunately, Jim and Jenny uploaded a sensitive configuration file to their website using the Traditional File Transfer Protocol (FTP) -  notorious for its lack of encryption. Somehow, an attacker was able to intercept their traffic – read the data, and then access the admin page of their website. 

**Secure Scenario (FTPS/SFTP):** As we saw in a previous article, there are two versions of the File Transfer Protocol which use a secure connection – these are the secure protocols FTPS and SSH File Transfer Protocol (SFTP). Either will provide the encryption which would have prevented this attack. FTPS wraps file transfers in a secure layer of encryption, while SFTP employs SSH's robust encryption mechanisms to protect data during transmission. Attackers intercepting encrypted data are faced with an unsolvable puzzle – encrypted content without decryption keys is meaningless. In today's world, one should *never* send any content across the internet in an unencrypted format – like Jim and Jenny, you’d probably never be able to trace where or how your traffic was intercepted.

 

## Simple Network Management Protocol, version 3 (SNMPv3)

**Insecure Scenario:** Unsecured SNMP versions (v1/v2c) compromise network security – not only do they fail to provide encryption (allowing an attacker to intercept SNMP communication to harvest credentials and other information) but the protocol itself is designed to allow the remote monitoring and configuration of network devices, a massive risk! 

 After a day spent looking for easy targets, an attacker identifies a target organization's network using Shodan – simply by entering some search filters, they easily discover SNMP-enabled devices within the network and exposed to the internet. Since SNMP versions 1 and 2c offer no encryption our attacker *could* try to intercept communications to the exposed network devices… but there’s no obvious way to do this since they don’t control any of the network segments between them and the target device. Fortunately for our attacker, SNMP implements a password-like system called  “community strings” to authenticate users…unfortunately for the organisation, they are using *very* weak community strings. Default or commonly used community strings (e.g., "public" or "private") take just seconds to try, and before you know it the attacker has access to SNMP.

With read access, the attacker queries SNMP agents for valuable information about the network, such as device configurations, network topology, and system details. The attacker identifies specific devices within the network that are running outdated firmware versions with known vulnerabilities. They find a network router susceptible to a remote code execution vulnerability.

Armed with the router's vulnerabilities, the attacker crafts and sends a malicious SNMP query to the device. The query triggers the remote code execution flaw, allowing the attacker to execute arbitrary commands on the router. Next, our attacker uses the exploited router as a pivot point. They install a backdoor or create a rogue administrative account to ensure persistent access to the compromised device.

With unauthorized and unlimited access to the router, the attacker gains control over network routing and traffic redirection. They manipulate routing tables, enabling the redirection of certain traffic through a controlled server under their command. The attacker now selectively redirects sensitive data traffic, such as confidential emails or valuable database queries, to a server they control. This data is captured for months until a network administrator finally logs into the compromised router and notices the rogue user account. 

 

**Secure Scenario (SNMPv3):**  A massive improvement over v1 and v2c SNMPv3 introduces a wide variety of security features – in this scenario, the use of a complex username and password could well have stopped this attack. 

SNMPv3 introduces the use of strong authentication mechanisms, such as HMAC-MD5 and HMAC-SHA (Hash-based Message Authentication Code with MD5 or SHA-1), which are more secure than the simple community string authentication used in SNMPv1 and SNMPv2c. These mechanisms ensure that the messages exchanged between SNMP devices are not tampered with during transmission.

Alongside authentication, SNMPv3 ensures the integrity of SNMP messages. The authentication mechanisms mentioned above not only verify the authenticity of the sender but also detect any unauthorized modifications to the message content. If a message is altered in transit, the integrity check fails, indicating potential tampering.

SNMPv3 allows for the use of usernames and passwords for authentication instead of the community strings used in SNMPv1 and SNMPv2c. These credentials are more secure and are not transmitted in clear text over the network. Additionally, SNMPv3 supports the use of security models, where users and devices can have different levels of access based on roles and privileges. Even better, SNMPv3 employs the User-Based Security Model, which enables organizations to define and enforce granular access controls. This model allows administrators to set up different users with varying levels of access to different parts of the network infrastructure.

SNMPv3 goes beyond authentication and message integrity by introducing encryption. With SNMPv3, data can be encrypted using privacy protocols like DES (Data Encryption Standard), 3DES, and AES (Advanced Encryption Standard). This means that even if an attacker intercepts SNMP messages, the content remains encrypted and unreadable without the decryption key.

 

## Hypertext Transfer Protocol over SSL/TLS (HTTPS)

**Insecure Scenario:** HTTP changed the world – without it, there would be no internet and much of today's digital economy simply wouldn’t exist. We all have a lot to thank HTTP for… but security isn't one of these things. When HTTP was conceived there was no perceived need to send information in a secure encrypted format, and so (notice a trend?) it transmits in plain text. 

Therefore, a website accepting HTTP connections is allowing information to be transmitted to and from the server in an open, readable format. Again, it’s easy for an attacker to intercept and read traffic, compromising credentials. When it comes to websites, our attacker does not necessarily even need to capture credentials – many websites use cookies to authenticate users, cookies which, if captured by an attacker, can be reused to gain access to an application. 

Let’s say our attacker is not especially interested in the vulnerable HTTP site but *would* like to gain access to a user's account on another platform. The other platform is protected with HTTPS, so even if they could intercept traffic it would be impossible to extract credentials – however, an attacker could and would assume there’s a reasonably good chance that a user has re-used their credentials – if they have, logging into an insecure site can expose their account on a secure site too. 

*Tip: This is one of the many reasons why using a strong and unique password for each site is so important!* 

**Secure Scenario (HTTPS):** As we mentioned above, through the integration of SSL/TLS encryption, HTTPS safeguards users' data during transmission. Intercepted encrypted information yields no actionable insights to attackers. Usernames, passwords, financial data, and personal information remain secure There are still many other ways an attacker could attempt to steal information from the user – but reading traffic is no longer one of them! 

 

## IPSec

**Insecure Scenario:** IPsec is one of the most widely used protocols for facilitating VPN connections. Before IPsec was widely implemented, the only way for organisations to transmit information securely between locations was to purchase an expensive, and relatively slow, leased line directly from a service provider. This assured security because no one (except the service provider) had access to the line – however the costs were often prohibitive. Since a physical leased line was often literally a single connection any damage to the line (perhaps from a storm) would mean communications were down and staying down for a while! To a business, this could mean considerable lost revenue. 

**Secure Scenario (IPSec):** IPSec employs a combination of authentication and encryption to secure communication channels between network segments. Once established an IPsec tunnel preserves the confidentiality and integrity of data exchanged between branches – even over a public network, like the Internet. Modern VPN connections allow locations to connect to each other over the hugely redundant internet backbone at a fraction of the cost. Today, establishing connectivity from a branch location to a company head office is as simple as purchasing regular internet access and configuring the secure tunnel.



## POP/IMAP (over SSL/TLS)

**Insecure Scenario:** Traditional POP3/IMAP email protocols are responsible for retrieving email messages from a server. Even if the email server itself is administered in a secure way, it’s critical that emails are also retrieved securely, or the system no longer provides a reasonable expectation of privacy. 

Sarah has just set up a small website – it’s just a blog and does not handle any sensitive data, so she’s paid minimal attention to security. While she has some technical skills, the administration of an email server isn’t one of them – so when configuring her email account, she used a wizard offered by her hosting provider and opted for traditional IMAP when configuring the mailbox. Sarah might not have known the difference between a secure and insecure configuration here, or the hosting provider wizard might have provided no warning – she might even have simply clicked the wrong box! Either way, her emails are now traversing the internet in clear text.

Later that day, Sarah heads down to the coffee shop and logs on to the public wifi – she checks her mail and starts working on a blog. Unfortunately, an attacker is active on the same network - they utilize network sniffing tools to capture unencrypted POP3 traffic between the user's email client and the server. The attacker captures the login credentials transmitted in plain text and could also capture the content of the emails, but there’s little need to do this now – after all, they can log in at any time. 

Armed with stolen credentials, the attacker gains unauthorized access to the user's email account. They can now read, manipulate, or delete emails at will – since they know Sarah’s email address, and have access to it, they may as well have access to any other system Sarah has used that address to create an account with. While she’s asleep, the attacker simply performs a password reset and logs in.

**Secure Scenario (POP/IMAP over SSL/TLS):** Secure versions of POP3/IMAP over SSL/TLS can prevent this attack, and are critical when using a public network. By implementing SSL/TLS encryption, email content remains encrypted during transmission. Intercepted emails reveal nothing to attackers, preserving the confidentiality of sensitive information. Users rest assured that their email exchanges, containing proprietary information, personal data, and sensitive attachments, are shielded from prying eyes.

*Tip: Although SSL (Secure socket layer) is no longer used, you’ll usually still see this written as SSL/TLS. TLS (Transport Layer Security) will be the protocol in use today.* 

# Final words

In this article we tried to bring some context to the need for secure protocols – especially if you’re just getting into IT, it’s not always obvious how the simple choice of protocol can have such significant consequences, but it’s a critical choice which can easily make or break an attack chain. Opt for secure protocols whenever possible and you stand the best chance of protecting confidentiality, integrity and availability. 

 
