:orphan:
(think-your-passwords-are-safe-think-again)=

# Think Your Passwords Are Safe? Think Again

Passwords are frequently susceptible due to where they are kept. You have many options for storage, ranging from plain text to utilizing a password manager. However, an attacker looks at many other places to find any valuable information related to user credentials. For example, auditing files. Your system logs failed password attempts. This generally includes a considerable number of passwords. If you don’t keep them safe, people who come across a recording of failed login attempts may try it for all valid user identities.

**Misapplication of cryptographic hash functions (CHF)**

When you enter a password, it passes through a one-way algorithm, and you are only logged in if it matches a previously saved hash value. However, it is frequently implemented incorrectly. The correct method is to construct a random value, (which is also referred to as salt) and combine the password with the salt. You should also prefer a slow but cryptographically strong algorithm and save both the salt and the hash values in a safe place.

**Password files**

Certain operating systems utilize password-encryption files. However, these OSs make it widely accessible. As a result, a person with access to it may decrypt passwords.

In modern Linux versions, you can benefit from salting the passwords, and keeping them in a directory where only the root user has access to them. However, if you've encrypted a file with a password you've forgotten, there are still password-recovery solutions available to assist you.

**Credential stuffing**

Credential stuffing is an attack in which you infiltrate a system using a list of stolen login details. It is a scenario in which your system may be hacked, credentials cracked, or found unprotected. They are then checked on other platforms to identify how many individuals have reused them. This is still an ongoing problem.

Deception is one mitigation method worth considering since it can work at many levels of the stack. Honeypot systems that alert whenever somebody logs is an option.

**Remote verification**

Some systems verify passwords offsite, utilizing cryptographic methods to safeguard the password while it is in transit, and the connection between password security and network security may be complicated.

Local networks typically utilize the Kerberos system, in which a server provides you with a key that is encrypted with your password; if you know the password, you may decode the key and use it to receive tickets that grant you access to resources. However, the Kerberos protocol may not always protect easy-to-guess passwords from an attacker.

**TLS**

To encrypt communication from your browser, most web servers employ a technology called TLS. If the server is compromised, TLS will not protect you. You can prefer Simultaneous Authentication of Equals (SAE) technology if you want to set up safe connections even when the credential is not strong.

## Conclusion

In this blog we have covered possible places where an attacker looks to steal user credentials, and vulnerabilities of some practices we employ daily. As you can see, passwords are the most common way to secure access to accounts and websites. Hovewer, they are also the easiest to hack. You should always protect your passwords where they are stored.

> **Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)!**
