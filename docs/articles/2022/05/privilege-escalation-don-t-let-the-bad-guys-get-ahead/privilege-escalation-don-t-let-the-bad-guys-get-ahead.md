:orphan:
(privilege-escalation-don-t-let-the-bad-guys-get-ahead)=

# Privilege Escalation: Don't Let the Bad Guys Get Ahead

Privilege escalation is a technique used by attackers to gain elevated access to resources or data that are normally forbidden to them. By exploiting vulnerabilities or misconfigurations, an attacker can escalate their privileges and gain access to sensitive information or perform actions that would otherwise be forbidden.

## Types of Privilege escalation attack

There are many different types of privilege escalation, each with its unique characteristics. To truly comprehend privilege escalation, you must first grasp the various categories and how they work. Privilege escalation can be classified into the following categories: horizontal, and vertical.

### Horizontal Privilege escalation

Horizontal privilege escalation is an attack that requires an attacker to get access to another system. For instance, to successfully broaden his access to a similar privilege level, the attacker can use the following methods. It could be a person who might have stored his username and password in his webserver or home directory. Phishing campaigns are currently one of the most popular attack methods, in which an attacker sends a tailored email with a link that seems like a legitimate site and tricks the user into logging in using his username and password.

### Vertical privilege escalation

Vertical privilege escalation is an attack in which an attacker acquires access to a highly privileged user, usually a root or administrator account, and services that are only accessible by root users. Once the malicious actor has gained access to the system, he can inflict all kinds of damages: Launch a ransomware attack to encrypt data, steal sensitive information, install backdoors, and erase data. An attacker who has a better understanding of the host system will usually disguise his tracks by tampering with logs and burying any changes he made deep within the system. They can remain undetected for a long time in this manner.

## Common privilege escalation attack methods

### Credential Exploitation

Stealing credentials and logging in as a valid user is one of the easiest ways for a hacker to get access to any system. An attacker first tries to gain a privileged user's username through Data Breaches and Dark Web. Attacker then focuses on cracking the password once they've figured out the username. Hackers get a free pass to move around the system undetected once they know the username and password.

The attacker then sets up some measures that allow him to access the system even if his actions are detected and the password is reset by the host. For example, They can maintain their presence by installing backdoors or rootkits.

### Privileged vulnerabilities and their exploits

Vulnerabilities can exist in a web application, service, operating system, or any other networked digital device. But does a vulnerability itself enough to escalate privileges? No, A vulnerability lets us know there is a possible exploit, To understand the potential consequences of the vulnerability, we must first learn what an "Exploit" is.

An exploit is a malicious code or software which leverages the vulnerability present in any system. Most of the exploits we find on the Internet are POC, while some exploits are reliable and easily weaponized others are unreliable. Exploits can also be found on the dark web.

In any organization there are many users in play, some might have fewer privileges, and others might have administrative access. Based on the privilege level we can know the amount of damage any vulnerability can cause. For example, let us assume a web application has been compromised, If the privileges are that of a standard user, the exploit might fail as there might be no way to elevate privileges. On the other hand, if the user has administrative privileges, this leads to a vertical privilege escalation.

### Misconfigurations

If you're a system administrator, you're well aware that misconfigurations can cause dozens of new issues. Did you know, however, that misconfigurations can result in privilege escalation? It can happen if a system isn't set up correctly. For example, if a system administrator creates a new user account with excessive rights, that user may be able to access sensitive information. To avoid privilege escalation, double-check your system's settings to ensure that only the appropriate users have access to the relevant privileges.

## Best practices to avoid privilege escalation

### Manage user Privileges

System administrators and security teams must make sure that they have allocated and defined the roles and privileges of each user clearly. Every user in the organization should have privileges concerning their job roles, This reduces the chance of privilege escalation by some services which were not supposed to be there in the first place.

### Use Multi-Factor authentication

Broken authentication mechanism are one of the most exploited vulnerabilities in any web application, Vulnerabilities such as IDOR, Session hijacking and brute force attack( Due to lack of login security mechanisms) makes way to privilege escalation.

Using complex passwords and security mechanisms like OTP authentication makes it difficult for an attacker to get access to the user accounts which can be entry points to a highly privileged security breach.

### Revoke default credentials

Using default credentials might be risky and result in a serious security breach. Many modern applications have default credentials, which, if not changed, can lead to serious vulnerabilities such as remote code execution, which could be exactly what an attacker needs to escalate his privileges.

### Regular security scans

Regularly scan for vulnerabilities and malware signatures in your application in many applications and services you use to get regular updates, it can be from a third-party vendor or an in-house update. This can allow an attacker to explore unknown vulnerabilities and get the initial foothold required to escalate privileges, this can be avoided by regularly scanning the network and patching any vulnerabilities which are detected during the process.

### User behavior monitoring

User behavior monitoring (UBM) is a security approach that detects and responds to irregularities in user behavior that may indicate a security breach. UBM can help organizations avoid privilege escalation threats and keep their data and systems safe by monitoring user activity and spotting strange patterns.

## Final words

Preventing privilege escalation is a critical security measure that should be included in any security strategy. By limiting user privileges and implementing least privilege policies, you can make it more difficult for attackers to gain access to sensitive data and systems. In addition, regularly auditing user privileges and activity can help you identify potential privilege escalation attempts and take action to prevent them.

:::{seealso}
Looking to expand your knowledge of penetration testing? Check out our online course, [MPT - Certified Penetration Tester](https://www.mosse-institute.com/certifications/mpt-certified-penetration-tester.html) In this course, you'll learn about the different aspects of penetration testing and how to put them into practice.
:::
