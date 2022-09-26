:orphan:
(a-general-overview-of-penetration-testing-methodologies)=

# A General Overview of Penetration Testing Methodologies

There are many ways to test the security of software, but penetration testing is one of the most common and effective. Penetration testing, also known as "pen testing," is a method of evaluating the security of a computer system or network by simulating an attack. Penetration testers use a variety of tools and techniques to test the security of a system. In this blog post, you are going to learn how penetration testing can be an invaluable tool for organizations to assess and improve their security posture. 

## Overview

As pen testers, we follow specific techniques to establish a clear path throughout a pentest, which makes the process more efficient and successful.

### Pre-engagement

Pentesting starts with the pre-engagement process, which includes discussing with the client about their pentest goals, and sketching out the scope (the extent and parameters of the test. When the pen tester and the client reach an agreement on these topics, real testing may start.

- Size/range of the IP addresses,
- Allowed actions and their results
- Duration, frequency, time, and date
- Agreed connection type and channel
- The written form of permission showing that you’re authorized to perform penetration testing
- Reporting format
- Non-disclosure agreement

### Reconnaissance

Reconnaissance is the first stage of the Ethical Hacker Methodology where we dedicate most of our effort to preparing for an attack. In this methodical process:

The type of information included is determined by how the organization operates.

Typically, we collect data on these groups:

- Network services, blocks
- Details about domain names
- Enumeration of the target
- Specific IP addresses of systems that can be reached
- System architecture
- Transmission Control Protocol (TCP) services in use
- User Datagram Protocol (UDP) services in use
- Running Intrusion Detection Systems (IDSs)
- Access Control List (ACL)
- Contact numbers, addresses
- Authentication procedures
- Type of the system

### Enumeration/Scanning

We utilize the information collected during reconnaissance to discover particular weaknesses in the scanning phase. It is a natural extension of active reconnaissance, and some experts do not distinguish scanning from active reconnaissance and the two stages may overlap. We need to enumerate all possible weaknesses to benefit from any opportunity in the next phase, which is “exploitation”.

### Gaining Access/Exploitation

After identifying the system's security weaknesses, we gain access to the system and exploit discovered flaws by using tools like Metasploit, Burp Suite, and SQLMap.

### Post-Exploitation

During post-exploitation, we acquire information about the system, hunt for interesting files, and attempt to escalate our privileges as needed. We may dump password hashes, for example, to see whether we can reverse them or use them to gain access to other systems.

### Reporting

In the reporting phase, we share our results with the client. We tell them what they're doing right, where they need to enhance their overall security, how we got in, what we discovered, and how to solve problems.

:::{seealso}
Want to learn practical Penetration Testing skills and improve mastery of penetration testing tools? Enrol in [MCSI's Penetration Testing Tools Master Course Certification Programme](https://www.mosse-institute.com/penetration-testing-certifications.html)
:::
