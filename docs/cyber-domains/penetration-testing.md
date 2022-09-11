(penetration-testing-main-page)=
# Penetration Testing

Penetration testing, also known as pen testing or ethical hacking, is the process of testing a computer system, network or web application to find security vulnerabilities that an attacker could exploit. Penetration tests can be used to test both internal and external systems and can be conducted using a variety of methods, including manual testing, automated tools, or a combination of both. Penetration testing is an important part of any security program as it can help identify weaknesses in systems before attackers do. By conducting regular penetration tests, organizations can keep their systems secure and reduce the risk of being breached.

## Procedures

```{admonition} What is a procedure and a workflow and why are they important?
:class: dropdown
A procedure is a set of instructions that detail how to carry out a task. It is important to have procedures in place so that tasks can be carried out efficiently and consistently. Having a procedure ensures that everyone knows what needs to be done and how to do it. This can help to avoid confusion and mistakes.

A workflow is a series of steps that are followed in order to complete an engagement. In penetration testing, a workflow is important in order to ensure that all steps are followed in order to complete the testing process. By following a workflow, penetration testers can ensure that they are thorough in their testing and that they do not miss any important steps. 
```

The image below proposes a workflow you can use to learn penetration testing:

<img alt="Penetration testing procedure and workflow" class="mb-5" src="/images/procedures/penetration-testing.svg">

**Articles:**

* [](a-general-overview-of-penetration-testing-methodologies)
* [](introduction-to-the-penetration-testing-workflow)
* [](mastering-the-preparation-phase-in-penetration-testing-engagements)
* [](reconnaissance-phase-in-penetration-testing-engagements)
* [](example-of-a-penetration-testing-report-executive-summary)

## Techniques

```{admonition} Why is learning penetration testing techniques important?
:class: dropdown
Techniques are important because they provide a means of achieving a desired outcome. They can be used to improve skills, to develop new ones, or to simply get a job done. There are many different techniques that can be employed, and the right one for any given situation depends on the goal. The most important thing is to select the appropriate technique and to use it correctly.
```

### Reconnaissance

The reconnaissance phase is the first phase of penetration testing and is used to gather information about the target system. This information can be used to identify potential vulnerabilities that can be exploited. Information gathering can be done manually or through automated tools. Automated tools can be used to scan for open ports, running services, and installed software. This information can help identify potential attack vectors. 

* [](network-footprinting-the-building-blocks-of-any-successful-attack)
* [](content-discovery-part-1)
* [](content-discovery-part-2)
* [](dns-enumeration-using-zone-transfer)

### Application Vulnerabilities

Application vulnerabilities are weaknesses in software that can be exploited by attackers to gain unauthorized access, compromise data, or cause other malicious activities. Common causes of vulnerabilities include poor coding practices, insecure configuration settings, and outdated software components. Attackers can exploit vulnerabilities to gain access to sensitive information, execute malicious code, or Denial-of-Service attacks. To prevent vulnerabilities from being exploited, developers need to follow secure coding practices and keep software up-to-date. Administrators also need to properly configure systems and deploy security controls. 

* [](common-code-injection-vulnerabilities)
* [](xml-external-entity-injection)
* [](server-side-request-forgery)
* [](an-introduction-to-web-shells)
* [](keep-your-web-application-safe-by-preventing-sql-injections)
* [](weaknesses-in-default-configuration-settings)
* [](idor-vulnerability-prevention-best-practices)
* [](avoid-race-conditions-with-our-easy-to-follow-strategies)
* [](how-to-prevent-insecure-design-vulnerabilities)
* [](broken-access-control-bac)

### Cloud Services Penetration Testing

Cloud penetration testing is a type of security testing that is used to assess the security of a cloud computing environment. The goal of cloud penetration testing is to identify vulnerabilities and weaknesses in the security of the system that could be exploited by an attacker. Cloud penetration testing can be used to test the security of both public and private cloud environments. 

* [](enumerating-aws-s3-buckets)
* [](s3-bucket-url-enumeration)
* [](enumerating-and-exploiting-aws-s3-buckets-with-s3scanner-and-flaws-cloud)

### Network Vulnerabilities

A network vulnerability is a security flaw that can be exploited to gain unauthorized access to a computer network. Common network vulnerabilities include unpatched software, weak passwords, and open ports. Exploiting a network vulnerability can allow an attacker to gain access to sensitive data, install malware, or launch denial-of-service attacks.

* [](find-out-what-is-banner-grabbing-and-how-to-prevent-it)
* [](bypass-ids-and-firewall-restrictions-while-network-scanning)
* [](directory-traversal-what-is-it-and-how-to-prevent-it)
* [](host-discovery-get-the-information-you-need-about-a-network)
* [](manual-and-automated-password-acquisition)
* [](scanning-smb-telnet-and-ftp-default-ports)

## Tools


```{admonition} Why do I need to master penetration testing tools?
:class: dropdown
Penetration testing tools are used to test the security of systems and networks. They are used to find vulnerabilities and weaknesses in systems and networks, and to exploit them to gain access to sensitive data or to take control of the system. Penetration testing tools are essential for ensuring the security of systems and networks, and for protecting against the ever-increasing threats posed by hackers and cyber criminals.
```

* [](using-netcat-as-a-reverse-shell)
* [](keep-your-systems-safe-with-regular-vulnerability-scanning)
* [](mimikatz-the-post-exploitation-tool-for-offensive-security-testing)
* [](understanding-the-different-types-of-scan-you-can-perform-with-nmap)
* [](privilege-escalation-don-t-let-the-bad-guys-get-ahead)
* [](a-brief-introduction-to-wordlists-and-how-to-generate-them-with-cewl)
* [](enumerating-active-directory-with-powerview))
* [](enumerating-smtp-with-metasploit)
* [](open-redirection)
* [](password-cracking-techniques-tools-and-protection-recommendations)
* [](using-metasploit-to-enumerate-ssh)