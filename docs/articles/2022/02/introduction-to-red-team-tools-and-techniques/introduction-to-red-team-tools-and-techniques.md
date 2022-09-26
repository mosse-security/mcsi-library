:orphan:
(introduction-to-red-team-tools-and-techniques)=

# Introduction to Red Team Tools and Techniques

The tools and techniques utilized by Cyber Red Teams are discussed in this blog post. Red Teams are individuals who engage in live-fire exercises to test an organization's security posture. Attempting to breach the organization's defences or imitating a real-world attack are examples of this. To achieve their objectives, red teams employ a variety of tools and techniques.

## Red Team Tools

The most critical consideration when picking tools for Red Team exercises is to undertake a benefits vs. risks analysis. Many automated tools will almost certainly generate alerts, and the main question is whether those notifications will trigger incident response (IR).

Even if IR is launched, the Red Team should plan ahead for how the investigation will go. What level of expertise will the first responders possess? Can we get away from them? Can we deceive them into underestimating the risks of our attacks?

### Vulnerability Scanners

_An automated vulnerability scanner is a computer program that automates the process of identifying security vulnerabilities in a computer system. These scanners can be used to scan networks, individual systems, or web applications._

Vulnerability scanners are often avoided by Red Teams since they are noisy and create a lot of traffic. These technologies can help identify susceptible systems rapidly, but they may not be the most effective for a targeted attack.

However, if you work in a Red Team and need to compromise a specific ICT asset, vulnerability scanners may be your only option. Consider the following considerations before making a final decision:

- What are the benefits of compromising the assets vs. the risks of getting caught?
- How likely is it that the Blue Team is monitoring the asset?
- Do we expect the Blue Team to do a detailed enquiry into the incident if the vulnerability scanner generates alerts? Will they use a junior analyst or a senior analyst to investigate?
- If the scans are detected, what negative impact could that have on the red team exercise?

### Exploit Kits

_Software exploitation is the process of gaining unauthorized access to a system or data by exploiting a vulnerability or weakness. The Red Team can use such flaws to accomplish their goals, such as installing malware or stealing sensitive information._

So you discovered a flaw with a publicly available exploit? Maybe Metasploit has everything neatly packaged? Now is the moment to determine whether or not to take advantage of it.

Anti-virus software, EDRs, and intrusion detection systems frequently grade exploitation attempts as HIGH risk, therefore proceed with caution.

Once again, a benefits vs. hazards analysis is recommended, and here are some additional questions to consider:

- How can we confirm whether the target machine is protected with AV/EDR? Can we identify the exact software name and version?
- How difficult would it be to re-engineer the exploit to reduce the risk of detection?
- Are there alternative options than exploitation that could achieve the same outcomes?
- How might we install a backdoor as a means of avoiding running the exploit again in the future?

### Phishing Emails and Websites

_Phishing emails and websites appear to be from a reputable source, but they are actually from the Red Team. Phishing attacks are designed to obtain personal information such as login credentials, credit card numbers, and social security numbers. Phishing emails and websites can be difficult to recognize since they are often quite convincing._

The majority of Red Team activities entail breaking into the target network via the Internet. Phishing is one of the most simple and prevalent methods. The Red Team can access Internet-facing interfaces that aren't protected by multi-factor authentication by stealing corporate network credentials. VPN, Citrix, and email are examples of this.

The majority of Red Teams will create their own phishing emails and clone websites with login pages. The success of their phishing effort will be determined by how carefully they identified the employees they want to phish, the quality of the emails, the social engineering tactics utilized and how well they are applied, and the legitimacy of the phishing websites.

With the correct pretext and social engineering tradecraft, we've been able to phish practically everyone within an organization.

### Spear-Phishing Framework

_A spear-phishing assault is one that is directed at a specific user. An email will be sent that appears to come from a reliable source, such as a friend or colleague. When the user clicks on a link or attachment in the email, malware is installed on their machine. Spear-phishing attacks are especially harmful since the attacker usually knows a lot about the target and may craft very convincing emails._

Advanced Red Teams will create their own spear-phishing platform, complete with their own exploits and capabilities:

- Target validation (i.e. IP validation, timezone validation, geolocation validation, browser fingerprinting etc.)
- Generating and delivering custom payloads on the fly
- Auto self-destruct after a certain period of time or if the framework detects behaviors attributed to the Blue Team
- Advanced logging and tracking to know whether targets have engaged with the framework
- Implementation of zero-days and n-days

### Password Guessing Tools

_Password guessing tools are computer programmes that use a combination of approaches to try to guess passwords, such as dictionary attacks and brute force attacks. Brute force attacks try every conceivable combination of characters, whereas dictionary attacks employ a list of popular passwords. Password guessing software can be extremely useful, particularly if the password is a simple word or string of characters._

1. **Online & Offline Password Cracking.** Online password cracking seeks to crack passwords in real-time as they are entered, whereas offline password cracking extracts passwords from a data repository, such as a file system or database.

2. **Password Spraying.** Password spraying is a method used by attackers to guess user account passwords. The attacker starts by testing a small number of regularly used passwords (such as "password," "123456," and so on) against a large number of user accounts. If the passwords are successful, the attacker tries variations of those passwords against other user accounts (e.g., "password1," "password2," etc.). Passwords for both user and administrator accounts can be guessed using this method.

### Command and Control (C2) Frameworks

_A C2 framework is a system that allows attackers to remotely manipulate compromised computers. This provides pentesters and red teamers with a valuable tool for managing infected systems and expanding their network reach. There are a variety of C2 frameworks to choose from, each with its own set of benefits and drawbacks._

Metasploit's Meterpreter is the most used C2 framework. Meterpreter is a popular choice among pentesters and red teamers since it is simple to use and offers a wide range of functions.

Advanced Red Teams will go so far as to write their own C2 framework in order to evade detection, force the Blue Team to reverse engineer the operation, and have complete control over every aspect of the operation.

### Zero-Day Exploits

_A zero-day exploit is an attack that takes advantage of a vulnerability in software that is unknown to the software maker or the security community. These exploits are highly sought after by some advanced Red Teams because they can be used to take control of computers or steal sensitive data without being detected._

The usage of zero-days in Red Team drills is a contentious topic. There are various grounds against doing so, including the fact that it is unreasonable to expect the target organization to defend itself against an attack it has no awareness of. Furthermore, some individuals question whether it is ethical for security professionals to keep vulnerability knowledge rather than reporting it to software vendors.

This post isn't intended to argue for one side or the other. Let's suppose for the time being that there may be legitimate instances in which a company could want a Red Team to use a zero-day to attack them.

Several clients have asked us to do this as a more realistic manner of testing intrusion detection software rather than providing us initial access in their ICT environment. The goal of the engagements also included evaluating security technologies that claimed to be able to block zero-day attacks.

Finding zero-day vulnerabilities may appear impossibly tough to the novice, and it can be in some circumstances. If the Red Team is expected to attack highly protected software, such as iOS devices or adequately secured Windows workstations, the assignment may be too tough for them to do. Most other types of enterprise software, on the other hand, are extremely vulnerable. A group of senior operators with a few weeks of research time can frequently find zero-days with relative ease.

## Red Team Techniques

The distinction between techniques and tools is significant. Techniques are the methods you employ to complete a task, whereas tools are the aids you employ to complete it. For example, the technique is how you use your hands, and the tool is a knife.

Although some of the approaches described below require the use of tools, they are included as techniques since the Red Team operator must manually identify and validate them first. They'll then decide on the best tool or approach to exploit any vulnerabilities found. In some circumstances, they may even create their own bespoke tools to do a technique in a very precise way.

### Open-Source Intelligence

_For red teaming, open-source intelligence, or OSINT, is a vital resource. All publicly available information, including social media, news channels, and government websites, is included in OSINT. Red teams can obtain a better grasp of their target and uncover potential flaws by gathering and analyzing this data._

A Red Team has access to hundreds of OSINT tools. Here's a list of important categories to consider:

1. Social media tools
2. Code search
3. Email search and check
4. ICT infrastructure enumeration
5. Search engines
6. Documents
7. Data breaches

### Web Application Vulnerabilities

_Web application vulnerabilities are coding flaws in web applications that can be exploited by the Red Team to gain access to sensitive data or take control of the application. Some common web application vulnerabilities include SQL injection, cross-site scripting, and session management flaws._

Vulnerable apps exposed to the Internet or deployed within the corporate network may be identified by the Red Team. In other cases, the purpose may involve gaining access to a specific application in order to steal data. Enterprise apps are frequently littered with vulnerabilities that may be identified quickly and effectively on the go.

- Injection vulnerabilities
- Broken authorization and access controls
- Security misconfiguration settings
- Malicious file upload

### Operating System Vulnerabilities

_Operating system vulnerabilities are holes in the security of the OS that can be exploited by the Red Team to gain access to the computer's data or to take control of the computer._

Advanced Red Teams are capable of detecting OS flaws in real time. They may start with a low-privileged account on a random machine, but they'll quickly find local privilege escalation vulnerabilities, steal credentials, and move on to other systems.

- Credentials stored on disk or in memory
- Local privilege escalation vulnerabilities
- Insecure software with administrative privileges
- Administrator password reuse
- Ability to uninstall security protections

### Open File Shares

_Open file shares are networked directories or files that anyone can access. This means that anyone on the network can view or alter files saved in an open file share, posing a security risk._

This is our favorite technique since it is straightforward, and it has proven to be highly vulnerable in every large organization we've tested.

The Red Team can exploit legitimate Windows network features to identify open file shares once it has gained access to the network and compromised a valid account. It can then slowly explore the shares and download data that its compromised user has access to.

Organizations, in our experience, do a poor job of controlling sensitive materials, and their networks are littered with documents and files that should have been removed or kept in secure folders.

## Final Words

It's critical to be deeply familiar with the tools and strategies utilized by cyber attackers if you work in cyber security. Many cyber professionals make the mistake of believing that technical nuances are unimportant to their job. That aligning conversations with frameworks and standards is enough in some way, when it's not. Please keep in mind that the quality of your decisions and advice is directly proportional to your expertise. The more deeply you comprehend tools and processes, the better a professional you will be.

We hope you found this post interesting and that you learned something new as a result of it. While we can't possibly cover all of the tools and techniques in this post, we've highlighted a few of the most significant. Thank you for taking the time to read this.

:::{seealso}
Looking to expand your knowledge of red teaming? Check out our online course, [MRT - Certified Red Teamer](https://www.mosse-institute.com/certifications/mrt-certified-red-teamer.html)
::: In this course, you'll learn about the different aspects of red teaming and how to put them into practice.**
