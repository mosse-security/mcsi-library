:orphan:
(an-introduction-to-web-shells)=

# An Introduction to Web Shells

A web shell is a malicious piece of code or script that is put on a target server and written in server-side languages such as PHP, ASP, PERL, RUBY, and Python. It gives an attacker the ability to run commands on the web application's server. The malicious script allows attackers to gain remote access to the target server's file system as well as remote administration capabilities.

Attackers inject malicious scripts by exploiting typical vulnerabilities such as remote file inclusion (RFI), local file inclusion (LFI), exposition of administration interfaces, and SQL injection. Attackers can also use social engineering techniques to install malicious code during XSS attacks. Sometimes attackers also use tools like Wireshark, and Zeek network monitoring tools to identify the vulnerabilities which can be exploited for web shell attacks. This type of vulnerability often lies in the content management system (CMS).

## How does the Web shell works?

Initially, the attacker uses common web vulnerabilities like Remote code execution, file upload, or SQL injection to send the reverse connection code or the file. Once the file or code is present in the target system, the attacker tricks the server to run the code or file to receive a reverse shell back to the attacker machine. If a web shell is successfully implanted into a web server, attackers can steal private data, destroy the website's reputation through DDoS attacks, change the structure of the website, make the web page's resources unavailable on the Internet, and maintain persistence, exfiltrate, etc.

_Some of common usage of web shells are as follows_

### Persistent Remote Access

A backdoor in a Web Shell script allows an attacker to remotely access and possibly control a server with Internet connectivity at any time this allows the attacker can keep a low profile and avoid any interaction with an admin, while still achieving the result.

### Privilege Escalation

An attacker can execute privilege escalation using a web shell by exploiting local system vulnerabilities. An attacker with elevated privileges can install malicious software, change user permissions, add or remove users, steal credentials, read emails, etc.

### Pivoting and Launching attacks

Web shells allow an attacker to compromise a system to gain a remote shell on it, and further bypass the firewall to pivot through the compromised system and gain access to the other vulnerable systems in the network.

### Botnet herding

Web shells can join servers to a botnet which then can be used for Denial-of-service attacks. These "herds" of bot machines, known as zombies, can then attack or infect other machines. The botnet is controlled by the herder using a command-and-control server that communicates over protocols such as Internet Relay Chat (IRC) or peer-to-peer (P2P) networking.

Some of the web shells that attackers use are WSO PHP Webshell, b374k, China chopper, Pentestmonkey, and WSO to gain remote control over target web servers.

## Prevention against web shells

The attacker uses web shells to escalate privileges and acquire remote access to download, upload, destroy, and run files on the target web server. So it is very important to defend against the web shells following are the countermeasure for web shells.

- Update the operating system and install fixes on a regular basis to protect the application and host server against known vulnerabilities.

- Block all unused ports and unwanted services on web servers.

- Create a demilitarised zone (DMZ) between your web server and your internal network.

- Use strong authentication procedures to ensure the web server's security and avoid using default passwords.

- To prevent directory traversal attacks, disable directory browsing on the webserver.

- Ensure that all online applications that use upload forms are secure and only allow the whitelisted file types.

> **Looking to expand your knowledge of penetration testing? Check out our online course, [MPT - Certified Penetration Tester](https://www.mosse-institute.com/certifications/mpt-certified-penetration-tester.html). In this course, you'll learn about the different aspects of penetration testing and how to put them into practice.**
