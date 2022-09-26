:orphan:
(remote-code-execution-is-a-serious-threat-be-prepared)=
# Remote Code Execution is a Serious Threat Be Prepared
 
If the attacker succeeds in taking complete control of the victim's device, he can carry out a variety of harmful tasks like gaining root-level access, installing backdoors, setting up a command and control server, infecting further devices in the network, and much more. Utilizing the remote code execution vulnerability, or RCE in short is one method by which the attacker might get unauthorized access to a remote device. Through the use of remote code execution, attackers can remotely run malicious software on a devices or system. In this article, the fundamental ideas underpinning remote code execution, its impact, the many types of attacks, and the preventative measures to address this vulnerability are covered.

## What is meant by RCE (Remote Code Execution)?

Remote Code Execution is a type of cyber attack in which an attacker can execute malicious code or script on the victim's remote device. While malicious malware is being executed on the victim's device, he is unaware of it. The attacker successfully uses this method to take full control of the remote computing device. Remote Code Execution is a subset of the larger domain of Arbitrary Code Execution. The ability to execute any command or piece of code on the target machine is known as "arbitrary code execution."

In a typical remote code execution attack, the attacker sends arbitrary HTTP requests to an HTTP server over the internet, LAN (Local Area Networks), or WAN (Wide Area Networks). The attacker can use his code to obtain access to a web server or application, fully control or compromise it, open backdoors, steal, modify, or delete data, carry out ransomware attack, etc. after he finds a vulnerability that enables him to inject his code. This type of attack is typically carried out using application interfaces that are visible to the public. RCE attacks are carried out by utilizing the underlying programming language of the web server such as Python, Perl, Java, PHP,Ruby, and much more. The remote code that is injected is then interpreted and executed by this back-end programming language. This attack therefore results in the complete takeover of the underlying server of the application.

## Example of Remote Code Execution attack

Consider the following scenario in order to better understand how this attack works. For example, let us suppose that a web page of an application allows the users to upload files on the web server. Now let us suppose that the application is vulnerable (i.e. it doesn't validate the user input properly) and lets the user upload files with the extension of his choice. The attacker exploits this vulnerability to upload a file containing reverse shell. Now after the file is uploaded, the attacker with help of directory listing tools discovers the directory in which the uploaded files are stored. Now all the attacker simply has to do is navigate to the directory containing the file and the reverse shell will automatically be executed on the web server. Upon execution, the attacker will get a shell on the web server which he can leverage to carry out malicious activities.

## Impact of the Remote Execution Vulnerability

Remote code execution usually occurs when a web application or other application programming interface accepts input without validating or otherwise sanitizing it before the parser of the underlying programming language interprets it. The remote code execution vulnerability has a very high impact and is always classified as a critical vulnerability. Due to this reason, bug bounty hunters are generously compensated for reporting RCE bugs. Some of the effects that the target can experience as a result of this attack is listed below:

**Complete takeover of the application or its server:** An attacker can exploit the RCE vulnerability to completely take over the web application and the web server.

**Escalation of privileges:** An attacker can exploit this vulnerability to escalate his privileges to the administrator or root level on the target machine.

**Information disclosure:** An attacker can exploit this vulnerability to gain access to the sensitive or confidential information stored on the server such as web configuration files, user passwords, confidential customer information, and much more.

**Modification or deletion of important data:** An attacker can exploit this vulnerability to modify or delete important files or data stored on the server.

**Monitoring Organization's Activities:** An attacker can utilize the RCE vulnerability to establish himself in the network and monitor the organization's critical operation. He can therefore leverage this information to carry out further harm such as learning companies trade secrets.
 
**Denial of Service Attack:** An attacker can cause the important services or applications running on the webserver to crash resulting in the denial of service attack.

**Ransomeware Attack:** An attacker can compromise the entire web server and install malware to encrypt sensitive files or data present on the server. He can therefore hold them hostage in exchange for getting ransom from the victim organization.

## Different ways to Execute Remote Code Execution attack

This section lists some of the ways in which an attacker can carry out a remote code execution attack. All of these attacks depend on a specific vulnerability, and in each scenario, the attacker has the ultimate goal to obtain unauthorized and unfettered access to the target system. This section describes each one of these scenarios in detail:

### Type Confusion

Type confusion can be referred to as the scenario when the software allocates or initializes resources like pointers, objects, or variables using one type, it then accesses those resources using a type that is incompatible with the initial type. Because the resource does not have the required attributes, logical errors may be caused when the program accesses the resource using an incompatible type. A malicious attacker can use this vulnerability to compromise an entire system by creating a specially crafted web page, tricking the victim into accessing it, causing a type confusion issue, and executing arbitrary code on the target.

### Insecure Deserialization attacks

A procedure known as serialization involves converting an object into a data format, such as bytes so that it can be restored later or sent across a network. On the other hand, deserialization reconstructs the item using the structured data to rebuild the original object. It is possible for an attacker to manipulate a serialized object and have undesired effects on the program's flow, which is a sort of vulnerability known as insecure deserialization. In order to remotely execute malicious code, the attacker can use this vulnerability to inject this code into the serialized object. In the absence of proper input validation, the web server will deserialize it, resulting in the execution of the attacker's malicious code. 

### Buffer overflow attacks

A buffer overflow vulnerability is a type of memory corruption that can also allow the execution of malicious RCE. Buffers are sequential memory partitions that can only hold a certain amount of data. Programs without bounds-checking safeguards run the risk of having an input that exceeds the memory that is allotted. When a buffer overflows, the memory in nearby buffers is overwritten. Utilizing buffer overflows maliciously can result in the destruction of important data, network crashes, or the execution of arbitrary code in memory by utilizing the instruction pointer after it has been altered by a different vulnerability.

## Real World Remote Code Execution attacks

This section goes over some of the most dangerous and widespread attacks that have been executed by exploiting a Remote Code Execution Vulnerability. 

### Apache Log4j Remote Code Execution Vulnerability - Log4Shell

A significant security issue in the Log4j framework allows attackers to compromise vulnerable systems due to malicious code injection. The user activity logger known as Log4J, a logging package made available for free by the Apache Software Foundation, is linked to the vulnerability. This security flaw has been labelled as the single most significant and critical vulnerability ever. Although it had been around since 2013, it was only discovered in November 2021 and made public in December of the same year. Java is used in a wide range of digital products, including cloud solutions, web servers, and apps, rendering each of these items vulnerable to exploitation via the Log4Shell vulnerability. This security flaw in Log4j enables users to run any Java code on servers, allowing for malware injection, botnet development, and ransomware attacks.

### WannaCry Remote Code Execution attack

The ransomware infection known as WannaCry made effective use of the Remote Code Execution vulnerability in Windows Operating systems. In May 2017, this computer network worm propagated quickly over several different networks. The way this worm operates is by infecting Windows machines, encrypting its contents on the hard drive to prevent users from accessing them, and then demanding a bitcoin ransom to unlock the files. Hackers were able to use the EternalBlue exploit to take advantage of the Windows vulnerability known as MS17-010 to distribute WannaCry worm. The NSA found this security flaw and instead of alerting Microsoft, they created code to take advantage of it. A mysterious hacker organization called The Shadow Brokers later obtained and released this code. EternalBlue was discovered by Microsoft, which then issued a patch to remediate this vulnerability. WannaCry is still one of the most notorious and well-known ransomware variants to this day.

## Preventive and detective techniques to mitigate RCE vulnerabilities

The targeted application or the web server may suffer serious consequences due to this extremely serious vulnerability. As long as this vulnerability is not promptly detected and patched, the attacker can exploit it to launch a variety of attacks. In order to identify and prevent attackers from conducting code execution attacks, a number of recommended strategies are covered in this section.

### Monitoring network traffic and endpoints

One of the main techniques that can be used to detect and block malicious activity related to code execution attacks is to monitor your network. Some of these techniques involve configuring your network firewalls to block any suspicious network activity such as exfiltration of sensitive data, unusual outgoing network connections, lateral movement within the network, and much more. In addition to monitoring your network traffic, you can also monitor and detect the organization's endpoints for suspicious activity such as access to sensitive data, monitoring the activity related to privileged accounts, attempts to encrypt the organization's files, and much more. Some of the tools that the organization can use to monitor the network and the endpoints include hardware firewalls, web application firewalls, network, and host-based intrusion detection systems, and intrusion prevention systems.

### Keep your computing devices and software updated with the latest versions

This preventive measure is extremely important to deal with RCE attacks. Organizations often times fail to install and deploy the latest security patches on their operating systems, devices, and third-party software used in the enterprise. This can lead to the attacker exploiting the known vulnerabilities in the older versions of the target systems or software. Therefore it is imperative for the organization to deploy the latest system or software updates and keep them updated to the latest version. Oneof the solutions that the organization can use is to deploy a centrally managed software to detect unpatched systems or applications and automatically download the latest updates.

### Implement buffer overflow protection

RCE attacks can also be prevented by implementing buffer overflow protection. Buffer overflow protection can be achieved by developing mechanisms in the server software to detect buffer and prevent buffer overflows. Buffer overflow software protection works by adding a canary value to memory that is allocated to a process. If this canary value gets overwritten, it can be indicative of a buffer overflow. You can identify buffer overflow, terminate the impacted process, and prevent an attacker from exploiting it by checking and verifying this canary value.

### Implement input validation

Implement a zero-trust approach while developing the web applications. It is very important to always sanitize user input before it is accepted by the server. The developers can utilize whitelists, blacklists, and escape sanitization to properly validate and sanitize user input. This will aid in filtering out numerous attempts at code injection and deserialization. Additionally, the application must have security controls that protect it from code evaluation attempts and forbid users from editing any parsed text.

### Implement strict access controls

Sometimes an organization's lax access control policies can end up granting excessive permissions to the organization's users. This can allow the attacker to access, modify and/or steal an organization's sensitive information. Enforce strict access control policies that are based on the principle of least privilege. Using this principle will ensure that the users only have those access to those resources that are necessary to perform their job responsibilities. This will ensure to a certain extent that the organization's sensitive information is protected from unauthorized access.

### Monitor and log activity related to privileged accounts

Privileged users play an important role in every organization. They have access to the most vulnerable areas of the corporate network and are aware of all the key company secrets. Activities involving the privileged accounts in the organization should be tracked and recorded by the organization. It is important to keep an eye on these accounts for any suspicious activity or misuse of the privileges.

### Invest in good quality threat detection software

Software for detecting threats can be crucial in preventing RCE. Incoming communication can be scanned by threat detection software, which can also identify suspicious activity and infiltration attempts. This type of software can also detect and block hosts with suspicious activity.

### Conduct Regular Security Testing in the organization

In order to find security holes and fix them before attackers can use them to launch new attacks, the organization must conduct frequent security testing. A crucial and extremely effective method of preventing the exploitation of RCE vulnerability is to perform penetration testing that focuses on finding potential RCE attack vectors.

### Secure File Upload forms in the application

The web application should never let a user choose the file extension or content of files stored on a web server. Instead, implement secure file uploading best practices such as implementing a whitelist of allowed file extensions that can be uploaded on the server.

## Conclusion

The remote code execution vulnerability is a serious security flaw that could have devastating effects on the company. The use of various security controls by an organization is crucial to identifying and thwarting threats that can launch RCE attacks. Regular testing is also necessary to quickly identify and fix RCE vulnerabilities.

:::{seealso}
Want to learn practical Secure Software Development skills? Enrol in MCSI’s [MASE - Certified Application Security Engineer](https://www.mosse-institute.com/certifications/mase-certified-application-security-engineer.html)
:::