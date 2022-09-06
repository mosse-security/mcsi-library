:orphan:
(advanced-persistent-threat-lifecycle)=

# Advanced Persistent Threat Lifecycle

An advanced persistent threat (APT) is a type of attack campaign in which an unauthorized user gains access to a network and remains there undetected for a prolonged period of time. These attacks are often orchestrated by highly skilled and well-funded adversaries and are designed to achieve specific objectives, such as espionage or data theft. While APT attacks can be difficult to detect and defend against, there are a number of steps organizations can take to reduce their risk of becoming a victim.

APTs may target an organization's IT assets, financial assets, intellectual property, and reputation. Commonly used security and defensive mechanisms will not sufficient to prevent such attacks. To effectively attack and get access to the target system, attackers must go through each phase step by step.

_The various phases of the APT lifecycle are as follows:_

## Preparation

The first stage of the APT lifecycle is preparation, during which an adversary defines the target, conducts thorough research on the target, gathers a team, creates or obtains tools, and runs detection tests. APT attacks typically demand extensive planning since the adversary cannot risk being detected by the target's network security.

## Intrusion

For an initial intrusion, common tactics include email spear-phishing in which the email appears genuine to the user, but contains malicious attachments or harmful links. These malicious links can redirect the target to a website where the attacker can compromise the target's web browser and software using various exploit techniques, Another method where the attacker obtains an initial foothold is by exploiting known vulnerabilities in publicly accessible servers.

## Expansion

The main objective of this phase is to expand access to the target network and obtain administrative login credentials to escalate privileges. If the attacker’s aim is to exploit and gain a single system, then there is no need to expand. However, in most cases, the objective of the attacker is to access multiple systems using a single compromised system. When attackers are unable to obtain valid credentials, they use other techniques such as social engineering, exploiting vulnerabilities, and distributing infected USB devices.

## Persistence

The main objective of this step involves keeping access to the target system, starting with bypassing IDS and firewalls, entering the network, and establishing system access. Attackers use custom malware and repacking tools to maintain access. These tools are intended to avoid detection by the target's antivirus software or security tools. Attackers also identify locations where malware might be installed that are not usually detected. These locations include firewalls, printers, routers, etc.

## Search and Exfiltration

In this phase, an attacker archives the ultimate goal of network exploitation, which is to exfiltrate the resources that can be used for performing further attacks or use that resources for financial gain. A common method for search and exfiltration is to steal all the data including important documents, emails, shared drives, and other types of data present. Data can also be gathered using automated tools and usually, attackers use encryption techniques to avoid data loss prevention technologies in the target network.

## Cleanup

This is the final phase, in which an attacker cleans up the target to avoid detection and remove traces of compromise. Attackers cover their traces by clearing logs and the any files which can hint of an attack. An attacker can also manipulate data in the target environment to mislead security experts.

> **Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)!**
