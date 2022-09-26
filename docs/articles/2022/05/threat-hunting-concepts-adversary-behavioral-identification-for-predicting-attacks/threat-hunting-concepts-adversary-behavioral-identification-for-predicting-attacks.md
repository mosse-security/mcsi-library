:orphan:
(threat-hunting-concepts-adversary-behavioral-identification-for-predicting-attacks)=

# Threat Hunting Concepts: Adversary Behavioral Identification for Predicting Attacks

Adversary behavioral identification is all about predicting attacks. It involves identifying the typical attack tactics or techniques used by an adversary to launch cyber attacks on a target network. It helps security experts in developing secure network infrastructure and adopting a variety of security techniques to prevent cyber attacks.

## Internal Recon

Once an attacker gains a foothold inside the network, they may begin enumerating other systems, hosts, processes, and programs that are running, maybe in search of another system of interest. This behavior is alarming, and security professionals should look for strange batch files, unexpected commands executed in PowerShell and bash scripts, and by using packet capture tools like Wireshark and Tcpdump.

## PowerShell

Windows PowerShell enables IT professionals to manage and control the Windows operating system and apps. An attacker can use PowerShell as a tool for data exfiltration, system exploration, and connecting to external systems. Entire harmful frameworks have been built around PowerShell, due to its ability to configure and work with networks. To identify this behavior, security experts can check PowerShell transcript logs or Windows Event logs and look for PowerShell usage by someone other than administrators.

## CLI/Terminal

An adversary can use the command-line interface to interact with the target system, view files, edit file content, connect to a remote system, and download and install malicious malware. Security professionals should analyze log files of process IDs with strange names and malicious files to determine an adversary's actions. for example, a process started from PowerShell with the execution policy bypassed should be monitored.

## Command and control server

The attackers use command and control servers to maintain communication with compromised systems via encrypted network sessions. In many cases, Command and control server traffic indicates that the attacker has gained access to the network and is planning to install additional tools. The adversary can steal data, erase data, and launch new attacks using the C&C server encrypted channel. This behavior can be detected by monitoring network traffic for outbound connection attempts and unauthorized open ports. Finding IP addresses and domains that are known to be C&C server traffic and blacklisting them is one approach to guard against the C2 server.

## DNS tunneling

The domain name system (DNS) resolves domain names into IP addresses, which are then used by browsers to load web pages. An attacker can use DNS tunneling to obfuscate malicious traffic into the legitimate traffic through common protocols that would not necessarily cause alarm. using the DNS tunneling an adversary can also communicate with the command and control server and perform data exfiltration.

## Data staging

Data exfiltration is the unauthorized copying or transfer of data from a computer or network. If data exfiltration is the goal after successful network penetration, the attacker uses the data staging technique to collect and combine as much data as possible. The attacker can gather sensitive information about employees and customers, as well as financial data, business techniques, and network infrastructure data. This behavior can be detected by monitoring network traffic for any malicious file transfer, file integrity monitoring, and event logs.

## Summary

Understanding the adversary's behavioral identification is critical because it provides insight into the common strategies used by adversaries to launch attacks. It provides security professionals with early warning of potential threats and exploits.

:::{seealso}
Want to learn practical Threat Hunting tactics and strategies? Enrol in [MTH - Certified Threat Hunter Certification](https://www.mosse-institute.com/certifications/mth-certified-threat-hunter.html)
:::
