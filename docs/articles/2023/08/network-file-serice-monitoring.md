:orphan:
(network-file-service-monitoring)=

# Monitoring Services, Networks and Files

In today's digital landscape, where data breaches and cyber threats are more common than ever, the proactive monitoring of services, networks, and files has become an essential practice for organizations to safeguard their critical assets and ensure continuous operation. Indeed,  It is often an unauthorised change to a file, service or network asset which first alerts a blue team to the presence of attackers in the network. This article looks at some of the key monitoring techniques, including port spanning/ port mirroring, port taps, monitoring services, and file integrity monitors.

 

## Port Spanning/Port Mirroring

Port spanning, also known as port mirroring, is a network monitoring technique that involves duplicating traffic from one network port to another. This process allows network administrators to analyze network traffic without interrupting its flow. Port spanning is particularly useful for monitoring network performance, identifying anomalies, and detecting potential security breaches. Setting up a port mirror using spanning is also usually the preferred way to provide information to a Network Intrusion Detection System (NIDS).

SPAN is usually performed on a single switch chassis, and takes place at layer two – this usually means that the source and destination ports must be located on the same device. Often this is perfectly acceptable, however an extension of span, known as **RSPAN** adds to the capabilities of traditional SPAN by allowing the monitoring of traffic from source ports on remote switches. This is particularly valuable in larger network infrastructures where physical proximity can limit direct monitoring. RSPAN can aggregate monitored traffic from multiple switches onto a single switch, simplifying monitoring access. 

```
user@switch> show analyzer
  Analyzer name                : traffic-monitor
  Output interface             : ge-0/0/10.0
  Mirror ratio                 : 1
  Loss priority                : Low
  Ingress monitored interfaces : ge-0/0/0.0
  Ingress monitored interfaces : ge-0/0/1.0
  Egress monitored interfaces  : None
 
```

 *Checking the configuration of a port mirror analyser in Juniper Junos*



## Port Taps

Where SPAN takes place in software, port taps are physical devices that provide a non-intrusive method of monitoring network traffic. Unlike port spanning, which operates within the network infrastructure and consumes computational resources, port taps are external devices that "tap" into the network cable, capturing traffic without introducing additional load to the network. This approach minimizes the risk of disrupting network operations while still providing comprehensive visibility. Being a physical device, however, taps are less flexible than SPAN or RSPAN which can be easily reconfigured as required. 

In a high-security environment, a financial institution might deploy port taps to monitor the communication between its internal systems and external networks. The tap captures all traffic passing through the network cable, allowing for real-time analysis and threat detection without affecting network performance. 



## **Network Monitoring** 

As network performance has become more critical, network monitoring has become more commonplace. More often than not, the primary reason for network monitoring is to identify possible bottlenecks and ensure optimal performance, however, network monitoring can also be of great value from a security point of view. Monitoring a network for security involves collecting and scrutinizing network data to unearth possible indicators of compromise, such as unusual traffic flows, errors or data spikes at odd times. Many organizations now offer network security monitoring as a service, providing enterprises with the ability to detect breaches and unauthorized access whether they have dedicated staff or not. While preventive measures are vital, network monitoring can offer a good chance to notice an attack which may have bypassed an initial line of defence. 

 

## Service Monitoring 

Service monitoring focuses on tracking the availability and performance of essential IT services and applications within an organization's infrastructure. The specific services which need to be monitored will usually be determined by business processes, with the most critical systems usually the best candidates for constant monitoring. 

By continually observing the health of these services, administrators can proactively identify potential issues, minimize downtime, and ensure a seamless user experience. Service monitoring involves setting up various checks and probes to assess the responsiveness and functionality of services. This can encompass a range of metrics, including response times, server resource utilization, error rates, and more. Monitoring tools are configured to periodically send requests to these services, simulating user interactions and gathering real-time data. In the event of a service disruption or degradation, monitoring tools send alerts to administrators, enabling swift intervention before users are impacted. 

For example, an e-commerce platform can use service monitoring to ensure that its online payment gateway and inventory management system are operating optimally. Through continuous monitoring, administrators can promptly detect any anomalies, resolve issues, and uphold a high level of service quality, contributing to enhanced user satisfaction and uninterrupted business operations

 

## File Integrity Monitors

File Integrity Monitors (FIM) are systems or programs which constantly check critical files and configuration data for unauthorised changes.  Built-in OS utilities and dedicated applications often oversee this crucial task, ensuring the trustworthiness of files and programs. FIM itself is simply intended to provide an alert if any aspect of a monitored file changes, but the data and alerts from FIM often feed into other security solutions such as endpoint detection and response software.

Some application whitelisting solutions can also leverage FIM by cross-referencing the hash values of files to a predefined list of legitimate values before authorizing program execution. Even when downloading files from reputable sources, performing a file integrity check is recommended - this practice unveils any alterations to the file, safeguarding against tampering or unauthorized modifications which may have occurred as part of a supply chain attack.  

You can easily test this out yourself - on Windows systems, the command-line directive `sfc /scannow` performs a comprehensive system file integrity check. Similarly, on Debian Linux systems, the `debsums` command validates hash values of installed package components.

```
C:\>sfc /scannow

Beginning system scan. This process may take a while.

Beginning verification phase of system scan.
Verification 100% complete.

Windows Resource Protection did not find any integrity violations.

C:\>
```

*Running sfc /scannow on Windows - no changes are detected.*

```
user@debian:~$ debsums -c

Checking installed files against checksums from package.
The following files are affected:
 /usr/bin/bash
 /lib/x86_64-linux-gnu/libc.so.6
 /etc/apt/sources.list
 /etc/ssh/sshd_config

user@debian:~$
```

*Running debsums on Debian, this time some files have been modified*.

# Final words

Monitoring services, networks, and files is an essential aspect of modern cybersecurity. Techniques like port spanning, port taps, monitoring services, and file integrity monitors provide organizations with the tools to maintain operational integrity and protect against a variety of threats. By implementing these monitoring strategies, organizations can identify vulnerabilities, detect anomalies, and respond to incidents in a timely manner. As cyber threats continue to evolve, proactive monitoring remains an indispensable practice in the ongoing battle to safeguard valuable assets and ensure the confidentiality, integrity and availably of data.
