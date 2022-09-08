:orphan:
(a-quick-start-guide-to-network-monitoring-and-security-features-in-aws)=
# A Quick Start Guide to Network Monitoring and Security features in AWS 

Amazon web services offer strong protection against standard network security vulnerabilities. In this blog post you'll find some of the network management and defense services and functionalities that AWS offers for clients.

## DDoS (Distributed Denial of Service) attacks

AWS API locations are housed on enormous, large-scale, worldwide infrastructure, and they employ proprietary Distributed Denial of Service (DDoS) mitigation methods. AWS connections are also multi-tiered among many suppliers to ensure Internet connection variety.

## Person-in-the-Middle (PITM) attacks

All AWS APIs are accessible over SSL-protected interfaces. These endpoints offer server authentication. On the initial boot, Amazon EC2 Amazon Machine Images (AMIs) create new Secure Shell (SSH) client certificates and then log them to the machine terminal. While you log in to the device for the first time, you may utilize the secure APIs to contact the terminal and get the client certificates.

AWS recommends that you utilize SSL for all of your communications.

## IP spoofing

Amazon EC2 instances are not permitted to transmit impersonated internet activity. The AWS-managed, host-based firewall system will not allow an instance to transmit communication with a source IP or MAC address outside of its own.

## Unauthorized port scanning

Illegal port scanning by Amazon EC2 clients violates the _AWS Acceptable Use Policy_. AWS Acceptable Use Policy violations are treated professionally, and every reported intrusion is inspected. Consumers can reach out to AWS to report a suspected violation using the AWS website's contact details. When AWS detects illegal port scanning, it stops and blocks it.

Port scans on Amazon EC2 instances are often useless since all outgoing ports on Amazon EC2 instances are blocked by default and may only be opened by the user.

Proper administration of security groups may help to reduce the risk of port scans even more.
If you set the security group to allow traffic of any origin to a given port, that port will be susceptible to a port scan.

You should take adequate security precautions to safeguard the listening services that may be critical to its app or software. They may be the target of an attacker during an illegal port scan. A web server, for example, should explicitly have port 80 (HTTP) accessible to the public as well as the server administrator, who is in charge of the security of the HTTP server. You can ask for authorization to do vulnerability scans as needed to fulfill your unique regulatory obligations.

The above inspections must only be performed on your own machines and must not infringe on the AWS Acceptable Use Policy.

## Packet sniffing by the other clients

Even though you may configure your interfaces to be in promiscuous mode, the hypervisor can not send any traffic that is not destined for them. Even two virtual instances run by the same client and hosted on the same physical machine are not allowed to see each other's traffic. While Amazon EC2 ensures enough security against one user unintentionally or deliberately trying to access another user's data, you should encrypt critical communications as a routine practice.

## Summary

In this blog article, we discussed some of AWS's network surveillance and protection services. These measures help you defend your systems from a variety of attacks, including Person-in-the-Middle (PITM), IP spoofing, unauthorized port scanning, and packet sniffing.

> **Want to learn practical cloud skills? Enroll in MCSI’s - [MCSF Cloud Services Fundamentals ](https://www.mosse-institute.com/certifications/mcsf-cloud-services-fundamentals.html)**