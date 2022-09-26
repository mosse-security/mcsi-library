:orphan:
(shared-security-responsibilities-in-aws-easing-your-administrative-strain)=
# Shared Security Responsibilities in AWS: Easing Your Administrative Strain
 

AWS provides a flexible cloud computing technology offering high availability and reliability, as well as the resources needed to operate a broad spectrum of applications. These resources help you safeguard the secrecy, authenticity, and accessibility of your infrastructure. But what are the boundaries of different security responsibilities between a cloud tenant and a cloud provider? This article answers this question in Amazon Web Services particular.

## Shared Responsibility Model

First we'll explore how cloud security differs from security in on-premises server farms. While you migrate information systems and workloads to the cloud, you and your Cloud Services Provider (CSP) share security obligations .

AWS is responsible for safeguarding the foundational infrastructure, and you are responsible for whatever you place on the cloud or attach to the cloud.

The shared responsibility concept may minimize your administrative strain in a number of ways, and it may even enhance your overall defense capabilities without any further intervention on your side.

The level of security setup effort required varies according to whatever services you use and how you assess the security of your material. User accounts and IDs, SSL/TLS encryption of data at rest, data in motion, and user activity logging are all security elements that you should setup.

### AWS Security Responsibilities

AWS is responsible for protecting the worldwide architecture which encompasses all of the Amazon Web Services. The infrastructure consists of the equipment, technology, networking, and buildings used to provide AWS Cloud services.

AWS's first responsibility is to protect this architecture. AWS publishes various reports from third-party inspectors that have confirmed their compliance with a broad range of key information security standards and legislation.

## Customer Security Responsibilities

The AWS Cloud allows you to deploy virtualized resources, storage, database systems, and workstations in minutes. You may also utilize cloud-based metrics and workload tools to analyze data as needed and preserve it in your own buildings or the cloud. How much configuration work you have to do as part of your security duties is determined by the AWS Cloud services you utilize.

**Updates/security patches**: You're in charge of managing the running operating system, as well as updates and security patches.

**Custom Applications**: You are responsible for any web applications or tools that you install on the instances.

**Security Groups**: You are also responsible for setting up the security groups. All those are essentially similar to security procedures that you are accustomed to completing regardless of where your servers are hosted. Amazon services such as Amazon Redshift give all of the resources required to complete a certain operation, but without the associated configuration burden.

**User Credentials/IAM user accounts**: As with any other service, you should safeguard your AWS login details and create unique user accounts with AWS Identity and Access Management (IAM). This way, all your users have their own passwords and you can apply a distribution of tasks.

You should also consider utilizing Multi-Factor Authentication (MFA) with each account, enforcing the usage of SSL/TLS to interface with your AWS services, and using AWS CloudTrail for API and user activity monitoring.

### Things you are not responsible for in AWS

You don't have to worry about deploying and managing instances, patching the runtime environment or database, or duplicating databases with managed services.

## Conclusion

This shared responsibility approach can help ease your administrative strain because AWS maintains, administers, and controls the elements such as the operating system and vms as well as physical safety of the buildings where the resources run.

:::{seealso}
Want to learn practical cloud skills? Enroll in MCSI’s - [MCSF Cloud Services Fundamentals ](https://www.mosse-institute.com/certifications/mcsf-cloud-services-fundamentals.html)
:::