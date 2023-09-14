:orphan:
(cloud-security-controls)=

# Cloud Security Controls

When it comes to cloud computing, security controls are essential – controls are simply measures and strategies put in place to safeguard cloud resources, data, and services. These controls act as the foundation of a robust cloud security posture, helping organizations mitigate threats, ensure compliance, and maintain the confidentiality, integrity, and availability of their cloud-based assets – without proper controls a transition to the cloud can end up as a security nightmare!

In this article, well take a look at some common controls – see the risks which they can address and explore some examples of services in both Amazon Web Services (AWS) and Microsoft Azure that can fulfill these security functions. Please keep in mind these are just examples, there is often more than one appropriate way to mitigate a risk in the cloud (just like on-prem!).

 

## High Availability Across Zones

Having high availability across zones is a cloud security control that enhances an organization's resilience by distributing resources and workloads across multiple geographic zones or data centers. This redundancy ensures that if one zone experiences downtime due to unforeseen events or failures, the application or service remains accessible from another zone. Cloud providers often implement these kinds of features by default – if you’re utilising the default VPC in AWS you’re already redundant across zones. In AWS, services like Amazon Elastic Load Balancing (ELB) can also distribute incoming traffic across multiple Availability Zones. Azure also offers Azure Availability Zones that provide data center redundancy. Let’s take a look at a scenario.

*Scenario without Control*: In the absence of high availability across zones, an organization's application hosted in a single data center or zone faces significant risks. If that zone experiences an outage due to a hardware failure or other unforeseen events, the application becomes unavailable – even if the application is resilient within that particular zone - resulting in downtime and potential revenue loss.

*Addressing the Problem*: Implementing high availability across zones, as offered by AWS and Azure, ensures that the application is distributed across multiple geographic zones or data centers. If one zone becomes unavailable, traffic is automatically redirected to another zone where the application continues to run smoothly, minimizing downtime and maintaining business continuity.

 

## Resource Policies

Resource policies are critical for managing access control to cloud resources. They define who can access and perform actions on specific resources within the cloud environment. AWS Identity and Access Management (IAM) policies, for instance, grant or restrict permissions for AWS resources and services. In Azure, Azure Role-Based Access Control (RBAC) allows organizations to define fine-grained access control policies. For example, AWS IAM policies can be created to grant read-only access to specific S3 buckets, limiting unauthorized users from modifying sensitive data.

*Scenario without Control*: Without resource policies defining access control, resources in a cloud environment may be left exposed to unauthorized users or overly permissive access. This could lead to data breaches, unauthorized changes, or even data loss if critical resources are tampered with.

*Addressing the Problem*: Implementing resource policies in AWS through IAM or Azure using RBAC allows organizations to define fine-grained access control. This ensures that only authorized users or entities can access and modify specific resources, reducing the risk of unauthorized access and maintaining data security. With proper resource policies in place, the impact of a compromise of a user account is also reduced – only the resources the account has permission to access can be exposed. Similarly, an attacker cannot spin up large amounts of resources in the cloud if the comprised account does not have explicit permission to do so. 

 

## Secrets Management

Secrets management involves securely storing, retrieving, and managing sensitive information such as API keys, passwords, and cryptographic keys. Both AWS and Azure provide solutions for secrets management. AWS Secrets Manager allows organizations to rotate, manage, and access secrets for various services, including databases and third-party applications. Azure Key Vault serves a similar purpose, enabling secure key management and secret storage. For instance, Secrets Manager in AWS can automatically rotate database credentials, reducing the risk of unauthorized access to databases.

*Scenario without Control*: In the absence of secrets management, sensitive information such as API keys and credentials might be stored in plaintext within code repositories or configuration files. This leaves critical data exposed to potential breaches if unauthorized access occurs – it’s also possible that an attacker may find a valid password or key exposed in something like a GitHub repository. 

*Addressing the Problem*: Implementing secrets management solutions like AWS Secrets Manager or Azure Key Vault allows organizations to securely store and manage sensitive information. These services ensure encryption and access control for secrets, mitigating the risk of unauthorized access and enhancing data security. Proper secure management also makes the setup of new virtual machines and services more secure – startup templates can now contain a reference to the secret (which has proper access control applied) rather than the actual secret information.  

 

## Integration and Auditing

Integration and auditing controls ensure that cloud environments are continually monitored and assessed for security threats and compliance. AWS CloudWatch and AWS CloudTrail enable organizations to collect and analyze logs and metrics, helping detect suspicious activities and compliance violations. In Azure, Azure Monitor provides comprehensive insights into cloud resources, while Azure Security Center offers threat detection and security recommendations. For example, AWS CloudTrail records all API calls made on an AWS account, allowing organizations to trace activity history and detect unauthorized changes to resources.

*Scenario without Control*: Without integration and auditing controls, organizations lack the visibility required to monitor and detect suspicious activities within their cloud environment. This blind spot can lead to security breaches going unnoticed until significant damage has occurred – this is also the case if logging and auditing is not enabled for all regions or zones – an attacker may be able to persist in an unused zone with little of any observability. 

*Addressing the Problem*: Integration and auditing controls, as provided by AWS CloudTrail and Azure Monitor, enable organizations to collect, analyze, and monitor logs and metrics. This proactive approach helps detect and respond to security incidents in real-time, ensuring that suspicious activities are identified and addressed promptly.

 

## Storage

The storage control in cloud security focuses on safeguarding data at rest within cloud environments. Both AWS and Azure offer features to protect data stored in their respective cloud platforms. AWS provides Amazon S3 bucket policies and access control lists (ACLs) to define who can access and manipulate data stored in Amazon S3 buckets. Azure Blob Storage allows organizations to configure access policies and shared access signatures for securing data. Amazon S3 now restricts access to S3 buckets by default, but this was once a major source of data leaks. With the new “default deny” setting, and Amazon S3 bucket policies, organizations can restrict public access to sensitive files stored in their buckets, ensuring data confidentiality.

*Scenario without Control*: In the absence of storage security controls, data at rest may remain unencrypted and unprotected, making it vulnerable to data breaches and unauthorized access. This lack of security could lead to data leaks, non-compliance with regulations, and reputational damage.

*Addressing the Problem*: Implementing storage security controls in AWS (e.g., Amazon S3 bucket policies) and Azure (e.g., Azure Blob Storage access policies) allows organizations to enforce data encryption and access policies. These controls ensure that data is protected while at rest, mitigating the risk of data breaches and maintaining regulatory compliance.

 

## Permissions

Permissions control is crucial for managing access privileges to cloud resources. AWS Identity and Access Management (IAM) and Azure Role-Based Access Control (RBAC) are vital components of these controls. AWS IAM allows organizations to define users, groups, and roles with specific permissions to access AWS services and resources. Azure RBAC follows a similar approach, granting role-based access to Azure resources. For instance, AWS IAM roles can be created to grant read-only access to EC2 instances, restricting users from making unauthorized changes to instances. Proper implementation of permissions through the use of groups also helps to make managing a large cloud environment with many users much easier. 

*Scenario without Control*: Without proper permission controls, users may have excessive or unnecessary access privileges within a cloud environment. This can result in unauthorized changes, data leaks, or even malicious activities if users exploit their elevated permissions. Keep in mind that users may never look to exploit excess permissions they have been granted (and may never even realise they have them) – an attacker with access to their account is another story! 

*Addressing the Problem*: Implementing permission controls using AWS IAM or Azure RBAC allows organizations to define and manage access privileges. This ensures that users have the necessary permissions to perform their roles while limiting access to critical resources, reducing the risk of unauthorized actions and maintaining a secure cloud environment.

 

## Encryption

Encryption is a fundamental control that ensures the confidentiality and integrity of data, both in transit and at rest. AWS and Azure offer robust encryption mechanisms to protect data. AWS Key Management Service (KMS) enables organizations to manage cryptographic keys and encrypt data stored in various AWS services, such as S3 and RDS. Azure Key Vault provides secure key management and encryption for Azure resources. For example, AWS KMS can be used to encrypt sensitive data at rest in an Amazon RDS database, adding an extra layer of protection against data breaches.

*Scenario without Control*: In the absence of encryption controls, sensitive data transmitted or stored in the cloud may remain unprotected, leaving it susceptible to eavesdropping or data theft. This can result in data exposure and compliance violations.

*Addressing the Problem*: Encryption controls provided by AWS KMS and Azure Key Vault enable organizations to encrypt data both in transit and at rest. By encrypting sensitive data, organizations protect it from unauthorized access and ensure compliance with data protection regulations, mitigating the risk of data breaches

 

## Replication

Replication is a cloud security control that ensures data redundancy and disaster recovery. AWS and Azure offer replication options for various services. AWS S3 provides options for cross-region replication, enabling automatic copying of data to a different geographic region for redundancy. Azure Blob Storage offers geo-redundant storage for data replication across Azure regions. For instance, AWS S3 cross-region replication helps organizations maintain data availability even in the event of a region-specific outage.

*Scenario without Control*: Without data replication controls, organizations may face the risk of data loss and extended downtime in the event of a regional outage or disaster. Critical data may not be redundantly stored, leading to potential business disruptions.

*Addressing the Problem*: Implementing data replication controls, such as AWS S3 cross-region replication and Azure geo-redundant storage, ensures that data is redundantly stored in multiple geographic regions. In the event of an outage, data remains accessible and downtime is minimized, safeguarding business continuity.

 

## High Availability

High availability is a critical control that aims to minimize downtime and ensure continuous access to applications and services. This feature is essential to make cloud services viable for any kind of business or service which requires constant (or near constant) uptime.

Both AWS and Azure offer solutions to achieve high availability. AWS provides Amazon Elastic Load Balancing (ELB) for distributing traffic across multiple instances in different Availability Zones (AZs), reducing the risk of service interruptions. Azure Traffic Manager offers global load balancing and failover capabilities. For instance, AWS ELB automatically distributes incoming traffic to healthy instances, ensuring uninterrupted access to applications even if some instances fail.

*Scenario without Control*: In a scenario where high availability controls are not in place, an organization's application or service hosted in a single data center or zone becomes vulnerable to disruptions caused by hardware failures or unexpected incidents. This lack of redundancy increases the likelihood of prolonged downtime and negatively impacts user experience – in some situations this may even pose a risk to life and safety. 

*Addressing the Problem*: High availability controls, as provided by AWS Elastic Load Balancing (ELB) and Azure Traffic Manager, distribute incoming traffic across multiple instances or zones. In the event of a failure or outage in one zone, traffic is automatically rerouted to healthy instances or zones, ensuring uninterrupted access to the application and minimizing downtime.

 

## Network

Proper network level controls are essential for building secure cloud infrastructures. AWS and Azure provide networking features to help organizations create secure, isolated environments. AWS Virtual Private Cloud (VPC) allows organizations to define virtual networks with fine-grained control over network traffic and security. Azure Virtual Network offers similar functionality, allowing organizations to create isolated networks. For example, AWS VPC enables organizations to set up network access control lists (ACLs) to control inbound and outbound traffic, providing an additional layer of security.

*Scenario without Control*: Without proper network controls, cloud resources may be interconnected without sufficient isolation or security measures. This can lead to unauthorized access, lateral movement within the network, and potential data breaches.

*Addressing the Problem*: Network controls like AWS Virtual Private Cloud (VPC) and Azure Virtual Network allow organizations to create secure, isolated network infrastructures. By defining network security groups, access control lists, and network policies, organizations can enforce strict network segmentation, reducing the risk of unauthorized access and enhancing overall network security.

 

## Public and Private Subnets

Public and private subnets are components of network segmentation, enhancing security by isolating resources with different access requirements. In AWS, public and private subnets are created within VPCs, allowing organizations to place resources like web servers in public subnets while placing databases in private subnets, limiting direct external access. Azure follows a similar approach with its Virtual Network, enabling organizations to create network security groups to control traffic between subnets. For example, AWS public subnets can host web servers that are publicly accessible, while private subnets can host sensitive databases that are isolated from the internet.

*Scenario without Control*: In a scenario where public and private subnets are not implemented, all resources within a network share the same level of connectivity, potentially exposing sensitive resources to the public internet. This lack of segmentation can lead to security vulnerabilities.

*Addressing the Problem*: Public and private subnets, established within AWS VPC and Azure Virtual Network, enable organizations to segregate resources based on their access requirements. With public subnets hosting resources that need public internet access and private subnets housing sensitive assets, this segmentation enhances security by isolating critical components from external threats.

 

## API Inspection and Integration: Ensuring Secure APIs

API inspection and integration controls focus on ensuring the security of APIs used in cloud environments. AWS offers Amazon API Gateway, which provides secure and managed APIs for connecting applications to cloud services. Azure API Management offers similar functionality for managing and securing APIs. For instance, Amazon API Gateway can be used to create RESTful APIs with authentication and authorization mechanisms, controlling access to backend services securely.

*Scenario without Control*: In the absence of API inspection and integration controls, organizations may expose APIs without proper security measures, leaving them susceptible to attacks such as injection or unauthorized access. This can result in data breaches and service disruptions.

*Addressing the Problem*: API inspection and integration controls offered by AWS API Gateway and Azure API Management allow organizations to secure and manage APIs effectively. By implementing authentication, authorization, and API rate limiting, organizations can ensure that APIs are protected against threats, unauthorized access, and excessive traffic, maintaining the integrity and availability of their services.



## Compute

Compute security controls are essential for securing cloud instances and virtual machines. AWS and Azure provide tools and features for securing computing resources. AWS offers Amazon EC2 instances, and Azure provides Azure Virtual Machines (VMs). Security Groups in AWS enable organizations to control inbound and outbound traffic to instances, defining which protocols and ports are accessible. Azure Network Security Groups (NSGs) offer similar functionality. For example, AWS Security Groups can be configured to allow only specific IP addresses to access EC2 instances, enhancing security.

*Scenario without Control*: In a scenario where compute security controls are lacking, cloud instances or virtual machines may not have adequate protection, making them vulnerable to security breaches, unauthorized access, or malicious activities – most of the same issues which affect physical systems also apply here except that since cloud systems are often internet accessible the attack surface may be larger by default.

*Addressing the Problem*: Compute security controls provided by AWS Security Groups and Azure Network Security Groups (NSGs) enable organizations to define firewall rules and access controls for instances or VMs. These controls restrict inbound and outbound traffic, ensuring that only authorized communication occurs. Implementing these controls enhances the security posture of instances or VMs, reducing the risk of unauthorized access and threats.

 

## Dynamic Resource Allocation

Dynamic resource allocation controls focus on optimizing resource utilization in cloud environments. AWS Auto Scaling and Azure Autoscale enable organizations to automatically adjust the number of instances or VMs based on traffic or demand. These controls ensure that applications can scale up or down efficiently to meet varying workloads. For instance, AWS Auto Scaling can automatically increase the number of EC2 instances during traffic spikes and decrease them during low-demand periods, optimizing resource usage and cost-effectiveness.

*Scenario without Control*: Without dynamic resource allocation controls, organizations may struggle to efficiently utilize their cloud resources, leading to overspending on unnecessary resources or experiencing performance issues during traffic spikes.

*Addressing the Problem*: Dynamic resource allocation controls like AWS Auto Scaling and Azure Autoscale allow organizations to automatically adjust the number of instances or VMs based on demand. This ensures optimal resource utilization and cost-effectiveness. During traffic spikes, additional resources are provisioned automatically, maintaining application performance and reducing operational costs.

 

## Instance Awareness

Instance awareness controls involve monitoring and reporting on the status and health of cloud instances. AWS CloudWatch and Azure Monitor provide comprehensive monitoring solutions. AWS CloudWatch collects and analyzes data on resource utilization, application performance, and operational health. Azure Monitor offers insights into the performance and availability of Azure resources. For example, AWS CloudWatch can be configured to send notifications when CPU utilization on EC2 instances exceeds a predefined threshold, allowing organizations to proactively address performance issues.

*Scenario without Control*: In a scenario where instance awareness controls are absent, organizations may lack visibility into the performance and health of their cloud instances or VMs. This can lead to performance bottlenecks, undetected issues, and inefficient resource management.

*Addressing the Problem*: Instance awareness controls provided by AWS CloudWatch and Azure Monitor enable organizations to collect and analyze metrics and logs from instances or VMs. These controls offer real-time insights into resource utilization, performance, and operational health. By proactively monitoring instances and receiving alerts for anomalies, organizations can maintain optimal performance, identify issues, and address them promptly.

 

## Virtual Private Cloud (VPC) Endpoint

VPC endpoints in AWS and Private Endpoints in Azure enable secure and private access to services such as AWS S3 or Azure Storage from within a virtual network. They bypass the public internet, reducing exposure to security threats. AWS PrivateLink allows private access to services like Amazon S3 or DynamoDB. Azure Private Link offers similar capabilities for Azure services. For example, AWS PrivateLink can be used to access Amazon S3 buckets privately, ensuring data remains within a secure network perimeter.

*Scenario without Control*: Without VPC endpoint controls, data access to cloud services like AWS S3 or Azure Storage may rely on public internet connections, potentially exposing data to security threats or eavesdropping.

*Addressing the Problem*: VPC endpoint controls such as AWS PrivateLink and Azure Private Link establish secure and private connections to cloud services. By using these controls, organizations ensure that data access remains within the private network and bypasses the public internet. This reduces the risk of data exposure and enhances security when accessing cloud services.

 

## Container Security

Container security controls are crucial for protecting containerized applications. AWS and Azure offer container management services with built-in security features. AWS Elastic Container Service (ECS) and Azure Kubernetes Service (AKS) provide container orchestration and management. AWS Fargate and Azure Container Instances offer serverless container management. For example, AWS ECS and Azure AKS provide options for securing containers with role-based access control (RBAC), network policies, and container scanning, ensuring that applications running in containers remain protected.

*Scenario without Control*: In the absence of container security controls, containerized applications may lack proper isolation and security measures, making them susceptible to container breakouts, unauthorized access, and malicious activities.

*Addressing the Problem*: Container security controls provided by AWS Elastic Container Service (ECS), Azure Kubernetes Service (AKS), and serverless container management services enable organizations to enforce security measures such as role-based access control (RBAC), network policies, and container scanning. These controls enhance the security posture of containerized applications, ensuring that they remain protected against threats and unauthorized access.

# Final words

In this article we looked at a range of security controls which can be utilised in the cloud, as well as some scenarios which they may help to address. These scenarios underscored the importance of compute security, dynamic resource allocation, instance awareness, VPC endpoint security, and container security controls in optimizing resource management, enhancing security, and maintaining the reliability of cloud instances, VMs, and containerized applications. Implementing some or all of these controls is essential for building and maintaining secure and efficient cloud environments.

 
