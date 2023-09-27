:orphan:
(authentication-authorisation-cloud-vs-on-premises)=

# Authentication and Authorisation - Cloud Vs. On-Premises

Authentication and authorization are fundamental concepts in cybersecurity. They work together to ensure that only authorized users and systems can access resources. In both cloud and on-premises environments, these processes are essential for safeguarding sensitive data and preventing unauthorized access – however, there are some differences between the physical environment and the cloud – let’s take a look.

 

## Authentication in On-Premises Environments

In on-premises environments, authentication typically involves a local infrastructure controlled by the organization. The Authentication process aims to ensure that the user *is* who they claim to be. Here's how it works:

- **User Authentication:** Users are required to prove their identity before accessing resources. Common methods include usernames and passwords, smart cards, or biometrics like fingerprint or facial recognition.

- **Authentication Servers:** On-premises networks often use authentication servers like Active Directory (AD) to manage user identities. These servers verify user credentials before granting access.

- **Single Sign-On (SSO):** SSO is a convenient method that allows users to log in once and access multiple resources without re-entering their credentials repeatedly. It's commonly used in on-premises setups.

  

## Authorization in On-Premises Environments

Authorization, on the other hand determines what actions authenticated users can (and cannot) perform within the network. In on-premises environments they key components are:

- **Access Control Lists (ACLs):** ACLs define who can access specific resources, like files, folders, or network segments. These lists are typically managed by administrators.

- **Role-Based Access Control (RBAC):** RBAC assigns users roles with specific permissions based on their job functions. For example, an HR manager might have access to employee records but not financial data.

- **Permissions:** Each resource has associated permissions that specify what actions users can perform, such as read, write, or delete.

  

## Physical Authorisation and Authentication

Of course, in an on-premises environment, it’s also important to control physical access to areas, spaces or whole buildings – therefore, items such as identify badges, door locks or biometric scanners are also an important consideration. There’s much more information about all of these topics on the Library! 



## Authentication and Authorization in Cloud Environments

Cloud environments, like those provided by AWS, Azure, or Google Cloud, have unique authentication and authorization requirements – while physical authentication (such as showing a badge) no longer applies, the way in which users access the cloud (remotely) means that different approaches take precedence. These can include: 

- **Federated Authentication:** Cloud services often support federated authentication, allowing users to log in using their existing on-premises credentials. This integration simplifies user management.

- **Multi-Factor Authentication (MFA):** MFA is crucial in the cloud to add an extra layer of security. Users must provide something they know (password) and something they have (e.g., a smartphone app) to access resources.

- **Identity as a Service (IDaaS):** Cloud environments offer IDaaS solutions that manage authentication centrally. Examples include Azure AD and AWS Identity and Access Management (IAM).

- **API Keys and Tokens:** In cloud environments, applications often communicate using API keys and tokens. These credentials require secure management to prevent unauthorized access.

  

## Authorization in Cloud Environments

While key aspects of authorisation, such as ACL’s, RBAC and permission assignment all apply in cloud-based environments, authorization also has some unique characteristics in this context. The main ones to keep in mind are:

- **Resource-Based Policies:** Cloud providers offer resource-based policies that define who can access specific cloud resources. For instance, AWS uses Identity and Access Management (IAM) policies.
- **Resource Tagging:** Cloud resources can be tagged with labels, allowing for more granular access control based on these tags. For example, you can restrict access to all resources tagged as "production."
- **Least Privilege Principle:** Applying the least privilege principle is always important, but is even more crucial in cloud environments. Users and services should have only the permissions they need, reducing the attack surface.

 

## Key Differences

We can also think about the differences between the cloud and on premises environments in terms of key themes – when considering the ways in which a cloud environment might differ, some important aspects to keep in mind can include: 

- **Ownership:** In on-premises, you have complete control over authentication and authorization infrastructure. In the cloud, you rely on the cloud provider's services, which can be more complex to manage. You may also have to utilise the services which exist in the cloud, rather than simply extending your on premises program. 
- **Scalability:** Cloud environments are highly scalable, making it easier to adapt authentication and authorization to growing needs. On-premises solutions may require significant hardware and software investments to scale, whereas cloud deployments can scale instantly. At the same time, it’s much easier for a rogue employee or attacker to spin up vast amounts of resources in the cloud, hence resource limitations are critical. 
- **Responsibility:** In on-premises, you're responsible for managing all aspects of security. In the cloud, the provider shares some of this responsibility through the Shared Responsibility Model. Physical security does remain a critical consideration in the cloud – but it’s no longer *your* responsibility. 
- **Integration:** Cloud environments can often integrate with existing on-premises security systems – where possible, this can provide superior management and oversight, however these integrations also tend to make identity management more complex. 

# Final Words

Understanding the differences between authentication and authorization in cloud and on-premises environments is crucial for securing your organization's assets. As technology continues to evolve, it's essential to stay informed about the latest best practices and tools in both realms to protect your data effectively - While many of the key principles are the same, cloud and on-premises approaches can vary - managing the differences will probably become even more important in the future as cloud expands further! 

 
