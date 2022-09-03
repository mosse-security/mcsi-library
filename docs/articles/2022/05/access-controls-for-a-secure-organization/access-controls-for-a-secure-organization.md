:orphan:
(access-controls-for-a-secure-organization)=
# Access Controls: For a Secure Organization
 

Every organization has resources that are used by various entities on a daily basis. The retrieval of information from these resources is referred to as access. These resources, however, should be accessed in a way that does not jeopardize their security. Access controls enable organizations to ensure secure access to resources.

## What are Access Controls?

Access controls are security countermeasures that govern how individuals can access resources in accordance with security policies. Access controls can be administrative, physical, or technical in nature. These controls enforce how individuals are identified, authenticated, and authorized in order to gain controlled access to resources.

## Importance of Access Controls to an Organization:
It is crucial for an organization to protect its assets, especially those that are critical. Access controls serve as the first line of defense against unauthorized access to the system and network resources. These controls give an organization the ability to protect the confidentiality, integrity, and availability of its resources.

The absence of such measures, or improper configuration of these controls, can result in unfavorable outcomes such as data breaches, theft of sensitive/critical company information, malware injection, and other issues.

## The Three A's of Access Control:
When a user seeks access to a resource, three critical processes should take place. These three steps are authentication, authorization, and accountability.

<u>Authentication:</u>
A user must submit a proof of his identification before gaining access to a resource. The user's identity can take many forms, including username, user ID, account number, and so on. Authentication is the process of verifying a user's identity. There are three general forms of Authentication:

* Something you know e.g. a password, PIN, or a lock combination
* Something you have e.g. a badge, a swipe card, or a smart card
* Something you are e.g. a fingerprint, a retina scan, or facial recognition

<u>Authorization:</u>
The system authorizes the user to access the resource after successful authentication. The process of granting or revoking access to a resource, or the permission to perform some action on it, is known as authorization.

<u>Accountability:</u>
Accountability refers to tracking an authenticated user's activity in a system so that he or she can be held responsible for their actions. The only way to guarantee accountability is for the user to be properly authenticated and his activities to be recorded using various security controls.

### Important Principles regarding user access:
There are three key principles to consider when defining user access permissions on a system or resource. These principles are as follows:

<u>Least Privilege Principle:</u> According to the principle of least privilege, users should have no more access than is strictly required to accomplish their job responsibilities.

<u>Need-to-Know Principle:</u> The need-to-know principle states that the users should only be given access to the resources that they absolutely require to carry out their duties.

<u>Separation of Duties:</u> The separation of duties principle refers to the requirement of multiple people to execute a critical task. The goal of the separation of duties is to ensure that no single user has sufficient access or power to jeopardize a resource's security. As a result, two or more parties must operate in concert to act against the security policy.

## Access Control Administration Approaches:
There are two main administration approaches utilized in the development of access control systems:

### Centralized Access Control:
Only one entity is responsible for enforcing access control mechanisms in Centralized Access Control. This type of access control approach allows for consistent, reliable, and strict access. Because only one entity is in charge of access provision, all user permissions are reviewed and processed by that entity before being granted to the user.

### Decentralized Access Control:
Decentralized access control is also known as distributed access control. It enables those closest to the resources to make access decisions. This method of access control is better suited to organizations with multiple business units and no strict requirements for centralized access control.

Decentralized access control gives each business unit more power, and user access provisioning happens faster than with centralized access control. However, there are security risks involved in this approach. It is because different departments have different levels of access control and security policies.

## Access Control Models:
It is up to an organization to implement different kinds of access controls that meet both its business and security needs. There are various access control models that can help businesses of all sizes implement these controls. Access Control models are frameworks that govern how subjects can access objects.

The subject is the entity such as an individual or a program that requests access to an object.

The object is the passive entity that contains the information required by the subject.

Each of these models will now be discussed in detail.

### DAC (Discretionary Access Control):

The owner of the resources specifies which subjects have access to which objects in Discretionary Access Control. The person or department that creates a resource is its owner. The owner has the authority to allow or restrict access to the resource. Access to resources in a business unit, for example, will be controlled by the manager of that business unit.

Operating systems use ACLs (access control lists) to grant user access via the DAC model. ACLs are used to specify the access permissions of different subjects on a particular object. The majority of today's standard operating systems, such as Windows, Linux, and Unix, are built on DAC. For example when a user creates a document, he can specify user permissions such as Read/Write/Execute/Full Control, among others.

DAC models are extremely flexible because they allow users to control who has access to their resources. This makes providing access to new users a relatively faster task. However, this adaptability comes at the expense of decreased security. It becomes incredibly difficult for security administrators to review access permissions in each department because they must navigate multiple ACLs to understand how user access is provisioned. A user can become overprivileged as a result of a department's permissive security policies. Any attacker who gains access to such a user account can use it to cause further security compromises in the organization.

### MAC (Mandatory Access Control):

The Mandatory Access Control Model is much stricter and more organized than the Discretionary Access Control Model. It does not allow users to grant access to other users. Instead, it makes access control decisions based on security labels and security clearance. The security clearance of the subjects and data classification labels have different levels such as Top Secret, Secret, Confidential, and so on. 

A user or subject may have access to an object only if his security clearance is equal to or higher than the corresponding data security label. For example, if a user with secret security clearance requests access to an object with a Top secret security label, the request will be denied because the clearance is less than the security label. A MAC model enhances security by emphasizing data confidentiality. Subjects in the MAC model cannot share resources with other subjects who have a lower security clearance.

MAC models are typically used in environments with strict security requirements, such as military and government institutions. Operating systems are designed specifically for organizations that use the Mandatory access control model. Operating systems based on the DAC model are general-purpose computers that do not acknowledge security labels or clearances. MAC systems, on the other hand, are designed with strict security requirements that align with the policies of the organization.

### RBAC (Role based access control model):

The role-based access control model makes access decisions based on user roles. The user roles are based on the user's actions or tasks that are part of his or her job responsibilities. A user may be granted access to a resource only if his or her job role requires access to the resource.

The RBAC model is a centralized and non-discretionary access control model in which a system administrator configures systems to provide access control in accordance with the security policy of the organization. Users in this type of access control model are not permitted to make access decisions and are not permitted to share a resource with another user in a different user role.

The RBAC model makes use of ACLs to associate different user roles with their corresponding privileges. RBAC is ideal for large organizations with high employee turnover. Because ACLs are based on user roles rather than specific subjects, system administrators have a much easier time provisioning user access.

### ABAC (Attribute based Access Control):

Attribute-based access control models are policy-based models. The ABAC model evaluates the attributes of all relevant entities and then makes access decisions based on the organization's security policies. The labels related to the subject, object, action, and environment are called attributes.

<u>Subject Attributes:</u>Departments, roles, group memberships, security clearance, user ID, and other user identification requirements are examples of subject attributes.

<u>Object Attributes:</u>The resource's name and creation date, the data classification label, the owner's name, and other attributes are all included in object attributes.

<u>Action Attributes:</u>Read, Write, Delete, Update, and other actions are examples of action attributes.

<u>Environment Attributes:</u>Contextual elements such as the time of the action, the location of the subject, and others are included in Environment Attributes.

This model is used to enable granular access control by specifying a collection of attributes that must be present before a user is permitted access to an object. Consider an example to understand this concept. If a subject requests access to an object during office hours and has a security clearance equal to or greater than the object's security label, then the ABAC model decides whether the user has a need to know about that object, and if so, gives access to the subject.

Attribute-based access controls are flexible because they determine user access decisions without stating which subjects can access which object objects individually. This permits a large set of users to access a large set of resources, making the system administrator's job considerably easier. Regardless of the subject/object relationship, the administrator or owner can change attribute values throughout the subject or object's lifecycle.

### RAdAC (Risk Adaptive Access Control):

The Risk Adaptive Access Control model is a dynamic access control model based on the ABAC model. This model bases access decisions on the level of risk that exists in the subject and object interaction.

The subject's identity and security clearance, the subject's need to know, the authentication technique employed, the strength of the communication session, and the subject's physical location are all utilized to assess risk. For example, if a user attempts to access his email account from an unfamiliar device, additional controls will be required to validate the user's identity before access is granted.

## Logical Access Controls:
Logical access controls are software/technical controls that verify a user's identity, assign access privileges, and audit user activity. These safeguards ensure that unauthorized parties do not gain access to resources and that their confidentiality, integrity, and availability are not jeopardized. Some examples of logical access controls are as follows:

### Access Control Matrix:

An access control matrix is a table containing multiple subjects and objects. It specifies the actions that a subject can perform on an object by mapping a subject to an object. These matrices are usually employed in the implementation of the DAC model.

### Access Control List:

An access control list is mostly used in devices such as operating systems and routers. Access control lists are associated with objects and are used to specify subject permissions on one particular object.

### Constrained User Interface:

Constrained User Interfaces limit users' abilities by preventing them from accessing specific functions of a system/application or by denying them access to certain resources.

Database views are an example of a Constrained User Interface application. Database views can restrict user access to the information contained in the database. For example, managers can view the employee information in their own department but they cannot access the information of the employees from other departments.

### Passwords:

Passwords are a combination of letters and numbers that are used to verify an individual's identity. Passwords are the most widely used authentication method, yet they are also the most vulnerable. Password policies should be strictly enforced in order for passwords to provide adequate security. The following are some of the best password practices:

- User passwords should be at least 8 characters long and contain a combination of upper and lowercase letters, digits, and special characters.

- User passwords should not be easy to guess and should not be linked to personal information such as names, date/place of birth, and so on.

- Password reuse should not be allowed.

- Users should be forced to change their passwords periodically.

- Passwords should be salted with a strong hashing algorithm before being stored in the database.

## Physical Access Controls:

Physical access controls are physical barriers that prevent people from entering/accessing areas with sensitive information. Some of the examples of physical access controls are:

### Electronic Access Control:

Electronic access control systems are used to restrict unwarranted user entry into a facility using electronically operated locks. Electronic access control systems can restrict user access through the use of key cards, biometric recognition, keypads, or mobile devices. This mechanism is used to verify an individual's identity and authorizes user access to specific areas of the facility.

### Device Locks:

Device locks are used to safeguard devices (desktops, laptops, printers, and so on) from unauthorized access to any of their components, theft, or malware installation. Slot locks, port controls, and cable traps are some examples of device locks.

### Mantraps:

A mantrap is a small room with two doors. A person enters the room through the first door, which is then locked. Security guards, keypads, smart cards, swipe cards, or biometric controls are used to identify and authenticate the individual. The second door opens after successful authentication, allowing the individual into the facility. Mantraps are usually found in high-security sites like bank vaults or military bases.

### Turnstiles:

Turnstiles are gates that only allow one person to pass through at a time. Turnstiles can be used to restrict access by limiting the number of persons who can enter or exit a facility. These doors will only open if the user presents a valid credential. Some turnstiles can detect forced or unauthorized entry attempts by sounding an alarm and alerting the appropriate security authorities.

### Bollards:

Bollards are small concrete pillars that are erected outside the buildings. One of the main functions of the bollards is to protect the building from damage caused by vehicles, either accidentally or intentionally. Bollards are a type of natural access control. They are used to direct people to the building's entry and exit points along the pavements.

> **Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)!**