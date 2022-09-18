:orphan:
(what-security-elements-are-crucial-for-creating-a-trusted-operating-system-os)=
# What Security Elements are Crucial for Creating a Trusted Operating System OS
 
An operating system that offers enough support for multilayer security and proof of accuracy to satisfy a certain set of government standards is referred to as a trusted operating system (TOS).

**A trusted OS is one that can provide:**

- Memory Protection: A section of memory that is secured against unauthorized access must be used to run each user's software. The security will undoubtedly bar access from outsiders, and it may also restrict a user's own access to restricted areas of the program space. Parts of a user's memory space may be subject to several levels of security, such as read, write, and execute.
- File Protection: this feature seeks to stop applications from replacing important OS files. Core system file protection reduces issues with programs and the OS, such as DLL hell.
- General object access control: Users require general objects, such constructs that allow synchronization and concurrency. However, access to these resources must be restricted to prevent one user from negatively affecting other users.
- User Authentication: This process must identify each user that wants access and confirm that the user is who they say they are. Password comparison is the most used authentication method.
- I/O control with a lookup table and an access control matrix: The OS must be able to have an I/O control with these features.
- Guaranteed fair service: Every user expects that CPU use and other services will be given such that no user will ever go without. To ensure fairness, hardware clocks work in conjunction with scheduling conventions. To be able to develop a trusted OS, we must build the components that give the OS its trustworthiness. Hardware facilities and data tables work together to offer control. If the components of policy, model, design, and trust can be brought together, an OS may be trusted. 
- Policy: Security requirements that are clearly specified, constant, unambiguous, and implementable.
- Model: Formal, representative representation of the policy. Functioning shouldn't be compromised.
- Design: Consists of functionality and implementation choices
- Trust: An operating system is trustworthy after an assessment of its features and guarantee. An OS process must be free of harmful segments and devoid of them from security flows in order to be trusted. The operating system (OS) must be examined, approved, and guarded by security regulations that are implemented and provide reassurance that our sensitive data will be protected.

**A Trusted OS's main characteristics include:**

1.	Identification and Authentication: The OS must be able to identify the person seeking access to an item and confirm that person's identity.
2.	Mandatory access control (MAC): stipulates that choices about the access control policy are made independently of the object's particular owner. Who has access to what information is decided by a central authority, and users cannot modify access privileges.
3.	Discretionary access control (DAC): gives the owner of the item or anybody else with permission to regulate the object's access some latitude in how much access is granted. The owner can choose who should be able to access an item and what those access privileges should be.
4.	Object Reuse Protection: Instead of fully destroying an item, it is frequently more economical to reuse it. By wiping, or zeroing, away each object before it is assigned to the user, trusted systems may ensure that security cannot be exploited owing to the reuse of objects.
5.	Complete Mediation: Complete mediation, or the control and verification of all accesses, is a need for a trusted OS.
6.	A trusted route: is a technique that gives users confidence that they are connecting with the people they plan to speak with, preventing hackers from intercepting or changing the data being sent.
7.	Accountability and Audit: Typically, accountability means keeping a record of all security-related events that have taken place, identifying each event along with the person who added, removed, or changed it. Every security-related event must be recorded, and the audit logs must be shielded from outsiders by a trusted OS.
8.	Audit Log Reduction: Because audit logs can be very large, the trustworthy OS should be able to move them or decrease their size as needed.
9.	Intrusion Detection: A trusted operating system must be capable of spotting some assaults.

> **Want to learn practical Secure Software Development skills? Enrol in MCSI’s [MASE - Certified Application Security Engineer](https://www.mosse-institute.com/certifications/mase-certified-application-security-engineer.html).** 