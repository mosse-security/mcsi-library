:orphan:
(asset-management)=
# Asset Management
 
Asset management is frequently not on the list of critical ways for computer security experts to prepare their environment for an event. Consider the following scenario: you learn that an attacker has targeted a department inside your company. The department conducts research on technologies that are important to the delivery of a new service by your firm. A logical reaction could be to review the department's systems to ensure they are not hacked. Perhaps you'd like to incorporate some extra security procedures for that department. To effectively achieve either of those aims, you must first understand which systems belong to that department and where they are situated.

There are numerous key asset management issues in the context of an inquiry. Although having all of this information in one location is more convenient, we find that most companies keep different kinds of information about a system in multiple places. The trick is to know how to get to the information when you need it. You should assess your organization's capacity to offer the following system information:

• **Provisioned date -** Consider the following scenario: you discover evidence of suspicious behavior on a certain machine two months ago. You look up the host name in your asset management system and discover that it refers to a server that was replaced just a few weeks ago. Based on that knowledge, you know that the present system will not have proof of activity from two months ago. The greatest chance of acquiring evidence in this scenario is to locate the old server, which the asset management system can also assist with.

• **Business division -** Knowing which business unit a system belongs to inside your organization might assist investigators develop context and make better investigation conclusions. The fact that a hacked system is a database server, for example, may or may not be significant. You will respond differently if you additionally know that the database server is part of a business unit that processes data subject to federal requirements.

• **Geographical location -** If you need to retrieve a hard disc image or do any activity that necessitates physical access to the machine, you must know where it is. We're not implying that the location information is real-time, as in the case of laptops, but rather that the system's principal position is documented.

• **Ownership -** Many businesses outsource services. If your business does not truly own a system, how you respond may be affected. The hardware should be properly identified in the inventory.

• **Getting in Touch -**  A list of contacts linked with the system is required for coordinating access requests, getting physical access, and alerting impacted parties. There should be a primary and secondary contact identified. It's a good idea to involve the system administrator, the application administrator, and a business point of contact when it comes to servers. Include the principal user and their supervisor in end-user systems.

• **Role or services -** It is critical for an investigator to understand the function of a system. We recommend that you be as specific as possible—merely putting "server" is not very descriptive. What sort of server are you? Depending on your function, you will make different options about what to do, who to notify, and how urgent the situation is. A forensic image of a hard drive in a laptop, for example, is easier to perform than a 16TB SAN disc tied to a production database server. Understanding this sooner rather than later will enable you to respond correctly.

• **Network configuration -** Each interface's network setup should be tracked, including the host name, IP configuration, and MAC address. If the IP address is determined through DHCP, the IP address itself is not generally listed. However, if the IP address is allocated statically, having it in the asset management system is beneficial.

:::{seealso}
Want to learn practical Governance, Risk and Compliance skills? Enrol in MCSI’s [MGRC Certified GRC Expert](https://www.mosse-institute.com/certifications/mgrc-certified-grc-practitioner.html)
:::