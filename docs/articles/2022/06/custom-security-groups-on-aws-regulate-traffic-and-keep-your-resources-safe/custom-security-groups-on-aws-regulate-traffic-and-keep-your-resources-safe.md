:orphan:
(custom-security-groups-on-aws-regulate-traffic-and-keep-your-resources-safe)=
# Custom Security Groups on Aws: Regulate Traffic and Keep Your Resources Safe
 

A security group functions as a cloud-based firewall, regulating the communications that can reach and exit the resources with which it is linked. Let’s say you don't want to use the built-in security groups. What should you do? AWS offers custom security groups for this purpose, which is the topic of today’s blog post.

## Custom security groups

You may establish your personal security groups and indicate them once you start your EC2. You may set up many security groups to represent the various tiers that your instances perform, such as a database server.
Upon creating your own security group, the next step is linking the security group to an Amazon Virtual Private Cloud (VPC).

A custom security group, once defined, doesn't allow inbound traffic. However, by default, a security group enables all outbound connections. Following the initial setup of the custom security group and selection of the security group attributes, you define the inbound rules, specifying the network activity that is permitted inbound from the Inbound Rules page.

**Inbound rules**: Specifies the origin of the communication, that is, where it is originating from, as well as the destination port or range of the port. A single IP address (either IPv4 or IPv6), a group of addresses, or a different security group might be the origin of the traffic.

**Outbound policies**: Specify the traffic's recipient, such as where it is heading as well as the port numbers or range. The communication might be routed to a single IP address, a set of addresses, or a different security group.

**A prefix list ID**: It is a unique identifier for an AWS network service, such as an Internet gateway.

**Another security group**: This option enables instances linked to one security group to contact instances belonging to another security group. A security group might be from the same VPC or from another VPC that has been via a VPC peering link.

**Naming conventions of security groups**

When you build a security group, you should give it a name and descriptive metadata. Security group names and descriptions are limited to the characters below and can be 255 characters long at maximum.

- A-Z, 0-9, spaces, and. -:/()#,@[]+=&;!$\*

For the VPC, a security group name must be distinct.

### Security best practices for custom security groups

When building security groups, the ideal approach is to limit which ports must be opened. If you put a load balancer in front of your Amazon EC2, the only ports that the security group defending the load balancer has to allow are the ports that your application needs.

Consider selecting unique ports for your production services in your architecture dependent on the tier arrangement of your production instance. In a three-tier configuration, for example, Web servers, application servers, and database instances could be assigned different unique ports. That's just an added layer of protection to think about. Moreover, plan ahead of time for a smooth security audit or effective debugging by defining and documenting your security group's naming strategy.

## Conclusion

In this blog, we have learned what a custom security group is, why it is important, and how we can benefit from it. We have also dealt with what are some security best methods that can be utilized while we create security groups. As the blog page shows, custom security groups help you protect your cloud-based resources by allowing you to regulate how traffic enters and exits your EC2 instances.

> **Want to learn practical cloud skills? Enroll in MCSI’s - [MCSF Cloud Services Fundamentals ](https://www.mosse-institute.com/certifications/mcsf-cloud-services-fundamentals.html)**