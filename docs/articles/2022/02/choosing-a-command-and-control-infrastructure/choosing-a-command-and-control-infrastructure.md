:orphan:
(choosing-a-command-and-control-infrastructure)=
# Choosing a Command and Control Infrastructure

When it comes to Red Teaming, one of the most crucial components of the operation is the command and control (C2) infrastructure. The C2 infrastructure is what allows Red Teams to orchestrate their attacks, thus it must be dependable and scalable to suit the team's needs. There are several possibilities for C2 infrastructure, each with its own set of benefits and drawbacks. In this blog article, we'll look at some of the most common C2 infrastructure alternatives and highlight the variables to consider while making your decision.

## Option 1: Self-Hosted Virtual Machines

This is a bit of a throwback, and it's better suited to internal penetration examinations. Nonetheless, it's worth mentioning!

This option allows you to operate the C2 infrastructure in a virtual machine on a testing laptop (for example Metasploit with Kali Linux). You use a virtual machine to connect to the target's ICT environment and conduct assaults from there.

This option will work if the target organization is unprepared. You can expect to be caught rather fast if they have network security monitoring tools.

## Option 2: Cloud Virtual Machines

In this example, the Red Team uses cloud servers to host its tools. Cobalt Strike or any other RT tool can be deployed in AWS, Azure, or GCP, which is a very typical setup.

When the blue team finds the red team, cloud infrastructure makes it simple to change IP addresses, switch cloud providers, and redeploy. In some cases, redeployment can be entirely automated.

It's worth noting that while implementing known attack tools in the cloud, Red Teams should exercise caution. Security researchers and cyber defence firms keep a close eye on major cloud providers. Your IP addresses will almost certainly be added to a watchlist as soon as you are found!

## Option 3: Software-as-a-Service

On their platform, cloud providers allow you to push and execute code. You can, for example, deploy web services, databases, automated jobs, and other services for free by simply writing the code and ignoring the underlying infrastructure.

Nobody has released a public Red Team C2 framework that only operates on SaaS platforms as of the time of writing this article. Nonetheless, we want you to know that it is very doable, and we have an in-house product that does just that.

This option provides many advantages:

1. The cost is easier to write and maintain

2. You don't need as many developers, and you don't need network or database engineers

3. You can architecture the code to run across multiple cloud providers

4. If you're competent enough, you can devise ways to prevent security researchers from identifying your cloud functions

5. It's incredibly simple to redeploy and migrate the infrastructure elsewhere (including the database)

6. Because everything is hosted in the cloud, standard network security measures like IP blacklisting and domain blacklisting can't be used to restrict your infrastructure.

Furthermore, many other modern DevOps firms, in addition to the main three cloud providers, allow you to run code on their infrastructure. This opens up a world of possibilities that the Blue Team is unlikely to have explored before, and security products have never seen before!

Overall, this is an exciting new way to write C2 frameworks!

> **Looking to expand your knowledge of red teaming? Check out our online course, [MRT - Certified Red Teamer](https://www.mosse-institute.com/certifications/mrt-certified-red-teamer.html). In this course, you'll learn about the different aspects of red teaming and how to put them into practice.**