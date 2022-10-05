:orphan:
(pros-and-cons-of-agent-based-and-agentless-log-collection)=
# Pros and Cons of Agent-based and Agentless Log Collection
 
In this blog post, we are going to explain the pros and cons of agent-based and agentless methods of log collection. Let’s start by defining what is log collection.

## What is log collection?

Log collection is a recommended practice that involves establishing a centralized system to gather all logs. In an enterprise, log entries come from a variety of locations, and by collecting logs, we may consolidate them all into a single location.

Logs are often gathered in one of two ways:

- Agent-based

- Agentless

Let’s have a look at each method in detail.

## What is agent-based log collection?

A generic agent is generally used to obtain log data from a source that does not support a format-specific agent or an agentless technique. Administrators can also design custom agents in some applications to accommodate incompatible log sources. Each method has certain weaknesses as well as benefits. Let's take a closer look at each of them.

### Pros and cons of agent-based log collection

If a host has a variety of logs of relevance, numerous agents may be required to be deployed. It is a tested and running program with many extra features such as automated parsing, encryption, log integrity, and so on. However, when the extra features are active, resource usage grows, leading to an increase in expense.

## What is agentless log collection?

The SIEM server collects data from individual hosts using this sort of gathering with no need for any extra software to be deployed on those hosts. Some servers collect logs from endpoints, which is commonly accomplished by having the server log in to each client and acquire its logs on a routine basis. In other circumstances, the hosts push their logs to the server, which normally entails each computer identifying itself to the server and frequently uploading its logs (you can visit this blog post for further detail on a practical illustration of a subscription config `.XML` file). The server then does incident filtration and consolidation, as well as log normalization and analysis on the gathered logs, irrespective of whether they are pushed or pulled.

### Pros and cons of agentless collection

The agentless approach has the primary advantage of eliminating the need to deploy, operate, and manage agents on each logging host. The most significant drawback is the absence of filter and consolidation at the respective endpoint. This may result in substantially bigger data volumes being sent across systems and taking longer to sort and examine the collected logs.

The Security information and event management (SIEM) server can demand authentication per logging endpoint in agentless solutions. In other cases, only one of the two ways is practical; for example, gathering logs from a specific server may be impossible without installing an agent on it. Because there are no setup or maintenance costs, the agentless log transmitting approach is sometimes preferable. Logs are often transmitted via talking to the destination through SSH or WMI.

Because this approach requires the log server's login and password, there is a danger of the password being stolen.

Agentless log transmission is a simpler way of preparation and management than agent-based log sending. It does, however, have significant limitations, because passwords are enveloped in the system.

## Conclusion

Upon completion of this blog page, now you are familiar with the advantages and disadvantages of agent-based and agentless log collection methods.

:::{seealso}
Want to learn practical Digital Forensics and Incident Response skills? Enrol in [MCSI's MDFIR - Certified DFIR Specialist Certification Programme](https://www.mosse-institute.com/certifications/mdfir-certified-dfir-specialist.html)
:::