:orphan:
(threat-hunting-in-distributed-organizations-the-challenges-are-not-insurmountable)=

# Threat Hunting in Distributed Organizations: The Challenges are not Insurmountable

Organizations are under constant threat from cyber attacks, and the traditional security perimeter is no longer adequate to protect them. To combat these threats, organizations are turning to threat hunting, which is the proactive search for indicators of compromise. However, threat hunting in a distributed organization can be challenging, due to the large number of devices and the vast amount of data that must be processed. However, these challenges are not insurmountable, and there are a number of steps that organizations can take to ensure effective threat hunting.

## Distributed Logging

To mitigate the challenge of having access to logs on all devices, investing in a centralized logging solution is recommended. Specifically, a well-tuned SIEM or Data Lake is necessary to make sense of the voluminous data that distributed organizations can generate. Though logs are not the sole source of a threat hunt, they can provide information to aid in the process by aggregating the data and producing reports that inform the hunt results. However, the process requires that organizations have insight into all the devices on each network segment at each site. Remote workers also extend the security boundary of organizational networks, so obtaining logs from those devices is essential. Policies are needed to require all devices to have logging capabilities and configured to log to a central log server or forwarding log server and then to the primary central logging system. Procedures that require scanning tools to ensure all devices are configured for remote logging and report if not are needed, as well. If available, VPN clients can sometimes check for the existence of operating system settings before authentication, and including a check for remote logging on remote devices could also be employed.

## Accessing all devices

Accessing all devices relevant to the hunt is another essential part of a threat hunting program in a distributed organization. That includes ensuring remote worker devices are accessible for interactive hunts is necessary, as well. Contractors may hamper access to some devices or other network assets where only they have the credentials, such as fire alarms, HVAC, or PBX systems. Senior management must decide if it is necessary to have access to those devices to perform hunts since those could present risks to the organization - namely because they don't have insight into how those systems are maintained or who is allowed to log in to it.

## Site specific hunts

Additionally, each site may also have threats specific to the tasks they perform for the organization. Accordingly, the type of hunt requires tailoring to the threats relevant to each site. A distributed site with developers and engineers in one location and data-entry personnel in another have unique risk profiles and different threat actors that target each job role.

Organizations must decide if they want to have a centralized threat hunting team or to decentralize the team and have members at each site. Both approaches have pros and cons, and senior management must decide based on the organization's needs. A centralized team has the advantage of being able to share resources, knowledge, and best practices more efficiently. They can also perform more complex hunts that require data from multiple sites. A decentralized team has the advantage of being able to focus on site-specific hunts and having better relationships with other teams at each location.

## Distributed threat hunting steps

To get started with threat hunting in a distributed enterprise, each security team should:

1. Identify the most common threats relevant to the tasks performed at their site. A generic hunt may result in performing hunts that miss threat actors actively in organizational systems. For example, a hunt for threat actors targeting engineers and developers may miss threat actors targeting access to employee data that resides at another site.

2. Create a threat hunting plan that includes where to look for threats, what tools to use, and how to respond to threats. The plan and process must consist of all relevant parties because there may be blindspots by one threat hunter that others catch. Strong communication is essential to perform a comprehensive threat hunt that is relevant to each site.

3. Train their team on threat hunting procedures and make sure they are familiar with the tools they will be using. Each team must be aware of how to use the tools and can supplement the tool's limitations. They also need to know if the tool is producing the relevant data to decide whether threats exist.

4. Conduct regular threat hunts and share information about any threats found with the other security teams in the enterprise. Threat hunts should be performed periodically, but the threat hunters must also read threat intelligence reports and stay up-to-date on the changing TTPs of threat actors. Information learned from the reports can help generate hypotheses to perform proactive hunts and determine if vulnerabilities currently exist in the organization that threat actors could exploit or may have already exploited.

Each security team in a distributed enterprise can effectively hunt and provide a more comprehensive analysis of potential threats by following these steps. However, in the absence of a threat hunting team at each site, the same steps above are necessary for organizations with only one threat hunter.

## Summary

Even though there are some challenges in distributed organizations with threat hunting, they are not insurmountable. Having one person or a team at each site can allow routine and comprehensive hunting. However, the capabilities of a well-tuned SIEM or Data Lake can aid large or small threat hunting teams by aggregating data to help make informed decisions on whether threat actors are or have already compromised an organization.

> **Want to learn practical Threat Hunting tactics and strategies? Enrol in [MTH - Certified Threat Hunter Certification](https://www.mosse-institute.com/certifications/mth-certified-threat-hunter.html).**
