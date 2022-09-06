:orphan:
(improve-efficiency-by-generating-a-hypothesis-before-beginning-a-threat-hunt)=

# Improve Efficiency by Generating a Hypothesis Before Beginning a Threat Hunt

Threat hunting can be a daunting task. It can be difficult to know where to start, or what tools to use. One way to make the process easier is to generate a hypothesis before beginning your hunt. This will help you focus on specific areas, and make sure that you are looking for the right things.

One of the primary reasons a hypothesis needs to be created is due to the volume of data that exists. Without a hypothesis, it would be easy to get lost in the data and miss something important. Creating a hypothesis gives you a specific scope for your hunt, which can help you focus your attention and make sure that you are not missing anything. While tools are used to wade through voluminous amounts of data, they are not perfect and it requires a person to analyze and determine if the findings support the hypothesis.

There are a few things to keep in mind when creating a hypothesis:

- Make sure the hypothesis is specific and measurable. This will help you determine if your hunt was successful or not.

- The hypothesis should be based on data that you already have. The data can come from multiple sources, such as system, firewall, intrusion detection, web or proxy logs.

- Be sure to involve other members of your team in the creation of the hypothesis. This will help ensure that everyone is on the same page and looking for the same thing. Additionally, the varying experience with other team members can help with the formulation of the hypothesis and provide suggestions on carrying out the hunt.

## Proactive Threat Hunting

If using threat intelligence, ensure it is actionable and relevant to the organization.
One of the common terms used when defining threat hunting is "proactive." A proactive hunt involves formulating hypotheses based on what a threat actor may have done or will do to get access to sensitive information. A proactive-based hypothesis can be guided by analysis methods such as the [Crown Jewel Analysis](https://www.mitre.org/publications/systems-engineering-guide/enterprise-engineering/systems-engineering-for-mission-assurance/crown-jewels-analysis) which provides a method of identifying critical assets that support the organization's mission. Effectively the threat hunter is using an [Attacker's Mindset](https://scopesecurity.com/a-conversation-with-maxie-reynolds-the-art-of-attack/) and will begin hunting for artifacts to determine if a compromise occurred based on their hypothesis. A proactive hunt could be informed by threat intelligence. For example, if the attacker's initial access methods are known, that would be a factor used to generate a hypothesis. In order for a proactive hunt to be successful access to the appropriate data sources is critical. Incidentally, the results of a proactive hunt could lead to an organization realizing they don't have the appropriate data sources to support the hypothesis. That type of finding is beneficial because the organization can take the appropriate steps to ensure the requisite data sources are in place to help support future hunts. Additionally, they can ensure the requisite access to the threat hunter is in place, as well. In some organizations, third-party contractors may have devices on an organization's network they don't have access to include in the hunt. That type of situation can leave the organization at a disadvantage if they're trying to determine whether or not malware is present on those devices.

## Hunting from Past Incidents

The hypothesis for a threat hunt could also be informed by past security incidents. If an organization had a ransomware attack in the past, for example, the hunt team may want to focus on examining the systems and events that were a part of its initial access. It is not unusual for organizations to be targeted multiple times by the same type of cyberattack and attack vector. By understanding what's happened in the past, organizations can be better prepared to identify threats in the future.

## Reactive Hunts

A reactive hunt is one that is undertaken after an organization has been notified of a compromise, for example, through an intrusion detection system (IDS) alert, incident response team, or law enforcement notification. In this case, the investigation begins with understanding what systems were impacted and then pulling artifacts from systems to determine what occurred. However, if the impacted system is not known, knowing the type of data that was impacted could help start the hypothesis formulation process.

Hypotheses that are formulated after an attack require a significant amount of work because knowing the type of data that was compromised, for example, requires the organization to know where the data is located. The hunt will generally start backward from where the data was exfiltrated and work its way back to the original compromise.

## Example Proactive Hunt

An example of a proactive hunt could start with a hypothesis, “The database server is at risk of an attack because the organization doesn't routinely update plugins for the content management system and many in use have known vulnerabilities.” With this hypothesis, the hunter would then look at which systems have access to pull data from the database servers. The threat hunter could then start examining logs of the database server. However, hunts are not limited to only logs. Any server that has access to the web server can be analyzed with a variety of tools to examine the users, logins, failed logins, processes, services, and logs to determine if a compromise has occurred. Any web servers or other servers that interact with the database would be analyzed.

It is important to note that a hypothesis should not be too specific. For example, a hypothesis of “a user with the username ‘administrator’ logged in from an IP address of 12.34.56.78 at 11:55am." Too specific and the number of false positives goes up astronomically. Not specific enough and the number of potential events to investigate goes up, which can quickly become unmanageable.

## Summary

Generating a hypothesis before beginning a threat hunt can help with identifying malware by creating a scope for the hunt. This will help to focus the hunt and make it more efficient. It is important to find the balance between too specific and not specific enough when creating a hypothesis.

> **Want to learn practical Threat Hunting tactics and strategies? Enrol in [MTH - Certified Threat Hunter Certification](https://www.mosse-institute.com/certifications/mth-certified-threat-hunter.html).**
