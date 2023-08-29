:orphan:
(what-is-threat-hunting)=

# Threat Hunting

In an interconnected digital world, the landscape of cyber threats continues to evolve at an alarming pace. As a result, organizations are switching from a reactive strategy to a proactive approach that involves actively looking for possible threats before they have a chance to cause harm. This strategic practice, known as threat hunting, represents a significant improvement in the field of cybersecurity. By blending cutting-edge technology, data analysis, and human expertise, threat hunting empowers defenders to anticipate, identify, and neutralize threats that may otherwise remain concealed within complex digital environments. In this article, we will explore the basics of threat hunting, its methodologies, and the role it plays in fortifying the defenses of modern businesses.

## What is Threat Hunting?

Threat hunting is a proactive cybersecurity approach aimed at uncovering hidden and potentially malicious activities within an organization's network or systems. Unlike traditional security measures that primarily focus on defending against known threats, threat hunting involves actively seeking out evidence of unauthorized or anomalous behavior, known as Tactics, Techniques, and Procedures (TTPs). This behavior might indicate the presence of advanced and evasive attackers. Attackers employ a variety of tactics to remain concealed within a network, such as utilizing sophisticated obfuscation techniques, leveraging legitimate credentials, or exploiting vulnerabilities in software. They often mimic legitimate user actions to blend in, making their activities difficult to distinguish from normal network behavior. By doing so, attackers can establish a persistent presence, exfiltrate sensitive data, or conduct other malicious activities undetected. The goal of threat hunting is to specifically detect these types of threats.

## How Does Threat Hunting Work?

Threat Hunting works by leveraging intelligence sources and indicators of attack/indicators of compromise (IoA/IoC) to unveil hidden cyber threats. Intelligence sources, comprising threat intelligence feeds, historical attack data, and industry-specific insights, furnish threat hunters with a comprehensive understanding of emerging attack trends and the tactics employed by adversaries. 

Indicators of attack encompass patterns and behaviors that could indicate an ongoing or imminent attack, allowing threat hunters to uncover malicious activities before they escalate. Examples of IoA include the creation of new user accounts, unauthorized access to sensitive files, and multiple failed login attempts.  On the other hand, indicators of compromise encompass artifacts left behind by past attacks, guiding the search for remnants of unauthorized activities. Examples of IoC include unusual modification in registry keys, fake executables within the system, and the presence of known malware variants in the memory. By collecting, analyzing, and correlating these IoAs and IoCs with ongoing network traffic and system behaviors, threat hunters can detect anomalous patterns and potential breaches that might otherwise remain hidden.

## Threat Hunting Methodologies

This section presents a brief overview of different threat-hunting methodologies.

### Intelligence Fusion

Threat intelligence involves the collection, analysis, and dissemination of information about potential and ongoing cyber threats. It provides organizations with valuable insights into the TTPs employed by adversaries, as well as the vulnerabilities they target. Threat intelligence can be sourced from both internal and external channels. 

Internal sources encompass an organization's own data or logs that enable the identification of abnormal activities within its network. External sources, on the other hand, involve data acquired from third-party vendors, open-source intelligence, security research, and government agencies. Threat intelligence fusion is the process of integrating and correlating information from these diverse sources to create a comprehensive and contextual understanding of the threat landscape. This fusion enhances the accuracy and relevance of threat detection, enabling security teams to proactively address new threats and strengthen their defenses against both well-known and undiscovered attack vectors.

### Threat Feeds

Threat feeds are curated streams of real-time and relevant threat intelligence information that provide organizations with timely insights into emerging cyber threats and malicious activities. These feeds consist of categorized data points such as IP addresses, domain names, hashes, URLs, and other indicators of compromise (IoCs) that can help security teams stay informed about potential risks. To gather threat feeds, organizations can draw from both internal and external sources. 

To collect threat feeds from internal sources, organizations can tap into their own network logs, firewall data, intrusion detection systems, and security information and event management (SIEM) solutions to identify unusual or suspicious patterns. This yields insights into threats that may have breached their defenses. Externally, organizations can subscribe to commercial threat intelligence providers, research reports, cybersecurity forums, and government advisories that offer broader perspectives on global threat trends and emerging attack methods. 

### Advisories and Bulletins

Advisories and bulletins are essential resources in the realm of threat hunting, providing timely and pertinent information to cybersecurity professionals. Advisories provide information on new vulnerabilities, attack strategies, and potential threats and are frequently issued by cybersecurity organizations, governmental bodies, or vendors. These advisories often include detailed descriptions of the threat, its impact, recommended mitigation measures, and sometimes even indicators of compromise (IoCs) to aid in threat detection.

Bulletins, on the other hand, are concise notifications that highlight specific threats, vulnerabilities, or security issues. They are designed to provide quick and actionable information to security teams, helping them make informed decisions about prioritizing their threat-hunting efforts.

### Maneuver

Maneuver in the context of threat hunting refers to the sophisticated movement within a network that advanced adversaries often use as they progress toward achieving their malicious goals. There are a couple of mechanisms that threat hunters can employ to hinder an attacker's maneuvering. 

First, they can monitor network traffic at critical points known as chokepoints. Chokepoints are areas where unauthorized entities must pass through during their movement within the network. By closely watching these chokepoints, threat hunters can detect and potentially block or intercept any suspicious activities, preventing attackers from advancing further.

Secondly, threat hunters can analyze the company's network infrastructure from the perspective of an attacker. This means simulating how an attacker might attempt to navigate the network to move laterally and escalate privileges. By doing so, threat hunters gain insights into potential weak points, connections, and pathways that attackers could exploit. This understanding allows for the implementation of better defensive measures against lateral movement, including enhanced network segmentation, access controls, and improved logging mechanisms.

These proactive efforts make it significantly more challenging for attackers to maneuver undetected within the network. Because much of this defense work can be carried out passively, without alerting the attacker, it adds to its effectiveness. Disrupting the attacker's ability to move freely and covertly, contributes to the overall security of the network and reduces the potential impact of successful attacks.

## Conclusion

In conclusion, threat hunting is an active and intelligence-driven approach to cybersecurity that involves proactively seeking out and neutralizing hidden threats within a network, ultimately bolstering an organization's overall security posture.

