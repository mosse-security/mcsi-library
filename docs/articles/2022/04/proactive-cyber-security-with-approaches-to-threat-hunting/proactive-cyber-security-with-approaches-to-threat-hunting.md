:orphan:
(proactive-cyber-security-with-approaches-to-threat-hunting)=

# Proactive Cyber Security with Approaches to Threat Hunting

Proactive monitoring of harmful activities on a company's networks is known as threat hunting. It's a crucial step in an organization's security, more companies are starting to invest in it. Threat hunting's goal is to find threats before they cause damage, which necessitates the employment of specific methodologies. Threat hunting is a time-consuming procedure, but it's critical for any firm that wants to keep ahead of the cybersecurity curve.

## Structured threat hunting

_We use cyber threat intelligence relevant to our organization and sector to designed threat hunts._

A structured hunt revolves around the core of threat intelligence which is the Tactics, Techniques, and Procedures (TTP) used by attackers. As all the possible attacks are based on the TTP of the malicious actor, the hunter can easily identify the threat actor before any harm to the organization is caused. MITRE ATT&CK is one such platform where Adversary TTP can be accessed.

## Unstructured threat hunting

_We make wild guesses and hope to get lucky._

An unstructured hunt is based on the alerts produced by SIEM or threat intelligence tools. This is where the hunter uses the alert type to find before and after attack patterns and prevent an attacker from causing harm.

## Hypotheses-based hunting

_We make education guesses and are more likely to catch bad guys._

A threat intelligence library is used in hypothesis hunting, which is a proactive hunting strategy. It takes input from global monitoring data sources to identify advanced persistent threat groups and malware attacks and uses the MITRE ATT&CK framework.

Hypotheses-based hunting involves three types of Hypotheses:

- An analytics-driven technique that uses machine learning and user behavior analytics to develop risk scores and prepare hypotheses.

- An intelligence-driven technique that includes and is not limited to malware analysis, vulnerability scans, data feeds, and so on…

- A situational awareness-driven technique that assesses the critical digital assets of the organization and performs risk assessment on them.

To begin, a list of all of the institution's digital assets is compiled. Using the MITRE ATT&Ck framework, the hunter identifies the tactics, techniques, and procedures (TTP) used by Advanced persistent threat groups (APT). Once the behavior and techniques are identified, the threat hunter actively monitors for similar indicators of compromise in the network. This way, the threat hunter can detect and isolate the threat before it causes any harm.

## Hybrid Hunting

_This is often the best approach!_

It is a technique that threat hunting team use to combine these techniques. For instance, hunting can be customized based on the domain of the organization, and geopolitical issues.

We recommend hybrid hunting because it covers the most scope and allows threat hunters to be creative. In our experience, you never which person on the team will identify the best way to catch active threat actors on a network. Allowing the team to have flexibility to run a combination of approaches is the right approach!

## Summary

Threat hunting is a way that organizations can employ to discover and protect against cyber threats. It's a proactive technique that goes beyond typical security measures and can be used in conjunction with other security measures.
Organizations can increase their detection capabilities and minimize their overall risk exposure by using the correct tools and approaches.

> **Want to learn practical Threat Hunting tactics and strategies? Enrol in [MTH - Certified Threat Hunter Certification](https://www.mosse-institute.com/certifications/mth-certified-threat-hunter.html).**
