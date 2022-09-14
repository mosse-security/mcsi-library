:orphan:
(structured-threat-information-expression-stix)=
# Structured Threat Information Expression STIX
 
MITRE is leading a cooperative process to transmit threat intelligence data utilizing a standardized language called Structured Threat Information Expression (STIX).

## Benefits of STIX

A security practitioner can swiftly express all parts of a compromise or analysis, as well as their interconnections, using STIX. An analyst may use relationship objects to indicate the link between one domain object and another while investigating an incident. With STIX, we aim to enable dynamic, expandable interactions while delivering data that is both human-readable and binary. You can use STIX data for graphically displaying as well as save as JavaScript Object Notation (JSON) for further use in automation.

### STIX framework

The STIX platform employs a model composed of essential domain objects (which are abbreviated as SDOs) and relationship objects (which are abbreviated as SROs) to describe threat information. These organized into objects, assign properties and attributes to each piece of info. Those items, or subgroups are used to comprehend and depict research or responding activities:

## STIX objects

Let’s have a look at STIX SDOs and SROs.

- **Attack patterns**: Attack trends are a type of tactic, technique, and procedure (TTP) that describes how attackers use their skills against their targets.

You can benefit from this domain object for classifying different sorts of attacks. Moreover, these artifacts may be leveraged to provide an understanding of how attacks are carried out. For example, in the case of a phishing, an attacker would pick a target, design a suitable phishing email, include a malicious file, and send the message with the intention that the target will download and view the attached file. When these separate acts are taken together, they form an attack pattern.

- **Campaign:** A campaign is a bunch of adversary activities directed at a common victim over a fixed period of time.

Campaign domain objects are widely recognized using multiple attributing techniques to link them to individual threat actors, as well as identifying the actor's distinctive usage of tools, infrastructure, methodologies, and targets.

- **Course of action:** A course of action is a proactive or reactive activity conducted in response to an attack. This domain object describes any technological changes, such as a firewall rule adjustment, as well as enterprise policy modifications, such as a compulsory awareness training.

- **Identity:** Identity STIX domain object identifies persons, companies, or groups. Identities might be particular and identifiable, or general, such as an entire industry. We may discover previously unknown trends when gathering identifiable details about the persons and organizations involved in an event. Using this approach, the persons who were the target of the popular social engineering methods such as a phishing message would be depicted as identity domain objects.

- **Indicator:** The indicator SDO, specifies an observable that may be used to identify strange activities on a network or a host machine. Again, for this single observable or sequence of observables to be genuinely valuable in expressing relevant features of a security incident, you must support the indicators with contextual information.

- **Intrusion set:** An intrusion set is a collection of actions, TTPs, or other attributes that are inherited by a single entity. An infiltration set, like a campaign, focuses on finding shared resources and activities instead of determining who is behind the action. Intrusion set domain objects vary from campaigns in that they are not always limited to a single timeline.

An intrusion set may also contain numerous campaigns, resulting in an extensive attack record across times. If a corporation has discovered that it has been the subject of many phishing operations from the same threat actor, such behavior may be classified as an intrusion set.

- **Malware:** Malware is defined as any harmful program or malicious code that is used to compromise the integrity or availability of a network or the data held inside it. Malware can also be deployed against a system to violate its confidentiality, allowing unauthorized parties to gain entry. Malware is considered a TTP in the context of this paradigm, as it is most typically delivered into a system in a way that prevents recognition by the consumer.

The malware domain object distinguishes samples and groups by describing the software's functionality and how it may influence an infected computer. Links to other malware objects to highlight patterns in its activities, or relationships to identities to convey the targets engaged in an event, are instances of how these objects may be related.

- **Observed Data:** The domain object observed data is used to represent any measurable obtained from a network or system component. This object can be used to convey a single assessment of an element or a collection of insights.

Importantly, observed data is not intelligence or knowledge, but rather actual data, such as the number of times communication is established or the amount of events during a certain duration.

- **Report:** Reports are completed intelligence products that describe a particular aspect of a security incident. Reports can include significant information regarding threat actors suspected of being involved in an event, the malware they may have employed, or the tactics utilized during a campaign.

- **Threat Actor:** Individuals or groups of people suspected of being behind a harmful behavior are defined as threat actor domain objects in STIX. Threat actors carry out the actions defined in the campaign and intrusion set objects, as well as the attacks specified in malware and attack pattern objects, against the targets identified by identity objects. This object can make use of their level of skill, personally identifiable information (PII), and statements regarding motivations.

- **Tool:** The tool SDO refers to the software utilized by a malicious actor to execute a campaign. Tools, as opposed to the malware object, are genuine technologies. To get an understanding of degrees of complexity and inclinations, tool objects can be linked to other objects defining TTPs. Learning how and when threat actors employ these technologies can give security defenders the information they need to design defenses. Because the software mentioned in tool objects is also used by power users, sys admins, and occasionally normal users, the problem shifts from just identifying the program's existence to identifying abnormal activity and assessing harmful intent.

A limitation to utilizing the tool object is that it is not intended to offer information about any software in use by defensive players in identifying or reacting to a security incident, additionally to avoid using it to identify malware.

- **Vulnerability:** A vulnerability domain object is used to convey an error in the software that an adversary might exploit to obtain unauthorized access to a system, program, or data. While malware objects give crucial information about harmful software and when they are employed in an attack, vulnerability objects disclose the specific weakness exploited by the attacker. The two may be coupled to demonstrate how a given malware object targets a specified vulnerability object.

- **Relationship:** SRO may be viewed as the connective instrument between domain objects, connecting them and demonstrating how they interact collectively. In the earlier discussion of the vulnerability, we mentioned that a link to a malware object might be formed to demonstrate how malicious code may exploit a specific issue. We can demonstrate how an origin and destination are associated using this architecture by using the relationship SRO relationship type target.

- **Sighting:** Sighting is the second relationship object which informs on the presence of any type of domain objects, such as an indicator or malware. It may be utilized to efficiently transmit key data about patterns and can be beneficial in creating knowledge about how an attacker's actions may change or act to mitigation procedures.

The sighting relationship object varies from the relationship SRO solely in that it can include extra information on when an object was first or last spotted, how many instances it was viewed, and where it was noticed. The sighting SRO is comparable to the observed data SDO in that both may be used to offer network inspections. Yet, an observed data SDO does not give intelligence and merely delivers the raw data connected with the observation.

While the observed data domain object would be used to convey that you noticed the existence of a specific malicious program on a computer, the sighting SRO would be used to indicate that a threat actor is probably behind the deployment of this malware given further information.

## Summary

As this blog page suggests, the STIX framework assists us in identifying trends that may signal cyber attacks and in facilitating cyber threat response efforts such as protection, diagnosis, and mitigation. STIX also improves the exchange of cyber threat intelligence within an enterprise as well as with foreign stakeholders or groups who benefit from it.

> **Want to learn practical Threat Hunting tactics and strategies? Enrol in [MTH - Certified Threat Hunter Certification](https://www.mosse-institute.com/certifications/mth-certified-threat-hunter.html)**