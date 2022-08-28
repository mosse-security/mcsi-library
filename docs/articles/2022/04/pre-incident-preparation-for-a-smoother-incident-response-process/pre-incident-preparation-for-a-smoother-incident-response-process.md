:orphan:
(pre-incident-preparation-for-a-smoother-incident-response-process)=
# Pre-Incident Preparation: For a Smoother Incident Response Process

When paramedics get a call, they immediately swoop into action. They have medical equipment stored and ready to use in their ambulance. Upon reaching the person requiring help, they provide immediate medical care to keep the person comfortable, until they can be taken to a hospital for further treatment. The paramedics collect as much information as they can about the patient’s medical condition and provide it to the doctors. Initial care provided by paramedics is very critical to saving a person’s life. Likewise, Incident Responders are the paramedics of the technology world. Professionals performing incident response must be equipped and prepared to deal with incidents. This can be achieved by executing pre-incident preparation.

What are the steps involved in pre-incident preparation?

**Analyze the business requirements**: The first step is to study the nature of the business. Consider a movie production company: Their IT infrastructure would have computers with video processing software, storage mechanisms to house different versions of video content, etc.

The potential risks to the infrastructure of a movie production company are as follows:

- The video processing software used has critical vulnerabilities that are unknown and susceptible to exploits
- The software is sometimes updated with unverified patches, potentially leading to a malware attack
- Unauthorized users gain access to confidential unreleased movie content

The company can protect their infrastructure by hiring security experts to regularly test the software, download software patches from verified publishers and ensure that only authorized personnel have access to data.

Despite all protection measures, there is still the possibility of cyberattacks occurring. Pre-incident preparation will assist the company to better handle such cyber incidents.

**Prepare an in-house incident response team**: The next step is to hire and build a team that is capable enough to response to incidents, who can be cyber paramedics. 

Apart from technical skills, incident response personnel must have the ability to handle stressful situations and take important decisions. 

The IR team can have an Incident Response Toolkit (IRT) ready to assist in collecting importance evidence. You can read more about IRT *[What is an Incident Response Toolkit?](what-is-an-incident-response-toolkit)*

The IR team can also create Incident Response Playbooks to serve as a guide while handling specific incidents. You can read more about IR playbooks *[A short introduction to writing incident response playbooks](a-short-introduction-to-writing-incident-response-playbooks)*

Here are some IR playbook ideas for the movie production company:

- Playbook to handle unauthorized access to critical business data
- Playbook to detect and handle malware attacks

**Prepare infrastructure to assist in incident response**: Log files are the foundation for Digital Forensics and Incident Response. Looking through the information stored in log files, helps identify the events that occurred, which led to the incident.

The next step would be to enable logging wherever relevant within the infrastructure. There are commercial tools can alert you when abnormal log events have been identified. 

Say the movie production company runs into a situation where they suspect that the final unreleased version of a movie has been leaked on torrent websites. They want to know who gained access to the movie file and how. Logs stored in various locations come in handy here to identify who gained access to the file, when the file was copied, etc.

**Map the infrastructure**: The next critical step would be to develop a map of the IT infrastructure in the company. This would involve identifying the physical location of the various servers, desktops, switches, routers and other networking devices. Then a blueprint of the infrastructure can be drawn and stored, along with critical configuration information. This information will come in handy when an incident is underway. 

If a server hosting a critical service goes down, sometimes it is important to gain access to the server physically to see what’s going on. Having a map of the infrastructure helps to quickly identify the physical location of the server, say ‘second floor, east end, room 408’ and take appropriate action. 

There have been situations where an organisation tried to identify why a server went down. They did not have any success until they reached the physical location and noticed that a rodent had chewed through the power cable! Knowing the physical location of the server helped them get there as soon as possible.

## A final word on pre-incident preparation

When pre-incident preparation has been performed diligently, the incident response process can proceed in a smooth manner. 

> **Want to learn practical Digital Forensics and Incident Response skills? Enrol in [MCSI's MDFIR - Certified DFIR Specialist Certification Programme](https://www.mosse-institute.com/certifications/mdfir-certified-dfir-specialist.html).**