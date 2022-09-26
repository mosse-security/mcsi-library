:orphan:
(what-will-i-do-as-an-incident-responder)=

# What will I do as an Incident Responder?

You just landed a new job as an Incident Responder. You have heard that Incident Response involves identifying the incident, containing the incident, recovering from the incident and preventing such an incident form happening again. Have you wondered what really happens in those stages? What might an Incident Responder actually do to ‘handle’ incidents? This blog post will walk you through the sequence of activities typically performed during incident handling.

## Scenario

You login to your computer at work. You notice that the desktop wallpaper has been changed. The wallpaper now has a message that reads, ‘I can see you’. At random instances, it appears that the ‘Command Prompt’ application opens on its own, prints out some code-like content and disappears. You find this suspicious.

Your co-worker comes in and reports the same sequence of events on their computer. Soon after, you realize that only some computers on the same floor are reporting this activity. Others seem to be unaffected by this suspicious event.

Your manager has classified this as an incident and you have been called in to help handle it.

## Incident Response Steps

You can follow the outlined sequence of steps to help handle the incident effectively.

**Step 1: Develop the Concept of Operation (CONOP)**

The Concept of Operation is a document that sets the tone for the entire incident handling process. In this step, all the parties affected by this incident are identified. The goal of the incident response process is identified and resources that may be required for this mission and outlined. Capable professionals are identified to assist and the mission commences.

**Step 2: Develop the Action Plan**

The Action Plan is the document that outlines all the tasks that must be performed during this engagement. It is typically drafted in a spreadsheet with columns like task name, personnel assigned to the task, start date/end date, tools required, additional notes, etc.

**Step 3 Develop an Incident Statement**

The Incident Statement is a document that describes ‘what we already know’ about the incident. Considering the scenario described above, we know that the desktop wallpaper has been changed and ‘Command Prompt’ pops up at irregular intervals, seemingly executing some code.

Before drafting the incident statement, you must also try to gather information about when this behaviour was first observed, if any specific task was performed right before the unfavourable behaviour was observed (to identify triggers), if anyone remembers having downloaded content from suspicious emails/websites, etc.

**Step 4: Identify the Incident's Dimensions**

The Incident Dimensions has more detailed information about the observed incident. Based on the known events, you identify what is already known and not known about the incident.

To handle the scenario described above, check if the files are encrypted. If so, then you may be dealing with a ransomware. If not, then you are dealing with another class of malware. Identify all the systems that have been affected by this malware. See if you can spot any pattern or common application across these systems.

**Step 5: Develop a Request for Information (RFI) document**

A Request for Information document is a formal document requesting the client for information about their systems. In some cases, it may be requesting access to critical machines on their network. It may be requesting specific logs or evidence from their corporate network.

**Step 6: Collect evidence**

In the next step, you will proceed to collect evidence that you think is relevant to the incident. This is where an Incident Response Toolkit (IRT) comes in handy. You can read more about _[IRT](what-is-an-incident-response-toolkit)_

Considering the scenario, it might be a malware attack. Maybe an adversary is controlling the system remotely by running scripts – this could explain why _Command Prompt_ seems to run code on its own. Look for ways in which malware could have entered the system. Check the Downloads folder, temporary file locations, _[Windows Prefetch Files May be the Answer to your Investigation](windows-prefetch-files-may-be-the-answer-to-your-investigation)_ files, etc. Check if there are any active network connections to a remote IP address.

Since only few systems are exhibiting this behaviour, maybe malware got into one system and spread to the others. Identify why it spread to only some systems on the network – is there a common application that is being used on those systems?

**Step 7: Develop a Mission Brief**

After processing the evidence, you will have a better idea about the situation at hand. Once you have conclusive findings, you meet all the involved parties and present your findings verbally. This activity is referred to as mission briefing.

**Step 8: Develop a Mission Report**

The most important step after handling an incident is to write a report about it. It is a document that describes the events in detail, your findings and the steps taken to bring back the systems to normal working condition. You can read more about _[DFIR reports](providing-clarity-in-the-face-of-adversity-digital-forensics-reports)_

## A final word about the ‘Incident Responder’ role

Usually, when an incident occurs, the involved parties are worried and stressed about their files. The Incident Responder is the person who helps to calm down the chaos. You must be mentally prepared to deal with emotionally sensitive clients and try to gather as much information as you can, to help recover from the incident.

:::{seealso}
Want to learn practical Digital Forensics and Incident Response skills? Enrol in [MCSI's MDFIR - Certified DFIR Specialist Certification Programme](https://www.mosse-institute.com/certifications/mdfir-certified-dfir-specialist.html)
:::
