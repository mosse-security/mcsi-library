(threat-hunting-main-page)=

# Threat Hunting

```{admonition} What is Threat Hunting?
:class: dropdown

Threat hunting is a security practice that involves proactively searching for signs of malware or malicious activity on a company’s network. The goal of threat hunting is to find and stop attacks before they cause damage. Threat hunting is a relatively new security practice, but it is gaining popularity as more companies become aware of the benefits it can offer. By proactively searching for signs of malware or malicious activity, threat hunters can help find and stop attacks before they cause damage. Threat hunting can be a valuable addition to any security program, and companies that are serious about protecting their data should consider adding it to their security arsenal.
```

## Articles

* [](the-right-team-can-keep-small-businesses-safe-from-disaster)
* [](email-another-source-for-data-exfiltration)
* [](fileless-malware-a-new-type-of-malware-that-doesnt-rely-on-executable-files)
* [](threat-hunting-concepts-adversary-behavioral-identification-for-predicting-attacks)
* [](introduction-to-malware-endpoint-hunting)
* [](threat-modeling-basics-system-modeling)
* [](what-is-an-indicator-of-compromise-ioc)

### Network

* [](detecting-exfiltration-over-network-protocols)
* [](dont-overlook-dns-in-your-threat-hunting-arsenal)
* [](stay-one-step-ahead-of-the-hackers-by-hunting-suspicious-traffic)

### Webshells

Webshells are malicious scripts that can be uploaded to a web server in order to gain control of the server. They are often used to take over a server by adding, modifying, or deleting files, and can also be used to execute arbitrary commands on the server. Webshells can be written in any scripting language, but are most commonly written in PHP or ASP.

* [](intro-to-hunting-webshells)
* [](hunting-webshells-tools)
* [](hunting-webshells-linux-and-windows-commands)

### Windows

Threat hunting on Windows is the process of proactively searching for signs of malicious activity on a Windows system. This can be done manually or by using automated tools. Some common techniques used in threat hunting include looking for unusual file activity, network traffic, and process behavior. 

* [](threat-hunting-windows-event-logs)

## Tools

There are many different tools that can be used for threat hunting. Some of these tools are designed specifically for threat hunting, while others are more general-purpose tools that can be used for a variety of security tasks.

* [](malware-hunting-detection-tools)
* [](threat-hunting-siem-elk-stack-splunk)
* [](make-your-incident-response-and-threat-hunting-easier-with-powershell-hunting-tools)

### Practice Datasets

When hunting for threats, analysts typically start with some sort of dataset that contains information about the activity that has taken place within a system or network. This dataset can come from a variety of sources, including system logs, network traffic data, and application data. Once a dataset has been collected, the next step is to look for IOCs that may indicate the presence of a threat.

The following articles teach tools to generate practice datasets:

* [](generating-logs-of-analysis-using-soc-faker-part-1)

MCSI also offers free threat hunting datasets to practice your skills:

* [MCSI Threat Hunting Samples](https://github.com/mosse-security/threat-hunting-samples)

### YARA

YARA is a powerful tool for reverse engineering malware. It can be used to identify and classify malware, and to find and extract specific features from malware samples. YARA can also be used to create signatures that can be used to detect and block malware.

**Procedure:**

The image below explains the process to follow when writing YARA rules:

```{thumbnail} ../images/procedures/yara-rules.svg
:align: center
:alt: Writing YARA rules procedure
:class: block max-width-400 mb-5 mx-auto
:width: 400px
```

**Articles:**

Read the following articles to learn how to write YARA rules:

* [](yara-a-powerful-malware-analysis-tool-for-detecting-ioc-s-part-1)
* [](yara-a-powerful-malware-analysis-tool-for-detecting-ioc-s-part-2)
* [](using-yara-for-threat-hunting-in-enterprise-environments)

## Workflow

```{admonition} What is a workflow?
:class: dropdown

A workflow is a series of steps that are followed in order to complete an engagement. In penetration testing, a workflow is important in order to ensure that all steps are followed in order to complete the testing process. By following a workflow, penetration testers can ensure that they are thorough in their testing and that they do not miss any important steps. 
```

The image below proposes a workflow you can use to learn threat hunting:

```{thumbnail} ../images/procedures/threat-hunting.svg
:alt: Threat hunting procedure and workflow
:class: block grey-border mb-5
```

**Articles:**

* [](a-general-overview-of-threat-modeling-workflow)
* [](understanding-the-threat-hunting-process-step-by-step)
* [](proactive-cyber-security-with-approaches-to-threat-hunting)
* [](threat-hunting-in-distributed-organizations-the-challenges-are-not-insurmountable)
* [](improve-efficiency-by-generating-a-hypothesis-before-beginning-a-threat-hunt)
* [](train-threat-hunters-and-develop-your-threat-hunting-program-with-threat-emulation)