:orphan:
(understanding-the-threat-hunting-process-step-by-step)=

# Understanding the Threat Hunting Process Step-by-Step

Threat hunting is the process of detecting and responding to cyber intrusions that network and endpoint security controls have missed. It is also a proactive approach to security that can help organizations identify and mitigate risks before it results in an incident. The stages of threat hunting vary based on the sources you read, though there are 5 general stages that can be gleaned from existing literature.

## Step 1 - Prepare

Preparation is the first stage of threat hunting. In this stage, you will need to gather information about your organization's network and security infrastructure. This information will help you identify potential vulnerabilities and threats. You should also create a list of all the devices and systems that are connected to your network to assist with developing a scope for the hunt, Identifying the types of information that reside in the organization, and where it is located is also essential.

During the preparation stage, hypotheses can be developed to help guide the types of hunts that will be performed. The hypotheses can be generated based on the threat intelligence of known threat actors and the organizations they target. That can aid the hunt by using known Indicators of Compromise (IOCs). This stage also identifies the types of data that can be collected from systems to aid in the detection of threats. Datasets can include system and network event logs, application and database logs, system files, network traffic flows, and other sources of machine-generated data.

## Step 2 - Hunt

The next stage is performing the actual hunt, which can be done manually or with automation. It is essential that the hunt match the hypotheses that were generated in the preparation stage. This will involve looking for IOCs and other signs of compromise within the data collected. For example, analysts may look for unusual login attempts, failed access attempts, or unusual process activity. By identifying these patterns, analysts can zero-in on systems or users that may be compromised and investigate further.

## Step 3 - Baseline and Compare

The third stage is where analysts will examine data more closely to determine if there is indeed malicious activity taking place. During this stage, data analysis techniques such as statistical analysis or rule-based detection look for telltale signs of malicious activity. For example, analysts may look for patterns of data exfiltration or lateral movement that could indicate an attacker is present in the system.

## Step 4 - Respond

If suspicious activity is found, the fourth stage is to investigate and determine the scope of the attack. If the threat is discovered through routine threat hunts, the attack may be limited to one or a few systems. However, if the threat is discovered after having been in the system for a significant amount of time, the scope of the attack may be much larger.

## Step 5 - Recover

The fifth and final stage is to take action to contain and remediate the threat. This may involve disconnecting systems from the network, isolating them from other systems, or taking other steps to prevent further damage. Sometimes experts may need to be brought in to help contain and remediate the threat.

## Final Words

Threat hunting is an important part of cybersecurity, but it's not the only activity you need to do to keep your systems safe. You also need to have a good security posture overall, including implementing strong security controls and having good incident response procedures in place. Proactive threat hunts can help identify risk by keeping up to date on the latest threats and trends, and determining if the methods used to gain access are mitigated in the organization - or if the vectors have already been exploited.

By understanding the processes of threat hunting, you can be better prepared to protect your organization from cyber threats.

> **Want to learn practical Threat Hunting tactics and strategies? Enrol in [MTH - Certified Threat Hunter Certification](https://www.mosse-institute.com/certifications/mth-certified-threat-hunter.html).**
